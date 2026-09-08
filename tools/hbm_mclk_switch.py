#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 duggasco
"""Change the CMP 100-210's HBM memory clock at runtime, properly.

Port of the GA100/170HX memory-clock switch sequence
(`~/170hx_unlock/docs/codex-combined-unlock-8x20c2-handoff-2026-08-04.md`) to GV100. Every
register and every bit field in that sequence exists in the GV100 headers at the SAME address
with the SAME name, so this is a direct port, not an analogy:

    0x9A0590  NV_PFB_FBPA_FBIO_BROADCAST          MEMCLK_CHANGE_ALERT   31:31
    0x9A031C  NV_PFB_FBPA_SELF_REF                CMD                     0:0
    0x9A3C90  NV_PFB_FBPA_FBIO_HBMPLL_CFG         ENABLE 0, EN_LCKDET 3, PLL_LOCK 5 (RO),
                                                  BYPASSPLL 10, SEL_ALT_DRAMCLK 12
    0x9A3C98  NV_PFB_FBPA_FBIO_HBMPLL_COEFF       MDIV 7:0, NDIV 15:8, PLDIV 21:16
    0x9A11DC  NV_PFB_FBPA_FBIO_HBM_DDLLCAL_CTRL1  CALIBRATE               6:6
    0x9A0674  NV_PFB_FBPA_FBIO_SUBP0_DDLLCAL_STATUS
    0x9A0678  NV_PFB_FBPA_FBIO_SUBP1_DDLLCAL_STATUS

⛔ **Why the naive write fails.** Pass 63 wrote the COEFF directly on a live, locked PLL -- with
no self-refresh, no PLL disable and no relock -- and the GPU died with 59 Xids and PLL_LOCK
dropped, even when writing the IDENTICAL value back. That is the middle line of step 3 below with
every surrounding step missing. Privilege was never the obstacle: NV_PFB_FBPA_FBIO_PRIV_LEVEL_MASK
(0x9A08FC) is 0xFF, host-writable at L0, so this needs **no L3 stamp and no ROM payload**.

## Sequence

  1. MEMCLK_CHANGE_ALERT = 1
  2. SELF_REF = 1                       (park DRAM; it self-refreshes with no external clock)
  3. PLL: disable -> reprogram NDIV -> re-enable -> poll lock -> select PLL as dramclk again
  4. SELF_REF = 0
  5. DDLL recalibration for the new clock period
  6. MEMCLK_CHANGE_ALERT = 0

## Safety

* Default target is **NDIV 65 = 877.5 MHz, the STOCK Tesla V100 value** for this die
  (`OPT_PCIE_DEVIDA = 0x1DB4`), reached from the CMP's 810 MHz. This is a restore, not an
  overclock -- unlike the 170HX work, which pushed past stock and documents real corruption risk.
* `--ndiv 60` performs the whole sequence with the value unchanged: the no-op round-trip control
  the 170HX handoff insists on before stepping the clock. Run it first.
* ⚠ A memory clock change can corrupt **silently**. Always follow with
  `tools/bench/gv100_memtest.cu` (12 GiB x 4 patterns), never a bandwidth number alone.
* Volatile: any reset restores 810 MHz.

usage: hbm_mclk_switch.py <bdf> [--ndiv N] [--apply]
"""
import argparse, mmap, os, struct, sys, time

BROADCAST, SELF_REF = 0x9A0590, 0x9A031C
# ⚠ The 0x9A3Cxx pair is WRITE-ONLY FAN-OUT. Measured under load: broadcast CFG reads 0x00000009
# and broadcast COEFF reads 0x00000002 (NDIV 0) while every one of the 16 real instances reads
# CFG 0x00000029 (locked) and COEFF 0x00013C02 (NDIV 60). Write the broadcast, read an instance.
CFG, COEFF = 0x9A3C90, 0x9A3C98           # write here -- fans out to all 16 FBPAs
FBPA_CFG, FBPA_COEFF, FBPA_STRIDE = 0x903C90, 0x903C98, 0x4000
NFBPA = 16                                # all 16 enumerated live on this card, canary-clean
DDLLCAL, DDLL_ST0, DDLL_ST1 = 0x9A11DC, 0x9A0674, 0x9A0678
BOOT0, BOOT0_EXPECT = 0x000000, 0x140000A1
MEM_SPACE_EN = 1 << 1
XTAL = 27.0

ALERT = 1 << 31
SR_CMD = 1 << 0
CFG_ENABLE, CFG_LCKDET, CFG_LOCK = 1 << 0, 1 << 3, 1 << 5
CFG_ALT_DRAMCLK = 1 << 12
CAL = 1 << 6

# --- safety envelope -----------------------------------------------------------
# ⚠ These are ENFORCED, not advisory. A memory clock change can corrupt silently, and an NDIV
# typo is a plausible way to push HBM far out of spec on a card nobody can replace.
CMP_NDIV = 60          # what this SKU's devinit programs -- 810.0 MHz
STOCK_NDIV = 65        # the stock Tesla V100 value for this die -- 877.5 MHz; the default target
MIN_NDIV = 40          # below this the DDLL recalibration window is untested here
ABS_MAX_NDIV = 75      # a hard ceiling even with --allow-overclock; refuse typos like 650

# ⛔⛔ ONE SWITCH PER POST SESSION.  Measured 2026-09-08 on the reference card: running the
# `--ndiv 60` no-op control and then the real `--ndiv 65` switch 3 s later gave **Xid 62** and a
# deadlocked RM (`os_acquire_rwlock_write`, nvidia-smi hung); recovery was a VM stop + SBR.  That
# is CLAUDE.md's standing pass-64 defect -- "Xid 62 on repeated back-to-back switches, keep
# resetting between experiments" -- and it directly contradicts the other standing rule, "always
# run the no-op control first".  The resolution is a RESET between any two switches, and it is
# enforced here rather than left to prose, because prose is what failed.
#
# Detection: at a fresh POST every FBPA CFG reads PRISTINE_CFG.  One switch leaves them changed
# (measured: 0x29 -> 0x2C29), which is the same divergence the pass-64 defect describes.  So
# "CFG is not pristine" == "a switch has already run since the last device reset".
PRISTINE_CFG = 0x29


def gpu_is_busy(bdf):
    """(busy, why).  Uses nvidia-smi, matched to THIS bdf -- never to 'GPU 0'.

    Returns (None, reason) when it cannot tell, which the caller treats as "refuse unless
    the operator asserts idle": an unknown state is not an idle state.
    """
    import subprocess
    try:
        q = subprocess.run(
            ["nvidia-smi", "--query-gpu=pci.bus_id,utilization.gpu,memory.used",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as e:
        return None, "nvidia-smi did not run (%s)" % e
    if q.returncode != 0:
        return None, "nvidia-smi failed: %s" % (q.stderr or "").strip()[:120]
    # ⚠ nvidia-smi prints an 8-digit domain ("00000000:0B:00.0"); sysfs uses 4 ("0000:0b:00.0").
    # Normalise both ends rather than comparing raw strings -- and never fall back to "GPU 0".
    def norm(x):
        x = x.strip().lower()
        parts = x.split(":")
        if len(parts) == 3:
            parts[0] = parts[0].lstrip("0") or "0"
            return ":".join(parts)
        return x
    want = norm(bdf)
    row = None
    for line in q.stdout.splitlines():
        f = [x.strip() for x in line.split(",")]
        if len(f) >= 3 and norm(f[0]) == want:
            row = f
            break
    if row is None:
        return None, "no nvidia-smi row matched %s (is the driver bound to this card?)" % bdf
    try:
        util, memused = int(row[1]), int(row[2])
    except ValueError:
        return None, "could not parse utilisation from %r" % row
    apps = subprocess.run(["nvidia-smi", "--query-compute-apps=pid,used_memory",
                           "--format=csv,noheader"], capture_output=True, text=True, timeout=20)
    napps = len([l for l in apps.stdout.splitlines() if l.strip()]) if apps.returncode == 0 else 0
    if util > 5 or napps:
        return True, "utilisation %d%%, %d compute process(es), %d MiB in use" % (util, napps, memused)
    return False, "utilisation %d%%, no compute processes, %d MiB in use" % (util, memused)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bdf")
    ap.add_argument("--ndiv", type=int, default=65,
                    help="target NDIV. %d = this SKU's 810 MHz, %d = the stock Tesla V100's "
                         "877.5 MHz and the default. Values above STOCK_NDIV are an OVERCLOCK "
                         "and need --allow-overclock." % (CMP_NDIV, STOCK_NDIV))
    ap.add_argument("--allow-overclock", action="store_true",
                    help="permit NDIV above the stock %d. ⛔ Past stock this is no longer a "
                         "restore: the 170HX work documents real, silent memory corruption "
                         "above stock, and nothing here has been validated there." % STOCK_NDIV)
    ap.add_argument("--allow-repeat-switch", action="store_true",
                    help="permit a second switch without an intervening device reset. ⛔ This is "
                         "the measured Xid 62 / RM-deadlock path; the recovery is a reset anyway.")
    ap.add_argument("--i-know-the-gpu-is-idle", action="store_true",
                    help="skip the idle check (it needs nvidia-smi). The sequence puts DRAM in "
                         "self-refresh; running it under load was measured at 325 Xids.")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--dump", action="store_true",
                    help="read-only: print all %d (CFG, COEFF) instances and exit. Use this to "
                         "inspect the pass-64 CFG-divergence defect, which the NDIV/LOCK "
                         "agreement check above does not detect." % 16)
    a = ap.parse_args()

    cfgp = "/sys/bus/pci/devices/%s/config" % a.bdf
    with open(cfgp, "r+b", buffering=0) as f:
        f.seek(4); c = struct.unpack("<H", f.read(2))[0]
        if not c & MEM_SPACE_EN:
            f.seek(4); f.write(struct.pack("<H", c | MEM_SPACE_EN))
    p = "/sys/bus/pci/devices/%s/resource0" % a.bdf
    fd = os.open(p, os.O_RDWR | os.O_SYNC)
    mm = mmap.mmap(fd, 16 << 20, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
    os.close(fd)
    rd = lambda o: struct.unpack_from("<I", mm, o)[0]
    wr = lambda o, v: struct.pack_into("<I", mm, o, v & 0xFFFFFFFF)

    def canary(w):
        b = rd(BOOT0)
        if b != BOOT0_EXPECT:
            print("!! PMC_BOOT_0 = 0x%08X at %s -- aborting" % (b, w)); sys.exit(2)

    canary("entry")
    mhz = lambda n: XTAL * n / 2

    def survey(tag):
        """Read every real FBPA instance; broadcast reads are meaningless."""
        out = []
        for i in range(NFBPA):
            canary("%s FBPA_%d" % (tag, i))
            out.append((rd(FBPA_CFG + i * FBPA_STRIDE), rd(FBPA_COEFF + i * FBPA_STRIDE)))
        nd = {(k >> 8) & 0xFF for _, k in out}
        lk = {(c >> 5) & 1 for c, _ in out}
        return out, nd, lk

    inst, ndivs, locks = survey("entry")

    if a.dump:
        # CFG bit map, from the GV100 headers (see the module docstring).
        BITS = [("ENABLE", 0), ("EN_LCKDET", 3), ("LOCK_OVERRIDE", 4), ("PLL_LOCK", 5),
                ("EN_FSTLCK", 6), ("IDDQ", 7), ("BYPASSPLL", 10), ("SEL_ALT_DRAMCLK", 12)]
        print("FBPA  CFG         COEFF       NDIV  set bits")
        for i, (c, k) in enumerate(inst):
            on = " ".join(n for n, b in BITS if c >> b & 1)
            print("  %2d  0x%08X  0x%08X  %3d   %s" % (i, c, k, (k >> 8) & 0xFF, on))
        cfgs = sorted({c for c, _ in inst})
        print("\n%d distinct CFG value(s): %s" % (len(cfgs), [hex(v) for v in cfgs]))
        for v in cfgs:
            who = [i for i, (c, _) in enumerate(inst) if c == v]
            incoherent = " <-- IDDQ and PLL_LOCK both set: INCOHERENT" \
                if (v >> 7 & 1) and (v >> 5 & 1) else ""
            print("   0x%08X  FBPA %s%s" % (v, who, incoherent))
        print("%d distinct COEFF value(s): %s"
              % (len({k for _, k in inst}), [hex(v) for v in sorted({k for _, k in inst})]))
        return

    c0, k0 = inst[0]
    nd0 = (k0 >> 8) & 0xFF
    print("entry:  CFG 0x%08X  COEFF 0x%08X   MDIV=%d NDIV=%d PLDIV=%d -> %.1f MHz"
          % (c0, k0, k0 & 0xFF, nd0, (k0 >> 16) & 0x3F, mhz(nd0)))
    print("        ENABLE=%d EN_LCKDET=%d PLL_LOCK=%d BYPASSPLL=%d SEL_ALT_DRAMCLK=%d"
          % (c0 & 1, (c0 >> 3) & 1, (c0 >> 5) & 1, (c0 >> 10) & 1, (c0 >> 12) & 1))
    print("        %d instances: NDIV set %s, PLL_LOCK set %s"
          % (NFBPA, sorted(ndivs), sorted(locks)))
    if (k0 & 0xFFF00000) == 0xBAD00000 or nd0 == 0:
        sys.exit("PLL does not read back sanely -- is the framebuffer clocked? "
                 "Reads are only valid while the GPU is busy.")
    if ndivs != {nd0} or locks != {1}:
        sys.exit("instances disagree (NDIV %s, LOCK %s) -- refusing to switch from a mixed state"
                 % (sorted(ndivs), sorted(locks)))

    # ⛔ ENFORCED ENVELOPE -- checked after the survey (so the report is still useful on a
    # dry run) but before anything is written.
    if not (MIN_NDIV <= a.ndiv <= ABS_MAX_NDIV):
        sys.exit("⛔ --ndiv %d is outside the hard range %d..%d.  %d = this SKU (810.0 MHz), "
                 "%d = stock (877.5 MHz).  Refusing: an out-of-range NDIV drives HBM far out of "
                 "spec." % (a.ndiv, MIN_NDIV, ABS_MAX_NDIV, CMP_NDIV, STOCK_NDIV))
    if a.ndiv > STOCK_NDIV and not a.allow_overclock:
        sys.exit("⛔ --ndiv %d is ABOVE the stock %d (%.1f MHz > %.1f MHz).  Everything measured "
                 "here is a RESTORE to stock, not an overclock, and past stock the 170HX work "
                 "records real silent corruption.  Pass --allow-overclock if you mean it, and "
                 "run gv100_memtest afterwards without exception."
                 % (a.ndiv, STOCK_NDIV, mhz(a.ndiv), mhz(STOCK_NDIV)))
    dirty = [i for i, (c, _) in enumerate(inst) if c != PRISTINE_CFG]
    if a.apply and dirty and not a.allow_repeat_switch:
        sys.exit("⛔ A MEMORY CLOCK SWITCH HAS ALREADY RUN SINCE THE LAST DEVICE RESET.\n"
                 "   %d of %d FBPA CFG registers are no longer the pristine 0x%02X "
                 "(instance %d reads 0x%08X).\n"
                 "   A second switch without an intervening reset is what produces **Xid 62** and\n"
                 "   a deadlocked RM -- measured on the reference card, recovery was a VM stop +\n"
                 "   SBR.  Reset the GPU and re-run:\n"
                 "       host:  qm stop <vmid> ; echo 1 > /sys/bus/pci/devices/<bdf>/reset\n"
                 "       bare:  modprobe -r nvidia_uvm nvidia_drm nvidia_modeset nvidia ; "
                 "echo 1 > /sys/bus/pci/devices/<bdf>/reset\n"
                 "   ⚠ This is why the `--ndiv 60` no-op control must NOT be chained straight into\n"
                 "   the real switch: the control IS a switch.  Run one or the other per boot.\n"
                 "   --allow-repeat-switch overrides, and is how the defect was characterised."
                 % (len(dirty), NFBPA, PRISTINE_CFG, dirty[0], inst[dirty[0]][0]))

    if a.apply and a.ndiv != nd0 and not a.i_know_the_gpu_is_idle:
        busy, why = gpu_is_busy(a.bdf)
        if busy:
            sys.exit("⛔ the GPU is NOT IDLE (%s).  Step 2 of this sequence puts DRAM into "
                     "self-refresh; doing that under load was measured at 325 Xids.  Stop the "
                     "workload, or pass --i-know-the-gpu-is-idle if you are certain." % why)
        if busy is None:
            sys.exit("⛔ could not confirm the GPU is idle: %s.  An unknown state is not an idle "
                     "state -- self-refresh under load was measured at 325 Xids.  Fix the check "
                     "or pass --i-know-the-gpu-is-idle." % why)
        print("idle:   %s" % why)

    target = (k0 & ~0x0000FF00) | ((a.ndiv & 0xFF) << 8)
    print("target: COEFF 0x%08X   NDIV %d -> %d   %.1f -> %.1f MHz%s"
          % (target, nd0, a.ndiv, mhz(nd0), mhz(a.ndiv),
             "   [NO-OP CONTROL]" if a.ndiv == nd0 else ""))
    if not a.apply:
        print("\ndry run: pass --apply to run the switch sequence.")
        return

    ok = False
    try:
        print("\n 1. MEMCLK_CHANGE_ALERT = 1")
        wr(BROADCAST, rd(BROADCAST) | ALERT)
        print(" 2. SELF_REF = 1")
        wr(SELF_REF, SR_CMD); time.sleep(0.005)
        canary("after self-refresh")

        # ⚠ PER-FBPA, not broadcast. The GA100 reference loops over instances, and on this card
        # the broadcast pair reads garbage -- a read-modify-write through it is meaningless, and
        # driving it left the 16 PLLs in a mixed NDIV {0,60} state with no lock.
        print(" 3. PLL disable -> reprogram -> relock, per FBPA (%d instances)" % NFBPA)
        nlocked = 0
        for i in range(NFBPA):
            ic, ik = FBPA_CFG + i * FBPA_STRIDE, FBPA_COEFF + i * FBPA_STRIDE
            oc, ok_ = rd(ic), rd(ik)
            if (oc & 0xFFF00000) == 0xBAD00000 or ((ok_ >> 8) & 0xFF) == 0:
                continue
            b = oc & ~CFG_LOCK              # PLL_LOCK is R--UF status; never write it back
            wr(ic, b & ~(CFG_ENABLE | CFG_LCKDET))
            time.sleep(0.002)
            wr(ik, (ok_ & ~0x0000FF00) | ((a.ndiv & 0xFF) << 8))
            wr(ic, b | CFG_ENABLE | CFG_LCKDET)
            end = time.time() + 0.2
            while time.time() < end:
                if rd(ic) & CFG_LOCK:
                    nlocked += 1; break
                time.sleep(0.0005)
            wr(ic, (b | CFG_ENABLE | CFG_LCKDET) & ~CFG_ALT_DRAMCLK)
        locked = nlocked == NFBPA
        print("    PLL_LOCK reacquired on %d/%d instances%s"
              % (nlocked, NFBPA, "" if locked else "   *** INCOMPLETE ***"))

        print(" 4. SELF_REF = 0")
        wr(SELF_REF, 0); time.sleep(0.010)
        canary("after self-refresh exit")

        print(" 5. DDLL recalibration")
        d = rd(DDLLCAL)
        wr(DDLLCAL, d | CAL); time.sleep(0.005)
        wr(DDLLCAL, d & ~CAL); time.sleep(0.002)
        print("    SUBP0 status 0x%08X   SUBP1 status 0x%08X" % (rd(DDLL_ST0), rd(DDLL_ST1)))
        ok = locked
    finally:
        print(" 6. MEMCLK_CHANGE_ALERT = 0")
        wr(BROADCAST, rd(BROADCAST) & ~ALERT)

    canary("exit")
    inst1, ndivs1, locks1 = survey("exit")
    c1, k1 = inst1[0]
    nd1 = (k1 >> 8) & 0xFF
    print("\nexit:   CFG 0x%08X  COEFF 0x%08X   NDIV=%d -> %.1f MHz" % (c1, k1, nd1, mhz(nd1)))
    print("        %d instances: NDIV set %s, PLL_LOCK set %s"
          % (NFBPA, sorted(ndivs1), sorted(locks1)))
    good = ok and ndivs1 == {a.ndiv} and locks1 == {1}
    print("verdict: %s" % ("OK, all %d instances at NDIV %d and locked -- now run gv100_memtest; "
                           "a bandwidth number alone proves nothing" % (NFBPA, a.ndiv) if good
                           else "*** did not complete cleanly ***"))


if __name__ == "__main__":
    main()
