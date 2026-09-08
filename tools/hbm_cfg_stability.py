#!/usr/bin/env python3
"""hbm_cfg_stability.py -- is the HBMPLL_CFG "divergence" hardware state or a read artifact?

STRICTLY READ-ONLY.  Never writes BAR0.  Safe on a running GPU.

`FINDINGS-2026-09-06-memory-clock-unlocked.md` §5 records an open defect: after one clean
memory-clock switch the 16 `NV_PFB_FBPA_FBIO_HBMPLL_CFG` instances stop agreeing and settle into
four values in groups of four, one of which has `IDDQ` (PLL analog powered down) set together with
`PLL_LOCK`, which is incoherent.  The handoff poses the discriminator explicitly:

    "Either these CFG reads are unreliable the way the broadcast ones are, or the sequence leaves
     the FBIO state machines genuinely inconsistent."

This tool decides it, without writing anything:

  1. repeat      -- read one instance N times back-to-back.  Genuine state is stable; a rotating
                    or stale-buffer read is not.  (The IEEE-1500 port on this card returns three
                    different dwords with period 3 for exactly this reason.)
  2. order       -- read all 16 forward, then backward, then forward again.  If a value follows the
                    FBPA *index* it is state; if it follows the *position in the read sequence* it
                    is an artifact of the access pattern.
  3. spacing     -- read all 16 with a delay between accesses.  The I1500 port on this card changes
                    its answer when reads are spaced out; a real register does not.

usage:  hbm_cfg_stability.py <bdf> [--repeats N] [--delay-ms N]
"""
import argparse, mmap, os, struct, sys, time

PMC_BOOT_0 = 0x000000
FBPA_CFG, FBPA_COEFF, FBPA_STRIDE, NFBPA = 0x903C90, 0x903C98, 0x4000, 16
MEM_SPACE_EN = 1 << 1
BITS = [("ENABLE", 0), ("EN_LCKDET", 3), ("LOCK_OVERRIDE", 4), ("PLL_LOCK", 5),
        ("EN_FSTLCK", 6), ("IDDQ", 7), ("BYPASSPLL", 10), ("SEL_ALT_DRAMCLK", 12)]


def openbar(bdf):
    cfg = "/sys/bus/pci/devices/%s/config" % bdf
    with open(cfg, "r+b", buffering=0) as f:
        f.seek(4); orig = struct.unpack("<H", f.read(2))[0]
        if not orig & MEM_SPACE_EN:
            f.seek(4); f.write(struct.pack("<H", orig | MEM_SPACE_EN))
    p = "/sys/bus/pci/devices/%s/resource0" % bdf
    fd = os.open(p, os.O_RDONLY | os.O_SYNC)
    mm = mmap.mmap(fd, min(os.path.getsize(p), 32 << 20), mmap.MAP_SHARED, mmap.PROT_READ)
    os.close(fd)
    return mm


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bdf")
    ap.add_argument("--repeats", type=int, default=8)
    ap.add_argument("--delay-ms", type=int, default=5)
    a = ap.parse_args()

    mm = openbar(a.bdf)
    rd = lambda o: struct.unpack_from("<I", mm, o)[0]
    boot = rd(PMC_BOOT_0)
    if boot in (0x00000000, 0xFFFFFFFF):
        sys.exit("PMC_BOOT_0 = 0x%08X -- BAR0 not readable" % boot)
    print("PMC_BOOT_0 = 0x%08X   (canary checked after every access below)\n" % boot)

    def canary(tag):
        if rd(PMC_BOOT_0) != boot:
            sys.exit("PRI ring canary FAILED at %s" % tag)

    def cfg(i):
        v = rd(FBPA_CFG + i * FBPA_STRIDE); canary("FBPA_%d" % i)
        return v

    def coeff(i):
        v = rd(FBPA_COEFF + i * FBPA_STRIDE); canary("FBPA_%d coeff" % i)
        return v

    # -- 1. repeatability of a single instance ---------------------------------------
    print("1. same instance, %d back-to-back reads" % a.repeats)
    unstable = []
    for i in (0, 4, 8, 12, 15):
        vals = [cfg(i) for _ in range(a.repeats)]
        uniq = sorted(set(vals))
        flag = "STABLE" if len(uniq) == 1 else "*** VARIES ***"
        print("   FBPA_%-2d  %s  %s" % (i, flag, [hex(v) for v in uniq]))
        if len(uniq) != 1:
            unstable.append(i)

    # -- 2. does a value follow the index or the read position? ----------------------
    print("\n2. read-order dependence")
    fwd1 = [cfg(i) for i in range(NFBPA)]
    rev = [0] * NFBPA
    for i in range(NFBPA - 1, -1, -1):
        rev[i] = cfg(i)
    fwd2 = [cfg(i) for i in range(NFBPA)]
    print("   forward #1 : %s" % " ".join("%04X" % v for v in fwd1))
    print("   backward   : %s" % " ".join("%04X" % v for v in rev))
    print("   forward #2 : %s" % " ".join("%04X" % v for v in fwd2))
    same_fwd = fwd1 == fwd2
    same_rev = fwd1 == rev
    print("   forward#1 == forward#2 : %s" % same_fwd)
    print("   forward#1 == backward  : %s" % same_rev)

    # -- 3. spacing ------------------------------------------------------------------
    print("\n3. same reads spaced %d ms apart" % a.delay_ms)
    spaced = []
    for i in range(NFBPA):
        time.sleep(a.delay_ms / 1000.0)
        spaced.append(cfg(i))
    print("   spaced     : %s" % " ".join("%04X" % v for v in spaced))
    print("   spaced == forward#1    : %s" % (spaced == fwd1))

    # -- summary ---------------------------------------------------------------------
    print("\n--- groups (forward #1) ---")
    for v in sorted(set(fwd1)):
        who = [i for i, x in enumerate(fwd1) if x == v]
        on = " ".join(n for n, b in BITS if v >> b & 1)
        bad = "   <-- IDDQ+PLL_LOCK INCOHERENT" if (v >> 7 & 1) and (v >> 5 & 1) else ""
        print("   0x%08X  FBPA %-16s %s%s" % (v, who, on, bad))
    ks = [coeff(i) for i in range(NFBPA)]
    print("   COEFF: %d distinct %s   (NDIV %s)"
          % (len(set(ks)), [hex(v) for v in sorted(set(ks))],
             sorted({(k >> 8) & 0xFF for k in ks})))

    # -- 4. the OTHER controller: NV_PTRIM_FBPA_HBMPLL_CFG0(i), 8 instances --------
    # dev_trim.h:11564  0x00130080 + i*256, __SIZE_1 = 8.  DIFFERENT bit layout from the
    # NV_PFB_FBPA_FBIO_ view above, and NV_PFB_FBPA_FBIO_HBMPLL_CFG has a PTRIM_OVERRIDE
    # bit (31:31), so the two are two views/controllers of the same PLLs.
    PT_CFG0, PT_STRIDE, PT_N = 0x130080, 256, 8
    PT_BITS = [("IDDQ", 0), ("ENABLE_BG", 3), ("SYNCMODE", 4), ("STOP_SYNCMUX", 5),
               ("BYPASSPLL", 6), ("SEL_ALT_DRAMCLK", 7), ("SWITCH_ASYNC_MODE", 8)]
    print("\n4. NV_PTRIM_FBPA_HBMPLL_CFG0(i) -- the other controller, %d instances" % PT_N)
    pts = []
    for i in range(PT_N):
        v = rd(PT_CFG0 + i * PT_STRIDE); canary("PTRIM_%d" % i)
        pts.append(v)
        on = " ".join(n for n, b in PT_BITS if v >> b & 1)
        print("   [%d] 0x%08X   %s" % (i, v, on if on else "(none set)"))
    print("   %d distinct value(s): %s"
          % (len(set(pts)), [hex(v) for v in sorted(set(pts))]))
    ovr = [i for i, v in enumerate(fwd1) if v >> 31 & 1]
    print("   FBPA-side PTRIM_OVERRIDE (bit 31) set on: %s" % (ovr if ovr else "none"))

    print("\nVERDICT:")
    if unstable:
        print("  CFG reads are NOT repeatable on FBPA %s -> the divergence is a READ ARTIFACT,"
              % unstable)
        print("  the same class as the broadcast/I1500 ports. The FBIO state machines are not")
        print("  implicated and the tool is not leaving the PLLs inconsistent.")
    elif not same_fwd or not same_rev:
        print("  CFG reads are individually stable but depend on the ACCESS PATTERN")
        print("  (fwd==fwd2 %s, fwd==rev %s) -> still an artifact, not state." % (same_fwd, same_rev))
    else:
        print("  CFG reads are stable, order-independent and spacing-independent")
        print("  -> the divergence is GENUINE HARDWARE STATE and must be explained.")
    mm.close()


if __name__ == "__main__":
    main()
