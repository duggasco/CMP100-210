#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 duggasco
"""Clear the CMP 100-210's CYA speed clamp, then retrain the link from the upstream port.

Background. logs/56 PROVED that one host-L0 write to NV_XVE_PRIV_MISC_1 (0x08841C), clearing the
four CYA_GEN2/GEN3_SPEED_OVERRIDE_{EN,VAL} bits, lifts the advertised capability from Gen1 to Gen3
(LNKCAP MAX_LINK_SPEED 1->3, LNKCAP2 GEN1->GEN1_GEN2_GEN3, VSEC_DEVICE 0x800->0x1801, all landing
on the stock Tesla V100's values). But LINK_CONTROL_STATUS still reported Gen1 x1 NEGOTIATED --
advertising a capability is not running at it. This issues the retrain that converts one into the
other, following the proven GA104 70HX recipe (nvidia_unlock_70HX/tools/unlock/70hx-unlock-all.sh
step 3): the retrain must be issued from the UPSTREAM port, because an endpoint's own retrain bit
bounces.

Sequence:
  1. record endpoint + upstream-port link state (setpci, read-only)
  2. BAR0: 0x08841C <- 0x00340500          (the proven capability lift)
  3. upstream port LnkCtl (CAP_EXP+10.w) |= 0x20   (Retrain Link)
  4. poll LnkSta on both sides
  5. keep on success, restore the clamp on failure

Safety. PCIe mandates speed fallback: a link that cannot train at the higher rate returns to a
lower one, so the realistic failure mode is "no change", not "no link". The card is driverless, so
nothing in the OS depends on it, and it sits behind a PLX downstream port so a link event cannot
disturb the host. ⚠ Residual risk is that the device stops responding, which costs a BMC power
cycle plus a 5-minute cold soak (CLAUDE.md). Everything here is per-boot: an SBR or a reboot
restores the stock clamp.

usage: pcie_retrain_probe.py <bdf> [--apply] [--target-gen N]
"""
import argparse, json, mmap, os, re, struct, subprocess, sys, time

PRIV_MISC_1 = 0x08841C
CLAMP_STOCK = 0x00340500          # stock Tesla V100 value, measured pre-POST in logs/53
# CYA_GEN2/GEN3_SPEED_OVERRIDE_{EN,VAL} -- the only four bits that differ from stock.
# Clear these out of the CURRENT value rather than writing CLAMP_STOCK literally: pre-POST
# this card reads 0xC0346500 and the two are the same write, but once the 580.xx driver has
# POSTed it PRIV_MISC_1 reads 0xC0B46500 -- bit 23 has been set by something downstream of
# devinit -- and writing the stock word would silently clear that too.  Only the clamp is
# ours to touch.
CYA_MASK = 0xC0006000
LNKCAP, LNKCAP2, LNKSTA, DEVICE = 0x088084, 0x0880A4, 0x088088, 0x08860C
MEM_SPACE_EN = 1 << 1
SPEED = {1: "2.5GT/s Gen1", 2: "5GT/s Gen2", 3: "8GT/s Gen3"}


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()


def pci(slot, off, width="w", val=None):
    c = "setpci -s %s CAP_EXP+%s.%s" % (slot, off, width)
    if val is not None:
        c += "=%0*x" % (4 if width == "w" else 8, val)
        subprocess.run(c, shell=True, check=True, capture_output=True)
        return None
    return int(sh(c), 16)


def linkstate(slot):
    sta = pci(slot, "12")
    return {"raw": "0x%04X" % sta, "speed": sta & 0xF, "width": (sta >> 4) & 0x3F}


def openbar(bdf, rw):
    cfg = "/sys/bus/pci/devices/%s/config" % bdf
    with open(cfg, "r+b", buffering=0) as f:
        f.seek(4); orig = struct.unpack("<H", f.read(2))[0]
        if not orig & MEM_SPACE_EN:
            f.seek(4); f.write(struct.pack("<H", orig | MEM_SPACE_EN))
    p = "/sys/bus/pci/devices/%s/resource0" % bdf
    fd = os.open(p, (os.O_RDWR if rw else os.O_RDONLY) | os.O_SYNC)
    mm = mmap.mmap(fd, min(os.path.getsize(p), 32 << 20), mmap.MAP_SHARED,
                   mmap.PROT_READ | (mmap.PROT_WRITE if rw else 0))
    os.close(fd)
    return mm


def bar_snapshot(bdf):
    mm = openbar(bdf, rw=False)
    rd = lambda o: struct.unpack_from("<I", mm, o)[0]
    s = {"PMC_BOOT_0": rd(0), "LNKCAP": rd(LNKCAP), "LNKCAP2": rd(LNKCAP2),
         "LNKSTA": rd(LNKSTA), "VSEC_DEVICE": rd(DEVICE), "PRIV_MISC_1": rd(PRIV_MISC_1)}
    mm.close()
    return s


def show(tag, bar, ep, up):
    print("  %-14s EP LnkSta %s x%-2d  |  UP LnkSta %s x%-2d  |  LNKCAP=0x%08X (max %s) "
          "PRIV_MISC_1=0x%08X"
          % (tag, SPEED.get(ep["speed"], "?"), ep["width"],
             SPEED.get(up["speed"], "?"), up["width"],
             bar["LNKCAP"], SPEED.get(bar["LNKCAP"] & 0xF, "?"), bar["PRIV_MISC_1"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bdf"); ap.add_argument("--apply", action="store_true")
    ap.add_argument("--target-gen", type=int, choices=(1, 2, 3),
                    help="also set the upstream port's LnkCtl2 Target Link Speed")
    a = ap.parse_args()

    slot = a.bdf.split(":", 1)[1] if a.bdf.startswith("0000:") else a.bdf
    up_full = os.path.basename(os.path.dirname(
        os.path.realpath("/sys/bus/pci/devices/%s" % a.bdf)))
    up = up_full.split(":", 1)[1]
    out = {"tool": "pcie_retrain_probe.py", "bdf": a.bdf, "upstream_port": up_full,
           "applied": a.apply, "target_gen": a.target_gen,
           "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    print("endpoint      %s" % a.bdf)
    print("upstream port %s  (%s)" % (up_full, sh("lspci -s %s" % up)[:70]))

    b0, e0, u0 = bar_snapshot(a.bdf), linkstate(slot), linkstate(up)
    upcap = pci(up, "0c", "l"); upctl2 = pci(up, "30")
    out["pre"] = {"bar": {k: "0x%08X" % v for k, v in b0.items()}, "ep": e0, "up": u0,
                  "up_lnkcap": "0x%08X" % upcap, "up_lnkctl2": "0x%04X" % upctl2}
    print("\n--- entry state ---")
    show("entry", b0, e0, u0)
    print("  upstream LnkCap max %s x%d ; LnkCtl2 Target Link Speed = %s"
          % (SPEED.get(upcap & 0xF, "?"), (upcap >> 4) & 0x3F,
             SPEED.get(upctl2 & 0xF, "?")))
    if b0["PMC_BOOT_0"] >> 20 != 0x140:
        print("ABORT: not a GV100"); sys.exit(1)

    if not a.apply:
        print("\n(dry run: pass --apply to clear the clamp and retrain)")
        print(json.dumps(out)); return

    keep = False
    try:
        # ---- 1. capability lift (proven in logs/56) --------------------------
        mm = openbar(a.bdf, rw=True)
        clamp_clear = b0["PRIV_MISC_1"] & ~CYA_MASK
        out["clamp_clear_value"] = "0x%08X" % clamp_clear
        out["clamp_stock_value"] = "0x%08X" % CLAMP_STOCK
        struct.pack_into("<I", mm, PRIV_MISC_1, clamp_clear)
        time.sleep(0.05)
        b1 = {"PMC_BOOT_0": struct.unpack_from("<I", mm, 0)[0],
              "LNKCAP": struct.unpack_from("<I", mm, LNKCAP)[0],
              "LNKCAP2": struct.unpack_from("<I", mm, LNKCAP2)[0],
              "LNKSTA": struct.unpack_from("<I", mm, LNKSTA)[0],
              "VSEC_DEVICE": struct.unpack_from("<I", mm, DEVICE)[0],
              "PRIV_MISC_1": struct.unpack_from("<I", mm, PRIV_MISC_1)[0]}
        mm.close()
        out["after_clamp_clear"] = {k: "0x%08X" % v for k, v in b1.items()}
        print("\n--- 1. clamp cleared: 0x%06X  0x%08X -> 0x%08X  (CYA mask 0x%08X; stock V100 word is 0x%08X) ---"
              % (PRIV_MISC_1, b0["PRIV_MISC_1"], clamp_clear, CYA_MASK, CLAMP_STOCK))
        show("lifted", b1, linkstate(slot), linkstate(up))
        if (b1["LNKCAP"] & 0xF) < 2:
            print("  ⛔ LNKCAP did not lift; aborting before touching link state")
            out["verdict"] = "ABORTED_NO_LIFT"; return

        # ---- 2. optional: raise the upstream port's target speed -------------
        if a.target_gen:
            new2 = (upctl2 & ~0xF) | a.target_gen
            print("\n--- 2. upstream LnkCtl2 Target Link Speed -> %s ---"
                  % SPEED[a.target_gen])
            pci(up, "30", "w", new2)
            got = pci(up, "30")
            out["up_lnkctl2_after"] = "0x%04X" % got
            print("  wrote 0x%04X, reads 0x%04X (target now %s)"
                  % (new2, got, SPEED.get(got & 0xF, "?")))

        # ---- 3. retrain from the UPSTREAM port -------------------------------
        ctl = pci(up, "10")
        print("\n--- 3. retrain: %s LnkCtl 0x%04X |= 0x20 ---" % (up_full, ctl))
        pci(up, "10", "w", ctl | 0x20)
        out["retrain_issued"] = True

        # ---- 4. poll ---------------------------------------------------------
        print("\n--- 4. polling link state ---")
        hist = []
        for t in (0.1, 0.3, 0.6, 1.0, 2.0, 3.0, 5.0):
            time.sleep(t if not hist else t - hist[-1][0])
            try:
                e, u = linkstate(slot), linkstate(up)
            except Exception as ex:
                print("  t=%4.1fs  ⛔ link state unreadable: %s" % (t, ex)); break
            hist.append((t, e, u))
            print("  t=%4.1fs  EP %s x%d   UP %s x%d"
                  % (t, SPEED.get(e["speed"], "?"), e["width"],
                     SPEED.get(u["speed"], "?"), u["width"]))
        out["poll"] = [{"t": t, "ep": e, "up": u} for t, e, u in hist]

        # ---- 5. verdict ------------------------------------------------------
        e2 = linkstate(slot)
        b2 = bar_snapshot(a.bdf)
        out["post"] = {"bar": {k: "0x%08X" % v for k, v in b2.items()}, "ep": e2,
                       "up": linkstate(up)}
        out["negotiated_speed_before"] = e0["speed"]
        out["negotiated_speed_after"] = e2["speed"]
        # keep whenever we are running faster than the STOCK Gen1 clamp -- not merely faster than
        # this invocation's entry state, or a failed Gen2->Gen3 attempt would restore the clamp
        # and throw away a Gen2 win already in hand.
        keep = e2["speed"] > 1
        print("\n--- verdict ---")
        print("  negotiated speed  %s  ->  %s" % (SPEED.get(e0["speed"], "?"),
                                                  SPEED.get(e2["speed"], "?")))
        print("  negotiated width  x%d -> x%d" % (e0["width"], e2["width"]))
        print("  PMC_BOOT_0 = 0x%08X  %s" % (b2["PMC_BOOT_0"],
              "healthy" if b2["PMC_BOOT_0"] == b0["PMC_BOOT_0"] else "⛔ CHANGED"))
        out["verdict"] = "SPEED_INCREASED" if keep else "NO_CHANGE"
        print("  ★ %s" % out["verdict"])
    finally:
        if not keep:
            try:
                mm = openbar(a.bdf, rw=True)
                struct.pack_into("<I", mm, PRIV_MISC_1, b0["PRIV_MISC_1"])
                mm.close()
                print("\n  clamp RESTORED to 0x%08X (no speed gain to preserve)"
                      % b0["PRIV_MISC_1"])
                out["clamp_restored"] = True
            except Exception as ex:
                print("\n  ⚠ could not restore clamp: %s" % ex)
                out["clamp_restored"] = False
        else:
            print("\n  clamp LEFT CLEARED to hold the trained speed; an SBR or reboot reverts it")
            out["clamp_restored"] = False
        print()
        print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
