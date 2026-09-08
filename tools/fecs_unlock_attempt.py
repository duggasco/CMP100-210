#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright 2026 duggasco
"""Attempt to lift the SM speed-select throttle with a host-L0 write, and prove the outcome.

Context.  On a POSTed CMP 100-210, devinit leaves
  NV_PGRAPH_PRI_FECS_FEATURE_OVERRIDE_SM_SPEED_SELECT (0x409664) = 0x999
    -> IMLA/FMLA/DP all REDUCED_SPEED with all three OVERRIDE bits asserted
  NV_PGRAPH_PRI_FECS_FEATURE_READOUT (0x409660) bits 20/21/22 (DP/IMLA/FMLA) all 1
and measurement shows fp64 and the tensor cores running at exactly 1/16 of the CC 7.0
architectural rate while fp32/int32/fp16 run at full rate.

Its PLM 0x409650 reads 0x8F -- Volta 3-level layout, WRITE field 6:4 = 0 -- which means write
level 3 only.  So this write is EXPECTED TO BE REFUSED, and the point of running it is to hold
that expectation to the tree's own standard: a permissive-looking mask is not a capability and a
refusal is not a capability either, until a readback says which one happened.  If it is refused
the throttle needs the pass-54 L3 decode-trap stamp, i.e. a flash cycle.  If it LANDS, the
throttle is host-liftable and no exploit is needed.

Safety.  Writes exactly one register, one time, with a value that only CLEARS reduce bits (never
sets one).  Both the pre-value and the post-value are printed, and --restore writes the original
back.  0x409664 is not on the CLAUDE.md load-bearing denylist and an SBR re-runs devinit, so the
change is doubly reversible.  Every read is followed by a PMC_BOOT_0 canary check, because BAR0
reads taken through sysfs while RM owns the GPU return stale bus data once the PRI ring is
poisoned -- this tool stops rather than reporting a number it cannot trust.

usage: fecs_unlock_attempt.py <bdf> [--apply] [--restore]
"""
import argparse, mmap, os, struct, sys

REG, PLM, READOUT, BOOT0 = 0x409664, 0x409650, 0x409660, 0x000000
BOOT0_EXPECT = 0x140000A1
MEM_SPACE_EN = 1 << 1

OVR_FIELDS = [("IMLA", 0), ("IMLA_OVERRIDE", 3), ("FMLA", 4), ("FMLA_OVERRIDE", 7),
              ("DP", 8), ("DP_OVERRIDE", 11)]
RDO_FIELDS = [("DP", 20), ("IMLA", 21), ("FMLA", 22)]        # dev_ctxsw_firmware.h:3173-3181


def dec(v, t):
    return " ".join("%s=%d" % (n, (v >> b) & 1) for n, b in t)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bdf")
    ap.add_argument("--apply", action="store_true", help="actually issue the write")
    ap.add_argument("--restore", action="store_true", help="write 0x999 back")
    ap.add_argument("--value", type=lambda x: int(x, 0), default=0x888,
                    help="value to write (default 0x888 = the measured-good full-speed word)")
    a = ap.parse_args()

    cfg = "/sys/bus/pci/devices/%s/config" % a.bdf
    with open(cfg, "r+b", buffering=0) as f:
        f.seek(4); cmd = struct.unpack("<H", f.read(2))[0]
        if not cmd & MEM_SPACE_EN:
            f.seek(4); f.write(struct.pack("<H", cmd | MEM_SPACE_EN))

    p = "/sys/bus/pci/devices/%s/resource0" % a.bdf
    fd = os.open(p, (os.O_RDWR if (a.apply or a.restore) else os.O_RDONLY) | os.O_SYNC)
    prot = mmap.PROT_READ | (mmap.PROT_WRITE if (a.apply or a.restore) else 0)
    mm = mmap.mmap(fd, 16 << 20, mmap.MAP_SHARED, prot)
    os.close(fd)

    def canary(where):
        b = struct.unpack_from("<I", mm, BOOT0)[0]
        if b != BOOT0_EXPECT:
            print("!! PRI ring poisoned at %s: PMC_BOOT_0 reads 0x%08X, expected 0x%08X" %
                  (where, b, BOOT0_EXPECT))
            print("!! aborting -- no reading past this point can be trusted")
            sys.exit(2)

    def rd(off, where):
        canary("before " + where)
        v = struct.unpack_from("<I", mm, off)[0]
        canary("after " + where)
        return v

    plm = rd(PLM, "PLM")
    wr_lvl = (plm >> 4) & 7
    pre = rd(REG, "OVERRIDE")
    rdo = rd(READOUT, "READOUT")

    print("  PLM      0x%06X = 0x%08X   WRITE field 6:4 = %d => %s"
          % (PLM, plm, wr_lvl, "LEVEL 3 ONLY" if wr_lvl == 0 else "host-writable"))
    print("  OVERRIDE 0x%06X = 0x%08X   %s" % (REG, pre, dec(pre, OVR_FIELDS)))
    print("  READOUT  0x%06X = 0x%08X   %s  (1 = REDUCED_SPEED)"
          % (READOUT, rdo, dec(rdo, RDO_FIELDS)))

    if a.restore:
        target = 0x999
        what = "restore devinit's 0x999"
    else:
        # ★ 0x888, not 0x000.  0x888 is OVERRIDE=TRUE with every value field FULL_SPEED, and it
        # is the value pass 62 measured (fp64 0.441 -> 6.849, tensor 7.06 -> 101.77 TFLOP/s, both
        # numerically validated) and toggled live against 0x999.  This tool originally wrote
        # `pre & ~0x999` = 0x000, which ALSO clears the three OVERRIDE bits and so hands the
        # decision back to whatever the un-overridden source says -- never measured.  Use the
        # value that was.
        target = a.value
        what = "OVERRIDE=TRUE, IMLA/FMLA/DP all FULL_SPEED"

    if not (a.apply or a.restore):
        print("\n  dry run: would write 0x%08X (%s).  Re-run with --apply." % (target, what))
        return

    print("\n  writing 0x%08X to 0x%06X (%s)" % (target, REG, what))
    struct.pack_into("<I", mm, REG, target)
    post = rd(REG, "OVERRIDE after write")
    rdo2 = rd(READOUT, "READOUT after write")

    print("  OVERRIDE 0x%06X = 0x%08X   %s" % (REG, post, dec(post, OVR_FIELDS)))
    print("  READOUT  0x%06X = 0x%08X   %s" % (READOUT, rdo2, dec(rdo2, RDO_FIELDS)))

    if post == target and post != pre:
        print("\n  ==> LANDED.  The write took at L0 despite PLM write-level %d." % wr_lvl)
        print("      Re-run the pipe benchmark now; if fp64 moves off 2.00 FMA/SM/clk the")
        print("      throttle is host-liftable and needs no L3 primitive.")
    elif post == pre:
        print("\n  ==> REFUSED.  Register unchanged, exactly as PLM 0x%08X (write-L3-only)" % plm)
        print("      requires.  Lifting this needs the pass-54 decode-trap L3 stamp,")
        print("      i.e. a flash cycle -- see HANDOFF-2026-09-04-l3-opener.md.")
    else:
        print("\n  ==> PARTIAL/UNEXPECTED: wrote 0x%08X, read 0x%08X -- investigate."
              % (target, post))


if __name__ == "__main__":
    main()
