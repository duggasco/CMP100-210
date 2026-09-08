#!/usr/bin/env python3
"""Drive the pass-54 L3 opener: re-aim trap 20 and stamp host-L0 writes to LEVEL_3.

Requires `cand5.rom` resident and an SBR since, so the FWSECLIC chain has armed slot 20 with
PLM 0x0FFF / DATA1 0xC0000000 (LEVEL_3) / ACTION 0x00100000 (SET_PRIV_LEVEL).  With that in
place, any host write whose address matches MATCH (MASK 0xFC000000 = address exact) is stamped
LEVEL 3 and lands, including on write-L3-only registers.  MATCH is re-aimable from L0 because
the chain opened the slot's own PLM; the privileged pair (DATA1 level + ACTION.SET_PRIV_LEVEL)
is NOT re-armable from L0 (pass 53 interlock), so never clear those.

⛔ The window is PRE-POST.  Once RM initialises the GPU it reprograms every one of the 22 trap
slots for its own use -- slot 20 comes back MATCH=0, MASK=0, ACTION=0x8, PLM=0x078F -- and the
opener is gone until the next reset re-fires the chain.  Passes 52-55 never had a driver loaded
and so never saw this.

Each --write is issued twice: once with MATCH parked on a functionless address (the UNMATCHED
control, which must be refused) and once with MATCH on the target (which must land).  Reporting
only the second would not distinguish "the stamp worked" from "this register was writable all
along".  PMC_BOOT_0 is checked around every access.

usage:
  trap20_stamp.py <bdf> --status
  trap20_stamp.py <bdf> --write 0x409650=0xFF [--write ...]
"""
import argparse, mmap, os, struct, sys, time

BASE = 0x122000
SLOT = 20
MATCH  = BASE + 0x400 + SLOT * 4      # 0x122450
MASK   = BASE + 0x480 + SLOT * 4      # 0x1224D0
DATA1  = BASE + 0x500 + SLOT * 4      # 0x122550
ACTION = BASE + 0x600 + SLOT * 4      # 0x122650
PLM    = BASE + 0x700 + SLOT * 4      # 0x122750

PARK = 0x00122434                     # trap13 MATCH -- functionless, the chain's initial aim
WANT_ACTION, WANT_DATA1 = 0x00100000, 0xC0000000
BOOT0, BOOT0_EXPECT = 0x000000, 0x140000A1
MEM_SPACE_EN = 1 << 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bdf")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--write", action="append", default=[], metavar="ADDR=VAL")
    a = ap.parse_args()

    cfg = "/sys/bus/pci/devices/%s/config" % a.bdf
    with open(cfg, "r+b", buffering=0) as f:
        f.seek(4); c = struct.unpack("<H", f.read(2))[0]
        if not c & MEM_SPACE_EN:
            f.seek(4); f.write(struct.pack("<H", c | MEM_SPACE_EN))

    p = "/sys/bus/pci/devices/%s/resource0" % a.bdf
    fd = os.open(p, os.O_RDWR | os.O_SYNC)
    mm = mmap.mmap(fd, 16 << 20, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
    os.close(fd)

    def canary(w):
        b = struct.unpack_from("<I", mm, BOOT0)[0]
        if b != BOOT0_EXPECT:
            print("!! PRI ring poisoned at %s (PMC_BOOT_0 = 0x%08X) -- aborting" % (w, b))
            sys.exit(2)

    def rd(o, w="read"):
        canary("before " + w); v = struct.unpack_from("<I", mm, o)[0]; canary("after " + w)
        return v

    def wr(o, v):
        struct.pack_into("<I", mm, o, v); time.sleep(0.01)

    st = {n: rd(o, n) for n, o in
          (("MATCH", MATCH), ("MASK", MASK), ("DATA1", DATA1), ("ACTION", ACTION), ("PLM", PLM))}
    print("  trap20  MATCH=0x%08X MASK=0x%08X DATA1=0x%08X ACTION=0x%08X PLM=0x%08X"
          % (st["MATCH"], st["MASK"], st["DATA1"], st["ACTION"], st["PLM"]))
    armed = (st["DATA1"] == WANT_DATA1 and st["ACTION"] == WANT_ACTION
             and ((st["PLM"] >> 4) & 7) == 7 and ((st["PLM"] >> 8) & 0xF) & 1)
    print("  => %s  (need DATA1=0xC0000000, ACTION=0x00100000, PLM WRITE=7, TRAP_APPLICATION has L0)"
          % ("ARMED and host-editable" if armed else "NOT USABLE"))
    if a.status or not a.write:
        return
    if not armed:
        print("\n  refusing to proceed: SBR the card to re-fire the chain first.")
        sys.exit(1)

    for spec in a.write:
        tgt, val = spec.split("=")
        tgt, val = int(tgt, 0), int(val, 0)
        print("\n  ---- target 0x%06X <- 0x%08X ----" % (tgt, val))
        pre = rd(tgt, "target pre")
        print("     pre                       0x%08X" % pre)

        # control: MATCH parked elsewhere, so this write is unmatched and must be refused
        wr(MATCH, PARK)
        wr(tgt, val)
        unmatched = rd(tgt, "target unmatched")
        print("     unmatched (MATCH=0x%06X)  0x%08X   %s"
              % (PARK, unmatched, "REFUSED (expected)" if unmatched == pre else "LANDED -- not L3-gated!"))

        # stamped: aim MATCH at the target
        wr(MATCH, tgt)
        got = rd(MATCH, "MATCH readback")
        if got != tgt:
            print("     !! MATCH re-aim failed: wrote 0x%08X, reads 0x%08X" % (tgt, got))
            continue
        wr(tgt, val)
        stamped = rd(tgt, "target stamped")
        print("     stamped   (MATCH=0x%06X)  0x%08X   %s"
              % (tgt, stamped, "LANDED" if stamped == val else "STILL REFUSED"))

        if stamped == val and unmatched == pre:
            print("     ★ L3 stamp CONFIRMED: refused unmatched, landed matched.")
        elif stamped == val:
            print("     ⚠ landed, but the unmatched control also landed -- register was not L3-gated.")
        else:
            print("     ⛔ the stamp did not take.")

    print("\n  trap20 MATCH left at 0x%08X" % rd(MATCH, "final"))


if __name__ == "__main__":
    main()
