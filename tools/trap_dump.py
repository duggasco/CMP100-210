#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright 2026 duggasco
"""Dump the 22 GV100 PRI decode traps and diff against the pre-exploit stock state.

STRICTLY READ-ONLY (only the PCI COMMAND memory-enable bit is touched, and restored).

Why: pass 48's overflow chain wrote MATCH slot 14 (0x122438) and MATCH slot 10 (0x122428)
at L3, and the write capability of the flash died in that same interval.  Traps 10-19 are
NOT idle -- devinit arms them as stock silicon workarounds (14-18 are REDIRECT_ADDR entries
remapping 0x10Exxx -> 0x118xxx; 10/11 stamp PRIV_LEVEL; 12 DROPs; 19 FORCE_DEC_PHYS).
Clobbering a devinit-installed redirect can silently break a subsystem's register access,
which is a candidate cause for NV_UCODE_CMD_COMMAND_EWR (page program) hanging forever while
EID/ERD/EPROT still succeed.

So "slot 10/14 are armed" proves nothing -- they are armed on a clean card too.  The test is
whether their VALUES still match devinit's.  Stock reference below is from
logs/15-trap-full-survey.json, captured 2026-09-02 before any exploit fire.

Layout: base 0x122000, MATCH +0x400, MASK +0x480, DATA1 +0x500, DATA2 +0x580,
ACTION +0x600, PLM +0x700; slot stride 4; GV100 has DECODE_TRAP0..21.

usage: trap_dump.py [bdf]
"""
import json, mmap, os, struct, sys

B = 0x122000
OFF = {"MATCH": 0x400, "MASK": 0x480, "DATA1": 0x500, "DATA2": 0x580,
       "ACTION": 0x600, "PLM": 0x700}
NSLOT = 22

# --- stock values -------------------------------------------------------------
# Captured 2026-09-04 from the card AFTER the CH341A recovery, with the ROM verified
# at the baseline hash 722bcbd...f30c9 -- i.e. a known-good devinit-programmed state.
# This supersedes logs/15-trap-full-survey.json, whose DATA2 column reads 0 for every
# slot and is not trustworthy (it produced false positives on traps 15-18).
STOCK = {
    10: ("0x00418304", "0x3C000000", "0xC0000000", "0x00000000", "0x00100000", "0x0000048F"),
    11: ("0x00100CD8", "0x3C000000", "0xC0000000", "0x00000000", "0x00100000", "0x0000048F"),
    12: ("0x001FB300", "0xFC0000FF", "0x00000000", "0x00000000", "0x00000001", "0x0000038F"),
    14: ("0x00118200", "0xFC0000FF", "0x00000008", "0x00000000", "0x00002080", "0x00000F8F"),
    15: ("0x0010E500", "0xFC0000FF", "0x00118000", "0xFC0000FF", "0x00000040", "0x00000F8F"),
    16: ("0x0010E600", "0xFC0000FF", "0x00118100", "0xFC0000FF", "0x00000040", "0x00000F8F"),
    17: ("0x0010E700", "0xFC0000FF", "0x00118B00", "0xFC0000FF", "0x00000040", "0x00000F8F"),
    18: ("0x0010E800", "0xFC0003FF", "0x00118C00", "0xFC0003FF", "0x00000040", "0x00000F8F"),
    19: ("0x00124110", "0xFC00380F", "0x00000000", "0x00000000", "0x00000002", "0x00000F8F"),
    21: ("0x00000000", "0xFFFFFFFF", "0x00000000", "0x00000000", "0x00000020", "0x00000F8F"),
}
FIELDS = ("MATCH", "MASK", "DATA1", "DATA2", "ACTION", "PLM")
# slots the pass-48 chain wrote (chain words 0x122438 / 0x122428 = MATCH slots 14 / 10)
SUSPECT = (10, 14)


def main():
    bdf = sys.argv[1] if len(sys.argv) > 1 else "0000:13:00.0"
    cfg = "/sys/bus/pci/devices/%s/config" % bdf
    f = open(cfg, "r+b", buffering=0)
    f.seek(4)
    orig = struct.unpack("<H", f.read(2))[0]
    if not orig & 2:
        f.seek(4); f.write(struct.pack("<H", orig | 2))

    p = "/sys/bus/pci/devices/%s/resource0" % bdf
    fd = os.open(p, os.O_RDONLY | os.O_SYNC)
    mm = mmap.mmap(fd, min(os.path.getsize(p), 32 << 20), mmap.MAP_SHARED, mmap.PROT_READ)
    os.close(fd)
    rd = lambda o: struct.unpack_from("<I", mm, o)[0]

    print("PMC_BOOT_0 = 0x%08X   SCRATCH(5) = 0x%08X   SCRATCH(6) = 0x%08X"
          % (rd(0), rd(0x1594), rd(0x1598)))
    print()
    print("slot  MATCH       MASK        DATA1       DATA2       ACTION      PLM         vs stock")
    live, mismatches = {}, []
    for i in range(NSLOT):
        v = tuple("0x%08X" % rd(B + OFF[k] + i * 4) for k in FIELDS)
        live["trap%d" % i] = dict(zip(FIELDS, v))
        exp = STOCK.get(i, ("0x00000000",) * 5 + (None,))
        if i in STOCK:
            diff = [FIELDS[j] for j in range(5) if v[j] != exp[j]]
        else:
            diff = [FIELDS[j] for j in range(5) if int(v[j], 16) != 0]
        note = "ok" if not diff else "*** DIFFERS: " + ",".join(diff)
        if diff:
            mismatches.append((i, diff, v, exp))
        print("%4d  %s  %s%s" % (i, "  ".join(v), note,
                                 "   <-- pass-48 target" if i in SUSPECT else ""))

    print()
    if not mismatches:
        print("VERDICT: all 22 traps match the pre-exploit stock state.")
        print("  => devinit's silicon workarounds are intact; nothing is clobbered.")
    else:
        print("VERDICT: %d trap(s) differ from stock: %s" % (
            len(mismatches), ", ".join("trap%d" % i for i, _, _, _ in mismatches)))
        for i, diff, v, exp in mismatches:
            print("  trap%-2d %s" % (i, "  ".join(diff)))
            for j, fld in enumerate(FIELDS[:5]):
                if fld in diff:
                    print("     %-6s live=%s  stock=%s" % (fld, v[j], exp[j]))
        print()
        print("  NOTE: trap15 can read as MATCH=0x60022408 / MASK=0x1C000000 / ACTION=0x1 (DROP)")
        print("        immediately after an nvflash run -- that is transient PMU flash-service")
        print("        state, not damage.  SBR the card and re-read before concluding anything.")
        hit = [i for i, _, _, _ in mismatches if i in SUSPECT]
        if hit:
            print()
            print("  *** slots %s are exactly what the pass-48 chain wrote."
                  % ", ".join(str(i) for i in hit))
            print("  => an overflow chain has clobbered devinit's traps.  If the ROM still")
            print("     carries the payload this recurs on every boot and the PMU flash")
            print("     page-program path (EWR cmd 0x05) hangs -- the pass-48 lockout.")
            print("     It cannot be starved from the host (pass 49c); recovery is an")
            print("     external programmer.  Confirm with: nvflash --save --entire.")

    out = {"bdf": bdf, "read_only": True, "writes_performed": 0,
           "PMC_BOOT_0": "0x%08X" % rd(0),
           "SCRATCH_5": "0x%08X" % rd(0x1594), "SCRATCH_6": "0x%08X" % rd(0x1598),
           "traps": live,
           "mismatched_slots": [i for i, _, _, _ in mismatches]}
    mm.close()
    if not orig & 2:
        f.seek(4); f.write(struct.pack("<H", orig))
    f.close()
    with open("/tmp/trap-dump.json", "w") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    print("\n(json -> /tmp/trap-dump.json)")


if __name__ == "__main__":
    main()
