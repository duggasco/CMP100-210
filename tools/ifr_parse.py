#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 duggasco
"""Parse the NVGI IFR prefix (the 0xA00 bytes hidden below the NV_PROM aperture). OFFLINE.

Input is the blob from tools/ifr_dump.py. The IFR is the pre-devinit init-from-ROM phase: it runs
before PCIe link training, which is why it -- not devinit -- is where per-SKU PCIe configuration
is installed.

Record format, derived empirically from this image (the header's own fields validate it: the NVGI
header at 0x00 is followed at 0x10 by the record 0xE208 <- 0x00000A00, i.e. the aperture skew this
very dump had to undo):

    [addr u32][...]      low 2 bits of addr are a tag (always 0b10 here); reg = addr & 0x00FFFFFC
    flag = addr >> 24
      flag & 0x02  ->  12 bytes: (addr, and_mask, or_data)   reg = (reg & and) | or
      else         ->   8 bytes: (addr, value)               reg = value

⚠ DERIVED, not from NVIDIA documentation. The evidence it is right: with these lengths the record
stream stays self-consistent for the whole populated region and every decoded address lands on a
real register in the GV100 map; with fixed 12-byte records it desynchronises after six entries.
Treat individual exotic records with suspicion; the PCIe ones below are corroborated on silicon.

usage: ifr_parse.py <ifr-prefix.bin> [--map gv100_reg_map.json] [--grep 08841C,08C040]
"""
import argparse, json, os, struct, sys


def parse(d):
    # ★ The record region is bounded by the NVGI header's length field at +0x08 (0x86C here);
    # everything above it is 0xFF erased fill. Parsing past it manufactures phantom records --
    # the first cut of this tool "found" 237 records by walking 0xFF into the tail. The last real
    # record is 0xE208 <- EN=1 (the IFR turning on the very ROM aperture this was dumped through),
    # which is a satisfying self-check that the bound is right.
    import struct as _s
    end = min(len(d), _s.unpack_from("<I", d, 0x08)[0] or len(d))
    recs, off = [], 0x10          # records start right after the 16-byte NVGI header
    while off + 8 <= end:
        a = struct.unpack_from("<I", d, off)[0]
        if a == 0:
            off += 4
            continue
        flag, reg = a >> 24, a & 0x00FFFFFC
        if flag & 0x02:
            if off + 12 > end:
                break
            m, v = struct.unpack_from("<II", d, off + 4)
            recs.append((off, a, reg, "RMW", m, v)); off += 12
        else:
            v = struct.unpack_from("<I", d, off + 4)[0]
            recs.append((off, a, reg, "SET", None, v)); off += 8
    return recs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("blob")
    ap.add_argument("--map", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                  "gv100_reg_map.json"))
    ap.add_argument("--grep", help="comma-separated hex register addresses to highlight")
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()

    names = {}
    if os.path.exists(a.map):
        names = {int(k, 16): v[0] for k, v in json.load(open(a.map))["regs"].items()}
    d = open(a.blob, "rb").read()
    if d[:4] != b"NVGI":
        print("⛔ not an NVGI block"); sys.exit(1)
    recs = parse(d)
    want = set()
    if a.grep:
        want = {int(x, 16) & ~3 for x in a.grep.replace("0x", "").split(",")}

    import struct as _s2
    _end = _s2.unpack_from("<I", d, 0x08)[0]
    print("NVGI IFR prefix: %d bytes; record region 0x10-0x%X; 0x%X-0x%X is 0xFF erased fill "
          "(%d bytes free); %d records"
          % (len(d), _end, _end, len(d), len(d) - _end, len(recs)))
    blocks = {}
    for _, _, reg, *_ in recs:
        blocks[reg & 0xFFF000] = blocks.get(reg & 0xFFF000, 0) + 1
    print("records by BAR0 block:")
    for b, n in sorted(blocks.items(), key=lambda x: -x[1])[:12]:
        print("   0x%06X-  %3d" % (b, n))
    print()
    for off, addr, reg, kind, m, v in recs:
        hit = reg in want
        if not (a.all or hit):
            continue
        nm = names.get(reg, "?").replace("NV_", "")
        if kind == "RMW":
            body = "and=0x%08X or=0x%08X   => clears 0x%08X, sets 0x%08X" % (
                m, v, (~m) & 0xFFFFFFFF, v)
        else:
            body = "value=0x%08X" % v
        print("%s@%04X  reg 0x%06X  %-52s %s  %s"
              % ("★ " if hit else "  ", off, reg, nm[:52], kind, body))
    if want:
        found = {r for _, _, r, *_ in recs} & want
        print()
        for w in sorted(want):
            print("  %s 0x%06X %s" % ("FOUND  " if w in found else "ABSENT ", w,
                                      names.get(w, "?").replace("NV_", "")))


if __name__ == "__main__":
    main()
