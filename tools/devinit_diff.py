#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 duggasco
"""Diff two GV100 VBIOSes at the devinit register-write level. OFFLINE -- no hardware.

Byte-diffing two VBIOSes is useless on its own: version strings, board part numbers, signature
blobs and per-SKU tables swamp the signal (377 differing bytes in the legacy image alone between
this card and a stock Tesla V100). This decodes the devinit script's register writes instead and
compares only those, which reduces the same comparison to a handful of records.

Opcodes decoded (empirically derived from this ROM family, not from envytools' pre-Volta table):
    0x6E  INIT_NV_REG   [op][reg u32][mask u32][data u32]   reg = (reg & mask) | data
    0x7A  INIT_ZM_REG   [op][reg u32][value u32]            reg = value

⚠ This is a linear opcode scan, not a control-flow-aware disassembly: it finds records by their
shape, so a byte sequence inside data can decode as a spurious record. That is tolerable here
because the comparison is offset-aligned -- both ROMs are scanned identically and only records
present at the SAME file offset in both are compared, so spurious matches cancel.

★ On this card the result is 7 differing records out of 428 -- see
FINDINGS-2026-09-04-cmp100-vs-170hx-nerfs.md §5b.

usage: devinit_diff.py <rom-a> <rom-b> [--map gv100_reg_map.json] [--limit 0xE400]
"""
import argparse, json, os, struct, sys


def scan(d, limit):
    out = {}
    i = 0
    while i < limit - 13:
        if d[i] == 0x6E:
            reg, m, da = struct.unpack_from("<III", d, i + 1)
            if 0 < reg < 0x1000000:
                out[i] = ("INIT_NV_REG", reg, m, da)
                i += 13
                continue
        elif d[i] == 0x7A:
            reg, v = struct.unpack_from("<II", d, i + 1)
            if 0 < reg < 0x1000000:
                out[i] = ("INIT_ZM_REG", reg, v, None)
                i += 9
                continue
        i += 1
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a"); ap.add_argument("b")
    ap.add_argument("--map", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                  "gv100_reg_map.json"))
    ap.add_argument("--limit", type=lambda s: int(s, 0), default=0xE400,
                    help="scan limit; default is the legacy image length")
    ap.add_argument("--census", help="a reg_full_census json, to show the measured value")
    z = ap.parse_args()

    names = {}
    if os.path.exists(z.map):
        names = {k: v[0] for k, v in json.load(open(z.map))["regs"].items()}
    meas = {}
    if z.census and os.path.exists(z.census):
        meas = {k: v[2] for k, v in json.load(open(z.census))["regs"].items()}

    A, B = open(z.a, "rb").read(), open(z.b, "rb").read()
    a, b = scan(A, z.limit), scan(B, z.limit)
    common = sorted(set(a) & set(b))
    diff = [o for o in common if a[o] != b[o]]

    print("A = %s" % z.a)
    print("B = %s" % z.b)
    print("devinit register writes: A %d, B %d, at matching offsets %d, DIFFERING %d\n"
          % (len(a), len(b), len(common), len(diff)))
    for o in diff:
        ta, reg, m, da = a[o]
        tb, rb, mb, db = b[o]
        key = "0x%06X" % reg
        nm = names.get(key, "?").replace("NV_", "")
        print("  file 0x%06X  %s  %s  (%s)" % (o, key, nm, ta))
        if ta == "INIT_NV_REG":
            print("      A: mask=0x%08X data=0x%08X" % (m, da))
            print("      B: mask=0x%08X data=0x%08X" % (mb, db))
            print("      A replaces bits %s with %s"
                  % ([i for i in range(32) if not (m >> i) & 1],
                     [i for i in range(32) if (da >> i) & 1]))
        else:
            print("      A: value=0x%08X" % m)
            print("      B: value=0x%08X" % mb)
        if key in meas:
            print("      measured on card: %s" % meas[key])
        print()


if __name__ == "__main__":
    main()
