#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 duggasco
"""Walk a GV100 VBIOS the way FWSECLIC does, and report the InfoROM objects it feeds
to the unbounded copy at IMEM VA 0x607E.  Host-side, read-only, no hardware.

This is a byte-for-byte re-implementation of three FWSECLIC routines
(`disasm/fwseclic_imem.asm`, IMEM base = file 0x033394):

  0x5EC6  scan the ROM in 512-byte steps for an image whose PCIR/NPDS/RGIS record
          has code type 0x70, then find its NBSI block and check the "RI" tag.
          Returns nbsi + 0x10 + nbsi.size.
  0x5E57  from (that - 0x10), follow `next = cur + u32@(cur+0xA)` while the tag
          u16@(cur+8) is "BI", and stop on "LU".  Returns cur + 0x10.
  0x607E  read 29 bytes there and parse them with the ucode-constant format
          "3s2bwbw4b3sw3sw3sw" -- a header plus three (3-char magic, u16 offset)
          directory entries.  For a magic the caller asks for, the object lives at
          dirbase + offset and starts with an INFOROM_OBJECT_HEADER_V1_00
          ("3s2bwb", NVIDIA's own format string), whose u16 at packed offset 5 is
          the object size.  ★ That u16 is the copy length, unchecked.

Confirmed against NVIDIA source in the Lapsus archive
(`drivers/resman/arch/nvalloc/common/inc/inforom/types.h`):
    INFOROM_OBJECT_HEADER_V1_00_FMT          "3s2bwb"
    INFOROM_OBJECT_HEADER_V1_00_SIZE_OFFSET  0x05
    INFOROM_OBJECT_HEADER_V1_00_PACKED_SIZE  8

usage: inforom_walk.py <rom-file>
"""
import struct
import sys

# FWSECLIC DMEM constants (image at file 0x03A008)
FMT_DIR = "3s2bwbw4b3sw3sw3sw"      # DMEM 0x129C -- 29 bytes packed, 24 slots
FMT_HDR = "3s2bwb"                  # DMEM 0x12AF -- INFOROM_OBJECT_HEADER_V1_00
# (magic, format used by the caller, destination buffer, next global above it)
CALLERS = [
    ("ULF", "3s2bwb278d",  0x49D9, 0x4E3C, "0x6333 in fn 0x62FE  (uGPU stage)"),
    ("UPR", "3s2bwb4b25d", 0x49D9, 0x4A4C, "0x635C in fn 0x62FE  (uGPU stage)"),
    ("HLK", "3s2bwb278d",  0x49D9, 0x4E3C, "0x624C via fn 0x6291 (HULK stage)"),
]


def fmt_data_size(fmt):
    """Packed size of a vbios format string, per fn 0x5BB9."""
    n = 0
    total = 0
    for ch in fmt:
        if ch.isdigit():
            n = n * 10 + int(ch)
            continue
        cnt = n or 1
        total += cnt * {'b': 1, 's': 1, 'w': 2, 'd': 4, 'q': 8, 't': 3}[ch]
        n = 0
    return total


def rd(d, off, n):
    return int.from_bytes(d[off:off + n], 'little')


def find_nbsi(d):
    """fn 0x5EC6.  Note the ucode does NOT stop at the first hit -- it keeps
    scanning and the last NBSI-bearing code-type-0x70 image wins."""
    pos = blocks = 0
    log = []
    result = None
    for _ in range(64):
        pos = (pos + ((blocks & 0xFFFF) << 9)) & 0xFFFFFFFF
        sig = rd(d, pos, 2)
        if sig not in (0xAA55, 0x4E56, 0xBB77):
            log.append("0x%06x: bad image signature 0x%04x -- ucode would spin" % (pos, sig))
            break
        pcir_off = rd(d, pos + 0x18, 2) & 0xFFFF
        pcir = pos + pcir_off
        if rd(d, pcir, 4) not in (0x52494350, 0x5344504E, 0x53494752):
            log.append("0x%06x: no PCIR/NPDS/RGIS at 0x%06x" % (pos, pcir))
            break
        pcir_len = rd(d, pcir + 0xA, 2) & 0xFFFF
        blocks = rd(d, pcir + 0x10, 4)
        code_type = d[pcir + 0x14]
        indicator = d[pcir + 0x15]
        aligned_off = (pcir_off + 0xF + pcir_len) & ~0xF
        npde = pos + aligned_off
        if rd(d, npde, 4) == 0x4544504E:                      # "NPDE"
            blocks = rd(d, npde + 8, 2)
            indicator = d[npde + 0xA]
        note = ""
        if code_type == 0x70:                                 # NBSI-bearing image
            alt = rd(d, pos + 0x16, 2) & 0xFFFF
            off = aligned_off
            if rd(d, npde, 4) != 0x4E425349 and rd(d, pos + alt, 4) == 0x4E425349:
                off = alt
            nbsi = pos + off
            if rd(d, nbsi, 4) != 0x4E425349:
                note = "  code 0x70, no NBSI at 0x%06x" % nbsi
            elif rd(d, nbsi + 0xA, 2) != 0x4952:              # "RI"
                note = "  code 0x70, NBSI 0x%06x lacks RI tag" % nbsi
            else:
                result = nbsi + 0x10 + rd(d, nbsi + 4, 4)
                note = "  ** NBSI at 0x%06x, RI ok -> 0x%06x **" % (nbsi, result)
        log.append("0x%06x sig=0x%04x %-4s blocks=0x%-4x codetype=0x%02x ind=0x%02x%s"
                   % (pos, sig, d[pcir:pcir + 4].decode('latin1'),
                      blocks & 0xFFFF, code_type, indicator, note))
        if indicator & 0x80:
            break
    return result, log


def walk_chain(d, start):
    """fn 0x5E57 -- returns (dirbase, [(addr, tag)])."""
    cur = start - 0x10
    trail = []
    for _ in range(8):
        cur = (cur + rd(d, cur + 0xA, 4)) & 0xFFFFFFFF
        tag = d[cur + 8:cur + 10].decode('latin1')
        trail.append((cur, tag))
        if tag == "LU":
            return cur + 0x10, trail
        if tag != "BI":
            return None, trail
    return None, trail


def main():
    d = open(sys.argv[1], 'rb').read()
    print("rom: %s  (0x%x bytes)\n" % (sys.argv[1], len(d)))

    ptr, log = find_nbsi(d)
    print("0x5EC6  ROM image walk:")
    for line in log:
        print("          " + line)
    if ptr is None:
        print("0x5EC6 FAILED -- no NBSI found")
        return 1
    print("0x5EC6  -> 0x%06x\n" % ptr)

    dirbase, trail = walk_chain(d, ptr)
    print("0x5E57  chain from 0x%06x:" % (ptr - 0x10))
    for a, t in trail:
        print("          0x%06x  tag %-4r  next += 0x%08x" % (a, t, rd(d, a + 0xA, 4)))
    if dirbase is None:
        print("0x5E57 FAILED")
        return 1
    print("0x5E57  -> directory base 0x%06x\n" % dirbase)

    raw = d[dirbase:dirbase + 29]
    print("0x607E  29-byte directory, format %r:" % FMT_DIR)
    print("          %s" % raw.hex(' '))
    print("          type=%r ver=%d subver=%d size=0x%04x"
          % (raw[0:3].decode('latin1'), raw[3], raw[4], rd(raw, 5, 2)))
    entries = {}
    for i in range(3):
        o = 14 + i * 5
        mag = raw[o:o + 3].decode('latin1')
        off = rd(raw, o + 3, 2)
        entries[mag] = off
        print("          entry %d: magic %-5r offset 0x%04x -> 0x%06x"
              % (i, mag, off, dirbase + off))
    print()

    print("0x607E  copy length vs destination, per caller:")
    print("  %-5s %-13s %8s %8s %8s %9s  %s"
          % ("magic", "format", "fmt size", "declared", "dest", "headroom", "verdict"))
    for mag, fmt, dest, nxt, where in CALLERS:
        room = nxt - dest
        fsz = fmt_data_size(fmt)
        if mag not in entries:
            print("  %-5s %-13s %8d %8s %8s %9d  magic ABSENT from directory"
                  % (mag, fmt, fsz, "-", "-", room))
            continue
        obj = dirbase + entries[mag]
        size = rd(d, obj + 5, 2)
        ok = "fits (%d spare)" % (room - size) if size <= room else "OVERFLOW by %d" % (size - room)
        print("  %-5s %-13s %8d %8d %8s %9d  %s"
              % (mag, fmt, fsz, size, "0x%04X" % dest, room, ok))
        print("        object at 0x%06x  hdr=%s  called from %s"
              % (obj, d[obj:obj + 8].hex(' '), where))
    print()
    print("The declared size is a U16 (max 0xFFFF).  Nothing between the ROM byte and")
    print("the copy compares it against the destination -- see FINDINGS fwseclic-audit.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
