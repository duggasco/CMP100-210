#!/usr/bin/env python3
"""Locate and extract the FWSECLIC falcon ucode from any NVIDIA VBIOS. Host-side, read-only.

Anchors on the ucode's own DMEM constants rather than on the BIT / falcon-ucode-table
chain, because that chain's pointer arithmetic changes between generations (see the
`FalconUcodeTablePtr` gotcha in CLAUDE.md) while the format strings do not:

    "3s2bwbw4b3sw3sw3sw"   the 29-byte InfoROM *directory* format (3 magic/offset pairs)
    "3s2bwb"               INFOROM_OBJECT_HEADER_V1_00_FMT

Method: find those strings, then scan backwards for a `FALCON_UCODE_DESC` whose DMEM
window actually contains them. A descriptor is accepted only if its own fields are
self-consistent *and* it covers the string -- so the answer is checked, not guessed.

Descriptor layout (V2, 60 bytes; V1 is 48 with no vDesc word; V3 is 44):
   +0x00 vDesc (bits 23:16 = descriptor size)   +0x04 storedSize     +0x08 uncompressedSize
   +0x18 imemLoadSize   +0x1C imemVirtBase   +0x20 imemSecBase   +0x24 imemSecSize
   +0x28 dmemOffset     +0x30 dmemLoadSize

  fwseclic_extract.py <rom> [<rom> ...]            report what was found
  fwseclic_extract.py --dump <outdir> <rom> ...    also write <name>.imem / <name>.dmem
"""
import os
import struct
import sys

DIRFMT = b"3s2bwbw4b3sw3sw3sw\x00"
HDRFMT = b"3s2bwb\x00"


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


# FALCON_UCODE_DESC comes in two shapes in the wild.  V2/V3 lead with a vDesc
# word whose bits 23:16 give the descriptor size; V1 has no such word and is a
# flat 48 bytes.  Volta's PreOS ships V2; **GA100/GA102/AD10x PreOS ships V1**,
# which is why an earlier vDesc-only scan reported "no FWSECLIC descriptor" on
# every Ampere ROM (see FINDINGS-2026-09-06-preos-overflow-ports-to-ampere.md).
# Each layout is (field offset relative to the descriptor, descriptor size).
DESC_LAYOUTS = (
    ("V2", 4, (0x2C, 0x3C)),   # vDesc word present; size read out of it
    ("V1", 0, (0x30,)),        # no vDesc word; fixed 48-byte descriptor
)


def _fields(d, desc, off):
    """(stored, uncomp, imem_load, imem_vbase, imem_sbase, imem_sec_size,
    dmem_off, dmem_load) -- `off` is 4 past the vDesc word on V2/V3, 0 on V1."""
    return (u32(d, desc + off + 0x00), u32(d, desc + off + 0x04),
            u32(d, desc + off + 0x14), u32(d, desc + off + 0x18),
            u32(d, desc + off + 0x1C), u32(d, desc + off + 0x20),
            u32(d, desc + off + 0x24), u32(d, desc + off + 0x2C))


def candidates(d, target):
    """Descriptors whose DMEM window contains file offset `target`."""
    out = []
    for desc in range(max(0, target - 0x60000), target, 4):
        for ver, off, sizes in DESC_LAYOUTS:
            if off:
                v = u32(d, desc)
                dsize = (v >> 16) & 0xFF
                if dsize not in sizes or (v & 0xFF) not in (1, 2, 3):
                    continue
            else:
                dsize = sizes[0]
            if desc + dsize + 0x40 > len(d):
                continue
            (stored, uncomp, imem_load, imem_vbase, imem_sbase,
             imem_sec_size, dmem_off, dmem_load) = _fields(d, desc, off)
            if not (0x1000 <= stored <= 0x40000) or uncomp != stored:
                continue
            if imem_vbase != 0 or not (0x1000 <= imem_load <= 0x20000):
                continue
            if not (0x100 <= dmem_load <= 0x20000) or dmem_off != imem_load:
                continue
            if imem_load + dmem_load > stored:
                continue
            base = desc + dsize
            dmem0 = base + dmem_off
            if not (dmem0 <= target < dmem0 + dmem_load):
                continue
            out.append(dict(desc=desc, dsize=dsize, base=base, stored=stored,
                            imem_load=imem_load, imem_sbase=imem_sbase,
                            imem_sec_size=imem_sec_size, dmem_off=dmem_off,
                            dmem_load=dmem_load, dmem0=dmem0, desc_ver=ver))
    # V1's layout is V2's shifted down by the vDesc word, so a real V2
    # descriptor always aliases as a V1 four bytes later.  The V2 read is the
    # true one -- keep it and drop the alias, or the image base comes out 8
    # bytes low and every VA in the disassembly is wrong.
    v2 = {c["desc"] for c in out if c["desc_ver"] == "V2"}
    return [c for c in out
            if not (c["desc_ver"] == "V1" and c["desc"] - 4 in v2)]


def scan(path):
    d = open(path, "rb").read()
    found, seen = [], set()
    off = d.find(DIRFMT)
    while off != -1:
        for c in candidates(d, off):
            if c["desc"] in seen:
                continue
            seen.add(c["desc"])
            c["dirfmt_file"] = off
            c["dirfmt_dmem"] = off - c["dmem0"]
            h = d.find(HDRFMT, c["dmem0"], c["dmem0"] + c["dmem_load"])
            c["hdrfmt_dmem"] = (h - c["dmem0"]) if h != -1 else None
            c["imem"] = d[c["base"]:c["base"] + c["imem_load"]]
            c["dmem"] = d[c["dmem0"]:c["dmem0"] + c["dmem_load"]]
            found.append(c)
        off = d.find(DIRFMT, off + 1)
    return found


def main():
    args = sys.argv[1:]
    outdir = None
    if args and args[0] == "--dump":
        outdir, args = args[1], args[2:]
        os.makedirs(outdir, exist_ok=True)
    for path in args:
        name = os.path.basename(path)
        hits = scan(path)
        if not hits:
            print("%-46s  no FWSECLIC descriptor covers the format string" % name)
            continue
        for i, c in enumerate(hits):
            print("%-40s %s desc@0x%06X sz=%d base=0x%06X imem=0x%05X "
                  "sec@0x%04X/0x%05X %s dmem@0x%06X len=0x%05X  "
                  "dirfmt@DMEM 0x%04X hdrfmt@DMEM %s"
                  % (name, c["desc_ver"], c["desc"], c["dsize"], c["base"],
                     c["imem_load"], c["imem_sbase"], c["imem_sec_size"],
                     "HS" if c["imem_sec_size"] else "NS",
                     c["dmem0"], c["dmem_load"], c["dirfmt_dmem"],
                     "0x%04X" % c["hdrfmt_dmem"] if c["hdrfmt_dmem"] is not None else "-"))
            if outdir:
                stem = os.path.join(outdir, "%s.%d" % (name, i))
                open(stem + ".imem", "wb").write(c["imem"])
                open(stem + ".dmem", "wb").write(c["dmem"])
                open(stem + ".meta", "w").write(
                    "\n".join("%s=0x%X" % (k, v) for k, v in c.items()
                              if isinstance(v, int)) + "\n")


if __name__ == "__main__":
    main()
