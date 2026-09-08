#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 duggasco
"""Is THIS card's ROM compatible with the CMP 100-210 unlock kit?  OFFLINE, read-only.

Run this on a dump taken from the target card **before** doing anything to it.  Everything the
kit does is keyed to properties of the resident firmware, and every one of them can differ on
another card even of the same model:

  * the InfoROM directory address -- it is reached by walking a per-card object chain
    (`0x5E57`), so the ULF object the payload is written into is at a DIFFERENT aperture
    offset on a different card.  `build_payload.py` used to hardcode this card's 0x04162D.
  * the FWSECLIC build -- every gadget VA, the DMEM buffer at 0x49D9, the return slot at
    0x9ED8 and the canary constant belong to ONE ucode build.  A different VBIOS branch
    moves them, and a chain built for the wrong build is a jump to an arbitrary address at
    level 3.
  * which nerfs are actually present -- the five devinit words are per-SKU.  A card that is
    not throttled needs no fp64 unlock, and a card whose throttle word differs is telling you
    the recipe was not derived for it.
  * the IFR width record -- its offset is not fixed either, and it is the one edit in this
    kit that can stop a card enumerating.

usage:
  rom_compat.py <rom-dump> [--reference <known-good.rom>] [--json]

The dump may be either shape and the tool detects which:
  * PHYSICAL  -- `nvflash --save --entire`, starts with the "NVGI" IFR magic at 0x0.
    Aperture offset A lives at file offset A + 0xA00.  ★ This shape is required for the
    IFR/width check; nothing else needs it.
  * APERTURE  -- a raw BAR0 NV_PROM read, starts with the 0x55AA PCI ROM signature.
    The IFR is invisible through the aperture by construction (ROM_ADDR_OFFSET hides it).

Exit status is 0 if at least one unlock is GO, 2 if none are, 1 on a malformed input.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fwseclic_extract as fx
import inforom_walk as iw
from devinit_diff import scan as devinit_scan
from ifr_parse import parse as ifr_parse

APERTURE_SKEW = 0xA00

# --- the reference build this kit was derived on -------------------------------------------
# CMP 100-210, VBIOS 88.00.51.00.04, PG500 SKU 111.  The IMEM hash is the strict gate; the
# per-VA signatures below are the diagnostic that says WHICH part moved when it fails.
REF_IMEM_SHA = "96c620510890e40b"          # first 16 hex of sha256(FWSECLIC IMEM image)
REF_VBIOS = "88.00.51.00.04"

# VA -> (expected bytes, what it is).  Indexed straight into the IMEM image, which starts at
# VA 0 -- ⚠ that is only true because fwseclic_extract keeps the 1024-byte NS bootloader; a
# body-only extraction puts every VA 0x400 low (CLAUDE.md IMAGE-BASE HAZARD).
GADGETS = {
    0x2294: ("89603c00", "PRI-write helper: mov $r9 0x3c60"),
    0x22C5: ("b21a",     "chain gadget: mov b32 $r10 $r1   (address)"),
    0x22C7: ("b20b",     "chain gadget: mov b32 $r11 $r0   (value)"),
    0x22C9: ("7e942200", "chain gadget: lcall 0x2294       (the PRI write)"),
    0x22CD: ("fb11",     "chain gadget: mpopret $r1        (next link)"),
    0x607E: ("8fb00100", "the unbounded copy's frame: mov $r15 0x1b0 (canary load)"),
    0x62FE: ("8fb00100", "uGPU stage, the caller whose frame we return into"),
    0x5908: ("b3a00035", "resume continuation -- where the chain hands control back"),
}
RESUME_GADGETS = {
    0x2A04: ("fb0530", 0x34, "mpopaddret $r0 0x30", 2),
    0x49BD: ("fb61",   0x1C, "mpopret $r6",         4),
    0x41AC: ("fb31",   0x10, "mpopret $r3",         5),
    0x42A3: ("fb31",   0x10, "mpopret $r3 (alt)",   5),
    0x288C: ("fb31",   0x10, "mpopret $r3 (alt)",   5),
    0x046A: ("fb01",   0x04, "mpopret $r0",         6),
}
KIT_RESUME = 0x41AC          # the 5-link geometry UNLOCK4 is built in
CANARY_DMEM, CANARY_VALUE = 0x1B0, 0x00006BD1
BUF_DMEM = 0x49D9            # copy destination; the object's declared size is unchecked against it

# --- the five devinit nerf words ------------------------------------------------------------
# (register, name, the CMP value, the stock Tesla V100 value, which unlock it drives)
NERFS = [
    (0x409664, "PGRAPH_FECS_FEATURE_OVERRIDE_SM_SPEED_SELECT", 0x00000999, 0x00000000, "fp64+tensor"),
    (0x98BC98, "PFB_FBPA_FBIO_HBMPLL_COEFF",                   0x00013C02, 0x00014102, "memclk"),
    (0x088610, "XVE_VSEC_NVIDIA_SPECIFIC_FEATURES_HIERARCHY",  0x00000000, 0x00001001, "pcie gen3"),
    (0x021968, "FUSE_CTRL_OPT_NVENC",                          0x00000007, 0x00000000, "nvenc (closed)"),
    (0x021824, "FUSE_CTRL_OPT_NVDEC",                          0x00000001, 0x00000000, "nvdec (closed)"),
]
WIDTH_REG = 0x08C040         # XP_PL_LINK_CONFIG_0 -- the IFR record that forces x1
WIDTH_SAFE_REG = 0x08C000    # XP_PL_LINK_PRESENT  -- read-only; retarget the record here


def ndiv_mhz(coeff):
    """HBMPLL_COEFF -> MHz.  MDIV 7:0, NDIV 15:8, PLDIV 21:16; 27 MHz xtal, /2 for the pair."""
    mdiv, ndiv, pldiv = coeff & 0xFF, (coeff >> 8) & 0xFF, (coeff >> 16) & 0x3F
    if not (mdiv and pldiv):
        return None, ndiv
    return 27.0 * ndiv / mdiv / pldiv / 2 * 2, ndiv     # 27*65/2/1/2*2 = 877.5


class Rom:
    def __init__(self, path):
        self.path = path
        self.d = open(path, "rb").read()
        if self.d[:4] == b"NVGI":
            self.kind, self.base = "physical", APERTURE_SKEW
        elif self.d[:2] == b"\x55\xaa":
            self.kind, self.base = "aperture", 0
        else:
            raise SystemExit("%s: not a GV100 ROM dump -- starts %s, expected 'NVGI' (physical, "
                             "from nvflash --save --entire) or 55 AA (aperture, from a BAR0 read)"
                             % (path, self.d[:4].hex()))
        self.ap = self.d[self.base:]          # the aperture view, offset 0 == aperture 0

    def phys(self, ap_off):
        return ap_off + APERTURE_SKEW


def check_identity(rom, out):
    m = re.search(rb"Version ([0-9A-F]{2}\.[0-9A-F]{2}\.[0-9A-F]{2}\.[0-9A-F]{2}\.[0-9A-F]{2})", rom.ap[:0x2000])
    b = re.search(rb"(P[GN]\d{3}[^\x00\r\n]{0,40})", rom.ap[:0x2000])
    out["vbios"] = m.group(1).decode() if m else None
    out["board"] = b.group(1).decode().strip() if b else None
    out["size"] = len(rom.d)
    out["kind"] = rom.kind
    out["sha256"] = hashlib.sha256(rom.d).hexdigest()


def check_fwseclic(rom, out):
    hits = fx.scan(rom.path)
    if not hits:
        out["fwseclic"] = {"found": False}
        return None
    c = max(hits, key=lambda h: h["imem_load"])
    im = c["imem"]
    sha = hashlib.sha256(im).hexdigest()
    bad = {}
    for va, (want, what) in sorted(GADGETS.items()):
        got = im[va:va + len(want) // 2].hex()
        if got != want:
            bad["0x%04X" % va] = {"want": want, "got": got, "what": what}
    resumes = {}
    for va, (want, pop, name, links) in sorted(RESUME_GADGETS.items()):
        resumes["0x%04X" % va] = im[va:va + len(want) // 2].hex() == want
    canary = struct.unpack_from("<I", c["dmem"], CANARY_DMEM)[0] if len(c["dmem"]) > CANARY_DMEM + 4 else None
    out["fwseclic"] = {
        "found": True, "desc_ver": c["desc_ver"], "file_base": c["base"],
        "imem_len": c["imem_load"], "dmem_len": c["dmem_load"],
        "imem_sha16": sha[:16], "imem_sha256": sha,
        "matches_reference_build": sha[:16] == REF_IMEM_SHA,
        "gadget_mismatches": bad,
        "resume_gadgets_present": resumes,
        "canary_dmem_0x1B0": canary,
        "canary_ok": canary == CANARY_VALUE,
    }
    return c


def check_inforom(rom, out):
    d = rom.ap
    start, log = iw.find_nbsi(d)
    info = {"walk": log}
    if start is None:
        info["found"] = False
        out["inforom"] = info
        return
    dirbase, trail = iw.walk_chain(d, start)
    info["chain"] = ["0x%06X %s" % (a, t) for a, t in trail]
    if dirbase is None:
        info["found"] = False
        out["inforom"] = info
        return
    hdr = struct.unpack_from("<3sBBHB", d, dirbase)
    # Directory format "3s2bwbw4b3sw3sw3sw": an 8-byte INFOROM_OBJECT_HEADER_V1_00 ('LIC',
    # ver, subver, u16 size, checksum) then a u16 and 4 bytes of padding, so the three
    # (3-char magic, u16 offset) entries begin at +14, not at +8.
    entries = {}
    for i in range(3):
        o = dirbase + 14 + i * 5
        magic, off = struct.unpack_from("<3sH", d, o)
        ap_off = dirbase + off
        osize = struct.unpack_from("<H", d, ap_off + 5)[0]
        entries[magic.decode("latin1")] = {
            "aperture": ap_off, "physical": rom.phys(ap_off),
            "declared_size": osize,
            "header": d[ap_off:ap_off + 8].hex(),
        }
    info.update({"found": True, "dirbase_aperture": dirbase,
                 "dirbase_physical": rom.phys(dirbase),
                 "dir_type": hdr[0].decode("latin1"), "entries": entries})
    out["inforom"] = info


def check_devinit(rom, out):
    recs = devinit_scan(rom.ap, 0xE400)
    by_reg = {}
    for off, (kind, reg, m, da) in recs.items():
        by_reg.setdefault(reg, []).append((off, kind, m, da))
    found = []
    for reg, name, cmp_val, stock_val, drives in NERFS:
        hit = by_reg.get(reg)
        e = {"reg": "0x%06X" % reg, "name": name, "drives": drives,
             "expected_cmp_value": "0x%08X" % cmp_val, "stock_v100_value": "0x%08X" % stock_val}
        if not hit:
            e["present"] = False
        else:
            off, kind, m, da = hit[0]
            val = da if kind == "INIT_NV_REG" else m
            e.update({"present": True, "kind": kind, "aperture": off,
                      "physical": rom.phys(off), "value": "0x%08X" % val,
                      "matches_cmp_recipe": val == cmp_val,
                      "already_stock": val == stock_val})
            if reg == 0x98BC98:
                mhz, nd = ndiv_mhz(val)
                e["ndiv"] = nd
                e["mhz"] = mhz
        found.append(e)
    out["devinit"] = {"records_scanned": len(recs), "nerfs": found}


def check_ifr(rom, out):
    if rom.kind != "physical":
        out["ifr"] = {"available": False,
                      "why": "aperture dump -- the IFR lives below the aperture and is not in "
                             "this file.  Re-dump with `nvflash --save --entire`."}
        return
    recs = ifr_parse(rom.d[:APERTURE_SKEW])
    hits = []
    for off, a, reg, kind, m, v in recs:
        if reg == WIDTH_REG:
            spec = (v >> 27) & 0x1F if kind == "RMW" else None
            hits.append({"physical": off, "kind": kind,
                         "and_mask": "0x%08X" % m if m is not None else None,
                         "or_data": "0x%08X" % v,
                         "link_specifier": spec,
                         "forces_x1": spec == 0x01,
                         "edit": {"physical": off, "from": "0x%02X" % rom.d[off],
                                  "to": "0x%02X" % (rom.d[off] & ~0x40 & 0xFF),
                                  "pure_1_to_0": bool(rom.d[off] & 0x40),
                                  "retargets_to": "0x%06X" % WIDTH_SAFE_REG}})
    out["ifr"] = {"available": True, "records": len(recs), "width_records": hits}


def verdicts(out):
    v = {}
    f = out.get("fwseclic", {})
    ir = out.get("inforom", {})
    ulf = ir.get("entries", {}).get("ULF") if ir.get("found") else None
    l3_reasons = []
    if not f.get("found"):
        l3_reasons.append("no FWSECLIC ucode found in this image")
    else:
        if not f["matches_reference_build"]:
            l3_reasons.append("FWSECLIC build differs from the reference (%s vs %s)"
                              % (f["imem_sha16"], REF_IMEM_SHA))
        if f["gadget_mismatches"]:
            l3_reasons.append("%d gadget signature(s) do not match: %s"
                              % (len(f["gadget_mismatches"]), ", ".join(f["gadget_mismatches"])))
        if not f["canary_ok"]:
            l3_reasons.append("stack canary constant D[0x1B0] is 0x%08X, expected 0x%08X"
                              % (f["canary_dmem_0x1B0"] or 0, CANARY_VALUE))
        if not f["resume_gadgets_present"].get("0x%04X" % KIT_RESUME):
            l3_reasons.append("the 5-link resume gadget 0x%04X is absent" % KIT_RESUME)
    if not ulf:
        l3_reasons.append("the InfoROM ULF object could not be located")
    elif ulf["declared_size"] != 1120:
        l3_reasons.append("ULF declared size is %d, expected 1120 -- the object layout differs"
                          % ulf["declared_size"])
    v["l3_opener"] = {"go": not l3_reasons, "blockers": l3_reasons}

    nerf = {n["drives"]: n for n in out["devinit"]["nerfs"]}
    def dv(key, needs_l3):
        n = nerf[key]
        r = []
        if not n["present"]:
            r.append("this VBIOS has no %s devinit record -- either not this SKU, or a "
                     "different branch" % n["name"])
        elif n.get("already_stock"):
            r.append("already at the stock value -- nothing to unlock")
        elif not n["matches_cmp_recipe"]:
            r.append("record present but the value is %s, not the %s this recipe was derived "
                     "for -- re-derive before trusting the numbers"
                     % (n["value"], n["expected_cmp_value"]))
        if needs_l3 and not v["l3_opener"]["go"]:
            r.append("needs the L3 opener, which is NO-GO above")
        return {"go": not r, "blockers": r, "record": n}
    v["fp64_tensor"] = dv("fp64+tensor", needs_l3=True)
    v["memclk"] = dv("memclk", needs_l3=False)
    v["pcie_gen3"] = dv("pcie gen3", needs_l3=False)

    ifr = out.get("ifr", {})
    r = []
    if not ifr.get("available"):
        r.append(ifr.get("why", "no IFR in this dump"))
    elif not ifr["width_records"]:
        r.append("no IFR record targets 0x%06X -- this card's width is not set there" % WIDTH_REG)
    elif not any(h["forces_x1"] for h in ifr["width_records"]):
        r.append("the IFR record does not force LINK_SPECIFIER to x1")
    if not v["l3_opener"]["go"]:
        r.append("delivery is over the L3 SPI stamp, which is NO-GO above")
    v["pcie_x16_fw"] = {"go": not r, "blockers": r}
    out["verdicts"] = v


def report(out, rom):
    p = print
    p("=" * 78)
    p("ROM COMPATIBILITY  --  %s" % out["path"])
    p("=" * 78)
    p("  shape           %s (%d bytes)%s" % (out["kind"], out["size"],
      "   aperture N = file N+0xA00" if out["kind"] == "physical" else "   file N = aperture N"))
    p("  sha256          %s" % out["sha256"])
    p("  VBIOS           %s%s" % (out["vbios"],
      "" if out["vbios"] == REF_VBIOS else "   ⚠ reference is %s" % REF_VBIOS))
    p("  board           %s" % out["board"])

    f = out["fwseclic"]
    p("\n-- FWSECLIC (the ucode the L3 chain runs inside) " + "-" * 29)
    if not f["found"]:
        p("  ⛔ NOT FOUND -- no descriptor covers the InfoROM format string.")
    else:
        p("  descriptor      %s at file 0x%06X, IMEM 0x%05X, DMEM 0x%05X"
          % (f["desc_ver"], f["file_base"], f["imem_len"], f["dmem_len"]))
        p("  IMEM sha256     %s...  %s" % (f["imem_sha16"],
          "★ MATCHES the reference build" if f["matches_reference_build"] else "⛔ DIFFERENT BUILD"))
        p("  canary D[0x1B0] 0x%08X  %s" % (f["canary_dmem_0x1B0"] or 0,
          "ok" if f["canary_ok"] else "⛔ expected 0x%08X" % CANARY_VALUE))
        if f["gadget_mismatches"]:
            p("  ⛔ gadget signatures that do NOT match:")
            for va, g in sorted(f["gadget_mismatches"].items()):
                p("       %s want %-8s got %-8s   %s" % (va, g["want"], g["got"], g["what"]))
        else:
            p("  gadgets         all %d signatures match" % len(GADGETS))
        miss = [k for k, ok in f["resume_gadgets_present"].items() if not ok]
        p("  resume gadgets  %d/%d present%s"
          % (len(f["resume_gadgets_present"]) - len(miss), len(f["resume_gadgets_present"]),
             "   missing: " + ", ".join(miss) if miss else ""))

    ir = out["inforom"]
    p("\n-- InfoROM (where the payload is written) " + "-" * 36)
    if not ir.get("found"):
        p("  ⛔ directory not reachable; walk trail:")
        for line in ir.get("chain", ir.get("walk", []))[-4:]:
            p("       %s" % line)
    else:
        p("  directory       aperture 0x%06X / physical 0x%06X  type '%s'"
          % (ir["dirbase_aperture"], ir["dirbase_physical"], ir["dir_type"]))
        for magic, e in ir["entries"].items():
            p("    %-4s          aperture 0x%06X / physical 0x%06X  declared size %d%s"
              % (magic, e["aperture"], e["physical"], e["declared_size"],
                 "   <- the payload object" if magic == "ULF" else ""))
        p("  ⚠ this address is per-card.  build_payload.py derives it; never hardcode it.")

    p("\n-- devinit nerf words (what is actually restricted here) " + "-" * 21)
    for n in out["devinit"]["nerfs"]:
        if not n["present"]:
            p("  %-46s  ABSENT" % n["name"][:46])
            continue
        extra = ""
        if "ndiv" in n:
            extra = "   NDIV %d = %.1f MHz" % (n["ndiv"], n["mhz"] or 0)
        p("  %-46s  %s at ap 0x%06X / phys 0x%06X%s"
          % (n["name"][:46], n["value"], n["aperture"], n["physical"], extra))
        if n.get("already_stock"):
            p("       ★ already stock -- no %s unlock needed on this card" % n["drives"])
        elif not n["matches_cmp_recipe"]:
            p("       ⚠ value differs from the recipe's %s" % n["expected_cmp_value"])

    p("\n-- IFR (PCIe width, physical dumps only) " + "-" * 37)
    ifr = out["ifr"]
    if not ifr["available"]:
        p("  n/a: %s" % ifr["why"])
    elif not ifr["width_records"]:
        p("  no record targets 0x%06X" % WIDTH_REG)
    else:
        for h in ifr["width_records"]:
            p("  physical 0x%06X  %s and=%s or=%s  LINK_SPECIFIER=0x%02X  %s"
              % (h["physical"], h["kind"], h["and_mask"], h["or_data"],
                 h["link_specifier"] or 0, "forces x1" if h["forces_x1"] else "(not x1)"))
            e = h["edit"]
            p("       edit: physical 0x%06X  %s -> %s  (%s, retargets the record to %s)"
              % (e["physical"], e["from"], e["to"],
                 "pure 1->0, no erase" if e["pure_1_to_0"] else "⛔ NOT a 1->0 clear",
                 e["retargets_to"]))

    p("\n" + "=" * 78)
    p("VERDICT")
    p("=" * 78)
    for k, lbl in [("l3_opener", "L3 opener (ROM payload + trap 20 + SPI)"),
                   ("fp64_tensor", "fp64 + tensor cores  (15.5x / 14.4x)"),
                   ("memclk", "memory clock        (+8.5%, no exploit)"),
                   ("pcie_gen3", "PCIe Gen3           (3.95x, no exploit)"),
                   ("pcie_x16_fw", "PCIe x16 firmware edit  (see the warning)")]:
        vv = out["verdicts"][k]
        p("  %-42s %s" % (lbl, "★ GO" if vv["go"] else "⛔ NO-GO"))
        for b in vv["blockers"]:
            p("       - %s" % b)

    if out["verdicts"]["l3_opener"]["go"]:
        ulf = out["inforom"]["entries"]["ULF"]
        p("\nBuild this card's payload FROM THIS CARD'S OWN DUMP -- never flash another card's")
        p("image, it carries that card's serial, UUID and board part number in the InfoROM:")
        p("""
  python3 tools/build_payload.py %s <out.rom> \\
      --resume 0x41AC \\
      --write 0x122750=0x00000FFF \\
      --write 0x1224D0=0xFC000000 \\
      --write 0x122550=0xC0000000 \\
      --write 0x122650=0x00100000 \\
      --write 0x409650=0x000000FF
""" % out["path"])
    p("⚠ Nothing here has touched hardware.  This tool only reads a file.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rom")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    rom = Rom(a.rom)
    out = {"path": a.rom}
    check_identity(rom, out)
    check_fwseclic(rom, out)
    check_inforom(rom, out)
    check_devinit(rom, out)
    check_ifr(rom, out)
    verdicts(out)

    if a.json:
        print(json.dumps(out, indent=2))
    else:
        report(out, rom)
    return 0 if any(v["go"] for v in out["verdicts"].values()) else 2


if __name__ == "__main__":
    sys.exit(main())
