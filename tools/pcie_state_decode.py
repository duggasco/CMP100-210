#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright 2026 duggasco
"""Decode a GV100's whole PCIe restriction path from an archived register dump. OFFLINE.

Reads either a reg_full_census.py json or a plain "  0xADDR  0xVALUE" text dump (the format of
~/nvidia_unlock/logs/gpubench-v100-first-contact-2026-08-01/07-registers.txt), so the CMP 100-210
and a stock Tesla V100 can be put side by side. Pass two dumps to diff them.

Why this exists: the tree's first PCIe analysis read NV_XVE_VSEC_..._HIERARCHY (0x088610) as the
state. It is the WRITE PORT. The state is NV_XVE_VSEC_..._DEVICE (0x08860C), read-only -- the same
override/readout pairing as FEATURE_OVERRIDE vs FEATURE_READOUT. Reading the wrong one of the pair
made a stock V100 and a CMP 100-210 look identical when they differ completely.
See FINDINGS-2026-09-05-pcie-clamp-is-four-cya-bits.md.

usage: pcie_state_decode.py <dump-a> [dump-b]
"""
import json, os, re, sys

FIELDS = [
    ("0x088084", "XVE_LINK_CAPABILITIES", [
        ("MAX_LINK_SPEED", 3, 0, {1: "Gen1", 2: "Gen2", 3: "Gen3"}, None),
        ("MAX_LINK_WIDTH", 9, 4, {1: "x1", 4: "x4", 8: "x8", 16: "x16"}, None)]),
    ("0x088088", "XVE_LINK_CONTROL_STATUS (negotiated)", [
        ("LINK_SPEED", 19, 16, {1: "Gen1", 2: "Gen2", 3: "Gen3"}, None),
        ("LINK_WIDTH", 25, 20, {1: "x1", 4: "x4", 8: "x8", 16: "x16"}, None)]),
    ("0x0880A4", "XVE_LINK_CAPABILITIES_2", [
        ("SUPPORTED_LINK_SPEED", 7, 1,
         {0: "HIDDEN", 1: "GEN1", 3: "GEN1_GEN2", 7: "GEN1_GEN2_GEN3"}, 0x7)]),
    ("0x08860C", "XVE_VSEC_..._DEVICE  <-- the EFFECTIVE capability, read-only", [
        ("NV_GEN2_PCIE", 0, 0, {0: "DISABLED", 1: "CAPABLE"}, None),
        ("NV_GEN3_PCIE", 12, 12, {0: "DISABLED", 1: "CAPABLE"}, None)]),
    ("0x088610", "XVE_VSEC_..._HIERARCHY  <-- the WRITE PORT (reads 0 even on a Gen3 part)", [
        ("NV_GEN2_PCIE", 0, 0, {0: "NOT_CAPABLE", 1: "CAPABLE"}, None),
        ("NV_GEN3_PCIE", 12, 12, {0: "NOT_CAPABLE", 1: "CAPABLE"}, None)]),
    ("0x08841C", "XVE_PRIV_MISC_1  <-- ★ the speed clamp, read/write", [
        ("CYA_GEN2_SPEED_OVERRIDE_EN", 13, 13, {0: "DISABLED", 1: "ENABLED"}, 0),
        ("CYA_GEN2_SPEED_OVERRIDE_VAL", 14, 14, {0: "5P0", 1: "2P5"}, None),
        ("CYA_GEN3_SPEED_OVERRIDE_EN", 30, 30, {0: "DISABLED", 1: "ENABLED"}, 0),
        ("CYA_GEN3_SPEED_OVERRIDE_VAL", 31, 31, {0: "8P0", 1: "5P0"}, None)]),
    ("0x08872C", "XVE_FUSE_OVERRIDE", [
        ("BOOT_GEN23_DIS_OVR", 1, 1, {0: "DISABLE", 1: "ENABLE"}, None),
        ("BOOT_GEN3_DIS_OVR", 3, 3, {0: "DISABLE", 1: "ENABLE"}, None)]),
    ("0x08C040", "XP_PL_LINK_CONFIG_0", [
        ("LINK_SPECIFIER", 31, 27, {0: "NULL", 1: "00_00 (x1)", 4: "03_00 (x4)",
                                    8: "07_00 (x8)", 16: "15_00 (x16)"}, 0x10),
        ("MAX_LINK_RATE", 19, 18, {0: "8000_MTPS", 1: "5000_MTPS", 2: "2500_MTPS"}, 0),
        ("TARGET_TX_WIDTH", 22, 20, {0: "x16", 4: "x8", 5: "x4", 6: "x2", 7: "x1"}, 0)]),
    ("0x08C004", "XP_PL_LANE_PRESENT  (static die constant -- says nothing about board routing)", []),
    ("0x08C2C0", "XP_PL_CYA_0", []),
]
FUSES = [("0x02157C", "OPT_PCIE_BOOT_GEN23_DISABLE"), ("0x021580", "OPT_PCIE_BOOT_GEN3_DISABLE"),
         ("0x021394", "OPT_PCIE_LANE_DISABLE")]


def load(path):
    if path.endswith(".json"):
        j = json.load(open(path))
        return ({"0x" + k[2:].upper(): int(v[2], 16) for k, v in j["regs"].items()},
                "%s %s" % (j.get("bdf", "?"), j.get("PMC_BOOT_0", "")))
    out = {}
    for ln in open(path, errors="replace"):
        m = re.match(r"\s*(0x[0-9A-Fa-f]{6})\s+(0x[0-9A-Fa-f]{8})\b", ln)
        if m:
            out.setdefault("0x" + m.group(1)[2:].upper(), int(m.group(2), 16))
    return out, os.path.basename(path)


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    dumps = [load(p) for p in sys.argv[1:3]]
    print("  ".join("[%d] %s" % (i, d[1]) for i, d in enumerate(dumps)))
    print()
    for addr, name, fields in FIELDS:
        vals = [d[0].get(addr) for d in dumps]
        if all(v is None for v in vals):
            continue
        raw = "  ".join("0x%08X" % v if v is not None else "  absent " for v in vals)
        flag = " ⚠DIFF" if len(vals) == 2 and vals[0] != vals[1] else ""
        print("%s %-62s %s%s" % (addr, name, raw, flag))
        for fn, hi, lo, enum, init in fields:
            outs = []
            for v in vals:
                if v is None:
                    outs.append("--"); continue
                x = (v >> lo) & ((1 << (hi - lo + 1)) - 1)
                s = enum.get(x, "0x%x" % x)
                if init is not None and x != init:
                    s += " (≠INIT)"
                outs.append(s)
            d = " ⚠" if len(outs) == 2 and outs[0] != outs[1] else ""
            print("      %-28s %s%s" % (fn, "   vs   ".join(outs), d))
        print()
    print("--- PCIe restriction fuses (OTP) ---")
    for addr, name in FUSES:
        vals = ["0x%08X" % d[0][addr] if addr in d[0] else "absent" for d in dumps]
        print("%s %-34s %s" % (addr, name, "   vs   ".join(vals)))


if __name__ == "__main__":
    main()
