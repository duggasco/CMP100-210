#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 duggasco
"""Dump the POST-dependent state of a GV100: is devinit done, and what did it program?

Strictly READ-ONLY -- it opens BAR0 O_RDONLY, so a stray write is impossible by construction.

CLAUDE.md records that on a driverless boot this card reads PMC_ENABLE = 0x40000020, the exact
complement on all four bits devinit controls, so "measured on card" so far has meant "measured
BEFORE devinit".  Everything downstream of devinit -- the FECS SM speed-select throttle, the HBM
PLL coefficient, the PCIe capability words -- is therefore unreadable on a stock boot.  Loading
the 580.xx proprietary driver POSTs the card; this tool is the before/after instrument.

usage: post_state_probe.py <bdf> [--json]
"""
import argparse, json, mmap, os, struct, sys

XTAL_MHZ = 27.0

PMC_BITS = [(0, "BUF_RESET"), (5, "PRIV_RING"), (8, "PFIFO"), (12, "PGRAPH"),
            (13, "PWR"), (14, "SEC"), (15, "NVDEC"), (30, "PDISP")]

SM_FIELDS = [("IMLA", 0), ("IMLA_OVERRIDE", 3), ("FMLA", 4), ("FMLA_OVERRIDE", 7),
             ("DP", 8), ("DP_OVERRIDE", 11)]

# dev_ctxsw_firmware.h:3173-3181 -- NOT the same order as the OVERRIDE register
READOUT_FIELDS = [("DP_REDUCED", 20), ("IMLA_REDUCED", 21), ("FMLA_REDUCED", 22)]

PLLS = [("GPCPLL", 0x132804, 0x132800), ("LTCPLL", 0x137024, None),
        ("XBARPLL", 0x137044, None), ("SYSPLL", 0x1370E4, None)]

HBMPLL = [("FBPA_MC_%d" % i, 0x983C98 + i * 0x4000) for i in range(4)] + \
         [("FBPA_%d" % i, 0x903C98 + i * 0x4000) for i in range(4)]

PCIE = [("XVE_LINK_CAPABILITIES", 0x088084), ("XVE_PRIV_MISC_1", 0x08841C),
        ("VSEC_NVIDIA_SPECIFIC_DEVICE", 0x08860C), ("VSEC_HIERARCHY", 0x088610),
        ("XP_PL_LINK_CONFIG_0", 0x08C040), ("XP_PL_LANE_PRESENT", 0x08C004)]

FUSES = [("OPT_PCIE_DEVIDA", 0x0214D8), ("OPT_SM_FMLA_SPEED_SELECT", 0x0214E0),
         ("OPT_SM_IMLA_SPEED_SELECT", 0x021410), ("OPT_DP_SPEED_SELECT", 0x021224),
         ("OPT_SHF_SPEED_SELECT", 0x02159C), ("OPT_GPC2CLK_CAP", 0x02142C)]

MISC = [("PMC_BOOT_0", 0x000000), ("PMC_BOOT_42", 0x000A00), ("PMC_ENABLE", 0x000200),
        ("PBUS_VBIOS_SCRATCH_5", 0x001594), ("PBUS_VBIOS_SCRATCH_6", 0x001598),
        ("FECS_FEATURE_OVERRIDE_PLM", 0x409650),
        ("FECS_FEATURE_READOUT", 0x409660),
        ("FECS_FEATURE_OVERRIDE_SM_SPEED_SELECT", 0x409664)]


def bits(v, table):
    return " ".join("%s=%d" % (n, (v >> b) & 1) for b, n in table)


def flds(v, table):
    return " ".join("%s=%d" % (n, (v >> b) & 1) for n, b in table)


def dead(v):
    return (v & 0xFFFFF000) in (0xBADF3000, 0xBADF5000, 0xBADF1000) or v == 0xFFFFFFFF


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bdf")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    # ⚠ --json means JSON ON STDOUT.  Rebinding sys.stdout is used instead of shadowing the
    # `print` name: a `def print` inside this function would make the name local for the WHOLE
    # function and every earlier call would raise UnboundLocalError.
    _real_stdout = sys.stdout
    if a.json:
        sys.stdout = sys.stderr          # human report -> stderr, restored before the JSON

    # ⚠ After a COLD BOOT with no driver bound, PCI memory space is disabled (COMMAND = 0x0100)
    # and every BAR0 read returns 0xFFFFFFFF -- which decodes as a plausible-looking "everything
    # set" state rather than an error. Enable it first; this is the only write this tool makes.
    cfg = "/sys/bus/pci/devices/%s/config" % a.bdf
    with open(cfg, "r+b", buffering=0) as f:
        f.seek(4); cmd = struct.unpack("<H", f.read(2))[0]
        if not cmd & 0x2:
            f.seek(4); f.write(struct.pack("<H", cmd | 0x2))
            print("(PCI memory space was disabled, COMMAND 0x%04X -> 0x%04X)" % (cmd, cmd | 0x2))

    p = "/sys/bus/pci/devices/%s/resource0" % a.bdf
    fd = os.open(p, os.O_RDONLY | os.O_SYNC)
    mm = mmap.mmap(fd, min(os.path.getsize(p), 16 << 20), mmap.MAP_SHARED, mmap.PROT_READ)
    os.close(fd)
    rd = lambda o: struct.unpack_from("<I", mm, o)[0]

    out = {"bdf": a.bdf, "regs": {}}

    def rec(name, off):
        v = rd(off)
        out["regs"]["0x%06X" % off] = {"name": name, "value": "0x%08X" % v}
        return v

    print("=" * 78)
    print("GV100 POST-state probe   bdf=%s" % a.bdf)
    print("=" * 78)
    if rd(0) == 0xFFFFFFFF:
        print("\n!! PMC_BOOT_0 reads 0xFFFFFFFF -- BAR0 is not decoding. Nothing below is real.")
        sys.exit(2)

    print("\n-- identity / power gating " + "-" * 50)
    for n, o in MISC:
        v = rec(n, o)
        extra = ""
        if o == 0x000200:
            extra = "  [%s]" % bits(v, PMC_BITS)
        if o == 0x409664:
            extra = "  [%s]" % flds(v, SM_FIELDS)
        if o == 0x409660:
            extra = "  [%s]" % flds(v, READOUT_FIELDS)
        if o == 0x409650:
            wm = (v >> 4) & 7
            extra = "  write mask %d => %s" % (wm, "L3 ONLY" if wm == 0 else "host-writable")
        print("  %-42s 0x%06X = 0x%08X%s" % (n, o, v, extra))

    pmc = rd(0x000200)
    posted = bool(pmc & (1 << 12))
    out["pgraph_powered"] = posted
    out["pmc_enable"] = "0x%08X" % pmc
    print("\n  ==> PGRAPH (bit 12) %s  ==> the card %s POSTed"
          % ("SET" if posted else "CLEAR", "IS" if posted else "has NOT"))

    print("\n-- core PLLs " + "-" * 64)
    for name, coeff, cfg in PLLS:
        v = rec(name + "_COEFF", coeff)
        if dead(v):
            print("  %-42s 0x%06X = 0x%08X   (block dark)" % (name, coeff, v))
            continue
        mdiv, ndiv, pldiv = v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0x3F
        f = XTAL_MHZ * ndiv / mdiv / (pldiv or 1) if mdiv else 0
        print("  %-42s 0x%06X = 0x%08X   MDIV=%d NDIV=%d PLDIV=%d -> %.1f MHz"
              % (name, coeff, v, mdiv, ndiv, pldiv, f))
        if cfg:
            print("  %-42s 0x%06X = 0x%08X" % (name + "_CFG", cfg, rec(name + "_CFG", cfg)))

    print("\n-- HBM PLL coefficients (memory clock) " + "-" * 38)
    for name, off in HBMPLL:
        v = rec("HBMPLL_" + name, off)
        if dead(v):
            print("  %-42s 0x%06X = 0x%08X   (FB not up)" % (name, off, v))
            continue
        mdiv, ndiv, pldiv = v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0x3F
        print("  %-42s 0x%06X = 0x%08X   MDIV=%d NDIV=%d PLDIV=%d -> %.1f MHz (x2 data = %.1f)"
              % (name, off, v, mdiv, ndiv, pldiv, XTAL_MHZ * ndiv / 2, XTAL_MHZ * ndiv))

    print("\n-- PCIe " + "-" * 70)
    for n, o in PCIE:
        v = rec(n, o)
        extra = ""
        if o == 0x088084:
            extra = "  MAX_LINK_SPEED=%d MAX_LINK_WIDTH=%d" % (v & 0xF, (v >> 4) & 0x3F)
        if o == 0x08C040:
            extra = "  LINK_SPECIFIER=0x%02X" % ((v >> 27) & 0x1F)
        print("  %-42s 0x%06X = 0x%08X%s" % (n, o, v, extra))

    print("\n-- speed-select fuses (all 0 = nothing throttled by OTP) " + "-" * 20)
    for n, o in FUSES:
        v = rec(n, o)
        print("  %-42s 0x%06X = 0x%08X" % (n, o, v))

    mm.close()
    sys.stdout = _real_stdout
    if a.json:
        # This used to print the human report first and append the JSON, so
        # `post_state_probe.py --json > report.json` produced a file no JSON parser accepts.
        print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
