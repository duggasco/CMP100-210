#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright 2026 duggasco
"""Is THIS card ready for the unlock kit, and what state is it in right now?  READ-ONLY.

The on-card companion to `tools/rom_compat.py` (which reads a ROM file).  Run this FIRST on any
card that is not the original CMP 100-210 -- it is the cheapest way to find out that something
about the target differs before anything irreversible happens.

Strictly read-only by construction: BAR0 is opened `O_RDONLY`, so a stray write is impossible.
The one thing it may change is the PCI COMMAND memory-space enable bit, which it restores.

⚠ Two measurement rules this tool enforces, both paid for in hardware incidents:
  * `PMC_BOOT_0` is re-read as a canary around every access.  If it stops reading 0x140000A1 the
    PRI ring has been poisoned and every later value is stale bus data, not an error -- abort.
  * `0x98BC98` (`FBPA_MC_2`) is NEVER read.  It does not decode on this die and reading it is
    what poisons the ring.  Only `MC_0 0x983C98` and the per-FBPA instances are real.

usage: preflight.py <bdf> [--json]
"""
import argparse
import json
import mmap
import os
import struct
import subprocess
import sys

BAR0_LEN = 1 << 24
BOOT0, BOOT0_EXPECT = 0x000000, 0x140000A1
ARCH_VOLTA = 0x140

R = {
    "PMC_BOOT_0":        0x000000,
    "PMC_ENABLE":        0x000200,
    "SCRATCH_5":         0x001594,
    "SCRATCH_6":         0x001598,
    "PMU_CPUCTL":        0x10A100,
    "FECS_PLM":          0x409650,
    "FECS_OVERRIDE":     0x409664,
    "FECS_READOUT":      0x409660,
    "XVE_LINK_CAP":      0x088084,
    "XVE_PRIV_MISC_1":   0x08841C,
    "VSEC_DEVICE":       0x08860C,
    "VSEC_HIERARCHY":    0x088610,
    "XP_PL_LINK_CONFIG_0": 0x08C040,
    "XP_PL_LANE_PRESENT":  0x08C004,
    "FBPA_FBIO_PLM":     0x9A08FC,
    "PMGR_ROM_PLM":      0x00D7D0,
    "PMGR_ROM_1_PLM":    0x00D7D8,
    "DEBUGCTRL_PLM":     0x0210E0,
    "FUSECTRL":          0x021000,
}
FUSES = {
    "OPT_PCIE_DEVIDA":      0x0214D8,
    "OPT_ECC_EN":           0x021228,
    "OPT_NVLINK_DISABLE":   0x021684,
    "OPT_DISPLAY_DISABLE":  0x02137C,
    "OPT_SM_FMLA_SPEED_SELECT": 0x0214E0,
    "OPT_SM_IMLA_SPEED_SELECT": 0x021410,
    "OPT_DP_SPEED_SELECT":  0x021224,
    "OPT_PCIE_BOOT_GEN23_DISABLE": 0x02157C,
    "OPT_PCIE_BOOT_GEN3_DISABLE":  0x021580,
    "OPT_PCIE_LANE_DISABLE": 0x021394,
    "OPT_SECURE_PMGR_ROM_WR_SECURE": 0x021164,
}
TRAP = {"MATCH": 0x122450, "MASK": 0x1224D0, "DATA1": 0x122550,
        "ACTION": 0x122650, "PLM": 0x122750}
TRAP_ARMED = {"MASK": 0xFC000000, "DATA1": 0xC0000000, "ACTION": 0x00100000, "PLM": 0x00000FFF}
FBPA_COEFF, FBPA_STRIDE, NFBPA = 0x903C98, 0x4000, 16

PMC_BITS = [(0, "BUF_RESET"), (5, "PRIV_RING"), (8, "PFIFO"), (12, "PGRAPH"),
            (13, "PWR"), (14, "SEC"), (15, "NVDEC"), (30, "PDISP")]
PRE_POST_PMC = 0x40000020


class Bar0:
    def __init__(self, bdf):
        self.bdf = bdf
        path = "/sys/bus/pci/devices/%s/resource0" % bdf
        if not os.path.exists(path):
            sys.exit("no such device: %s" % bdf)
        self.cmd_restored = None
        cmd = self._cfg_command()
        if not (cmd & 0x2):
            # Cold boot with no driver bound: memory space is disabled and every BAR0 read
            # returns 0xFFFFFFFF -- which decodes as a plausible "everything set", not an error.
            subprocess.run(["setpci", "-s", bdf.split(":", 1)[1], "COMMAND=0x0002:0x0002"],
                           check=True, capture_output=True)
            self.cmd_restored = cmd
        fd = os.open(path, os.O_RDONLY | os.O_SYNC)
        self.mm = mmap.mmap(fd, BAR0_LEN, mmap.MAP_SHARED, mmap.PROT_READ)
        os.close(fd)
        if self.rd(BOOT0) == 0xFFFFFFFF:
            sys.exit("PMC_BOOT_0 reads 0xFFFFFFFF -- BAR0 is not mapped.  Check that PCI memory "
                     "space is enabled and that no VM holds this device.")

    def _cfg_command(self):
        with open("/sys/bus/pci/devices/%s/config" % self.bdf, "rb") as f:
            f.seek(4)
            return struct.unpack("<H", f.read(2))[0]

    def rd(self, off):
        return struct.unpack_from("<I", self.mm, off)[0]

    def rdc(self, off, what=""):
        """Read with a PMC_BOOT_0 canary either side."""
        if self.rd(BOOT0) != BOOT0_EXPECT:
            sys.exit("⛔ PRI ring poisoned before reading %s (0x%06X) -- PMC_BOOT_0 reads 0x%08X, "
                     "not 0x%08X.  Every value from here is stale bus data.  Reset the card."
                     % (what, off, self.rd(BOOT0), BOOT0_EXPECT))
        v = self.rd(off)
        if self.rd(BOOT0) != BOOT0_EXPECT:
            sys.exit("⛔ reading %s (0x%06X) POISONED the PRI ring.  Reset the card; do not "
                     "trust anything measured after this point." % (what, off))
        return v

    def close(self):
        self.mm.close()
        if self.cmd_restored is not None:
            subprocess.run(["setpci", "-s", self.bdf.split(":", 1)[1],
                            "COMMAND=0x%04x" % self.cmd_restored], capture_output=True)


def sysfs(bdf, name):
    try:
        return open("/sys/bus/pci/devices/%s/%s" % (bdf, name)).read().strip()
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bdf")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--force-arch", action="store_true",
                    help="read on even if PMC_BOOT_0 says this is not a Volta die")
    a = ap.parse_args()

    b = Bar0(a.bdf)
    o = {"bdf": a.bdf}
    try:
        # ⛔ Architecture FIRST, and abort on a mismatch before reading anything else.  On a
        # GA100 the fuse block alone moved 0x21000 -> 0x820000; every other address below would
        # return a plausible-looking number that means nothing, and some of them do not decode.
        boot0 = b.rd(BOOT0)
        arch0 = (boot0 >> 20) & 0xFFF
        if arch0 != ARCH_VOLTA and not a.force_arch:
            sys.exit("⛔ PMC_BOOT_0 = 0x%08X -> arch field 0x%03X, not 0x%03X (Volta).\n"
                     "   Every register address in this kit belongs to GV100.  0x170 is GA100 --\n"
                     "   see ~/170hx_unlock for that die.  Nothing was read beyond PMC_BOOT_0.\n"
                     "   --force-arch reads on anyway; the output will be meaningless."
                     % (boot0, arch0, ARCH_VOLTA))
        o["regs"] = {k: b.rdc(v, k) for k, v in R.items()}
        o["fuses"] = {k: b.rdc(v, k) for k, v in FUSES.items()}
        o["trap20"] = {k: b.rdc(v, "trap20." + k) for k, v in TRAP.items()}
        o["fbpa_coeff"] = [b.rdc(FBPA_COEFF + i * FBPA_STRIDE, "FBPA_%d COEFF" % i)
                           for i in range(NFBPA)]
    finally:
        b.close()

    o["pci"] = {k: sysfs(a.bdf, k) for k in
                ("current_link_speed", "current_link_width", "max_link_speed",
                 "max_link_width", "device", "vendor")}
    o["driver"] = os.path.basename(os.path.realpath(
        "/sys/bus/pci/devices/%s/driver" % a.bdf)) if os.path.exists(
        "/sys/bus/pci/devices/%s/driver" % a.bdf) else None

    r, f, t = o["regs"], o["fuses"], o["trap20"]
    arch = (r["PMC_BOOT_0"] >> 20) & 0xFFF
    posted = r["PMC_ENABLE"] != PRE_POST_PMC
    chain_fired = (r["SCRATCH_5"] & 0xFF) == 0x00 and r["SCRATCH_5"] != 0
    trap_armed = all(t[k] == v for k, v in TRAP_ARMED.items())
    ndivs = sorted({(c >> 8) & 0xFF for c in o["fbpa_coeff"]})
    o["derived"] = {
        "arch": "0x%03X" % arch, "is_volta": arch == ARCH_VOLTA,
        "devid": o["pci"]["device"], "posted": posted,
        # ⚠ 0x20 is the value on a DRIVERLESS card, once FWSECLIC has finished.  Once RM owns
        # the PMU other bits legitimately set (0x60 = STOPPED|ALIAS_EN measured on a healthy,
        # fully-benchmarked card).  Treating "!= 0x20" as unhealthy is a false positive that
        # would stop a tester on a working card.  Only HALT, or an all-zero register, is bad.
        "pmu_healthy": bool(r["PMU_CPUCTL"]) and not (r["PMU_CPUCTL"] & 0x10),
        "chain_fired": chain_fired, "trap20_armed": trap_armed,
        "fecs_plm_open": r["FECS_PLM"] == 0xFF,
        "cya_clamped": bool(r["XVE_PRIV_MISC_1"] & 0xC0006000),
        "lnkcap_speed": r["XVE_LINK_CAP"] & 0xF,
        "lnkcap_width": (r["XVE_LINK_CAP"] >> 4) & 0x3F,
        "link_specifier": (r["XP_PL_LINK_CONFIG_0"] >> 27) & 0x1F,
        "hbm_ndivs": ndivs,
    }
    d = o["derived"]

    v = {}
    v["safe_to_proceed"] = {
        "go": d["is_volta"] and d["pmu_healthy"],
        "blockers": ([] if d["is_volta"] else
                     ["PMC_BOOT_0 arch field is %s, not 0x140 (Volta) -- this kit's every "
                      "register address is wrong for this die" % d["arch"]]) +
                    ([] if d["pmu_healthy"] else
                     ["PMU CPUCTL = 0x%08X.  Bit 4 (0x10) is HALT; 0x00000000 is the "
                      "post-Xid-79 signature.  SBR -- twice if needed, the first reset after an "
                      "Xid 79 can still read 0x00 -- and re-run before any flash."
                      % r["PMU_CPUCTL"]]),
    }
    v["memclk"] = {
        "go": r["FBPA_FBIO_PLM"] == 0xFF and len(ndivs) == 1 and ndivs[0] not in (0,),
        "blockers": ([] if r["FBPA_FBIO_PLM"] == 0xFF else
                     ["FBPA_FBIO PLM 0x9A08FC = 0x%02X, not 0xFF -- not host-L0 writable here"
                      % r["FBPA_FBIO_PLM"]]) +
                    ([] if len(ndivs) == 1 else
                     ["the 16 FBPA COEFF instances disagree (NDIV %s).  If the GPU is idle the "
                      "FB partition clock-gates and these read garbage -- hold a load and "
                      "re-read before believing this." % ndivs]),
        "note": "needs NO exploit: pure host L0.  Requires the card POSTed and IDLE."
                if posted else "the card has not POSTed; the FB block is dark.  Load the driver "
                               "first -- COEFF is only meaningful after devinit.",
    }
    v["pcie_gen3"] = {
        "go": not posted and d["cya_clamped"],
        "blockers": (["the card has already POSTed (PMC_ENABLE 0x%08X).  The CYA clear is a "
                      "PRE-POST-only lever -- the capability is latched at devinit.  Reset and "
                      "run before anything opens the GPU." % r["PMC_ENABLE"]] if posted else []) +
                    ([] if d["cya_clamped"] else
                     ["CYA_GEN2/GEN3_SPEED_OVERRIDE bits are already clear in 0x08841C = 0x%08X "
                      "-- this card is not clamped that way (a 170HX reaches Gen1 by fused "
                      "bits instead, and this write does nothing there)." % r["XVE_PRIV_MISC_1"]]),
        "note": "needs NO exploit.  Retrain must be issued from the UPSTREAM port.",
    }
    v["l3_opener"] = {
        "go": d["trap20_armed"] or d["fecs_plm_open"],
        "blockers": ([] if (d["trap20_armed"] or d["fecs_plm_open"]) else
                     ["no unlock payload is resident and armed: trap 20 is not armed and the "
                      "FECS PLM is 0x%02X, not 0xFF.  Build one for THIS card with "
                      "tools/rom_compat.py + tools/build_payload.py." % r["FECS_PLM"]]),
        "note": "trap 20 %s, FECS PLM %s" % ("ARMED" if d["trap20_armed"] else "not armed",
                                             "OPEN" if d["fecs_plm_open"] else "closed"),
    }
    v["fp64_tensor"] = {
        "go": d["fecs_plm_open"] or d["trap20_armed"],
        "blockers": ([] if (d["fecs_plm_open"] or d["trap20_armed"]) else
                     ["FECS PLM 0x409650 = 0x%02X (write-L3-only) and no opener is armed"
                      % r["FECS_PLM"]]),
        "note": "OVERRIDE 0x409664 = 0x%08X, READOUT 0x409660 = 0x%08X (bits 20/21/22 "
                "DP/IMLA/FMLA; 0 = FULL_SPEED)" % (r["FECS_OVERRIDE"], r["FECS_READOUT"]),
    }
    # ★ The firmware limit is REAL and PROVEN REMOVABLE: one byte in the IFR record at physical
    # flash 0x214 retargets the RMW that forces LINK_SPECIFIER to x1.  Measured on the reference
    # card: LINK_SPECIFIER 0x01 -> 0x10, MAX_LINK_WIDTH 1 -> 16, lspci LnkCap x1 -> x16, card
    # enumerates normally.  What is NOT guaranteed is the payoff: the link only trains as wide as
    # the board routes lanes, and on the reference bench only one lane had a partner.  That is a
    # property of that slot/riser, not of the technique -- so this is a real capability with a
    # hardware-dependent return, NOT a dead end.  Report the state; let the operator judge.
    fw_limited = d["link_specifier"] == 0x01 and d["lnkcap_width"] == 1
    x16_blockers = []
    if not fw_limited:
        x16_blockers.append("this card is not firmware-limited to x1 (LINK_SPECIFIER 0x%02X, "
                            "LnkCap width %d) -- nothing for this edit to remove"
                            % (d["link_specifier"], d["lnkcap_width"]))
    v["pcie_x16_fw"] = {
        "go": fw_limited,
        "blockers": x16_blockers,
        "note": "LANE_PRESENT 0x08C004 = 0x%08X, LINK_SPECIFIER = 0x%02X (0x01 = x1, 0x10 = x16), "
                "LnkCap width %d, currently trained %s.\n"
                "⚠ The edit itself is proven (one byte, LnkCap x1 -> x16). It is ONE OF TWO "
                "gates:\n"
                "  the second is physical -- the series AC-coupling capacitors for the extra "
                "lanes are\n"
                "  DEPOPULATED on this SKU, so those lanes have no DC path and no link partner "
                "is detected.\n"
                "  ★ The traces are there; the caps are not. Fitting them is a soldering job, "
                "not a dead end.\n"
                "  ⛔ LANE_PRESENT is NOT predictive -- it read 0xFFFF (16 lanes at the PHY) on "
                "a card that\n"
                "  trained x1. Inspect the board: look for empty pad pairs on the lane traces "
                "by the edge\n"
                "  connector, alongside the populated ones on the working lane.\n"
                "⛔ Highest-risk edit in the kit: it writes flash sector 0 (the IFR), which "
                "programs\n"
                "  ROM_ADDR_OFFSET and the PCIe config. A bad one stops the card enumerating and "
                "the only\n"
                "  way back is a 1.8 V programmer. Attach one first."
                % (r["XP_PL_LANE_PRESENT"], d["link_specifier"], d["lnkcap_width"],
                   o["pci"]["current_link_width"]),
    }
    o["verdicts"] = v

    if a.json:
        print(json.dumps(o, indent=2, default=str))
        return 0

    p = print
    p("=" * 78)
    p("CARD PREFLIGHT  --  %s   (READ-ONLY)" % a.bdf)
    p("=" * 78)
    p("  PMC_BOOT_0      0x%08X   arch %s %s" % (r["PMC_BOOT_0"], d["arch"],
      "(Volta)" if d["is_volta"] else "⛔ NOT VOLTA"))
    p("  device          %s:%s   driver: %s" % (o["pci"]["vendor"], o["pci"]["device"],
                                                o["driver"] or "none (driverless)"))
    p("  PMC_ENABLE      0x%08X   %s" % (r["PMC_ENABLE"],
      "POSTed (devinit has run)" if posted else "PRE-POST (driverless; devinit has NOT run)"))
    p("                  %s" % " ".join("%s%s" % ("+" if r["PMC_ENABLE"] >> i & 1 else "-", n)
                                        for i, n in PMC_BITS))
    p("  PMU CPUCTL      0x%08X   %s" % (r["PMU_CPUCTL"],
      ("healthy" + ("" if r["PMU_CPUCTL"] == 0x20 else "  (0x20 driverless; RM sets more bits)"))
      if d["pmu_healthy"] else "⛔ HALT (bit 4) / 0x00 post-Xid-79; SBR before flashing"))
    p("  postcodes       SCRATCH(5) 0x%08X  SCRATCH(6) 0x%08X" % (r["SCRATCH_5"], r["SCRATCH_6"]))
    p("  link            trained %s / %s lane(s), LnkCap speed %d width %d"
      % (o["pci"]["current_link_speed"], o["pci"]["current_link_width"],
         d["lnkcap_speed"], d["lnkcap_width"]))
    p("                  ⚠ sysfs max_link_speed is cached at enumeration -- trust "
      "current_link_speed")

    p("\n-- unlock-relevant state " + "-" * 52)
    p("  FECS PLM        0x409650 = 0x%08X   %s" % (r["FECS_PLM"],
      "OPEN (L0-writable)" if d["fecs_plm_open"] else "write-L3-only"))
    p("  FECS OVERRIDE   0x409664 = 0x%08X   READOUT 0x409660 = 0x%08X"
      % (r["FECS_OVERRIDE"], r["FECS_READOUT"]))
    p("  trap 20         MATCH 0x%08X MASK 0x%08X DATA1 0x%08X ACTION 0x%08X PLM 0x%08X"
      % (t["MATCH"], t["MASK"], t["DATA1"], t["ACTION"], t["PLM"]))
    p("                  %s" % ("ARMED -- the L3 stamp is available" if d["trap20_armed"]
                                else "not armed"))
    p("  PCIe clamp      0x08841C = 0x%08X   CYA bits %s" % (r["XVE_PRIV_MISC_1"],
      "SET (clamped to Gen1)" if d["cya_clamped"] else "clear"))
    p("  HBM PLL         NDIV %s across %d FBPA instance(s)%s"
      % (ndivs, NFBPA, "" if posted else "   (pre-POST: FB is dark, ignore these)"))
    p("  FBPA_FBIO PLM   0x9A08FC = 0x%08X   %s" % (r["FBPA_FBIO_PLM"],
      "L0-writable" if r["FBPA_FBIO_PLM"] == 0xFF else "restricted"))

    p("\n-- fuses (sensed at power-on; valid pre- and post-POST) " + "-" * 22)
    for k in ("OPT_PCIE_DEVIDA", "OPT_ECC_EN", "OPT_NVLINK_DISABLE", "OPT_DISPLAY_DISABLE",
              "OPT_SM_FMLA_SPEED_SELECT", "OPT_SM_IMLA_SPEED_SELECT", "OPT_DP_SPEED_SELECT",
              "OPT_PCIE_BOOT_GEN23_DISABLE", "OPT_PCIE_LANE_DISABLE",
              "OPT_SECURE_PMGR_ROM_WR_SECURE"):
        p("  %-32s 0x%08X" % (k, f[k]))
    if f["OPT_SM_FMLA_SPEED_SELECT"] or f["OPT_SM_IMLA_SPEED_SELECT"] or f["OPT_DP_SPEED_SELECT"]:
        p("  ⚠ a SPEED_SELECT fuse is BURNED on this card.  The reference card has all three "
          "clear\n    and is throttled by devinit only -- a fused throttle is NOT liftable by "
          "this kit.")

    p("\n" + "=" * 78)
    p("VERDICT")
    p("=" * 78)
    for k, lbl in [("safe_to_proceed", "safe to proceed at all"),
                   ("l3_opener", "L3 opener resident + armed"),
                   ("fp64_tensor", "fp64 + tensor cores"),
                   ("memclk", "memory clock"),
                   ("pcie_gen3", "PCIe Gen3 (right now, this boot)"),
                   ("pcie_x16_fw", "PCIe x16 firmware edit")]:
        vv = v[k]
        p("  %-34s %s" % (lbl, "★ GO" if vv["go"] else "⛔ NO-GO"))
        if vv.get("note"):
            p("       %s" % vv["note"])
        for x in vv["blockers"]:
            for i, line in enumerate(x.split("\n")):
                p("       %s%s" % ("- " if i == 0 else "  ", line))
    if not v["safe_to_proceed"]["go"]:
        p("\n⛔ 'safe to proceed at all' is NO-GO, so treat every GO above as provisional: fix "
          "that\n   first and re-run, rather than acting on the rows below it.")
    p("\n⚠ Read-only: BAR0 was opened O_RDONLY.  Nothing on this card was changed.")
    return 0 if v["safe_to_proceed"]["go"] else 2


if __name__ == "__main__":
    sys.exit(main())

