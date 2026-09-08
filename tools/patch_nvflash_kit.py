#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 duggasco
"""Turn a STOCK Linux nvflash 5.680 into the binary this kit needs, in one step.  OFFLINE.

The tree grew three separate patchers, each written the day its gate was discovered, and each
assuming the previous one had already been applied.  Anyone starting from a clean nvflash had to
find that out by failing.  This applies all three, verifies every preimage, and refuses on any
surprise.

  1. Certificate 3.0 result store   file 0x1175AA   89 c3      -> 31 db      (mov ebx,eax
                                                                              -> xor ebx,ebx)
     This is exactly what the circulating `nvflash-nocert3` build is.
  2. Certificate 2.0 result store   file 0x117AD0   41 89 c6   -> 45 31 f6   (mov r14d,eax
                                                                              -> xor r14d,r14d)
     ⛔ A SEPARATE, live gate.  Without it a legacy-image or ucode-image edit is refused with
     "BIOS Cert 2.0 Verification Error, Update aborted."  ⛔ And the devid whitelist inside the
     same block is NOT the lever -- adding an id there was tried on hardware and the flash was
     still refused (cmp100 logs/69); the verifier still runs.  The result store is the patch.
  3. InfoROM preservation devid gate  file 0x0F8ABB   cmp ax,0x1EFC -> cmp ax,<your devid>
     Without it a card outside NVIDIA's four-device whitelist falls through to a forced
     whole-InfoROM merge and the full-ROM path cannot write the InfoROM at all -- which is
     exactly where this kit's payload lives.  ⚠ It sacrifices the 0x1EFC case in the output
     copy: this is a purpose-built binary, never a general-purpose nvflash.

⛔⛔ What this does NOT do.  These are HOST gates.  The card's own BIOSCERT runs at every boot and
is untouched -- and it stays happy on a modified image (the failure with a modified legacy image
is `RmInitAdapter 0x31:0xffff:2780`, from the DRIVER, not the card).  Nor does patching change
what the PMU's flash service will accept: it refuses any write below physical 0x00EE00 regardless.

usage:
  patch_nvflash_kit.py <stock-nvflash> --devid 0x1DF4 --out nvflash-kit
  patch_nvflash_kit.py <any-nvflash>                       (report what is already applied)
"""
import argparse
import hashlib
import os
import sys
from pathlib import Path

EXPECT_SIZE = 7793296          # the audited Linux nvflash 5.680 build
VA_BIAS = 0x400000             # file offset + this = the VA quoted in the findings docs

PATCHES = [
    {"name": "cert 3.0 result store", "off": 0x1175AA,
     "old": bytes.fromhex("89c3"), "new": bytes.fromhex("31db"),
     "desc": "mov ebx,eax -> xor ebx,ebx"},
    {"name": "cert 2.0 result store", "off": 0x117AD0,
     "old": bytes.fromhex("4189c6"), "new": bytes.fromhex("4531f6"),
     "desc": "mov r14d,eax -> xor r14d,r14d"},
]
# guards: bytes that must be intact, or the offsets belong to a different build
GUARDS = [
    (0x117AEC, bytes.fromhex("4585f6745e"), "cert 2.0 test/branch"),
    (0x1175C5, bytes.fromhex("85db"),       "cert 3.0 test"),
]
DEVID_OFF = 0x0F8ABB
DEVID_OLD = bytes.fromhex("663dfc1e7523")     # cmp ax,0x1EFC ; jne
KNOWN = {
    "5f615976e0ff36fa": "pristine nvflash 5.680",
    "e533d1260762b61c": "nvflash-nocert3 (cert 3.0 only)",
    "5f8988cd8825a3c7": "nvflash-nocert3-devid1df4-cert20v2 (the cmp100 production binary)",
}


def state(blob, p):
    got = blob[p["off"]:p["off"] + len(p["old"])]
    if got == p["new"]:
        return "applied", got
    if got == p["old"]:
        return "stock", got
    return "unexpected", got


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("nvflash", type=Path)
    ap.add_argument("--devid", type=lambda s: int(s, 16),
                    help="PCI device id to route through the InfoROM gate, e.g. 0x1DF4")
    ap.add_argument("--out", type=Path, help="write the patched copy here")
    a = ap.parse_args()

    blob = bytearray(a.nvflash.read_bytes())
    sha = hashlib.sha256(bytes(blob)).hexdigest()
    print("input   %s" % a.nvflash)
    print("size    %d %s" % (len(blob),
          "" if len(blob) == EXPECT_SIZE else "  ⛔ expected %d (Linux nvflash 5.680)" % EXPECT_SIZE))
    print("sha256  %s   %s" % (sha, KNOWN.get(sha[:16], "(unrecognised base)")))
    if len(blob) != EXPECT_SIZE:
        sys.exit("refusing: every offset here was derived on the 5.680 build")

    for off, want, what in GUARDS:
        if bytes(blob[off:off + len(want)]) != want:
            sys.exit("ABORT: %s at 0x%06X reads %s, expected %s -- this is a different build; "
                     "re-derive the offsets before patching anything"
                     % (what, off, blob[off:off + len(want)].hex(), want.hex()))
    print("guards  ok (%d)" % len(GUARDS))

    print("\npatch sites:")
    todo = []
    for p in PATCHES:
        st, got = state(blob, p)
        print("  %-24s file 0x%06X / VA 0x%06X  %-9s %s"
              % (p["name"], p["off"], p["off"] + VA_BIAS, got.hex(), st.upper()))
        if st == "unexpected":
            sys.exit("ABORT: %s is neither the stock nor the patched byte sequence" % p["name"])
        if st == "stock":
            todo.append(p)

    dv = bytes(blob[DEVID_OFF:DEVID_OFF + len(DEVID_OLD)])
    cur_devid = int.from_bytes(dv[2:4], "little")
    print("  %-24s file 0x%06X / VA 0x%06X  %-9s cmp ax,0x%04X"
          % ("InfoROM devid gate", DEVID_OFF, DEVID_OFF + VA_BIAS, dv.hex(), cur_devid))
    if dv[:2] != DEVID_OLD[:2] or dv[4:] != DEVID_OLD[4:]:
        sys.exit("ABORT: the InfoROM gate instruction does not have the expected shape")

    if not a.out:
        print("\n(report only; pass --out and --devid to write a patched copy)")
        return 0
    if a.devid is None:
        sys.exit("--out needs --devid: the InfoROM gate has to name the card you are flashing")
    if not (0 < a.devid <= 0xFFFF):
        sys.exit("devid out of range")

    expect_changed = []
    for p in todo:
        blob[p["off"]:p["off"] + len(p["new"])] = p["new"]
        expect_changed += list(range(p["off"], p["off"] + len(p["new"])))
    if cur_devid != a.devid:
        blob[DEVID_OFF + 2] = a.devid & 0xFF
        blob[DEVID_OFF + 3] = (a.devid >> 8) & 0xFF
        expect_changed += [DEVID_OFF + 2, DEVID_OFF + 3]

    orig = a.nvflash.read_bytes()
    changed = sorted(i for i in range(len(orig)) if orig[i] != blob[i])
    if changed != sorted(expect_changed):
        sys.exit("ABORT: changed %d byte(s) at %s, expected %s -- not writing"
                 % (len(changed), [hex(i) for i in changed[:8]],
                    [hex(i) for i in sorted(expect_changed)]))

    a.out.write_bytes(bytes(blob))
    os.chmod(a.out, a.nvflash.stat().st_mode)
    print("\nwrote %s" % a.out)
    print("  %d byte(s) changed at %s" % (len(changed), ", ".join("0x%06X" % i for i in changed)))
    print("  InfoROM gate now  cmp ax,0x%04X" % a.devid)
    print("  sha256 %s" % hashlib.sha256(bytes(blob)).hexdigest())
    print("\n⚠ Verify the BYTES, not the filename.  This tree has had three binaries whose names")
    print("  claimed patches they did not carry; re-run this tool on the output to confirm all")
    print("  three sites read APPLIED before using it on a card.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
