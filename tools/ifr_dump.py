#!/usr/bin/env python3
"""Dump the hidden IFR / NVGI prefix that sits BELOW the NV_PROM aperture. READ-ONLY on flash.

Why it is hidden. NV_PMGR_ROM_ADDR_OFFSET (0xE208) reads 0x00000A01 = EN=1, AMOUNT=0x280 dwords,
so the NV_PROM aperture starts 0xA00 bytes into the physical flash device. Everything this tree
has ever dumped -- firmware/gv100-nvprom.rom included -- is an APERTURE image, not a physical one.
nvflash agrees independently: its "adapter ROM space" is 0xFF600 = 1 MiB minus that 0xA00 prefix.
The prefix is an NVGI IFR header block (FINDINGS-2026-09-02-fwseclic-audit.md:1528) and nothing in
this tree has ever seen its contents.

Method. 0xE208 is write-L0 and volatile. Setting AMOUNT=0 (keeping EN=1) slides the aperture down
to physical 0, exposing the prefix; the register is restored in a finally block, and a reset or a
power cycle restores it regardless (devinit reprograms it to 0x00000A01 -- logs/20).

★ Built-in correctness check. With the window at 0, new[0xA00:] MUST equal the armed window's
[0:]. If that holds, the slide is proven and bytes [0:0xA00] really are the hidden prefix. If it
does not, the dump is discarded rather than archived -- a wrong window is worse than no data.

⚠ 0xE200-0xE210 is on the load-bearing denylist because that block is how the recovery path
addresses the flash. This tool writes exactly ONE register in it, with a known restore value that
is verified before exit, and performs NO flash writes. It is nonetheless the denylist, so it is
run deliberately, not casually.

⚠ Unlike the PCIe width writes, this one is NOT self-severing: 0xE208 does not touch the PCIe
link, so host access is retained throughout and the restore path always exists.

usage: ifr_dump.py <bdf> [--apply] [--out ifr-prefix.bin]
"""
import argparse, hashlib, json, mmap, os, struct, sys, time

PROM = 0x300000                 # NV_PROM aperture in BAR0
ROM_ADDR_OFFSET = 0xE208        # EN 0:0, AMOUNT 23:2 (dwords)
APERTURE_ARMED = 0x00000A01     # EN=1, AMOUNT=0x280 -> skewed 0xA00 from physical
APERTURE_ZERO = 0x00000001      # EN=1, AMOUNT=0     -> aperture starts at physical 0
PREFIX = 0xA00                  # bytes hidden below the armed window
TAIL = 0x80                     # overlap used for the correctness check
MEM_SPACE_EN = 1 << 1


def openbar(bdf, rw):
    cfg = "/sys/bus/pci/devices/%s/config" % bdf
    with open(cfg, "r+b", buffering=0) as f:
        f.seek(4); orig = struct.unpack("<H", f.read(2))[0]
        if not orig & MEM_SPACE_EN:
            f.seek(4); f.write(struct.pack("<H", orig | MEM_SPACE_EN))
    p = "/sys/bus/pci/devices/%s/resource0" % bdf
    fd = os.open(p, (os.O_RDWR if rw else os.O_RDONLY) | os.O_SYNC)
    mm = mmap.mmap(fd, min(os.path.getsize(p), 32 << 20), mmap.MAP_SHARED,
                   mmap.PROT_READ | (mmap.PROT_WRITE if rw else 0))
    os.close(fd)
    return mm


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bdf"); ap.add_argument("--apply", action="store_true")
    ap.add_argument("--out", default="/tmp/ifr-prefix.bin")
    a = ap.parse_args()
    out = {"tool": "ifr_dump.py", "bdf": a.bdf, "applied": a.apply,
           "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    mm = openbar(a.bdf, rw=a.apply)
    rd = lambda o: struct.unpack_from("<I", mm, o)[0]
    boot0, ent = rd(0), rd(ROM_ADDR_OFFSET)
    out["PMC_BOOT_0"] = "0x%08X" % boot0
    out["ROM_ADDR_OFFSET_entry"] = "0x%08X" % ent
    print("PMC_BOOT_0 = 0x%08X" % boot0)
    print("ROM_ADDR_OFFSET 0x%05X = 0x%08X  (EN=%d, AMOUNT=0x%X dwords = 0x%X bytes)"
          % (ROM_ADDR_OFFSET, ent, ent & 1, (ent >> 2) & 0x3FFFFF, ((ent >> 2) & 0x3FFFFF) * 4))
    if ent != APERTURE_ARMED:
        print("⛔ ABORT: entry value is not the expected armed 0x%08X" % APERTURE_ARMED)
        sys.exit(1)

    armed_head = bytes(mm[PROM:PROM + TAIL])
    out["armed_head"] = armed_head[:16].hex()
    print("\narmed window head: %s ..." % armed_head[:16].hex())
    print("  (legacy ROM signature 0x55AA expected: %s)"
          % ("YES" if armed_head[:2] == b"\x55\xaa" else "no"))

    if not a.apply:
        print("\n(dry run: pass --apply to slide the window and dump the prefix)")
        mm.close(); print(json.dumps(out)); return

    blob = None
    try:
        print("\n--- sliding aperture to physical 0: 0x%05X <- 0x%08X ---"
              % (ROM_ADDR_OFFSET, APERTURE_ZERO))
        struct.pack_into("<I", mm, ROM_ADDR_OFFSET, APERTURE_ZERO)
        time.sleep(0.05)
        now = rd(ROM_ADDR_OFFSET)
        out["ROM_ADDR_OFFSET_slid"] = "0x%08X" % now
        print("  reads back 0x%08X  %s" % (now, "OK" if now == APERTURE_ZERO else "⛔ REFUSED"))
        if now != APERTURE_ZERO:
            out["verdict"] = "SLIDE_REFUSED"; return
        blob = bytes(mm[PROM:PROM + PREFIX + TAIL])
    finally:
        struct.pack_into("<I", mm, ROM_ADDR_OFFSET, APERTURE_ARMED)
        time.sleep(0.05)
        back = rd(ROM_ADDR_OFFSET)
        out["ROM_ADDR_OFFSET_restored"] = "0x%08X" % back
        head2 = bytes(mm[PROM:PROM + TAIL])
        ok = (back == APERTURE_ARMED and head2 == armed_head)
        out["restore_verified"] = ok
        print("\n--- restore ---")
        print("  0x%05X = 0x%08X   window head identical: %s   %s"
              % (ROM_ADDR_OFFSET, back, head2 == armed_head,
                 "RESTORED CLEAN" if ok else "⛔ RESTORE PROBLEM"))
        mm.close()

    if blob:
        overlap_ok = blob[PREFIX:PREFIX + TAIL] == armed_head
        out["overlap_check"] = overlap_ok
        print("\n--- correctness check ---")
        print("  new[0xA00:0xA80] == armed window head : %s" % overlap_ok)
        if not overlap_ok:
            print("  ⛔ window did not land where expected -- DISCARDING the dump")
            out["verdict"] = "WINDOW_MISMATCH"
        else:
            pre = blob[:PREFIX]
            open(a.out, "wb").write(pre)
            out["out"] = a.out
            out["sha256"] = hashlib.sha256(pre).hexdigest()
            out["nonzero_bytes"] = sum(1 for b in pre if b)
            out["verdict"] = "OK"
            print("  ★ prefix captured: %d bytes -> %s" % (len(pre), a.out))
            print("    sha256 %s" % out["sha256"])
            print("    non-zero bytes: %d / %d" % (out["nonzero_bytes"], PREFIX))
            print("\n--- first 256 bytes ---")
            for off in range(0, 0x100, 16):
                row = pre[off:off + 16]
                txt = "".join(chr(c) if 32 <= c < 127 else "." for c in row)
                print("  %04X  %-47s  %s" % (off, row.hex(" "), txt))
    print()
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
