#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 duggasco
"""Program the one-byte IFR width edit directly over SPI, via the trap-20 L3 stamp.

nvflash cannot deliver this: flash sector 0 (the IFR) is outside its `0xFF600` extent, behind
`ROM_ADDR_OFFSET` (`FINDINGS-2026-09-05-cert20-gate-located.md` §7d/§8f). The manual SPI frame
engine can — `logs/81` read the JEDEC id and both status registers through it, with a sentinel
control proving the replies were fresh.

## The edit

    flash 0x000214 : 0x42 -> 0x02      (IFR record target 0x08C040 -> 0x08C000)

`XP_PL_LINK_CONFIG_0` -> `XP_PL_LINK_PRESENT` (`R--4R`, read-only), which neutralises the record
that forces `LINK_SPECIFIER` to lanes `00_00` (x1). Left alone, `LINK_SPECIFIER` keeps its `_INIT`
of `0x10` = lanes `15_00` = x16. The record's length and type nibble are untouched, so the stream
stays well formed.

★ **1 -> 0 only, one bit.** NOR page program can only clear bits, so this needs **NO ERASE** — and
a single-bit clear has **no partial state**: either the bit is programmed or it is not. That
removes the erase window, which is the genuinely dangerous part of touching sector 0.

## Controls, in order (the program step is refused if any fails)

  1. RDID -> must be `EF 60 14`                     (engine alive, RX buffer fresh)
  2. READ `0x03` @ 0x000214 -> must return **0x42** (proves the address encoding matches the
     physical image; without this the write could land anywhere)
  3. WREN `0x06` -> RDSR must show **WEL = 1**      (write enable actually took)
  4. PP `0x02` @ 0x000214 with one byte 0x02
  5. poll RDSR until **BUSY = 0**, then WEL must be **0**
  6. READ back -> must be **0x02**

⛔ Opcodes used: `0x9F` RDID, `0x05` RDSR, `0x03` READ, `0x06` WREN, `0x02` PAGE PROGRAM.
**No erase opcode (`0x20`/`0x52`/`0xD8`/`0xC7`/`0x60`) appears anywhere in this file.**

⛔⛔ Recovery: nvflash CANNOT rewrite sector 0. If this leaves the IFR inconsistent the card may
fail to enumerate, and the only path back is a CH341A. The single-bit no-erase property is what
makes that unlikely, not impossible.

usage: spi_write_ifr_l3.py <bdf> [--program]      (default: controls only, no write)
"""
import argparse, json, mmap, os, struct, sys, time

TRAP = 20
T_MATCH = 0x122400 + TRAP * 4
T_DATA1 = 0x122500 + TRAP * 4
T_ACTION = 0x122600 + TRAP * 4

SPI_DATA0 = 0x00E4A0
RX0 = SPI_DATA0 + 32 * 4                 # 0xE520, receive buffer
SPI_CTRL = 0x00E5A0
MEM_SPACE_EN = 1 << 1
SENT = 0xEEEEEEEE

TX, RX, DESEL, GO = 1 << 16, 1 << 17, 1 << 27, 1 << 31

TARGET_ADDR = 0x000214
EXPECT_OLD = 0x42
NEW_BYTE = 0x02

RDID, RDSR, READ, WREN, PP = 0x9F, 0x05, 0x03, 0x06, 0x02


class Spi:
    def __init__(self, rd, wr):
        self.rd, self.wr = rd, wr

    def _aim(self, addr):
        self.wr(T_MATCH, addr)

    def frame(self, tx_bytes, total):
        """Stage tx_bytes, run a `total`-byte transaction, return the RX bytes."""
        nrx = (total + 3) // 4 + 1
        for k in range(nrx):                       # poison the RX area
            self._aim(RX0 + k * 4); self.wr(RX0 + k * 4, SENT)
        for k in range((len(tx_bytes) + 3) // 4):
            word = int.from_bytes(tx_bytes[k * 4:k * 4 + 4].ljust(4, b"\xee"), "little")
            self._aim(SPI_DATA0 + k * 4); self.wr(SPI_DATA0 + k * 4, word)
        ctrl = ((total - 1) & 0xFF) | (((len(tx_bytes) - 1) & 0xFF) << 8) | TX | DESEL | GO
        if total > len(tx_bytes):
            ctrl |= RX
        self._aim(SPI_CTRL); self.wr(SPI_CTRL, ctrl)
        end = time.time() + 1.0
        while self.rd(SPI_CTRL) >> 31 & 1:
            if time.time() > end:
                raise RuntimeError("TRANSFER stuck PENDING, SPI_CTRL=0x%08X" % self.rd(SPI_CTRL))
        out = b""
        for k in range(nrx):
            out += struct.pack("<I", self.rd(RX0 + k * 4))
        return out[:total]

    def rdid(self):
        return self.frame(bytes((RDID,)), 4)[1:4]

    def rdsr(self):
        return self.frame(bytes((RDSR,)), 2)[1]

    def read_byte(self, addr):
        cmd = bytes((READ, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF))
        return self.frame(cmd, 5)[4]

    def wren(self):
        self.frame(bytes((WREN,)), 1)

    def page_program(self, addr, data):
        cmd = bytes((PP, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF)) + data
        self.frame(cmd, len(cmd))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bdf")
    ap.add_argument("--program", action="store_true", help="actually write the byte")
    a = ap.parse_args()

    cfg = "/sys/bus/pci/devices/%s/config" % a.bdf
    with open(cfg, "r+b", buffering=0) as f:
        f.seek(4); oc = struct.unpack("<H", f.read(2))[0]
        if not oc & MEM_SPACE_EN:
            f.seek(4); f.write(struct.pack("<H", oc | MEM_SPACE_EN))
    p = "/sys/bus/pci/devices/%s/resource0" % a.bdf
    fd = os.open(p, os.O_RDWR | os.O_SYNC)
    mm = mmap.mmap(fd, min(os.path.getsize(p), 32 << 20), mmap.MAP_SHARED,
                   mmap.PROT_READ | mmap.PROT_WRITE)
    os.close(fd)
    rd = lambda o: struct.unpack_from("<I", mm, o)[0]
    wr = lambda o, v: struct.pack_into("<I", mm, o, v & 0xFFFFFFFF)
    spi = Spi(rd, wr)

    r = {"bdf": a.bdf, "target": "flash 0x%06X" % TARGET_ADDR,
         "edit": "0x%02X -> 0x%02X" % (EXPECT_OLD, NEW_BYTE),
         "will_program": a.program, "controls": {}}
    saved = None
    try:
        if not (rd(T_DATA1) == 0xC0000000 and rd(T_ACTION) == 0x00100000):
            r["error"] = "trap20 not armed"; raise SystemExit
        saved = {"match": rd(T_MATCH), "tx": rd(SPI_DATA0), "ctrl": rd(SPI_CTRL)}

        jed = spi.rdid()
        r["controls"]["1_rdid"] = " ".join("%02X" % x for x in jed)
        if jed != bytes((0xEF, 0x60, 0x14)):
            r["error"] = "RDID control failed"; raise SystemExit

        cur = spi.read_byte(TARGET_ADDR)
        r["controls"]["2_read_target"] = "0x%02X" % cur
        if cur == NEW_BYTE:
            r["already_programmed"] = True
            r["VERDICT"] = "byte is already 0x%02X -- nothing to do" % NEW_BYTE
            raise SystemExit
        if cur != EXPECT_OLD:
            r["error"] = ("address control FAILED: 0x%06X reads 0x%02X, expected 0x%02X -- "
                          "addressing does not match the physical image, REFUSING to write"
                          % (TARGET_ADDR, cur, EXPECT_OLD))
            raise SystemExit
        r["controls"]["2_verdict"] = "address encoding confirmed against the physical image"

        sr = spi.rdsr()
        r["controls"]["3_sr1_before"] = "0x%02X" % sr

        if not a.program:
            r["VERDICT"] = ("controls PASS -- addressing proven, byte still 0x%02X. "
                            "Re-run with --program to write." % cur)
            raise SystemExit

        spi.wren()
        sr = spi.rdsr()
        r["controls"]["4_sr1_after_wren"] = "0x%02X" % sr
        if not (sr >> 1) & 1:
            r["error"] = "WREN did not set WEL -- refusing to program"; raise SystemExit

        spi.page_program(TARGET_ADDR, bytes((NEW_BYTE,)))
        end = time.time() + 5.0
        while True:
            sr = spi.rdsr()
            if not sr & 1:
                break
            if time.time() > end:
                r["error"] = "WIP stuck set after program"; break
        r["controls"]["5_sr1_after_program"] = "0x%02X" % sr
        r["controls"]["5_wel_cleared"] = not ((sr >> 1) & 1)

        back = spi.read_byte(TARGET_ADDR)
        r["controls"]["6_readback"] = "0x%02X" % back
        r["VERDICT"] = ("PROGRAMMED: flash 0x%06X now reads 0x%02X" % (TARGET_ADDR, back)
                        if back == NEW_BYTE else
                        "FAILED: readback 0x%02X, wanted 0x%02X" % (back, NEW_BYTE))
    except SystemExit:
        pass
    except Exception as e:
        r["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        try:
            if saved:
                wr(T_MATCH, SPI_DATA0); wr(SPI_DATA0, saved["tx"])
                wr(T_MATCH, SPI_CTRL);  wr(SPI_CTRL, saved["ctrl"] & ~GO)
                wr(T_MATCH, saved["match"])
        except Exception as e:
            r["restore_error"] = str(e)
        mm.close()
        try:
            if not oc & MEM_SPACE_EN:
                with open(cfg, "r+b", buffering=0) as f:
                    f.seek(4); f.write(struct.pack("<H", oc))
        except Exception:
            pass
    json.dump(r, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
