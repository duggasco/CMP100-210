#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright 2026 duggasco
"""General SPI flash access on a GV100, through the pass-54 trap-20 L3 stamp.

Generalises `spi_write_ifr_l3.py` (pass 60, which did exactly one 1-byte page program at flash
`0x000214`) into read / page-program / **sector-erase** / bulk-rewrite, because three things the
tree wants all need more than one byte:

  * fp64/tensor devinit word   3 bytes, all 1->0, NO erase   (works with the pass-60 primitive)
  * memory NDIV                needs a 4 KiB sector erase
  * PCIe Gen3 devinit word     needs a 4 KiB sector erase

## Why this path and not nvflash

nvflash's PMU flash service refuses **any** write below physical `0x00EE00` -- the IFR plus the
legacy image -- and halts the falcon when asked (pass 63, seven data points). The L3 SPI stamp does
not use that service at all: it drives `SPI_CTRL` / `SPI_DATA_ARRAY` directly, with trap 20
stamping each host L0 write to LEVEL_3. Pass 60 already programmed physical `0x000214` this way,
which is sector 0. The chip itself permits everything: `SR1 = SR2 = 0x00`, so `BP2:BP0 = 000` and
`TB = SEC = CMP = SRL = 0` -- no block protection anywhere.

## Hard constraints

`SPI_DATA_ARRAY` dwords 0-31 (`0xE4A0`..) are TX staging = **128 bytes**, so one page program
carries at most **124** payload bytes after the 4-byte cmd+address. Dwords 32-63 (`0xE520`..) are
the RX buffer. A 4 KiB sector therefore takes ~34 program frames, each with its own `WREN` and
`BUSY` poll, and chunks must not cross a 256-byte page boundary.

## Safety

* Every write is preceded by a read of the current bytes and refuses unless they match `--expect`.
* `--program` refuses any byte whose change is not a pure 1->0 unless `--allow-erase` is given,
  because a NOR page program can only clear bits; a 0->1 silently does nothing.
* Erase is only reachable via the explicit `erase` subcommand.
* ⚠ **1->0 writes are ONE-WAY without an erase.** Prove the erase path on free space before making
  any one-way write you might need to undo. Physical `0x080000` sits in an all-0xFF run spanning
  `0x04295D`-`0x100000` (757 KiB), outside every image.
* ⚠ After a legacy-image edit **nvflash can no longer revert it**; the restore is also over SPI.

usage:
  spi_flash_l3.py <bdf> id
  spi_flash_l3.py <bdf> read  <addr> <len>
  spi_flash_l3.py <bdf> erase <addr>                     --i-know-this-erases
  spi_flash_l3.py <bdf> program <addr> <hexbytes> --expect <hexbytes>
  spi_flash_l3.py <bdf> verify <addr> <hexbytes>
"""
import argparse, mmap, os, struct, sys, time

TRAP = 20
T_MATCH = 0x122400 + TRAP * 4
T_ACTION = 0x122600 + TRAP * 4
WANT_ACTION = 0x00100000

SPI_DATA0 = 0x00E4A0
RX0 = SPI_DATA0 + 32 * 4          # 0xE520
SPI_CTRL = 0x00E5A0
MEM_SPACE_EN = 1 << 1
SENT = 0xEEEEEEEE
TX, RX, DESEL, GO = 1 << 16, 1 << 17, 1 << 27, 1 << 31

RDID, RDSR, READ, WREN, PP, SE = 0x9F, 0x05, 0x03, 0x06, 0x02, 0x20
# ⚠ MEASURED, not derived. The TX staging area is 128 bytes, but the engine truncates any
# transaction whose TOTAL exceeds 124: a 4+120 read returns fully, 4+121 and up leave 94 bytes of
# the RX buffer untouched (still holding the 0xEE sentinel). So the usable payload after a 4-byte
# cmd+address is 120, not 124. Pass 60's tool never issued a frame larger than 5 bytes, so this
# limit had never been hit.
MAX_TOTAL = 124
MAX_PAYLOAD = MAX_TOTAL - 4       # 120
PAGE = 256
SECTOR = 4096


class Spi:
    def __init__(self, rd, wr):
        self.rd, self.wr = rd, wr

    def _aim(self, addr):
        self.wr(T_MATCH, addr)

    def frame(self, tx_bytes, total):
        if total > MAX_TOTAL:
            raise ValueError("total %d exceeds the measured %d-byte transaction limit"
                             % (total, MAX_TOTAL))
        # cap at the 32-dword RX window: RX0 + 32*4 is SPI_CTRL itself, not receive data
        nrx = min((total + 3) // 4 + 1, 32)
        for k in range(nrx):
            self._aim(RX0 + k * 4); self.wr(RX0 + k * 4, SENT)
        for k in range((len(tx_bytes) + 3) // 4):
            word = int.from_bytes(tx_bytes[k * 4:k * 4 + 4].ljust(4, b"\xee"), "little")
            self._aim(SPI_DATA0 + k * 4); self.wr(SPI_DATA0 + k * 4, word)
        ctrl = ((total - 1) & 0xFF) | (((len(tx_bytes) - 1) & 0xFF) << 8) | TX | DESEL | GO
        if total > len(tx_bytes):
            ctrl |= RX
        self._aim(SPI_CTRL); self.wr(SPI_CTRL, ctrl)
        end = time.time() + 2.0
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

    def read(self, addr, n):
        out = b""
        while n:
            c = min(n, MAX_PAYLOAD)
            cmd = bytes((READ, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF))
            out += self.frame(cmd, 4 + c)[4:]
            addr += c; n -= c
        return out

    def wren(self):
        self.frame(bytes((WREN,)), 1)
        if not self.rdsr() & 0x02:
            raise RuntimeError("WREN did not set WEL")

    def wait(self, timeout=5.0):
        end = time.time() + timeout
        while self.rdsr() & 0x01:
            if time.time() > end:
                raise RuntimeError("BUSY stuck set")

    def page_program(self, addr, data):
        assert len(data) <= MAX_PAYLOAD
        assert (addr // PAGE) == ((addr + len(data) - 1) // PAGE), "crosses a page boundary"
        self.wren()
        cmd = bytes((PP, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF)) + data
        self.frame(cmd, len(cmd))
        self.wait()
        if self.rdsr() & 0x02:
            raise RuntimeError("WEL still set after program")

    def sector_erase(self, addr):
        self.wren()
        cmd = bytes((SE, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF))
        self.frame(cmd, len(cmd))
        self.wait(timeout=10.0)

    def write_span(self, addr, data, log=lambda s: None):
        """Program an arbitrary span, chunked to fit staging and page boundaries."""
        off = 0
        n = 0
        while off < len(data):
            a = addr + off
            room = PAGE - (a % PAGE)
            c = min(MAX_PAYLOAD, room, len(data) - off)
            self.page_program(a, data[off:off + c])
            off += c; n += 1
            if n % 8 == 0:
                log("    %d/%d bytes" % (off, len(data)))
        return n


def openbar(bdf):
    cfg = "/sys/bus/pci/devices/%s/config" % bdf
    with open(cfg, "r+b", buffering=0) as f:
        f.seek(4); oc = struct.unpack("<H", f.read(2))[0]
        if not oc & MEM_SPACE_EN:
            f.seek(4); f.write(struct.pack("<H", oc | MEM_SPACE_EN))
    p = "/sys/bus/pci/devices/%s/resource0" % bdf
    fd = os.open(p, os.O_RDWR | os.O_SYNC)
    mm = mmap.mmap(fd, min(os.path.getsize(p), 32 << 20), mmap.MAP_SHARED,
                   mmap.PROT_READ | mmap.PROT_WRITE)
    os.close(fd)
    return mm


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bdf")
    ap.add_argument("cmd", choices=("id", "read", "erase", "program", "verify"))
    ap.add_argument("addr", nargs="?")
    ap.add_argument("arg", nargs="?")
    ap.add_argument("--expect", help="hex bytes that must currently be present")
    ap.add_argument("--allow-erase", action="store_true",
                    help="permit a program whose bits are not purely 1->0 (it will NOT take)")
    ap.add_argument("--i-know-this-erases", action="store_true")
    a = ap.parse_args()

    mm = openbar(a.bdf)
    rd = lambda o: struct.unpack_from("<I", mm, o)[0]
    wr = lambda o, v: struct.pack_into("<I", mm, o, v & 0xFFFFFFFF)
    spi = Spi(rd, wr)

    if rd(T_ACTION) != WANT_ACTION:
        sys.exit("trap20 ACTION=0x%08X, not armed (0x%08X). SBR with cand5.rom resident."
                 % (rd(T_ACTION), WANT_ACTION))

    jid = spi.rdid()
    if jid != bytes((0xEF, 0x60, 0x14)):
        sys.exit("RDID = %s, expected EF 60 14 -- engine not answering" % jid.hex())
    sr = spi.rdsr()
    print("RDID EF 60 14   SR1 0x%02X  (BUSY=%d WEL=%d BP=%d)" % (sr, sr & 1, (sr >> 1) & 1, (sr >> 2) & 7))

    if a.cmd == "id":
        return

    addr = int(a.addr, 0)

    if a.cmd == "read":
        n = int(a.arg, 0)
        d = spi.read(addr, n)
        for i in range(0, len(d), 16):
            print("  %06X  %s" % (addr + i, ' '.join('%02X' % b for b in d[i:i + 16])))
        return

    if a.cmd == "verify":
        want = bytes.fromhex(a.arg)
        got = spi.read(addr, len(want))
        print("  at 0x%06X want %s got %s  => %s"
              % (addr, want.hex(), got.hex(), "MATCH" if got == want else "MISMATCH"))
        sys.exit(0 if got == want else 1)

    if a.cmd == "erase":
        if not a.i_know_this_erases:
            sys.exit("refusing: pass --i-know-this-erases")
        if addr % SECTOR:
            sys.exit("address must be 4 KiB aligned")
        print("  erasing sector 0x%06X ..." % addr)
        t0 = time.time()
        spi.sector_erase(addr)
        print("  done in %.3f s" % (time.time() - t0))
        d = spi.read(addr, 64)
        print("  first 64 bytes all 0xFF: %s" % all(b == 0xFF for b in d))
        return

    if a.cmd == "program":
        data = bytes.fromhex(a.arg)
        cur = spi.read(addr, len(data))
        if a.expect is not None:
            exp = bytes.fromhex(a.expect)
            if cur != exp:
                sys.exit("REFUSING: at 0x%06X found %s, --expect %s" % (addr, cur.hex(), exp.hex()))
        bad = [i for i in range(len(data)) if (data[i] & ~cur[i])]
        if bad and not a.allow_erase:
            sys.exit("REFUSING: byte(s) %s need 0->1 bits; a page program cannot set bits. "
                     "Erase the sector first." % bad)
        print("  0x%06X: %s -> %s" % (addr, cur.hex(), data.hex()))
        n = spi.write_span(addr, data, log=print)
        got = spi.read(addr, len(data))
        print("  %d frame(s); readback %s  => %s"
              % (n, got.hex(), "LANDED" if got == data else "FAILED"))
        sys.exit(0 if got == data else 1)


if __name__ == "__main__":
    main()
