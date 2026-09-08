#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 duggasco
"""Locate the SPI frame engine's RECEIVE buffer using RDID (0x9F). READ-ONLY ON THE FLASH.

`spi_rdsr_l3.py` proved the trap-20 L3 stamp can drive `SPI_CTRL`/`SPI_DATA_ARRAY` (`logs/77`) and
that a frame completes (`TRANSFER` PENDING -> DONE), but no received byte was found and RDSR's
answer is a single byte that could be confused with buffer contents.

RDID is the right instrument: it returns the **three-byte JEDEC id `EF 60 14`** — a string nvflash
already prints for this part ("EEPROM ID (EF,6014) : WBond W25Q80EW"). Searching the whole
`SPI_DATA_ARRAY` for that byte pattern locates the RX buffer unambiguously, and cannot be confused
with a staged opcode.

⛔ Safety: the only opcode transmitted is `0x9F` = RDID, read-only. No `WREN` (0x06), no `WRSR`
(0x01), no program (0x02), no erase (0x20/0x52/0xD8/0xC7/0x60) is ever staged. `ROM_SERIAL_BYPASS`
(bit-bang) is untouched. Everything written is restored; an SBR clears engine state regardless.

⚠ The stamp's `MASK = 0xFC000000` matches ONE address, so only the dword the MATCH is aimed at is
writable — the aim is moved per dword. Reads need no stamp (`ROM_PLM` allows read at L0).

usage: spi_rdid_l3.py <bdf> [--dwords 16] [--go]
"""
import argparse, json, mmap, os, struct, sys, time

TRAP = 20
T_MATCH = 0x122400 + TRAP * 4
T_DATA1 = 0x122500 + TRAP * 4
T_ACTION = 0x122600 + TRAP * 4

SPI_DATA0 = 0x00E4A0
SPI_CTRL = 0x00E5A0
ROM_HW_CONTROL = 0x00E20C
MEM_SPACE_EN = 1 << 1
RDID = 0x9F
JEDEC = bytes((0xEF, 0x60, 0x14))          # what nvflash reports for this part
# ★ The array is split: dwords 0-31 are the TX staging area, dwords 32-63 are the RECEIVE
# buffer. Found by dumping the whole block -- dword 32 (0xE520) already held 0x1460EFFF, i.e.
# bytes FF EF 60 14, the JEDEC reply left by nvflash's own RDID. Byte 0 of the RX dword is the
# don't-care clocked during the command phase; the reply starts at byte 1.
RX_DWORD = 32
RX_ADDR = SPI_DATA0 + RX_DWORD * 4

TX, RX, DESEL, GO = 1 << 16, 1 << 17, 1 << 27, 1 << 31


def variants():
    """(label, SPI_CTRL) -- TRANSFER_SIZE 7:0 and TRANSMIT_SIZE 15:8 are N-1 encoded."""
    return [
        ("A total=4 tx=1 deselect", ((4 - 1) << 0) | ((1 - 1) << 8) | TX | RX | DESEL | GO),
        ("B total=4 tx=1 no-desel", ((4 - 1) << 0) | ((1 - 1) << 8) | TX | RX | GO),
        ("C total=3 tx=1 deselect", ((3 - 1) << 0) | ((1 - 1) << 8) | TX | RX | DESEL | GO),
        ("D rx-only-size=3       ", ((3 - 1) << 0) | ((1 - 1) << 8) | TX | RX | DESEL | GO),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bdf")
    ap.add_argument("--dwords", type=int, default=64)
    ap.add_argument("--go", action="store_true")
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
    dump = lambda n: [rd(SPI_DATA0 + k * 4) for k in range(n)]

    def as_bytes(dw):
        b = bytearray()
        for v in dw:
            b += struct.pack("<I", v)
        return bytes(b)

    r = {"bdf": a.bdf, "opcode": "0x9F RDID", "looking_for": "EF 60 14", "dry_run": not a.go}
    saved = {}
    try:
        r["trap20"] = {"DATA1": "0x%08X" % rd(T_DATA1), "ACTION": "0x%08X" % rd(T_ACTION)}
        if not (rd(T_DATA1) == 0xC0000000 and rd(T_ACTION) == 0x00100000):
            r["error"] = "trap20 not armed"; raise SystemExit
        r["entry"] = {"SPI_CTRL": "0x%08X" % rd(SPI_CTRL),
                      "ROM_SERIAL_HW_CONTROL": "0x%08X" % rd(ROM_HW_CONTROL),
                      "array_head": ["0x%08X" % v for v in dump(4)]}
        if not a.go:
            r["variants"] = [{"label": l, "SPI_CTRL": "0x%08X" % c} for l, c in variants()]
            r["note"] = "dry run"; raise SystemExit

        saved = {"match": rd(T_MATCH), "data0": rd(SPI_DATA0), "ctrl": rd(SPI_CTRL)}
        out = []
        for label, ctrl in variants():
            wr(T_MATCH, SPI_DATA0)
            wr(SPI_DATA0, 0xEEEEEE00 | RDID)      # opcode in byte0, sentinel elsewhere
            before = dump(a.dwords)
            wr(T_MATCH, SPI_CTRL)
            wr(SPI_CTRL, ctrl)
            end = time.time() + 1.0
            stuck = False
            while rd(SPI_CTRL) >> 31 & 1:
                if time.time() > end:
                    stuck = True; break
            after = dump(a.dwords)
            blob = as_bytes(after)
            idx = blob.find(JEDEC)
            out.append({
                "variant": label, "SPI_CTRL": "0x%08X" % ctrl,
                "RX_dword32": "0x%08X" % after[RX_DWORD] if len(after) > RX_DWORD else None,
                "stuck_pending": stuck,
                "ctrl_after": "0x%08X" % rd(SPI_CTRL),
                "changed_dwords": [{"i": k, "was": "0x%08X" % before[k], "now": "0x%08X" % after[k]}
                                   for k in range(a.dwords) if before[k] != after[k]],
                "jedec_found_at_byte": idx if idx >= 0 else None,
                "array_head": ["0x%08X" % v for v in after[:4]],
            })
            if idx >= 0:
                out[-1]["RX_BUFFER_LOCATED"] = ("SPI_DATA_ARRAY dword %d byte %d"
                                                % (idx // 4, idx % 4))
        r["runs"] = out
        hit = next((o for o in out if o.get("jedec_found_at_byte") is not None), None)
        r["VERDICT"] = (("RX buffer located: %s (variant %s)"
                         % (hit["RX_BUFFER_LOCATED"], hit["variant"].strip()))
                        if hit else "EF 60 14 not found in any variant -- RX buffer still unknown")
    except SystemExit:
        pass
    except Exception as e:
        r["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        try:
            if saved:
                wr(T_MATCH, SPI_DATA0); wr(SPI_DATA0, saved["data0"])
                wr(T_MATCH, SPI_CTRL);  wr(SPI_CTRL, saved["ctrl"] & ~GO)
                wr(T_MATCH, saved["match"])
                r["restored"] = {"SPI_DATA0": "0x%08X" % rd(SPI_DATA0),
                                 "SPI_CTRL": "0x%08X" % rd(SPI_CTRL),
                                 "MATCH": "0x%08X" % rd(T_MATCH)}
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
