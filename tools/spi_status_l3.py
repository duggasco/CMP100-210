#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 duggasco
"""Read the SPI flash JEDEC id and STATUS REGISTERS over the trap-20 L3 stamp. READ-ONLY ON FLASH.

Supersedes `spi_rdsr_l3.py` / `spi_rdid_l3.py`, both of which looked in the wrong place.

★ **The `SPI_DATA_ARRAY` is split.** Dwords 0-31 (`0xE4A0`-`0xE51F`) are the TX staging area;
**dwords 32-63 (`0xE520`+) are the RECEIVE buffer.** Found by dumping the whole block: dword 32
already held `0x1460EFFF` = bytes `FF EF 60 14`, the JEDEC reply left behind by nvflash's own RDID.
Byte 0 of the RX dword is the don't-care clocked out during the command phase; the reply starts at
byte 1. Earlier probes dumped only 16 dwords and never reached it.

Method, per command:
  1. aim the stamp at the RX dword and pre-fill it with a SENTINEL, so a fresh reply is provably
     distinct from residue (this is what the earlier runs could not establish)
  2. aim at TX dword 0, stage the opcode
  3. aim at SPI_CTRL, trigger; poll TRANSFER
  4. read the RX dword -- changed away from the sentinel == a real reply

RDID runs first as a positive control: if `EF 60 14` does not come back fresh, no status read from
the same run may be believed.

⛔ Safety: only read opcodes are ever staged -- `0x9F` RDID, `0x05` RDSR, `0x35` RDSR-2. Never
`WREN` (0x06), `WRSR` (0x01), program (0x02) or any erase (0x20/0x52/0xD8/0xC7/0x60).
`ROM_SERIAL_BYPASS` is untouched. All writes restored; an SBR clears engine state regardless.

usage: spi_status_l3.py <bdf> [--go]
"""
import argparse, json, mmap, os, struct, sys, time

TRAP = 20
T_MATCH = 0x122400 + TRAP * 4
T_DATA1 = 0x122500 + TRAP * 4
T_ACTION = 0x122600 + TRAP * 4

SPI_DATA0 = 0x00E4A0
RX_DWORD = 32
RX_ADDR = SPI_DATA0 + RX_DWORD * 4          # 0x00E520
SPI_CTRL = 0x00E5A0
MEM_SPACE_EN = 1 << 1
SENTINEL = 0xEEEEEEEE

TX, RX, DESEL, GO = 1 << 16, 1 << 17, 1 << 27, 1 << 31


def ctrl_for(total):
    """TRANSFER_SIZE 7:0 and TRANSMIT_SIZE 15:8 are N-1 encoded; 1 byte out, rest in."""
    return ((total - 1) << 0) | ((1 - 1) << 8) | TX | RX | DESEL | GO


def decode_sr1(v):
    return {"BUSY": v & 1, "WEL": (v >> 1) & 1, "BP0": (v >> 2) & 1, "BP1": (v >> 3) & 1,
            "BP2": (v >> 4) & 1, "TB": (v >> 5) & 1, "SEC": (v >> 6) & 1, "SRP0": (v >> 7) & 1}


def protected(sr1, sr2):
    """W25Q80EW: 1 MiB, 16 x 64 KiB blocks."""
    bp, tb, sec = (sr1 >> 2) & 7, (sr1 >> 5) & 1, (sr1 >> 6) & 1
    cmp_ = (sr2 >> 6) & 1
    if bp == 0:
        base = "NONE — no block protection"
    elif sec:
        kb = {1: 4, 2: 8, 3: 16, 4: 32, 5: 32}.get(bp, 32)
        base = "%d KiB at the %s" % (kb, "BOTTOM" if tb else "top")
    else:
        base = "%d KiB at the %s" % (min(64 * (1 << (bp - 1)), 1024), "BOTTOM" if tb else "top")
    return base + ("   (CMP=1 => COMPLEMENT of that)" if cmp_ else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bdf")
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

    r = {"bdf": a.bdf, "rx_dword": "%d (0x%06X)" % (RX_DWORD, RX_ADDR), "dry_run": not a.go}
    saved = {}
    try:
        r["trap20"] = {"DATA1": "0x%08X" % rd(T_DATA1), "ACTION": "0x%08X" % rd(T_ACTION)}
        if not (rd(T_DATA1) == 0xC0000000 and rd(T_ACTION) == 0x00100000):
            r["error"] = "trap20 not armed with the L3 stamp"; raise SystemExit
        r["entry"] = {"SPI_CTRL": "0x%08X" % rd(SPI_CTRL),
                      "TX_dword0": "0x%08X" % rd(SPI_DATA0),
                      "RX_dword32": "0x%08X" % rd(RX_ADDR)}
        if not a.go:
            r["note"] = "dry run"; raise SystemExit

        saved = {"match": rd(T_MATCH), "tx": rd(SPI_DATA0),
                 "rx": rd(RX_ADDR), "ctrl": rd(SPI_CTRL)}
        out = {}
        for label, op, total in (("RDID", 0x9F, 4), ("SR1", 0x05, 2), ("SR2", 0x35, 2)):
            wr(T_MATCH, RX_ADDR);   wr(RX_ADDR, SENTINEL)          # 1. poison the RX dword
            wr(T_MATCH, SPI_DATA0); wr(SPI_DATA0, 0xEEEEEE00 | op)  # 2. stage the opcode
            wr(T_MATCH, SPI_CTRL);  wr(SPI_CTRL, ctrl_for(total))   # 3. trigger
            end = time.time() + 1.0
            stuck = False
            while rd(SPI_CTRL) >> 31 & 1:
                if time.time() > end:
                    stuck = True; break
            got = rd(RX_ADDR)                                       # 4. read the reply
            b = struct.pack("<I", got)
            out[label] = {"opcode": "0x%02X" % op, "total_bytes": total,
                          "SPI_CTRL": "0x%08X" % ctrl_for(total),
                          "stuck_pending": stuck,
                          "RX_before": "0x%08X" % SENTINEL, "RX_after": "0x%08X" % got,
                          "fresh": got != SENTINEL,
                          "bytes": " ".join("%02X" % x for x in b)}
        r["runs"] = out

        if not out["RDID"]["fresh"]:
            r["VERDICT"] = ("RDID did not refresh the RX dword -- the engine is not transferring; "
                            "no status value from this run may be believed")
        else:
            jed = struct.pack("<I", int(out["RDID"]["RX_after"], 16))[1:4]
            r["jedec"] = " ".join("%02X" % x for x in jed)
            r["jedec_ok"] = jed == bytes((0xEF, 0x60, 0x14))
            if r["jedec_ok"] and out["SR1"]["fresh"] and out["SR2"]["fresh"]:
                sr1 = struct.pack("<I", int(out["SR1"]["RX_after"], 16))[1]
                sr2 = struct.pack("<I", int(out["SR2"]["RX_after"], 16))[1]
                r["SR1"] = "0x%02X" % sr1
                r["SR2"] = "0x%02X" % sr2
                r["SR1_decoded"] = decode_sr1(sr1)
                r["SR2_CMP"] = (sr2 >> 6) & 1
                r["SR2_SRL"] = sr2 & 1
                r["PROTECTED_REGION"] = protected(sr1, sr2)
                r["VERDICT"] = "status registers read: SR1=0x%02X SR2=0x%02X" % (sr1, sr2)
            else:
                r["VERDICT"] = "RDID fresh but jedec/status mismatch -- see runs"
    except SystemExit:
        pass
    except Exception as e:
        r["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        try:
            if saved:
                wr(T_MATCH, RX_ADDR);   wr(RX_ADDR, saved["rx"])
                wr(T_MATCH, SPI_DATA0); wr(SPI_DATA0, saved["tx"])
                wr(T_MATCH, SPI_CTRL);  wr(SPI_CTRL, saved["ctrl"] & ~GO)
                wr(T_MATCH, saved["match"])
                r["restored"] = {"TX": "0x%08X" % rd(SPI_DATA0), "RX": "0x%08X" % rd(RX_ADDR),
                                 "CTRL": "0x%08X" % rd(SPI_CTRL),
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
