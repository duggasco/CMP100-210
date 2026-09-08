# ECC: the gate is one VBIOS bit, and it is behind every wall at once

**Date:** 2026-09-06 (pass 65) · **Card:** `0000:0b:00.0` · **Nothing was written to the card.**
Companion: `~/170hx_unlock/docs/ecc-capability-gate-source-analysis-2026-08-03.md` (GA100, where
this gate was originally decoded) and `ecc-pmu-recipe-shareable-2026-08-12.md`.

## 0. Result

ECC on this card is gated by **one bit in the VBIOS**, isolated to a byte:

| ROM | INTERNAL_USE table | `bFlag5` @ aperture `0x0003E3` | `SKU_SUPPORTS_ECC` |
|---|---|---|---|
| **CMP 100-210 (this card)** | `0x03A0`, ver 2, size 96 | **`0x00`** | **0** |
| **stock Tesla V100** | `0x03A0`, ver 2, size 96 | **`0x01`** | **1** |

Identical table location and size; the two ROMs differ in that one bit. This mirrors the
170HX-vs-A100 result exactly, so it is the deliberate SKU nerf, not a Volta quirk.

⇒ **It cannot be lifted on this card.** Not "hard" — blocked by three independent things at once.

## 1. Why it is not a fuse or a register problem

Everything *below* the VBIOS already says ECC is available. Measured on a POSTed card:

* `NV_FUSE_OPT_ECC_EN 0x021228` = **1** (the 170HX reads 0)
* the HBM2 dies themselves report **ECC-capable = 1** in their IEEE-1500 `DEVICE_ID`
  (`FINDINGS-2026-09-06-memory-clock-unlocked.md` §7)
* `nvidia-smi` nonetheless reports `ECC Mode: Current N/A / Pending N/A`

The reason no register work helps is in the RM source: `gpuQueryEccStatus_IMPL` reads
`bSkuSupportsECC = ((pVbios->InternalUseFlags5 & …SKU_SUPPORTS_ECC) != 0)` — a field of RM's
**parsed VBIOS structure in host memory**. Clause B **reads no GPU register at all**. So there is
no BAR0 poke, no PLM, no decode-trap stamp and no fuse override that can move it. The 170HX
programme established this and spent considerable effort proving it the hard way.

## 2. Locating the byte (method, reusable)

Per the GA100 analysis, applied to a GV100 ROM:

1. Image base: our ROM is a **raw expansion ROM** with `55 AA` at aperture `0x0` (the GA100 ROMs
   are NV-container images based at `0x5E00` — getting this wrong yields a plausible but
   meaningless table).
2. Find `FF B8 42 49 54 00`; here at `0x0001B0`. `HeaderSize=12 TokenSize=6 TokenEntries=17`.
3. Walk 6-byte tokens `{TokenId, DataVersion, DataSize:u16, DataPtr:u16}`; take
   `TokenId = 0x69` (`BIT_TOKEN_INTERNAL_USE`) with `DataVersion == 2`, `DataSize >= 68`.
   Ours: ver 2, size **96**, ptr `0x03A0`.
4. `bFlag5` is packed byte **67** ⇒ aperture `0x03A0 + 67` = **`0x0003E3`**.
5. `NV_BIT_DATA_INTERNAL_V2_BFLAG5_SKU_SUPPORTS_ECC = 0x01`, polarity **SET = supports**.

## 3. ⛔ Why it is blocked — three walls, any one of which is fatal

1. **It lives in the legacy image.** Aperture `0x0003E3` is inside `0x0`–`0xE400`, and pass 63
   established that **RM refuses to POST a card whose legacy image has been modified by even one
   byte** with the checksum correct — `RmInitAdapter failed! (0x31:0xffff:2780)`, reproduced
   **6/6** against **6/6** clean on the unmodified image. Two unrelated *inert* edits fail
   identically, so this is not about what the byte means.
2. **It needs an erase, and uniquely that erase lands in the IFR's own sector.**
   ⛔ *An earlier draft listed "needs an erase" as a blocker in its own right. That was wrong and is
   retracted — `tools/spi_flash_l3.py` does sector erase + 4 KiB bulk reprogram and has done it
   cleanly ~8 times this session. Delivery is not the problem.* What is specific to **this** byte:
   the transition is `0x00 → 0x01` (0→1, so erase is unavoidable) at physical `0x0003E3 + 0xA00` =
   **`0x000DE3`**, in flash sector **`0x000000`** — the sector containing the IFR.
   That matters because the IFR is **the first link of our own recovery chain**:

   | recovery link | lives in |
   |---|---|
   | card enumerates (IFR: `ROM_ADDR_OFFSET`, PCIe cfg) | **sector `0x000000`** |
   | FWSECLIC ucode (fires the chain) | sector `0x020000` |
   | `cand5.rom` ULF payload | sector `0x042000` |
   | ⇒ trap 20 ⇒ SPI stamp | volatile |

   Erasing `0x008000` or `0x00E000` is safe precisely because a failed reprogram still leaves an
   enumerable, flashable card. Erasing `0x000000` does not have that property: lose the IFR and
   there is no BAR0, hence no SPI primitive, hence CH341A only.
3. **Even with the bit set, GA100 says it would not be working ECC.** The 170HX programme drove
   the hardware ECC-DRAM readout with PMU code-exec + trap-31 and recorded the outcome plainly:
   *"Not working ECC. Not user-visible. Not durable across a driver load"* — a PMU bootstrap
   re-derives the fuse shadow and reverts it. And that route needed **PMU code execution**, which
   on Volta we do not have: the PMU is HS-sealed (`IMEMC.SEC_LOCK = 1`, reads poison `0xDEAD5EC1`).

## 3a. ★ Measured: the integrity check DOES cover the ECC bit's region — so sector 0 need never be risked

Wall 1 had only ever been demonstrated mid-image (aperture `0x008222`) and late-image
(`0x00E2D0`). The ECC bit sits near the **start** (`0x0003E3`), which was untested — and if
coverage had a hole there, ECC would have reopened. That was settled **without touching sector
`0x000000`**:

* byte A — aperture `0x0600` / physical `0x001000` / sector **`0x001000`**: `0xE8 → 0xE0` (−8)
* byte B — aperture `0x00E2D0` / physical `0x00ECD0` / sector **`0x00E000`**: `0xFF → 0x07` (+8 mod 256)

Both pure 1→0 (no erase), net checksum delta **0**, and both in sectors already proven safe to
erase and rewrite. Byte A is the first byte of the x86 option-ROM body — irrelevant on a headless
card, since RM POSTs directly and the legacy option ROM never executes.

Result: **0 POST / 3 attempts**, every one `RmInitAdapter failed! (0x31:0xffff:2780)`. Reverted by
SPI erase + reprogram of both sectors, verified byte-exact against `cand5.rom` (`185ad14d…`), card
POSTs again, 0 Xids.

⇒ coverage is now demonstrated at **three widely separated points** — early `0x0600`, mid
`0x008222`, late `0x00E2D0` — so the check spans the legacy image and the BIT table at `0x03A0` is
inside it. **ECC is definitively behind wall 1, and no experiment ever needs to erase sector 0.**

## 4. The second gate, moot but worth recording

Independently of the VBIOS bit, the **InfoROM has no ECC object**:

```
OEM Object                : 1.1
ECC Object                : N/A      <- RM's ECC state / error bookkeeping
Power Management Object   : N/A      <- why only Instantaneous Power Draw works
```

Both were stripped for the CMP SKU. Unlike the VBIOS bit, the InfoROM **is** in the in-band
writable region (physical ≥ `0x00EE00`; it is where `cand5.rom` lives). So *that* half is
reachable — but it is pointless while gate 1 is closed, and constructing an InfoROM object RM
accepts is its own project.

## 5. Verdict

**ECC is closed on this card**, and it is a strictly worse target than the three devinit words:
same legacy-image integrity wall, plus an erase, plus that erase landing in the IFR sector, plus
GA100's evidence that the payoff would not be working ECC anyway.

★ The one thing that *would* move it is the same thing that would move the devinit words: the
integrity check that rejects a modified legacy image lives in **`nv-kernel.o`**, not in silicon —
the card's own BIOSCERT is clean on a modified image (`BIOSCERT_ERR = 0x00`, PMU `CPUCTL = 0x20`,
post-codes byte-identical). See `FINDINGS-2026-09-05-vbios-write-boundary.md` §8.
