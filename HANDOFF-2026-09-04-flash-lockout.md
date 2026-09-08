# HANDOFF 2026-09-04 — CMP 100-210: the flash lockout, its cause, and the recovery

> ## ★★★ RESOLVED 2026-09-04 — the CH341A flash succeeded and in-band flashing works again.
> Card now at **`0000:0b:00.0`** (new slot), **nvflash index 7** — re-derive from `--list`.
> ROM `722bcbd…f30c9`, `SCRATCH(5)=0x7000506D`, `SCRATCH(6)=0x2208106D`, **all 22 traps
> match stock**, and a real `--wrulf` program completes `exit 0`. See pass 49d in the
> findings. Two new gotchas: the chip comes back **write-protected** after external
> programming (`--protectoff` clears it), and **nvflash leaves trap15 repurposed** — SBR
> before reading traps. Also: traps 15-18 were **never** damaged; that was a transcription
> error in my baseline. Real damage was exactly trap10 MASK + trap14 MATCH.

> ## ★★★ RESOLVED — the CH341A flash succeeded and the card is verified at baseline.
> Card reseated into a different slot: now **`0000:0b:00.0`** (was `13:00.0`), **nvflash index 7**.
> ROM sha256 `722bcbd…f30c9` exact; `SCRATCH(5)=0x7000506D`, `SCRATCH(6)=0x2208106D` exact;
> `trap_dump.py` → **all 22 traps match the pre-exploit stock state**.
> Two corrections to the body below: the damage was **2 registers** (trap14 MATCH, trap10 MASK),
> not 6 — the trap15-18 DATA2 entries were a transcription error in the tool's baseline; and
> **trap15 reads as clobbered immediately after any nvflash run** (transient PMU state — SBR first).
> See pass 50 in `FINDINGS-2026-09-02-fwseclic-audit.md`.

Companion to `HANDOFF-2026-09-05-hardware-exec.md` (which covers the overflow itself, passes
10-48). That document's exploit results all stand. This one covers **why the card can no longer
be flashed in band, what caused it, and how to get it back.**

## One-paragraph status

The FWSECLIC overflow is a proven L3 write primitive (pass 47). **Firing it in pass 48 locked the
card out of in-band flashing.** The pass-48 chain wrote PRI decode-trap registers — but slots 10
and 14 were *already in use*: devinit arms traps 10-19 as silicon workarounds. The write destroyed
trap14's `REDIRECT_RS` remap, which breaks the PMU's flash page-program service, which is the only
in-band way to remove the payload. The payload lives in ROM and re-fires every boot, so the damage
is **self-perpetuating and cannot be undone from the host** (pass 49c). Card is otherwise healthy:
it enumerates, boots, reads fine, VBIOS cert verifies; it is **55 bytes off baseline**
(`2f3568f5…c0d9` vs `722bcbd…f30c9`) and byte-identical to where the recovery session started —
every write attempt was a true no-op. **RESOLVED — see the banner above.**

## What is proven this session (do not re-derive)

| # | result | evidence |
|---|---|---|
| 49-1 | **A short BMC power cycle drops both `13:00.0` and `10:00.0` off the PCI bus entirely** — the root port for their segment does not enumerate. A **5-minute cold soak** restores both. | reproduced twice |
| 49-2 | **The PMU is NOT halted in a normal boot** — `CPUCTL=0x20`, `ENGINE=0`, `HWCFG=0x400E0100`, identical to the healthy A30X at `10:00.0`. Pass 48's "post-exploit PMU halt" explanation is wrong. | `logs/39-flash-recovery/` |
| 49-3 | **`mailbox0 = 0x20000005` = status nibble 2 (PENDING) \| cmd_id 5 (`EWR`, Page Program).** The PMU accepts the program and never completes it. It is answering, not dead. | nvflash's own command table |
| 49-4 | **`EID` (0x02), `ERD` (0x04) and `EPROT` (0x0C) all succeed on this card**; only `EWR` stalls. `--protectoff` returns exit 0, "Setting EEPROM protection complete." | `protectoff.txt` |
| 49-5 | **`--inforomnopreserve` fails identically** ⇒ InfoROM preservation is not the cause. | `r0-restore-nopreserve.txt` |
| 49-6 | **Every nvflash write path converges on one mailbox routine `0x475db8`.** `--wrulf`'s `0x51e4f0` is a pure in-memory edit; its only caller `0x50f558` reaches the same programmer via app-slot `+0x370` = `0x4f81fa` → `0x514876` → `0x51130c`. All 38 sites of backend factory `0x454b80` pass access-method `0xa` (uCode). | static RE |
| 49-7 | **`--nofalc` is not exposed in this build.** Non-PMU backends exist (`0x7b74b0`, `0x7b7710`, `0x7b8350`, `0x7b85a0`, none reach `0x475db8`) but every CLI spelling is rejected; `--manualread`, adjacent in the same option table, parses fine. | tested 3 spellings |
| 49b-1 | **Fire C wrote NOTHING** — `Nothing changed!`, exit 12, at the *first* page program. The block **predates** it. Transcript size is a reliable discriminator: a real program run is ~9.4 KB (progress bar), a no-op ~1.4 KB. | `p48c-fire.typescript` (1367 B) vs `p48b-fire` (9473 B) |
| **49c-1** | ★★★ **6 decode traps differ from the pre-exploit baseline**, which is validated by two independent surveys on this bdf (`logs/01`, `logs/15`, both `PMC_BOOT_0=0x140000A1`). | `trap-dump-2026-09-04.{txt,json}` |
| **49c-2** | ★★★ **trap14 MATCH = `0x00122428` is the chain's unambiguous signature.** The ROP chain holds `0x122438` and `0x122428` as adjacent words; `0x122438` *is* trap14's MATCH register. Gadget `0x22C5` took one word as address, the next as data. | `logs/39-flash-recovery/` |
| **49c-3** | ★★★ **The copy cannot be starved from the host.** The blank mechanism is verified working (`0xE208<-0` → aperture reads `FF FF…`; restore → `4C 49 43 … 55 4C`), yet narrow 2-6 ms windows **and** a hammer running *through* the reset (300/600/1000 ms, covering the whole ~180 ms boot) all leave the traps byte-identically clobbered. ⇒ **FWSECLIC's PMU-side ROM reads are not gated by `ROM_ADDR_OFFSET.EN`; that bit gates only the host aperture view.** | `tools/aperture_starve_boot.py --pre-hammer` |
| 49c-4 | **The direct-SPI escape is closed on hardware grounds, not just CLI grounds.** PLM census: `NV_PMGR_ROM_PRIV_LEVEL_MASK 0x00D7D0 = 0xCF`, `write_levels: [2]` — covers `SPI_CTRL`, `SPI_DATA_ARRAY`, `ROM_SERIAL_BYPASS`, `ROM_CONFIG`. The host runs at L0. | `logs/06` |

## The trap damage, exactly

Traps 10-19 are **not** idle slots — devinit arms them as stock silicon workarounds: 10/11 stamp
`PRIV_LEVEL`, 12 `DROP`s, **14 = `REDIRECT_RS | OVERRIDE_DEC_ERR` on `0x00118200`** routing to ring
station 8, 15-18 `REDIRECT_ADDR` remapping `0x10Exxx → 0x118xxx`, 19 `FORCE_DEC_PHYS`.

| slot | live | stock | field |
|---|---|---|---|
| **trap14** | **`0x00122428`** | `0x00118200` | MATCH |
| **trap10** | `0xFC000000` | `0x3C000000` | MASK |
| trap15 / 16 / 17 | `0xFC0000FF` | `0x00000000` | DATA2 (collateral) |
| trap18 | `0xFC0003FF` | `0x00000000` | DATA2 (collateral) |

Destroying a devinit register-remap fully explains `EWR` hanging while `EID`/`ERD`/`EPROT` — which
take different address paths — still succeed. **No chip write-protection needs to be invoked**;
pass 49's protection theory is withdrawn.

Trap layout: base `0x122000`, MATCH `+0x400`, MASK `+0x480`, DATA1 `+0x500`, DATA2 `+0x580`,
ACTION `+0x600`, PLM `+0x700`, stride 4, GV100 has slots 0-21.
**Free (all-zero) slots: 0-9, 13, 20.** Trap PLMs are write-L3-only (`0x0F8F` / `0x048F`), so the
traps cannot be repaired from the host.

## The deadlock

```text
ROM payload fires the chain every boot
  -> chain clobbers devinit's trap14 REDIRECT_RS workaround (and trap10 MASK)
     -> the PMU's flash page-program path breaks (EWR latches PENDING forever)
        -> the ROM cannot be rewritten in band
           -> the payload stays, and the cycle repeats next boot
```

All three routes to the SPI chip are shut: PMU uCode (broken by the traps), direct SPI registers
(write-L2, host is L0), manual SPI frames (fuse-gated,
`NV_FUSE_OPT_SECURE_PMGR_ROM_WR_SECURE = 1`). **Only an external programmer breaks the loop.**

## Card state

| | |
|---|---|
| ROM now | `2f3568f5f4c2166eef3dff7168a962b1058b92acb1d61b2ed0da1cc08cbac0d9` |
| baseline | `722bcbdff33e7119247a74ad6d22e01180af516dbee5c851596d7b49c77f30c9` |
| POST | `SCRATCH(5) = 0x70005000`, `SCRATCH(6) = 0x22081438` (clean card: `0x7000506D` / `0x2208106D`) |
| health | enumerates, boots, reads fine, VBIOS cert verifies OK, PMU in normal `CPUCTL=0x20` |

The 55-byte delta, in three runs:

| run | extent | bytes | contents |
|---|---|---|---|
| 1 | `0x042032`-`0x042034` | 3 | ULF InfoROM SIZE `0x551B` (want `0x0460`), cksum `0xD2` (want `0x00`) |
| 2 | `0x04748C`-`0x04749F` | 20 | overflow payload, mpop register slots |
| 3 | `0x047528`-`0x047547` | 32 | ROP chain: canary `0x6BD1`, gadget `0x22C5` ×2, trap targets `0x122438`/`0x122428`, resume `0x2A04` |

Run 1 arms the overflow. Runs 2 and 3 sit in sector `0x047000`, **fully erased at baseline**
(4096/4096 `0xFF`), so they are inert once SIZE is correct.

## Recovery — CH341A (next action)

⚠ **The chip is 1.8V.** `WBond W25Q80EW 1.65-1.95V`. A stock CH341A drives 3.3V and will damage
it. Use a 1.8V-capable programmer or a level shifter.

| | |
|---|---|
| image | `firmware/gv100-RECOVERY-entire-2026-09-02.rom` (+ `.sha256` sidecar) |
| sha256 | `722bcbdf…f30c9` |
| size | 1,048,576 B = exactly 1 MiB |
| **offset** | **0 — whole chip. Do NOT apply the `0xA00` correction.** |

The `+0xA00` rule in `CLAUDE.md` is for the raw BAR0 aperture dump `firmware/gv100-nvprom.rom`
**only**. This is a `--save --entire` image and is already physical: verified by the PCI
expansion-ROM signature `55 AA` sitting at physical `0xA00` (exactly where the aperture starts),
with 1251 meaningful bytes in the pre-aperture region `0x000-0x9FF` that an aperture-only image
would omit.

**Minimum intervention** if the clip is marginal: you need only disarm the overflow.
`0x551B → 0x0403` is a **strict submask**, and SPI programming only clears bits (1→0), so this
needs **no erase** — just 2 bytes at physical `0x042032`: `1B 55` → `03 04`. 1027 < the 1123-byte
DMEM buffer ⇒ no overflow. The PMU flash path then recovers and ordinary nvflash restores the
remaining 53 bytes. (`0x0460` is *not* a submask — bit 5 is clear in `0x551B` — so a true baseline
SIZE does need an erase.)

### Verification after flashing

1. Programmer read-back sha256 == `722bcbd…f30c9`.
2. Power on (5-min soak if the card is missing from the bus), then:
   - `nvflash --list` → **re-derive the index**, it is not stable across reboots (match `10DE,1DF4`; it was 10 this session)
   - `nvflash --index=<n> --save /tmp/v.rom --entire` → sha256 `722bcbd…f30c9`
   - `python3 tools/fwseclic_scratch.py 0000:13:00.0` → `SCRATCH(5)=0x7000506D`, `SCRATCH(6)=0x2208106D`
   - ★ `python3 tools/trap_dump.py 0000:13:00.0` → **"VERDICT: all 22 traps match the pre-exploit stock state"**, trap14 MATCH back to `0x00118200`
3. A full-ROM nvflash write completes past `Storing updated firmware image...` with no
   `mailbox0 = 0x20000005`.

★ The trap dump is the real proof. The ROM hash shows the bytes landed; **only the trap dump shows
the mechanism is fixed.**

## ⛔ Closed — do not retry

- BMC power cycle as a recovery (spent; restores enumeration, not flashing).
- Aperture starvation in any form — narrow windows, wide windows, or hammering through the reset.
- `--protectoff` / `--protecton` / chip-write-protection theories.
- `--inforomnopreserve`; patched `--wrulf` (converges on the same mailbox); `--nofalc`.
- Repairing the traps from the host (write-L3-only PLMs).
- Manual SPI frames (fuse-gated) and raw BAR0 `NV_PROM` writes (pass 31).

## New tools

| tool | what |
|---|---|
| `tools/trap_dump.py` | read-only dump of all 22 decode traps **with an automatic diff against the embedded pre-exploit stock values**; prints a verdict. Standalone (no repo needed on the bench host). |
| `tools/aperture_starve_boot.py` | blanks `ROM_ADDR_OFFSET.EN` across the boot; `--delay-ms`/`--window-ms`, and `--pre-hammer` to run through the reset. Kept for the record — it works mechanically but cannot starve FWSECLIC. |
| `tools/nvflash_wiuconsole.py` | pty driver for nvflash sub-consoles/prompts. |
| `logs/39-flash-recovery/CH341A-recovery-card.md` | the bench card for the programmer session. |
| `logs/39-flash-recovery/trap-stock-reference.json` | stock trap values extracted from `logs/15`. |

## Corrections this session makes to the record

- ⛔ Pass 48: *"the post-exploit boot leaves the PMU halted, so the mailbox times out"* — **wrong on both counts.** The PMU is not halted; the cause is the clobbered trap.
- ⛔ Pass 48: fire C *"failed mid-program"* — **wrong.** It wrote nothing. This single misreading sent the recovery session down a false causal path (interrupted-program → chip protection) for hours.
- ⛔ Pass 49: *"the flash block is NOT the overflow"* and *"chip-level write protection"* — **both withdrawn.** It is the overflow, one level removed: not the DMEM smash, but the chain's L3 trap writes.
- ⛔ Pass 49b: the proposed narrow-window starve fix — **closed** by the pre-hammer result.
- ⚠ `logs/20`'s *"ROM_ADDR_OFFSET is reprogrammed by devinit — off-flash delivery closed"* now extends further: the aperture cannot be used to starve FWSECLIC either, because its PMU-side reads are not gated by that enable bit.

## How to not do this again

See the **"How the 2026-09-04 self-lockout happened"** section in `CLAUDE.md` hazards. The
headline: `logs/01` and `logs/15` **already recorded that traps 10-19 were occupied** before pass
48 chose slots 10 and 14. Slots 0-9, 13 and 20 were free and would have proven exactly the same
thing while breaking nothing. Screen every payload's write targets against the census offline, keep
functional registers out of proof-of-capability fires (pass 47's scratch-register fire was
completely safe and fully reversible), and smoke-test the recovery channel immediately after any
fire that touches a functional register.
