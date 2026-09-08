# The VBIOS is writable over SPI — and RM rejects any modified copy. The devinit route is closed.

**Date:** 2026-09-05/06 (pass 63) · **Card:** `0000:0b:00.0` · **Logs:** `logs/110`–`logs/113`

**Read §8 first — it is the result.** §1-§4 establish that nvflash cannot write the VBIOS region;
§5 establishes that the L3 SPI stamp can, completely (erase + bulk program, built and proven); §8
then shows it does not matter, because **RM refuses to POST a card whose legacy image has been
modified by even one byte**, with the checksum correct. An external programmer would place the same
bytes and hit the same wall.

**Card state at exit: RESTORED and verified.** The legacy image *was* modified on silicon several
times during §8 and reverted each time by SPI sector erase + reprogram, confirmed byte-exact against
`cand5.rom` by an independent nvflash `--save`; then the full baseline was reflashed. Verified at
exit: resident ROM `722bcbd…f30c9`, `PMC_ENABLE 0x40000020`, `SCRATCH(5) 0x7000506D`,
`SCRATCH(6) 0x2208106D`, **all 22 traps stock**, driver loads, zero Xids.
**The memory clock was never changed** — `firmware/gv100-MEMCLK-877-entire-2026-09-05.rom`
(`75d93a97…29eb`) is built and archived but was not programmed, and §8 says it would not have helped.

---

## 1. The edit itself is trivial and verified

The whole memory nerf is **one devinit record**. A 432-record opcode scan of the legacy image finds
exactly one write to any HBMPLL register pair:

```
aperture 0x0089A2   7A 98 BC 98 00 | 02 3C 01 00
                    INIT_ZM_REG  NV_PFB_FBPA_MC_2_FBIO_HBMPLL_COEFF <- 0x00013C02
                    MDIV 2, NDIV 60, PLDIV 1   ->  27 MHz * 60 / 2 = 810.0 MHz
three stock Tesla V100 VBIOSes, same file offset:  0x00014102   NDIV 65  ->  877.5 MHz
```

Two bytes change (`tools/vbios_memclk_edit.py`):

| | aperture | physical | change | |
|---|---|---|---|---|
| NDIV | `0x0089A8` | `0x0093A8` | `0x3C → 0x41` | erase required (0→1 bits) |
| legacy checksum | `0x00E3FF` | `0x00EDFF` | `0x37 → 0x32` | program-only |

Independently verified: after the edit, `devinit_diff.py` against a stock V100 drops from **7
differing register writes to 6**, and the HBMPLL record is no longer one of them. Legacy image
checksum back to `0x00`. The `0xA00` aperture→physical skew is confirmed by the record reading
byte-identically at both offsets.

★ Incidentally this explains a standing oddity: devinit programs the PLL through **`0x98BC98`**
(`FBPA_MC_2`), the address pass 61 found *poisons the PRI ring when read*. That aperture is
**write-broadcast, read-invalid** — which is why the value shows up afterwards at `0x9A3C98`
(broadcast) and `0x983C98` (MC_0).

## 2. ★★★ Cert 2.0 covers the legacy image — measured, not inferred

First attempt, `nvflash-nocert3-devid1df4` (cert 3.0 patched, cert 2.0 **stock**):

```
BIOS Cert 2.0 Verification Error, Update aborted.
Nothing changed!
ERROR: Invalid firmware image detected.          exit 2, transcript 1390 B
```

⇒ **The same binary flashed `cand5.rom` earlier the same session without complaint.** cand5's
changes live at physical `0x042032` and `0x04748C`–`0x04756B`, i.e. in the InfoROM region; this
image's two bytes are confined to the legacy image. So Cert 2.0 passes an InfoROM-region change and
refuses a legacy-image change.

⛔ **This retires CLAUDE.md's "Cert 2.0 covers the IFR stays *inferred*".** It is now measured, for
the legacy image at least: a 2-byte, checksum-correct change to `0x0`–`0xE400` trips it.

## 3. ⛔⛔ And with Cert 2.0 patched out, the PMU halts instead

`nvflash-nocert3-devid1df4-cert20v2` is the only staged binary carrying the pass-60 result-store
patch (file `0x117AD0` = `45 31 f6`, `xor r14d,r14d`; every other binary reads `41 89 c6`). With it,
Cert 2.0 passes — and programming fails at a lower level:

```
Storing updated firmware image...
EEPROM programming failed.
Nothing changed!
PROGRAMMING ERROR: Reading EEPROM status register failed
 Nvflash CPU side error Code:2 Error Message:
 Falcon In HALT or STOP state, abort uCode command issuing process.
```

`NV_PPWR_FALCON_CPUCTL` (`0x10A100`) reads **`0x00000000`** afterwards — the PMU is stopped. nvflash
drives programming through PMU ucode, so the write never happens. **An SBR fully recovers it**
(`CPUCTL` back to `0x20`, both post-codes back to baseline), and a second attempt from a verified-
healthy PMU failed identically ⇒ the halt is caused *by* the program attempt, not inherited.

⚠ The read path is unaffected throughout: `--save --entire` and `--protectoff` both succeed with
exit 0 in the same runs. Only the erase/program path dies. This is the same shape as the pass-48
lockout symptom (`EID`/`ERD`/`EPROT` fine, `EWR` dead) reached by a completely different route.

## 4. ★★★ nvflash's write boundary, from seven data points

| image | physical bytes | sector | region | erase? | result |
|---|---|---|---|---|---|
| `CTRL-highsector.rom` (pass 60) | `0x080000` | `0x080000` | unallocated | no | **programs** |
| `cand5.rom` | `0x042032`, `0x04748C`+ | `0x042000`,`0x047000` | InfoROM | **yes** | **programs** |
| `RECOVERY-entire.rom` restore | same | same | InfoROM | yes | **programs** |
| ★ `CTRL-efi-image.rom` (this pass) | `0x02051A`-`0x02051B` | `0x020000` | **EFI image** | no | ★ **programs** |
| `WIDTH-x16-entire.rom` (pass 60) | `0x000214` | `0x000000` | IFR | — | **halts the PMU** |
| `MEMCLK-877-entire.rom` (this pass) | `0x0093A8`, `0x00EDFF` | `0x009000`,`0x00E000` | legacy image | **yes** | **halts the PMU** |
| ★ `CTRL-legacy-programonly.rom` (this pass) | `0x00ECD0`-`0x00ECD1` | `0x00E000` | **legacy image padding** | **no** | ★ **halts the PMU** |

Three variables are eliminated:

* **Not erase.** `cand5.rom` requires an erase at `0x042000` and programs; `CTRL-legacy-programonly`
  is pure 1→0 with no erase anywhere and halts.
* **Not the binary.** `cert20v2` programmed `CTRL-highsector.rom` (pass 60), `CTRL-efi-image.rom`
  and the final `RECOVERY` restore in this pass.
* **Not "low sectors".** `CTRL-efi-image.rom` lands at physical `0x02051A`, *below* the InfoROM at
  `0x042000`, and programs cleanly — readback byte-identical, both bytes verified on the chip.
* **Not content semantics.** `CTRL-legacy-programonly` changes two bytes of **0xFF padding** with
  both image checksums preserved. Inert, and still refused.

⇒ ★★★ **The boundary is the VBIOS proper.** The PMU's flash service refuses **any** write below
physical `0x00EE00` — the IFR (`0x0`-`0x9FF`) plus the legacy image (`0xA00`-`0xEDFF`) — and halts
the falcon when asked. Everything at or above the EFI image is writable: EFI image, InfoROM,
unallocated space, erase or not.

⛔ **This explains pass 60's "unexplained" `WIDTH-x16-entire.rom` programming failure**, which
CLAUDE.md records as an open puzzle ("it still refuses even when the chip's sector 0 already matches
it byte-for-byte"). Same mechanism, now with three instances and a named error.

⚠ Sector `0x00E000` straddles the boundary (legacy ends at `0x00EDFF`, EFI starts at `0x00EE00`), and
the failing write was in its legacy half. Whether an EFI-only write inside that sector would pass —
i.e. whether the check is byte-range or sector-granular — is untested and makes no practical
difference: all three devinit words sit well inside the legacy image.

## 5. The SPI path DOES reach it — what is missing is an erase, not a programmer

Pass 60 wrote flash **directly over SPI** using the L3 trap stamp on `SPI_CTRL` / `SPI_DATA_ARRAY`,
bypassing the PMU entirely, and that is how the IFR width byte was changed. It worked because that
edit was **one byte, `0x42 → 0x02`, purely 1→0** — a page-program with no erase.

⛔ **There is no 1→0 path to a higher memory clock.** freq = XTAL × NDIV / MDIV with the field
values `MDIV 0x02`, `NDIV 0x3C`:

* NDIV up from `0x3C` (`0011 1100`) requires setting bits — every value reachable by clearing bits
  only (`0x38, 0x34, 0x30, 0x2C, 0x28, 0x24, 0x1C, 0x18, 0x14, 0x0C …`) is **lower**, i.e. a slower
  clock.
* MDIV down from `0x02` to `0x01` requires setting bit 0. `0x00` is not a divisor.

⇒ raising the memory clock over SPI needs a **4 KiB sector erase** of `0x009000` followed by a
reprogram of the sector.

⛔⛔ **CORRECTION — an earlier draft of this section said that has "no in-band recovery" and needs a
CH341A. That is WRONG and is retracted.** §4's boundary is a property of **nvflash's PMU path only**.
The L3 SPI stamp does not go through the PMU flash service at all, and pass 60 already used it to
program physical **`0x000214`** — sector 0, the IFR, the deepest part of the region nvflash refuses.
The SPI path is not blocked by any of this; it simply has never been asked to erase.

★ **And the erase window is recoverable, because nothing the recovery depends on lives in the sector
being erased.** Sector `0x009000` (aperture `0x008600`-`0x0095FF`) is devinit script content. If a
program fails after the erase:

| recovery link | where it lives | affected by a blank `0x009000`? |
|---|---|---|
| card enumerates | IFR, physical `0x0`-`0x9FF` | no |
| FWSECLIC runs, chain fires | NVIDIA ucode images ~`0x020600`-`0x03F000` | no |
| the chain's payload | `cand5.rom` ULF object, InfoROM ~`0x042000` | no |
| trap 20 arms → SPI stamp | volatile, from the chain | no |

⇒ the card still enumerates, FWSECLIC still copies the InfoROM object **before** it verifies the
VBIOS certificate (pass 10), the chain still fires, trap 20 still arms, and the SPI engine is still
reachable — **so the program can simply be retried.** A blank devinit sector costs a POST, not the
card.

★★★ **BUILT AND PROVEN — `tools/spi_flash_l3.py`.** Erase and chunked bulk program now exist on
this path, proved first on free space (physical `0x080000`, inside the all-`0xFF` run spanning
`0x04295D`-`0x100000`, outside every image) and then used four times on the legacy image itself:

```
post-erase: full 4096 bytes all 0xFF: True
bulk program: 48 frames, 0.0 s        readback matches pattern: True
re-erase 0.027 s; sector back to all 0xFF: True
```

Sector erase (`0x20`) takes **28 ms**; a full 4 KiB sector is **48** program frames. Both legacy
sectors (`0x008000`, `0x00E000`) were subsequently erased and rewritten byte-exact several times,
including a full revert verified against `cand5.rom` by an independent nvflash `--save`. ⇒ **the
SPI path has complete read / erase / program access to the region nvflash refuses.** Write access
is a solved problem.

⚠ **MEASURED, and it contradicts the obvious guess:** the engine truncates any transaction whose
**total** exceeds **124 bytes**, not 128. A 4+120 read returns fully; 4+121 and up leave 94 bytes
of the RX buffer still holding the `0xEE` sentinel. So the usable payload after a 4-byte
cmd+address is **120**. Pass 60 never issued a frame larger than 5 bytes, so this had never
surfaced — and it fails *silently*, returning stale buffer contents rather than an error.

⚠ **After a legacy-image SPI edit, nvflash can no longer revert it** (§4). The restore is symmetric
— another SPI erase + reprogram — and that is now routine.

## 6. Where this leaves the three devinit words

⛔⛔ **ALL THREE ARE DEAD, and not for a write-access reason — see §8. The writes all succeed; RM
then refuses to POST the card.** The table below records the delivery mechanics, which are solved;
it is §8 that closes the route.

| word | physical | bit direction | via nvflash | write via L3 SPI | accepted by RM? |
|---|---|---|---|---|---|
| **fp64/tensor** `0x999 → 0x888` | `0x008C2B`-`2C` + rebalance | pure 1→0 | no | ★ yes, done | ⛔ **no** |
| memory NDIV `0x3C → 0x41` | `0x0093A8` + rebalance | 0→1, erase | no | yes (erase built) | ⛔ no (untested, same class) |
| PCIe Gen3 `0 → 0x00001001` | `0x00CD45`+ | 0→1, erase | no | yes (erase built) | ⛔ no (untested, same class) |

★★★★ **The fp64 word needs NO ERASE, so it is deliverable with pass 60's already-proven SPI
primitive — no new capability at all.** The record is
`INIT_NV_REG 0x409664, mask 0xFFFFF666, data 0x00000999` at aperture `0x008222`; its data u32 sits
at aperture `0x00822B` / physical `0x008C2B`. Built and verified
(`/tmp/.../FP64-perm-entire.rom`, sha256 `2388b926…`):

| physical | change | direction |
|---|---|---|
| `0x008C2B` | `0x99 → 0x88` | pure 1→0 |
| `0x008C2C` | `0x09 → 0x08` | pure 1→0 |
| `0x00ECD0` | `0xFF → 0x11` | pure 1→0 — the checksum rebalance |

Sum delta from the two record bytes is **−18**, and `0xFF → 0x11` supplies **+18 mod 256**
(`0x11 − 0xFF = −238 ≡ +18`) — a *wrapping increase is still a bit-clear*, which is what makes an
erase-free rebalance possible at all. Legacy checksum verified back at `0x00`, data u32 verified as
`0x00000888`. Three single-byte page programs, two sectors (`0x008000`, `0x00E000`), **no erase
opcode anywhere** — exactly the shape of the pass-60 `0x000214` write that is already proven on
silicon, just three of them.

⚠ `CTRL-legacy-programonly.rom` (§4) shows **nvflash** refuses these bytes even though they need no
erase — that is what makes the SPI route necessary, not optional. It does not block the SPI route.

All three live in the legacy image, so the permanent-fix plan recommended at the end of
`FINDINGS-2026-09-05-fp64-throttle-lifted.md` §7 is **not reachable through nvflash**, and it is
**not reachable at all** — but the blocker is §8, not access. An external programmer would not help
either: it would place exactly the same bytes.

★ The per-boot alternatives remain fully available and need no flash beyond `cand5.rom`, which sits
in the InfoROM region and therefore *is* in-band writable:
* **fp64 + tensor:** 15.5× / 14.4×, `tools/fp64_unlock.sh` (pass 62)
* **PCIe Gen3:** 3.95×, `tools/gen3_boot_unlock.sh` (pass 61)
* **memory:** ⛔⛔ **RETRACTED 2026-09-06 (pass 64) — "no runtime path" is WRONG.** The narrower
  pass-61 finding (*any naive COEFF write kills a live PLL*) stands; the generalisation does not.
  The GA100/170HX 6-step switch (alert → self-refresh → **per-FBPA** PLL relock → DDLL recal) ports
  to GV100 register-for-register and needs **no exploit at all** — pure host L0,
  `NV_PFB_FBPA_FBIO_PRIV_LEVEL_MASK 0x9A08FC = 0xFF` was open the whole time. **810 → 877.5 MHz,
  820.8 → 890.5 GB/s (+8.5 %)**, 15 GiB × 4 patterns × 2 passes clean, GEMMs correct, 0 Xids.
  `tools/hbm_mclk_switch.py`, `FINDINGS-2026-09-06-memory-clock-unlocked.md`.

## 7. Operational notes

1. ⚠ **A refused or failed flash leaves the PMU halted.** `CPUCTL = 0` afterwards, and the next
   nvflash run fails the same way for a *different* reason than the first. **SBR and confirm
   `CPUCTL = 0x20` before every program attempt**, and re-confirm after a failure before drawing any
   conclusion from the next one.
2. ⚠ Only `nvflash-nocert3-devid1df4-cert20v2` has the cert-2.0 patch. The names are misleading:
   `-cert20` and the plain `-devid1df4` both read `41 89 c6` (stock) at `0x117AD0`. Check the bytes,
   do not trust the filename.
3. ⚠ `nvflash --list` index was **7** again this session, but re-derive it every time.
4. ★ Memory integrity baseline for any future clock work: `tools/bench/gv100_memtest.cu`, 12 GiB ×
   4 patterns (addr / ones / zeros / random), **clean at 810 MHz** (`logs/110`).

## 8. ★★★★★ A position-sensitive integrity check covers the legacy image — that, not access, kills it

With write access solved (§5), the fp64 edit was actually placed on silicon: three bytes over SPI,
`0x008C2B 0x99→0x88`, `0x008C2C 0x09→0x08`, `0x00ECD0 0xFF→0x11`, verified through an independent
nvflash `--save` — exactly 3 bytes differ from `cand5.rom`, legacy checksum `0x00`, record data u32
reads `0x00000888`. Then the card was booted with **no host intervention and no trap stamp**, to see
devinit set full speed by itself.

**It did not POST.** `NVRM: GPU 0000:01:00.0: RmInitAdapter failed! (0x31:0xffff:2780)`.

Three further experiments isolate the cause:

| resident image | legacy checksum | RmInitAdapter |
|---|---|---|
| `cand5.rom`, unmodified | `0x00` | **POSTs** |
| + 3-byte fp64 edit (rebalanced on padding) | `0x00` | `0x31:0xffff:2780` |
| + 2 bytes of **inert `0xFF` padding**, sum preserved | `0x00` | `0x31:0xffff:2780` |
| + fp64 record bytes only, **checksum left wrong** | `0xEE` | `0x30:0xffff:1129` |

⇒ **Two distinct checks, and the enum names them** (`osinit.c:106-108`, open RM):
`RM_INIT_VBIOS_FAILED = 0x30`, `RM_INIT_VBIOS_POST_FAILED = 0x31`. A wrong 8-bit checksum gives
**`0x30`** — RM's own image validation catching it. A *correct* checksum with any byte changed gives
**`0x31`**, i.e. RM's validation **passes** and the **POST itself** fails. Two entirely unrelated,
semantically inert edits — two padding bytes after the option ROM's terminating `C3 C3`, and a
devinit data word four thousand bytes away — fail identically. **The legacy image is
integrity-protected beyond its checksum.**

★★ **Reproducibility, measured** (this is not the bench's known POST flakiness — CLAUDE.md records a
stock V100 hitting `RM_INIT_VBIOS_POST_FAILED` until a bus reset, so it had to be ruled out):

| resident image | POST attempts (rmmod/modprobe cycles) |
|---|---|
| pristine `cand5.rom` | **6 / 6 succeed** |
| + 2 bytes of inert padding | **0 / 6 succeed**, every one `0x31:0xffff:2780` |

★★★ **And it is NOT an additive checksum.** The padding edit changed two **adjacent** bytes
sum-neutrally (`FF FF → FE 00`, −1 and +1 mod 256). Any additive checksum over any range containing
both bytes is unchanged by that, and one containing only one of two adjacent bytes is not a real
structure. It failed anyway ⇒ the check is **position-sensitive**: a CRC, a hash, or a signature.
That also means **no amount of rebalancing will get past it**.

⛔ **This refutes the standing claim** in `FINDINGS-2026-09-02-vbios-dump.md` and CLAUDE.md that the
legacy image is *"protected only by an 8-bit checksum, which is trivially re-balanced"*, and it
retires the open question of whether anything covers `0x0`-`0xE400`. Something does. `logs/49`'s
result stands as far as it goes — no signature *descriptor* is findable in the image — but absence
of a findable descriptor was never evidence of absence of verification, and this is the experiment
that should have been run before that inference was drawn.

★★ **The card's own firmware is happy.** With the modified image resident:
`SCRATCH(5) = 0x70005000`, `SCRATCH(6) = 0x22081650`, `BIOSCERT_ERR = 0x00`, PMU `CPUCTL = 0x20` —
**byte-identical to a clean boot**. FWSECLIC verifies the VBIOS certificate and raises no error.

⚠ **Where the failing check actually lives is NOT established, and "patch RM" is probably the wrong
frame.** `0x31` is raised in the closed `nv-kernel.o` (the open tree only defines the enum and uses
`X86EMU_FAILED`), and it means *the POST failed*, not *the image was rejected* — RM's image
validation is the `0x30` path and our edits sail through it. So the position-sensitive check is
somewhere inside the POST sequence, and it could be either:
* RM's devinit interpreter on the host — in `nv-kernel.o`, so patchable in principle, the same class
  of target as the nvflash Cert 2.0/3.0 patches; or
* GPU-side firmware invoked during POST — not patchable at all.

Distinguishing them needs the VBIOS POST path in `nv-kernel.o` reversed. ⇒ before spending that
effort, note the payoff: the per-boot runtime unlocks already deliver the full performance, so a
permanent devinit fix buys **only the memory clock (+7.7 % bandwidth) plus convenience**:

* fp64 + tensor **15.5× / 14.4×** — `tools/fp64_unlock.sh` (pass 62)
* PCIe Gen3 **3.95×** — `tools/gen3_boot_unlock.sh` (pass 61)

and the memory clock is not recoverable by either route (no runtime path, and the devinit route
now closed), so it stays at 810 MHz.

⛔⛔ **RETRACTED 2026-09-06 (pass 64): the clause "the memory clock is not recoverable by either
route … so it stays at 810 MHz" is WRONG.** There *is* a runtime route — the full 6-step switch
sequence, pure L0, no exploit — giving **810 → 877.5 MHz, 820.8 → 890.5 GB/s (+8.5 %)**, validated
(15 GiB × 4 patterns × 2 passes clean, DGEMM/HGEMM correct, 0 Xids). See
`FINDINGS-2026-09-06-memory-clock-unlocked.md` and `tools/hbm_mclk_switch.py`. ⇒ **all four
restrictions are lifted per-boot, and three of the four need no persistent change to the card.**
Everything else in this section — the integrity wall, and that it is what closes the devinit route
— is unaffected.

⚠ Untested, and worth knowing before anyone spends time on it: whether RM's check is a hash over a
declared range, a comparison against something in the InfoROM, or a signature. All that is
established is that it is content-sensitive at single-byte granularity and distinct from the
checksum.

★ Card restored and verified at exit: two SPI sector reverts to `cand5.rom` (independently confirmed
byte-exact by nvflash `--save`), then a baseline reflash to `722bcbd…f30c9`, `PMC_ENABLE
0x40000020`, both post-codes at baseline, **all 22 traps stock**, driver loads, zero Xids.
