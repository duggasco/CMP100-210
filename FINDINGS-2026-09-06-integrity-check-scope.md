# RM's integrity check: what it covers, and what it doesn't

⛔⛔ **CORRECTED WITHIN A DAY (pass 69).** The original title and §0 of this document said the check
is scoped to *the legacy image*. **That over-generalised from one data point.** A second probe put
the identical edit inside **image 2 (NVIDIA ucode)** and RM refused with the same
`0x31:0xffff:2780`. The check covers **legacy + NVIDIA ucode**, and excludes only the **EFI image**.
The corrected map is §3; the new evidence is §6 and `logs/126`. Everything measured in §1-§2 stands
— only the generalisation drawn from it was wrong.

**Date:** 2026-09-06 (pass 68) · **Card:** `0000:0b:00.0` · one flash, one revert, both byte-exact.
Card left at the pass-66 unlocked baseline and re-validated. **0 Xids.**

## 0. Result

Pass 63 established that RM refuses to POST a card whose **legacy image** has been modified by even
one byte, with the checksum correct (`RmInitAdapter failed! (0x31:0xffff:2780)`). What it never
established is **how far that check reaches**. Pass 68 answered half of it; pass 69 answered the
other half and corrected the conclusion.

| edit | image | aperture | physical | POSTs |
|---|---|---|---|---|
| `FF FF -> FE 00` (pass 63) | **legacy** `0x0`-`0xE400` | `0x00E2D0` | `0x00ECD0` | ⛔ **0 / 3** |
| `FF FF -> FE 00` (**pass 68**) | **EFI** `0xE400`-`0x1FC00` | `0x01FB60` | `0x020560` | ★ **3 / 3** |

**The same transformation, on the same kind of byte, in two different images, gives opposite
answers.** That is the whole experiment.

⇒ the wall is **not** "the ROM" — but ⛔ nor is it "the legacy image", which is what this document
originally concluded. Pass 69 showed the same edit is rejected inside **image 2**. See §3 and §6.

## 1. Why this edit and not another — removing every confound

The point of a scope test is that a negative result must mean *"the region is covered"* and nothing
else. So the edit was built to be indistinguishable from pass 63's except for its address:

* **Identical transformation.** `0xFF 0xFF -> 0xFE 0x00` on two adjacent bytes of inert `0xFF`
  padding — byte-for-byte the same change pass 63 made inside the legacy image.
* **Sum-neutral, so no rebalance is involved.** `0xFF + 0xFF = 0x1FE ≡ 0xFE`, and
  `0xFE + 0x00 = 0xFE`. The 8-bit sum over any containing range is unchanged. This also means the
  result cannot be attributed to a botched checksum fix-up.
* **The EFI image's own checksum stays valid.** Its 8-bit sum over `0x00EE00`-`0x0205FF` is `0x00`
  before and after, so "RM validated the EFI image and found it broken" is excluded as an
  explanation.
* **Pure 1->0**, so a plain page-program does it — no erase, no sector rewrite, no partial state.
* **Inert location.** `0x020560` sits mid-way through a **229-byte run of `0xFF`** at
  `0x02051A`-`0x0205FE` at the tail of the EFI image. Nothing parses it; nothing on this bench
  executes the UEFI GOP driver at all (headless card, vfio guest).
* **Nothing else moved.** The legacy image and the IFR (`0x0`-`0x9FF`) are byte-identical to
  `UNLOCK4`; `cmp` reports exactly **2** differing bytes in the whole 1 MiB image.
* **Not in the recovery chain.** The EFI image holds no link of enumerate -> BAR0 -> trap -> SPI, so
  a bad outcome could not have cost the card.

## 2. Method and evidence (`logs/125`)

```
base   firmware/gv100-UNLOCK4-entire-2026-09-06.rom      d4b0218a…2bed834
test   firmware/gv100-TEST-EFIPAD-entire-2026-09-06.rom  99e65d9e…8aa3c9c1
       2 bytes differ:  0x020560 FF->FE   0x020561 FF->00
```

Flash, with the PMU confirmed healthy first (`CPUCTL 0x20`) and the index re-derived from `--list`:

```
./nvflash-nocert3-devid1df4 --index=7 --protectoff          "Setting EEPROM protection complete."
drive_nvflash.py … --inforomnopreserve TEST-EFIPAD.rom      transcript 9168 B, no "Nothing changed!", exit 0
./nvflash-nocert3-devid1df4 --index=7 --save --entire       99e65d9e…8aa3c9c1   byte-exact
cmp vs UNLOCK4                                              2 bytes: 132449 377 376 / 132450 377 000
```

★ **Plain `nvflash-nocert3-devid1df4` accepted it** — the `cert20v2` patch was *not* needed: the
same binary that refuses a 2-byte legacy edit programs a 2-byte EFI edit without complaint.
⛔ Note this does **not** mean "Cert 2.0 covers the legacy image only" — pass 69 found it also
refuses an image-2 edit. Cert 2.0 covers **legacy + NVIDIA ucode**. §6.

Card firmware after flash + SBR, identical to a clean boot:
`CPUCTL 0x20`, `SCRATCH(5) 0x70005000`, `SCRATCH(6) 0x22081650`, trap 20 `ACTION 0x00100000`
armed, `FECS_PLM 0xFF`.

Three independent POST attempts, each a full `qm stop` / `qm start` / `modprobe nvidia`:

```
1  Tesla V100-PCIE-12GB, 810 MHz, 16384 MiB    dmesg RmInitAdapter|Xid: 0
2  Tesla V100-PCIE-12GB, 16384 MiB             dmesg RmInitAdapter|Xid: 0
3  Tesla V100-PCIE-12GB, 16384 MiB             dmesg RmInitAdapter|Xid: 0
```

Reverted with `UNLOCK4.rom`: transcript 9168 B, readback `d4b0218a…2bed834` — byte-exact. The full
unlock stack was then reapplied and re-validated: fp64 **6.778**, TensorCore **100.734**, FP32
12.588 TFLOP/s, device read **891.6 GB/s**, H2D **0.79** / D2H **0.83 GB/s**,
`gv100_memtest 15 2` **CLEAN — 0 bad words**, `current_link_speed 8.0 GT/s`, **0 Xids**.

## 3. The accepted/rejected map, as it now stands

| region | aperture | RM accepts a byte change? | basis |
|---|---|---|---|
| IFR | `0x0`-`0xA00` (phys) | ⚠ **untested** | pass 60's edit was only ever measured driverless |
| **legacy image** | `0x0`-`0xE400` | ⛔ **NO** | pass 63, three separated offsets, 0/6 and 0/3 |
| **EFI image** | `0xE400`-`0x1FC00` | ★ **YES** | pass 68, 3/3 |
| **NVIDIA ucode image 2** | `0x1FC00`-`0x030A00` | ⛔ **NO** | **pass 69, §6** |
| NVIDIA ucode image 3 | `0x030A00`-`0x03DE00` | ⚠ untested | presumed covered |
| InfoROM | `~0x041600`+ | ★ **YES** | every `UNLOCK*` flash changes it and POSTs |
| unallocated | `0x080000`+ (phys) | ⚠ untested by POST | programs fine |

★★ **RM's check and nvflash's Cert 2.0 have the same scope on all three tested points** —
legacy NO / EFI YES / ucode NO — with the *unpatched* `nvflash-nocert3-devid1df4` in every case.
Two independent implementations agreeing on an unusual boundary is a strong hint they validate the
same artifact: something covering the NVIDIA-owned images and excluding the third-party EFI image.

## 4. ⛔ The devinit-repointing lead this opened — and pass 69 closed it

devinit is **not** at a hardcoded address. RM locates it through a **descriptor record table** whose
first record's second entry is the devinit script pointer (`logs/49`):

```
descriptor record table: aperture 0x030280
  @0x030280 type=0x0001 len=0x0038
     0005F0 0048F4 000E00 0076A2 0076CA 085817 004DE4 000000 004938 000000 004D1C 004D3E
                   ^^^^^^ = 0x0048F4 = the devinit script, inside the legacy image
```

`0x030280` is **above `0xE400`**, so on the pass-68 result it looked like the pointer deciding where
devinit lives might be editable — which would have let devinit be repointed at a corrected script in
an accepted region, sidestepping the wall entirely with no `nv-kernel.o` patch, and turning all five
nerfs plus ECC into ordinary edits. It was, briefly, the most promising lead in the tree.

⛔⛔ **It is dead.** `0x030280` is physical `0x030C80`, which is inside **image 2** — and §6 measures
image 2 as **covered**. Repointing devinit hits exactly the same `0x31:0xffff:2780`.

## 5. What this does *not* change

* The legacy image is still closed, and that is still where all five nerfs' permanent fixes and the
  ECC bit live. Lead (a) — patching RM's check in `nv-kernel.o` — is unaffected and remains the
  route that works regardless of how the repointing question resolves.
* Nothing here says *what* the check is. It bounds its **scope**, not its mechanism.
* ⚠ The scope is demonstrated at one address per image. "The EFI image is uncovered" rests on one
  address (`0x01FB60`, 3/3); "image 2 is covered" rests on one address (`0x031280`). Neither
  boundary has been walked.

## 6. ⛔ PASS 69 — image 2 IS covered, and that is what corrects this document

`logs/126`. Same transformation again — `FF FF -> FE 00` on inert `0xFF` padding, sum-neutral,
image 2's own 8-bit sum preserved at `0x00`, pure 1->0, every other region byte-identical, exactly
2 differing bytes. Target physical `0x031280`/`0x031281`, mid-way through the 176-byte `0xFF` run at
`0x031250`-`0x0312FF`: 1536 bytes from the descriptor table, 384 from the end of image 2.

**(a) nvflash refused the image outright** — `BIOS Cert 2.0 Verification Error, Update aborted.` /
`ERROR: Invalid firmware image detected.`, transcript 879 B with `Nothing changed!`, chip unchanged.
So Cert 2.0's coverage matches RM's on all three tested points.

**(b) Delivered over the L3 SPI path instead**, which skips nvflash's policy entirely and writes
exactly 2 bytes rather than reprogramming the image — a smaller blast radius than the `cert20v2`
bypass. `program 0x031280 fe00 --expect ffff` → `readback fe00 => LANDED`.

**(c) ★ The card's own firmware is completely happy.** After an SBR with the modified image
resident: `CPUCTL 0x00000020`, `SCRATCH(5) 0x70005000`, `SCRATCH(6) 0x22081650`, trap 20
`ACTION 0x00100000` armed, `FECS_PLM 0xFF` — identical to a clean boot. ⇒ **no HS signature covers
this byte**; FWSECLIC verifies, runs, and fires our payload normally. The "image 2 is signed, so
editing it will break the recovery chain" fear did **not** materialise, which is worth knowing.

**(d) ⛔ But RM refuses to POST:** `RmInitAdapter failed! (0x31:0xffff:2780)` — the *identical* error
a legacy-image edit produces.

⇒ the check covers **legacy + NVIDIA ucode** and excludes the **EFI image**. Reverted with
`UNLOCK4.rom` (9168 B, readback `d4b0218a…` byte-exact) and the unlock stack restored and
re-validated: fp64 **6.849**, TensorCore **101.711** TFLOP/s, read **890.5 GB/s**, H2D 0.79 /
D2H 0.83, `gv100_memtest 15 2` **CLEAN**, 8.0 GT/s, **0 Xids**.

★ **The useful residue:** the boundary is not "one contiguous protected span". It is
*NVIDIA-authored images protected, third-party EFI image not* — which is a **policy** shape, not an
address-range shape, and it is mirrored by two independent implementations. That is a real clue
about what the check actually validates, and it is the best structural hint the tree has for
lead (a).
