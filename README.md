# CMP 100-210 unlock

Lifting the firmware restrictions on an NVIDIA **CMP 100-210** (GV100 / Volta, `10de:1df4`) — the
mining SKU of the Tesla V100 — by getting arbitrary PRI writes at **privilege level 3** out of a
bug in NVIDIA's own boot firmware.

Validated end-to-end on hardware. **FP64 15.5×, tensor cores 14.4×, PCIe 3.95×, memory +8.4%.**

![nvidia-smi on the unlocked card](docs/img/01-nvidia-smi.png)

---

## 1. What is actually restricted

The die is an unrestricted 80-SM V100. A whole-die census — 39,930 named BAR0 registers, 1508
PLMs, the 256-row OTP array — says the restrictions are **not** in silicon and **not** in fuses:

* `OPT_PCIE_DEVIDA` = `0x1DB4` — this die is a **V100-PCIE-16GB**.
* `OPT_SM_FMLA_SPEED_SELECT`, `OPT_SM_IMLA_SPEED_SELECT`, `OPT_DP_SPEED_SELECT` all read **0**.
  Nothing is throttled by fuse.
* Zero GPC / FBP / FBPA / FBIO / ROP_L2 / PES floorsweeping. 80 SM, two TPCs cut (one genuinely
  defective, one binned).
* `OPT_ECC_EN` = 1, and the HBM2 dies report ECC-capable.

Diffing the CMP VBIOS against a stock Tesla V100 **at the devinit register-write level** — decode
`INIT_NV_REG` / `INIT_ZM_REG`, compare only records at matching file offsets — collapses 377
differing legacy bytes to **7 differing writes out of 431**. Five are of substance:

| devinit writes | effect |
|---|---|
| `0x409664` ← `0x999` | FP64 + tensor cores to 1/16 rate |
| `HBMPLL_COEFF` NDIV 60 (vs 65) | memory 810 MHz instead of 877.5 |
| `0x088610` ← `0` (vs `0x1001`) | PCIe capped at Gen1 |
| `CTRL_OPT_NVENC` ← 7, `CTRL_OPT_NVDEC` ← 1 | all four video engines floorswept off |

**The card is a Tesla V100 that is told to behave worse at boot.** Everything below is about
countermanding those instructions.

---

## 2. The primitive

Three of the four unlocks need no exploit at all — they are plain L0 register writes into blocks
whose PLMs are already open. **Only the FP64/tensor throttle is privileged**, and it is the reason
any of this needed an exploit.

### 2.1 Why a privilege escalation is needed

`0x409664` is guarded by its own priv-level mask `0x409650`, which reads `0x8F`: on Volta's
3-level PLM layout that is `WRITE 6:4 = 0` — **write level 3 only**. A host write at L0 bounces.

There is no designed path to L3. Confirmed from NVIDIA's own source: HS entry halts unless
`SCTL.LSMODE` is already true, LS is granted only by ACR writing `SCTL`, and `SCTL_PLM = 0x47`
requires L2 to make that write. *L3 needs HS, HS needs LS, LS needs L2, L2 needs LS.* No L0 entry
exists by construction.

So the escalation has to come from a bug in code **already running at L3**.

### 2.2 The bug: an unbounded copy in FWSECLIC

`FWSECLIC` is a falcon ucode that runs on the **PMU in HS / level 3 at every boot**. Before it
verifies the VBIOS certificate, it parses the InfoROM. Function `0x607E` copies an InfoROM
object's **self-declared U16 size** out of the ROM into a fixed 1123-byte global DMEM buffer at
`0x49D9`, with **no bound check**:

```
0x607E   read the INFOROM_OBJECT_HEADER_V1_00 ("3s2bwb" — NVIDIA's own format string)
         size = u16 at packed offset 5          <-- attacker-controlled, straight from flash
         copy `size` bytes to D[0x49D9]         <-- no comparison against the destination
```

The buffer sits `0x5483` bytes below the falcon return address at DMEM `0x9ED8`, and the stack
canary is a **compile-time constant**, `D[0x1B0] = 0x00006BD1` — 72 loads, 0 stores. Overwrite the
canary with its own known value and the return address with anything, and the result is not a
crash: it is **`$pc` control at level 3**.

This is NVIDIA's bug, and NVIDIA names it. Across 12 VBIOSes and 4 architectures, later FWSECLIC
builds add a check at exactly this site staging `NV_PREOS_ERR_INFOROM_BUFFER_OVERFLOW = 0x202A`.
Every CMP part sampled — 100-210, 170HX, 90HX — is on the unguarded side. The boundary is a VBIOS
branch, not an architecture: a **stock Tesla V100 ships the byte-identical FWSECLIC image**.

### 2.3 Turning `$pc` into arbitrary PRI writes

One `$pc` is not enough — the useful thing is a *sequence* of privileged writes. FWSECLIC contains
a convenient gadget, and the frame the copy lands in is deep enough to chain it:

```
0x22C5   mov b32 $r10 $r1      ; address
0x22C7   mov b32 $r11 $r0      ; value
0x22C9   lcall 0x2294          ; the PRI write
0x22CD   mpopret $r1           ; pop the next (value, address) and return to the next link
```

Each link is **12 bytes of stack**: two words popped by `mpopret $r1`, one word of next-`$pc`.
Point the last link at a *resume gadget* whose stack consumption lands `$sp` exactly where the
original caller's return address sits, and FWSECLIC carries on booting as if nothing happened.
The chain length is fixed by that arithmetic — `nlinks = (0x9F28 − pop − 0x9EDC) / 12` — so the
resume gadget selects it. `0x41AC` (`mpopret $r3`, pop `0x10`) gives **5 links**, and restores
`r0`–`r3`, which the continuation at `0x5908` needs.

> A 6-link chain (`0x046A`, `mpopret $r0`) also lands all its writes — and halts the PMU on every
> boot, because it only restores `r0`. Recoverable, but there is no reason to go there.

### 2.4 What the five writes do

The payload does **not** aim at `0x409664`. It cannot: RM's POST reprograms all 22 PRI decode-trap
slots for its own use, so the chain's window (pre-POST) and the target's window (post-devinit) do
not overlap.

Instead the chain spends its writes on **making the target reachable later**:

```
0x122750 <- 0x00000FFF     decode-trap 20's own PLM: open the slot to host L0 edits
0x1224D0 <- 0xFC000000     MASK   — address-exact match
0x122550 <- 0xC0000000     DATA1  — SET_PRIV_LEVEL value = LEVEL_3
0x122650 <- 0x00100000     ACTION — SET_PRIV_LEVEL
0x409650 <- 0x000000FF     the FECS PLM: 0x8F -> 0xFF
```

Two independent capabilities come out of that:

1. **A general L3 write primitive.** With trap 20's PLM open, the host re-aims `MATCH` freely at
   L0, and any host write matching it is **stamped LEVEL_3** and lands — on registers that refuse
   an L0 write. `MATCH` need not come from the chain (it boots as 0, which is inert), which is
   what frees the fifth link. Verified with unmatched controls: the same write *bounces* unstamped
   and *lands* stamped.
2. **The FP64 unlock, pre-armed.** `0x409650 = 0xFF` makes `0x409664` **plain-L0 writable for the
   rest of the boot** — and unlike the trap, a PLM survives PGRAPH power-up *and* RM's trap
   teardown. This is the whole trick: spend the privileged write on the *lock*, not the *target*.

The payload is 90 bytes inside the InfoROM. It is delivered by an ordinary VBIOS reflash and
re-fires from ROM at every boot.

---

## 3. How it is applied

**The ordering is the entire trick.** Two of the four levers have windows that do not overlap:

```
device reset ──► [PCIe retrain] ──► load driver (devinit runs) ──► [FP64] ──► [memory clock]
                 pre-POST only                                     post-POST  post-POST, IDLE
     │
     └─ the ROM chain fires here: trap 20 arms, FECS PLM opens
```

| lever | needs the primitive? | mechanism |
|---|---|---|
| **PCIe Gen1 → Gen3** | no | clear 4 CYA bits in `NV_XVE_PRIV_MISC_1` (`0x08841C`), then retrain **from the upstream port**. devinit latches the capability, so this must land before the driver. A Gen3 link trained in that window *survives* devinit — RM re-clamps `LnkCap` but does not force a downshift. |
| **memory 810 → 877.5 MHz** | no | a 6-step sequence: `MEMCLK_CHANGE_ALERT` → self-refresh → per-FBPA PLL disable/reprogram/relock → DDLL recal. `NV_PFB_FBPA_FBIO_PRIV_LEVEL_MASK` was `0xFF` all along; privilege was never the obstacle, **sequencing** was. |
| **FP64 + tensor** | **yes** | the ROM chain opens `0x409650`; then `0x409664 <- 0x888` at plain L0, after the driver loads. |
| video engines | — | **closed.** The mask lift lands perfectly and the GPU falls off the bus 4.5 s later (Xid 79) — devinit skipped the engines' bring-up, so the fix must be *inside* devinit. |

```bash
bash tools/unlock_all.sh --bdf <bdf>          # enforces the order; --dry-run rehearses it
```

---

## 4. Results

### FP64 and the tensor cores

Once `0x409650` is open the throttle is a **live toggle** — on a running GPU, with a CUDA context,
no reload and no reset. That makes the cleanest possible A/B: same boot, same binary, one register
write apart.

![live A/B of the throttle](docs/img/03-throttle-ab.png)

| | throttled (`0x999`) | lifted (`0x888`) | |
|---|---|---|---|
| FP64 | 0.443 TFLOP/s — **2.0**/32 FMA/SM/clk | **6.876** — 31.1/32 | **15.5×** |
| TensorCore HMMA | 7.097 TFLOP/s — **32.1**/512 | **102.082** — 462.3/512 | **14.4×** |
| FP32 | 12.756 TFLOP/s | 12.741 | *unchanged* |

Both throttled figures are exactly **1/16** of the architectural rate — a hardware rate divider,
flat across 9 occupancy/ILP configurations. **FP32, INT32 and FP16 were never throttled** (63.7/64,
58.8/64, 112/128 FMA/SM/clk at stock), and they do not move, which is what shows the lift is
pipe-specific rather than a clock artifact.

Numerically validated, not just timed:

```
DGEMM  fp64    max abs err 8.882e-15  (bound 9.095e-13)   over bound: 0   CORRECT
HGEMM  tensor  max abs err 4.532e-05  (tol 3.2e-02)       over tol:   0   CORRECT
```

### Memory clock

`nvidia-smi` reports the card running **above its own advertised maximum** — 877 MHz against a
`Max Clocks → Memory` of 810:

![memory clock above reported max](docs/img/02-memory-clock.png)

820.8 → **889.4 GB/s** device read (+8.4%), at 99% of theoretical both sides. Validated with
12 GiB × 4 patterns × 2 passes clean — a memory clock change can corrupt *silently*, so bandwidth
alone proves nothing.

### PCIe

H2D **0.20 → 0.79 GB/s**, D2H **0.21 → 0.83** — **3.95×**. The naive 8/2.5 = 3.2× is wrong because
it ignores the encoding change: Gen1 is 8b/10b, Gen3 is 128b/130b, so the true ceiling ratio is
(8/2.5)·(0.9846/0.8) = **3.94**, which is what the measurement lands on.

> ⚠ `nvidia-smi` reports `pcie.link.gen.current = 1` on a physically-Gen3 link, permanently — it
> reads the re-clamped capability. Trust lspci `LnkSta`, sysfs `current_link_speed`, or throughput.

### PCIe width — the firmware limit comes off; the payoff is your board's

The x1 link is **not** in the VBIOS. It is in the **IFR**, at physical flash `0x214`: a record that
read-modify-writes `XP_PL_LINK_CONFIG_0` to force `LINK_SPECIFIER` to lanes `00_00`. Retargeting
that record at the read-only `XP_PL_LINK_PRESENT` neutralises it — **one byte, `0x42 → 0x02`, a
single bit 1→0**, so no erase and no partial state. Delivered over the L3 SPI stamp, because
nvflash's PMU flash service refuses every write below physical `0x00EE00`.

**It works, and it was measured:**

```
LINK_SPECIFIER               0x01 -> 0x10      (lanes 00_00 -> 15_00)
XVE_LINK_CAPABILITIES width     1 -> 16
lspci  LnkCap                  x1 -> x16       card enumerates normally
```

**Width has two gates, and this removes the firmware one.** The second is physical: on this SKU
the series **AC-coupling capacitors for the additional lanes are depopulated** — empty pads. PCIe
negotiates width by per-lane receiver detection, and a lane with no coupling cap has no AC path,
so no partner is detected and the link trains x1 no matter what either end advertises. That is
what happened on the reference bench.

★ **The traces are present; the capacitors are not.** That makes full width a **soldering job**,
not a dead end — fit caps matching the value of the populated ones on the working lane. This kit
removes the firmware gate; the rework removes the other. *(The rework has not been performed here,
so it is reported, not verified.)*

> ⛔ `XP_PL_LANE_PRESENT` is **not** predictive — it read `0xFFFF` (16 lanes present at the PHY) on
> the card that trained x1. Inspect the board instead: look for empty pad pairs on the lane traces
> near the edge connector, next to the populated ones on the working lane.

The kit ships the write path as an escalation ladder — `spi_rdid_l3.py` (is the engine reachable?)
and `spi_status_l3.py` (is the chip protected?) are read-only, then `spi_write_ifr_l3.py` does the
one byte behind six interlocks and **contains no erase opcode anywhere in the file**.
`spi_flash_l3.py` is the general read/erase/program tool for everything else — pointing *that* at
sector 0 is how a card is lost, because an interrupted erase leaves the IFR blank.

⛔ This is the **highest-risk** change in the kit and the only one that can stop a card
enumerating: it writes flash sector 0, the IFR, which programs `ROM_ADDR_OFFSET` and the PCIe
config. There is no in-band way back. Attach a **1.8 V** programmer first.

### Whole card, one boot

FP64 **6.85** / tensor **101.8** / FP32 **12.7 TFLOP/s**, read **890 GB/s**, H2D **0.79 GB/s**,
memtest clean, GEMMs correct, **0 Xids** — a stock-performance Tesla V100.

Raw output for all of the above is in [`docs/evidence/`](docs/evidence).

---

## 5. What is closed, and why

Recorded because the negative results cost as much as the positive ones:

* **A permanent VBIOS fix.** All five devinit words could just be edited in the ROM. They cannot:
  **RM refuses to POST a card whose legacy image or NVIDIA ucode images differ by even one byte** —
  `RmInitAdapter failed! (0x31:0xffff:2780)` — demonstrated at three separated offsets, 6/6
  reproducible, including with two bytes of *inert `0xFF` padding* with both checksums preserved.
  The card's own firmware is happy (`BIOSCERT_ERR = 0`, chain fires, PMU healthy); only the driver
  objects, so the check is in `nv-kernel.o`. The same edit inside the **third-party EFI image**
  POSTs 3/3 — it is a policy about NVIDIA-authored images, not an address range.
* **ECC.** The gate is one VBIOS bit (`bFlag5` bit 0 `SKU_SUPPORTS_ECC`) that RM reads from a
  parsed struct **in host memory**. No register write, PLM, trap stamp or fuse override can reach
  it — and the byte is inside the legacy image, behind the wall above.
* **Video engines.** See §3. Runtime lift = Xid 79. Do not re-attempt.
* **NVLink** — fused off, all six links, `OPT_NVLINK_DISABLE = 0x3F`. Silicon intact, but there is
  no firmware path around a burned fuse.
* **No LHR-style flag.** Volta *has* one — `bFlag6` bit 7 `REDUCE_MINING_PERF` — and this SKU's
  `bFlag6` is byte-identical to a stock V100's. Don't go looking for it.

---

## 6. Using this

Start with **[`PORTING-2026-09-08-other-cards.md`](PORTING-2026-09-08-other-cards.md)**: risk
ladder, prerequisites, five phases from an offline self-test to rollback, and a table of what to do
when your card does not match this one.

```bash
bash tools/kit_selftest.sh                   # offline, no hardware
bash tools/bench/build.sh                    # compile the benchmarks (needs nvcc)
python3 tools/preflight.py <bdf>             # on-card GO/NO-GO, strictly read-only
python3 tools/rom_compat.py <your-dump.rom>  # offline GO/NO-GO on your card's own ROM
```

### Two things that will cost you a card

⛔ **The flash chip is 1.8 V.** Winbond **W25Q80EW**, `Vcc 1.65–1.95 V`. **A stock CH341A drives
3.3 V and destroys it.** Use a 1.8 V-capable programmer and verify the rail with a meter — several
boards sold as "1.8 V" only shift the data lines and still feed 3.3 V to Vcc.

⛔ **One memory-clock switch per boot.** The `--ndiv 60` "no-op control" *is* a switch. Running it
and then the real switch produced **Xid 62 and a deadlocked RM**; recovery was a device reset.
`tools/hbm_mclk_switch.py` now refuses the second one and names the reset you need.

### No firmware images are published here

Each 1 MiB VBIOS image contains its card's InfoROM — **serial number, UUID, board part number**.
They would also be useless to you: the InfoROM object the chain is written into sits at a
**different address on every card**, so a payload must be built from your own dump.
`tools/rom_compat.py` derives that address, verifies the FWSECLIC build by IMEM hash *and* eight
per-VA gadget byte signatures, and prints the exact build command for your card.

---

## 7. Scope

Developed and validated on **exactly one** CMP 100-210. It has never been run on a second card.
That the approach generalises is a hypothesis — the FWSECLIC image is byte-identical on a stock
V100, which is suggestive, but suggestive is not tested. §10 of the porting guide is how you test
it; §11 is what to send back.

No warranty. This modifies firmware on hardware you own, at your own risk. Nothing here is
endorsed by or affiliated with NVIDIA.
