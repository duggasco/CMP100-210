# Porting the CMP 100-210 unlock to another card, and to another operator

**Audience: someone who is not me, holding a card that is not the one this tree was written on.**
Everything here has been run end-to-end on exactly one CMP 100-210 (`10de:1df4`, VBIOS
`88.00.51.00.04`, board `900-1G500-0040-000`). Nothing here has been run on a second card. This
document exists to make the second card cheap and the second operator independent — not to claim
the result generalises. It probably does; that is a hypothesis, and §10 is how you test it.

The original bench had a one-page runbook with its BDFs, VM ids and nvflash index hardcoded. That
is deliberately not published: it is worthless anywhere else and misleading everywhere else. This
document assumes none of them.

---

## 0. The risk ladder — read this before anything else

Three of the four unlocks require **no flash and no exploit**. Do those first: they are per-boot
and a device reset restores stock.

⚠ **"Per-boot" is not the same as "harmless."** The memory-clock switch drives real analogue state
— it parks DRAM in self-refresh and reprograms a PLL — so a bad NDIV or a switch under load is a
genuine hardware risk, not just an Xid. `tools/hbm_mclk_switch.py` now **enforces** what earlier
versions only documented: NDIV is bounded (`40..75`, and anything above the stock 65 needs
`--allow-overclock`), and `--apply` refuses to run unless it can confirm through `nvidia-smi` —
matched to *your* BDF, never "GPU 0" — that the GPU is idle. Do not defeat those checks to save
time.

| | what it needs | persistent? | worst realistic outcome | recovery |
|---|---|---|---|---|
| **PCIe Gen3** | one host register write + a retrain | no | link stays at Gen1 | nothing to undo |
| **memory clock** | a 6-step host sequence, **GPU idle, bounded NDIV, one switch per boot** | no | Xid 62 + deadlocked RM on a repeated switch; out of bounds or under load, silent corruption | device reset (+ memtest to prove it) |
| **fp64 + tensor** | **a ROM flash** (payload in the InfoROM) | **yes** | card boots but refuses to POST | reflash the baseline |
| **PCIe x16 (IFR)** | an SPI write to flash sector 0 | **yes** | **card stops enumerating** | **1.8 V programmer only** |

⚠ **The fourth works, and it is half of a two-part job.** The firmware edit is proven — one byte,
`LnkCap` x1 → x16, card enumerates normally. The other half is physical: this SKU ships with the
**AC-coupling capacitors for the extra lanes depopulated**, so those lanes present no link partner
and the link still trains x1. The traces are there, so full width is a soldering job rather than a
dead end — but the two are only useful together, and this is the one change here that can stop a
card enumerating. See §9.

⚠ **The single most expensive mistake in this tree's history** was firing a payload that wrote PRI
decode-trap registers that devinit had already programmed. That broke the in-band flash path, and
because the payload re-fires from ROM on every boot it was self-perpetuating. It cost a CH341A
session. `tools/build_payload.py` and `tools/trap_dump.py` now screen for exactly that, and the
supplied recipe touches only free slot 20. If you improvise a chain, the four rules that came out
of that incident are:

1. **Never write a PRI register that is non-zero at fire time.** devinit arms traps 10–19 as
   silicon workarounds. Free slots on GV100 are **0–9, 13, 20**.
2. **Keep a load-bearing denylist.** Anything the recovery path depends on is off limits: the
   decode-trap block `0x122000`–`0x1227FF`, PMGR/ROM (`0xD7D0`, `0xD7D8`, `0xE200`–`0xE210`,
   `0xE5A0`), `PMC_ENABLE`, and the priv-ring stations. Break one and you lose the ability to undo
   the change.
3. **Prove primitives on registers with no function first** — scratch registers, not functional
   ones.
4. **Smoke-test the recovery channel immediately** after any fire that touched a functional
   register, before anything else. One `--protectoff` answers "can I still write flash?" in
   seconds.

---

## 1. What you get, measured

All numbers from the reference card at a locked 1380 MHz SM clock, one boot, same binaries
numerically validated — DGEMM max abs err 8.882e-15 against a
`16*N*eps*max|A|*max|B|` bound of 9.095e-13, HGEMM 0 elements over tolerance.

| | stock | unlocked | ratio |
|---|---|---|---|
| FP64 | 0.441 TFLOP/s | **6.85** | 15.5× |
| TensorCore (HMMA) | 7.06 TFLOP/s | **101.8** | 14.4× |
| PCIe H2D / D2H | 0.20 / 0.21 GB/s | **0.79 / 0.83** | 3.95× |
| memory read | 820.8 GB/s | **890.5** | +8.5% |

**FP32, INT32 and FP16 are not throttled and never were** — 63.70/64, 58.8/64 and 112/128
FMA/SM/clk measured at stock. Do not expect a change there, and be suspicious of any report that
claims one.

Under sustained load the card is **power-limited, not compute-limited**: `gpu_burn -tc 180` gives
~52 TFLOPS at the 250 W cap, not the 101.8 peak.

**What you do not get, and why — do not re-litigate these:**

* **ECC** — the gate is one VBIOS bit (`bFlag5` bit 0 `SKU_SUPPORTS_ECC`) that RM reads from a
  parsed struct in *host memory*. No register write can reach it, and the byte is inside the
  legacy image, which RM refuses to POST if modified. See README §5.
* **NVDEC / NVENC** — devinit floorsweeps them off, and lifting the mask at runtime lands
  perfectly and then kills the GPU 4.5 s later with Xid 79, because devinit skipped the engines'
  bring-up. **Do not re-attempt.** See README §5.
* **NVLink** — fused off (`OPT_NVLINK_DISABLE = 0x3F`), all six links.
* **A permanent VBIOS fix for any of the above** — RM refuses to POST a card whose legacy image or
  NVIDIA ucode images differ by even one byte (`RmInitAdapter 0x31:0xffff:2780`), demonstrated at
  three separated offsets, 6/6 reproducible, including with sum-neutral inert padding. The card's
  own firmware is happy; only the driver objects. See README §5.

---

## 2. What you need

**Hardware**

* the card, in a slot you can physically reach
* **a 1.8 V-capable SPI programmer + SOIC-8 clip, attached or immediately available, before any
  flash.** This converts a deadlock from a bench-day into five minutes. The reference card needed
  it once.
  ⛔⛔ **THE FLASH CHIP IS 1.8 V.** It is a Winbond **W25Q80EW**, `Vcc 1.65-1.95 V`. **A stock
  CH341A drives 3.3 V and will destroy it.** Use a 1.8 V-capable programmer, or a CH341A with a
  proper level shifter / 1.8 V adapter — and *verify the rail with a meter before clipping on*,
  because several CH341A boards sold as "1.8 V" only shift the data lines and still feed 3.3 V to
  Vcc. This is the one mistake in this document that destroys the card outright rather than
  costing a reflash.
* a host that can fully power-cycle the card (BMC or a plug). ⚠ On the reference chassis a short
  power cycle left the GPU absent from the PCI bus entirely; a **5-minute cold soak** between off
  and on fixed it. If your card vanishes after a power cycle, wait longer before panicking.

**Software**

* Python 3, stdlib only. Every tool here mmaps `resource0`; nothing else is needed.
* **NVIDIA driver 580.178.04 proprietary, installed with `-m=kernel`.**
  ⛔ **Not `kernel-open`.** NVIDIA never published a GSP-RM image for Volta and the open kernel
  module is GSP-client-only, so it cannot drive this die at all. The device id being absent from
  `supported-gpus.json` costs nothing but an installer warning — `rm_is_supported_pci_device()`
  gates on class/vendor/legacy-list, not the id.
* CUDA 12.8 `nvcc`, to build `tools/bench/*.cu`.
* **nvflash 5.680 for Linux, patched.** See §6.1. The kit patches a stock binary for you.

**Topology.** The reference bench passes the card through to a VM because that host has no
business running a GPU driver. **You almost certainly do not need a VM** — bare metal is simpler
and every tool supports it. The only requirement is that you control *when* the driver loads, so
blacklist `nvidia` at boot and `modprobe` it by hand.

---

## 3. Phase 0 — prove the toolchain, with no hardware

```bash
bash tools/kit_selftest.sh
```

This rebuilds both shipped payload images from the shipped baseline dump and compares them
byte-for-byte, then checks that the build gate refuses a corrupted ucode and that `rom_compat`
gives the right verdicts on a CMP100 and on a stock Tesla V100. Expect **0 failed** (12 checks,
or 13 if a stock nvflash 5.680 and the stock-V100 reference ROM are both present — the two
optional checks say `SKIP` rather than failing).

If this does not pass, stop. A payload built by broken tooling is a `$pc` jump to an arbitrary
address at privilege level 3, on the only card you have.

Then build the benchmarks, on the machine that will drive the card:

```bash
bash tools/bench/build.sh          # SM=70 by default (GV100)
```

⚠ **This kit was authored on a host with no CUDA toolchain, so the five `.cu` files are the one
part of it that has not been through `nvcc` in its current form.** Their call sites, macro
ordering and includes are checked and the device-selection helper compiles standalone, but that is
not the same as a real compile. Do this early: a build error here is a five-minute fix, and you do
not want to meet it with a card sitting half-unlocked.

---

## 4. Phase 1 — identify the card, change nothing

```bash
# re-derive the BDF every time; it moves when the card is reseated
BDF=$(lspci -Dd 10de:1df4 | cut -d' ' -f1)
python3 tools/preflight.py $BDF
```

`preflight.py` opens BAR0 `O_RDONLY`, so it cannot write. It reports the arch field, POST state,
PMU health, the trap-20 and FECS-PLM state, the PCIe clamp, the HBM PLL, and the fuses that decide
whether this card is throttled the same way — and gives a GO/NO-GO per unlock.

**The three answers that matter most:**

* `PMC_BOOT_0` arch must be `0x140` (Volta). If it is `0x170` you have a GA100 and **every address
  in this kit is wrong** — the fuse block alone moved from `0x21000` to `0x820000`.
* `PMC_ENABLE = 0x40000020` means the card has **not** POSTed. Almost everything interesting is
  unreadable in that state; that is normal and expected before the driver loads.
* If any `OPT_*_SPEED_SELECT` fuse reads non-zero, **this card is throttled by an OTP fuse, not by
  devinit**, and this kit cannot lift it. On the reference card all three read 0.

⚠ **Cold-boot trap.** With no driver bound, PCI memory space is disabled and *every BAR0 read
returns `0xFFFFFFFF`* — which decodes as a plausible "everything is set", not as an error. The
tools do `setpci -s <slot> COMMAND=0x0002:0x0002` themselves and abort if `PMC_BOOT_0` reads
all-ones. Any tool of your own must do the same.

⛔ **Never read `0x98BC98`** (`FBPA_MC_2`). It does not decode on this die and reading it *poisons
the PRI ring*: every later read then returns stale bus data rather than an error. It cost one
"GPU has fallen off the bus" here. Every tool in this kit canaries `PMC_BOOT_0` around each access
for this reason; keep that habit.

---

## 5. Phase 2 — the two unlocks that need no flash

Do these first. They cost nothing and they tell you whether the card behaves like the reference
one before you commit to anything persistent.

### 5.1 PCIe Gen1 → Gen3

The clamp is four bits in `NV_XVE_PRIV_MISC_1` (`0x08841C`): clearing
`CYA_GEN2/GEN3_SPEED_OVERRIDE_{EN,VAL}` lifts `LnkCap` from Gen1 to Gen3, landing on the stock
Tesla V100's exact values. Then the link must be **retrained from the upstream port** — an
endpoint's own retrain bit bounces.

⚠⚠ **The window is pre-POST.** devinit latches the capability, so this must happen after the
device reset and **before** the driver loads. A Gen3 link trained in that window *survives* devinit:
RM re-clamps `LnkCap` but does not force a downshift, and lspci then reads `8GT/s (overdriven)`.

```bash
python3 tools/pcie_retrain_probe.py $BDF --apply --target-gen 3
```

⚠ `nvidia-smi` reports `pcie.link.gen.current = 1` on a physically-Gen3 link, permanently — it
reads the re-clamped capability. ⚠ sysfs `max_link_speed` is cached at enumeration. Trust lspci
`LnkSta`, sysfs `current_link_speed`, or measured throughput, and nothing else.

★ This works here because the CYA bits are *set* and the fuses are clear. On a 170HX it is the
other way round — Gen1 by burned fuses with the CYA bits clear — and this write does nothing.
Same nerf, two mechanisms. `preflight.py` tells you which one you have.

### 5.2 Memory clock 810 → 877.5 MHz

`NV_PFB_FBPA_FBIO_PRIV_LEVEL_MASK` (`0x9A08FC`) is `0xFF`, host-writable at L0. Privilege was
never the obstacle here — **sequencing** was.

```bash
python3 tools/hbm_mclk_switch.py $BDF --ndiv 65 --apply    # the real switch
```

⚠⚠⚠ **ONE SWITCH PER BOOT. The `--ndiv 60` "no-op control" IS a switch.**
The older guidance here said to run the no-op control first and then the real switch. Doing exactly
that on the reference card — control, then `--ndiv 65` three seconds later — produced **Xid 62 and
a deadlocked RM** (`os_acquire_rwlock_write`, `nvidia-smi` hung); recovery was a VM stop plus an
SBR. Two long-standing rules were in conflict — *"always run the no-op control first"* and *"avoid
repeated back-to-back switches"* — and chaining them satisfies the first by violating the second.
`hbm_mclk_switch.py` now **refuses** a second switch when it sees the FBPA `CFG` registers are no
longer pristine, and names the reset you need. If you want the control, give it its own boot:

```bash
python3 tools/hbm_mclk_switch.py $BDF --ndiv 60 --apply    # optional: the sequence at the
                                                           # current value, then RESET the GPU
```

⚠⚠ Three more traps, each of which cost a card recovery here:
* ⛔ **The GPU must be IDLE.** Self-refresh under an 800 GB/s benchmark is 325 Xids.
* ⛔ **The broadcast pair `0x9A3C90`/`0x9A3C98` is write-only fan-out.** Reading it returns
  garbage that looks like data (`NDIV 0` while all 16 real instances read `NDIV 60`). A
  read-modify-write through it is meaningless. The tool loops over the 16 per-FBPA instances.

⚠ A memory clock change can corrupt **silently** — bandwidth looks perfect while the data is wrong.
`tools/bench/gv100_memtest.cu` afterwards is **not optional**. 15 GiB × 4 patterns × 2 passes.

⚠ Known open defect, downgraded but not closed: after a clean switch the 16 FBPA-side `CFG`
registers diverge in groups of four, one group showing `IDDQ` set together with `PLL_LOCK`. The
physics rules out a genuinely powered-down PLL (a quarter of the FBPAs unclocked cannot give
890.5 GB/s or a clean memtest, both measured after the switch), and the second controller reads
`IDDQ` clear on all 8. But **avoid repeated back-to-back switches** — that produced an Xid 62 —
and reset between experiments.

---

## 6. Phase 3 — the payload flash, for fp64 and the tensor cores

This is the only persistent step, and the only one that needs the exploit.

**Why a flash at all.** The throttle lives in `0x409664`, whose PLM `0x409650` is write-L3-only.
The L3 opener is a ROP chain in an InfoROM object that FWSECLIC — which runs at level 3 on the PMU
at every boot — copies without a bound check. The chain's one useful job is to open `0x409650` so
that `0x409664` becomes plain-L0 writable for the rest of the boot. RM's POST tears down all 22
decode traps, but **it cannot close a PLM the chain already opened**, which is why this works.

### 6.1 Patch nvflash

```bash
python3 tools/patch_nvflash_kit.py ./nvflash                      # report only
python3 tools/patch_nvflash_kit.py ./nvflash --devid 0x1DF4 --out ./nvflash-kit
```

Three gates, all of them live on a stock binary: Certificate 3.0, Certificate 2.0 (a *separate*
path — this is what refuses a legacy-image edit with "BIOS Cert 2.0 Verification Error"), and the
four-device whitelist that decides whether your card's InfoROM can be written at all.

⚠ **Verify the bytes, not the filename.** This tree has had three binaries whose names claimed
patches they did not carry. Re-run the tool on its own output; all three sites must read `APPLIED`.

### 6.2 Dump *this card's* ROM and check it

```bash
./nvflash-kit --list | grep -i 1df4          # re-derive the index EVERY time; it is not stable
./nvflash-kit --index=N --save baseline.rom --entire
sha256sum baseline.rom | tee baseline.sha256          # ★ this is your rollback image. Keep it.
python3 tools/rom_compat.py baseline.rom
```

⛔⛔ **Never flash another card's image.** The 1 MiB image contains that card's InfoROM: serial
number, UUID and board part number. That is also why no reference image is published in this
repository — publishing one publishes a specific card's identity, and it would be useless to you
anyway. **Build your own payload from your own card's dump.**

`rom_compat.py` derives, rather than assumes: the InfoROM directory address (reached by walking a
per-card object chain, so it *is* different on your card), the FWSECLIC build (every gadget VA and
DMEM offset belongs to one ucode build), which devinit nerf words are actually present, and where
the IFR width record sits. It prints a GO/NO-GO and the exact build command.

### 6.3 Build the payload

```bash
python3 tools/build_payload.py baseline.rom payload.rom \
    --resume 0x41AC \
    --write 0x122750=0x00000FFF \
    --write 0x1224D0=0xFC000000 \
    --write 0x122550=0xC0000000 \
    --write 0x122650=0x00100000 \
    --write 0x409650=0x000000FF
```

Five writes in a 5-link chain: trap 20's own PLM open, then MASK / DATA1 / ACTION to arm it as a
`SET_PRIV_LEVEL` LEVEL_3 stamp, then the FECS PLM. That gives you both a general L3 write primitive
(MATCH is re-aimable from the host once the slot's PLM is open) *and* the fp64 unlock pre-armed.

The builder refuses to run if the FWSECLIC build does not match, and reports the flash footprint —
which sectors, how many bytes, and whether an erase is required. Read that before flashing. The
output has the same shape as the input, so a `--save --entire` dump round-trips straight back.

⛔ **Do not use a 6-link chain (`--resume 0x046A`).** All six writes land and the PMU halts on every
boot: `0x046A` is `mpopret $r0` and restores only r0, where the 5-link `0x41AC` is `mpopret $r3` and
restores r0-r3, which the continuation needs. Recoverable — nvflash still worked with the PMU
halted — but there is no reason to go there.

### 6.4 Flash

```bash
# PMU must be healthy first: a previous failed flash leaves it halted, and the next run then
# fails for a DIFFERENT reason than the first.
python3 tools/preflight.py $BDF | grep CPUCTL          # want 0x00000020
./nvflash-kit --index=N --protectoff
python3 tools/nvflash_pty.py --log flash.txt -- ./nvflash-kit --index=N --inforomnopreserve payload.rom
./nvflash-kit --index=N --save readback.rom --entire && sha256sum readback.rom payload.rom
```

⚠⚠ **nvflash reads confirmations from `/dev/tty`, not stdin.** `< /dev/null`, `printf 'y' |`,
bare `script`, and `ssh -tt` with the answer piped up front **all fail** — measured, all four; the
first is the long-standing "nvflash refuses to write the InfoROM" myth. `tools/nvflash_pty.py`
does a real `pty.fork()` and answers when the prompt appears. Keep the transcript.

⚠ **Classify the transcript mechanically, never by eye.** A real program run is ~9.2 KB and says
`Update successful`; a no-op is ~1.4 KB and says `Nothing changed!`. A misread of exactly this
sent one session down the wrong causal path for hours. **The readback hash is the only proof.**

⚠ After any external-programmer session the chip comes back software-write-protected and the first
in-band write fails with `Software write protection enabled`. `--protectoff` clears it. Note that
`--protectoff` succeeding proves nothing on its own — it also worked during the lockout. Only a
real program does.

Then reset the device and confirm the chain fired:

| | want |
|---|---|
| PMU `CPUCTL` `0x10A100` | `0x00000020` (`0x10` = HALT, `0x00` = the post-Xid-79 signature) |
| `SCRATCH(5)` `0x1594` | `0x70005000` (`0x7000506D` = the chain did **not** fire) |
| `0x409650` | `0x000000FF` — FECS PLM open |
| trap 20 | `MASK 0xFC000000  DATA1 0xC0000000  ACTION 0x00100000  PLM 0x00000FFF` |

`python3 tools/preflight.py $BDF` reports all four.

⚠⚠ After an Xid-79 fall-off the **first** SBR left `CPUCTL = 0x00000000` here — the halted-PMU
signature — and a second SBR gave `0x20`. **Never diagnose a halted PMU from one reset.**

### 6.5 Per-boot sequence

```bash
# bare metal (nvidia.ko blacklisted at boot)
bash tools/unlock_all.sh --bdf $BDF

# Proxmox passthrough
bash tools/unlock_all.sh --bdf $BDF --vm 130 --guest root@<guest-ip> \
                         --guest-bdf 0000:01:00.0 --guest-tools /root

# rehearse the whole thing with no hardware attached
bash tools/unlock_all.sh --bdf $BDF --dry-run
```

The script enforces the ordering and refuses to continue when a precondition fails. The ordering
*is* the trick:

```
device reset ──► [PCIe retrain] ──► load driver (devinit runs) ──► [fp64] ──► [memclk]
                 pre-POST only                                     post-POST  post-POST, IDLE
```

⚠ `nvidia-smi -pm 1` immediately after the first successful init. Without it, RM cannot re-init
the adapter after a teardown (`RmInitAdapter 0x22:0x40:897`), `FLReset-` means sysfs reset fails,
and only a module reload recovers it.

★ The throttle is a **live toggle** once the PLM is open — `0x409664 <- 0x888` gives full speed and
`<- 0x999` puts it straight back, on a running GPU with a CUDA context, no reload and no reset.
That makes A/B measurement trivial and is the cheapest way to prove the unlock is real.

---

## 7. Phase 4 — verify

⚠⚠ **Bind every benchmark to the card under test.** CUDA device 0 is *not* necessarily your card
on a multi-GPU host, and a clean memtest on the wrong GPU is worse than no result at all. Export
`GV100_BDF` and every binary here selects by PCI address and **prints the bus id it actually ran
on** — check that line before believing any number below it.

```bash
export GV100_BDF=$BDF                  # all five binaries honour this
nvidia-smi -lgc 1380,1380 -i $BDF
./gv100_pipes 0 1380        # fp64 ~6.85, tensor ~101.8, fp32 ~12.7 TFLOP/s, read ~890 GB/s
./gv100_memtest 15 2        # MANDATORY after any memory clock change
./gv100_validate 1024       # DGEMM/HGEMM against a CPU reference
lspci -vv -s ${BDF#0000:} | grep LnkSta
```

Each prints `device N  <name>  @ <bus id>` as its first line. If that bus id is not `$BDF`, stop —
everything after it describes a different GPU. An unmatched `GV100_BDF` is a hard refusal (exit 2)
rather than a silent fallback to device 0.

⚠ `gv100_memtest` backs its allocation off 256 MiB at a time until it fits. If it cannot test what
you asked for it now says `*** COVERAGE SHORTFALL ***` and **exits non-zero** — a `CLEAN` line over
2 GiB of a 16 GiB framebuffer is not the 15 GiB the runbook asks for. Free the GPU and re-run.

A bandwidth number is not a correctness result. Both `gv100_memtest` and `gv100_validate` exist
because a marginal memory interface returns wrong bits rather than hanging, and every headline
number in §1 was taken with them passing.

---

## 8. Phase 5 — rollback

```bash
./nvflash-kit --index=N --protectoff
python3 tools/nvflash_pty.py --log restore.txt -- ./nvflash-kit --index=N --inforomnopreserve baseline.rom
./nvflash-kit --index=N --save check.rom --entire && sha256sum check.rom     # == baseline.sha256
python3 tools/trap_dump.py $BDF        # want "all 22 traps match the pre-exploit stock state"
```

⚠ `trap_dump.py`'s stock table is the *reference card's* devinit-programmed state. On another card
compare against a dump you took **before** flashing, not against the shipped table. Take one.

⚠ Immediately after any nvflash run, trap15 reads a transient PMU flash-service state
(`MATCH=0x60022408 MASK=0x1C000000 ACTION=0x1`). **Reset before reading traps**, or you will chase
a phantom.

---

## 9. The x16 firmware edit — proven, and gated by your board

The x1 link is not in the VBIOS. It is in the **IFR**, at physical flash `0x214`: a record that
read-modify-writes `XP_PL_LINK_CONFIG_0` to force `LINK_SPECIFIER` to lanes `00_00`. Retargeting it
at the read-only `XP_PL_LINK_PRESENT` neutralises it — **one byte, `0x42 → 0x02`, a single bit
1→0**, so no erase and no partial state, which is what makes touching sector 0 survivable at all.
Delivered over the L3 SPI stamp (`tools/spi_flash_l3.py`), because nvflash's PMU flash service
refuses every write below physical `0x00EE00`.

**It works.** Measured after the write and an SBR:

```
LINK_SPECIFIER               0x01 -> 0x10      (lanes 00_00 -> 15_00)
XVE_LINK_CAPABILITIES width     1 -> 16
lspci  LnkCap                  x1 -> x16       card enumerates normally
```

**What it bought on the reference bench: nothing yet** — because width has a *second* gate, and it
is physical. On this SKU the series **AC-coupling capacitors for the additional lanes are
depopulated**. PCIe negotiates width by per-lane receiver detection; a lane with no coupling
capacitor has no AC path, so no partner is detected and the link trains **x1** regardless of what
either end advertises. With both ends at x16 and a forced retrain, that is exactly what happened.

★ **The traces are there; the caps are not.** Full width is therefore a **rework**, not an
impossibility: fit capacitors matching the value of the populated ones on the working lane. This
kit removes the firmware gate and the soldering removes the other. ⚠ *That rework has not been
performed here — it is reported from board inspection, not verified by measurement, so treat the
end-to-end result as untested.*

**Before you commit:**

* ⛔ **`XP_PL_LANE_PRESENT` is not predictive.** It read `0xFFFF` — 16 lanes present at the PHY —
  on the card that trained x1. The PHY is fine; the coupling path is not.
* ★ **Inspect the board.** Look for empty pad pairs on the lane traces near the edge connector,
  alongside the populated pair on the lane that works. That is the depopulation, and it is what
  you would be fitting.
* ⚠ Doing the firmware edit **without** the rework gains nothing but still carries the full risk
  below. Doing the rework without the firmware edit also gains nothing, because the IFR record
  keeps forcing `LINK_SPECIFIER` to x1. **They are only useful together.**

⛔⛔ **The risk is real and asymmetric.** The IFR programs `ROM_ADDR_OFFSET` and the PCIe config, so
a bad edit can stop the card enumerating — and nvflash cannot rewrite sector 0 without the L3
stamp, which needs the card to enumerate. There is no in-band way back. **Attach a 1.8 V-capable
programmer before the write** (see §2 — a stock 3.3 V CH341A destroys this chip), and remember the
edit and the L3 chain are coupled: the SPI stamp needs trap 20, which needs the payload resident.

## 10. If your card is not the reference card

This is the interesting part, and the reason to write any of this down.

| what `rom_compat` / `preflight` says | what it means | what to do |
|---|---|---|
| FWSECLIC IMEM sha differs, gadgets still match | a different VBIOS branch, same ucode shape | probably fine, but re-derive the frame geometry (`tools/fuc_frames.py`, `tools/falcon_cfg.py`) before `--force-incompatible` |
| a gadget VA does not match | different FWSECLIC build | **stop.** The chain is a jump to an arbitrary address at L3. Re-derive, do not force |
| ULF declared size ≠ 1120 | different InfoROM object layout | check the headroom in `tools/inforom_walk.py`; the copy must still overflow into the frame |
| InfoROM directory at a different address | **expected and handled** | nothing — this is why it is derived |
| a `SPEED_SELECT` fuse is burned | throttled in OTP, not devinit | this kit cannot lift it. That is the 170HX's mechanism, not this one |
| `arch != 0x140` | not Volta | every address here is wrong. See `~/170hx_unlock` for GA100 |
| CYA bits already clear | the Gen1 cap is fused, not CYA | the Gen3 write will do nothing |
| the `0x409664` record has a value other than `0x999` | a different throttle configuration | measure before and after; do not assume the 15.5× number transfers |

**Your FWSECLIC build is probably compatible even if your VBIOS version is not.** A stock Tesla
V100 at `88.00.4F.00.09` ships the *identical* FWSECLIC image (verified: same IMEM sha256). The
vulnerable copy is unguarded on every CMP part sampled — 100-210, 170HX, 90HX — and the guard that
NVIDIA later added stages `NV_PREOS_ERR_INFOROM_BUFFER_OVERFLOW = 0x202A`, their own name for this
bug. The boundary is a VBIOS branch, not an architecture.

**The two failure modes worth rehearsing before you meet them:**

1. **`RmInitAdapter failed! (0x31:0xffff:2780)`** — the driver refuses to POST because a byte in the
   legacy image or an NVIDIA ucode image changed. The card is fine: `BIOSCERT_ERR = 0x00`, PMU
   healthy, chain fired. Reflash the baseline. This is why the payload lives in the InfoROM, which
   the check does not cover.
2. **`Falcon In HALT or STOP state` on a flash** — the PMU is halted from a previous failed attempt.
   SBR, confirm `CPUCTL = 0x20`, retry. Do not retry into a halted PMU; you will get a different
   error and misdiagnose it.

---

## 11. What to send back

If you run this on another card, these are the artifacts that make the result usable to everyone
else. Keep them **as raw tool output**, unedited.

```bash
python3 tools/rom_compat.py baseline.rom --json > report-romcompat.json
python3 tools/preflight.py  $BDF --json         > report-preflight-prepost.json
# ... after the driver loads:
python3 tools/preflight.py  $BDF --json         > report-preflight-posted.json
python3 tools/post_state_probe.py $BDF --json   > report-poststate.json   # JSON on stdout,
                                                                         # human report on stderr
python3 tools/trap_dump.py  $BDF                > report-traps.txt
sha256sum baseline.rom payload.rom readback.rom > report-hashes.txt
# plus: flash.txt, the gv100_pipes / memtest / validate output, and `dmesg | grep -i xid`
```

And in prose, four things:

1. **card identity** — devid, VBIOS version, board part number, and whether the FWSECLIC hash
   matched.
2. **which of the four unlocks you attempted, and the measured before/after** for each. The live
   toggle (`0x409664` `0x888` ↔ `0x999`) makes a same-boot A/B cheap; please do that rather than
   comparing across boots.
3. **anything that differed from this document**, including things that turned out not to matter.
   A card where a step was unnecessary is as informative as one where it failed.
4. **Xid count.** Zero is the expected answer for every step here. A non-zero count that you
   worked around is the single most useful thing you can report.

⚠ **Bring the evidence back the same session.** The one transcript this tree lost was left on the
bench overnight and the machine powered off before it was copied — it was the sole primary evidence
for a central claim. A refused flash costs nothing to re-run; an evaporated transcript costs the
claim.

---

## Index of what the kit contains

| file | what it does | hardware? |
|---|---|---|
| `tools/kit_selftest.sh` | proves the offline chain end-to-end | no |
| `tools/rom_compat.py` | is this ROM compatible, and what is nerfed on it | no |
| `tools/build_payload.py` | build a payload from **this card's own** dump | no |
| `tools/patch_nvflash_kit.py` | stock nvflash 5.680 → the binary the kit needs | no |
| `tools/preflight.py` | on-card GO/NO-GO, strictly read-only | yes, read-only |
| `tools/unlock_all.sh` | the per-boot sequence, in the one order that works | yes |
| `tools/pcie_retrain_probe.py` | the Gen1 → Gen3 clamp clear + retrain | yes |
| `tools/hbm_mclk_switch.py` | the 6-step memory clock switch | yes |
| `tools/fecs_unlock_attempt.py` | the fp64/tensor throttle write, with readback | yes |
| `tools/trap20_stamp.py` | re-aim trap 20; stamp an arbitrary host write to L3 | yes |
| `tools/spi_flash_l3.py` | read/erase/program flash over the L3 stamp | yes, writes |
| `tools/nvflash_pty.py` | drive nvflash under a real tty (it reads `/dev/tty`) | yes |
| `tools/trap_dump.py` | the 22 decode traps vs a stock reference | yes, read-only |
| `tools/bench/*.cu` | pipes, sweep, memtest, numerical validation | yes |
| `tools/fuc_frames.py`, `tools/falcon_cfg.py`, `tools/falcon_disasm.py` | re-derive the chain geometry if your FWSECLIC build differs | no |
