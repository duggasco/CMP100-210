# The video engines are a FIFTH devinit nerf — and the BIT flag hypothesis is dead

**Date:** 2026-09-06 (pass 67) · **Card:** `0000:0b:00.0`, driver 580.178.04 in VM 130
**Writes to the card:** one refused L0 control pair (§4), then a deliberate runtime-lift attempt
(§6) — one trap-20 stamp and one-or-two `CTRL_OPT` writes per boot, all **volatile SW overrides**.
**No flash, no OTP, nothing persistent.** The lift attempt took the GPU off the bus twice (Xid 79);
both times two SBRs restored the exact documented baseline and the full unlock stack was reapplied
and re-validated (fp64 6.849 / tensor 101.742 TFLOP/s, 890.1 GB/s, `gv100_memtest 15 2` CLEAN,
0 Xids).

Opens from `HANDOFF-2026-09-06-session-61-66.md` §4(c) — *"why RM does not advertise NVENC/NVDEC"*.
The answer is not where §4(c) predicted, and it is considerably better than expected.

---

## 0. Result

⛔⛔ **The tree read `FUSE_CTRL_OPT_NVDEC`/`NVENC` backwards.** These are **disable** masks, and
this card has **every video engine floorswept off by devinit** — against clear fuses, healthy
silicon and live power. CLAUDE.md's pass-64c conclusion, *"the video engines are enabled at the
fuse, control-register AND power-gate level ⇒ the blocker is above devinit (RM/VBIOS capability
advertisement)"*, is **wrong and is retracted**. The blocker **is** devinit, and it is two register
writes of exactly the same class and privilege as the fp64/tensor throttle `0x409664`.

⇒ **This is a fifth nerf.** It *looked* like the same shape as the one pass 62 lifted, and at the
register level it is — but ⛔⛔ **it was attempted on hardware and it CANNOT be lifted at runtime**
(§6). The lift itself works perfectly: a trap-20 stamp reopens the PLM and L0 writes clear both
masks, with the read-only `STATUS_OPT_*` following to 0 and holding across RM's trap teardown. Then
RM tries to *load* an engine devinit never initialised and the GPU falls off the bus —
**Xid 79 / `RmInitAdapter 0x25:0x65:1636` (`RM_INIT_GPU_LOAD_FAILED`)**, reproduced with NVDEC
alone. ⇒ the fix must be **inside devinit**, which puts this behind the same legacy-image integrity
wall as the other three devinit words and ECC.

★ Second, independent result: an A/B of the BIT `INTERNAL_USE` table against **three** stock Tesla
V100 VBIOSes **refutes** §4(c)'s stated hypothesis — the CMP nerf is *not* a set of `bFlag`-class
capability bits. There are exactly two flag differences, both already accounted for, and
**`REDUCE_MINING_PERF` — NVIDIA's own LHR-style VBIOS bit — is `0` on this card, identical to
stock.** §5.

---

## 1. The polarity, from NVIDIA's own header — not inferred

`drivers/common/inc/hwref/volta/gv100/dev_fuse.h`, read out of the header, lines 2684-2689:

```
#define NV_FUSE_CTRL_OPT_NVDEC                    0x00021824  /* RWI4R */
#define NV_FUSE_CTRL_OPT_NVDEC__PRIV_LEVEL_MASK   0x000210FC
#define NV_FUSE_CTRL_OPT_NVDEC_DATA                      0:0  /* RWIVF */
#define NV_FUSE_CTRL_OPT_NVDEC_DATA_ENABLE        0x00000000  /* RW--V */
#define NV_FUSE_CTRL_OPT_NVDEC_DATA_DISABLE       0x00000001  /* RW--V */   <-- this card
```

`NV_FUSE_CTRL_OPT_NVENC 0x021968` has the same shape with `DATA` = **2:0** — one bit per NVENC
instance, and GV100 has three. So `0x7` is not "all three enabled"; it is **all three disabled**.

`CTRL_OPT_*` is the SW-writable *effective floorsweeping* register, the same family as
`CTRL_OPT_TPC_GPC` / `CTRL_OPT_FBP` / `CTRL_OPT_GPC`, where a set bit has always meant *swept off*
in this tree (`nerf_diff.py` reads `TPC_GPC0 0x20` as "TPC 5 cut", giving 42 − 2 = 40 TPC = 80 SM,
which is the measured SM count). The video registers are read the same way; only the *label* was
wrong.

## 2. Measured on silicon — the complete causal chain

`tools/video_engine_probe.py 0000:01:00.0`, POSTed card, driver loaded, GPU idle
(`logs/117-video-engine-floorsweep-0b.txt`). Canary `PMC_BOOT_0 = 0x140000A1` held across every
read:

| register | offset | value | reading |
|---|---|---|---|
| `FUSE_OPT_NVDEC_DISABLE` | `0x021378` | `0x00000000` | OTP fuse: **not** disabled |
| `FUSE_OPT_NVENC_DISABLE` | `0x021414` | `0x00000000` | OTP fuse: **not** disabled |
| `FUSE_OPT_NVDEC_DEFECTIVE` | `0x0215E0` | `0x00000000` | silicon intact |
| `FUSE_OPT_NVENC_DEFECTIVE` | `0x0215DC` | `0x00000000` | silicon intact |
| `FUSE_OPT_NVDEC_DISABLE_CP` | `0x021458` | `0x00000000` | redundant copy agrees |
| `FUSE_OPT_NVENC_DISABLE_CP` | `0x02145C` | `0x00000000` | redundant copy agrees |
| `FUSE_OPT_VP8_VP9_DISABLE` | `0x021500` | `0x00000000` | codecs not fused off |
| `FUSE_OPT_NVENC_THROTTLE` | `0x021610` | `0x00000000` | encoder not throttled |
| ⛔ **`FUSE_CTRL_OPT_NVDEC`** | **`0x021824`** | **`0x00000001`** | **SW override: DISABLE** |
| ⛔ **`FUSE_CTRL_OPT_NVENC`** | **`0x021968`** | **`0x00000007`** | **SW override: all 3 DISABLE** |
| `FUSE_STATUS_OPT_NVDEC` | `0x021C24` | `0x00000001` | **effective** floorsweep — read-only |
| `FUSE_STATUS_OPT_NVENC` | `0x021D68` | `0x00000007` | **effective** floorsweep — read-only |
| `PMC_ENABLE` | `0x000200` | `0x1FECDFF1` | NVDEC=1 NVENC0=1 NVENC1=1 NVENC2=0 — **power on** |

★ `NV_FUSE_STATUS_OPT_*` (`R-I4R`, read-only) is the register the hardware and RM actually consult —
the OR of the OTP fuse and the SW override. It mirrors `CTRL_OPT_*` exactly, which closes the chain:
**fuse clear + override set ⇒ effective = swept off.**

★ And devinit is the writer. `tools/devinit_diff.py` (pass 60, `logs/50`) already listed
`CTRL_OPT_NVENC <- 7` and `CTRL_OPT_NVDEC <- 1` among the **7 devinit writes that differ from a
stock Tesla V100** — they were simply filed as harmless. They are two of the five substantive
CMP nerfs.

## 3. Functional confirmation — `nNumNVDECs = 0`, not a sampling artifact

`nvidia-smi -q` reports Encoder/Decoder/JPEG/OFA *utilisation* as `N/A`, which is weak evidence:
utilisation **sampling** being unsupported and the engine being **absent** are different things, and
the tree had been treating the first as proof of the second.

`tools/bench/nvdec_probe.c` asks the driver directly — CUDA context, then
`cuvidGetDecoderCaps()` per codec (`logs/116-nvdec-probe-cuvid.txt`):

```
device: Tesla V100-PCIE-12GB
codec      bits   chroma   sup  maxW      maxH      nNVDECs  cuvid_rc
MPEG1/2/4, VC1, H264, JPEG, H264_SVC/MVC, HEVC, VP8, VP9, AV1   (8- and 10-bit)
                            0    0         0         0        0
RESULT: 0 supported (codec,bitdepth) combinations
```

Every call **succeeds** (`cuvid_rc = 0`) and reports `bIsSupported = 0`, `nMaxWidth = 0` and
**`nNumNVDECs = 0`**. The driver is not failing to answer; it is answering *zero decoders present*.
⇒ the `N/A` is real, and it is downstream of the floorsweep, not a telemetry gap.

## 4. The gate: `PLM 0x0210FC = 0x8F`, write-L3-only — control write REFUSED

```
PLM 0x0210FC = 0x0000008F   READ=7 WRITE=0 => L3 ONLY
APPLY: writing 0x021824<-0x0, 0x021968<-0x0
  0x021824: 0x00000001 -> wrote 0x00000000 -> reads 0x00000001   BOUNCED
  0x021968: 0x00000007 -> wrote 0x00000000 -> reads 0x00000007   BOUNCED
  PMC_ENABLE now 0x1FECDFF1 (unchanged)
```

`logs/118-video-engine-l0-control-refused.txt`. Both writes bounce, exactly as `WRITE 6:4 = 0`
requires on a Volta 3-level PLM. PMC_ENABLE unchanged, canary held, **0 Xids**. This is the clean
control CLAUDE.md demands (*"always prove a write with a readback plus a control write"*): the gate
is real, and the target is in the **same write-L3-only class that pass 62 defeated on `0x409650`**.

⚠ Note this also settles the pass-64c question in the other direction: the PLM reading `0x8F`
post-POST is not incidental — it is what makes the floorsweep stick.

## 5. ⛔ The BIT `INTERNAL_USE` hypothesis is refuted (and `REDUCE_MINING_PERF` is 0)

§4(c) proposed that the video blocker was *"another `bFlag`-class field in the BIT `INTERNAL_USE`
table, i.e. the same family as the ECC bit"*. It was cheap to test and it is **wrong**: that table
has no video-engine field at all.

`tools/bit_internal_ab.py` decodes all 96 packed bytes of `BIT_DATA_INTERNAL_USE_V2_96` — struct and
bit definitions taken verbatim from NVIDIA's `bit.h`
(`BIT_DATA_INTERNAL_USE_V2_96_FMT "1d1b1w1d2w8b1w2d1w3b1w2d22b1w16b1d1w2b"`), not inferred — and
A/Bs images. Run against **three** independent stock Tesla V100 VBIOSes
(`logs/115-bit-internal-ab.txt`):

| flag | aperture | CMP 100-210 | V100 16GB '17 | V100 32GB '18 | V100 16GB (live card) |
|---|---|---|---|---|---|
| `bFlag3` | `0x0003C5` | **`0x10`** | `0x1A` | `0x1A` | `0x1A` |
| `bFlag5` | `0x0003E3` | **`0x00`** | `0x01` | `0x01` | `0x01` |
| `bFlag6` | `0x0003E5` | `0x12` | `0x12` | `0x12` | `0x12` |

Exactly **two** capability differences, 3/3 consistent:

* `bFlag5` bit 0 `SKU_SUPPORTS_ECC` `1 → 0` — the pass-65 ECC gate, now confirmed against three
  references instead of one.
* `bFlag3` — **new** — two bits cleared:
  * bit 3 `ECC_DEFAULT_SETTING_ENABLED` `1 → 0` (the ECC *default*, same nerf as above);
  * bit 1 `COMPUTE_ONLY` `1 → 0`.

★★ **`bFlag6` is byte-identical to stock, so `REDUCE_MINING_PERF` (bit 7) = 0 on this card.**
NVIDIA *does* have a VBIOS mining-throttle flag on Volta —
`NV_BIT_DATA_INTERNAL_V2_BFLAG6_REDUCE_MINING_PERF`, `bit.h:1238` — and the CMP 100-210 **does not
use it**. `LOCKED_CLOCKS_MODE_SUPPORTED=1 / _ENABLED=0` and `WS_FEATURE_OVERRIDE=0` are likewise
identical to stock. ⇒ there is no LHR-style VBIOS lever here; the throttle is the devinit word
`0x409664`, as pass 62 established. **Do not go looking for a mining flag again.**

⛔ **`COMPUTE_ONLY` is branding only — not a performance lever.** Its only consumers in the RM
source are:

* `gpu_gf100.c:1644 gpuReadTeslaSupport_GK104()` → `return !!(pVbios->InternalUseFlags3 &
  ..._BFLAG3_COMPUTE_ONLY) && (IsPASCALorBetter(pGpu) || !gpuIsQuadroBranded(pGpu));`
  used at `gpu_branding.c:194` and exposed as `NV2080_CTRL_GPU_INFO_INDEX_TESLA_ENABLE`;
* `grid_features.c:145` — vGPU/GRID licence support, and only together with `BRANDING_TYPE_VGX`.

Neither touches a clock, a pipe or an engine. Worth recording because a `COMPUTE_ONLY` difference
*looks* like a capability nerf and is not one.

## 6. ⛔⛔ ATTEMPTED ON HARDWARE — the lift WORKS and the card dies anyway

**Tried, same day, three boots (`logs/122`-`logs/124`, `tools/video_post_race.py`). The register
lift succeeds completely and is still useless.** §6a below is the pre-experiment analysis, kept
because its ordering prediction was right; this is what actually happened.

### The ordering, measured at millisecond resolution (`logs/122`, observe-only, zero writes)

| t (s) | event |
|---|---|
| 0.000 | driverless: `PMC_ENABLE 0x40000020`, **`PLM 0x0210FC = 0xFF`**, `CTRL_OPT` **0 / 0**, trap 20 ARMED |
| 22.856 | POST starts — `PMC_ENABLE -> 0x1FECDFF1`, PGRAPH on, PLM **still `0xFF`** |
| 22.858 | **devinit lowers the PLM `0xFF -> 0x8F`** |
| 22.858 | **then** devinit writes `CTRL_OPT` **1 / 7**; `STATUS_OPT` follows in the same sample |
| 23.189 | RM tears trap 20 down |

⇒ ★ **devinit closes the PLM *before* it floorsweeps**, so there is no exploit-free window — the
hoped-for "just beat devinit with a plain L0 write" does not exist. But trap 20 stays armed for
**331 ms** after the floorsweep, which is an enormous window for the L3 stamp.

★ Also confirmed here for the first time on silicon: pre-devinit the masks are **0 / 0**. The
floorsweep is created by devinit; it is not a reset default.

### The lift lands, exactly as designed (`logs/123`)

One trap-20 stamp and two L0 writes, inside the window:

```
10.408  PGRAPH ON  trap20 ARMED  PLM 0x00008F  cNVDEC 0x0 cNVENC 0x0     <- devinit closes PLM
10.409  PGRAPH ON  trap20 ARMED  PLM 0x00008F  cNVDEC 0x1 cNVENC 0x7     <- devinit floorsweeps
10.409  PGRAPH ON  trap20 ARMED  PLM 0x0000FF  cNVDEC 0x1 cNVENC 0x7     <- our stamp reopens PLM
10.409  PGRAPH ON  trap20 ARMED  PLM 0x0000FF  cNVDEC 0x0 cNVENC 0x0     <- our L0 writes clear it
        ...                                    sNVDEC 0x0 sNVENC 0x0     <- STATUS_OPT follows
14.246  PGRAPH ON  trap20 dead   PLM 0x0000FF  cNVDEC 0x0 cNVENC 0x0     <- survives RM teardown
14.940  everything reads 0xFFFFFFFF                                       <- GPU off the bus
```

`iterations 1235368  plm stamps 1  ctrl_opt writes 2` — no hammering; it wrote once and stopped.
The un-floorsweep **held for 4.5 s**, including across RM's trap teardown, with `STATUS_OPT_NVDEC`
and `STATUS_OPT_NVENC` — the read-only *effective* floorsweep — both reading **0**.

### …and then the card falls off the bus

```
NVRM: Xid (PCI:0000:01:00): 79, GPU has fallen off the bus.
NVRM: GPU 0000:01:00.0: RmInitAdapter failed! (0x25:0x65:1636)
NVRM: GPU 0000:01:00.0: RmInitAdapter failed! (0x22:0x56:897)
```

`0x25` = **`RM_INIT_GPU_LOAD_FAILED`** (`osinit.c:105`) — not the VBIOS path, the engine **load**
phase. ⇒ RM found the video engines present, went to bring them up, and the access killed the bus.

★ **`--only nvdec` reproduces it identically** (`logs/124`): clearing `CTRL_OPT_NVDEC` alone —
leaving all three NVENCs swept — gives the same Xid 79 and the same `0x25:0x65:1636`. So it is not
NVENC-specific, and **one engine is enough**.

### ⇒ The conclusion, and it reclassifies the nerf

**`CTRL_OPT_*` is only the mask.** Because devinit floorswept these engines, the rest of devinit's
per-engine bring-up — clock tree, priv-ring path, reset/ucode plumbing — was **skipped for them**.
Un-masking after the fact hands RM an engine that was never initialised, and RM's first real access
to it takes the GPU off the PCIe bus.

⇒ **The fix has to be in devinit, so that devinit initialises the engines** — i.e. the fifth nerf is
a *devinit word*, exactly like the other three, and it sits behind the **same legacy-image integrity
wall** (`RmInitAdapter 0x31:0xffff:2780`, handoff §3a) as the fp64/memory/PCIe words and ECC. There
is no runtime route. ⛔ **Do not re-attempt the runtime lift.**

★ **Recovery was complete and routine every time.** Two SBRs restored the documented driverless
baseline on both occasions — `PMC_BOOT_0 0x140000A1`, `PMC_ENABLE 0x40000020`, `CPUCTL 0x20`,
`SCRATCH5 0x70005000`, trap 20 armed, `FECS_PLM 0xFF`, `CTRL_OPT` back to 0/0. Nothing persistent
was written: no flash, no OTP. The full unlock stack was then reapplied and re-validated —
fp64 **6.849**, tensor **101.742**, fp32 12.695 TFLOP/s, read **890.1 GB/s**, H2D **0.78** /
D2H **0.83**, and `gv100_memtest 15 2` **CLEAN, 0 bad words**, 0 Xids.

⚠⚠ **New gotcha, paid for here:** after an Xid-79 fall-off the **first** SBR left
`PMU CPUCTL = 0x00000000`, which is the documented signature of a halted PMU — the second SBR
brought it to `0x20`. **Do not conclude "the PMU is halted" from a single SBR**; reset twice and
re-read before drawing any conclusion (or, worse, before attempting a flash on that basis).

## 6a. The pre-experiment analysis (kept — its ordering prediction was correct)

The target is **structurally identical to the fp64 throttle**: a functional register behind a
write-L3-only PLM, set by devinit, with the die underneath unrestricted. Pass 62's recipe therefore
applies in outline — spend an L3 write on the **PLM** rather than on the register, because the PLM
survives POST and RM's decode-trap teardown while an armed trap does not.

⚠ But the timing is **not** the same, and this is the crux:

| | fp64 `0x409664` | video `CTRL_OPT_NVDEC/NVENC` |
|---|---|---|
| when the value matters | **continuously** — FECS re-reads it every cycle; pass 62 toggled it live on a running GPU with a CUDA context | **once**, when RM enumerates engines during POST |
| so a post-POST L0 write | works, immediately (`logs/105`) | ⚠ almost certainly too late — RM's engine database is already built |

⇒ the write must land **after devinit writes 1/7** but **before RM enumerates engines**. Two
candidate procedures, neither yet tried:

**(A) Hit the window.** `tools/fecs_post_race.py` already measured this exact region at register
resolution (`logs/101`): devinit runs at t = 6.474 s, RM tears trap 20 down at t = 6.798 s — a
**324 ms** window in which trap 20 is still armed *and* devinit has finished. Stamp
`0x0210FC <- 0xFF` there, then immediately L0-write both `CTRL_OPT` registers to 0. Racy, but the
instrumentation to hit it exists and was proven on the fp64 target.

**(B) Stamp in the window, then reload the module.** The PLM is persistent register state, so it
only has to be opened once. Then `rmmod nvidia` → L0-write `CTRL_OPT_NVDEC <- 0`,
`CTRL_OPT_NVENC <- 0` → `modprobe nvidia`. This is race-free **iff** RM skips devinit on the second
load because the GPU is already POSTed. There is direct evidence that such a gate exists: in
`RmInitAdapter` the POST call is guarded by `cmpb $0x0,0xe01(%rax); jne <skip>`
(`logs/119`, .text `0xd6ec38`). Whether that predicate is false on a warm reload is untested.

⚠ **Unknown that must be measured first:** whether a pre-POST stamp of `0x0210FC` even survives.
CLAUDE.md records `0x0210FC = 0xFF` pre-POST and `0x8F` post-POST, so **something during POST
lowers it** — a writer may always lower privilege. If devinit closes this PLM, a stamp placed
before `modprobe` is wasted and only (A) can work. One boot answers it: stamp pre-POST, `modprobe`,
read `0x0210FC`.

⚠ **What it would be worth.** 1 × NVDEC and up to 3 × NVENC on a V100 — real, but this is the
*least* valuable of the five nerfs by a wide margin, and unlike the other four it has an ordering
problem with no known clean solution. Rank it below the memory-clock defect (handoff §4(b)).

## 7. Safety — what `PLM 0x0210FC` does and does **not** govern

Checked before proposing any stamp, because the tree carries a hard hazard *"never write
`FUSEWDATA_PLM`"*:

| PLM | governs | on the OTP-burn path? |
|---|---|---|
| `0x0210F4` | `FUSEWDATA` | **yes** |
| `0x0210F8` | `FUSECTRL`, `FUSEADDR`, `FUSERDATA`, `EN_SW_OVERRIDE` | **yes** |
| **`0x0210FC`** | **948** shadow / floorsweeping / `STATUS_OPT` / `SECURE_*` registers | **no** |

★ The OTP write path lives behind **two different PLMs**, neither of which is `0x0210FC`. Opening
`0x0210FC` therefore **cannot burn a fuse** — every register it governs is volatile and restored by
reset. That is the property that makes this target acceptable at all.

⚠ It is still a broad surface: opening it makes `CTRL_OPT_TPC_GPC`, `CTRL_OPT_FBP`,
`CTRL_OPT_FBPA`, `CTRL_OPT_GPC`, `CTRL_OPT_PCIE_LANE` and ~940 more L0-writable for the rest of the
boot. Nothing else writes them, but a stray poke there would floorsweep real hardware. Write only
the two intended registers, and read back every one.

⚠ `0x0210FC` is **not** on the load-bearing denylist (decode traps `0x122000`-`0x1227FF`, PMGR/ROM
`0xD7D0`/`0xD7D8`/`0xE200`-`0xE210`/`0xE5A0`, `PMC_ENABLE 0x200`, priv-ring stations), and neither
are `0x021824`/`0x021968`.

## 8. Corrections this pass makes to the tree's record

* ⛔ *"`FUSE_CTRL_OPT_NVENC 0x021968 = 0x7` and `FUSE_CTRL_OPT_NVDEC 0x021824 = 0x1` — precisely what
  devinit writes ⇒ the video engines are enabled at the fuse, control-register and power-gate
  level"* (CLAUDE.md, pass 64c) — **the polarity is inverted**; `1`/`7` are DISABLE. Everything else
  in that pass-64c block stands: the fuses really are clear, `PMC_ENABLE` bit 15 really is set, and
  the PLM really is `0x8F`.
* ⛔ *"⇒ the blocker is above devinit (RM/VBIOS capability advertisement), not any of the mechanisms
  this line used to blame"* — **wrong**; the blocker is precisely one of those mechanisms.
* ⛔ Handoff §4(c)'s hypothesis *"most likely another `bFlag`-class field in the BIT `INTERNAL_USE`
  table"* — **refuted**, §5.
* ★ New: `bFlag3` bit 1 `COMPUTE_ONLY` differs from stock (branding/vGPU only) — a second
  `bFlag3`-byte difference that pass 65 did not report because it only decoded `bFlag5`.
* ★ New: `REDUCE_MINING_PERF` exists on Volta and is **not** used by this SKU.

## 9. Tools and logs added

| path | what |
|---|---|
| `tools/bit_internal_ab.py` | decode + A/B `BIT_DATA_INTERNAL_USE_V2_96` across VBIOS images; handles both aperture (`base 0`) and physical/NVGI (`base 0xA00`) layouts |
| `tools/video_engine_probe.py` | the register chain above; read-only by default, `--apply`/`--restore` write and read back |
| `tools/bench/nvdec_probe.c` | `cuvidGetDecoderCaps()` per codec via dlopen; no CUDA/SDK headers needed |
| `tools/video_post_race.py` | watch/act inside the POST window; **observe-only by default**, `--apply`, `--only nvdec\|nvenc\|both` |
| `logs/115-bit-internal-ab.txt` | the 4-way BIT A/B |
| `logs/116-nvdec-probe-cuvid.txt` | `nNumNVDECs = 0` |
| `logs/117-video-engine-floorsweep-0b.txt` | the register chain, read-only |
| `logs/118-video-engine-l0-control-refused.txt` | the refused control write |
| `logs/122-video-post-race-observe.txt` | ★ the POST ordering, read-only: PLM closes *before* the floorsweep |
| `logs/123-video-post-race-apply-both.txt` | the lift lands, holds 4.5 s, then Xid 79 |
| `logs/124-video-post-race-apply-nvdec-only.txt` | NVDEC alone reproduces it identically |
