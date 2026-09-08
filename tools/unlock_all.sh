#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 duggasco
# unlock_all.sh -- run the whole per-boot CMP 100-210 unlock sequence, in the one order that works.
#
# Everything this does is PER-BOOT and reverted by any device reset.  The only persistent change
# the kit ever makes is the ROM payload, and that is a separate, deliberate step (see
# PORTING-2026-09-08-other-cards.md §4) -- this script never flashes anything.
#
# ⚠⚠ THE ORDER IS THE WHOLE TRICK, and two of the three steps have a window:
#
#   device reset ──► [PCIe retrain] ──► load driver (devinit runs) ──► [fp64] ──► [memclk]
#                    ^^^^^^^^^^^^^^                                   ^^^^^^     ^^^^^^^^
#                    pre-POST only                                    post-POST  post-POST, IDLE
#
#   * retrain BEFORE the reset/VM start -> the reset renegotiates the link and it is wasted
#     (measured: H2D 0.20 GB/s instead of 0.78).
#   * retrain AFTER the driver loads     -> devinit has re-clamped LnkCap; the write lands and
#     moves nothing.
#   * the fp64 write needs the FECS PLM open, which the ROM chain does at reset and RM cannot
#     undo; but it needs PGRAPH powered, so it must come after the driver.
#   * the memclk switch puts DRAM in self-refresh.  Under load that is 325 Xids.  IDLE ONLY.
#
# Topologies:
#   bare metal   unlock_all.sh --bdf 0000:0b:00.0
#                (nvidia.ko must NOT be loaded yet -- blacklist it, or `modprobe -r nvidia*`)
#   Proxmox VM   unlock_all.sh --bdf 0000:0b:00.0 --vm 130 --guest root@<guest-ip> \
#                              --guest-bdf 0000:01:00.0 --guest-tools /root
#
# usage: unlock_all.sh --bdf <host-bdf> [--vm N --guest <ssh-target> --guest-bdf <bdf>]
#                      [--guest-tools DIR]  (where tools/ lives IN THE GUEST; default /root)
#                      [--skip-gen3] [--skip-fp64] [--skip-memclk] [--ndiv N] [--dry-run]
set -u
HERE=$(cd "$(dirname "$0")" && pwd)

BDF=""; VM=""; GUEST=""; GBDF=""; GTOOLS=""; NDIV=65; DRY=0
SKIP_GEN3=0; SKIP_FP64=0; SKIP_MEMCLK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --bdf) BDF=$2; shift 2;;
    --vm) VM=$2; shift 2;;
    --guest) GUEST=$2; shift 2;;
    --guest-bdf) GBDF=$2; shift 2;;
    --guest-tools) GTOOLS=$2; shift 2;;
    --ndiv) NDIV=$2; shift 2;;
    --skip-gen3) SKIP_GEN3=1; shift;;
    --skip-fp64) SKIP_FP64=1; shift;;
    --skip-memclk) SKIP_MEMCLK=1; shift;;
    --dry-run) DRY=1; shift;;
    -h|--help) sed -n '2,32p' "$0"; exit 0;;
    *) echo "unknown argument: $1"; exit 1;;
  esac
done
[ -n "$BDF" ] || { echo "--bdf is required"; exit 1; }
[ -n "$VM" ] && [ -z "$GUEST" ] && { echo "--vm needs --guest <ssh-target>"; exit 1; }
GBDF=${GBDF:-$BDF}
# In VM mode the guest has its own copy of tools/ -- $HERE is a HOST path and means nothing there.
GTOOLS=${GTOOLS:-$( [ -n "$GUEST" ] && echo /root || echo "$HERE" )}

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
run()  { if [ "$DRY" = 1 ]; then echo "  [dry-run] $*"; else eval "$@"; fi; }
# In VM mode the compute-side commands run in the guest; on bare metal they run here.
gexec() { if [ -n "$GUEST" ]; then run "ssh $GUEST '$*'"; else run "$*"; fi; }
die()  { echo "⛔ $*" >&2; exit 1; }

rd() {  # rd <bdf> <offset>   -- read one BAR0 dword, read-only, canaried
  if [ "$DRY" = 1 ]; then
    # Rehearsal mode: hand back the values a healthy pre-POST card with a payload resident
    # would give, so the whole sequence can be walked through with no hardware present.
    case "$2" in
      0x0)      echo "0x140000A1";;
      0x200)    echo "0x40000020";;
      0x10A100) echo "0x00000020";;
      0x409650) echo "0x000000FF";;
      *)        echo "0x00000000";;
    esac
    return 0
  fi
  python3 - "$1" "$2" <<'PY'
import mmap, os, struct, sys
fd = os.open("/sys/bus/pci/devices/%s/resource0" % sys.argv[1], os.O_RDONLY | os.O_SYNC)
mm = mmap.mmap(fd, 1 << 24, mmap.MAP_SHARED, mmap.PROT_READ); os.close(fd)
if struct.unpack_from("<I", mm, 0)[0] != 0x140000A1:
    sys.exit("PRI canary bad: PMC_BOOT_0 = 0x%08X" % struct.unpack_from("<I", mm, 0)[0])
print("0x%08X" % struct.unpack_from("<I", mm, int(sys.argv[2], 0))[0])
PY
}

step "0. host preconditions"
# A cold boot with no driver bound leaves PCI memory space disabled; every BAR0 read then
# returns 0xFFFFFFFF, which decodes as a plausible "everything set" rather than an error.
run "setpci -s ${BDF#0000:} COMMAND=0x0002:0x0002"
BOOT0=$(rd "$BDF" 0x0) || die "BAR0 is not readable on $BDF"
echo "  PMC_BOOT_0     $BOOT0"
[ "$BOOT0" = "0x140000A1" ] || die "not a GV100 (or the ring is poisoned): PMC_BOOT_0 = $BOOT0"
PMC=$(rd "$BDF" 0x200); echo "  PMC_ENABLE     $PMC"
CPUCTL=$(rd "$BDF" 0x10A100); echo "  PMU CPUCTL     $CPUCTL"
[ "$CPUCTL" = "0x00000020" ] || echo "  ⚠ PMU is not in the healthy 0x20 state -- do not flash in this condition"
if [ "$PMC" != "0x40000020" ]; then
  die "the card has already POSTed (PMC_ENABLE $PMC, expected 0x40000020).
   The Gen3 window is pre-POST only.  Unload the driver / stop the VM, reset the device, and
   re-run:   echo 1 > /sys/bus/pci/devices/$BDF/reset"
fi
PLM=$(rd "$BDF" 0x409650); echo "  FECS PLM       $PLM"
if [ "$PLM" != "0x000000FF" ]; then
  echo "  ⚠ the FECS PLM is not open, so no unlock payload fired at this reset."
  echo "    fp64/tensor will fall back to the trap-20 stamp, which needs a payload resident."
fi

if [ -n "$VM" ]; then
  step "1. start VM $VM  (the ROM chain fires on the VM-start device reset)"
  run "qm start $VM"
  run "sleep 20"
  run "setpci -s ${BDF#0000:} COMMAND=0x0002:0x0002"
else
  step "1. bare metal: the chain fired at the last device reset; not resetting again"
  [ "$DRY" = 0 ] && lsmod 2>/dev/null | grep -q '^nvidia' && die "nvidia.ko is already loaded -- devinit has run and
   the Gen3 window is closed.  modprobe -r nvidia_uvm nvidia_drm nvidia_modeset nvidia, reset the
   device, and re-run."
fi

if [ "$SKIP_GEN3" = 0 ]; then
  step "2. PCIe Gen1 -> Gen3   (HOST, pre-POST window, must be before the driver loads)"
  run "python3 $HERE/pcie_retrain_probe.py $BDF --apply --target-gen 3" \
    || echo "  ⚠ retrain reported a problem; continuing -- a failed retrain is a no-op, not damage"
  echo "  link now: $(cat /sys/bus/pci/devices/$BDF/current_link_speed 2>/dev/null) / $(cat /sys/bus/pci/devices/$BDF/current_link_width 2>/dev/null) lane(s)"
else
  step "2. PCIe Gen3 SKIPPED"
fi

step "3. load the driver  (devinit runs here: it writes the 0x999 throttle and re-clamps LnkCap)"
gexec "modprobe nvidia && nvidia-smi -pm 1"
# ⚠ nvidia-smi -pm 1 immediately: without it, RM cannot re-init the adapter after a teardown
# (RmInitAdapter 0x22:0x40:897) and only a module reload recovers it.

if [ "$SKIP_FP64" = 0 ]; then
  step "4. lift the fp64 + tensor throttle  (plain L0; the PLM is already open)"
  gexec "python3 $GTOOLS/fecs_unlock_attempt.py $GBDF --apply"
  echo "  ⚠ want READOUT 0x409660 bits 20/21/22 clear.  This is a LIVE toggle: writing 0x999"
  echo "    back puts the throttle straight back, with a CUDA context open and no reset."
else
  step "4. fp64/tensor SKIPPED"
fi

if [ "$SKIP_MEMCLK" = 0 ]; then
  step "5. memory clock -> NDIV $NDIV   (GPU MUST BE IDLE)"
  # ⛔ Do NOT chain the `--ndiv 60` no-op control into the real switch: the control IS a switch,
  # and two switches without an intervening device reset give Xid 62 and a deadlocked RM
  # (measured 2026-09-08; recovery was a VM stop + SBR).  hbm_mclk_switch.py now refuses the
  # second one.  Run the control on its own boot if you want it; this path does the real switch.
  gexec "python3 $GTOOLS/hbm_mclk_switch.py $GBDF --ndiv $NDIV --apply" \
    || die "the memory clock switch failed -- do not retry without a device reset first"
else
  step "5. memory clock SKIPPED"
fi

step "done -- verify before trusting any of it"
cat <<MSG
  lspci -vv -s ${BDF#0000:} | grep LnkSta        want "8GT/s", possibly "(overdriven)"
  gv100_pipes 0 1380                             want fp64 ~6.85, tensor ~101.8 TFLOP/s
  gv100_memtest 15 2                             MANDATORY after any memory clock change
  gv100_validate 1024                            DGEMM/HGEMM vs a CPU reference

  ⚠ nvidia-smi lies about two of these.  It reports pcie.link.gen.current = 1 on a Gen3 link
    (it reads the re-clamped capability) and clocks.mem lags the memory switch.  Trust lspci
    LnkSta, the COEFF across all 16 FBPAs, and measured throughput.
  ⚠ A memory clock change can corrupt SILENTLY: bandwidth looks perfect while the data is wrong.
    gv100_memtest is not optional.
MSG
