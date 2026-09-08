#!/bin/bash
# build.sh -- compile the five bench binaries, and fail loudly if any does not build.
#
# ⚠ Run this EARLY, on the machine that will drive the card. The kit was authored on a host with
# no CUDA toolchain, so these five .cu files are the one part of it that has never been through
# nvcc in its current form. Everything they depend on is checked (call sites, macro ordering,
# includes) and the device-selection helper compiles standalone, but a real compile is a real
# compile. If something here fails it is a five-minute fix, not a card risk -- but find out now,
# not while a card sits half-unlocked.
#
# usage: build.sh [outdir]        default: ./bin ;  override arch with SM=70
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$HERE/bin}
SM=${SM:-70}                      # GV100 = sm_70
mkdir -p "$OUT"

command -v nvcc >/dev/null || { echo "⛔ nvcc not on PATH. Install the CUDA toolkit (12.x)."; exit 1; }
echo "nvcc: $(nvcc --version | tail -1)"
echo "arch: sm_$SM   out: $OUT"
echo

fail=0
for src in gv100_pipes gv100_memtest gv100_validate gv100_sweep gpu_hold; do
    printf '  %-16s ' "$src"
    if nvcc -O3 -arch="sm_$SM" -o "$OUT/$src" "$HERE/$src.cu" 2> "$OUT/$src.log"; then
        echo "ok"
    else
        echo "FAILED"; sed 's/^/      /' "$OUT/$src.log" | head -20; fail=1
    fi
done

echo
if [ "$fail" = 0 ]; then
    cat <<MSG
★ all five built into $OUT

  Bind every run to the card under test -- CUDA device 0 is not necessarily your card:
      export GV100_BDF=0000:0b:00.0
  Each binary prints "device N <name> @ <bus id>" first. If that is not your card, stop.
MSG
else
    echo "⛔ build failures above. Report them with the .log files -- see the porting doc §11."
    exit 1
fi
