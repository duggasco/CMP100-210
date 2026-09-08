#!/bin/bash
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright 2026 duggasco
# make_release.sh -- assemble the distributable unlock kit, and REFUSE if it leaks the bench.
#
# The working tree is not the package.  `README.md` and `CLAUDE.md` are bench notes: they carry
# host IPs, an ssh target and a BMC credential, and they describe one specific chassis.  Handing a
# tester "the whole tree" ships all of that and gives them a hundred files they do not need.
#
# This builds the package explicitly: a named file list, a secret scan that is a HARD GATE rather
# than a warning, and a manifest with checksums for everything shipped.  If the scan fires, no
# archive is produced.
#
# usage: make_release.sh [outdir]        default: ./release/cmp100-unlock-kit-<date>
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DATE=$(date -u +%Y-%m-%d)
OUT=${1:-$ROOT/release/cmp100-unlock-kit-$DATE}
# NO_FIRMWARE=1 omits the reference .rom images. They are the only files in the kit that carry
# the reference card's identity (InfoROM: serial, UUID, board part number), and a tester cannot
# use them anyway -- a payload must be built from their own card's dump. Required for anything
# published.
NO_FIRMWARE=${NO_FIRMWARE:-0}
cd "$ROOT" || exit 1

# --- what the package IS -------------------------------------------------------------------
DOCS="
PORTING-2026-09-08-other-cards.md
LICENSE
LICENSE-DOCS
NOTICE
"
TOOLS="
tools/kit_selftest.sh tools/make_release.sh
tools/rom_compat.py tools/preflight.py tools/build_payload.py
tools/patch_nvflash_kit.py tools/unlock_all.sh tools/nvflash_pty.py
tools/pcie_retrain_probe.py tools/hbm_mclk_switch.py tools/fecs_unlock_attempt.py
tools/trap20_stamp.py tools/trap_dump.py
tools/spi_rdid_l3.py tools/spi_status_l3.py tools/spi_write_ifr_l3.py tools/spi_flash_l3.py
tools/post_state_probe.py tools/inforom_walk.py tools/fwseclic_extract.py
tools/devinit_diff.py tools/ifr_parse.py tools/ifr_dump.py
tools/fuc_frames.py tools/falcon_cfg.py tools/falcon_disasm.py
tools/pcie_state_decode.py tools/hbm_cfg_stability.py
"
BENCH="tools/bench/build.sh tools/bench/gv100_pipes.cu tools/bench/gv100_memtest.cu tools/bench/gv100_validate.cu
       tools/bench/gv100_sweep.cu tools/bench/gpu_hold.cu"
# Reference artifacts: for HASH COMPARISON and for kit_selftest.  ⛔ NOT for flashing to another
# card -- they carry the reference card's InfoROM identity.
FIRMWARE="
firmware/gv100-RECOVERY-entire-2026-09-02.rom
firmware/gv100-UNLOCK4-entire-2026-09-06.rom
firmware/gv100-UNLOCK2-entire-2026-09-06.rom
firmware/gv100-nvprom.rom
firmware/gv100-UNLOCK4-entire-2026-09-06.README
firmware/gv100-UNLOCK2-entire-2026-09-06.README
"

[ "$NO_FIRMWARE" = 1 ] && FIRMWARE=""
# ⛔ This rm -rf takes a caller-supplied path.  Refuse to delete a git working tree: the
# published kit is staged in one, and "rebuild the release" must never mean "delete the
# repository and its history".
if [ -e "$OUT/.git" ]; then
  echo "⛔ $OUT contains a .git directory.  Refusing to rm -rf a git working tree."
  echo "   Stage to a different path, or update the checkout in place."
  exit 1
fi
rm -rf "$OUT"; mkdir -p "$OUT/tools/bench"
[ -n "$FIRMWARE" ] && mkdir -p "$OUT/firmware"
miss=0
for f in $DOCS $TOOLS $BENCH $FIRMWARE; do
  [ -f "$f" ] || { echo "MISSING from the tree: $f"; miss=1; continue; }
  install -Dm "$(stat -c%a "$f")" "$f" "$OUT/$f"
done
[ "$miss" = 0 ] || { echo "⛔ refusing to package an incomplete kit"; exit 1; }

# --- HARD GATE: no bench access details may leave this tree --------------------------------
# Patterns are deliberately broad.  A false positive costs one line of editing; a false negative
# publishes a BMC credential.
echo "== secret scan =="
PAT='(-P[[:space:]]+ADMIN|-U[[:space:]]+ADMIN|ipmitool|192\.168\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+|BEGIN [A-Z ]*PRIVATE KEY|ssh-rsa AAAA|password[[:space:]]*=)'
# ⚠ Exclude this script from its own scan: it *contains* the patterns, so it always self-matches.
# Nothing else is exempt.
hits=$(grep -rInE "$PAT" "$OUT" --exclude='*.rom' --exclude='make_release.sh' || true)
if [ -n "$hits" ]; then
  echo "$hits" | sed 's/^/  /'
  echo
  echo "⛔ REFUSING TO PACKAGE: the files above carry bench access details."
  echo "   Redact them or drop the file from the list in $(basename "$0"), then re-run."
  rm -rf "$OUT"
  exit 1
fi
echo "  clean -- no host IPs, ssh targets or BMC credentials in the staged files"

# --- manifest + checksums ------------------------------------------------------------------
( cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z \
    | xargs -0 sha256sum > SHA256SUMS )
n=$(wc -l < "$OUT/SHA256SUMS")
# ⚠ The MANIFEST must describe what was ACTUALLY packaged.  It used to assert that reference
# firmware images were present regardless, which is false for a NO_FIRMWARE build.
if [ -n "$FIRMWARE" ]; then
  FW_PARA='⛔ **The firmware images are reference artifacts for hash comparison, not something to
flash.** Each 1 MiB image contains the reference card'"'"'s InfoROM: serial number, UUID and board
part number. Build your own payload from your own card'"'"'s dump.'
else
  FW_PARA='No firmware images are included: each 1 MiB image carries its card'"'"'s InfoROM (serial
number, UUID, board part number), and a payload must be built from your own card'"'"'s dump anyway.
Use `tools/rom_compat.py` then `tools/build_payload.py`.'
fi

cat > "$OUT/MANIFEST.md" <<MSG
# CMP 100-210 unlock kit — $DATE

Start with **PORTING-2026-09-08-other-cards.md**. Run \`bash tools/kit_selftest.sh\` before
touching hardware.

$n files. Verify with:

    sha256sum -c SHA256SUMS

$FW_PARA

⚠ **Build the benchmarks first:** \`bash tools/bench/build.sh\`. The five \`.cu\` files are the
one part of this kit that has not been through \`nvcc\` in its current form — the authoring host
had no CUDA toolchain. Find any build error early, not mid-unlock.

⛔ **The flash chip is 1.8 V** (Winbond W25Q80EW, 1.65–1.95 V). A stock 3.3 V CH341A destroys it.
See the porting doc §2 before buying or clipping on a programmer.

This kit is packaged from a working tree that also contains bench-specific notes; those are
deliberately excluded, and \`tools/make_release.sh\` refuses to build if any access detail
survives into the package.
MSG

echo
echo "== packaged =="
echo "  $OUT"
echo "  $n files, $(du -sh "$OUT" | cut -f1)"
echo
echo "  next: bash $OUT/tools/kit_selftest.sh $OUT"
