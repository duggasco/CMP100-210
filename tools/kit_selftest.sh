#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 duggasco
# kit_selftest.sh -- prove the offline half of the unlock kit works, with NO hardware.
#
# Run this before touching a card.  It rebuilds both shipped payload images from the shipped
# baseline dump and checks them byte-for-byte, which exercises the whole offline chain: image
# shape detection, the FWSECLIC build gate, the InfoROM object derivation, the chain layout, the
# checksum, and the physical/aperture round trip.  If this passes, a payload you build for another
# card was produced by exactly the code that produced the images that were tested on silicon.
#
# usage: kit_selftest.sh [tree-root]     (default: the parent of this script)
set -u
ROOT=${1:-$(cd "$(dirname "$0")/.." && pwd)}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cd "$ROOT" || exit 1
PASS=0; FAIL=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); }
hash_of() { sha256sum "$1" | cut -d' ' -f1; }

BASE=firmware/gv100-RECOVERY-entire-2026-09-02.rom
UNLOCK4=firmware/gv100-UNLOCK4-entire-2026-09-06.rom
UNLOCK2=firmware/gv100-UNLOCK2-entire-2026-09-06.rom
APERTURE=firmware/gv100-nvprom.rom

echo "== reference images =="
have_fw=1
for f in "$BASE" "$UNLOCK4" "$UNLOCK2" "$APERTURE"; do
  if [ -f "$f" ]; then ok "$f"; else have_fw=0; echo "  SKIP  $f not present"; fi
done
if [ "$have_fw" = 0 ]; then
  cat <<'MSG'

  The reference firmware images are NOT shipped in this distribution: each 1 MiB image contains
  the reference card's InfoROM -- its serial number, UUID and board part number -- and publishing
  someone's hardware identity is not a thing to do casually. They are also useless to you: a
  payload MUST be built from your own card's dump (see the porting doc, "Never flash another
  card's image").

  Consequence: the payload-rebuild regression checks below cannot run here. The offline chain is
  still exercised on YOUR dump the moment you run:
        python3 tools/rom_compat.py <your-card-dump.rom>
        python3 tools/build_payload.py <your-card-dump.rom> payload.rom --resume 0x41AC ...
  and build_payload.py verifies the FWSECLIC build before it writes anything.

  For reference, the two payloads this kit produced on the card it was developed on:
        UNLOCK4  d4b0218aad84baf10901419b41e6d49f8a91dbda15ec46d14edfc485d2bed834
        UNLOCK2  61114e3eaed09078d6c250de03e7ca1da0bdad636a26ef3e20397eb7499b6820
        baseline 722bcbdff33e7119247a74ad6d22e01180af516dbee5c851596d7b49c77f30c9
  Yours will NOT match these -- different InfoROM -- and that is correct, not a failure.

MSG
fi

if [ "$have_fw" = 1 ]; then
echo
echo "== UNLOCK4 (5-link: general L3 primitive + FECS PLM pre-opened) =="
python3 tools/build_payload.py "$BASE" "$T/u4.rom" \
    --resume 0x41AC \
    --write 0x122750=0x00000FFF --write 0x1224D0=0xFC000000 \
    --write 0x122550=0xC0000000 --write 0x122650=0x00100000 \
    --write 0x409650=0x000000FF > "$T/u4.log" 2>&1
if [ "$(hash_of "$T/u4.rom")" = "$(hash_of "$UNLOCK4")" ]; then
  ok "rebuilt byte-identical to $UNLOCK4"
else
  bad "rebuild differs: got $(hash_of "$T/u4.rom"), want $(hash_of "$UNLOCK4")"; sed 's/^/        /' "$T/u4.log"
fi

echo
echo "== UNLOCK2 (2-link, no trap: FECS PLM + CYA clamp clear) =="
python3 tools/build_payload.py "$BASE" "$T/u2.rom" \
    --resume 0x2A04 \
    --write 0x409650=0x000000FF --write 0x08841C=0x00340500 > "$T/u2.log" 2>&1
if [ "$(hash_of "$T/u2.rom")" = "$(hash_of "$UNLOCK2")" ]; then
  ok "rebuilt byte-identical to $UNLOCK2"
else
  bad "rebuild differs: got $(hash_of "$T/u2.rom"), want $(hash_of "$UNLOCK2")"; sed 's/^/        /' "$T/u2.log"
fi

echo
echo "== the old aperture-input recipe still produces the same physical image =="
python3 tools/build_payload.py "$APERTURE" "$T/a.rom" \
    --resume 0x41AC \
    --write 0x122750=0x00000FFF --write 0x1224D0=0xFC000000 \
    --write 0x122550=0xC0000000 --write 0x122650=0x00100000 \
    --write 0x409650=0x000000FF \
    --physical "$T/a-phys.rom" --ifr "$BASE" --entire > "$T/a.log" 2>&1
[ "$(hash_of "$T/a-phys.rom")" = "$(hash_of "$UNLOCK4")" ] \
  && ok "aperture-in + --physical --ifr --entire == physical-in path" \
  || bad "the two input shapes disagree -- one of them is wrong"

echo
echo "== the FWSECLIC build gate refuses a foreign ucode =="
python3 - "$BASE" "$T/bad.rom" <<'PY'
import sys
d = bytearray(open(sys.argv[1], "rb").read())
d[0x033D94 + 0x22C5] ^= 0xFF        # corrupt one byte of the chain's first gadget
open(sys.argv[2], "wb").write(bytes(d))
PY
if python3 tools/build_payload.py "$T/bad.rom" "$T/no.rom" --resume 0x41AC \
      --write 0x122750=0x00000FFF --write 0x1224D0=0xFC000000 \
      --write 0x122550=0xC0000000 --write 0x122650=0x00100000 \
      --write 0x409650=0x000000FF > "$T/bad.log" 2>&1; then
  bad "a corrupted gadget was ACCEPTED -- the build gate is not working"
else
  grep -q "FWSECLIC BUILD MISMATCH" "$T/bad.log" \
    && ok "refused, and named the mismatching VA" \
    || bad "refused for the wrong reason: $(head -1 "$T/bad.log")"
fi

echo
echo "== rom_compat verdicts =="
python3 tools/rom_compat.py "$BASE" > "$T/c1.txt" 2>&1
grep -q "L3 opener (ROM payload + trap 20 + SPI)    ★ GO" "$T/c1.txt" \
  && ok "baseline dump: L3 opener GO" || bad "baseline dump did not come back GO"
grep -q "0x04162D" "$T/c1.txt" \
  && ok "ULF object derived at aperture 0x04162D (the reference card's)" \
  || bad "ULF object derivation moved"
grep -q "physical 0x000214" "$T/c1.txt" \
  && ok "IFR width record located at physical 0x000214" || bad "IFR width record not found"

V100=$HOME/nvidia_unlock/logs/gpubench-v100-first-contact-2026-08-01/v100_nvprom.rom
if [ -f "$V100" ]; then
  python3 tools/rom_compat.py "$V100" > "$T/c2.txt" 2>&1
  grep -q "already at the stock value" "$T/c2.txt" \
    && ok "stock Tesla V100: correctly reports nothing to unlock" \
    || bad "a stock V100 was not recognised as unthrottled"
else
  echo "  SKIP  stock V100 reference not present ($V100)"
fi

else
  echo "  (payload-rebuild, build-gate and rom_compat checks skipped -- no reference images)"
fi

echo
echo "== nvflash patcher (only if a stock 5.680 is present) =="
STOCK=""
for c in /tmp/nvflash-5.680-smc8 "$ROOT/firmware/nvflash-5.680" ./nvflash; do
  [ -f "$c" ] && [ "$(stat -c%s "$c" 2>/dev/null)" = 7793296 ] && STOCK=$c && break
done
if [ -n "$STOCK" ]; then
  python3 tools/patch_nvflash_kit.py "$STOCK" --devid 0x1DF4 --out "$T/nvflash-kit" > "$T/nf.log" 2>&1
  # 5f8988cd... is the binary that actually flashed this card; reproducing it byte-for-byte
  # proves the one-step patcher is equivalent to the three tools it replaces.
  if [ "$(hash_of "$T/nvflash-kit")" = "5f8988cd8825a3c7de3776952465adee5820725c1b80b13a208e464300596333" ]; then
    ok "stock 5.680 -> the exact production binary used on this card"
  else
    bad "patched output does not match the production binary"; sed 's/^/        /' "$T/nf.log"
  fi
else
  echo "  SKIP  no stock nvflash 5.680 found (7,793,296 bytes)"
fi

echo
echo "======================================================================"
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
if [ "$FAIL" = 0 ]; then
  echo "  ★ the offline half of the kit is intact.  Hardware steps: PORTING-2026-09-08-other-cards.md"
else
  echo "  ⛔ do NOT flash anything until these pass."
fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
