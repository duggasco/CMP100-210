# CMP 100-210 unlock kit — 2026-09-08

Start with **PORTING-2026-09-08-other-cards.md**. Run `bash tools/kit_selftest.sh` before
touching hardware.

37 files. Verify with:

    sha256sum -c SHA256SUMS

⛔ **The firmware images are reference artifacts for hash comparison, not something to flash.**
Each 1 MiB image contains the reference card's InfoROM: serial number, UUID and board part
number. Build your own payload from your own card's dump — `tools/rom_compat.py` then
`tools/build_payload.py`, both documented in the porting doc.

⚠ **Build the benchmarks first:** `bash tools/bench/build.sh`. The five `.cu` files are the
one part of this kit that has not been through `nvcc` in its current form — the authoring host
had no CUDA toolchain. Find any build error early, not mid-unlock.

⛔ **The flash chip is 1.8 V** (Winbond W25Q80EW, 1.65–1.95 V). A stock 3.3 V CH341A destroys it.
See the porting doc §2 before buying or clipping on a programmer.

This kit is packaged from a working tree that also contains bench-specific notes; those are
deliberately excluded, and `tools/make_release.sh` refuses to build if any access detail
survives into the package.
