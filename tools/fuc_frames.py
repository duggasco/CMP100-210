#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 duggasco
"""Falcon frame-size and call-depth calculator for envydis fuc5 listings.

⛔ **MEASURED WRONG ON SILICON (pass 46): `mpush $rK` pushes K+1 registers
(r0..rK), not K.** The docstring formula below under-counts by one register
per `mpush` — for the FWSECLIC chain this made every computed frame ~0x7C too
low and cost passes 40-44 of flat sweeps. The observed true geometry
(`0x607E` ret at `0x9ED8`, `0x61D4` canary/ret `0x9EF8`/`0x9EFC`,
`0x62FE` `0x9F24`/`0x9F28`) is the calibration; use it over this tool's chain
output until the push count is fixed.

Frame size of a function = the `add $sp -N` in its prologue plus the bytes an
`mpush $rK` pushes (r0..rK, 4 bytes each), plus the 4-byte return address the
`lcall` itself pushes. Used to turn a call chain into an absolute `$sp` and so
locate live return addresses in DMEM.

  fuc_frames.py <listing.asm> sizes <va> [<va> ...]   frame size of each function
  fuc_frames.py <listing.asm> callers <va>            who calls this function
  fuc_frames.py <listing.asm> chain <sp0> <va> ...    walk a chain, print $sp
"""
import re
import sys

LINE = re.compile(r'^([0-9a-f]{8}):\s+((?:[0-9a-f]{2} )+)\s*([BC]?)\s+(\S+)(?:\s+(.*))?$')


def parse(path):
    out = []
    for line in open(path):
        m = LINE.match(line.rstrip('\n'))
        if m:
            va, _, flag, op, args = m.groups()
            out.append((int(va, 16), flag, op, (args or '').strip()))
    return out


def frame(insns, va, window=14):
    """(locals, pushed, total) for the function starting at va.

    Only the prologue counts: scanning stops at the first branch target after the
    entry instruction, or after `window` instructions, so a later `add $sp -N`
    inside the body is not mistaken for frame setup."""
    loc = push = 0
    n = 0
    for a, flag, op, args in insns:
        if a < va:
            continue
        if n and flag:        # reached another branch target: prologue is over
            break
        if op == 'add' and args.startswith('$sp '):
            v = int(args.split()[1], 0)
            if v < 0:
                loc += -v
        elif op == 'mpush':
            push += (int(args.lstrip('$r')) + 1) * 4
        n += 1
        if n > window:
            break
    return loc, push, loc + push


def callers(insns, target):
    out = []
    starts = sorted({int(a, 16) for _, _, op, a in insns
                     if op == 'lcall' and a.startswith('0x')})
    cur = None
    for a, flag, op, args in insns:
        if a in starts:
            cur = a
        if op == 'lcall' and args.startswith('0x') and int(args, 16) == target:
            out.append((cur, a))
    return out


def main():
    insns = parse(sys.argv[1])
    mode = sys.argv[2]
    if mode == 'sizes':
        for s in sys.argv[3:]:
            va = int(s, 0)
            loc, push, tot = frame(insns, va)
            print('0x%04x  locals=0x%-4x mpush=0x%-4x frame=0x%-4x '
                  '(+4 ret) => 0x%x' % (va, loc, push, tot, tot + 4))
    elif mode == 'callers':
        for fn, site in callers(insns, int(sys.argv[3], 0)):
            print('called from fn 0x%04x at 0x%04x'
                  % (fn if fn is not None else 0, site))
    elif mode == 'chain':
        sp = int(sys.argv[3], 0)
        print('$sp at entry                = 0x%04x' % sp)
        for s in sys.argv[4:]:
            va = int(s, 0)
            loc, push, tot = frame(insns, va)
            sp -= 4                      # lcall pushes the return address
            print('  lcall 0x%04x -> ret addr stored at 0x%04x' % (va, sp))
            sp -= tot
            print('    frame 0x%-4x (locals 0x%x + mpush 0x%x) -> $sp = 0x%04x'
                  % (tot, loc, push, sp))
        print('$sp inside innermost fn    = 0x%04x' % sp)
    else:
        sys.exit('unknown mode')


if __name__ == '__main__':
    main()
