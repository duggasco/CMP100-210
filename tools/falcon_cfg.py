#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright 2026 duggasco
"""Call graph, function extents and callers/callees over a recursive-descent listing.

Offline.  Input is the output of `falcon_disasm.py` -- a listing whose audit reported
0 overlapping decodes and 0 undecoded targets.  Running this on a plain envydis linear
sweep gives confident nonsense, because in a drifted sweep most call targets are not
functions at all.

A function's body is taken as the flow closure from its entry: follow fall-through and
`bra`/`lbra` targets, stop at `ret`/`exit`/`mpopret`, and do NOT follow `lcall` (that is
a different function).  This is exact where the flow is, rather than the
"entry..next-entry" approximation, which mis-attributes any out-of-line block.

  falcon_cfg.py <rd.asm> fn 0x5aff          print the function
  falcon_cfg.py <rd.asm> callers 0x5aff     who calls it (and from which function)
  falcon_cfg.py <rd.asm> callees 0x5aff     what it calls
  falcon_cfg.py <rd.asm> paths 0x5aff       call paths from the entry point down to it
  falcon_cfg.py <rd.asm> owner 0x5c78       which function contains an address
  falcon_cfg.py <rd.asm> consts 0x5aff      immediates that look like PRI addresses
"""
import re
import sys
import collections

LINE = re.compile(r'^([0-9a-f]{8}):\s+((?:[0-9a-f]{2} )+)\s*([BC]?)\s+(\S+)(?:\s+(.*))?$')
TERM_NOFALL = ("ret", "exit", "lbra", "trap", "mpopret", "mpopaddret", "iret")


def load(path):
    code = {}
    for l in open(path):
        m = LINE.match(l.rstrip())
        if m:
            code[int(m.group(1), 16)] = dict(
                va=int(m.group(1), 16), nb=len(m.group(2).split()),
                op=m.group(4), args=(m.group(5) or "").strip(), text=l.rstrip())
    return code


def tgt(ins, kinds):
    t = ins["args"].split()
    if ins["op"] in kinds and t:
        w = t[0] if ins["op"] in ("lcall", "call") else t[-1]
        if w.startswith("0x"):
            return int(w, 16)
    return None


def body(code, entry):
    seen, todo = set(), [entry]
    while todo:
        a = todo.pop()
        while a in code and a not in seen:
            seen.add(a)
            ins = code[a]
            b = tgt(ins, ("bra", "lbra"))
            if b is not None and b not in seen:
                todo.append(b)
            if ins["op"] in TERM_NOFALL:
                break
            a += ins["nb"]
    return sorted(seen)


def entries(code):
    return sorted({tgt(i, ("lcall", "call")) for i in code.values()
                   if tgt(i, ("lcall", "call")) is not None})


def owner_map(code):
    """address -> the entry whose flow closure contains it (smallest body wins)."""
    own = {}
    for e in entries(code):
        b = body(code, e)
        for a in b:
            if a not in own or len(b) < own[a][1]:
                own[a] = (e, len(b))
    return {a: v[0] for a, v in own.items()}


def edges(code):
    own = owner_map(code)
    out = collections.defaultdict(set)
    ins_of = collections.defaultdict(set)
    for a, i in code.items():
        c = tgt(i, ("lcall", "call"))
        if c is not None:
            f = own.get(a, 0)
            out[f].add(c)
            ins_of[c].add((f, a))
    return out, ins_of, own


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    path, cmd = sys.argv[1], sys.argv[2]
    arg = int(sys.argv[3], 16) if len(sys.argv) > 3 else None
    code = load(path)
    if cmd == "fn":
        for a in body(code, arg):
            print(code[a]["text"])
    elif cmd == "owner":
        print("0x%04X" % owner_map(code).get(arg, 0))
    elif cmd == "callers":
        _, ins_of, _ = edges(code)
        for f, a in sorted(ins_of.get(arg, ())):
            print("0x%04X  called from 0x%04X (fn 0x%04X)" % (arg, a, f))
    elif cmd == "callees":
        out, _, own = edges(code)
        for c in sorted(out.get(arg, ())):
            print("0x%04X" % c)
    elif cmd == "paths":
        out, ins_of, _ = edges(code)
        rev = collections.defaultdict(set)
        for f, cs in out.items():
            for c in cs:
                rev[c].add(f)
        seen, res, todo = set(), [], [(arg, (arg,))]
        while todo:
            n, p = todo.pop()
            if not rev.get(n):
                res.append(p)
                continue
            for q in rev[n]:
                if q in p or (q, n) in seen:
                    continue
                seen.add((q, n))
                todo.append((q, (q,) + p))
        for p in res[:40]:
            print(" -> ".join("0x%04X" % x for x in p))
        print("(%d root path(s))" % len(res))
    elif cmd == "consts":
        for a in body(code, arg):
            for m in re.finditer(r"0x([0-9a-f]{5,8})\b", code[a]["args"]):
                v = int(m.group(1), 16)
                if 0x1000 <= v <= 0x2000000:
                    print("0x%04X  %-8s %s" % (a, code[a]["op"], code[a]["args"]))
                    break
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
