#!/usr/bin/env python3
"""Disassemble a falcon image and AUDIT the result. Offline.

★ THE HAZARD THIS EXISTS TO CATCH IS THE IMAGE BASE, NOT THE DECODER.
A signed falcon application is [1024-byte plaintext NS bootloader][encrypted secure
body].  The secure body is loaded at IMEM VA **0x400**.  Disassemble the decrypted body
on its own and every VA is 0x400 too low: on FWSEC that puts **170 of 257 `lcall`
targets off an instruction boundary**, starting with the `lcall 0x414` issued by the
third instruction in the image, and every "function" address in the listing -- hence
every `in fn` attribution downstream -- is then fiction.  Feed this the whole
application image (`fwsec_decrypt.py -o`, which prepends the bootloader), not the body.

With the base right, envydis's plain linear sweep of these images is exact: 0 of 270
`lcall` targets and 1 of 1339 branch targets off-boundary on FWSEC, 0 and 0 on PreOS.
So the linear sweep is the listing; the audit is what tells you the base is right.

An application image is two separately-loaded sections -- the NS bootloader at VA 0 and
the secure body at VA 0x400 -- so the sweep is restarted at each `--split` address
(0x400 by default).  Without that, the bootloader's tail swallows the first instruction
of the body and its own `lcall 0x400` reads as off-boundary.

  falcon_disasm.py <app.bin> -o out.asm              sweep + audit (default)
  falcon_disasm.py <app.bin> -o out.asm --descent    also cross-check by recursive descent
  falcon_disasm.py <body.bin> -o out.asm --split ""  a bare body/imem with no bootloader

`--descent` follows control flow from the entry point, decoding one basic block at a
time, and reports whether it disagrees with the sweep anywhere.  It is the stronger
check but has lower coverage: it cannot follow an indirect `call $rN` off a dispatch
table, which is how PreOS is built.

⛔ Do NOT try to repair a misaligned sweep by re-anchoring it on branch targets.  That
was tried: a drifted region emits bogus `bra`/`lcall` instructions whose bogus targets
become anchors and then chop real instructions.  The symptom is an impossible length
table -- the same 4-byte `lcall 0x1048` encoding coming out as 1, 2 and 3 bytes at
different sites.  Fix the base instead.
"""
import argparse
import re
import subprocess

LINE = re.compile(r'^([0-9a-f]{8}):\s+((?:[0-9a-f]{2} )+)\s*([BC]?)\s+(\S+)(?:\s+(.*))?$')
ENVYDIS = "/root/170hx/tools/envytools/build/envydis/envydis"
TERM = ("ret", "exit", "bra", "lbra", "trap", "mpopret", "mpopaddret", "iret")
NOFALL = ("ret", "exit", "lbra", "trap", "mpopret", "mpopaddret", "iret")
BLOCK_WINDOW = 0x100


def sweep(envydis, path, variant, start=0, length=0):
    cmd = [envydis, "-m", "falcon", "-V", variant, "-F", "crypt", "-i", "-n",
           "-d", "%x" % start, "-b", "%x" % start]
    if length:
        cmd += ["-l", "%x" % length]
    cmd.append(path)
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    res = []
    for l in out.splitlines():
        m = LINE.match(l.rstrip())
        if m:
            res.append(dict(va=int(m.group(1), 16), nb=len(m.group(2).split()),
                            op=m.group(4), args=(m.group(5) or "").strip(),
                            text=l.rstrip()))
    return res


def flow_targets(ins):
    t = ins["args"].split()
    if ins["op"] in ("lcall", "call") and t and t[0].startswith("0x"):
        return {int(t[0], 16)}, set()
    if ins["op"] in ("bra", "lbra") and t and t[-1].startswith("0x"):
        return set(), {int(t[-1], 16)}
    return set(), set()


def audit(lines, size):
    addrs = {i["va"] for i in lines}
    calls, brs = set(), set()
    for i in lines:
        c, b = flow_targets(i)
        calls |= c
        brs |= b
    off_c = sorted(t for t in calls if t not in addrs and t < size)
    off_b = sorted(t for t in brs if t not in addrs and t < size)
    return calls, brs, off_c, off_b


def descend(envydis, path, variant, size, entry=0):
    code, todo = {}, [entry]
    while todo:
        a = todo.pop()
        if a in code or not (0 <= a < size):
            continue
        blk = sweep(envydis, path, variant, a, min(BLOCK_WINDOW, size - a))
        for ins in blk:
            if ins["va"] in code:
                break
            code[ins["va"]] = ins
            c, b = flow_targets(ins)
            for t in c | b:
                if t not in code and 0 <= t < size:
                    todo.append(t)
            if ins["op"] in TERM:
                if ins["op"] not in NOFALL:
                    n = ins["va"] + ins["nb"]
                    if n not in code and n < size:
                        todo.append(n)
                break
        else:
            n = a + sum(i["nb"] for i in blk)
            if n not in code and n < size:
                todo.append(n)
    return code


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--envydis", default=ENVYDIS)
    ap.add_argument("--variant", default="fuc5")
    ap.add_argument("--entry", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--descent", action="store_true")
    ap.add_argument("--split", default="0x400",
                    help="comma-separated VAs at which to restart the sweep "
                         "(section boundaries); \"\" for none")
    a = ap.parse_args()
    size = len(open(a.image, "rb").read())
    splits = sorted({0} | {int(x, 0) for x in a.split.split(",") if x.strip()}
                    - {x for x in [0] if False})
    splits = [x for x in splits if 0 <= x < size]
    lines = []
    for i, st in enumerate(splits):
        end = splits[i + 1] if i + 1 < len(splits) else size
        lines += [x for x in sweep(a.envydis, a.image, a.variant, st, end - st)
                  if x["va"] < end]
    calls, brs, off_c, off_b = audit(lines, size)
    open(a.out, "w").write("\n".join(i["text"] for i in lines) + "\n")
    print("wrote %s" % a.out)
    print("  instructions             %d over 0x%X bytes" % (len(lines), size))
    print("  lcall targets            %d, off an instruction boundary %d%s"
          % (len(calls), len(off_c),
             "" if not off_c else "   <<< " + " ".join("0x%X" % x for x in off_c[:6])))
    print("  branch targets           %d, off an instruction boundary %d"
          % (len(brs), len(off_b)))
    if calls and len(off_c) > max(2, 0.02 * len(calls)):
        print("  ⛔ THE BASE IS PROBABLY WRONG -- disassemble the whole application image")
        print("     (NS bootloader + decrypted body), not the body alone.")
    elif off_c:
        print("  (a handful off-boundary: check they are section boundaries, not drift)")
    if a.descent:
        code = descend(a.envydis, a.image, a.variant, size, a.entry)
        by = {i["va"]: i for i in lines}
        disagree = [v for v in code if v not in by or by[v]["nb"] != code[v]["nb"]]
        cov = sum(i["nb"] for i in code.values())
        print("  descent cross-check      %d instrs, 0x%X bytes (%.1f%%), disagrees with the "
              "sweep at %d" % (len(code), cov, 100.0 * cov / size, len(disagree)))


if __name__ == "__main__":
    main()
