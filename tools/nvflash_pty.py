#!/usr/bin/env python3
"""Drive an interactive nvflash command under a real controlling terminal.

⛔ WHY THIS IS REQUIRED, AND WHY THE OBVIOUS THINGS ALL FAIL.
`--wrhlk` / `--wrulf` prompt for confirmation, and nvflash reads the answer from
**`/dev/tty`** -- its own controlling terminal -- not from stdin (verified: fd 5 of a
blocked run is `/dev/tty`, and the read site is `0x541ADA`, `cmp $0x59,%eax` = 'Y').
So:

  * `nvflash ... < /dev/null`   -> "console read: Bad file descriptor",
                                   "ERROR: Reading from the keyboard failed", exit 2.
                                   ★ This is the June-2026 "the 170HX refuses InfoROM
                                   writes" result, reproduced on demand.
  * `printf 'y\\n' | nvflash`    -> stdin is a pipe; the tty read still finds nothing.
  * `printf 'y\\n' | script -qec ...` over ssh WITHOUT `-t` -> script logs
                                   "<not executed on terminal>" and nvflash blocks
                                   forever on the first prompt.
  * `ssh -tt` with the answers piped up front -> the characters arrive before nvflash
                                   opens /dev/tty and are flushed; it still blocks.

The answer has to be written to the pty **when the prompt appears**.  `pty.fork()` gives
the child a controlling terminal (it does setsid + TIOCSCTTY for us), and this driver
watches the output and replies on match.

⚠ Run it on the bench host, not here -- and never let an ssh timeout sever it; a killed
ssh leaves nvflash parked on the tty read.  Prefer `nohup ... &` plus a poll.

  nvflash_pty.py --log run.txt -- /root/nvflash --index=10 --wrhlk file.hulk
  nvflash_pty.py --log run.txt --expect "confirm" --send y --timeout 900 -- <cmd...>
"""
import argparse
import os
import pty
import re
import select
import sys
import time

DEFAULT_PROMPTS = (r"Press 'y' to confirm", r"\(y/n\)", r"confirm")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True, help="write the full transcript here")
    ap.add_argument("--send", default="y", help="answer to send on a prompt match")
    ap.add_argument("--expect", action="append", default=[],
                    help="extra prompt regex (defaults cover nvflash's own wording)")
    ap.add_argument("--timeout", type=float, default=900.0,
                    help="give up after this many seconds with no output")
    ap.add_argument("--max-answers", type=int, default=20,
                    help="refuse to answer more prompts than this (runaway guard)")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        sys.exit("no command given (put it after --)")

    pats = [re.compile(p) for p in (list(DEFAULT_PROMPTS) + a.expect)]
    pid, fd = pty.fork()
    if pid == 0:                                   # child: has the pty as its ctty
        os.execvp(cmd[0], cmd)
        os._exit(127)

    log = open(a.log, "wb")
    buf, answers, last = b"", 0, time.time()
    try:
        while True:
            if time.time() - last > a.timeout:
                print("\n[nvflash_pty] TIMEOUT after %.0fs with no output" % a.timeout)
                os.kill(pid, 15)
                break
            r, _, _ = select.select([fd], [], [], 1.0)
            if not r:
                continue
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            last = time.time()
            log.write(chunk)
            log.flush()
            sys.stdout.write(chunk.decode("utf-8", "replace"))
            sys.stdout.flush()
            buf += chunk
            tail = buf[-400:].decode("utf-8", "replace")
            if any(p.search(tail) for p in pats):
                if answers >= a.max_answers:
                    print("\n[nvflash_pty] refusing to answer more than %d prompts"
                          % a.max_answers)
                    os.kill(pid, 15)
                    break
                answers += 1
                print("\n[nvflash_pty] prompt #%d -> sending %r" % (answers, a.send))
                os.write(fd, (a.send + "\n").encode())
                buf = b""                          # do not re-match the same prompt
    finally:
        log.close()
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") \
        else (status >> 8)
    print("\n[nvflash_pty] exit=%s answers=%d log=%s" % (code, answers, a.log))
    return 0 if code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
