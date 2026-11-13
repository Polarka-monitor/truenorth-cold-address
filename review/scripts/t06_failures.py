#!/usr/bin/env python3
"""Review check T6: what happens when a run is cut short.

For each case the unmodified tool is run through a pseudo-terminal (dry run on regtest) and interrupted at a
chosen moment. Reported: exit code, whether the alternate screen was wiped and left, whether the helper node is
still running, whether its temporary folder is still on disk, whether an output folder was written.
Throw-away dry-run phrases only; never printed.

usage: t06_failures.py SRC BIN WORK
"""
import importlib.util
import os
import re
import shutil
import signal
import subprocess
import sys
import time

SRC, BIN, WORK = sys.argv[1], sys.argv[2], sys.argv[3]
sys.argv = [sys.argv[0], SRC, BIN, WORK, "dry-regtest"]
spec = importlib.util.spec_from_file_location("t04", os.path.join(os.path.dirname(os.path.abspath(__file__)), "t04_trace.py"))
t04 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t04)
ALT_ON, ALT_OFF, WIPE = "\x1b[?1049h", "\x1b[?1049l", "\x1b[3J"


def node_pids(tmp):
    res = []
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                cmd = open("/proc/%s/cmdline" % pid, "rb").read().decode("utf-8", "replace")
            except OSError:
                continue
            if "truenorthd" in cmd and tmp in cmd:
                res.append(int(pid))
    return res


def case(label, stage, action):
    kit, tmp = os.path.join(WORK, "kit-fail"), os.path.join(WORK, "tmp-fail")
    for d in (kit, tmp):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    for name in ("cold-address.py", "tn-seed.py", "english.txt"):
        shutil.copy(os.path.join(SRC, name), kit)
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "TERM": "xterm-256color", "TN_BIN": BIN, "TMPDIR": tmp, "HOME": tmp}
    s = t04.Session([sys.executable, os.path.join(kit, "cold-address.py"), "--dry-run", "--chain", "regtest"], env)
    words = None
    s.expect(r"Press Enter to show the 24 words\. ")
    if stage != "before":
        s.send("")
        words = t04.grab_words(s.expect(r"The words will disappear from the screen\. "))
        if stage in ("typing", "after-typing-kill-node"):
            s.send("")
            upto = 10 if stage == "typing" else 23
            for i, w in enumerate(words[:upto]):
                s.expect(r"%2d: " % (i + 1))
                s.send(w)
            s.expect(r"%2d: " % (upto + 1))
    time.sleep(0.3)
    if action == "ctrl-c":
        os.write(s.fd, b"\x03")
    elif action == "ctrl-d":
        os.write(s.fd, b"\x04")
    elif action == "kill-node":
        for p in node_pids(tmp):
            os.kill(p, signal.SIGKILL)
        time.sleep(0.5)
        s.send(words[23])
    elif action == "close-window":
        os.close(s.fd)                 # the terminal goes away: the kernel sends SIGHUP
    else:
        os.kill(s.pid, getattr(signal, action))
    if action == "close-window":
        try:
            rc = os.waitstatus_to_exitcode(os.waitpid(s.pid, 0)[1])
        except ChildProcessError:
            rc = "?"
    else:
        rc = s.finish(timeout=90)
    time.sleep(1.0)
    raw = s.raw
    wiped = raw.rfind(ALT_OFF) > raw.rfind(ALT_ON) if ALT_ON in raw else None
    alive = node_pids(tmp)
    left = sorted(os.listdir(tmp))
    outdir = os.path.isdir(os.path.join(kit, "out-dry-run"))
    tail = t04.ANSI.sub("", raw)[-400:]
    last = [ln.strip() for ln in tail.splitlines() if ln.strip()]
    leak = False
    if words:
        after = t04.ANSI.sub("", raw[raw.rfind(ALT_OFF):]) if wiped else ""
        leak = any(("%2d. %s" % (i + 1, w)) in after for i, w in enumerate(words))
    print("%-58s exit %-4s alt screen %-22s node %-8s temp folder %-8s out folder %-3s"
          % (label, rc, {True: "wiped and left", False: "NOT LEFT (words stay)", None: "not used yet"}[wiped],
             "RUNNING" if alive else "stopped", "LEFT" if left else "removed", "yes" if outdir else "no"))
    print("      last line: %s%s" % (last[-1][:110] if last else "(none)", "   WORDS AFTER WIPE" if leak else ""))
    for p in alive:                                   # tidy up what this test itself left behind
        os.kill(p, signal.SIGTERM)
    time.sleep(1.5 if alive else 0)
    shutil.rmtree(tmp, ignore_errors=True)
    return not alive and not left and wiped is not False


def main():
    os.makedirs(WORK, exist_ok=True)
    res = [
        case("Ctrl+C at the prompt before the words", "before", "ctrl-c"),
        case("Ctrl+C while the words are shown", "shown", "ctrl-c"),
        case("Ctrl+C while typing the words back", "typing", "ctrl-c"),
        case("Ctrl+D (end of input) while the words are shown", "shown", "ctrl-d"),
        case("helper node killed just before the addresses are computed", "after-typing-kill-node", "kill-node"),
        case("SIGTERM (kill) while the words are shown", "shown", "SIGTERM"),
        case("SIGHUP while the words are shown", "shown", "SIGHUP"),
        case("terminal window closed while the words are shown", "shown", "close-window"),
        case("SIGQUIT (Ctrl+\\) while the words are shown", "shown", "SIGQUIT"),
    ]
    print("RESULT", "OK" if all(res) else "CHECK")


if __name__ == "__main__":
    main()
