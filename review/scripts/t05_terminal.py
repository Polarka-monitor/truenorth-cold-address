#!/usr/bin/env python3
"""Review check T5: what a real terminal emulator still holds after the tool has finished.

The unmodified tool is run inside tmux and inside GNU screen (both keep a scrollback like a terminal window
does). The words are read from the screen while they are shown, typed back, and after the run the whole
screen plus scrollback is dumped and searched for the words. Throw-away dry-run phrases only; never printed.

usage: t05_terminal.py SRC BIN WORK
"""
import os
import re
import shutil
import subprocess
import sys
import time

SRC, BIN, WORK = sys.argv[1], sys.argv[2], sys.argv[3]


def sh(*cmd, **kw):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, **kw).stdout


class Tmux:
    def __init__(self, rows, cols, altoff=False):
        self.name = "tmux 3.4" + (" (alternate-screen off)" if altoff else "")
        self.altoff = altoff
        Tmux.count = getattr(Tmux, "count", 0) + 1
        self.sock = "review%d-%d" % (os.getpid(), Tmux.count)
        sh("tmux", "-L", self.sock, "-f", "/dev/null", "new-session", "-d", "-s", "cold", "-x", str(cols), "-y", str(rows),
           "env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "TERM=tmux-256color", "sh")
        sh("tmux", "-L", self.sock, "set-option", "-g", "history-limit", "5000")
        if self.altoff:
            sh("tmux", "-L", self.sock, "set-window-option", "-g", "alternate-screen", "off")
            sh("tmux", "-L", self.sock, "kill-session", "-t", "cold")
            sh("tmux", "-L", self.sock, "new-session", "-d", "-s", "cold", "-x", str(cols), "-y", str(rows),
               "env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "TERM=tmux-256color", "sh")

    def type(self, text):
        sh("tmux", "-L", self.sock, "send-keys", "-t", "cold", "-l", text)
        sh("tmux", "-L", self.sock, "send-keys", "-t", "cold", "Enter")

    def screen(self):
        return sh("tmux", "-L", self.sock, "capture-pane", "-p", "-t", "cold")

    def everything(self):
        normal = sh("tmux", "-L", self.sock, "capture-pane", "-p", "-J", "-S", "-", "-E", "-", "-t", "cold")
        alt = sh("tmux", "-L", self.sock, "capture-pane", "-p", "-a", "-q", "-t", "cold")
        return normal + "\n" + alt

    def close(self):
        sh("tmux", "-L", self.sock, "kill-server")
        time.sleep(0.5)


class Screen:
    def __init__(self, rows, cols, altscreen):
        self.name = "GNU screen 4.09 (altscreen %s%s)" % ("on" if altscreen else "off", "" if altscreen else ", its default")
        self.sess = "review%d" % os.getpid()
        self.rc = os.path.join(WORK, "screenrc")
        with open(self.rc, "w") as f:
            f.write("altscreen %s\ndefscrollback 5000\nstartup_message off\n" % ("on" if altscreen else "off"))
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "TERM": "xterm-256color", "HOME": WORK, "SCREENDIR": os.path.join(WORK, "scr")}
        os.makedirs(env["SCREENDIR"], mode=0o700, exist_ok=True)
        self.env = env
        subprocess.run(["screen", "-c", self.rc, "-dmS", self.sess, "sh"], env=env)
        time.sleep(1)
        sh("screen", "-S", self.sess, "-X", "width", "-w", str(cols), str(rows), env=env)

    def type(self, text):
        sh("screen", "-S", self.sess, "-p", "0", "-X", "stuff", text + "\r", env=self.env)

    def _hard(self, full):
        p = os.path.join(WORK, "hardcopy.txt")
        if os.path.exists(p):
            os.remove(p)
        args = ["screen", "-S", self.sess, "-p", "0", "-X", "hardcopy"] + (["-h"] if full else []) + [p]
        sh(*args, env=self.env)
        for _ in range(20):
            if os.path.exists(p):
                break
            time.sleep(0.1)
        try:
            data = open(p, errors="replace").read()
            os.remove(p)
            return data
        except OSError:
            return ""

    def screen(self):
        return self._hard(False)

    def everything(self):
        return self._hard(True)

    def close(self):
        sh("screen", "-S", self.sess, "-X", "quit", env=self.env)


def wait_for(term, pattern, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        s = term.screen()
        if re.search(pattern, s):
            return s
        time.sleep(0.3)
    raise AssertionError("did not see %r; screen:\n%s" % (pattern, term.screen()[-500:]))


def run(term, label, rows):
    kit = os.path.join(WORK, "kit-term")
    tmp = os.path.join(WORK, "tmp-term")
    for d in (kit, tmp):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    for name in ("cold-address.py", "tn-seed.py", "english.txt"):
        shutil.copy(os.path.join(SRC, name), kit)
    term.type("TN_BIN=%s TMPDIR=%s %s %s/cold-address.py --dry-run --chain regtest; echo finished-$?" % (BIN, tmp, sys.executable, kit))
    wait_for(term, r"Press Enter to show the 24 words")
    term.type("")
    s = wait_for(term, r"The words will disappear")
    found = dict((int(n), w) for n, w in re.findall(r"(\d{1,2})\. ([a-z]+)", s))
    visible = len(found)
    if sorted(found) != list(range(1, 25)):
        print("%-46s rows=%-3d only %d of 24 words are visible while they are shown (the screen is too small)"
              % (label, rows, visible))
        term.type("")
        time.sleep(0.5)
        subprocess.run(["true"])
        return None
    words = [found[i] for i in range(1, 25)]
    term.type("")
    for i, w in enumerate(words):
        wait_for(term, r"(?m)^\s*%2d: *$" % (i + 1))
        term.type(w)
    wait_for(term, r"finished-\d+", 180)
    time.sleep(0.5)
    dump = term.everything()
    code = re.search(r"finished-(\d+)", dump)
    shown = sum(1 for i, w in enumerate(words) if ("%2d. %s" % (i + 1, w)) in dump)
    typed = sum(1 for i, w in enumerate(words) if re.search(r"(?m)^\s*%2d: %s\s*$" % (i + 1, w), dump))
    runs = sum(1 for i in range(22) if re.search(r"\b%s\s+(?:\d+\.\s+)?%s\s+(?:\d+\.\s+)?%s\b" % tuple(words[i:i + 3]), dump))
    print("%-46s rows=%-3d exit %s; left in screen plus scrollback: %d of 24 words as shown, %d of 24 as typed, "
          "%d runs of 3 words; dump is %d lines"
          % (label, rows, code.group(1) if code else "?", shown, typed, runs, len(dump.splitlines())))
    return shown == 0 and typed == 0 and runs == 0


def real_refused(term, label):
    """A real run (no --dry-run) inside this terminal: what does the tool say?"""
    kit = os.path.join(WORK, "kit-term")
    term.type("clear; TN_BIN=%s TMPDIR=%s %s %s/cold-address.py; echo real-finished-$?" % (BIN, os.path.join(WORK, "tmp-term"), sys.executable, kit))
    s = wait_for(term, r"real-finished-\d+", 60)
    said = "refused: not a plain terminal window" if "not a plain terminal window" in s else (
        "refused: connected to a network" if "connected to a network" in s else "did not refuse for the terminal")
    print("%-46s a REAL run here is %s" % (label, said))


def main():
    os.makedirs(WORK, exist_ok=True)
    results = []
    for rows in (40, 24, 16):
        t = Tmux(rows, 100)
        try:
            results.append(run(t, t.name, rows))
        finally:
            t.close()
    for rows in (40, 24):
        t = Tmux(rows, 100, altoff=True)
        try:
            results.append(run(t, t.name, rows))
            if rows == 24:
                real_refused(t, t.name)
        finally:
            t.close()
    for alt in (False, True):
        for rows in (40, 24):
            t = Screen(rows, 100, alt)
            try:
                results.append(run(t, t.name, rows))
                if rows == 24:
                    real_refused(t, t.name)
            finally:
                t.close()
    print("RESULT", "OK" if all(r for r in results) else "CHECK")


if __name__ == "__main__":
    main()
