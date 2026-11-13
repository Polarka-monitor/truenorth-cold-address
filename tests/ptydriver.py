"""Drive cold-address.py through a pseudo-terminal, the way a person at a keyboard would.

Used by the tests. Everything here runs the tool with --dry-run, so no real secrets are involved.
"""
import importlib.util
import os
import pty
import re
import select
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = ("cold-address.py", "tn-seed.py", "english.txt")
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
ALT_ON, ALT_OFF, WIPE_SCROLLBACK = "\x1b[?1049h", "\x1b[?1049l", "\x1b[3J"


def load_tool(folder=ROOT):
    """Import cold-address.py as a module (its file name has a dash, so a plain import does not work)."""
    spec = importlib.util.spec_from_file_location("coldaddress", os.path.join(folder, "cold-address.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def fresh_kit():
    """A temporary copy of the three files a user needs, so that test output never lands in the repository."""
    kit = tempfile.mkdtemp(prefix="coldkit-test-")
    for name in FILES:
        shutil.copy(os.path.join(ROOT, name), kit)
    return kit


class Session:
    def __init__(self, kit, args, bindir):
        self.buf, self.raw = "", ""
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.environ["TERM"] = "xterm-256color"
            os.environ["TN_BIN"] = bindir
            os.execvp(sys.executable, [sys.executable, os.path.join(kit, "cold-address.py")] + list(args))

    def _read(self):
        try:
            data = os.read(self.fd, 65536).decode("utf-8", "replace")
        except OSError:
            data = ""
        self.raw += data
        self.buf += ANSI.sub("", data)
        return data

    def expect(self, pattern, timeout=180):
        end = time.time() + timeout
        while time.time() < end:
            m = re.search(pattern, self.buf)
            if m:
                seen, self.buf = self.buf[:m.end()], self.buf[m.end():]
                return seen
            if select.select([self.fd], [], [], 0.5)[0] and not self._read():
                break
        raise AssertionError("did not see %r; the screen ended with:\n%s" % (pattern, self.buf[-600:]))

    def send(self, line):
        os.write(self.fd, (line + "\n").encode())

    def finish(self, timeout=180):
        end = time.time() + timeout
        while time.time() < end:
            if select.select([self.fd], [], [], 0.5)[0]:
                if not self._read():
                    break
            else:
                done, status = os.waitpid(self.pid, os.WNOHANG)
                if done:
                    return os.waitstatus_to_exitcode(status)
        return os.waitstatus_to_exitcode(os.waitpid(self.pid, 0)[1])

    def outside_alternate_screen(self):
        """Everything the terminal received while the normal screen (the one with a scrollback) was active."""
        text, pos, inside = "", 0, False
        while True:
            nxt = self.raw.find(ALT_OFF if inside else ALT_ON, pos)
            if nxt < 0:
                if not inside:
                    text += self.raw[pos:]
                return ANSI.sub("", text)
            if not inside:
                text += self.raw[pos:nxt]
            pos, inside = nxt + len(ALT_ON), not inside


def grab_words(screen):
    found = dict((int(n), w) for n, w in re.findall(r"(\d{1,2})\. ([a-z]+)", screen))
    assert sorted(found) == list(range(1, 25)), found
    return [found[i] for i in range(1, 25)]


def new_ceremony(kit, bindir, chain="main", mode="ok", dice=None):
    """Run 'new' as a dry run. mode: ok | typo | fail3. Returns (exit code, words, session)."""
    args = ["--dry-run", "--chain", chain] + (["--dice"] if dice is not None else [])
    s = Session(kit, args, bindir)
    words = None
    if dice is not None:
        s.expect(r"Rolls: ")
        s.send(dice)
        if len(dice) < 99 or set(dice) - set("123456"):
            return s.finish(), None, s
    s.expect(r"Press Enter to show the 24 words\. ")
    s.send("")
    rounds = {"ok": 1, "typo": 2, "fail3": 3}[mode]
    for rnd in range(rounds):
        words = grab_words(s.expect(r"The words will disappear from the screen\. "))
        s.send("")
        mistakes = False
        for i, w in enumerate(words):
            s.expect(r"%2d: " % (i + 1))
            if mode != "ok" and rnd == 0 and i == 2:
                s.send("notaword")                          # not in the list: the tool must ask again
                s.expect(r"not in the word list")
                s.expect(r" 3: ")
            wrong = (mode == "typo" and rnd == 0 and i in (6, 18)) or (mode == "fail3" and i == 0)
            mistakes = mistakes or wrong
            s.send(("zone" if w == "zoo" else "zoo") if wrong else w)
        if mistakes:
            s.expect(r"do not match: [0-9, ]+")
            if rnd < 2:
                s.expect(r"type them once more\. ")
                s.send("")
    return s.finish(), words, s


def verify_ceremony(kit, bindir, words, chain="main"):
    """Run 'verify' as a dry run with the given words. Returns (exit code, session)."""
    s = Session(kit, ["verify", "--dry-run", "--chain", chain], bindir)
    s.expect(r"Press Enter\. ")
    s.send("")
    for i, w in enumerate(words):
        s.expect(r"%2d: " % (i + 1))
        s.send(w)
    return s.finish(), s
