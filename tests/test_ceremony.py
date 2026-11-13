#!/usr/bin/env python3
"""Tests for cold-address.py: the whole procedure is run through a pseudo-terminal, as a dry run.

  python3 tests/test_ceremony.py

Needs the official TrueNorth Core programs (see README): in ./bin, in an unpacked release folder next to
the script, or in the folder named by the TN_BIN environment variable.
"""
import glob
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

# Everything this test creates (copies of the tool, helper node folders) goes into one private folder, so that
# "nothing is left behind" can be checked exactly, whatever else runs on this computer.
PRIVATE_TMP = tempfile.mkdtemp(prefix="coldtest-")
os.environ["TMPDIR"] = tempfile.tempdir = PRIVATE_TMP

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ptydriver as pd   # noqa: E402

tool = pd.load_tool()
tn = tool.load_tnseed()
BIN = tool.find_bin()
failed = []


def check(name, ok, detail=""):
    print("%s  %s%s" % ("PASS" if ok else "FAIL", name, ("   [" + detail + "]") if detail and not ok else ""))
    if not ok:
        failed.append(name)


def first_address(words, chain):
    return tool.py_addresses(tn.bip39_seed(" ".join(words)), chain, 1)[0]


def leftovers():
    return set(glob.glob(os.path.join(PRIVATE_TMP, "tn-cold-*")))


def helper_nodes():
    """Helper nodes of this test that are still running (their data folder is inside the private folder)."""
    r = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True)
    return [ln.split()[0] for ln in r.stdout.splitlines() if "truenorthd" in ln and PRIVATE_TMP in ln]


def numbered_or_typed(words, text):
    """True if the text shows the words the way the tool prints them or the way a person types them in."""
    return any(("%2d. %s" % (i + 1, w)) in text or ("%2d: %s" % (i + 1, w)) in text for i, w in enumerate(words))


before = leftovers()

# 1. The normal path, on mainnet parameters and on regtest
for chain, prefix in (("main", "north1z"), ("regtest", "rnorth1z")):
    kit = pd.fresh_kit()
    rc, words, s = pd.new_ceremony(kit, BIN, chain)
    outdir = os.path.join(kit, "out-dry-run")
    saved = open(os.path.join(outdir, "cold-address.txt")).read().strip() if rc == 0 else ""
    check("%s: dry run finishes" % chain, rc == 0, "exit code %s" % rc)
    check("%s: saved address is the one the words give" % chain, saved == first_address(words, chain), saved)
    check("%s: address has the %s prefix and 5 addresses are listed" % (chain, prefix), saved.startswith(prefix)
          and len(open(os.path.join(outdir, "cold-addresses.txt")).read().split("\n")) == 6)
    check("%s: the info file is marked as a dry run" % chain,
          "DRY RUN" in open(os.path.join(outdir, "cold-info.txt")).read())
    modes = [stat.S_IMODE(os.stat(os.path.join(outdir, f)).st_mode) for f in os.listdir(outdir)]
    check("%s: output is private to the user (folder 700, files 600)" % chain,
          stat.S_IMODE(os.stat(outdir).st_mode) == 0o700 and set(modes) == {0o600})
    phrase_pairs = [words[i] + " " + words[i + 1] for i in range(23)]
    hits = []
    for dirpath, _, names in os.walk(kit):
        for n in names:
            data = open(os.path.join(dirpath, n), errors="replace").read()
            if n not in pd.FILES and any(p in data for p in phrase_pairs):
                hits.append(n)
    check("%s: no file contains the words" % chain, not hits, ",".join(hits))
    check("%s: the words appear only on the alternate screen" % chain,
          not numbered_or_typed(words, s.outside_alternate_screen()) and numbered_or_typed(words, pd.ANSI.sub("", s.raw)))
    check("%s: the screen is wiped and the scrollback cleared at the end" % chain,
          s.raw.rfind(pd.WIPE_SCROLLBACK) > s.raw.rfind(pd.ALT_OFF) > 0)

    # 2. verify: right words, two words swapped, a different valid phrase
    rc, s = pd.verify_ceremony(kit, BIN, words, chain)
    check("%s: verify accepts the right words" % chain, rc == 0 and "OK: the words on your paper" in s.buf, s.buf[-200:])
    swapped = words[:3] + [words[4], words[3]] + words[5:]
    rc, s = pd.verify_ceremony(kit, BIN, swapped, chain)
    check("%s: verify rejects swapped words" % chain, rc == 1 and "MISMATCH" in s.buf, s.buf[-200:])
    other = tn.to_mnemonic(bytes(range(32)), tn.wordlist()).split()
    rc, s = pd.verify_ceremony(kit, BIN, other, chain)
    check("%s: verify rejects a different valid phrase" % chain,
          rc == 1 and "different address" in s.buf and first_address(other, chain) in s.buf, s.buf[-300:])
    shutil.rmtree(kit)

# 3. Mistakes while typing the words back
kit = pd.fresh_kit()
rc, words, s = pd.new_ceremony(kit, BIN, "regtest", "typo")
check("typo: unknown word is asked again, wrong words are reported, second attempt succeeds",
      rc == 0 and "do not match: 7, 19" in pd.ANSI.sub("", s.raw), "exit code %s" % rc)
shutil.rmtree(kit)
kit = pd.fresh_kit()
rc, words, s = pd.new_ceremony(kit, BIN, "regtest", "fail3")
check("three failed attempts: stops and creates nothing",
      rc == 2 and "Nothing was created" in s.buf and not os.path.exists(os.path.join(kit, "out-dry-run")),
      "exit code %s" % rc)
shutil.rmtree(kit)

# 4. Dice
kit = pd.fresh_kit()
rolls = "".join("123456"[(i * 7 + 3) % 6] for i in range(99))
rc, words, s = pd.new_ceremony(kit, BIN, "regtest", "ok", dice=rolls)
check("dice: 99 rolls are accepted and stay off the normal screen",
      rc == 0 and rolls not in s.outside_alternate_screen() and rolls in pd.ANSI.sub("", s.raw), "exit code %s" % rc)
rc, _, s = pd.new_ceremony(kit, BIN, "regtest", "ok", dice=rolls[:98])
check("dice: 98 rolls are refused", rc == 2 and "expected at least 99 digits" in s.buf, "exit code %s" % rc)
rc, _, s = pd.new_ceremony(kit, BIN, "regtest", "ok", dice=rolls[:98] + "7")
check("dice: a digit outside 1 to 6 is refused", rc == 2 and "expected at least 99 digits" in s.buf, "exit code %s" % rc)
shutil.rmtree(kit)

# 5. Refusals
kit = pd.fresh_kit()
env = dict(os.environ, TN_BIN=BIN, TERM="xterm-256color")
r = subprocess.run([sys.executable, os.path.join(kit, "cold-address.py"), "--dry-run"], env=env,
                   stdin=subprocess.DEVNULL, capture_output=True, text=True)
check("refuses to run without a terminal", r.returncode == 2 and "directly in a terminal" in r.stdout)
s = pd.Session(kit, ["--chain", "regtest"], BIN)
rc = s.finish()
check("refuses another chain outside a dry run", rc == 2 and "only allowed together with --dry-run" in s.buf)
os.makedirs(os.path.join(kit, "out"))
open(os.path.join(kit, "out", "cold-address.txt"), "w").write("north1zexample\n")
s = pd.Session(kit, [], BIN)
rc = s.finish()
check("refuses to make a second address next to an existing one", rc == 2 and "already exists" in s.buf)
shutil.rmtree(os.path.join(kit, "out"))
online, _ = tool.net_status()
s = pd.Session(kit, [], BIN)
rc = s.finish()
if online:
    check("real run refuses while the computer is online", rc == 2 and "connected to a network" in s.buf, s.buf[-300:])
else:
    print("SKIP  real run refuses while the computer is online (this computer is offline)")
with open(os.path.join(kit, "tn-seed.py"), "a") as f:
    f.write("\n")
s = pd.Session(kit, ["--dry-run"], BIN)
rc = s.finish()
check("refuses a changed tn-seed.py", rc == 2 and "expected checksum" in s.buf)
shutil.rmtree(kit)
kit = pd.fresh_kit()
fake = os.path.join(kit, "bin")
os.makedirs(fake)
for name in ("truenorthd", "truenorth-cli"):
    shutil.copy(os.path.join(BIN, name), fake)
with open(os.path.join(fake, "truenorthd"), "ab") as f:
    f.write(b"\0")
s = pd.Session(kit, ["--dry-run"], fake)
rc = s.finish()
check("refuses a changed truenorthd", rc == 2 and "do not have the expected checksums" in s.buf)
shutil.rmtree(kit)

# 6. WSL is recognised (the real file is replaced by a fake one for this check)
if sys.platform.startswith("linux"):
    real_open = open

    def fake_open(path, *a, **kw):
        if path == "/proc/version":
            import io
            return io.StringIO("Linux version 5.15.153.1-microsoft-standard-WSL2 (gcc)")
        return real_open(path, *a, **kw)

    tool.__dict__["open"] = fake_open
    reasons, _ = tool.net_status()
    del tool.__dict__["open"]
    check("WSL is recognised as not checkable", any("WSL" in r for r in reasons))

# 7. Not a plain terminal window: a real run refuses, a dry run says so and goes on
kit = pd.fresh_kit()
for var, value, word in (("STY", "4242.pts-0.host", "GNU screen"), ("TMUX", "/tmp/tmux-0/default,1,0", "tmux"),
                         ("SSH_CONNECTION", "192.0.2.1 50000 192.0.2.2 22", "SSH"), ("SCRIPT", "typescript", "script")):
    s = pd.Session(kit, [], BIN, env={var: value})
    rc = s.finish()
    check("real run refuses when %s is set (%s)" % (var, word),
          rc == 2 and "not a plain terminal window" in s.buf and word in s.buf, s.buf[-300:])
s = pd.Session(kit, ["--dry-run"], BIN, env={"STY": "4242.pts-0.host"})
s.expect(r"A real run would stop or ask because of:")
s.expect(r"GNU screen")
s.expect(r"Press Enter to show the 24 words\. ")
s.key(b"\x03")
check("dry run inside screen says so and goes on", s.finish() == 130)
rc, words, s = pd.new_ceremony(kit, BIN, None)
saved = open(os.path.join(kit, "out-dry-run", "cold-address.txt")).read().strip() if rc == 0 else ""
check("a plain --dry-run makes a test-network address that cannot receive real coins",
      rc == 0 and saved.startswith("rnorth1z") and "cannot receive real coins" in s.buf, saved)
check("the recipe for the paper is printed and saved",
      rc == 0 and "m/88h/1h/0h/0/0" in s.buf
      and "recipe for the paper" in open(os.path.join(kit, "out-dry-run", "cold-info.txt")).read())
shutil.rmtree(kit)

# 8. An early end: the screen is wiped, the helper node stops, nothing is saved
for name, sig in (("SIGTERM (kill)", signal.SIGTERM), ("SIGHUP (terminal closed)", signal.SIGHUP),
                  ("SIGQUIT (Ctrl+\\)", signal.SIGQUIT)):
    kit = pd.fresh_kit()
    s, words = pd.until_words(kit, BIN)
    os.kill(s.pid, sig)
    rc = s.finish()
    check("%s while the words are shown: screen wiped, nothing saved" % name,
          rc == 128 + sig and s.wiped() and "Nothing was saved" in s.buf
          and not os.path.exists(os.path.join(kit, "out-dry-run")), "exit code %s" % rc)
    shutil.rmtree(kit)
kit = pd.fresh_kit()
s, words = pd.until_words(kit, BIN)
s.key(b"\x1a")                       # Ctrl+Z must not freeze the words on the screen
time.sleep(0.5)
s.send("")
s.expect(r" 1: ")
s.key(b"\x03")
rc = s.finish()
check("Ctrl+Z is ignored; Ctrl+C wipes the screen and saves nothing",
      rc == 130 and s.wiped() and "Nothing was saved" in s.buf, "exit code %s" % rc)
shutil.rmtree(kit)

# 9. The private key never leaves the tool: the helper node is only ever given public keys of the user's words
kit = pd.fresh_kit()
log = os.path.join(PRIVATE_TMP, "cli-stdin.log")
wrap = os.path.join(PRIVATE_TMP, "wrapbin")
os.makedirs(wrap)
shutil.copy(os.path.join(BIN, "truenorthd"), wrap)
shutil.copy(os.path.join(BIN, "truenorth-cli"), os.path.join(wrap, "truenorth-cli.real"))
tool2 = pd.load_tool(kit)
words2 = None
# A stand-in for truenorth-cli that records what the tool sends to it on stdin, then calls the real program.
with open(os.path.join(wrap, "truenorth-cli"), "w") as f:
    f.write("#!/bin/sh\nif [ \"$5\" = \"-stdin\" ]; then tee -a '%s' | '%s.real' \"$@\"; else exec '%s.real' \"$@\"; fi\n"
            % (log, os.path.join(wrap, "truenorth-cli"), os.path.join(wrap, "truenorth-cli")))
os.chmod(os.path.join(wrap, "truenorth-cli"), 0o755)
src = open(os.path.join(kit, "cold-address.py")).read()
key = "Linux-x86_64" if sys.platform.startswith("linux") else "Darwin-arm64"
old = tool2.EXPECT[key]["truenorth-cli"]
import hashlib   # noqa: E402
new = hashlib.sha256(open(os.path.join(wrap, "truenorth-cli"), "rb").read()).hexdigest()
with open(os.path.join(kit, "cold-address.py"), "w") as f:
    f.write(src.replace(old, new))               # the copy under test accepts the recording stand-in
rc, words2, s = pd.new_ceremony(kit, wrap, "regtest")
sent = open(log).read() if os.path.exists(log) else ""
descs = [ln for ln in sent.splitlines() if ln.startswith("qrh(")]
priv = [d for d in descs if "/88h/" in d]
mine = tn.descriptors(tn.master_xprv(tn.bip39_seed(" ".join(words2)), tn.CHAINS["regtest"][0]), 1)[0]["desc"] if words2 else ""
check("the node gets 5 descriptors: 2 public (test phrase, user) and 3 private (test and throw-away phrases)",
      rc == 0 and len(descs) == 5 and len(priv) == 3, "%d descriptors, %d private" % (len(descs), len(priv)))
check("the private descriptor of the user's words is never sent",
      rc == 0 and mine and mine not in sent and mine.split("/88h")[0] not in sent)
check("what is sent for the user's words is a public descriptor that gives the saved address",
      rc == 0 and tool2.public_descriptor(tn, tn.bip39_seed(" ".join(words2)), "regtest") in descs)
shutil.rmtree(kit)

# 10. tn-seed.py at a keyboard: what is typed is not shown
kit = pd.fresh_kit()
phrase = tn.to_mnemonic(bytes(range(32)), tn.wordlist())
t = pd.Session(kit, [], BIN, argv=[sys.executable, os.path.join(kit, "tn-seed.py"), "restore", "--chain", "regtest", "--json"])
t.expect(r"not shown as you type\): ")
t.send(phrase)
rc = t.finish()
lines = [ln for ln in t.buf.splitlines() if ln.strip()]
want = tn.descriptors(tn.master_xprv(tn.bip39_seed(phrase), tn.CHAINS["regtest"][0]), 1)
check("tn-seed.py restore --json: the typed words are not shown and only the descriptors are printed",
      rc == 0 and " ".join(phrase.split()[:3]) not in t.raw and len(lines) == 1
      and __import__("json").loads(lines[0]) == want, "exit code %s, %d lines" % (rc, len(lines)))
t = pd.Session(kit, [], BIN, argv=[sys.executable, os.path.join(kit, "tn-seed.py"), "new", "--chain", "regtest", "--dice"])
t.expect(r"not shown as you type\): ")
t.send(rolls)
rc = t.finish()
check("tn-seed.py new --dice: the rolls are asked for and not shown", rc == 0 and rolls not in t.raw and "RECOVERY WORDS" in t.buf)
shutil.rmtree(kit)

check("no helper node is left running", not helper_nodes(), ",".join(helper_nodes()))
check("no temporary node folder is left behind", leftovers() <= before, str(leftovers() - before))
shutil.rmtree(PRIVATE_TMP, ignore_errors=True)

print()
print("%d check(s) failed: %s" % (len(failed), "; ".join(failed)) if failed else "All checks passed.")
sys.exit(1 if failed else 0)
