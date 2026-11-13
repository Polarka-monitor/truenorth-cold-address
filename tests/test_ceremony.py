#!/usr/bin/env python3
"""Tests for cold-address.py: the whole procedure is run through a pseudo-terminal, as a dry run.

  python3 tests/test_ceremony.py

Needs the official TrueNorth Core programs (see README): in ./bin, in an unpacked release folder next to
the script, or in the folder named by the TN_BIN environment variable.
"""
import glob
import os
import shutil
import stat
import subprocess
import sys
import tempfile

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
    return set(glob.glob(os.path.join(tempfile.gettempdir(), "tn-cold-*")))


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

check("no temporary node folder is left behind", leftovers() <= before, str(leftovers() - before))

print()
print("%d check(s) failed: %s" % (len(failed), "; ".join(failed)) if failed else "All checks passed.")
sys.exit(1 if failed else 0)
