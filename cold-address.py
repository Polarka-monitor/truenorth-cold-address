#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cold-address: create a TrueNorth (NORTH) cold address once, on a computer that is offline.

Usage (in a terminal, in the folder that holds this script):

  python3 cold-address.py              make 24 recovery words and the first addresses that belong to them
  python3 cold-address.py verify       check that the words on your paper give the saved address
  python3 cold-address.py --dry-run    rehearsal: throw-away words, the network may stay on

Principles:
  * secrets (words, keys) exist only in memory; nothing secret is ever written to disk
  * only public data (addresses) is written, to the out/ folder
  * every address is computed twice, independently: by the Python code below and by TrueNorth Core
  * Python standard library only, so that the whole script can be read and checked
"""
import argparse
import glob
import hashlib
import hmac
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import types

VERSION = "1.1 (2026-11-13)"
RELEASE = "v30.5.4"
ISSUES = "https://github.com/severka-monitor/truenorth-cold-address/issues"
REPORT = "Do not use anything from this run. Please report it (never include your words): " + ISSUES
DIR = os.path.dirname(os.path.abspath(__file__))

# SHA-256 of the files this script relies on. The binaries are the ones inside the official v30.5.4 release
# archives (the archive checksums were checked against the signed SHA256SUMS before unpacking, see README).
EXPECT = {
    "tn-seed.py": "b8f1ea5a863118cf4881d0e9076f428bad1c3e165bd12606a450858657212259",
    "english.txt": "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
    "Darwin-arm64": {
        "truenorthd": "ab90e2cb6f513510d6df482c3f4da28f55dc7782fa51f503b6765ed2e89f5ced",
        "truenorth-cli": "f40ceb7dc88ef73db88b88bfa186f93da96e41e40ab5a742e97d02dd4a1f7b32",
    },
    "Linux-x86_64": {
        "truenorthd": "3b06c5d55566690e3158c581b89e9fac5f6f6ee7a3b320012111c7db248b3589",
        "truenorth-cli": "2c46f09a18eb20cf40dd6f9ebac31d4654d1ba25e2296b2c534d9bba018dfd5d",
    },
}

# chain -> (bech32 prefix, SLIP-44 coin type used in the derivation path)
CHAINS = {"main": ("north", 1867), "regtest": ("rnorth", 1)}

# Known-answer test: the public BIP39 test phrase must give these first addresses (m/88h/COINh/0h/0/0).
KAT_WORDS = "abandon " * 11 + "about"
KAT = {
    "main": "north1zju65aymm3nsz3uhpxcv0x7vrsw2x3pq4ehdne9a682j3fzd5s2vsenx7fx",
    "regtest": "rnorth1zfgvaxg6parqfv2drvsk9zadefh40zg97ese44hjkjzkjamkftpzsnpx4h6",
}

NWORDS = 24
NADDR = 5

_saved = []        # output folders written in this run (public data only)


# ---------------------------------------------------------------- terminal

def out(s=""):
    sys.stdout.write(s + "\n")
    sys.stdout.flush()


def alt_on():      # alternate screen: nothing shown there reaches the scrollback
    sys.stdout.write("\033[?1049h\033[2J\033[H")
    sys.stdout.flush()


def alt_clear():
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def alt_off():     # wipe the alternate screen, leave it, and clear the scrollback for good measure
    sys.stdout.write("\033[2J\033[H\033[?1049l\033[3J")
    sys.stdout.flush()


class Stop(Exception):
    pass


def ask(prompt):
    try:
        return input(prompt)
    except EOFError:
        raise Stop("The input ended.")


# ---------------------------------------------------------------- files

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_tnseed():
    """Check tn-seed.py and english.txt, then load tn-seed.py from the very bytes that were checked."""
    for name in ("tn-seed.py", "english.txt"):
        path = os.path.join(DIR, name)
        if not os.path.isfile(path):
            raise Stop("The file %s is missing next to the script." % name)
        if sha256_file(path) != EXPECT[name]:
            raise Stop("The file %s does not have the expected checksum. Do not continue." % name)
    path = os.path.join(DIR, "tn-seed.py")
    data = open(path, "rb").read()
    if hashlib.sha256(data).hexdigest() != EXPECT["tn-seed.py"]:
        raise Stop("The file tn-seed.py changed during the check. Do not continue.")
    mod = types.ModuleType("tnseed")
    mod.__file__ = path
    exec(compile(data, path, "exec"), mod.__dict__)
    return mod


def find_bin():
    key = platform.system() + "-" + platform.machine()
    if key not in EXPECT:
        raise Stop("This version knows no verified TrueNorth programs for this computer (%s).\n"
                   "Supported: macOS on Apple silicon and Linux on x86_64." % key)
    cands = []
    if os.environ.get("TN_BIN"):
        cands.append(os.environ["TN_BIN"])
    cands.append(os.path.join(DIR, "bin"))
    cands += sorted(glob.glob(os.path.join(DIR, "truenorth-*", "bin")))
    seen = False
    for c in cands:
        d, cli = os.path.join(c, "truenorthd"), os.path.join(c, "truenorth-cli")
        if os.path.isfile(d) and os.path.isfile(cli):
            seen = True
            if sha256_file(d) == EXPECT[key]["truenorthd"] and sha256_file(cli) == EXPECT[key]["truenorth-cli"]:
                return c
    if seen:
        raise Stop("The TrueNorth programs do not have the expected checksums. Do not continue.\n"
                   "This version expects the official %s release. If the project has published a newer "
                   "release,\nyou can still use %s here: deriving an address does not depend on the node "
                   "version." % (RELEASE, RELEASE))
    raise Stop("Cannot find truenorthd and truenorth-cli. Unpack the official %s release archive next to "
               "the script,\nor put the two programs into a folder named bin next to the script." % RELEASE)


# ---------------------------------------------------------------- network

def _run(cmd):
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
        return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else None
    except Exception:
        return None


IGNORE_IF = ("lo", "utun", "awdl", "llw", "gif", "stf", "anpi", "bridge", "ap", "vmenet", "vmnet", "pktap")
TUNNEL_IF = ("lo", "utun", "ipsec", "gif", "stf")


def net_status():
    """Return (reasons, hints). reasons: why the machine counts as online. hints: things worth a look."""
    reasons, hints = [], []
    sysname = platform.system()
    if sysname == "Darwin":
        for fam, label in (("inet", "IPv4"), ("inet6", "IPv6")):
            txt = _run(["/usr/sbin/netstat", "-rn", "-f", fam])
            if txt is None:
                reasons.append("cannot read the routing table (%s)" % label)
                continue
            for line in txt.splitlines():
                f = line.split()
                if len(f) >= 4 and f[0] in ("default", "0/1", "128.0/1", "::/1", "8000::/1"):
                    nif = f[3]
                    if nif.startswith(TUNNEL_IF):
                        continue      # a tunnel carries nothing without a physical link; macOS keeps such routes
                    reasons.append("default %s route through %s" % (label, nif))
        hp = _run(["/usr/sbin/networksetup", "-listallhardwareports"])
        if hp is None:
            reasons.append("cannot read the Wi-Fi state")
        else:
            port = None
            for line in hp.splitlines():
                if line.startswith("Hardware Port:"):
                    port = line.split(":", 1)[1].strip()
                elif line.startswith("Device:") and port in ("Wi-Fi", "AirPort"):
                    dev = line.split(":", 1)[1].strip()
                    p = _run(["/usr/sbin/networksetup", "-getairportpower", dev])
                    if p is None or not p.strip().endswith("Off"):
                        reasons.append("Wi-Fi is on (%s)" % dev)
        ifc = _run(["/sbin/ifconfig", "-a"]) or ""
        cur, active, addrs = None, set(), {}
        for line in ifc.splitlines():
            if line and not line[0].isspace():
                cur = line.split(":")[0]
            elif cur:
                s = line.strip()
                if s.startswith("status: active"):
                    active.add(cur)
                elif s.startswith("inet "):
                    ip = s.split()[1]
                    if not ip.startswith(("127.", "169.254.")):
                        addrs.setdefault(cur, ip)
        for name, ip in sorted(addrs.items()):
            if name in active and not name.startswith(IGNORE_IF):
                hints.append("interface %s is active (address %s)" % (name, ip))
    elif sysname == "Linux":
        try:
            if "microsoft" in open("/proc/version").read().lower():
                reasons.append("this is WSL: the network state of Windows cannot be checked from here")
        except OSError:
            pass
        try:
            for line in open("/proc/net/route").read().splitlines()[1:]:
                f = line.split()
                if len(f) > 2 and f[1] == "00000000":
                    reasons.append("default IPv4 route through %s" % f[0])
        except OSError:
            reasons.append("cannot read the routing table")
        try:
            for line in open("/proc/net/ipv6_route").read().splitlines():
                f = line.split()
                if len(f) >= 10 and set(f[0]) == {"0"} and f[1] == "00" and f[-1] != "lo":
                    reasons.append("default IPv6 route through %s" % f[-1])
        except OSError:
            pass
    else:
        reasons.append("the network state cannot be checked on this system")
    return sorted(set(reasons)), hints


# ---------------------------------------------------------------- independent address computation

_P = 2 ** 256 - 2 ** 32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % _P == 0:
            return None
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, _P) % _P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, _P) % _P
    x = (lam * lam - a[0] - b[0]) % _P
    return x, (lam * (a[0] - x) - a[1]) % _P


def _mul(k):
    r, q = None, _G
    while k:
        if k & 1:
            r = _add(r, q)
        q = _add(q, q)
        k >>= 1
    return r


def _ckd(k, c, i):     # BIP32 private child derivation
    if i >= 0x80000000:
        data = b"\0" + k.to_bytes(32, "big") + i.to_bytes(4, "big")
    else:
        x, y = _mul(k)
        data = bytes([2 + (y & 1)]) + x.to_bytes(32, "big") + i.to_bytes(4, "big")
    d = hmac.new(c, data, hashlib.sha512).digest()
    il = int.from_bytes(d[:32], "big")
    child = (il + k) % _N
    if il >= _N or child == 0:
        raise ValueError("unusable child key")
    return child, d[32:]


_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            if top >> i & 1:
                chk ^= gen[i]
    return chk


def _bech32m(hrp, version, program):
    data, acc, bits = [version], 0, 0
    for b in program:
        acc, bits = acc << 8 | b, bits + 8
        while bits >= 5:
            bits -= 5
            data.append(acc >> bits & 31)
    if bits:
        data.append(acc << (5 - bits) & 31)
    hx = [ord(ch) >> 5 for ch in hrp] + [0] + [ord(ch) & 31 for ch in hrp]
    pm = _polymod(hx + data + [0] * 6) ^ 0x2BC830A3
    return hrp + "1" + "".join(_B32[d] for d in data + [pm >> 5 * (5 - i) & 31 for i in range(6)])


def py_addresses(seed, chain, count):
    """P2QRH receive addresses m/88h/COINh/0h/0/i computed without TrueNorth Core (doc/p2qrh.md)."""
    hrp, coin = CHAINS[chain]
    d = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = int.from_bytes(d[:32], "big"), d[32:]
    if not 0 < k < _N:
        raise ValueError("unusable seed")
    for i in (88 | 0x80000000, coin | 0x80000000, 0x80000000, 0):
        k, c = _ckd(k, c, i)
    res = []
    for i in range(count):
        ki, _ = _ckd(k, c, i)
        x = _mul(ki)[0].to_bytes(32, "big")                       # x-only public key
        commitment = hashlib.sha256(b"TrueNorth/QRH/v1" + b"\x01" + x + bytes(32)).digest()
        res.append(_bech32m(hrp, 2, commitment))
    return res


# ---------------------------------------------------------------- TrueNorth Core, started without any network

class Node:
    def __init__(self, bindir, chain):
        self.bindir, self.chain = bindir, chain
        self.datadir = tempfile.mkdtemp(prefix="tn-cold-")
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        self.errlog = open(os.path.join(self.datadir, "stderr.txt"), "wb")
        cmd = [os.path.join(bindir, "truenorthd"), "-datadir=" + self.datadir, "-chain=" + chain,
               "-listen=0", "-connect=0", "-dnsseed=0", "-fixedseeds=0", "-disablewallet=1",
               "-server=1", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-rpcport=%d" % self.port,
               "-printtoconsole=0", "-dbcache=16"]
        self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=self.errlog)

    def cli(self, *args, **kw):
        cmd = [os.path.join(self.bindir, "truenorth-cli"), "-datadir=" + self.datadir, "-chain=" + self.chain,
               "-rpcconnect=127.0.0.1", "-rpcport=%d" % self.port] + list(args)
        r = subprocess.run(cmd, input=kw.get("stdin"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=kw.get("timeout", 60))
        return r.returncode, r.stdout.strip(), r.stderr.strip()

    def wait_ready(self, seconds=120):
        end = time.time() + seconds
        while time.time() < end:
            if self.proc.poll() is not None:
                break
            try:
                if self.cli("getblockcount", timeout=20)[0] == 0:
                    return
            except subprocess.TimeoutExpired:
                pass
            time.sleep(1)
        raise Stop("TrueNorth Core did not start.\n" + self.tail())

    def tail(self):
        res = []
        for name in ("stderr.txt", "debug.log", os.path.join("regtest", "debug.log")):
            try:
                lines = open(os.path.join(self.datadir, name), errors="replace").read().splitlines()[-8:]
                res += ["   " + ln for ln in lines]
            except OSError:
                pass
        return "\n".join(res)

    def derive(self, desc, count):
        """Addresses for a descriptor. The descriptor goes in through stdin, never on a command line."""
        try:
            code, so, _ = self.cli("-stdin", "deriveaddresses", stdin=desc + "\n[0,%d]\n" % (count - 1))
        except subprocess.TimeoutExpired:
            code, so = 1, ""
        if code != 0:
            raise Stop("TrueNorth Core did not compute the addresses (code %d)." % code)   # no output shown on purpose
        return json.loads(so)

    def stop(self):
        try:
            self.cli("stop", timeout=20)
        except Exception:
            pass
        try:
            self.proc.wait(timeout=40)
        except Exception:
            self.proc.kill()
            try:
                self.proc.wait(timeout=10)
            except Exception:
                pass
        try:
            self.errlog.close()
        except Exception:
            pass
        shutil.rmtree(self.datadir, ignore_errors=True)


def both_ways(tn, node, mnemonic, chain, count):
    """Addresses from the words, computed twice (pure Python and Core). Stops if they differ."""
    seed = tn.bip39_seed(mnemonic)
    mine = py_addresses(seed, chain, count)
    version, coin = tn.CHAINS[chain]
    desc = tn.descriptors(tn.master_xprv(seed, version), coin)[0]["desc"]
    core = node.derive(desc, count)
    if mine != core or len(mine) != count:
        raise Stop("The two independent address computations disagree.\n" + REPORT)
    return mine


# ---------------------------------------------------------------- the ceremony

def show_words(parts, dry):
    alt_on()
    out()
    out("  RECOVERY WORDS" + ("   (DRY RUN, never use these words)" if dry else ""))
    out()
    for i in range(0, len(parts), 4):
        out("   " + "   ".join("%2d. %-9s" % (i + j + 1, parts[i + j]) for j in range(4)))
    out()
    out("  Copy them to paper, legibly and in exactly this order. Check every word.")
    out("  Do not photograph them and do not type them into a phone or another computer.")
    out()
    ask("  When they are written down, press Enter. The words will disappear from the screen. ")
    alt_clear()


def type_words(wordset):
    """Ask for the words one at a time. The screen is redrawn for each word, so the phrase never piles up on it."""
    got, note = [], ""
    while len(got) < NWORDS:
        alt_clear()
        out()
        out("  Now type the words from your paper, one at a time (press Enter after each word).")
        out("  Entered: %d of %d" % (len(got), NWORDS))
        out()
        if note:
            out("  " + note)
            out()
        w = ask("  %2d: " % (len(got) + 1)).strip().lower()
        if w in wordset:
            got.append(w)
            note = ""
        else:
            note = "That word is not in the word list. Check for a typo and type it again."
    alt_clear()
    return got


def ceremony_new(tn, node, chain, dry, outdir, dice):
    words = tn.wordlist()
    ent = os.urandom(32)
    if dice:
        alt_on()
        try:
            out()
            out("  Roll a die at least 99 times and type the results as digits 1 to 6, without spaces.")
            d = ask("  Rolls: ").strip()
        finally:
            alt_off()
        if len(d) < 99 or set(d) - set("123456"):
            raise Stop("Dice rolls: expected at least 99 digits from 1 to 6.")
        ent = bytes(x ^ y for x, y in zip(ent, hashlib.sha256(d.encode()).digest()))
    mnemonic = tn.to_mnemonic(ent, words)
    parts = mnemonic.split()
    if len(parts) != NWORDS or tn.check_mnemonic(mnemonic, words) is not None:
        raise Stop("Internal error while making the words.\n" + REPORT)
    out()
    out("  Have paper and a pen ready. Make sure that nobody can see the screen and that no camera points at it.")
    ask("  Press Enter to show the 24 words. ")
    try:
        wordset = set(words)
        for attempt in range(3):
            show_words(parts, dry)
            got = type_words(wordset)
            bad = [i + 1 for i in range(NWORDS) if got[i] != parts[i]]
            if not bad:
                break
            out()
            out("  The words at these positions do not match: " + ", ".join(str(b) for b in bad))
            if attempt == 2:
                raise Stop("The words could not be confirmed in three attempts. Nothing was created. "
                           "Destroy the paper and run the script again; it will make new words.")
            ask("  Press Enter. The words will be shown again; correct your paper and type them once more. ")
    finally:
        alt_off()
    addrs = both_ways(tn, node, mnemonic, chain, NADDR)
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "cold-address.txt"), "w") as f:
        f.write(addrs[0] + "\n")
    with open(os.path.join(outdir, "cold-addresses.txt"), "w") as f:
        f.write("".join("%d %s\n" % (i, a) for i, a in enumerate(addrs)))
    with open(os.path.join(outdir, "cold-info.txt"), "w") as f:
        f.write("TrueNorth (NORTH) cold address%s\n" % (" - DRY RUN, DO NOT USE" if dry else ""))
        f.write("created: %s\n" % time.strftime("%Y-%m-%d %H:%M %Z"))
        f.write("chain: %s\n" % chain)
        f.write("address type: P2QRH (qrh), path m/88h/%dh/0h/0/i, i = 0 to %d\n" % (CHAINS[chain][1], NADDR - 1))
        f.write("backup: 24 BIP39 words on paper, no extra passphrase\n")
        f.write("checks: the Python computation and TrueNorth Core agree; the known-answer test passed\n")
        f.write("script: cold-address.py %s, sha256 %s\n" % (VERSION, sha256_file(os.path.abspath(__file__))))
        f.write("This folder contains no secrets.\n")
    _saved.append(outdir)
    return addrs


def ceremony_verify(tn, node, chain, outdir):
    path = os.path.join(outdir, "cold-address.txt")
    if not os.path.isfile(path):
        raise Stop("Cannot find %s, so there is nothing to compare with." % path)
    want = open(path).read().strip()
    words = tn.wordlist()
    out()
    ask("  Have the paper with your words ready. Make sure that nobody can see the screen. Press Enter. ")
    alt_on()
    try:
        got = type_words(set(words))
    finally:
        alt_off()
    mnemonic = " ".join(got)
    if tn.check_mnemonic(mnemonic, words) is not None:
        out("  MISMATCH: these words are not a valid set (a word is different or out of order).")
        return False
    addr = both_ways(tn, node, mnemonic, chain, 1)[0]
    if addr == want:
        out("  OK: the words on your paper give the saved address")
        out("     " + want)
        return True
    out("  MISMATCH: the words on your paper give a different address than the one saved in " + path)
    out("     the words give: " + addr)
    out("     saved address:  " + want)
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", nargs="?", default="new", choices=["new", "verify"])
    ap.add_argument("--dry-run", action="store_true",
                    help="rehearsal: the network may stay on, the output goes to out-dry-run/")
    ap.add_argument("--dice", action="store_true", help="mix your own dice rolls into the randomness")
    ap.add_argument("--version", action="version", version="cold-address.py " + VERSION)
    ap.add_argument("--chain", default="main", choices=sorted(CHAINS), help=argparse.SUPPRESS)
    a = ap.parse_args()
    dry = a.dry_run
    if sys.version_info < (3, 8):
        raise Stop("Python 3.8 or newer is needed.")
    if a.chain != "main" and not dry:
        raise Stop("A chain other than main is only allowed together with --dry-run.")
    if not (sys.stdin.isatty() and sys.stdout.isatty()) or os.environ.get("TERM", "dumb") == "dumb":
        raise Stop("Run the script directly in a terminal window.")
    os.umask(0o077)
    outdir = os.path.join(DIR, "out-dry-run" if dry else "out")
    out("TrueNorth cold address, version %s%s" % (VERSION, "   *** DRY RUN ***" if dry else ""))
    if a.cmd == "new" and os.path.exists(os.path.join(outdir, "cold-address.txt")) and not dry:
        raise Stop("A cold address already exists (%s).\nA new one will not be made, so that it stays clear which "
                   "words belong to which address.\nIf you really want a new one, move the out folder away first."
                   % outdir)

    out("[1/4] Checking the files ...")
    tn = load_tnseed()
    bindir = find_bin()
    out("      ok (tn-seed.py, english.txt, truenorthd, truenorth-cli)")

    out("[2/4] Checking that the computer is offline ...")
    reasons, hints = net_status()
    if dry:
        if reasons or hints:
            out("      not offline, which is fine in a dry run. A real run would stop or ask because of:")
            for r in reasons + hints:
                out("        - " + r)
        else:
            out("      offline")
    else:
        if reasons:
            raise Stop("The computer is connected to a network:\n" + "\n".join("   - " + r for r in reasons) +
                       "\nTurn Wi-Fi off (and unplug any network cable or phone), then run the script again.")
        if hints:
            out("      Note: there seems to be another connection:")
            for h in hints:
                out("        - " + h)
            if ask("      If you know about it and it does not lead to the internet, type YES and press Enter: "
                   ).strip().upper() != "YES":
                raise Stop("Disconnect the device and run the script again.")
        out("      ok, the computer is offline")

    out("[3/4] Starting TrueNorth Core without any network (this takes a moment) ...")
    node = Node(bindir, a.chain)
    try:
        node.wait_ready()
        out("      running")
        out("[4/4] Known-answer test ...")
        if both_ways(tn, node, KAT_WORDS, a.chain, 1)[0] != KAT[a.chain]:
            raise Stop("The known-answer test gave a wrong result. Do not continue.\n" + REPORT)
        out("      ok, two independent computations agree with the expected address")

        if a.cmd == "verify":
            ok = ceremony_verify(tn, node, a.chain, outdir)
            return 0 if ok else 1

        addrs = ceremony_new(tn, node, a.chain, dry, outdir, a.dice)
        late, _ = net_status()
        out()
        out("Done." + ("  (DRY RUN: do not use the address or the words)" if dry else ""))
        out()
        out("Cold address:")
        out()
        out("   " + addrs[0])
        out()
        out("Write it on the paper next to the words. When you restore one day, it tells you that all is right.")
        out("The public data is saved in: " + outdir)
        if not dry:
            if late:
                out()
                out("WARNING: the computer went online during the procedure (" + "; ".join(late) + ").")
                out("If you did not intend that, do not use the address.")
            out()
            out("Next: put the paper in a safe place and close this terminal window. Only then go back online.")
            out("Never send the words to anyone and never type them into a website.")
        return 0
    finally:
        node.stop()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Stop as e:
        out()
        out("STOP: " + str(e))
        sys.exit(2)
    except KeyboardInterrupt:
        out()
        if _saved:
            out("Interrupted after the address was saved in %s." % _saved[0])
            out("Run the script again with 'verify' (and the same options) to check that your paper matches it.")
        else:
            out("Interrupted. Nothing was saved.")
        sys.exit(130)
    except Exception as e:   # never print details here: they could contain secret material
        out()
        out("STOP: unexpected error (%s).\n%s" % (type(e).__name__, REPORT))
        sys.exit(3)
