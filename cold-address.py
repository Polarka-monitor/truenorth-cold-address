#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cold-address: create a TrueNorth (NORTH) cold address once, on a computer that is offline.

Usage (in a terminal, in the folder that holds this script):

  python3 cold-address.py              make 24 recovery words and the first addresses that belong to them
  python3 cold-address.py verify       check that the words on your paper give the saved address
  python3 cold-address.py --dry-run    rehearsal: throw-away words, test-network address, the network may stay on

Principles:
  * secrets (words, keys) exist only in the memory of this one Python process: they are never written to
    disk and never handed to another program
  * only public data (addresses) is written, to the out/ folder
  * every address is computed twice: by the Python code below from the private keys, and by TrueNorth Core,
    which is given nothing but the public key of the account
  * Python standard library only, so that the whole script can be read and checked
"""
import os
import sys

if __name__ == "__main__" and not sys.flags.isolated and sys.executable:
    # Start again in Python's isolated mode (-I). The PYTHON* environment variables and the user's own package
    # folder are then ignored and the folder of this script is not searched for modules, so every import below
    # can only come from the standard library.
    os.execv(sys.executable, [sys.executable, "-I", os.path.abspath(__file__)] + sys.argv[1:])

import argparse      # noqa: E402
import glob          # noqa: E402
import hashlib       # noqa: E402
import hmac          # noqa: E402
import json          # noqa: E402
import platform      # noqa: E402
import shutil        # noqa: E402
import signal        # noqa: E402
import socket        # noqa: E402
import subprocess    # noqa: E402
import tempfile      # noqa: E402
import time          # noqa: E402
import types         # noqa: E402

VERSION = "1.2 (2026-11-13)"
RELEASE = "v30.5.4"
ISSUES = "https://github.com/severka-monitor/truenorth-cold-address/issues"
REPORT = "Do not use anything from this run. Please report it (never include your words): " + ISSUES
DIR = os.path.dirname(os.path.abspath(__file__))

# SHA-256 of the files this script relies on. The binaries are the ones inside the official v30.5.4 release
# archives (the archive checksums were checked against the signed SHA256SUMS before unpacking, see README).
EXPECT = {
    "tn-seed.py": "2fe108f45a7c0ba702cf435173b48ebbeb8ae88beecc0c3ee8d5448d2441397f",
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

# chain -> (bech32 prefix, SLIP-44 coin type in the derivation path, version bytes of an extended PUBLIC key)
# The version bytes are base58Prefixes[EXT_PUBLIC_KEY] in src/kernel/chainparams.cpp of TrueNorth Core.
CHAINS = {"main": ("north", 1867, "7e5d5a83"), "regtest": ("rnorth", 1, "043587cb")}

# Known-answer test: the public BIP39 test phrase must give these first addresses (m/88h/COINh/0h/0/0).
KAT_WORDS = "abandon " * 11 + "about"
KAT = {
    "main": "north1zju65aymm3nsz3uhpxcv0x7vrsw2x3pq4ehdne9a682j3fzd5s2vsenx7fx",
    "regtest": "rnorth1zfgvaxg6parqfv2drvsk9zadefh40zg97ese44hjkjzkjamkftpzsnpx4h6",
}

# Test vectors 1, 3 and 4 of BIP-0032 (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), copied
# unchanged: the seed, then (child number, extended private key) for the master key and for every step.
# Vectors 3 and 4 were added to the standard because of keys that begin with zero bytes.
H = 0x80000000
BIP32_VECTORS = (
    ("000102030405060708090a0b0c0d0e0f", (
        (None, "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPP"
         "qjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"),
        (0 | H, "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvU"
         "xt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"),
        (1, "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLn"
         "vSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"),
        (2 | H, "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBD"
         "ptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"),
        (2, "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb"
         "2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"),
        (1000000000, "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8F"
         "Ha8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"),
    )),
    ("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4ac"
     "ba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be", (
        (None, "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJ"
         "Du7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"),
        (0 | H, "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBA"
         "JMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"),
    )),
    ("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678", (
        (None, "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14"
         "S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv"),
        (0 | H, "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRn"
         "aALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G"),
        (1 | H, "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuV"
         "oHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1"),
    )),
)

NWORDS = 24
NADDR = 5

_saved = []        # output folders written in this run (public data only)


# ---------------------------------------------------------------- terminal

def _put(s):
    try:
        sys.stdout.write(s)
        sys.stdout.flush()
    except (OSError, ValueError):      # the terminal is gone (window closed); the clean-up must still run
        pass


def out(s=""):
    _put(s + "\n")


def alt_on():      # alternate screen: nothing shown there reaches the scrollback
    _put("\033[?1049h\033[2J\033[H")


def alt_clear():
    _put("\033[2J\033[H")


def alt_off():     # wipe the alternate screen, leave it, and clear the scrollback for good measure
    _put("\033[2J\033[H\033[?1049l\033[3J")


class Stop(Exception):
    pass


class Signalled(BaseException):
    """The process was told to end (window closed, kill). Not an Exception, so that nothing swallows it."""


def ask(prompt):
    try:
        return input(prompt)
    except (EOFError, OSError):
        raise Stop("The input ended.")


# ---------------------------------------------------------------- this process

END_SIGNALS = ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT")


def _on_signal(signum, frame):
    for name in END_SIGNALS:           # from here on the clean-up runs and must not be cut short
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), signal.SIG_IGN)
    if signum == signal.SIGINT:
        raise KeyboardInterrupt()
    raise Signalled(signum)


def protect_process():
    """Make sure an early end still wipes the screen and stops the helper node, and that memory stays private."""
    for name in END_SIGNALS:
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _on_signal)
    if hasattr(signal, "SIGTSTP"):
        signal.signal(signal.SIGTSTP, signal.SIG_IGN)      # Ctrl+Z would freeze the words on the screen
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))   # no core file, of this process or of its children
    except Exception:
        pass
    if platform.system() == "Linux":
        try:
            import ctypes
            ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)         # PR_SET_DUMPABLE off: other programs cannot attach to it
        except Exception:
            pass


def child_env(home):
    """The environment of the helper programs: nothing from the user's shell (LD_PRELOAD, DYLD_...) is passed on."""
    return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": home, "LANG": "C", "LC_ALL": "C"}


def terminal_objections():
    """Reasons why this is not a plain terminal window on the computer itself."""
    env, res = os.environ, []
    term = env.get("TERM", "")
    if env.get("STY") or term.startswith("screen"):
        res.append("the terminal runs inside GNU screen (or says so): screen keeps what was shown in its scrollback")
    if env.get("TMUX") or term.startswith("tmux"):
        res.append("the terminal runs inside tmux, which keeps a session alive after the window is closed")
    if env.get("SSH_CONNECTION") or env.get("SSH_CLIENT") or env.get("SSH_TTY"):
        res.append("this is a remote (SSH) session: the words would travel over a network to another screen")
    if env.get("SCRIPT"):
        res.append("the session is being recorded by the 'script' command")
    return res


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
        r = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=15, env=child_env("/"))
        return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else None
    except Exception:
        return None


IGNORE_IF = ("lo", "utun", "awdl", "llw", "gif", "stf", "anpi", "bridge", "ap", "vmenet", "vmnet", "pktap")
TUNNEL_IF = ("lo", "utun", "ipsec", "gif", "stf")

# One public address in every /8 block of IPv4 and of the global IPv6 range 2000::/3, so that a route to any
# large part of the internet is noticed. Nothing is ever sent to them: see _routable().
PROBE4 = tuple("%d.1.1.1" % a for a in range(1, 224) if a not in (10, 127))
PROBE6 = tuple("%x:1::1" % h for h in range(0x2000, 0x4000, 0x100))


def _routable(family, probes):
    """Ask the kernel whether it has a route to public addresses. Connecting a UDP socket sends no packet;
    it only makes the kernel look the route up, with all its routing tables and rules."""
    for addr in probes:
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
        except OSError:
            return False               # this address family is switched off altogether
        try:
            s.connect((addr, 9))
            src = s.getsockname()[0]
        except OSError:
            src = ""
        finally:
            s.close()
        if src and not src.startswith("127.") and src != "::1":
            return True
    return False


def _net_darwin(reasons, hints):
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


def _net_linux(reasons, hints):
    try:
        if "microsoft" in open("/proc/version").read().lower():
            reasons.append("this is WSL: the network state of Windows cannot be checked from here")
    except OSError:
        pass
    try:                               # the main routing table, read for the interface name in the message
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
    if _routable(socket.AF_INET, PROBE4):
        reasons.append("the system has a route to public IPv4 addresses")
    if _routable(socket.AF_INET6, PROBE6):
        reasons.append("the system has a route to public IPv6 addresses")
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        names = []
        reasons.append("cannot list the network interfaces")
    for name in names:
        if name == "lo":
            continue
        try:
            carrier = open("/sys/class/net/%s/carrier" % name).read().strip()
        except OSError:
            carrier = "0"              # the kernel refuses to say while the interface is switched off
        if carrier == "1":
            hints.append("interface %s has a link" % name)
    for path in sorted(glob.glob("/sys/class/rfkill/rfkill*")):
        try:
            if open(path + "/type").read().strip() == "wlan" and open(path + "/soft").read().strip() == "0" \
                    and open(path + "/hard").read().strip() == "0":
                hints.append("the Wi-Fi radio is switched on (%s)" % open(path + "/name").read().strip())
        except OSError:
            pass


def net_status():
    """Return (reasons, hints). reasons: why the machine counts as online. hints: things the user must judge."""
    reasons, hints = [], []
    sysname = platform.system()
    if sysname == "Darwin":
        _net_darwin(reasons, hints)
    elif sysname == "Linux":
        _net_linux(reasons, hints)
    else:
        reasons.append("the network state cannot be checked on this system")
    return sorted(set(reasons)), sorted(set(hints))


# ---------------------------------------------------------------- address computation in this script

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


def account_key(seed, chain):
    """Private key and chain code of the account m/88h/COINh/0h."""
    d = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = int.from_bytes(d[:32], "big"), d[32:]
    if not 0 < k < _N:
        raise ValueError("unusable seed")
    for i in (88 | H, CHAINS[chain][1] | H, H):
        k, c = _ckd(k, c, i)
    return k, c


def py_addresses(seed, chain, count):
    """P2QRH receive addresses m/88h/COINh/0h/0/i, computed from the private keys (doc/p2qrh.md of Core)."""
    k, c = _ckd(*account_key(seed, chain), 0)
    res = []
    for i in range(count):
        ki, _ = _ckd(k, c, i)
        x = _mul(ki)[0].to_bytes(32, "big")                       # x-only public key
        commitment = hashlib.sha256(b"TrueNorth/QRH/v1" + b"\x01" + x + bytes(32)).digest()
        res.append(_bech32m(CHAINS[chain][0], 2, commitment))
    return res


def public_descriptor(tn, seed, chain):
    """The receive descriptor with the PUBLIC key of the account. It holds no secret: it cannot spend."""
    k, c = account_key(seed, chain)
    x, y = _mul(k)
    # An extended public key: version, then depth, parent and child number left at zero, chain code, public key.
    xpub = tn.b58check(bytes.fromhex(CHAINS[chain][2]) + bytes(9) + c + bytes([2 + (y & 1)]) + x.to_bytes(32, "big"))
    d = "qrh(%s/0/*)" % xpub
    return d + "#" + tn.descriptor_checksum(d)


# ---------------------------------------------------------------- TrueNorth Core, started without any network

class Node:
    def __init__(self, bindir, chain):
        self.bindir, self.chain = bindir, chain
        self.proc = self.errlog = None
        self.datadir = tempfile.mkdtemp(prefix="tn-cold-")        # private to this user (mode 700)
        self.cookie = os.path.join(self.datadir, "" if chain == "main" else chain, ".cookie")
        self.env = child_env(self.datadir)

    def start(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        self.errlog = open(os.path.join(self.datadir, "stderr.txt"), "wb")
        cmd = [os.path.join(self.bindir, "truenorthd"), "-datadir=" + self.datadir, "-chain=" + self.chain,
               "-listen=0", "-connect=0", "-dnsseed=0", "-fixedseeds=0", "-disablewallet=1",
               "-server=1", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-rpcport=%d" % self.port,
               "-printtoconsole=0", "-dbcache=16"]
        self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=self.errlog,
                                     env=self.env, start_new_session=True)

    def mine(self):
        """True while OUR node runs and has opened its port.

        The port number was free when it was picked, but another program could take it before our node does.
        Our node then fails to start. It writes its cookie file only after it has the port and removes the file
        when it stops, and nobody else can write into the private data folder. So: cookie there and process
        alive means that the listener on the port is our node."""
        return self.proc is not None and self.proc.poll() is None and os.path.isfile(self.cookie)

    def cli(self, *args, **kw):
        cmd = [os.path.join(self.bindir, "truenorth-cli"), "-datadir=" + self.datadir, "-chain=" + self.chain,
               "-rpcconnect=127.0.0.1", "-rpcport=%d" % self.port] + list(args)
        io = {"input": kw["stdin"]} if kw.get("stdin") is not None else {"stdin": subprocess.DEVNULL}
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                           timeout=kw.get("timeout", 60), env=self.env, **io)
        return r.returncode, r.stdout.strip(), r.stderr.strip()

    def wait_ready(self, seconds=120):
        end = time.time() + seconds
        while time.time() < end and self.proc.poll() is None:
            if self.mine():
                try:
                    if self.cli("getblockcount", timeout=20)[0] == 0 and self.mine():
                        return
                except subprocess.TimeoutExpired:
                    pass
            time.sleep(0.5)
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
        if not self.mine():
            raise Stop("The helper node is not running any more. Nothing was sent.")
        try:
            code, so, _ = self.cli("-stdin", "deriveaddresses", stdin=desc + "\n[0,%d]\n" % (count - 1))
        except subprocess.TimeoutExpired:
            code, so = 1, ""
        if not self.mine():
            raise Stop("The helper node stopped during the computation.\n" + REPORT)
        if code != 0:
            raise Stop("TrueNorth Core did not compute the addresses (code %d)." % code)   # no output shown on purpose
        return json.loads(so)

    def stop(self):
        if self.proc is not None:
            try:
                if self.mine():
                    self.cli("stop", timeout=20)
                else:
                    self.proc.terminate()      # never talk to a port that is not ours
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
            if self.errlog:
                self.errlog.close()
        except Exception:
            pass
        shutil.rmtree(self.datadir, ignore_errors=True)


# ---------------------------------------------------------------- checks

def selftest_bip32(tn):
    """The private key derivation of this script (_ckd) against the published BIP-0032 vectors."""
    for seed_hex, steps in BIP32_VECTORS:
        seed = bytes.fromhex(seed_hex)
        d = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        k, c = int.from_bytes(d[:32], "big"), d[32:]
        for index, xprv in steps:
            if index is None:
                if tn.master_xprv(seed, bytes.fromhex("0488ade4")) != xprv:
                    return False
            else:
                k, c = _ckd(k, c, index)
            n = 0
            for ch in xprv:
                n = n * 58 + tn.B58.index(ch)
            raw = n.to_bytes(82, "big")            # 78 bytes of key data and 4 bytes of checksum
            if hashlib.sha256(hashlib.sha256(raw[:78]).digest()).digest()[:4] != raw[78:]:
                return False
            if raw[13:45] != c or raw[45:78] != b"\0" + k.to_bytes(32, "big"):
                return False
    return True


def selftest_restore_path(tn, node, chain):
    """The way back from paper, tried with phrases that are not yours.

    TrueNorth Core is given the PRIVATE descriptor that tn-seed.py builds from a phrase (that is what you import
    when you restore) and must derive the addresses this script computes. The phrases are the public test phrase
    and two throw-away ones made here, which are never shown or kept. Your own words never take this route."""
    words = tn.wordlist()
    for phrase in [KAT_WORDS] + [tn.to_mnemonic(os.urandom(32), words) for _ in range(2)]:
        seed = tn.bip39_seed(phrase)
        version, coin = tn.CHAINS[chain]
        desc = tn.descriptors(tn.master_xprv(seed, version), coin)[0]["desc"]
        if node.derive(desc, 2) != py_addresses(seed, chain, 2):
            return False
    return True


def both_ways(tn, node, mnemonic, chain, count):
    """Addresses from the words, computed twice. This script derives them from the private keys. TrueNorth Core
    derives them from the public key of the account, which is all it is given. Stops if they differ."""
    seed = tn.bip39_seed(mnemonic)
    mine = py_addresses(seed, chain, count)
    core = node.derive(public_descriptor(tn, seed, chain), count)
    if mine != core or len(mine) != count:
        raise Stop("The two independent address computations disagree.\n" + REPORT)
    return mine


def recipe(chain):
    return "TrueNorth (NORTH), BIP39, 24 English words, no passphrase, qrh(), path m/88h/%dh/0h/0/0" % CHAINS[chain][1]


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


def ceremony_new(tn, node, chain, dry, outdir, dice, accepted):
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
    if not dry:
        reasons, hints = net_status()
        changed = reasons + [h for h in hints if h not in accepted]
        if changed:
            raise Stop("The network state changed after the check:\n" + "\n".join("   - " + r for r in changed) +
                       "\nNo words were shown. Disconnect and run the script again.")
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
        f.write("recipe for the paper: %s\n" % recipe(chain))
        f.write("to restore: tn-seed.py restore turns the words into descriptors for TrueNorth Core\n")
        f.write("checks: the Python computation and TrueNorth Core agree; the self-tests passed\n")
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
                    help="rehearsal on test-network parameters: the network may stay on, the output goes to out-dry-run/")
    ap.add_argument("--dice", action="store_true", help="mix your own dice rolls into the randomness")
    ap.add_argument("--version", action="version", version="cold-address.py " + VERSION)
    ap.add_argument("--chain", choices=sorted(CHAINS), help=argparse.SUPPRESS)
    a = ap.parse_args()
    dry = a.dry_run
    chain = a.chain or ("regtest" if dry else "main")       # a rehearsal address can never receive real coins
    if sys.version_info < (3, 8):
        raise Stop("Python 3.8 or newer is needed.")
    if chain != "main" and not dry:
        raise Stop("A chain other than main is only allowed together with --dry-run.")
    if not (sys.stdin.isatty() and sys.stdout.isatty()) or os.environ.get("TERM", "dumb") == "dumb":
        raise Stop("Run the script directly in a terminal window.")
    protect_process()
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

    out("[2/4] Checking the terminal and the network ...")
    objections = terminal_objections()
    reasons, hints = net_status()
    if dry:
        if objections or reasons or hints:
            out("      fine for a dry run. A real run would stop or ask because of:")
            for r in objections + reasons + hints:
                out("        - " + r)
        else:
            out("      a plain terminal, no network connection found")
    else:
        if objections:
            raise Stop("This is not a plain terminal window on the computer itself:\n" +
                       "\n".join("   - " + r for r in objections) +
                       "\nOpen a terminal window on this computer (no screen, tmux or SSH) and run the script there.")
        if reasons:
            raise Stop("The computer is connected to a network:\n" + "\n".join("   - " + r for r in reasons) +
                       "\nTurn Wi-Fi off, unplug any network cable or phone and switch off any VPN, then run the "
                       "script again.")
        if hints:
            out("      Note: there may be another connection:")
            for h in hints:
                out("        - " + h)
            if ask("      If you know about it and it does not lead to the internet, type YES and press Enter: "
                   ).strip().upper() != "YES":
                raise Stop("Disconnect the device and run the script again.")
        out("      ok, no network connection found")

    out("[3/4] Starting TrueNorth Core without any network (this takes a moment) ...")
    node = Node(bindir, chain)
    try:
        node.start()
        node.wait_ready()
        out("      running")
        out("[4/4] Self-tests ...")
        if not selftest_bip32(tn):
            raise Stop("The BIP-0032 test vectors gave a wrong result. Do not continue.\n" + REPORT)
        if both_ways(tn, node, KAT_WORDS, chain, 1)[0] != KAT[chain]:
            raise Stop("The known-answer test gave a wrong result. Do not continue.\n" + REPORT)
        if not selftest_restore_path(tn, node, chain):
            raise Stop("The restore path gave a wrong result. Do not continue.\n" + REPORT)
        out("      ok: key derivation vectors, known address, restore path with throw-away phrases")

        if a.cmd == "verify":
            ok = ceremony_verify(tn, node, chain, outdir)
            return 0 if ok else 1

        addrs = ceremony_new(tn, node, chain, dry, outdir, a.dice, hints)
        late, _ = net_status()
        out()
        out("Done." + ("  (DRY RUN: do not use the address or the words)" if dry else ""))
        out()
        out("Cold address:")
        out()
        out("   " + addrs[0])
        out()
        if dry and chain != "main":
            out("This rehearsal address is on test-network parameters. It cannot receive real coins.")
        out("Write the address on the paper next to the words. When you restore one day, it tells you that all is")
        out("right. Write this line on the paper as well; it says how the words are to be used:")
        out()
        out("   " + recipe(chain))
        out()
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
        code = main()
    except Stop as e:
        out()
        out("STOP: " + str(e))
        code = 2
    except (KeyboardInterrupt, Signalled) as e:
        out()
        if _saved:
            out("Interrupted after the address was saved in %s." % _saved[0])
            out("Run the script again with 'verify' (and the same options) to check that your paper matches it.")
        else:
            out("Interrupted. Nothing was saved.")
        code = 130 if isinstance(e, KeyboardInterrupt) else 128 + int(e.args[0])
    except Exception as e:   # never print details here: they could contain secret material
        out()
        out("STOP: unexpected error (%s).\n%s" % (type(e).__name__, REPORT))
        code = 3
    sys.exit(code)
