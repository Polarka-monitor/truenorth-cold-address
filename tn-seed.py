#!/usr/bin/env python3
"""tn-seed: recovery words for a TrueNorth (NORTH) cold wallet.

Makes (or restores) a BIP39 recovery phrase and turns it into the private
descriptors that TrueNorth Core imports with `importdescriptors`. The default
P2QRH path is the one Core itself uses: m/88h/1867h/0h (1h on test chains).

It handles secrets. `new` shows the words and prints private descriptors: run it
only on a machine that is offline and will stay offline. `restore` asks for the
words without showing them; with --json it prints nothing but the descriptors,
so that they can go straight into TrueNorth Core through a pipe and never touch
a file. Python standard library only, so it can be read and audited in one
sitting; no elliptic-curve code is needed because Core derives the keys.

  python3 tn-seed.py selftest
  python3 tn-seed.py new      [--chain main|testnet4|regtest] [--words 24|12] [--dice] [--passphrase] [--out FILE]
  python3 tn-seed.py restore  [--chain main|testnet4|regtest] [--passphrase] [--json | --out FILE | --check FILE]
"""
import argparse
import getpass
import hashlib
import hmac
import json
import os
import sys
import unicodedata

WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
CHAINS = {   # extended private key version bytes (src/kernel/chainparams.cpp), SLIP-44 coin type
    "main": (bytes.fromhex("7e5c6544"), 1867),
    "testnet4": (bytes.fromhex("04358392"), 1),
    "regtest": (bytes.fromhex("04358390"), 1),
}
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def wordlist():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "english.txt")
    data = open(path, "rb").read()
    if hashlib.sha256(data).hexdigest() != WORDLIST_SHA256:
        sys.exit("english.txt is not the standard BIP39 word list (checksum mismatch)")
    words = data.decode().split()
    assert len(words) == 2048
    return words


def to_mnemonic(entropy, words):
    bits = len(entropy) * 8
    check = hashlib.sha256(entropy).digest()
    n = (int.from_bytes(entropy, "big") << (bits // 32)) | (check[0] >> (8 - bits // 32))
    count = (bits + bits // 32) // 11
    return " ".join(words[(n >> (11 * (count - 1 - i))) & 2047] for i in range(count))


def check_mnemonic(mnemonic, words):
    parts = mnemonic.split()
    if len(parts) not in (12, 15, 18, 21, 24):
        return "expected 12 to 24 words, got %d" % len(parts)
    index = {w: i for i, w in enumerate(words)}
    for p in parts:
        if p not in index:
            return "'%s' is not a BIP39 word" % p
    n = 0
    for p in parts:
        n = (n << 11) | index[p]
    cs_bits = len(parts) * 11 // 33
    entropy = (n >> cs_bits).to_bytes(len(parts) * 11 * 32 // 33 // 8, "big")
    if hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits) != n & ((1 << cs_bits) - 1):
        return "checksum does not match (a word is wrong or out of order)"
    return None


def bip39_seed(mnemonic, passphrase=""):
    norm = lambda s: unicodedata.normalize("NFKD", s)
    return hashlib.pbkdf2_hmac("sha512", norm(mnemonic).encode(), ("mnemonic" + norm(passphrase)).encode(), 2048, 64)


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def master_xprv(seed, version):
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key, chain_code = i[:32], i[32:]
    if not 0 < int.from_bytes(key, "big") < N:
        sys.exit("unusable seed (astronomically unlikely); generate a new phrase")
    return b58check(version + b"\0" + b"\0" * 4 + b"\0" * 4 + chain_code + b"\0" + key)


def descriptor_checksum(desc):
    """Checksum from Bitcoin Core's descriptor.cpp (DescriptorChecksum)."""
    inp = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
    out = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    def polymod(c, val):
        c0 = c >> 35
        c = ((c & 0x7FFFFFFFF) << 5) ^ val
        for bit, g in enumerate((0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD)):
            if c0 >> bit & 1:
                c ^= g
        return c

    c, cls, count = 1, 0, 0
    for ch in desc:
        pos = inp.find(ch)
        if pos < 0:
            raise ValueError("invalid descriptor character %r" % ch)
        c = polymod(c, pos & 31)
        cls, count = cls * 3 + (pos >> 5), count + 1
        if count == 3:
            c, cls, count = polymod(c, cls), 0, 0
    if count:
        c = polymod(c, cls)
    for _ in range(8):
        c = polymod(c, 0)
    c ^= 1
    return "".join(out[(c >> (5 * (7 - j))) & 31] for j in range(8))


def descriptors(xprv, coin):
    res = []
    for branch, internal in ((0, False), (1, True)):
        d = "qrh(%s/88h/%dh/0h/%d/*)" % (xprv, coin, branch)
        res.append({"desc": d + "#" + descriptor_checksum(d), "active": True, "internal": internal,
                    "timestamp": "now", "range": [0, 999]})
    return res


def secret_line(prompt):
    """One line of secret input. At a keyboard it is not echoed, so it cannot end up in the scrollback."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return sys.stdin.readline()


def selftest(words):
    ent = bytes(16)
    assert to_mnemonic(ent, words) == "abandon " * 11 + "about"
    assert to_mnemonic(bytes([0x7F] * 32), words).endswith("title") and check_mnemonic(to_mnemonic(bytes([0x7F] * 32), words), words) is None
    assert check_mnemonic("abandon " * 11 + "abandon", words) is not None
    seed = bip39_seed("abandon " * 11 + "about", "TREZOR")
    assert seed.hex().startswith("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553")
    x = master_xprv(bytes.fromhex("000102030405060708090a0b0c0d0e0f"), bytes.fromhex("0488ade4"))
    assert x == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    assert descriptor_checksum("wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)") == "8zl0zxma"
    assert master_xprv(seed, CHAINS["main"][0]).startswith("Tprv")
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["new", "restore", "selftest"])
    ap.add_argument("--chain", choices=list(CHAINS), default="main")
    ap.add_argument("--words", type=int, choices=[12, 24], default=24)
    ap.add_argument("--dice", action="store_true", help="new only: ask for dice rolls (digits 1 to 6, 99 or more) and mix them into the system randomness")
    ap.add_argument("--passphrase", action="store_true", help="ask for an extra BIP39 passphrase (it is NOT recoverable from the words)")
    ap.add_argument("--out", help="write the importdescriptors JSON to this file (mode 0600) instead of printing it")
    ap.add_argument("--check", help="restore only: compare with a file written by --out and report whether the words match")
    ap.add_argument("--json", action="store_true", help="restore only: print nothing but the descriptors, for a pipe into truenorth-cli")
    a = ap.parse_args()
    if a.json and a.cmd != "restore":
        sys.exit("--json is for restore only")
    words = wordlist()
    if a.cmd == "selftest":
        return selftest(words)
    if a.cmd == "new":
        ent = os.urandom(32)
        if a.dice:
            dice = secret_line("Dice rolls, digits 1 to 6, at least 99 (not shown as you type): ").strip()
            if len(dice) < 99 or set(dice) - set("123456"):
                sys.exit("--dice needs at least 99 rolls written as digits 1 to 6")
            ent = bytes(x ^ y for x, y in zip(ent, hashlib.sha256(dice.encode()).digest()))
        mnemonic = to_mnemonic(ent[: a.words * 4 // 3], words)
    else:
        mnemonic = " ".join(secret_line("Recovery words, all on one line (not shown as you type): ").lower().split())
    err = check_mnemonic(mnemonic, words)
    if err:
        sys.exit("Recovery phrase rejected: " + err)
    pw = ""
    if a.passphrase:
        pw = getpass.getpass("BIP39 passphrase: ")
        if a.cmd == "new" and pw != getpass.getpass("Repeat passphrase: "):
            sys.exit("passphrases differ")
    version, coin = CHAINS[a.chain]
    descs = descriptors(master_xprv(bip39_seed(mnemonic, pw), version), coin)
    if a.check:
        same = json.load(open(a.check)) == descs
        print("The words match the wallet being created." if same else "MISMATCH: these words do not produce the same wallet.")
        sys.exit(0 if same else 1)
    if a.cmd == "new":
        print("RECOVERY WORDS (write them on paper, in order; never photograph or type them elsewhere):\n")
        parts = mnemonic.split()
        for i in range(0, len(parts), 4):
            print("   " + "   ".join("%2d. %-9s" % (i + j + 1, parts[i + j]) for j in range(4)))
        print()
    if a.out:
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(descs, f)
        return
    if not a.json:
        print("Private descriptors for `truenorth-cli importdescriptors` (as secret as the words):\n")
    print(json.dumps(descs))


if __name__ == "__main__":
    main()
