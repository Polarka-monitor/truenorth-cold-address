#!/usr/bin/env python3
"""Compares this set of P2QRH test vectors with the set that TrueNorth Core publishes.

  ours:  vectors/p2qrh-test-vectors.json (made by vectors/tnvec.py)
  Core:  src/test/data/p2qrh_wallet_vectors.json of github.com/truenorth-project/truenorth

Every value of Core's file is computed again here with the code behind our set (cold-address.py and tnvec.py:
Python standard library only, no code shared with TrueNorth Core or its test framework) and compared. Nothing
is taken from Core's generator. The witnesses that must be refused are judged by the order of the P2QRH rules
as it reads in src/script/interpreter.cpp (master, commit ed6d245): that part is a model of the rules, written
down by hand, and not a second implementation of consensus.

  python3 vectors/compare-upstream.py PATH/TO/p2qrh_wallet_vectors.json

Exit status 0 if nothing differs. No node is needed and nothing is written.
"""
import hashlib
import hmac
import importlib.util
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if len(sys.argv) != 2:
    raise SystemExit(__doc__)
UP_JSON, OUR_JSON = sys.argv[1], os.path.join(HERE, "p2qrh-test-vectors.json")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tv = load("tnvec", os.path.join(HERE, "tnvec.py"))
sa = tv.sa
tn = sa.load_tnseed()            # checks tn-seed.py and english.txt against the sums pinned in cold-address.py
U = json.load(open(UP_JSON))
O = json.load(open(OUR_JSON))
H = 0x80000000

results = []


def check(group, name, ok, detail=""):
    results.append((group, name, bool(ok), detail))


# ---------------------------------------------------------------- small tools that our kit does not have

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode_check(s):
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(s) - len(s.lstrip("1"))) + raw
    payload, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != chk:
        raise ValueError("base58 checksum")
    return payload


def hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def pub33(k):
    x, y = sa._mul(k)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def derive(seed, path):
    """BIP32 from the seed along hardened/unhardened indexes; returns key, chain code, depth, parent fingerprint, child."""
    d = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c, depth, parent, child = int.from_bytes(d[:32], "big"), d[32:], 0, bytes(4), 0
    for i in path:
        parent = hash160(pub33(k))[:4]
        k, c = sa._ckd(k, c, i)
        depth, child = depth + 1, i
    return k, c, depth, parent, child


def ext(version, node, private):
    k, c, depth, parent, child = node
    key = b"\0" + k.to_bytes(32, "big") if private else pub33(k)
    return tn.b58check(version + bytes([depth]) + parent + child.to_bytes(4, "big") + c + key)


def parse_path(p):
    return [int(s[:-1]) | H if s.endswith("h") else int(s) for s in p.split("/")[1:]]


def bech32_decode(addr):
    if addr.lower() != addr and addr.upper() != addr:
        return None, "mixed case"
    a = addr.lower()
    pos = a.rfind("1")
    if pos < 1 or pos + 7 > len(a):
        return None, "no separator"
    hrp, data = a[:pos], a[pos + 1:]
    if any(ch not in sa._B32 for ch in data):
        return None, "bad character"
    vals = [sa._B32.index(ch) for ch in data]
    pm = sa._polymod([ord(ch) >> 5 for ch in hrp] + [0] + [ord(ch) & 31 for ch in hrp] + vals)
    enc = "bech32m" if pm == 0x2BC830A3 else "bech32" if pm == 1 else None
    if enc is None:
        return None, "bad checksum"
    acc = bits = 0
    prog = bytearray()
    for v in vals[1:-6]:
        acc, bits = acc << 5 | v, bits + 5
        while bits >= 8:
            bits -= 8
            prog.append(acc >> bits & 255)
    if bits >= 5 or acc & ((1 << bits) - 1):
        return None, "bad padding"
    return (hrp, vals[0], bytes(prog), enc), None


def p2qrh_problem(addr, hrp):
    """None if this is a P2QRH address of the chain with that prefix; otherwise why not."""
    d, err = bech32_decode(addr)
    if err:
        return err
    got_hrp, ver, prog, enc = d
    if got_hrp != hrp:
        return "other chain (%s)" % got_hrp
    if (ver == 0) != (enc == "bech32"):
        return "checksum kind does not fit the witness version"
    if ver != 2 or len(prog) != 32:
        return "witness v%d with a %d-byte program: valid address, not P2QRH" % (ver, len(prog))
    return None


def parse_tx(raw):
    b, p = bytes.fromhex(raw), 0

    def take(n):
        nonlocal p
        r = b[p:p + n]
        assert len(r) == n
        p += n
        return r

    def varint():
        n = take(1)[0]
        return n if n < 0xFD else struct.unpack("<H", take(2))[0] if n == 0xFD else struct.unpack("<I", take(4))[0]

    version = struct.unpack("<i", take(4))[0]
    segwit = b[p:p + 2] == b"\x00\x01"
    if segwit:
        take(2)
    vin = []
    for _ in range(varint()):
        txid, n = take(32)[::-1].hex(), struct.unpack("<I", take(4))[0]
        assert varint() == 0
        vin.append((txid, n, struct.unpack("<I", take(4))[0]))
    vout = []
    for _ in range(varint()):
        a = struct.unpack("<q", take(8))[0]
        vout.append((a, take(varint())))
    wit = [[take(varint()) for _ in range(varint())] for _ in vin] if segwit else None
    locktime = struct.unpack("<I", take(4))[0]
    assert p == len(b)
    return version, vin, vout, locktime, wit


def sigmsg(version, locktime, vin, prevouts, vout, index, hash_type):
    """BIP-341 signature message for a key-path spend without annex, every hash type; first byte is the epoch."""
    base, acp = hash_type & 3, hash_type & 0x80
    p = tv.sighash_parts(vin, prevouts, vout)
    m = bytes([hash_type]) + struct.pack("<i", version) + struct.pack("<I", locktime)
    if not acp:
        m += p["sha_prevouts"] + p["sha_amounts"] + p["sha_scriptpubkeys"] + p["sha_sequences"]
    if base not in (2, 3):
        m += p["sha_outputs"]
    m += b"\x00"
    if acp:
        (t, n, seq), (a, s) = vin[index], prevouts[index]
        m += bytes.fromhex(t)[::-1] + struct.pack("<I", n) + struct.pack("<q", a) + tv.cs(len(s)) + s + struct.pack("<I", seq)
    else:
        m += struct.pack("<I", index)
    if base == 3:
        m += tv.sha(tv.ser_out(*vout[index]))
    return b"\x00" + m


def sighash(*a):
    return tv.tagged("TapSighash", sigmsg(*a))


def verdict(stack, program, tx, prevouts, index):
    """The order of the P2QRH rules as read in src/script/interpreter.cpp at master ed6d245; None means valid."""
    st = list(stack)
    if not st:
        return "WITNESS_PROGRAM_WITNESS_EMPTY"
    if len(st) >= 2 and st[-1] and st[-1][0] == 0x50:
        return "(annex: not modelled here)"
    if len(st) < 2:
        return "QRH_WITNESS_SIZE"
    sid = st.pop()
    if len(sid) != 1:
        return "QRH_SCHEME_SIZE"
    if sid[0] != 1:
        return "QRH_SCHEME_UNKNOWN"
    if len(st) != 2:
        return "QRH_WITNESS_SIZE"
    sig, pk = st
    if len(pk) != 32:
        return "QRH_PUBKEY_SIZE"
    if tv.commitment(1, pk) != program:
        return "WITNESS_PROGRAM_MISMATCH"
    if len(sig) not in (64, 65):
        return "SCHNORR_SIG_SIZE"
    ht = sig[64] if len(sig) == 65 else 0
    if (len(sig) == 65 and ht == 0) or ht not in (0, 1, 2, 3, 0x81, 0x82, 0x83) or (ht & 3 == 3 and index >= len(tx[2])):
        return "SCHNORR_SIG_HASHTYPE"
    version, vin, vout, locktime = tx[:4]
    return None if tv.schnorr_verify(sighash(version, locktime, vin, prevouts, vout, index, ht), pk, sig[:64]) else "SCHNORR_SIG"


# ---------------------------------------------------------------- 0. our own file with the same tools (control)

seed = tn.bip39_seed(U["derivation"]["mnemonic"], U["derivation"]["passphrase"])
check("control", "our own keys recomputed from the phrase", all(
    tv.key_info(seed, ch, *[int(x) for x in k["path"].split("/")[-2:]]) == k
    for ch in ("main", "regtest") for k in O["chains"][ch]["keys"]))
sp = O["spend"]
o_tx = parse_tx(sp["signed_tx"])
o_prev = [(i["amount_sat"], bytes.fromhex(i["scriptPubKey"])) for i in sp["inputs"]]
check("control", "our own signature hashes with the general function used below", [
    sighash(o_tx[0], o_tx[3], o_tx[1], o_prev, o_tx[2], i, 0).hex() for i in range(2)] == sp["signature_hashes"])
check("control", "our own signed transaction is valid under the rule order used below", all(
    verdict(o_tx[4][i], o_prev[i][1][2:], o_tx, o_prev, i) is None for i in range(2)))

# ---------------------------------------------------------------- 1. phrase, seed, extended keys, descriptors

D = U["derivation"]
check("derivation", "same phrase and passphrase", D["mnemonic"] == O["mnemonic"] and D["passphrase"] == O["bip39_passphrase"])
check("derivation", "seed: Core = ours = PBKDF2 here", D["seed"] == O["seed"] == seed.hex())
HRP = {"main": "north", "testnet4": "tnorth4"}
OURS_FOR = {"main": "main", "testnet4": "regtest"}
versions = {}
for ch in D["chains"]:
    name = ch["chain"]
    acct_path = parse_path(ch["accountPath"])
    coin = acct_path[1] & ~H
    root_raw, acct_raw, pub_raw = (b58decode_check(ch[k]) for k in ("rootXprv", "accountXprv", "accountXpub"))
    versions[name] = (root_raw[:4].hex(), pub_raw[:4].hex())
    check("derivation", "%s: root extended private key" % name, ext(root_raw[:4], derive(seed, []), True) == ch["rootXprv"])
    check("derivation", "%s: account extended private key at %s" % (name, ch["accountPath"]),
          ext(acct_raw[:4], derive(seed, acct_path), True) == ch["accountXprv"] and acct_raw[:4] == root_raw[:4])
    check("derivation", "%s: account extended public key" % name, ext(pub_raw[:4], derive(seed, acct_path), False) == ch["accountXpub"])
    fp = hash160(pub33(derive(seed, [])[0]))[:4].hex()
    for branch, key in ((0, "receiveDescriptor"), (1, "changeDescriptor")):
        d = "qrh([%s/88h/%dh/0h]%s/%d/*)" % (fp, coin, ext(pub_raw[:4], derive(seed, acct_path), False), branch)
        check("derivation", "%s: %s with its checksum" % (name, key), d + "#" + tn.descriptor_checksum(d) == ch[key])
    ours = O["chains"][OURS_FOR[name]]
    o_root = b58decode_check(ours["master_xprv"])
    check("derivation", "%s root key against ours (%s): same key and chain code" % (name, OURS_FOR[name]),
          o_root[4:] == root_raw[4:], "version bytes: Core %s, ours %s" % (root_raw[:4].hex(), o_root[:4].hex()))
    okeys = {k["path"]: k for k in ours["keys"]}
    for k in ch["keys"]:
        priv = derive(seed, parse_path(k["path"]))[0]
        x, y = sa._mul(priv)
        xo = x.to_bytes(32, "big")
        c = tv.commitment(1, xo)
        mine = {"path": k["path"], "privkey": priv.to_bytes(32, "big").hex(), "xonlyPubkey": xo.hex(), "fullPubkeyHasOddY": bool(y & 1),
                "commitment": c.hex(), "scriptPubKey": "5220" + c.hex(), "address": sa._bech32m(HRP[name], 2, c)}
        check("keys", "%s %s: private key, x-only key, parity, commitment, script, address computed here" % (name, k["path"]), mine == k,
              "" if mine == k else json.dumps({a: (mine[a], k[a]) for a in k if mine[a] != k[a]}))
        o = okeys.get(k["path"])
        same = o and all(o[a] == k[b] for a, b in (("private_key", "privkey"), ("xonly_pubkey", "xonlyPubkey"), ("commitment", "commitment"), ("scriptPubKey", "scriptPubKey")))
        if name == "main":
            same = same and o["address"] == k["address"]
        check("keys", "%s %s: equal to the entry in our file%s" % (name, k["path"], "" if name == "main" else " (all but the address prefix)"), same)

# ---------------------------------------------------------------- 2. raw keys, addresses on every chain

for v in U["scriptPubKey"]:
    g, im, ex = v["given"], v["intermediary"], v["expected"]
    pk, root = bytes.fromhex(g["pubkey"]), bytes.fromhex(g["scriptRoot"])
    pre = tv.TAG + bytes([g["schemeId"]]) + pk + root
    c = tv.sha(pre)
    ok = pre.hex() == im["commitmentPreimage"] and c.hex() == im["commitment"] and "5220" + c.hex() == ex["scriptPubKey"]
    priv = v["comment"].rsplit(" ", 1)[1]
    ok = ok and sa._mul(int(priv, 16))[0].to_bytes(32, "big") == pk
    for net, addr in ex["addresses"].items():
        hrp = addr[:addr.rfind("1")]
        ok = ok and sa._bech32m(hrp, 2, c) == addr and p2qrh_problem(addr, hrp) is None and bech32_decode(addr)[0][2] == c
    check("addresses", "%s: preimage, commitment, script and %d addresses" % (v["comment"], len(ex["addresses"])), ok,
          "prefixes: " + ", ".join(sorted(a[:a.rfind("1")] for a in ex["addresses"].values())))
for v in U["invalidAddresses"]:
    why = p2qrh_problem(v["address"], HRP[v["chain"]])
    structurally_valid = bech32_decode(v["address"])[1] is None and why is not None and why.startswith("witness v")
    check("addresses", "refused: " + v["comment"][:70], why is not None and structurally_valid == bool(v.get("valid_but_not_p2qrh")), "our reason: %s" % why)

# ---------------------------------------------------------------- 3. signed spends

spends = []
for n, v in enumerate(U["keyPathSpending"]):
    tx = parse_tx(v["given"]["rawUnsignedTx"])
    version, vin, vout, locktime = tx[:4]
    prevouts = [(u["amount"], bytes.fromhex(u["scriptPubKey"])) for u in v["given"]["utxosSpent"]]
    parts = tv.sighash_parts(vin, prevouts, vout)
    names = {"hashAmounts": "sha_amounts", "hashOutputs": "sha_outputs", "hashPrevouts": "sha_prevouts", "hashScriptPubkeys": "sha_scriptpubkeys", "hashSequences": "sha_sequences"}
    label = "spend %d (%d input%s)" % (n + 1, len(vin), "" if len(vin) == 1 else "s")
    check("spends", label + ": the five shared hashes", all(parts[names[k]].hex() == h for k, h in v["intermediary"].items()) and len(v["intermediary"]) == 5)
    wit = []
    for i in v["inputSpending"]:
        idx, priv, ht = i["given"]["txinIndex"], int(i["given"]["privkey"], 16), i["given"]["hashType"]
        xo = sa._mul(priv)[0].to_bytes(32, "big")
        msg = sigmsg(version, locktime, vin, prevouts, vout, idx, ht)
        h = tv.tagged("TapSighash", msg)
        sig = tv.schnorr_sign(h, priv) + (bytes([ht]) if ht else b"")
        w = [sig, xo, b"\x01"]
        wit.append(w)
        ok = (xo.hex() == i["intermediary"]["xonlyPubkey"] and msg.hex() == i["intermediary"]["sigMsg"] and h.hex() == i["intermediary"]["sigHash"]
              and [x.hex() for x in w] == i["expected"]["witness"] and prevouts[idx][1] == b"\x52\x20" + tv.commitment(1, xo)
              and verdict(w, prevouts[idx][1][2:], tx, prevouts, idx) is None)
        check("spends", label + ", input %d, hash type 0x%02x: message, hash, signature, witness" % (idx, ht), ok)
    signed = tv.ser_tx(version, vin, vout, locktime, wit)
    check("spends", label + ": signed transaction, txid, wtxid", signed.hex() == v["expected"]["signedTx"]
          and tv.txid_of(version, vin, vout, locktime) == v["expected"]["txid"] and tv.sha(tv.sha(signed))[::-1].hex() == v["expected"]["wtxid"],
          "witness bytes per input: %d" % (len(tv.ser_tx(version, vin, vout, locktime, [wit[0]] + [[]] * (len(vin) - 1))) - len(tv.ser_tx(version, vin, vout, locktime)) - 2 - (len(vin) - 1)))
    spends.append((tx, prevouts))

# ---------------------------------------------------------------- 4. witnesses that must be refused

tx, prevouts = spends[0]
for v in U["invalidKeyPathSpending"]:
    got = verdict([bytes.fromhex(x) for x in v["witness"]], prevouts[0][1][2:], tx, prevouts, 0)
    check("refused", "Core: " + v["comment"][:64], got == v["scriptError"], "Core %s, rule order here %s" % (v["scriptError"], got))

print("extended key version bytes in Core's file (private, public):", versions)
for g, name, ok, detail in results:
    print("%-4s %-10s %s%s" % ("ok" if ok else "FAIL", g, name, ("   [" + detail + "]") if detail else ""))
bad = [r for r in results if not r[2]]
print("\n%d checks, %d failed" % (len(results), len(bad)))

# ---------------------------------------------------------------- 5. our six broken spends under the new rule order (a reading, not a run)

print("\nour broken spends: reason given by v30.5.4 -> error by the rule order of master ed6d245 (read from the code, not run)")
for c in O["invalid_spends"]["cases"]:
    got = verdict([bytes.fromhex(x) for x in c["witness_input_0"]], o_prev[0][1][2:], o_tx, o_prev, 0)
    print("  %-66s %s -> %s" % (c["name"], c["core_reject_reason"].split("(")[1].rstrip(")"), got))
r = O["reserved_scheme_output"]
for a in r["spend_attempts"]:
    t = parse_tx(a["signed_tx"])
    pv = [(r["funding"]["amount_sat"], bytes.fromhex(r["scriptPubKey"]))]
    print("  %-66s %s -> %s" % ("output committed to scheme 0x02, witness scheme id 0x%02x" % a["witness_scheme_id"],
                                 a["mempool_reject_reason"].split("(")[1].rstrip(")"), verdict(t[4][0], pv[0][1][2:], t, pv, 0)))
sys.exit(1 if bad else 0)
