#!/usr/bin/env python3
"""tnvec: P2QRH test vectors for TrueNorth (NORTH), made by an implementation that shares no code with
TrueNorth Core and checked against the official v30.5.4 programs on regtest.

What it does:
  1. derives keys and P2QRH addresses from the public BIP39 test phrase (m/88h/COINh/0h/branch/index),
  2. builds a two-input P2QRH key-path spend, computes the BIP-341 signature hash and signs with BIP-340,
  3. asks TrueNorth Core (regtest) to accept and mine that transaction,
  4. checks that signatures made by Core's own wallet for the same transaction verify against the
     signature hash computed here (so both sides hash the same message),
  5. records how Core rejects a set of deliberately broken spends,
  6. funds an output that commits to the reserved scheme id 0x02 and records that Core refuses to spend it,
     in the mempool and in a block,
  7. writes everything to p2qrh-test-vectors.json.

Python standard library only. The keys in the output belong to a public test phrase: never send coins to them
on mainnet.

  python3 vectors/tnvec.py [output.json]

The TrueNorth Core programs are found the same way as by cold-address.py (./bin, an unpacked release folder
next to it, or the folder named by the TN_BIN environment variable). Running it again gives the same file,
byte for byte: regtest coinbase transactions and BIP-340 signatures with a fixed auxiliary value are deterministic.
"""
import hashlib
import hmac
import importlib.util
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("coldaddress", os.path.join(os.path.dirname(HERE), "cold-address.py"))
sa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sa)          # secp256k1 arithmetic, BIP32 and bech32m live in cold-address.py
P, N, H = sa._P, sa._N, 0x80000000
MNEMONIC = "abandon " * 11 + "about"
TAG = b"TrueNorth/QRH/v1"
SCHNORR = 0x01


def sha(b):
    return hashlib.sha256(b).digest()


def tagged(tag, msg):
    t = sha(tag.encode())
    return sha(t + t + msg)


def b32(i):
    return i.to_bytes(32, "big")


# ---------------------------------------------------------------- keys and addresses

def derive_key(seed, chain, branch, index):
    coin = sa.CHAINS[chain][1]
    d = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = int.from_bytes(d[:32], "big"), d[32:]
    for i in (88 | H, coin | H, H, branch, index):
        k, c = sa._ckd(k, c, i)
    return k


def commitment(scheme_id, pubkey, script_root=bytes(32)):
    return sha(TAG + bytes([scheme_id]) + pubkey + script_root)


def key_info(seed, chain, branch, index):
    k = derive_key(seed, chain, branch, index)
    x = b32(sa._mul(k)[0])
    c = commitment(SCHNORR, x)
    return {"path": "m/88h/%dh/0h/%d/%d" % (sa.CHAINS[chain][1], branch, index), "private_key": b32(k).hex(),
            "xonly_pubkey": x.hex(), "commitment": c.hex(), "scriptPubKey": (b"\x52\x20" + c).hex(),
            "address": sa._bech32m(sa.CHAINS[chain][0], 2, c)}


# ---------------------------------------------------------------- BIP-340

def lift_x(x):
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    if pow(y, 2, P) != (pow(x, 3, P) + 7) % P:
        return None
    return x, y if y % 2 == 0 else P - y


def schnorr_sign(msg, seckey, aux=bytes(32)):
    pt = sa._mul(seckey)
    d = seckey if pt[1] % 2 == 0 else N - seckey
    t = b32(d ^ int.from_bytes(tagged("BIP0340/aux", aux), "big"))
    k0 = int.from_bytes(tagged("BIP0340/nonce", t + b32(pt[0]) + msg), "big") % N
    r = sa._mul(k0)
    k = k0 if r[1] % 2 == 0 else N - k0
    e = int.from_bytes(tagged("BIP0340/challenge", b32(r[0]) + b32(pt[0]) + msg), "big") % N
    sig = b32(r[0]) + b32((k + e * d) % N)
    assert schnorr_verify(msg, b32(pt[0]), sig)
    return sig


def schnorr_verify(msg, pubkey, sig):
    pt = lift_x(int.from_bytes(pubkey, "big"))
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big")
    if pt is None or r >= P or s >= N:
        return False
    e = int.from_bytes(tagged("BIP0340/challenge", sig[:32] + pubkey + msg), "big") % N
    neg = (pt[0], P - pt[1])
    rr = sa._add(sa._mul(s), _mul_point(neg, e))
    return rr is not None and rr[1] % 2 == 0 and rr[0] == r


def _mul_point(pt, k):
    res = None
    while k:
        if k & 1:
            res = sa._add(res, pt)
        pt = sa._add(pt, pt)
        k >>= 1
    return res


# ---------------------------------------------------------------- transactions

def cs(n):
    return bytes([n]) if n < 0xFD else b"\xfd" + struct.pack("<H", n)


def ser_out(amount, spk):
    return struct.pack("<q", amount) + cs(len(spk)) + spk


def ser_tx(version, vin, vout, locktime, witnesses=None):
    b = struct.pack("<i", version) + (b"\x00\x01" if witnesses is not None else b"") + cs(len(vin))
    for txid, n, seq in vin:
        b += bytes.fromhex(txid)[::-1] + struct.pack("<I", n) + b"\x00" + struct.pack("<I", seq)
    b += cs(len(vout)) + b"".join(ser_out(a, s) for a, s in vout)
    for w in witnesses or []:
        b += cs(len(w)) + b"".join(cs(len(i)) + i for i in w)
    return b + struct.pack("<I", locktime)


def sighash_parts(vin, prevouts, vout):
    """The five SHA256 values of BIP-341 that are shared by all inputs of a transaction."""
    return {"sha_prevouts": sha(b"".join(bytes.fromhex(t)[::-1] + struct.pack("<I", n) for t, n, _ in vin)),
            "sha_amounts": sha(b"".join(struct.pack("<q", a) for a, _ in prevouts)),
            "sha_scriptpubkeys": sha(b"".join(cs(len(s)) + s for _, s in prevouts)),
            "sha_sequences": sha(b"".join(struct.pack("<I", s) for _, _, s in vin)),
            "sha_outputs": sha(b"".join(ser_out(a, s) for a, s in vout))}


def sighash(version, locktime, vin, prevouts, vout, index, hash_type=0):
    """BIP-341 signature hash for a key-path spend, no annex (the message P2QRH signs under scheme 0x01)."""
    p = sighash_parts(vin, prevouts, vout)
    msg = bytes([hash_type]) + struct.pack("<i", version) + struct.pack("<I", locktime)
    msg += p["sha_prevouts"] + p["sha_amounts"] + p["sha_scriptpubkeys"] + p["sha_sequences"] + p["sha_outputs"]
    msg += b"\x00" + struct.pack("<I", index)
    return tagged("TapSighash", b"\x00" + msg)


def txid_of(version, vin, vout, locktime):
    return sha(sha(ser_tx(version, vin, vout, locktime)))[::-1].hex()


# ---------------------------------------------------------------- TrueNorth Core on regtest

class Node:
    def __init__(self, bindir):
        self.bin, self.d = bindir, tempfile.mkdtemp(prefix="tn-vec-")
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        self.p = subprocess.Popen([bindir + "/truenorthd", "-datadir=" + self.d, "-chain=regtest", "-listen=0", "-connect=0",
                                   "-dnsseed=0", "-fixedseeds=0", "-server=1", "-rpcport=%d" % self.port, "-printtoconsole=0"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            try:
                self.cli("getblockcount")
                return
            except Exception:
                time.sleep(1)
        raise SystemExit("node did not start")

    def cli(self, *a, stdin=None, wallet=None):
        cmd = [self.bin + "/truenorth-cli", "-datadir=" + self.d, "-chain=regtest", "-rpcport=%d" % self.port]
        r = subprocess.run(cmd + (["-rpcwallet=" + wallet] if wallet else []) + list(a), input=stdin,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=600)
        if r.returncode:
            raise RuntimeError(r.stderr.strip()[:700])
        try:
            return json.loads(r.stdout)
        except ValueError:
            return r.stdout.strip()

    def stop(self):
        try:
            self.cli("stop")
        except Exception:
            pass
        try:
            self.p.wait(timeout=40)
        except Exception:
            self.p.kill()
        shutil.rmtree(self.d, ignore_errors=True)


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "p2qrh-test-vectors.json")
    tn = sa.load_tnseed()
    seed = tn.bip39_seed(MNEMONIC)
    vec = {"description": "P2QRH test vectors for TrueNorth (NORTH). Keys come from the public BIP39 test phrase; test use only.",
           "made_with": "vectors/tnvec.py (Python standard library only, no code shared with TrueNorth Core); "
                        "every value was checked against TrueNorth Core v30.5.4 on regtest",
           "mnemonic": MNEMONIC, "bip39_passphrase": "", "seed": seed.hex(), "derivation": "m/88h/COINh/0h/branch/index, x-only key",
           "commitment_formula": "SHA256('TrueNorth/QRH/v1' || scheme_id || xonly_pubkey || script_root), script_root = 32 zero bytes",
           "chains": {}}
    for chain in ("main", "regtest"):
        version, coin = tn.CHAINS[chain]
        vec["chains"][chain] = {"hrp": sa.CHAINS[chain][0], "coin_type": coin, "master_xprv": tn.master_xprv(seed, version),
                                "descriptors": [d["desc"] for d in tn.descriptors(tn.master_xprv(seed, version), coin)],
                                "keys": [key_info(seed, chain, b, i) for b, i in ((0, 0), (0, 1), (0, 2), (1, 0), (1, 1))]}
    keys = {k["path"]: k for k in vec["chains"]["regtest"]["keys"]}
    k00, k01, k02, k10, k11 = (keys["m/88h/1h/0h/%s" % s] for s in ("0/0", "0/1", "0/2", "1/0", "1/1"))
    # the same key as 1/1, but committed under the reserved scheme id 0x02 (see step 6 above)
    c2 = commitment(0x02, bytes.fromhex(k11["xonly_pubkey"]))
    spk2, addr2 = b"\x52\x20" + c2, sa._bech32m(sa.CHAINS["regtest"][0], 2, c2)

    node = Node(sa.find_bin())
    try:
        # Core must derive the same addresses from the descriptors (receive and change branch)
        for d, want in zip(vec["chains"]["regtest"]["descriptors"], ([k00, k01, k02], [k10])):
            got = node.cli("-stdin", "deriveaddresses", stdin=d + "\n[0,%d]\n" % (len(want) - 1))
            assert got == [w["address"] for w in want], (got, want)
        node.cli("generatetoaddress", "1", k00["address"])
        node.cli("generatetoaddress", "1", k01["address"])
        node.cli("generatetoaddress", "1", addr2)
        node.cli("generatetoaddress", "100", k02["address"])
        prev = []
        for h, k in ((1, k00), (2, k01)):
            cb = node.cli("getblock", node.cli("getblockhash", str(h)), "2")["tx"][0]
            assert cb["vout"][0]["scriptPubKey"]["hex"] == k["scriptPubKey"]
            prev.append((cb["txid"], 0, round(cb["vout"][0]["value"] * 10 ** 8), k))
        version, locktime, seq, fee = 2, 0, 0xFFFFFFFD, 20000
        vin = [(t, n, seq) for t, n, _, _ in prev]
        prevouts = [(a, bytes.fromhex(k["scriptPubKey"])) for _, _, a, k in prev]
        total = sum(a for a, _ in prevouts)
        vout = [(1000 * 10 ** 8, bytes.fromhex(k10["scriptPubKey"])), (total - 1000 * 10 ** 8 - fee, bytes.fromhex(k02["scriptPubKey"]))]
        hashes = [sighash(version, locktime, vin, prevouts, vout, i) for i in range(2)]
        sigs = [schnorr_sign(hashes[i], int(prev[i][3]["private_key"], 16)) for i in range(2)]
        wit = [[sigs[i], bytes.fromhex(prev[i][3]["xonly_pubkey"]), bytes([SCHNORR])] for i in range(2)]
        raw = ser_tx(version, vin, vout, locktime, wit).hex()
        unsigned = ser_tx(version, vin, vout, locktime).hex()

        def accept(hexstr):
            r = node.cli("testmempoolaccept", json.dumps([hexstr]))[0]
            return r["allowed"], r.get("reject-reason", ""), r.get("vsize")

        ok, why, vsize = accept(raw)
        assert ok, why

        # Core's own wallet signs the same unsigned transaction; its signatures must verify against our hashes
        node.cli("-named", "createwallet", "wallet_name=core", "blank=true")
        res = node.cli("-stdin", "importdescriptors", stdin=json.dumps(tn.descriptors(vec["chains"]["regtest"]["master_xprv"], 1)) + "\n", wallet="core")
        assert all(r["success"] for r in res), res
        core_signed = node.cli("signrawtransactionwithwallet", unsigned, wallet="core")
        assert core_signed["complete"]
        core_wit = [i["txinwitness"] for i in node.cli("decoderawtransaction", core_signed["hex"])["vin"]]
        core_ok = [schnorr_verify(hashes[i], bytes.fromhex(core_wit[i][1]), bytes.fromhex(core_wit[i][0])) and core_wit[i][2] == "01" for i in range(2)]
        assert all(core_ok), core_ok

        def broken(name, mutate):
            w = [list(x) for x in wit]
            mutate(w)
            allowed, reason, _ = accept(ser_tx(version, vin, vout, locktime, w).hex())
            assert not allowed, name
            return {"name": name, "witness_input_0": [i.hex() for i in w[0]], "core_reject_reason": reason}

        other_sig = schnorr_sign(hashes[0], int(k02["private_key"], 16))
        bad = [
            broken("scheme id 0x02 (reserved, not active)", lambda w: w[0].__setitem__(2, b"\x02")),
            broken("scheme id 0x00", lambda w: w[0].__setitem__(2, b"\x00")),
            broken("public key of another wallet key, with that key's valid signature", lambda w: (w[0].__setitem__(0, other_sig), w[0].__setitem__(1, bytes.fromhex(k02["xonly_pubkey"])))),
            broken("signature with the last bit flipped", lambda w: w[0].__setitem__(0, sigs[0][:63] + bytes([sigs[0][63] ^ 1]))),
            broken("extra witness item before the signature", lambda w: w[0].insert(0, b"\x01")),
            broken("scheme id missing (signature and key only)", lambda w: w[0].pop()),
        ]

        txid = node.cli("sendrawtransaction", raw)
        assert txid == txid_of(version, vin, vout, locktime)
        blk = node.cli("generatetoaddress", "1", k02["address"])[0]
        conf = node.cli("getrawtransaction", txid, "1", blk)["confirmations"]
        assert conf == 1
        vec["spend"] = {
            "chain": "regtest", "what": "two P2QRH key-path inputs (keys 0/0 and 0/1), outputs to 1/0 and 0/2, SIGHASH_DEFAULT",
            "version": version, "locktime": locktime,
            "inputs": [{"txid": t, "vout": n, "sequence": seq, "amount_sat": a, "scriptPubKey": k["scriptPubKey"], "key_path": k["path"]} for t, n, a, k in prev],
            "outputs": [{"amount_sat": a, "scriptPubKey": s.hex()} for a, s in vout],
            "sighash_intermediates": {k: v.hex() for k, v in sighash_parts(vin, prevouts, vout).items()},
            "signature_hashes": [h.hex() for h in hashes], "bip340_aux_rand": bytes(32).hex(),
            "signatures": [s.hex() for s in sigs],
            "witness_layout": "per input, in serialization order: signature (64 bytes), x-only public key (32 bytes), scheme id (1 byte, 0x01)",
            "unsigned_tx": unsigned, "signed_tx": raw, "txid": txid, "vsize": vsize, "fee_sat": fee,
            "core_result": "accepted by testmempoolaccept, broadcast, confirmed in a block",
            "core_wallet_signatures_verify_against_these_hashes": all(core_ok),
        }
        vec["invalid_spends"] = {"note": "same transaction with input 0's witness changed; reject reasons as returned by TrueNorth Core v30.5.4", "cases": bad}

        # step 6: the coinbase of block 3 pays to the scheme 0x02 commitment; try to spend it both ways
        cb = node.cli("getblock", node.cli("getblockhash", "3"), "2")["tx"][0]
        assert cb["vout"][0]["scriptPubKey"]["hex"] == spk2.hex()
        amount2 = round(cb["vout"][0]["value"] * 10 ** 8)
        vin2, prevouts2 = [(cb["txid"], 0, seq)], [(amount2, spk2)]
        vout2 = [(amount2 - fee, bytes.fromhex(k10["scriptPubKey"]))]
        sig2 = schnorr_sign(sighash(version, locktime, vin2, prevouts2, vout2, 0), int(k11["private_key"], 16))
        attempts = []
        for scheme in (0x02, 0x01):
            tx2 = ser_tx(version, vin2, vout2, locktime, [[sig2, bytes.fromhex(k11["xonly_pubkey"]), bytes([scheme])]]).hex()
            allowed, reason, _ = accept(tx2)
            assert not allowed
            try:
                node.cli("generateblock", k02["address"], json.dumps([tx2]))
                raise SystemExit("a block with the scheme 0x%02x spend was accepted" % scheme)
            except RuntimeError as e:
                block_reason = str(e).replace("error code: -25\nerror message:\n", "")
            attempts.append({"witness_scheme_id": scheme, "signed_tx": tx2, "mempool_reject_reason": reason,
                             "block_reject_reason": block_reason})
        # control: the same one-input construction is accepted when the output was made with scheme 0x01
        cb = node.cli("getblock", node.cli("getblockhash", "4"), "2")["tx"][0]
        amount3, spk3 = round(cb["vout"][0]["value"] * 10 ** 8), bytes.fromhex(k02["scriptPubKey"])
        assert cb["vout"][0]["scriptPubKey"]["hex"] == spk3.hex()
        vin3, vout3 = [(cb["txid"], 0, seq)], [(amount3 - fee, bytes.fromhex(k10["scriptPubKey"]))]
        sig3 = schnorr_sign(sighash(version, locktime, vin3, [(amount3, spk3)], vout3, 0), int(k02["private_key"], 16))
        ok3, why3, _ = accept(ser_tx(version, vin3, vout3, locktime, [[sig3, bytes.fromhex(k02["xonly_pubkey"]), bytes([SCHNORR])]]).hex())
        assert ok3, why3
        cb = node.cli("getblock", node.cli("getblockhash", "3"), "2")["tx"][0]
        vec["reserved_scheme_output"] = {
            "note": "An output that commits to scheme id 0x02 cannot be spent under the rules of v30.5.4: a witness with "
                    "scheme id 0x02 is refused, and a witness with scheme id 0x01 gives a different commitment. "
                    "Wallets must not create such outputs.",
            "chain": "regtest", "key_path": k11["path"], "scheme_id": 2, "commitment": c2.hex(), "scriptPubKey": spk2.hex(),
            "address": addr2, "funding": {"txid": cb["txid"], "vout": 0, "amount_sat": amount2, "block_height": 3},
            "spend_attempts": attempts,
            "control": "the same one-input transaction shape, spending the scheme 0x01 output of block 4 with key 0/2, "
                       "is accepted by testmempoolaccept"}
    finally:
        node.stop()
    with open(out_path, "w") as f:
        json.dump(vec, f, indent=1)
        f.write("\n")
    print("written", out_path)
    print("regtest address 0/0:", k00["address"])
    print("mainnet address 0/0:", vec["chains"]["main"]["keys"][0]["address"])
    print("signed tx accepted and mined, txid", vec["spend"]["txid"], "vsize", vec["spend"]["vsize"])
    for c in bad:
        print("rejected: %-70s -> %s" % (c["name"], c["core_reject_reason"]))
    for c in vec["reserved_scheme_output"]["spend_attempts"]:
        print("scheme 0x02 output, witness scheme id 0x%02x: mempool: %s | block: %s"
              % (c["witness_scheme_id"], c["mempool_reject_reason"], c["block_reject_reason"]))


if __name__ == "__main__":
    main()
