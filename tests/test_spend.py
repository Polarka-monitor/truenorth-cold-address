#!/usr/bin/env python3
"""Regtest proof that coins on an address made by cold-address.py can be spent again with the 24 words.

  python3 tests/test_spend.py

1. The tool makes an address (dry run on regtest, driven through a pseudo-terminal like a person would).
2. Blocks are mined to that address on a regtest node.
3. Route A (README "Spending", simple route): tn-seed.py turns the words into descriptors, a wallet on the
   node imports them, rescans and sweeps the address with sendall.
4. Route B (air-gapped): the node that knows the chain builds a PSBT without any key; a second node that has
   no chain and no connection holds the restored wallet and signs; the first node broadcasts.

Needs the official TrueNorth Core programs, found the same way as in test_ceremony.py.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ptydriver as pd   # noqa: E402

tool = pd.load_tool()
BIN = tool.find_bin()


class RegtestNode:
    def __init__(self, name):
        self.dir = tempfile.mkdtemp(prefix="tn-spendtest-%s-" % name)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        self.proc = subprocess.Popen(
            [os.path.join(BIN, "truenorthd"), "-datadir=" + self.dir, "-chain=regtest", "-listen=0", "-connect=0",
             "-dnsseed=0", "-fixedseeds=0", "-server=1", "-rpcport=%d" % self.port, "-printtoconsole=0"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            try:
                self.cli("getblockcount")
                return
            except Exception:
                time.sleep(1)
        raise SystemExit("node %s did not start" % name)

    def cli(self, *args, stdin=None, wallet=None):
        cmd = [os.path.join(BIN, "truenorth-cli"), "-datadir=" + self.dir, "-chain=regtest", "-rpcport=%d" % self.port]
        if wallet:
            cmd.append("-rpcwallet=" + wallet)
        r = subprocess.run(cmd + list(args), input=stdin, capture_output=True, text=True, timeout=600)
        if r.returncode:
            raise RuntimeError("%s: %s" % (" ".join(args[:2]), r.stderr.strip()[:300]))
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
            self.proc.wait(timeout=40)
        except Exception:
            self.proc.kill()
        shutil.rmtree(self.dir, ignore_errors=True)


def restore_descriptors(kit, words):
    """What the README tells a user to do: tn-seed.py restore --out FILE, typing the words when asked."""
    path = os.path.join(kit, "cold-keys.json")
    r = subprocess.run([sys.executable, os.path.join(kit, "tn-seed.py"), "restore", "--chain", "regtest", "--out", path],
                       input=" ".join(words) + "\n", capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return path


def step(text):
    print("ok    " + text)


kit = pd.fresh_kit()
online, offline = RegtestNode("online"), RegtestNode("offline")
try:
    rc, words, _ = pd.new_ceremony(kit, BIN, "regtest")
    assert rc == 0
    addr = open(os.path.join(kit, "out-dry-run", "cold-address.txt")).read().strip()
    step("the tool made the cold address " + addr)

    online.cli("generatetoaddress", "110", addr)
    scan = online.cli("scantxoutset", "start", json.dumps(["addr(%s)" % addr]))
    assert len(scan["unspents"]) == 110
    step("110 blocks mined to it; scantxoutset (no wallet needed) sees %s NORTH" % scan["total_amount"])
    online.cli("-named", "createwallet", "wallet_name=elsewhere")
    dest_a = online.cli("getnewaddress", wallet="elsewhere")
    dest_b = online.cli("getnewaddress", wallet="elsewhere")
    keys = restore_descriptors(kit, words)

    # Route B first, while all coins are still on the cold address: one mature output, signed by the offline node
    offline.cli("-named", "createwallet", "wallet_name=coldspend", "blank=true")
    res = offline.cli("-stdin", "importdescriptors", stdin=open(keys).read() + "\n", wallet="coldspend")
    assert all(r["success"] for r in res), res
    assert offline.cli("getblockcount") == 0
    tip = online.cli("getblockcount")
    utxo = [u for u in scan["unspents"] if u["height"] <= tip - 100][0]
    amount = "%.8f" % (float(utxo["amount"]) - 0.0001)
    psbt = online.cli("createpsbt", json.dumps([{"txid": utxo["txid"], "vout": utxo["vout"]}]), json.dumps([{dest_b: amount}]))
    psbt = online.cli("utxoupdatepsbt", psbt)
    seen = offline.cli("decodepsbt", psbt)
    assert abs(float(seen["fee"]) - 0.0001) < 1e-9 and seen["tx"]["vout"][0]["scriptPubKey"]["address"] == dest_b
    step("route B: the offline node shows the destination and the fee (%.8f NORTH) before signing" % float(seen["fee"]))
    signed = offline.cli("walletprocesspsbt", psbt, wallet="coldspend")
    assert signed["complete"]
    final = online.cli("finalizepsbt", signed["psbt"])
    assert final["complete"]
    txid = online.cli("sendrawtransaction", final["hex"])
    block = online.cli("generatetoaddress", "1", dest_a)[0]
    assert online.cli("getrawtransaction", txid, "1", block)["confirmations"] == 1
    step("route B: signed by a node with no chain and no connection, broadcast and confirmed (%s...)" % txid[:16])

    # Route A: restore on the node itself, rescan, sweep
    online.cli("-named", "createwallet", "wallet_name=coldspend", "blank=true")
    res = online.cli("-stdin", "importdescriptors", stdin=open(keys).read() + "\n", wallet="coldspend")
    assert all(r["success"] for r in res), res
    online.cli("rescanblockchain", wallet="coldspend")
    bal = online.cli("getbalances", wallet="coldspend")["mine"]
    assert float(bal["trusted"]) > 0 and float(bal["immature"]) > 0
    step("route A: the restored wallet sees %s NORTH spendable and %s NORTH immature" % (bal["trusted"], bal["immature"]))
    sweep = online.cli("-named", "sendall", 'recipients=["%s"]' % dest_a, "fee_rate=1", wallet="coldspend")
    assert sweep["complete"]
    left = online.cli("getbalances", wallet="coldspend")["mine"]
    assert float(left["trusted"]) == 0 and float(left["immature"]) > 0
    block = online.cli("generatetoaddress", "1", dest_b)[0]
    tx = online.cli("getrawtransaction", sweep["txid"], "1", block)
    assert tx["confirmations"] == 1 and len(tx["vout"]) == 1
    step("route A: sendall swept %d outputs into one payment of %s NORTH, confirmed; only immature coins remain"
         % (len(tx["vin"]), tx["vout"][0]["value"]))
    print()
    print("All spending checks passed.")
finally:
    online.stop()
    offline.stop()
    shutil.rmtree(kit, ignore_errors=True)
