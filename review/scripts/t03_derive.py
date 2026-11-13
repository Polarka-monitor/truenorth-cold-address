#!/usr/bin/env python3
"""Review check T3: for many random 24-word phrases, the addresses computed by cold-address.py (pure Python)
must equal the addresses TrueNorth Core v30.5.4 derives from the descriptor that tn-seed.py builds.
Random test phrases only; nothing here is a real secret."""
import importlib.util, os, random, sys, time

SRC, BIN, CHAIN, N = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
spec = importlib.util.spec_from_file_location("coldaddress", os.path.join(SRC, "cold-address.py"))
tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
tn = tool.load_tnseed()
words = tn.wordlist()
rng = random.Random(1867 if CHAIN == "main" else 1)
node = tool.Node(BIN, CHAIN)
t0 = time.time()
bad = lead0 = 0
try:
    node.wait_ready()
    # fixed corner cases first: all-zero and all-one entropy, then random
    cases = [bytes(32), bytes([255] * 32)] + [rng.randbytes(32) for _ in range(N - 2)]
    for n, ent in enumerate(cases):
        m = tn.to_mnemonic(ent, words)
        seed = tn.bip39_seed(m)
        mine = tool.py_addresses(seed, CHAIN, 5)
        version, coin = tn.CHAINS[CHAIN]
        desc = tn.descriptors(tn.master_xprv(seed, version), coin)[0]["desc"]
        code, so, se = node.cli("-stdin", "deriveaddresses", stdin=desc + "\n[0,4]\n")
        if code != 0:
            print("Core error at phrase %d (test entropy %s): code %d, %s" % (n, ent.hex(), code, se[:400]), flush=True)
            bad += 1
            continue
        import json
        core = json.loads(so)
        if mine != core:
            bad += 1
            print("MISMATCH for test entropy", ent.hex())
        if (n + 1) % 100 == 0:
            print("  %d phrases, %d mismatches, %.0f s" % (n + 1, bad, time.time() - t0), flush=True)
    hrp = tool.CHAINS[CHAIN][0]
    print("chain %s: %d random phrases x 5 addresses, all start with %s1z: %s" % (
        CHAIN, len(cases), hrp, "checked on the last phrase: " + str(all(a.startswith(hrp + "1z") for a in mine))))
    print("chain %s: mismatches between the Python computation and TrueNorth Core: %d of %d phrases (%d addresses)"
          % (CHAIN, bad, len(cases), 5 * len(cases)))
    print("RESULT", "OK" if bad == 0 else "FAIL")
finally:
    node.stop()
