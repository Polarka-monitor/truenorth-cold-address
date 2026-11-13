#!/usr/bin/env python3
"""Review check T2: tn-seed.py against the official BIP39 vectors and against an independent implementation
(the reference library 'mnemonic' 0.21 by Trezor). No secrets involved; random test values only."""
import hashlib, importlib.util, json, os, random, sys, types

SRC = sys.argv[1]            # folder with tn-seed.py and english.txt (the reviewed copy)
VEC = sys.argv[2]            # official vectors.json
sys.path.insert(0, sys.argv[3])   # independent library
from mnemonic import Mnemonic     # noqa: E402

data = open(os.path.join(SRC, "tn-seed.py"), "rb").read()
print("tn-seed.py sha256", hashlib.sha256(data).hexdigest())
tn = types.ModuleType("tnseed"); tn.__file__ = os.path.join(SRC, "tn-seed.py")
exec(compile(data, tn.__file__, "exec"), tn.__dict__)
words = tn.wordlist()
ref = Mnemonic("english")
assert ref.wordlist == words, "word lists differ"
print("word list identical to the reference library's list: yes (2048 words)")

fails = 0
vec = json.load(open(VEC))["english"]
for ent_hex, mnem, seed_hex, xprv in vec:
    ent = bytes.fromhex(ent_hex)
    ok = (tn.to_mnemonic(ent, words) == mnem and tn.check_mnemonic(mnem, words) is None
          and tn.bip39_seed(mnem, "TREZOR").hex() == seed_hex
          and tn.master_xprv(bytes.fromhex(seed_hex), bytes.fromhex("0488ade4")) == xprv)
    fails += not ok
print("official BIP39 vectors (entropy -> words -> seed -> root xprv): %d of %d pass" % (len(vec) - fails, len(vec)))

rng = random.Random(20261113)
N1, N2 = 20000, 400
bad = 0
for _ in range(N1):
    ent = rng.randbytes(32)
    m = tn.to_mnemonic(ent, words)
    if m != ref.to_mnemonic(ent) or bytes(ref.to_entropy(m)) != ent or tn.check_mnemonic(m, words) is not None \
            or len(m.split()) != 24:
        bad += 1
print("random 256-bit entropies, words equal to the reference and back to the same entropy: %d of %d" % (N1 - bad, N1))
bad = 0
for _ in range(N2):
    m = tn.to_mnemonic(rng.randbytes(32), words)
    if tn.bip39_seed(m) != Mnemonic.to_seed(m, ""):
        bad += 1
print("random phrases, 64-byte seed equal to the reference: %d of %d" % (N2 - bad, N2))

# validity decisions must agree with the reference for damaged phrases
agree = accepted = 0
N3 = 20000
for _ in range(N3):
    parts = tn.to_mnemonic(rng.randbytes(32), words).split()
    kind = rng.randrange(3)
    if kind == 0:                      # one word replaced
        i = rng.randrange(24); parts[i] = rng.choice([w for w in rng.sample(words, 3) if w != parts[i]])
    elif kind == 1:                    # two neighbours swapped
        i = rng.randrange(23); parts[i], parts[i + 1] = parts[i + 1], parts[i]
    else:                              # one word dropped, another doubled
        i = rng.randrange(24); parts[i] = parts[(i + 1) % 24]
    m = " ".join(parts)
    mine = tn.check_mnemonic(m, words) is None
    agree += mine == ref.check(m)
    accepted += mine
print("damaged phrases: validity decision equal to the reference in %d of %d; %d (%.2f %%) pass the checksum by chance"
      % (agree, N3, accepted, 100.0 * accepted / N3))
print("RESULT", "OK" if fails == 0 and bad == 0 and agree == N3 else "FAIL")
