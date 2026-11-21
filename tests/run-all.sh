#!/bin/sh
# Runs every check in this repository. The tests need Python 3.9 or newer (the tool itself runs on 3.8) and the
# official TrueNorth Core v30.5.4 programs: in ./bin, in an unpacked release folder next to cold-address.py, or
# in the folder named by TN_BIN. The test vectors are made against v30.5.5: its programs in the folder named by
# TN_VEC_BIN.
set -e
cd "$(dirname "$0")/.."

echo "== tn-seed.py selftest"
python3 tn-seed.py selftest

echo "== the procedure, through a pseudo-terminal"
python3 tests/test_ceremony.py

echo "== a stranger on the helper node's port"
python3 tests/test_port_owner.py

echo "== spending on regtest"
python3 tests/test_spend.py

echo "== the offline check and a real run, in network namespaces (Linux, root)"
python3 tests/test_linux_offline.py

echo "== test vectors (TrueNorth Core v30.5.5)"
[ -n "${TN_VEC_BIN:-}" ] || { echo "TN_VEC_BIN must name the folder with the v30.5.5 programs"; exit 1; }
tmp=$(mktemp)
TN_BIN="$TN_VEC_BIN" python3 vectors/tnvec.py "$tmp" > /dev/null
cmp "$tmp" vectors/p2qrh-test-vectors.json
rm -f "$tmp"
echo "reproduced byte for byte"

echo "== checksums"
if command -v sha256sum > /dev/null 2>&1; then sha256sum -c FILES.sha256; else shasum -a 256 -c FILES.sha256; fi

echo
echo "Everything passed."
