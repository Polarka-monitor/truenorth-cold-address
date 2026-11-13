#!/bin/sh
# Runs every check in this repository. Needs Python 3.9 or newer and the official TrueNorth Core v30.5.4
# programs: in ./bin, in an unpacked release folder next to cold-address.py, or in the folder named by TN_BIN.
set -e
cd "$(dirname "$0")/.."

echo "== tn-seed.py selftest"
python3 tn-seed.py selftest

echo "== the procedure, through a pseudo-terminal"
python3 tests/test_ceremony.py

echo "== spending on regtest"
python3 tests/test_spend.py

echo "== test vectors"
tmp=$(mktemp)
python3 vectors/tnvec.py "$tmp" > /dev/null
cmp "$tmp" vectors/p2qrh-test-vectors.json
rm -f "$tmp"
echo "reproduced byte for byte"

echo "== checksums"
if command -v sha256sum > /dev/null 2>&1; then sha256sum -c FILES.sha256; else shasum -a 256 -c FILES.sha256; fi

echo
echo "Everything passed."
