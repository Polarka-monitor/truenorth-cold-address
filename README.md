# TrueNorth cold address

A small tool that makes a cold address for TrueNorth (NORTH) on a computer that is offline.
You end up with 24 words on paper and an address you can mine or receive to. The computer keeps nothing secret.

It is meant for solo miners and holders who do not want block rewards to pile up in a hot wallet:
`truenorth-miner` only needs an address, not a wallet.

This is an independent community tool. It is not published or endorsed by the TrueNorth project.

## Status

- **Not audited.** The code and the tests were written with an AI model (Claude) under the direction of
  one person. About 650 lines of Python, standard library only, written to be read.
  Read it, rehearse with `--dry-run`, and start with small amounts.
- Making and checking an address is guided. **Spending is still done by hand** with TrueNorth Core
  (see [Spending](#spending)); a guided version is the next step.
- Works with the official **v30.5.4** programs on **macOS (Apple silicon)** and **Linux (x86_64)**.
  Windows and WSL are not supported: the tool cannot check there that the computer is offline.
- The author's own coins sit on an address made with the previous build of this tool (same logic,
  different interface language).

## How it works

1. The words come from the operating system's random source (`os.urandom`), optionally mixed with your own dice rolls.
2. You copy the 24 words to paper and type them back, so a wrong or unreadable copy is caught on the spot.
3. The address is computed twice and the two results must agree:
   by the Python code in `cold-address.py`, and by TrueNorth Core started with no network, no wallet
   and a temporary data folder that is deleted afterwards.
4. Only public data is written to disk (`out/cold-address.txt` and two companion files).
   The words are shown on the terminal's alternate screen, which is wiped, and the scrollback is cleared.
5. A real run refuses to start while the computer has a default network route
   (on macOS also while Wi-Fi is switched on).

The derivation is the one TrueNorth Core uses for its own `qrh()` descriptors (`m/88h/1867h/0h/0/i`),
so the words restore in TrueNorth Core itself. You do not depend on this tool to get your coins back.

## Before you start (online)

Get this repository (green **Code** button, **Download ZIP**, or `git clone`) and the official release
for your computer. In a terminal, inside the unpacked folder of this repository:

```sh
# macOS (Apple silicon); on Linux replace macos-arm64 with linux-x86_64
R=https://github.com/truenorth-project/truenorth/releases/download/v30.5.4
curl -LO $R/truenorth-v30.5.4-macos-arm64.tar.gz
curl -LO $R/SHA256SUMS
curl -LO $R/SHA256SUMS.asc
grep macos-arm64 SHA256SUMS | shasum -a 256 -c      # Linux: grep linux-x86_64 SHA256SUMS | sha256sum -c
tar xzf truenorth-v30.5.4-macos-arm64.tar.gz
```

Also check the signature of `SHA256SUMS` as the
[project README](https://github.com/truenorth-project/truenorth#pre-built-binaries) describes
(`gpg --verify SHA256SUMS.asc SHA256SUMS`, release key `3F0B AE04 5861 5427 B8CA 935E 3E24 2DF5 E447 8AE5`).
On macOS use `curl` as shown: files downloaded with a browser are quarantined and macOS may refuse to run them.

The tool then checks the two programs it uses (`truenorthd`, `truenorth-cli`) against the SHA-256 values
written in `cold-address.py`. Those values are from the release archives as published on 12 November 2026,
whose signature and checksums were verified. If the tool says the checksums differ, do not continue.

Rehearse once while you are still online. Nothing from a dry run may be used:

```sh
python3 cold-address.py --dry-run
```

## Making the address (offline)

1. Turn Wi-Fi off and unplug any network cable or tethered phone.
2. Have paper and a pen ready. Make sure nobody and no camera can see the screen.
3. Run:

   ```sh
   python3 cold-address.py
   ```

4. Copy the 24 words to paper, type them back when asked, and write the address next to the words.
5. Close the terminal window, then go back online.

Your address is in `out/cold-address.txt`. It is public; `out/` holds no secrets.
`out/cold-addresses.txt` lists the first five addresses of the same words (index 0 to 4).

Options: `--dice` mixes at least 99 dice rolls of your own into the randomness.
`python3 cold-address.py verify` (offline again) asks for the words and tells you whether they give the saved
address. Do that before you send anything of value, and whenever you want to be sure the paper is still right.

Keep two paper copies in two places. Whoever reads the words owns the coins. If the paper is lost, the coins are lost.
There is no extra passphrase: the 24 words alone are the wallet.

## Using the address

Mining: pass it to the official miner, `truenorth-miner -address=north1z...` (see the project README).

Balance, on any synced node, without a wallet:

```sh
truenorth-cli scantxoutset start '["addr(north1z...)"]'
```

## Spending

The simple route, tested on regtest (`tests/test_spend.py`): restore the words on your synced node and move
everything in one transaction. The keys are on an online computer from that moment, so make a new cold address
first, point your miner at it, and never use the old address again.

```sh
# 1. Words to a descriptor file. It asks for the 24 words and shows them as you type.
python3 tn-seed.py restore --out cold-keys.json

# 2. A new wallet on the node, filled from that file. Then delete the file.
truenorth-cli -named createwallet wallet_name=coldspend blank=true
truenorth-cli -rpcwallet=coldspend -stdin importdescriptors < cold-keys.json
rm cold-keys.json

# 3. Let the wallet find the coins (an import does not look into the past by itself).
truenorth-cli -rpcwallet=coldspend rescanblockchain
truenorth-cli -rpcwallet=coldspend getbalances

# 4. Send everything that is spendable to the destination.
truenorth-cli -rpcwallet=coldspend -named sendall recipients='["north1z...destination"]' fee_rate=1
```

Block rewards need 100 confirmations before they can be spent; `sendall` leaves the younger ones behind.
Run step 4 again once they have matured.

The air-gapped route keeps the keys offline: the online node builds a PSBT without any key
(`createpsbt`, `utxoupdatepsbt`), an offline node that holds the restored wallet shows the destination and the
fee (`decodepsbt`) and signs (`walletprocesspsbt`), and the online node broadcasts (`finalizepsbt`,
`sendrawtransaction`). `tests/test_spend.py` runs exactly this sequence; TrueNorth Core's
`doc/offline-signing-tutorial.md` explains the general idea. A guided version of this route is planned here.

A P2QRH address shows only a hash of your public key until the first spend from it. If that property matters
to you, empty an address in one go and use a fresh one afterwards.

## What you are trusting

- **This script and `tn-seed.py`.** Both are short and use only the Python standard library.
- **Python's `os.urandom`** for the randomness (plus your dice, if you use them).
- **The official TrueNorth Core programs.** `truenorthd` receives the private descriptor on standard input to
  derive the addresses for the cross-check. It runs with networking and the wallet disabled and its data folder
  is deleted, but a malicious program could still hide a copy somewhere. That is why the tool insists on the
  checksums of the signed release. The release builds are signed but not reproducible. For larger amounts use a
  live USB session on a computer without a disk, so that nothing can persist.
- **Your terminal.** Clearing the scrollback works in Terminal.app and in common Linux terminals; closing the
  window afterwards costs nothing.

What the tool does not protect against: someone who sees your screen or your paper, a compromised operating
system on the offline computer, and mistakes made later while spending.

## Test vectors for P2QRH

`vectors/p2qrh-test-vectors.json` is for people who write wallets. It was made by `vectors/tnvec.py`, which
shares no code with TrueNorth Core, and every value was checked against the official v30.5.4 programs on
regtest. See [vectors/README.md](vectors/README.md).

## Tests

```sh
sh tests/run-all.sh
```

runs the self-test of `tn-seed.py`, 35 checks of the whole procedure through a pseudo-terminal
(`tests/test_ceremony.py`), the spending test on regtest (`tests/test_spend.py`), regenerates the test
vectors and compares them byte for byte, and checks `FILES.sha256`. Last full run: 13 November 2026,
Linux x86_64, official v30.5.4 programs. On macOS (Apple silicon) the previous build was used for a real run
and for dry runs; a full test run of version 1.1 there will follow.

## Files

| File | Purpose |
|---|---|
| `cold-address.py` | The tool: `new` (default), `verify`, `--dry-run`, `--dice`. |
| `tn-seed.py` | Words to TrueNorth Core descriptors, and back from paper (`restore`). Used by the tool and for spending. |
| `english.txt` | The standard BIP39 English word list, unchanged (SHA-256 `2f5eed53...3b24dbda`). |
| `vectors/` | P2QRH test vectors and the program that makes them. |
| `tests/` | The tests described above. |
| `FILES.sha256` | SHA-256 checksums of the files above. |

## Versions

- 1.1 (13 November 2026): first public version. English interface, WSL is recognised and refused, dice rolls
  are typed on the alternate screen, a dry run lists what a real run would object to.
- 1.0 (not published): the build used for the author's own address.

## Licence and contact

MIT, see [LICENSE](LICENSE). Bugs and questions: open an issue in this repository.
Never post recovery words, private keys or descriptor files anywhere, and nobody from this repository will ever ask for them.

Severka is a pseudonym. No donations are asked for.
