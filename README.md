# TrueNorth cold address

A small tool that makes a cold address for TrueNorth (NORTH) on a computer that is offline.
You end up with 24 words on paper and an address you can mine or receive to. The computer keeps nothing secret.

It is meant for solo miners and holders who do not want block rewards to pile up in a hot wallet:
`truenorth-miner` only needs an address, not a wallet.

This is an independent community tool. It is not published or endorsed by the TrueNorth project.

## Status

- **Reviewed twice. A further review by a human security expert is recommended.**
  The code and the tests were written with an AI model (Claude, named Cloe in the commit history) under the
  direction of one person. On 13 November 2026 version 1.1 went through an internal security review with
  measurements and a separate review by a second AI model; version 1.2 contains the fixes. No human expert
  has examined the code yet. See [SECURITY-REVIEW.md](SECURITY-REVIEW.md), read the code (about 930 lines of
  Python, standard library only), rehearse with `--dry-run`, and start with small amounts.
- **If you made an address with version 1.1:** see "Version 1.1" at the end of this file.
- Making and checking an address is guided. **Spending is still done by hand** with TrueNorth Core
  (see [Spending](#spending)); a guided version is the next step.
- Works with the official **v30.5.4** programs on **macOS (Apple silicon)** and **Linux (x86_64)**.
  Windows and WSL are not supported: the tool cannot check there that the computer is offline.
- The author's own coins sit on an address made with the first build of this tool.

## How it works

1. The words come from the operating system's random source (`os.urandom`), optionally mixed with your own dice rolls.
2. You copy the 24 words to paper and type them back, so a wrong or unreadable copy is caught on the spot.
3. The address is computed twice and the two results must agree: by the Python code in `cold-address.py`,
   from the private keys, and by TrueNorth Core, which is given only the public key of the account.
   Core runs with no network, no wallet and a temporary data folder that is deleted afterwards.
   **Your words and private keys never leave the Python process:** no file, no other program, no network.
4. Only public data is written to disk (`out/cold-address.txt` and two companion files).
   The words are shown on the terminal's alternate screen, which is wiped, and the scrollback is cleared.
5. A real run refuses to start inside `screen`, `tmux` or an SSH session, and while it finds a network
   connection. It looks again just before the words are shown. On Linux it asks the kernel whether any
   route to public addresses exists; on macOS it reads the routing table and the Wi-Fi switch.
   This check is a seat belt, not a proof: the safe set-up is a computer that has no network at all.

The words are standard BIP39. `tn-seed.py restore` turns them into the descriptors that TrueNorth Core
imports (`qrh(.../88h/1867h/0h/0/*)`), and from there on TrueNorth Core alone can spend the coins.
TrueNorth Core does not read BIP39 words by itself, so keep `tn-seed.py` and `english.txt` (20 kB together)
with your backups, and write the recipe that the tool prints at the end on the paper next to the words:
`TrueNorth (NORTH), BIP39, 24 English words, no passphrase, qrh(), path m/88h/1867h/0h/0/0`.
With that line, any careful person with a BIP39 and BIP32 tool can find the key even without this repository.

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

Also check the signature of `SHA256SUMS`, as the
[project README](https://github.com/truenorth-project/truenorth#pre-built-binaries) describes:

```sh
curl -sS https://github.com/septentrion-dev.gpg | gpg --import
gpg --verify SHA256SUMS.asc SHA256SUMS
```

`gpg` must report a good signature and the primary key `3F0B AE04 5861 5427 B8CA 935E 3E24 2DF5 E447 8AE5`.
On macOS use `curl` as shown: files downloaded with a browser are quarantined and macOS may refuse to run them.

The tool then checks the two programs it uses (`truenorthd`, `truenorth-cli`) against the SHA-256 values
written in `cold-address.py`. Those values are from the release archives as published on 12 November 2026,
whose signature and checksums were verified. If the tool says the checksums differ, do not continue.
On Linux the two programs need a few system libraries (libevent, sqlite3, numa, libstdc++); a desktop
system has them, a minimal live system may not.

Check this repository too: `shasum -a 256 -c FILES.sha256` (Linux: `sha256sum -c FILES.sha256`).

Rehearse once while you are still online. A dry run uses test-network parameters: its address starts with
`rnorth1z` and cannot receive real coins.

```sh
python3 cold-address.py --dry-run
```

## Making the address (offline)

1. Turn Wi-Fi off and unplug any network cable or tethered phone.
2. Open a plain terminal window on the computer itself (Terminal on macOS, the desktop's terminal on Linux).
   Not `screen`, not `tmux`, not SSH, and no session recording.
3. Have paper and a pen ready. Make sure nobody and no camera can see the screen.
4. Run:

   ```sh
   python3 cold-address.py
   ```

5. Copy the 24 words to paper and type them back when asked. Write the address and the recipe line next to
   the words.
6. Close the terminal window, then go back online.

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

There are two routes. `tests/test_spend.py` runs both on regtest, the simple one with the very commands below.

### The simple route: restore on your synced node, sweep, remove

For a few minutes the keys are on an online computer. From that moment the address counts as used up.
So, before you start:

- **Make a new cold address** (move the `out` folder away and run the tool again: new words, new paper),
  point your miner at it, and never use the old address again.
- **Wait until every reward on the old address is 100 blocks old.** Younger rewards cannot be spent yet,
  and you want one transaction to empty the address, not a wallet that waits on the node for days.

Then, in one sitting:

```sh
# 1. A temporary wallet on the node.
truenorth-cli -named createwallet wallet_name=coldspend blank=true

# 2. The words go from the keyboard straight into the node: no file, and they are not shown as you type.
#    Type all 24 on one line, with spaces. Both answers must say "success": true.
python3 tn-seed.py restore --json | truenorth-cli -rpcwallet=coldspend -stdin importdescriptors

# 3. Let the wallet find the coins (an import does not look into the past by itself).
truenorth-cli -rpcwallet=coldspend rescanblockchain
truenorth-cli -rpcwallet=coldspend getbalances

# 4. Send everything to the destination. Check the destination address twice.
truenorth-cli -rpcwallet=coldspend -named sendall recipients='["north1z...destination"]' fee_rate=1

# 5. Take the keys off the node again.
truenorth-cli unloadwallet coldspend
rm -r ~/.truenorth/wallets/coldspend      # macOS: ~/Library/Application\ Support/TrueNorth/wallets/coldspend
```

A deleted file can linger on a disk, and a backup program may have copied the wallet while it existed. That
is why the old address must stay unused for good, and why the disk of the node should be encrypted.

### The air-gapped route: the keys stay offline

The online node builds a PSBT without any key (`createpsbt`, `utxoupdatepsbt`). An offline node that holds
the restored wallet shows the destination and the fee (`decodepsbt`) and signs (`walletprocesspsbt`). The
online node broadcasts (`finalizepsbt`, `sendrawtransaction`). The address stays cold and can go on receiving.
`tests/test_spend.py` runs exactly this sequence; TrueNorth Core's `doc/offline-signing-tutorial.md` explains
the general idea. Use this route for amounts that matter to you. A guided version of it is planned here.

A P2QRH address shows only a hash of your public key until the first spend from it. If that property matters
to you, empty an address in one go and use a fresh one afterwards.

## What you are trusting

- **This script and `tn-seed.py`.** Both are short and use only the Python standard library. The script
  restarts itself in Python's isolated mode, so that nothing but the standard library can be loaded.
- **Python's `os.urandom`** for the randomness (plus your dice, if you use them).
- **The official TrueNorth Core programs, for the cross-check only.** They are given the public key of your
  account and nothing else, so they cannot leak your words. They are still part of the check that the
  address is right, which is why the tool insists on the checksums of the signed release. The release
  builds are signed but not reproducible.
- **The computer and its operating system.** Anything that can read the screen, the keyboard or the memory
  of your own programs can read the words. The tool switches off core dumps and, on Linux, attaching to its
  process; it cannot do more. For larger amounts use a live USB session on a computer without a disk and
  without a network.
- **Your terminal.** Clearing the scrollback was measured in tmux and in GNU screen (where it fails, which is
  why the tool refuses to run there). In Terminal.app and the common Linux terminals it relies on their
  documented behaviour; closing the window afterwards costs nothing.

What the tool does not protect against: someone who sees your screen or your paper, a compromised operating
system on the offline computer, and mistakes made later while spending.

## Test vectors for P2QRH

`vectors/p2qrh-test-vectors.json` is for people who write wallets. It was made by `vectors/tnvec.py`, which
shares no code with TrueNorth Core, and every value was checked against the official v30.5.5 programs on
regtest, a spend with an annex among them (the mempool refuses it, a block takes it). TrueNorth Core has
published a set of its own; `vectors/compare-upstream.py` computes that set again with the code behind this
one, and the two agreed at commit `ed6d245`. See [vectors/README.md](vectors/README.md).

## Tests

```sh
sh tests/run-all.sh
```

runs the self-test of `tn-seed.py`; the whole procedure through a pseudo-terminal, including interruptions,
refusals and a check that the helper node is only ever given public keys of the user's words
(`tests/test_ceremony.py`); a stranger taking the helper node's port (`tests/test_port_owner.py`); the
spending test on regtest (`tests/test_spend.py`); on Linux as root, the offline check and a whole real run in
network namespaces (`tests/test_linux_offline.py`); it regenerates the test vectors against v30.5.5 (its
programs in the folder named by `TN_VEC_BIN`) and compares them byte for byte, and checks `FILES.sha256`. The folder `review/` holds the measurements of the security review and
the programs that made them.

## Files

| File | Purpose |
|---|---|
| `cold-address.py` | The tool: `new` (default), `verify`, `--dry-run`, `--dice`. |
| `tn-seed.py` | Words to TrueNorth Core descriptors, and back from paper (`restore`). Used by the tool and for spending. |
| `english.txt` | The standard BIP39 English word list, unchanged (SHA-256 `2f5eed53...3b24dbda`). |
| `SECURITY-REVIEW.md` | What two reviews of version 1.1 found, and what version 1.2 changed. |
| `review/` | Evidence and programs of the internal review; the second review in full. |
| `vectors/` | P2QRH test vectors, the program that makes them, and the comparison with TrueNorth Core's own set. |
| `tests/` | The tests described above. |
| `FILES.sha256` | SHA-256 checksums of the files above. |

## Versions

- 21 November 2026: the test vectors made again against v30.5.5, which gives each P2QRH rule a reject reason
  of its own, and a spend with an annex added (asked for in discussion #34 of TrueNorth Core). The tool is
  unchanged and still 1.2.
- 14 November 2026: `vectors/compare-upstream.py` added. The tool is unchanged and still 1.2.
- 1.2 (13 November 2026): the fixes from the security review. Core is given only the public key of the
  account; the tool makes sure it talks to its own helper node; it refuses screen, tmux and SSH; it cleans up
  when the window is closed or the process is killed; no core dumps; the offline check on Linux asks the kernel
  and is repeated just before the words are shown; a dry run makes a test-network address; `tn-seed.py restore`
  no longer shows the words and can feed TrueNorth Core through a pipe; the spending instructions no longer
  leave keys on the node.
- 1.1 (13 November 2026): first public version.
- 1.0 (not published): the build used for the author's own address.

### Version 1.1

Version 1.1 was public from 13 November 2026 until 1.2 replaced it. Its addresses are computed correctly:
nothing in the review puts the keys themselves in doubt. Its weak point was that it sent the private
descriptor of the new words to a helper program over a local port without making sure who was listening
(finding 1 of the review). To use that, a hostile program written for this purpose had to be running on the
same computer during the run. If you made an address with 1.1 on a computer you do not fully trust, make a
new one with 1.2 and move the coins.

## Licence and contact

MIT, see [LICENSE](LICENSE). Bugs and questions: open an issue in this repository.
Never post recovery words, private keys or descriptor files anywhere, and nobody from this repository will ever ask for them.

Severka is a pseudonym. No donations are asked for.
