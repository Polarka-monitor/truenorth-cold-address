# The second review, in full

Written on 13 November 2026 by a second AI model (not the one that wrote the tool) in a fresh session. It was
given the public repository at commit 380212820c2b3485e018588057529baa9df14041, the official TrueNorth Core
v30.5.4 programs and the TrueNorth Core source, and no notes or explanations from the author's side. The text
below is its report, unchanged. Paths such as `/home/claude/...` and the files it names under `logs/` are
those of the reviewer's sandbox; they are not part of this repository.

What became of each finding is in [SECURITY-REVIEW.md](../SECURITY-REVIEW.md).

---

## Independent security review: truenorth-cold-address (commit 380212820c2b3485e018588057529baa9df14041)

The supporting scripts are in `/home/claude/audit/independent/`, with logs in `logs/` and `derive_check.log`. The reviewed copy is unchanged (`FILES.sha256` still all OK).

### 1. Verdict
Yes, I would put my own coins on an address made with this tool, with four conditions:
- Run it from a live USB system with no network hardware enabled; don't rely on the tool's offline check.
- Run it in a plain terminal window, not inside GNU screen or over SSH. Close the window only after the run has finished.
- Write the derivation recipe on the paper next to the words: BIP39, no passphrase, `qrh()`, `m/88h/1867h/0h/{0,1}/*`.
- Don't follow the README's "simple" spending route as written. Use the air-gapped PSBT route, or harden the simple route (see M1).

The core is sound. The words are generated correctly, and the derivation matched in every check below. A real (non-dry) run under `strace` wrote nothing secret to disk and connected only to loopback. The weak points are around the core: the offline check, signal handling, terminal assumptions and the spending instructions.

**Counts:** critical 0, high 0, medium 3, low 7, informational 4.

### 2. Findings

**M1 (medium): the README spending route leaves the master private key on the online computer.**
- **Where:** README.md 101-125; tn-seed.py 167 and 188-191.
- **Evidence** (`logs/readme_spend.log`): I ran the README steps literally on regtest, adding only `-regtest`/`-datadir`. They work.
  - Afterwards `wallets/coldspend/wallet.dat` remains, with `"private_keys_enabled": true` and no encryption.
  - `cold-keys.json` holds the private xprv. It is written to the current folder and deleted with a plain `rm`, so it stays recoverable.
  - `restore` reads the words with `input()`, so they are echoed into the scrollback of an online terminal.
- **Impact:**
  - The key stays hot indefinitely.
  - Immature mining rewards stay under this key for 100 or more blocks, by design ("run step 4 again").
  - The descriptor file can be uploaded within seconds if the folder is cloud-synced (iCloud Desktop/Documents, OneDrive, Dropbox) or backed up.
- **Fix:**
  - Make the air-gapped PSBT route the default.
  - For the simple route: pipe the descriptors straight into `importdescriptors` with no file, read the words without echo, create the wallet with a passphrase, and `unloadwallet` and delete it after the final sweep.
  - Warn about synced folders and backups.

**M2 (medium): the offline check on Linux is narrow and runs only once, yet the tool prints "ok, the computer is offline".**
- **Where:** cold-address.py 216-235, 576-596, 613-627.
- **Evidence** (`logs/netcheck_scenarios.log`, run in a network namespace, compared with what `ip route get 8.8.8.8` actually returns):
  - A default route only in policy routing table 100: tool returns `([], [])` while the kernel routes 8.8.8.8 through v0.
  - A wide non-default route `8.0.0.0/7`: `([], [])`.
  - An active interface with an address but no default route: no hint at all.
- **Evidence** (`logs/ipv6_parse_test.log`, synthetic input because IPv6 is disabled in this VM): IPv6 `::/1 + 8000::/1` and `2000::/3` both give `([], [])`.
- **Cause:**
  - The code reads only the main routing table, and for IPv6 only prefix length 0.
  - It does not check Wi-Fi or rfkill on Linux.
  - The second check (line 613) only warns, after the address is already saved.
- **Impact:** false reassurance. The README sentence "refuses to start while the computer has a default network route" is false under policy routing. Exploiting this still needs malware on the offline machine.
- **Fix:**
  - Ask the kernel directly: `ip route get`, or `connect()` on a UDP socket to public v4 and v6 addresses.
  - List every interface that is up and has an address, and check rfkill.
  - Keep re-checking during the ceremony and abort before the words are shown.
  - Soften the wording.

**M3 (medium): the README claims the words "restore in TrueNorth Core itself" and "you do not depend on this tool".**
- **Where:** README.md 35-36.
- **Evidence:** `grep -rli "mnemonic\|bip39" src` on the v30.5.4 source finds nothing; Core has no BIP39 support. Recovery needs `tn-seed.py` or another BIP39 tool, plus knowledge of the custom path 88h/1867h and the `qrh()` descriptor.
- **Impact:** a user holding only the paper years from now may be stuck.
- **Fix:** correct the sentence, tell users to write the recipe on the paper, and keep `tn-seed.py` and `english.txt` alongside it.

**L1: no signal handling** (cold-address.py 337-350, 636-654). Closing the terminal window (SIGHUP) or SIGTERM leaves an orphan `truenorthd` and its temp folder. Evidence in `logs/signal_test.log`, e.g. SIGHUP: "leftover-datadirs=1 running-truenorthd=['4351']". The node runs in the same process group and treats SIGHUP as a log reopen, so it survives. Ctrl+Z leaves the words on screen. Ctrl+C at every prompt is handled correctly (`logs/ctrlc_test.log`). Fix: signal handlers, `start_new_session=True`, and a parent-death signal for the child.

**L2: words can reach disk through a core dump or swap.** With core dumps enabled, SIGQUIT to Python while the words are shown produced "core 14266368 bytes; contains the 24-word phrase: True" (`logs/core_test.log`). Fix: set RLIMIT_CORE to 0 and PR_SET_DUMPABLE to 0, also for the child, and recommend a live system without swap.

**L3: the alternate-screen protection fails in GNU screen, and the README overstates it.** After a dry run inside GNU screen 4.09.01 with default settings, all 24 shown and all 24 typed words were still in screen's scrollback (`logs/screen_test.log`). The same applies to terminal session logging. Fix: refuse or warn when `$STY` or `$TMUX` is set.

**L4: only the two executables are hash-checked.**
- `truenorthd` is dynamically linked against system libevent, sqlite3, numa and libstdc++ (`ldd`).
- The child inherits the full environment (the strace shows 224 variables), so `LD_PRELOAD` and `DYLD_*` would apply.
- There is a gap between the hash check and execution.
- A minimal live USB may lack libevent (not checked).

Fix: copy the binaries to the private temp folder, hash the copies and run those; clear `LD_*`/`DYLD_*`; document that the system libraries are trusted.

**L5: the master xprv is passed to `truenorthd` when an account xpub would be enough** for the cross-check (lines 412-421). Found by reading the code.

**L6: RPC port race** (lines 341-344). The tool picks a free port and closes it before the node binds. In that window a local process could take the port and receive the private descriptor. Only matters if local malicious code is already running. Found by reading the code.

**L7: dry runs default to mainnet** and print a valid `north1z…` address from words generated online, separated from a real address only by a "DRY RUN" label. Fix: make regtest the default for dry runs.

**Informational:**
- **I1:** the README's `gpg --verify` step lacks the key import, so a literal user gets "No public key". I verified the signature after importing the key: Good signature, primary key 3F0B…8AE5, matching the README.
- **I2:** `tn-seed.py new --dice` takes the dice on the command line (shell history, `/proc`) and prints secrets to the terminal.
- **I3:** the macOS network-check branch was only read, never run (tunnel routes are ignored, and interface names starting `ap` or `bridge` are skipped).
- **I4:** test gaps, listed in section 3.

### 3. What I checked, with evidence

**Integrity.**
- `FILES.sha256` in the reviewed copy: all OK.
- Release tarballs: OK against `SHA256SUMS`, and the `SHA256SUMS` signature verified ("Good signature").
- The pinned SHA-256 values for Linux (3b06c5d5…, 2c46f09a…) and Darwin (ab90e2cb…, f40ceb7d…) match the binaries inside the verified tarballs.
- `english.txt` matches the official BIP39 English list.

**Project test suite.** `run-all.sh` passed: 35 ceremony checks (the README number is right), both spending routes, test vectors reproduced byte for byte, and checksums.

**Randomness** (code reading).
- 32 bytes from `os.urandom` (getrandom on Linux).
- Dice are hashed with SHA-256 and XORed in, which cannot lower entropy below what urandom provides. Dice quality is not checked (99 ones are accepted).
- Checksum handling is correct, and there is no source of bias.

**Derivation** (`derive_check.py`, log in `derive_check.log`).
- The 24 official Trezor BIP39 vectors pass: mnemonic, seed with passphrase "TREZOR", and root xprv.
- Both known-answer addresses match an independent implementation.
- 250 random mnemonics per chain (mainnet and regtest), compared three ways (tool's Python code, bip_utils, Core `deriveaddresses` on tn-seed's descriptors), branches 0 and 1, indexes 0 to 4:
  - 1250 addresses compared between the tool's Python code and bip_utils;
  - 2500 compared between Core and bip_utils;
  - 500 descriptor checksums compared against Core;
  - 0 failures.
- A mutation of the commitment byte made the tool stop with "disagree".
- Restoring and spending works on regtest, including the README's literal commands.

**Leakage, real run** (`unshare -n`, `strace -f`, logs in `logs/real/`).
- Programs started: `truenorthd` with only public flags. `truenorth-cli` with `getblockcount`, `-stdin deriveaddresses` and `stop`; the descriptor goes in through stdin only.
- Files written: only the node's temp data folder and `out/*`.
- Network: netlink queries plus TCP on 127.0.0.1 only.
- A search of every file changed during the run for any 3 consecutive words, the xprv and the seed: "scanned 8 files, 0 hits". The temp folder was removed.
- A node data folder kept on purpose after a real derivation contains no xprv or seed.

**Failure paths.**
- Ctrl+C at every prompt: exit 130, nothing left behind. Ctrl+D: "STOP: The input ended."
- Three wrong attempts at typing the words back: nothing is saved.
- `verify` rejects swapped words and a different valid phrase.
- A second real run over an existing `out/` is refused.
- No error path prints secrets.
- Words are confirmed before the address is saved, so a user cannot end up with a saved address whose words they never confirmed.

**Test gaps.**
- The "no file contains the words" check scans only the kit folder.
- No test of the real (non-dry) success path.
- No synthetic tests of the route parsing; the macOS branch is untested.
- No signal or terminal-multiplexer tests.
- The online-refusal test depends on the host machine's network.
- `test_spend.py` does not run the README's literal commands.
- Nothing checks the wallet left behind after spending.

### 4. Not checked
- Nothing on macOS was run, only read.
- No live IPv6 (disabled in this VM; synthetic input only).
- No real live-USB system: library availability and Linux text-console behaviour are unknown.
- Python 3.8 not run. vermin reports a minimum of 3.5; `pow(x, -1, p)` needs 3.8, which the tool checks for.
- The air-gapped route was run only as the test does it, not by following the README prose.
- `vectors/tnvec.py` only reproduced, not reviewed.
- The miner was not run.

### 5. Method and independence
- **Tools:** Python 3.13.18, Core v30.5.4 official binaries, strace 6.8, unshare, iproute2, GnuPG 2.4.4, bip_utils 2.12.3 with coincurve 21.0.0, vermin, GNU screen 4.09.01.
- **Time:** about 1.5 hours.
- **What I read:** only the reviewed copy, `/home/claude/rel`, `/home/claude/tn/bin`, and the needed parts of `/home/claude/wp/repo` (`doc/p2qrh.md`, `README.md`, `qrh.h`, `descriptor.cpp`, `chainparams.cpp`, `consensus.h`, `contrib/keys`).
- **What I did not read:** I never opened `/home/claude/pub`, other parts of `/home/claude/wp`, or `/home/claude/audit/internal`, and the filesystem secret search skipped them. No memory or project tools were used. Nothing was posted or sent anywhere.
- **Downloads:** the official BIP39 vectors and word list, from GitHub.
- **Incident:** in my first signal test I used a broad process pattern and killed three `truenorthd` processes with `/tmp/tn-cold-*` data folders. They may have belonged to another session running in the same container. Every later test used a private TMPDIR.
- **Refused change:** the environment refused one change to `core_pattern`. I worked around it by signalling only the Python process.
- **Words in `logs/real/secrets.json`:** throw-away words made for the search. They must never be used.

### Most important findings
1. **M1:** the README's simple spending route leaves the master key on the online computer, both as a plaintext descriptor file that can be cloud-synced and as an unencrypted wallet that is never removed.
2. **M2:** the Linux offline check misses default routes in other routing tables, wide non-default routes and IPv6 split routes, checks only once, and still prints "the computer is offline".
3. **M3:** the README wrongly says the words restore in TrueNorth Core itself. Core has no BIP39 support, and users aren't told to write the custom derivation recipe on the paper.
