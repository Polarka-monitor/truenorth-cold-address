# Security review of the cold address tool, 13 November 2026

This is not an audit. No human security expert has examined this code, and a review by one is recommended.
What follows are two reviews done on the day version 1.1 was published, what they found, and what version 1.2
changed because of them.

- **Internal review.** Done by the side that wrote the tool (the author and the AI model that wrote the
  code), so it is not independent. To make up for that it rests on measurements, not on reading alone: the
  programs and their output are in [`review/`](review/).
- **Second review.** Done by a second AI model, a different one, in a fresh session. It was given the public
  repository, the official TrueNorth Core programs and the TrueNorth Core source, and nothing else: no notes,
  no explanation of the design. Its report is in [`review/second-review.md`](review/second-review.md), unchanged.

Reviewed: version 1.1, commit `380212820c2b3485e018588057529baa9df14041`, with the official TrueNorth Core
v30.5.4 programs on Linux x86_64. Both reviews ran in the same kind of Linux sandbox.

## Result in short

The part that makes the keys is sound. The words are exactly the 32 random bytes the operating system gave,
the derivation matched TrueNorth Core and two independent libraries for every phrase tried, and a real run
wrote nothing secret to disk and spoke to nothing but the loopback interface.

The weaknesses were around that core. One was serious: version 1.1 handed the private descriptor of the new
words to a helper program over a local port without making sure who was listening there. The others
concerned the offline check, the terminal, an interrupted run and the spending instructions.

Version 1.2 fixes all of them. The same measurements were repeated on 1.2 and are in `review/evidence-1.2/`.

## What was confirmed

| What | How it was checked | Evidence |
|---|---|---|
| The release programs are the signed ones | signature of `SHA256SUMS`, checksums of the archives, of the programs inside and of the values pinned in the tool | `evidence-1.1/01` |
| BIP39 is implemented to the standard | 24 of 24 official vectors; 20,000 random phrases against the reference library, 400 seeds, 20,000 damaged phrases | `evidence-1.1/02` |
| The addresses are right | 500 random phrases on mainnet and 500 on regtest parameters, five addresses each, against TrueNorth Core: no mismatch. The second review: 250 per chain against another library and Core, no mismatch | `evidence-1.1/03`, second review |
| The words are the system's randomness and nothing else | the trace shows one request for 32 random bytes; the 24 words encode exactly those bytes (with dice: those bytes XOR SHA-256 of the rolls) | `evidence-1.1/04`, `evidence-1.2/04` |
| Nothing secret reaches the disk, a program argument or the environment | the whole run under `strace`, as a dry run and as a real run in a network namespace without any network; search of the disk afterwards | `evidence-1.1/04`, `evidence-1.2/04` |
| No network use | every socket of every process: loopback and kernel queries only | `evidence-1.1/04`, `evidence-1.2/04` |
| Ctrl+C, end of input, a dead helper node | screen wiped, node stopped, nothing left, nothing saved | `evidence-1.1/06` |

## Findings in version 1.1

Severity: **high** means the whole key can be lost under a condition that can really occur; **medium** means
a wrong assurance, or a secret that can stay behind in an ordinary set-up; **low** is hardening.
"Second" gives the number of the same finding in the second review.

| No. | Severity | Finding | Second | In 1.2 |
|---|---|---|---|---|
| 1 | high | The private descriptor could reach a program that is not the tool's own helper node | L5, L6 | fixed |
| 2 | medium | The spending instructions left the keys on the online node | M1 | rewritten |
| 3 | medium | The offline check on Linux missed real connections and still said "the computer is offline" | M2 | fixed |
| 4 | medium | The README said the words restore in TrueNorth Core itself | M3 | corrected |
| 5 | medium | Inside GNU screen all 24 words stayed in the scrollback | L3 | refused |
| 6 | low | Closing the window or killing the process left the node running and the screen unwiped | L1 | fixed |
| 7 | low | A core dump of the process contained the words | L2 | fixed |
| 8 | low | The helper programs inherited the user's whole environment; Python could load modules from the tool's folder | L4 | fixed |
| 9 | low | A dry run printed a valid mainnet address for words that may have been made online | L7 | fixed |
| 10 | low | `tn-seed.py` took dice rolls on the command line and showed the words when restoring | I2 | fixed |
| 11 | info | The README's signature check lacked the key import; gaps in the tests | I1, I4 | fixed |

### 1. The private descriptor could reach a stranger (high)

To compare its own result with TrueNorth Core, version 1.1 started a helper node and sent it the private
descriptor of the new words through `truenorth-cli`, over a port on the loopback interface. It chose the port
by asking the system for a free one and closing it again, then told the node to use it. For a moment the
port was free, and the node's command line shows the number to every user of the computer.

Two things made that dangerous. `truenorth-cli` sends its request even when it finds no access cookie
(`src/truenorth-cli.cpp`, lines 866 to 880 and 919 to 926 in v30.5.4). And the tool accepted the first
answer on the port without checking that its own node was still alive.

Measured (`evidence-1.1/08`): a second program watched the process list, took the port before the node
could, and passed the requests on to a real node of its own. In 6 runs it got the port 6 times. Once the
tool stopped with "TrueNorth Core did not start". Five times it finished normally and printed a cold address,
and in each of those five the private descriptor of the new words had gone to the second program.

What an attacker needs: a program of his own running on the same computer during the ceremony, under any
user account, with no special rights; and a way to carry the result out later. That is less than the
"compromised operating system" which the README of 1.1 named as out of scope.

Fixed in 1.2 in two ways. First, the node no longer receives anything secret: the tool computes the public
key of the account itself and gives Core only that. The way back from paper, which does use a private
descriptor, is tried at every run with the public test phrase and two throw-away phrases, never with the
user's words; the tool's own key derivation is checked against the published BIP-0032 vectors.
Second, the tool talks to the port only while its own node is alive and has written its cookie file into the
tool's private folder, which the node does after it has the port. `tests/test_port_owner.py` plays the
second program; on 1.2 it receives no request at all (`evidence-1.2/08`). `tests/test_ceremony.py` records
everything the tool sends to `truenorth-cli` and checks that the user's private descriptor is not in it.

The second review listed the two halves of this as low (L5: the node gets more than it needs; L6: the port
race, found by reading). The internal review rates it high because the measurement shows a normal-looking
run that gives the key away.

### 2. Spending instructions (medium)

The "simple route" of the README wrote the private descriptors to a file, deleted it with `rm`, left an
unencrypted wallet with the keys on the online node, and showed the words on the terminal while they were
typed. The second review ran the commands literally and found all of that. In 1.2 `tn-seed.py restore` reads
the words without showing them and can print the descriptors alone (`--json`), so they go through a pipe
into the node and never into a file; the instructions end with unloading and removing the wallet, and say
first to wait until nothing on the address is younger than 100 blocks. `tests/test_spend.py` now runs those
very commands and then searches the node's folder and the terminal output for the words and the key.

### 3. Offline check on Linux (medium)

Version 1.1 read the main routing table only. Measured in network namespaces (`evidence-1.1/07`): a default
route in another routing table, as some VPN set-ups have, and a LAN without a gateway both passed as "ok,
the computer is offline". Version 1.2 asks the kernel whether it can route to public addresses, one in every
/8 block of IPv4 and of the global IPv6 range (connecting a UDP socket sends nothing; the trace in
`evidence-1.2/04` confirms that no data leaves), names every interface that has a link and asks the user
about it, looks at the Wi-Fi switch, and repeats the check just before the words are shown. The message now
says "no network connection found". `tests/test_linux_offline.py` builds the cases, including a whole real
run with no network.

On macOS the check is as in 1.1: routing table, Wi-Fi switch, active interfaces.

### 4 to 11

4. TrueNorth Core has no BIP39 support. The README now says what restoring needs (`tn-seed.py` and
   `english.txt`), and the tool prints a one-line recipe to write on the paper.
5. GNU screen ignores the alternate screen by default; after a run all 24 words, as shown and as typed, were
   in its scrollback (`evidence-1.1/05`). tmux 3.4 kept nothing. A real run of 1.2 refuses inside screen,
   tmux, an SSH session and a session recorded by `script`.
6. 1.2 handles the signals, wipes the screen, stops the node and removes its folder (`evidence-1.2/06`).
   Ctrl+Z is ignored while the tool runs.
7. 1.2 sets the core file limit to zero for itself and its children and, on Linux, forbids attaching to its
   process.
8. 1.2 restarts itself with `python -I` and gives its helper programs a minimal environment.
   Still true: the helper programs are checked by SHA-256 and then started by path, and on Linux they load
   system libraries. Whoever can change files in the tool's folder or the system's libraries can change the
   outcome.
9. A dry run of 1.2 uses test-network parameters; its address starts with `rnorth1z`.
10. `tn-seed.py` asks for dice rolls and for the words without showing them.
11. The README has the key import; the tests cover the points above.

## What was not checked, and what stays as it is

- **macOS.** The measurements above were made on Linux. On a Mac the offline check was run only in the
  online state (`evidence-1.1/10`), and what Terminal.app keeps after a run was not measured: the tool
  relies on the alternate screen and on the "clear scrollback" sequence working as documented.
- **IPv6.** The sandbox has no IPv6. The second review tested the route parsing with synthetic input only.
- **A real live-USB system** was not tried.
- **The operating system is trusted.** A program that can read the screen, the keyboard or the memory of the
  user's own processes gets the words. The tool cannot prevent that.
- **Memory.** Python cannot erase the words from memory; they can reach a swap file. Use an encrypted disk,
  or a live system without swap.
- **The release programs are trusted for the cross-check.** In 1.2 they no longer see anything secret, but a
  wrong program could still agree with a wrong address. They are signed, not reproducible.
- **Spending** is still done by hand. The simple route puts the keys on an online computer for a few minutes.

## Reproducing

Everything in `review/scripts/` takes the folder of the tool, the folder of the TrueNorth Core programs and
a work folder as arguments. The tests in `tests/` need no arguments (`sh tests/run-all.sh`). The network
namespace cases need Linux and root.
