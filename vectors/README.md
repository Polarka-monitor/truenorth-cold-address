# P2QRH test vectors

`p2qrh-test-vectors.json` gives wallet authors something to test against: keys, addresses, a signed
transaction that TrueNorth Core accepted and mined, and spends that it refused.

The file is made by `tnvec.py`. That program uses only the Python standard library and shares no code with
TrueNorth Core (the secp256k1, BIP32 and bech32m code lives in `../cold-address.py`). Every value in the file
was checked against the official v30.5.4 programs on regtest while the file was made, and running the program
again gives the same file byte for byte:

```sh
python3 vectors/tnvec.py /tmp/vectors.json && cmp /tmp/vectors.json vectors/p2qrh-test-vectors.json
```

All keys come from the public BIP39 test phrase (`abandon` eleven times, then `about`).
**Never send coins to these addresses on mainnet.**

## What P2QRH looks like on the wire (v30.5.4)

| Item | Value |
|---|---|
| Output script | `OP_2 <32-byte commitment>`, hex `5220` followed by the commitment (witness version 2) |
| Commitment | `SHA256("TrueNorth/QRH/v1" \|\| scheme_id \|\| x-only public key \|\| script_root)`, with `scheme_id = 0x01` and `script_root` = 32 zero bytes |
| Address | bech32m, prefix `north` (mainnet), `rnorth` (regtest) |
| Key path | `m/88h/1867h/0h/branch/index` on mainnet, coin type `1h` on test chains; branch 0 receive, 1 change |
| Extended private key version | `7e5c6544` on mainnet (`Tprv...`), `04358390` on regtest |
| Witness of a spend | three items in this order: signature (64 bytes), x-only public key (32 bytes), scheme id (1 byte, `0x01`) |
| Signed message | the BIP-341 key path signature hash (`SIGHASH_DEFAULT`, no annex), signed with BIP-340 Schnorr |

A spend carries 101 bytes of witness per input, against 66 for a Taproot key path spend, because the public
key and the scheme id travel in the witness. The two-input, two-output transaction in the file is 229 vB.

## What is in the file

- `chains.main` and `chains.regtest`: master extended private key, the two `qrh()` descriptors as TrueNorth
  Core imports them, and five keys each (`0/0`, `0/1`, `0/2`, `1/0`, `1/1`) with private key, x-only public key,
  commitment, output script and address. TrueNorth Core derives the same addresses from the descriptors.
- `spend`: a transaction with two P2QRH inputs. It lists the inputs with amounts and scripts, the five shared
  BIP-341 hashes (`sighash_intermediates`), the signature hash and the signature of each input (BIP-340 with
  an all-zero auxiliary value, so the signatures are reproducible), the unsigned and the signed transaction and
  the transaction id. TrueNorth Core accepted it into the mempool and mined it. Signatures made by TrueNorth
  Core's own wallet for the same transaction verify against the signature hashes computed here.
- `invalid_spends`: the same transaction with the witness of input 0 changed in six ways (other scheme ids,
  another key, a damaged signature, an extra item, a missing scheme id), each with the reason TrueNorth Core
  gave for refusing it.
- `reserved_scheme_output`: an output whose commitment was made with scheme id `0x02`. TrueNorth Core refuses
  to spend it both in the mempool and in a block, whether the witness says `0x02` or `0x01`. As a control,
  the same transaction shape spending an ordinary output of the same age is accepted.

## Two things worth knowing

1. **Only scheme `0x01` can be spent today, and the scheme id is part of the commitment.** An output made with
   any other scheme id is frozen under the rules of v30.5.4. A wallet must never create one.
2. **Almost every P2QRH failure gives the same error**, `Witness program hash mismatch`: a wrong scheme id,
   a wrong number of witness items, a wrong key size, a commitment that does not match. Only the signature
   check has errors of its own (`Invalid Schnorr signature` in the file). The text does not tell you which
   rule you broke; compare with the vectors. This is so in v30.5.4. On master each rule has since been given
   an error of its own, see the comparison below.

## Not covered

Signature hash types other than `SIGHASH_DEFAULT`, the optional annex, testnet4 addresses, and script path
spending (the consensus code of v30.5.4 accepts key path spends only). The other hash types and the prefixes
of the test networks are in TrueNorth Core's own set, see below.

## Compared with TrueNorth Core's own vectors

TrueNorth Core has since published a set of its own, `src/test/data/p2qrh_wallet_vectors.json`. It has what
this set leaves out: the testnet, testnet4 and signet prefixes, extended public keys and descriptors with key
origin, every signature hash type, addresses that must be refused, and six more witness shapes that must be
refused. This set has what that one leaves out: everything here was produced against a running node.

`compare-upstream.py` computes every value of Core's file again with the code behind this set, and compares:

```sh
python3 vectors/compare-upstream.py PATH/TO/p2qrh_wallet_vectors.json
```

It needs no node, writes nothing, and uses nothing of Core's generator. With Core's file at commit `ed6d245`
(SHA-256 `e8709e70031254f677890831d5eb6c08013b7f051b49863bf04138556892ddde`) it reported 64 checks and no
difference on 14 November 2026: 61 comparisons with Core's values and 3 controls on this set. The witnesses
that must be refused are judged by the order of the rules as it reads in `src/script/interpreter.cpp`. That
part is a model of the rules, written down by hand, and not a second implementation of them.

The same commit gives each P2QRH rule a script error of its own. It is on master and in no release yet, so the
reasons in `invalid_spends` and `reserved_scheme_output` are still those of v30.5.4. By the new order of the
rules they become, as read from the code and not yet run:

| Case in the file | v30.5.4 | master at `ed6d245` |
|---|---|---|
| scheme id `0x02` | Witness program hash mismatch | `QRH_SCHEME_UNKNOWN` |
| scheme id `0x00` | Witness program hash mismatch | `QRH_SCHEME_UNKNOWN` |
| another key with that key's valid signature | Witness program hash mismatch | `WITNESS_PROGRAM_MISMATCH` |
| signature with the last bit flipped | Invalid Schnorr signature | `SCHNORR_SIG` |
| extra item before the signature | Witness program hash mismatch | `QRH_WITNESS_SIZE` |
| scheme id missing | Witness program hash mismatch | `QRH_SCHEME_SIZE` |
| output committed to `0x02`, witness says `0x02` | Witness program hash mismatch | `QRH_SCHEME_UNKNOWN` |
| output committed to `0x02`, witness says `0x01` | Witness program hash mismatch | `WITNESS_PROGRAM_MISMATCH` |

The file will be made again against the first release that carries the change.
