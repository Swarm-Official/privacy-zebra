# SWARM destination-address tool

This downstream application is maintained in `brs-holding/privacy-zebra`. It is not an upstream Zebra release or an endorsement by the Zcash Foundation.

`zebrad/src/bin/swarm-keytool.rs` creates the P2SH script addresses that a configured Zebra Testnet needs for its funding-stream recipients. Zebra asserts `address must be P2SH` in `zebra-consensus/src/block/check.rs`, so a P2PKH (`tm…`) recipient makes the node panic at startup; the desktop wallet only produces P2PKH transparent addresses, which is why this tool exists.

## No new cryptography

The tool only:

- draws 32 bytes per key from the operating-system CSPRNG (`rand::rngs::OsRng`) and rejects the value if `secp256k1::SecretKey::from_slice` does not accept it;
- asks the `secp256k1` crate for the matching compressed public key;
- assembles the standard multisig redeem script `OP_M <pubkey…> OP_N OP_CHECKMULTISIG`, with the public keys in the order generated and each pushed as 33 bytes;
- computes HASH160 (`sha2::Sha256` then `ripemd::Ripemd160`), the same construction upstream Zebra uses for transparent addresses;
- passes the 20-byte hash to upstream `zebra_chain::transparent::Address::from_script_hash(NetworkKind::Testnet, …)` for encoding.

`ripemd` and `secp256k1` are listed in `zebrad/Cargo.toml` at the workspace versions that `zebra-chain` already uses, so no package or version in `Cargo.lock` changes; only zebrad's own dependency list gains the two names.

## Usage

```sh
swarm-keytool new --threshold M --keys N --label NAME --out DIR
swarm-keytool address --redeem-script HEX
```

`new` prints only the address, the redeem script hex, the public keys, the threshold and the path of the key file. `1 <= M <= N <= 15`; `--threshold 1 --keys 1` is a valid single-signature script. Private keys are written once to `DIR/NAME.keys.json` with `create_new`, so an existing key file is never overwritten, and `0600` permissions on Unix. They are never printed or logged. Labels are restricted to letters, digits, `-` and `_` because they become file names.

`address` recomputes the address from a redeem script and prints nothing else. It is the check to run before a recipient address is written into a network configuration.

Anyone holding `M` of the `N` keys can spend from the address. Spending from a P2SH multisig needs signing support that neither the desktop wallet nor Zallet provides today, so until a spending path is demonstrated these balances are "received and visible", not "spendable".

## Tests

`cargo test --locked --release --package zebrad --features internal-miner --bin swarm-keytool` runs the unit tests, which cover:

- upstream's own P2SH vector (a 20-byte all-zero script encodes to `t2L51LcmpA43UMvKTw2Lwtt9LMjwyqU2V1P`), pinning the HASH160 and Base58Check path;
- fixed 1-of-1 and 2-of-3 redeem scripts over the well-known public keys of the scalars 1, 2 and 3, with expected script hex, script hash and `t2…` address computed independently in Python (`hashlib` SHA-256 and RIPEMD-160 plus a hand-written Base58Check with the Zcash testnet P2SH prefix `0x1CBA`);
- script layout and public-key ordering;
- threshold and label validation;
- freshly generated keys producing distinct `t2…` addresses;
- the key file refusing to be overwritten.

This is a testnet engineering tool. It is not a key-ceremony procedure, not an audited custody solution and not a launch authorization.
