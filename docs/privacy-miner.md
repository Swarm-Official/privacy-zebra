# Privacy testnet miner application

This downstream application is maintained in `brs-holding/privacy-zebra`. It is not an upstream Zebra release or an endorsement by the Zcash Foundation.

`zebrad/src/bin/privacy-miner.rs` is a separate RPC client around Zebra's unchanged `proposal_block_from_template`, `Solution::solve`, Equihash verification, target checks and block serialization. It adds no cryptographic primitive or consensus rule. The source base is `7c64a8419388dd72664a19a70aed66e84f3e2d5b`; dependency versions remain in the existing Cargo.lock.

Build using Rust 1.91.0 and the existing workspace:

```sh
CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_PROFILE_RELEASE_LTO=false CARGO_INCREMENTAL=0 \
  cargo +1.91.0 build --locked --release --bin privacy-miner --features internal-miner -j 6
```

Run `privacy-miner --help`. A selected node URL, local cookie file, matching node configuration and explicit transparent testnet payout are required. The node must construct its coinbase for that same payout. The application refuses Mainnet, Regtest, disabled PoW, unexpected genesis, missing payout and unencrypted non-loopback RPC. Cookies are read from a local file and are not logged or passed as command-line passwords. Responses are capped at eight MiB.

One CPU worker solves real Equihash 200,9 work. The miner checks for changed chain tips, cancels stale work and handles Ctrl+C. `--blocks N` stops after N accepted blocks; zero runs until stopped. Accepted blocks must still be independently validated by peers. CPU capability on a low-difficulty testnet does not establish competitive CPU mining on a public network.

The client refuses configured target limits above the standard upstream Testnet bound. Upstream difficulty adjustment sums seventeen targets in U256; the earlier experimental V1 limit could overflow that arithmetic. V1 is retired and must not be mined further. The offline generator now uses safe compact bits `2007ffff` for the replacement V2 network. This changes application configuration and generation inputs, not the solver or adjustment algorithm.

The `genesis` subcommand constructs a deterministic disposable test genesis from the pinned historical Testnet fixture, preserving its original transaction. It uses the same upstream solver and verifies solution/target. This is not a production launch mechanism or an economic audit.

```sh
privacy-miner genesis UPSTREAM_TEST_GENESIS_HEX OUTPUT_JSON UNIX_TIME
```

`UNIX_TIME` is required. It is the header time in whole seconds and is the only per-network input: the fixture, its coinbase and Merkle root, the compact target `2007ffff`, the 32-zero-byte start nonce and the selection rule (smallest display-order hash among the solutions returned for the first successful nonce) are all unchanged. The manifest records the time that was actually used, the bits string and a purpose line naming SWARM, and both output files are created with `create_new`, so an existing genesis is never overwritten. Two runs of the same command into two fresh directories must produce byte-identical `genesis.hex` files.

Local integration evidence and Windows launchers are in the companion `brs-holding/privacy-network` repository. Verification includes real blocks accepted by three nodes, a corrupted Equihash header rejected, persistent restart, deterministic genesis reproduction, independent miner stop/restart and actual Ctrl+C handling. Boundary checks reject a wrong genesis, oversized RPC response, Regtest and unencrypted remote RPC. Full upstream workspace tests, production security review and the complete difficulty/fork test matrix are not implied by these targeted results.

Original upstream licenses remain applicable. The adapter is MIT OR Apache-2.0 and was developed with Codex assistance for the user's downstream test network.
