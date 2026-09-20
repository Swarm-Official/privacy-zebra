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

The `genesis` subcommand constructs a deterministic disposable test genesis from the pinned historical Testnet fixture, preserving its original transaction. It uses the same upstream solver and verifies solution/target. This is not a production launch mechanism or an economic audit.

Local integration evidence and Windows launchers are in the companion `brs-holding/privacy-network` repository. Verification includes real blocks accepted by three nodes, a corrupted Equihash header rejected, persistent restart, deterministic genesis reproduction, independent miner stop/restart and actual Ctrl+C handling. Boundary checks reject a wrong genesis, oversized RPC response, Regtest and unencrypted remote RPC. Full upstream workspace tests, production security review and the complete difficulty/fork test matrix are not implied by these targeted results.

Original upstream licenses remain applicable. The adapter is MIT OR Apache-2.0 and was developed with Codex assistance for the user's downstream test network.
