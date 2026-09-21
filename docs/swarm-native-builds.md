# SWARM native `zebrad` builds

This branch (`swarm-ci`) is the unmodified Zebra source at tag **v6.3.0** plus a
single GitHub Actions workflow, `.github/workflows/swarm-binaries.yml`. Its job
is to produce a `zebrad` binary with Zebra's optional internal CPU miner for
Windows, Linux and macOS, so that the SWARM Node desktop app can bundle a node
that users can run and mine with on their own machine.

Upstream lists `x86_64-pc-windows-msvc` as a
[Tier-3 platform](../book/src/user/supported-platforms.md): supported in code,
never built or tested by upstream CI. Proving the Windows build is the point of
this branch.

## Consensus safety

Nothing that affects consensus is changed on this branch:

- the tree is tag `v6.3.0` (`git diff v6.3.0` shows only this document and the
  workflow file);
- no Rust source, no `Cargo.toml`, no `Cargo.lock` is touched;
- the build uses `--locked`, so the dependency graph is exactly the one the
  official v6.3.0 release was built from;
- the feature set is the upstream release set (`default`, which expands to
  `default-release-binaries`) plus `internal-miner`. `internal-miner` adds
  `equihash/solver` (the tromp Equihash 200,9 solver) and the `zebrad` mining
  task. It adds no consensus rules and changes none.

The resulting binary is therefore consensus-identical to the official
v6.3.0 release that PrivacyTestnetV2 already runs, with mining code added.

`internal-miner` mines with the real Equihash solver
(`zebra_chain::work::equihash::Solution::solve` → `equihash::tromp::solve_200_9`)
and checks the difficulty threshold before submitting. The stale doc comment on
`zebra_rpc::config::mining::Config::internal_miner` that says the feature "uses
null solutions and skips checking for a valid Proof of Work" does not match the
code at this tag.

## What the workflow does

Triggers: `workflow_dispatch`, and any push to `swarm-ci`.

| Runner | Rust target |
| --- | --- |
| `windows-latest` | `x86_64-pc-windows-msvc` |
| `ubuntu-22.04` | `x86_64-unknown-linux-gnu` (low glibc floor) |
| `macos-latest` | `aarch64-apple-darwin` |

Per job:

1. Install build prerequisites — `clang`/`libclang` (RocksDB's bindgen),
   `cmake`, and `protoc`. On Windows `LIBCLANG_PATH` is pointed at the runner's
   bundled LLVM; `protoc` is best-effort there because `zebra-rpc/build.rs`
   falls back to its pre-generated indexer protos when `protoc` is missing.
2. Install the toolchain from the tag's own `rust-toolchain.toml`
   (`channel = 1.91.0`, which satisfies `zebrad`'s `rust-version = 1.91`).
   `rustflags` is set to the empty string so the action's default `-D warnings`
   cannot turn a Tier-3 platform warning into a build failure.
3. Cache with `Swatinem/rust-cache`.
4. `cargo build --locked --release --package zebrad --bin zebrad --features internal-miner`.
5. Smoke test: `zebrad --version`, `zebrad generate -o generated.toml`, then run
   `zebrad start` for 30 s against a configured Testnet with an **ephemeral**
   state directory and **no peers at all**. The job fails unless the log
   contains both `Opened Zebra state cache at` and
   `Opened Zcash protocol endpoint at`, and fails if the log contains a panic.
6. Package `zebrad(.exe)`, `LICENSE-APACHE`, `LICENSE-MIT`, `README.md` and a
   `build-manifest.json` (git commit, tag, `rustc -Vv`, cargo features, runner
   image, UTC build time) into
   `swarm-zebrad-v6.3.0-<target>.zip` (Windows) or `.tar.gz`, with a
   `SHA256SUMS` file, and upload both as a workflow artifact with 30-day
   retention. Archive members sit at the archive root, with no wrapping
   directory.

All third-party actions are pinned to full commit SHAs. The workflow needs no
secrets and requests only `contents: read`.

## Running it

```bash
gh workflow run swarm-binaries.yml --ref swarm-ci -R brs-holding/privacy-zebra
gh run list --workflow=swarm-binaries.yml -R brs-holding/privacy-zebra --limit 1
gh run watch <run-id> -R brs-holding/privacy-zebra --exit-status
```

Always pass `-R brs-holding/privacy-zebra`: this repository is a fork, and `gh`
otherwise resolves to the upstream parent.

## Downloading and verifying

```bash
gh run download <run-id> -R brs-holding/privacy-zebra \
  -n swarm-zebrad-x86_64-pc-windows-msvc -D ./dl
cd dl
sha256sum -c SHA256SUMS        # PowerShell: Get-FileHash -Algorithm SHA256
```

`SHA256SUMS` covers the archive. `build-manifest.json` inside the archive
records the commit, tag, compiler and runner that produced the binary. These are
plain workflow artifacts, not signed releases: there is no cosign signature or
build attestation, unlike upstream's official Linux release pipeline.

## Results

First run, no retries:
<https://github.com/brs-holding/privacy-zebra/actions/runs/35603263833>
(commit `cb99dd063feaac493f93fdfca3e7d7acad685573`, all three jobs green,
`rustc 1.91.0 (f8297e351 2025-10-28)`, `zebrad 6.3.0` on every platform).

| Target | Runner image | Build + smoke | Archive | SHA-256 of the archive |
| --- | --- | --- | --- | --- |
| `x86_64-pc-windows-msvc` | `win25-vs2026/20260907.229.1` | 22 min, pass | `swarm-zebrad-v6.3.0-x86_64-pc-windows-msvc.zip` | `7b427286704d618e34937f84dcf4b6e455353f8009abf6d3ed164758f691af2c` |
| `x86_64-unknown-linux-gnu` | `ubuntu22/20260907.292.1` | 13 min, pass | `swarm-zebrad-v6.3.0-x86_64-unknown-linux-gnu.tar.gz` | `f221191bd18a7c77a6ea40da0939afc8a400927b6ddb27adafa180008dc88390` |
| `aarch64-apple-darwin` | `macos26/20260907.0351.1` | 11 min, pass | `swarm-zebrad-v6.3.0-aarch64-apple-darwin.tar.gz` | `41ff37138d4b2f38db66f1b9baecf83a620120a7b7d390ed174c0050940b1ad7` |

Unpacked Windows binary: `zebrad.exe`, 84 311 552 bytes, SHA-256
`b6ea39096b99debd64b248789d47c8a3a94afea5541e3a75f896b552ac61c477`.

### Windows acceptance on a real machine

The Windows binary was run natively (not under WSL) on Windows 11 Pro
26200 as an ordinary P2P peer of the live PrivacyTestnetV2 network
(three official Zebra 6.3.0 Linux nodes in WSL1 on loopback).

| Measurement | Result |
| --- | --- |
| Peers connected | 3 of 3 (`127.0.0.1:19731-3`, all outbound) |
| Height / best block hash | 144 / `03cb99c4…47f838` — identical to V2 node 1 |
| `difficulty` | `1.9233960907463388` — identical to V2 node 1 |
| Time from process start to synced tip | 12.8 s |
| Peak working set while syncing | 61.4 MB (steady ~57 MB) |
| State on disk at height 144 | 573 KB (genesis in RocksDB, 144 blocks in the non-finalized backup) |
| Graceful stop | `CTRL_C_EVENT` → clean shutdown in 0.4 s, `received Ctrl-C, starting shutdown` |
| Restart | reopened the state with **zero peers configured**, `restored blocks from non-finalized backup cache num_blocks_restored=144`, same tip hash |

Nothing was written to the V2 nodes: only `getblockchaininfo` /
`getbestblockhash` were called against them, and all three stayed at height 144.

### Internal miner acceptance (throwaway network only)

A disposable single-node network (`SwarmCiThrowaway`, magic `[83,67,73,84]`,
no peers, real PoW) reusing the V2 genesis block, which was submitted through
the node's own `submitblock`. 23 blocks were mined by the native Windows binary
on a Ryzen 9 5950X.

| Question | Answer |
| --- | --- |
| Does the internal miner start on a configured Testnet? | Yes. `spawning Zcash miner` → `launching mining tasks with parallel solvers solver_count=1`. No Regtest gate; the only gates are the `internal-miner` cargo feature and `mining.internal_miner = true`. |
| Solver threads | **1, hard-coded.** `zebrad/src/components/miner.rs` sets `let configured_threads = 1;` with a TODO pointing at upstream issue #8797. There is no config key at v6.3.0. |
| CPU | ~1.0–1.6 logical cores (≈5 % of a 32-thread machine), miner thread runs at lowest thread priority |
| RAM | peak working set 388 MB while mining (58 MB as a plain node) |
| Seconds per block at the minimum difficulty (`difficulty = 1.0`) | mean 16 s, median 10 s, range 0.7–63 s over 13 samples |
| Mining status over RPC | `getmininginfo` reports only chain-level data (`blocks`, `currentblocksize`, `networksolps`); it has **no** field saying whether the internal miner is running. `getnetworksolps` returned `0` throughout on this minimum-difficulty chain. |
| Prometheus metrics | No miner-specific metric exists. Progress is visible only indirectly (`zcash_chain_verified_block_total`, `state_memory_best_committed_block_count`) or from the log line `successfully mined a new block`. |
| Transparent `miner_address` | Works. Block 1 coinbase paid 6.25 to `tmJymvcUCn1ctbghvTJpXBwHiMEB8P6wxNV`. |
| Unified `miner_address` with a shielded receiver | Works. Using Zebra's own documented default testnet UA from `zebra-rpc/src/config/mining.rs`, the config parsed, the miner started, and block 17's coinbase had **zero transparent outputs** and a single Ironwood (NU6.3) shielded action with `valueBalance = -6.25`. |

## Known platform notes

For bundling `zebrad.exe` inside a desktop app:

- **Console subsystem.** The PE subsystem is `WINDOWS_CUI`, so spawning it
  creates a console window unless the parent passes `windowsHide: true`.
- **Graceful shutdown is Ctrl-C only.** On Windows Zebra waits on
  `tokio::signal::ctrl_c()` and explicitly does not implement NT service
  control (`zebrad/src/components/tokio.rs`). Node's
  `child.kill('SIGTERM')` maps to `TerminateProcess`, a hard kill.
  `taskkill /PID <pid>` without `/F` **fails** ("can only be terminated
  forcefully") because the process has no window. The only graceful stop is a
  real `CTRL_C_EVENT` via `AttachConsole` + `GenerateConsoleCtrlEvent`
  (see the helper used for the acceptance run).
- **MSVC runtime.** `zebrad.exe` imports `VCRUNTIME140.dll`,
  `VCRUNTIME140_1.dll` and `MSVCP140.dll`, which are **not** part of a clean
  Windows install. Ship the Visual C++ 2015-2022 x64 redistributable, or the
  three DLLs, with the app. The `api-ms-win-crt-*` imports are the UCRT and are
  part of Windows 10 and later.
- **State locking.** The RocksDB state directory is held exclusively; a second
  `zebrad` on the same `state.cache_dir` will not start. Shutdown logs
  `forcing shutdown of a state database with multiple active instances`, which
  is normal.
- **Mark of the web.** Artifacts fetched with `gh run download` carry no
  `Zone.Identifier` stream, so no SmartScreen prompt was seen. A browser
  download of the same zip would add one, and an unsigned `zebrad.exe` inside
  an unsigned installer will trigger SmartScreen until a code-signing
  certificate is bought.
- **No peers means mining on a stale tip.** `check_synced_to_tip` in
  `zebra-rpc/src/methods/types/get_block_template.rs` returns early for any
  test network, so a Testnet node with zero peers will happily build templates
  and mine on whatever tip it has. That is what makes the throwaway network
  work, and it is also a hazard for a shipped app: it must ensure peers before
  it starts mining.
