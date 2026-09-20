//! Standalone test-network miner using Zebra's existing block builder and Equihash solver.
// SPDX-License-Identifier: MIT OR Apache-2.0
// Application adapter around Zebra's unchanged block construction and Equihash solver.
// Build as zebrad/src/bin/privacy-miner.rs in the pinned Zebra workspace.

#[cfg(not(feature = "internal-miner"))]
fn main() {
    eprintln!("Build privacy-miner with --features internal-miner");
    std::process::exit(1);
}

#[cfg(feature = "internal-miner")]
mod app {
    use color_eyre::eyre::{bail, eyre, Result};
    use rand::RngCore;
    use serde_json::{json, Value};
    use std::{
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };
    use zebra_chain::{
        parameters::{Network, NetworkKind},
        serialization::{ZcashDeserializeInto, ZcashSerialize},
        transparent::Address,
        work::{
            difficulty::{CompactDifficulty, ParameterDifficulty},
            equihash::{Solution, SolverCancelled},
        },
    };
    use zebra_rpc::{
        client::{BlockTemplateResponse, BlockTemplateTimeSource},
        proposal_block_from_template,
    };

    const HELP: &str = "Privacy CPU Miner — separate application using Zebra's upstream Equihash 200,9 solver\n\
Usage: privacy-miner --config NODE_CONFIG --rpc URL --cookie COOKIE_FILE --payout TESTNET_T_ADDRESS [--blocks COUNT]\n\
Use the same custom-Testnet network configuration as your node. Set [mining].miner_address\n\
on that node to your chosen payout first. This client verifies the coinbase recipient.\n\
One CPU worker; --blocks 0 (default) runs until Ctrl+C. Mainnet and Regtest are refused.\n\
HTTP is permitted only on loopback; use HTTPS or a local SSH tunnel for your remote node.\n\
Offline TEST genesis: privacy-miner genesis UPSTREAM_TEST_GENESIS_HEX OUTPUT_JSON\n\
The test genesis uses a fixed timestamp/target and the unchanged upstream coinbase fixture.\n\
It is not a mainnet launch genesis or final economic configuration.";

    struct Options {
        config: PathBuf,
        rpc: reqwest::Url,
        cookie: PathBuf,
        payout: String,
        blocks: u64,
    }

    fn options() -> Result<Option<Options>> {
        let mut args = std::env::args().skip(1);
        let (mut config, mut endpoint, mut cookie, mut payout) = (None, None, None, None);
        let mut blocks = 0;
        while let Some(key) = args.next() {
            if key == "--help" || key == "-h" {
                println!("{HELP}");
                return Ok(None);
            }
            let value = args
                .next()
                .ok_or_else(|| eyre!("Missing argument value; use --help"))?;
            match key.as_str() {
                "--config" => config = Some(PathBuf::from(value)),
                "--rpc" => endpoint = Some(value),
                "--cookie" => cookie = Some(PathBuf::from(value)),
                "--payout" => payout = Some(value),
                "--blocks" => blocks = value.parse()?,
                _ => bail!("Unknown option; use --help"),
            }
        }
        let rpc = reqwest::Url::parse(&endpoint.ok_or_else(|| eyre!("--rpc is required"))?)?;
        let loopback = matches!(
            rpc.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
        );
        if !rpc.username().is_empty()
            || rpc.password().is_some()
            || rpc.query().is_some()
            || rpc.fragment().is_some()
        {
            bail!("RPC URL must not contain credentials, queries or fragments; use --cookie");
        }
        if rpc.scheme() != "https" && !(rpc.scheme() == "http" && loopback) {
            bail!("Remote RPC requires HTTPS or a loopback SSH tunnel");
        }
        Ok(Some(Options {
            config: config.ok_or_else(|| eyre!("--config is required"))?,
            rpc,
            cookie: cookie.ok_or_else(|| eyre!("--cookie is required"))?,
            payout: payout.ok_or_else(|| eyre!("--payout is required"))?,
            blocks,
        }))
    }

    struct Rpc {
        client: reqwest::Client,
        endpoint: reqwest::Url,
        cookie: PathBuf,
    }
    impl Rpc {
        async fn call(&self, method: &str, params: Value) -> Result<Value> {
            // Reread the cookie for each call so node restarts do not retain stale credentials.
            let cookie = std::fs::read_to_string(&self.cookie)?;
            let (user, password) = cookie
                .trim()
                .split_once(':')
                .ok_or_else(|| eyre!("Invalid RPC cookie format"))?;
            let mut response = self
                .client
                .post(self.endpoint.clone())
                .basic_auth(user, Some(password))
                .header("Content-Type", "application/json")
                .body(serde_json::to_vec(
                    &json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}),
                )?)
                .send()
                .await
                .map_err(|_| eyre!("RPC transport failed for {method}"))?;
            if !response.status().is_success() {
                bail!("RPC HTTP status {} for {method}", response.status());
            }
            // Bound a selected server's reply before allocating its full body.
            // Eight MiB accommodates a serialized Zcash block template.
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                if body.len().saturating_add(chunk.len()) > 8 * 1024 * 1024 {
                    bail!("RPC {method} response exceeds the application limit");
                }
                body.extend_from_slice(&chunk);
            }
            let result: Value = serde_json::from_slice(&body)?;
            if !result["error"].is_null() {
                // Server messages are deliberately not copied: they can include confidential inputs.
                bail!("RPC {method} failed (code {})", result["error"]["code"]);
            }
            result
                .get("result")
                .cloned()
                .ok_or_else(|| eyre!("RPC response missing result"))
        }
    }

    fn genesis() -> Result<()> {
        use std::io::Write;
        let args: Vec<_> = std::env::args().skip(2).collect();
        if args.len() != 2 {
            bail!("Usage: privacy-miner genesis UPSTREAM_TEST_GENESIS_HEX OUTPUT_JSON");
        }
        let input = std::fs::read_to_string(&args[0])?;
        let bytes = hex::decode(input.split_whitespace().collect::<String>())?;
        let mut block: zebra_chain::block::Block = bytes.as_slice().zcash_deserialize_into()?;
        if block.hash().to_string()
            != "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38"
        {
            bail!("Expected the pinned original Zcash Testnet genesis fixture");
        }
        let mut header = *block.header;
        header.time = chrono::DateTime::from_timestamp(1789862400, 0)
            .ok_or_else(|| eyre!("Invalid fixed timestamp"))?;
        header.difficulty_threshold =
            CompactDifficulty::from_bytes_in_display_order(&[0x20, 0x07, 0xff, 0xff])
                .map_err(|e| eyre!("Invalid fixed target: {e}"))?;
        header.nonce = [0; 32].into();
        println!("Solving deterministic TEST genesis with upstream Equihash solver...");
        let solved =
            Solution::solve(header, || Ok(())).map_err(|_| eyre!("Genesis solver cancelled"))?;
        let mut headers: Vec<_> = solved.into_iter().collect();
        headers.sort_by_key(|h| h.hash().to_string());
        let header = headers
            .into_iter()
            .next()
            .ok_or_else(|| eyre!("No solved header"))?;
        header.solution.check(&header)?;
        if header.hash()
            > header
                .difficulty_threshold
                .to_expanded()
                .ok_or_else(|| eyre!("Invalid target"))?
        {
            bail!("Solved genesis does not meet its target");
        }
        block.header = Arc::new(header);
        let hex_path = PathBuf::from(&args[1]).with_file_name("genesis.hex");
        let report = json!({
            "purpose":"Disposable Privacy PoW testnet genesis; not a mainnet launch",
            "upstream_revision":"7c64a8419388dd72664a19a70aed66e84f3e2d5b",
            "upstream_genesis":"05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38",
            "timestamp":1789862400u32, "bits":"2007ffff", "nonce_start":"00".repeat(32),
            "selection":"First successful upstream solver nonce, smallest display-order hash among returned headers",
            "hash":block.hash().to_string(), "block_hex":hex::encode(block.zcash_serialize_to_vec()?),
            "genesis_hash":block.hash().to_string(), "genesis_hex_file":hex_path.file_name().and_then(|n| n.to_str()),
            "source_revision":"7c64a8419388dd72664a19a70aed66e84f3e2d5b",
            "solver_version":"zebra-chain 12.0.0 / equihash 0.3 / upstream tromp solve_200_9",
            "nonce":hex::encode(&header.nonce[..]),
            "equihash_verified":true, "target_verified":true,
            "coinbase":"Unchanged upstream historical genesis fixture; Zebra excludes genesis outputs from UTXO state"
        });
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&args[1])?;
        let mut hex_output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&hex_path)?;
        hex_output.write_all(hex::encode(block.zcash_serialize_to_vec()?).as_bytes())?;
        hex_output.write_all(b"\n")?;
        output.write_all(serde_json::to_string_pretty(&report)?.as_bytes())?;
        output.write_all(b"\n")?;
        println!("TEST genesis {} saved to {}", block.hash(), args[1]);
        Ok(())
    }

    pub async fn run() -> Result<()> {
        if std::env::args().nth(1).as_deref() == Some("genesis") {
            return genesis();
        }
        let Some(opts) = options()? else {
            return Ok(());
        };
        let config: zebrad::config::ZebradConfig =
            toml::from_str(&std::fs::read_to_string(&opts.config)?)?;
        let network = &config.network.network;
        if network.kind() != NetworkKind::Testnet || network.disable_pow() {
            bail!("This miner requires a PoW-enabled Testnet; Mainnet and Regtest are refused");
        }
        // Upstream retargeting sums seventeen expanded targets in U256. Its
        // arithmetic assumes targets stay within the standard Testnet limit.
        if network.target_difficulty_limit()
            > Network::new_default_testnet().target_difficulty_limit()
        {
            bail!("Configured target limit exceeds the upstream retarget arithmetic bound; use the corrected testnet profile");
        }
        let payout: Address = opts.payout.parse()?;
        if payout.network_kind() != NetworkKind::Testnet {
            bail!("Payout must be a Testnet transparent address");
        }
        if config
            .mining
            .miner_address
            .as_ref()
            .map(ToString::to_string)
            .as_deref()
            != Some(opts.payout.as_str())
        {
            bail!("Payout does not match [mining].miner_address in the node configuration");
        }
        let rpc = Rpc {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()?,
            endpoint: opts.rpc,
            cookie: opts.cookie,
        };
        let genesis = rpc.call("getblockhash", json!([0])).await?;
        if genesis.as_str() != Some(network.genesis_hash().to_string().as_str()) {
            bail!("Connected node genesis does not match the selected network configuration");
        }
        println!(
            "Connected to {}. Payout {}. One CPU worker; Ctrl+C stops mining.",
            rpc.endpoint, opts.payout
        );
        println!("Upstream Equihash 200,9 proof solving and target checks enabled.");
        let stopped = Arc::new(AtomicBool::new(false));
        let stop_signal = stopped.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                stop_signal.store(true, Ordering::Relaxed);
            }
        });
        let mut accepted = 0u64;
        while !stopped.load(Ordering::Relaxed) && (opts.blocks == 0 || accepted < opts.blocks) {
            let template: BlockTemplateResponse = serde_json::from_value(
                rpc.call(
                    "getblocktemplate",
                    json!([{"capabilities":["coinbasetxn"],"mode":"template"}]),
                )
                .await?,
            )?;
            let block =
                proposal_block_from_template(&template, BlockTemplateTimeSource::CurTime, network)?;
            let coinbase = block
                .transactions
                .first()
                .ok_or_else(|| eyre!("Template has no coinbase"))?;
            let paid: u64 = coinbase
                .outputs()
                .iter()
                .filter(|o| o.lock_script == payout.script())
                .try_fold(0u64, |total, output| {
                    total
                        .checked_add(u64::from(output.value))
                        .ok_or_else(|| eyre!("Template payout total overflow"))
                })?;
            if paid == 0 {
                bail!("Node template does not pay the chosen address; mining stopped");
            }
            println!(
                "Working on height {} | payout {} zatoshis | target {:?}",
                template.height(),
                paid,
                template.target()
            );
            let mut header = *block.header;
            rand::thread_rng().fill_bytes(&mut header.nonce[..]);
            let expected_tip = header.previous_block_hash.to_string();
            let cancel = Arc::new(AtomicBool::new(false));
            let solver_cancel = cancel.clone();
            let solver_stop = stopped.clone();
            let mut solver = tokio::task::spawn_blocking(move || {
                Solution::solve(header, || {
                    if solver_cancel.load(Ordering::Relaxed) || solver_stop.load(Ordering::Relaxed)
                    {
                        Err(SolverCancelled)
                    } else {
                        Ok(())
                    }
                })
            });
            let started = Instant::now();
            let mut poll = tokio::time::interval(Duration::from_secs(2));
            let solved = loop {
                tokio::select! {
                    result = &mut solver => { break result?; }
                    _ = poll.tick() => {
                        if stopped.load(Ordering::Relaxed) || started.elapsed() > Duration::from_secs(60) {
                            cancel.store(true, Ordering::Relaxed);
                        } else {
                            match rpc.call("getbestblockhash", json!([])).await {
                                Ok(tip) if tip.as_str() == Some(expected_tip.as_str()) => {},
                                Ok(_) => { println!("Chain tip changed; refreshing work."); cancel.store(true, Ordering::Relaxed); },
                                Err(_) => { println!("Node unavailable; cancelling current work."); cancel.store(true, Ordering::Relaxed); },
                            }
                        }
                    }
                }
            };
            if stopped.load(Ordering::Relaxed) {
                break;
            }
            let Ok(headers) = solved else {
                continue;
            };
            // Refresh on stale work even if a solution races with the cancellation signal.
            if cancel.load(Ordering::Relaxed) {
                continue;
            }
            for header in headers {
                let mut candidate = block.clone();
                candidate.header = Arc::new(header);
                let hash = candidate.hash().to_string();
                let result = rpc
                    .call(
                        "submitblock",
                        json!([hex::encode(candidate.zcash_serialize_to_vec()?)]),
                    )
                    .await?;
                if result.is_null() {
                    accepted += 1;
                    println!(
                        "ACCEPTED height {} hash {} elapsed {:.2}s accepted {}",
                        template.height(),
                        hash,
                        started.elapsed().as_secs_f64(),
                        accepted
                    );
                    break;
                } else {
                    println!("REJECTED height {} hash {}", template.height(), hash);
                }
            }
        }
        println!("Miner stopped; accepted {accepted} blocks.");
        Ok(())
    }
}

#[cfg(feature = "internal-miner")]
#[tokio::main]
async fn main() {
    if let Err(error) = app::run().await {
        eprintln!("Miner stopped: {error}");
        std::process::exit(1);
    }
}
