//! `swarm-treasury` — the offline 2-of-3 custody tool for the SWARM treasury.
//!
//! Every subcommand is offline and file-based: nothing here opens a socket or talks to a node. The
//! command-line conventions follow `swarm-keytool` — `--option value` pairs, no positional
//! arguments except the single file a `verify`/`show` reads, and a refusal rather than a guess.
//!
//! See `docs/swarm-treasury.md` for the ceremony these subcommands are meant to be run in.

// A command-line tool prints its results.
#![allow(clippy::print_stdout, clippy::print_stderr)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{path::PathBuf, process::ExitCode};

use rand::{rngs::OsRng, RngCore};
use swarm_treasury::{
    network::TreasuryNetwork,
    policy::{self, Fund, Policy},
    refuse,
    shielded::{self, Pool},
    signer::{self, SignerPublic, SignerSecret},
    spend::{self, Proposal, SignatureFile},
    utxo::{self, UtxoFile},
    Result, TOOL_VERSION,
};

const HELP: &str = "\
swarm-treasury — offline 2-of-3 custody for the SWARM treasury

Usage:
  swarm-treasury signer new      --label A --out DIR
  swarm-treasury signer recover  --backup A.signer.age --expect A.public.json
  swarm-treasury signer check    --backup A.signer.age --policy policy.json
  swarm-treasury policy assemble --fund Core --threshold 2 --network testnet \\
                                 --public A.public.json --public B.public.json \\
                                 --public C.public.json --out policy.json
  swarm-treasury policy verify   policy.json
  swarm-treasury spend propose   --policy policy.json --utxos utxos.json --to ADDRESS \\
                                 --fee ZAT --expiry-height H --network-upgrade nu6_3 \\
                                 [--memo TEXT] --out proposal.json
  swarm-treasury spend show      proposal.json [--policy policy.json]
  swarm-treasury spend sign      --proposal proposal.json --signer A.signer.age \\
                                 [--policy policy.json] --out A.sig.json
  swarm-treasury spend combine   --proposal proposal.json --sig A.sig.json --sig B.sig.json \\
                                 [--policy policy.json] --out final.hex
  swarm-treasury --help
  swarm-treasury --version

Each device runs `signer new` once and shares ONLY its .public.json. The coordinator runs
`policy assemble`; every device runs `policy verify` on the result. To disburse, the
coordinator runs `spend propose`, two devices run `spend show` and then `spend sign`, and the
coordinator runs `spend combine` and broadcasts the hex with sendrawtransaction.

Backup passphrases are read from the SWARM_TREASURY_PASSPHRASE environment variable if it is
set, otherwise from a prompt. They are never taken from the command line.

Networks: testnet, swarmrehearsal. The swarmmain address encoding is on another branch and
this build refuses it rather than handing back a testnet address.

This tool never talks to a node, never holds more than one signer key per device, keeps no
change (whole selected UTXOs minus the fee go to the shielded recipient) and is not a hardware
wallet. Read docs/swarm-treasury.md before using it with real value.";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("swarm-treasury: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match (
        arguments.first().map(String::as_str),
        arguments.get(1).map(String::as_str),
    ) {
        (None, _) | (Some("--help" | "-h" | "help"), _) => {
            println!("{HELP}");
            Ok(())
        }
        (Some("--version"), _) => {
            println!("swarm-treasury {TOOL_VERSION}");
            Ok(())
        }
        (Some("signer"), Some("new")) => signer_new(&arguments[2..]),
        (Some("signer"), Some("recover")) => signer_recover(&arguments[2..]),
        (Some("signer"), Some("check")) => signer_check(&arguments[2..]),
        (Some("policy"), Some("assemble")) => policy_assemble(&arguments[2..]),
        (Some("policy"), Some("verify")) => policy_verify(&arguments[2..]),
        (Some("spend"), Some("propose")) => spend_propose(&arguments[2..]),
        (Some("spend"), Some("show")) => spend_show(&arguments[2..]),
        (Some("spend"), Some("sign")) => spend_sign(&arguments[2..]),
        (Some("spend"), Some("combine")) => spend_combine(&arguments[2..]),
        (Some(group @ ("signer" | "policy" | "spend")), other) => {
            Err(refuse!("unknown {group} subcommand {other:?}; use --help"))
        }
        (Some(other), _) => Err(refuse!("unknown subcommand {other:?}; use --help")),
    }
}

// -- argument parsing --------------------------------------------------------

/// Parsed `--key value` pairs, plus at most one leading positional argument.
struct Arguments {
    positional: Option<String>,
    options: Vec<(String, String)>,
}

impl Arguments {
    /// Parses `args`, rejecting unknown options and options repeated when they may not be.
    fn parse(args: &[String], allowed: &[&str], repeatable: &[&str]) -> Result<Self> {
        let mut positional = None;
        let mut options: Vec<(String, String)> = Vec::new();
        let mut iter = args.iter().peekable();

        if let Some(first) = iter.peek() {
            if !first.starts_with("--") {
                positional = Some((*first).clone());
                iter.next();
            }
        }

        while let Some(key) = iter.next() {
            if key == "--help" || key == "-h" {
                println!("{HELP}");
                std::process::exit(0);
            }
            let name = key
                .strip_prefix("--")
                .ok_or_else(|| refuse!("expected an option starting with --, found {key:?}"))?;
            if !allowed.contains(&name) {
                return Err(refuse!("unknown option --{name}; use --help"));
            }
            if !repeatable.contains(&name) && options.iter().any(|(seen, _)| seen == name) {
                return Err(refuse!("option --{name} was given twice"));
            }
            let value = iter
                .next()
                .ok_or_else(|| refuse!("option --{name} needs a value"))?;
            options.push((name.to_string(), value.clone()));
        }

        Ok(Arguments {
            positional,
            options,
        })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn required(&self, name: &str) -> Result<&str> {
        self.get(name)
            .ok_or_else(|| refuse!("--{name} is required; use --help"))
    }

    fn all(&self, name: &str) -> Vec<&str> {
        self.options
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    fn required_positional(&self, what: &str) -> Result<&str> {
        self.positional
            .as_deref()
            .ok_or_else(|| refuse!("a {what} path is required; use --help"))
    }

    fn required_number<T: std::str::FromStr>(&self, name: &str) -> Result<T> {
        self.required(name)?
            .parse()
            .map_err(|_| refuse!("--{name} must be a whole number"))
    }
}

// -- file helpers ------------------------------------------------------------

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    let body =
        std::fs::read_to_string(path).map_err(|error| refuse!("could not read {path}: {error}"))?;
    serde_json::from_str(&body).map_err(|error| refuse!("{path} is not the JSON expected: {error}"))
}

fn write_json_new<T: serde::Serialize>(path: &PathBuf, value: &T) -> Result<()> {
    let mut body = serde_json::to_vec_pretty(value)
        .map_err(|error| refuse!("could not serialize {}: {error}", path.display()))?;
    body.push(b'\n');
    signer::write_new_file(path, &body)
}

// -- signer ------------------------------------------------------------------

fn signer_new(args: &[String]) -> Result<()> {
    let args = Arguments::parse(args, &["label", "out"], &[])?;
    let label = args.required("label")?;
    let directory = PathBuf::from(args.required("out")?);

    signer::check_label(label)?;
    let (backup_path, public_path) = signer::signer_paths(&directory, label);
    if backup_path.exists() || public_path.exists() {
        return Err(refuse!(
            "signer {label} already has files in {}; this tool never overwrites a signer key",
            directory.display(),
        ));
    }

    let passphrase = signer::read_passphrase(&format!(
        "Choose a passphrase for signer {label}'s encrypted backup. \
         Write it down and keep it somewhere the backup is not."
    ))?;

    let secret = signer::generate(label)?;
    let encrypted = signer::encrypt_backup(&secret, &passphrase)?;

    // The encrypted key first: printing a public key whose secret was never stored would be worse
    // than failing.
    signer::write_new_file(&backup_path, &encrypted)?;
    write_json_new(&public_path, &secret.public())?;

    println!("label        {}", secret.label);
    println!("public_key   {}", secret.public_key);
    println!("fingerprint  {}", secret.fingerprint);
    println!("created      {}", secret.created);
    println!("backup       {}", backup_path.display());
    println!("public       {}", public_path.display());
    println!();
    println!(
        "Share ONLY {}. The backup and its passphrase never leave this device",
        public_path.display()
    );
    println!("together, and no other device ever sees this key.");
    Ok(())
}

fn signer_recover(args: &[String]) -> Result<()> {
    let args = Arguments::parse(args, &["backup", "expect"], &[])?;
    let backup_path = args.required("backup")?;
    let expected_path = args.required("expect")?;

    let ciphertext = std::fs::read(backup_path)
        .map_err(|error| refuse!("could not read {backup_path}: {error}"))?;
    let expected: SignerPublic = read_json(expected_path)?;
    let expected_key = expected.validate()?;

    let passphrase = signer::read_passphrase("Enter the passphrase for this signer backup.")?;
    let secret = signer::decrypt_backup(&ciphertext, &passphrase)?;
    let (_secret_key, public_key) = secret.key_pair()?;

    if public_key != expected_key {
        return Err(refuse!(
            "the backup holds a different key than {expected_path}: the backup's fingerprint is \
             {}, the expected one is {}",
            secret.fingerprint,
            expected.fingerprint,
        ));
    }
    if secret.label != expected.label {
        return Err(refuse!(
            "the backup is labelled {:?}, the public record is labelled {:?}",
            secret.label,
            expected.label,
        ));
    }

    println!("label        {}", secret.label);
    println!("fingerprint  {}", secret.fingerprint);
    println!("public_key   {}", secret.public_key);
    println!("created      {}", secret.created);
    println!("recovered    yes — the backup decrypts and holds the expected key");
    Ok(())
}

fn signer_check(args: &[String]) -> Result<()> {
    let args = Arguments::parse(args, &["backup", "policy"], &[])?;
    let backup_path = args.required("backup")?;
    let policy_path = args.required("policy")?;

    let ciphertext = std::fs::read(backup_path)
        .map_err(|error| refuse!("could not read {backup_path}: {error}"))?;
    let policy: Policy = read_json(policy_path)?;
    let checked = policy::verify(&policy)?;

    let passphrase = signer::read_passphrase("Enter the passphrase for this signer backup.")?;
    let secret: SignerSecret = signer::decrypt_backup(&ciphertext, &passphrase)?;
    let (_secret_key, public_key) = secret.key_pair()?;

    let index = checked.index_of(&public_key).ok_or_else(|| {
        refuse!(
            "this backup is not one of the {} fund's keys",
            checked.policy.fund
        )
    })?;

    println!("fund         {}", checked.policy.fund);
    println!("address      {}", checked.policy.address);
    println!("policy       {}", checked.policy.policy_fingerprint);
    println!("label        {}", secret.label);
    println!("fingerprint  {}", secret.fingerprint);
    println!("key index    {index} of {}", checked.public_keys.len());
    println!("belongs      yes — this backup is one of the policy's keys");
    Ok(())
}

// -- policy ------------------------------------------------------------------

fn policy_assemble(args: &[String]) -> Result<()> {
    let args = Arguments::parse(
        args,
        &["fund", "threshold", "public", "network", "out"],
        &["public"],
    )?;
    let fund = Fund::parse(args.required("fund")?)?;
    let threshold: u8 = args.required_number("threshold")?;
    let network = TreasuryNetwork::parse(args.required("network")?)?;
    let out = PathBuf::from(args.required("out")?);

    let public_paths = args.all("public");
    if public_paths.is_empty() {
        return Err(refuse!("at least one --public record is required"));
    }
    let mut signers = Vec::with_capacity(public_paths.len());
    for path in &public_paths {
        signers.push(read_json::<SignerPublic>(path)?);
    }

    let policy = policy::assemble(fund, network, threshold, &signers)?;
    // Built, then re-checked from scratch, so nothing is written that `policy verify` would reject.
    policy::verify(&policy)?;
    write_json_new(&out, &policy)?;

    print_policy(&policy);
    println!("policy_file  {}", out.display());
    Ok(())
}

fn policy_verify(args: &[String]) -> Result<()> {
    let args = Arguments::parse(args, &["policy"], &[])?;
    let path = match args.get("policy") {
        Some(path) => path.to_string(),
        None => args.required_positional("policy")?.to_string(),
    };
    let policy: Policy = read_json(&path)?;
    let checked = policy::verify(&policy)?;

    print_policy(&checked.policy);
    println!("verified     yes — the redeem script, script hash, address and fingerprint");
    println!("             were all recomputed from the public keys in this file");
    Ok(())
}

fn print_policy(policy: &Policy) {
    println!("fund         {}", policy.fund);
    println!("network      {}", policy.network);
    println!(
        "threshold    {} of {}",
        policy.threshold,
        policy.signers.len()
    );
    println!("address      {}", policy.address);
    println!("script_hash  {}", policy.script_hash);
    println!("redeem       {}", policy.redeem_script);
    println!("policy       {}", policy.policy_fingerprint);
    for (index, entry) in policy.signers.iter().enumerate() {
        println!(
            "signer[{index}]    {}  {}  {}",
            entry.label, entry.fingerprint, entry.public_key,
        );
    }
}

// -- spend -------------------------------------------------------------------

/// Loads the policy a spend subcommand should check against: the file if one was given, otherwise
/// the one derived from the proposal's own fields.
fn spend_policy(
    args: &Arguments,
    proposal: &Proposal,
) -> Result<(swarm_treasury::policy::CheckedPolicy, bool)> {
    match args.get("policy") {
        Some(path) => {
            let policy: Policy = read_json(path)?;
            Ok((policy::verify(&policy)?, true))
        }
        None => Ok((
            policy::derive_from_proposal(
                &proposal.fund,
                &proposal.network,
                &proposal.redeem_script,
            )?,
            false,
        )),
    }
}

fn spend_propose(args: &[String]) -> Result<()> {
    let args = Arguments::parse(
        args,
        &[
            "policy",
            "utxos",
            "to",
            "fee",
            "expiry-height",
            "network-upgrade",
            "memo",
            "out",
        ],
        &[],
    )?;

    let policy_file: Policy = read_json(args.required("policy")?)?;
    let policy = policy::verify(&policy_file)?;
    let utxo_file: UtxoFile = read_json(args.required("utxos")?)?;
    let selected = utxo::select_all(&utxo_file, &policy.lock_script, &policy.policy.network)?;

    let pool = Pool::parse(args.required("network-upgrade")?)?;
    let recipient_text = args.required("to")?;
    let recipient = shielded::parse_recipient(recipient_text, policy.network)?;
    let fee: u64 = args.required_number("fee")?;
    let expiry_height: u32 = args.required_number("expiry-height")?;
    let memo = args.get("memo").unwrap_or("");
    let out = PathBuf::from(args.required("out")?);

    let mut rng_seed = [0u8; 32];
    OsRng.fill_bytes(&mut rng_seed);

    let proposal = spend::propose(spend::ProposalRequest {
        policy: &policy,
        selected: &selected,
        recipient_text,
        recipient,
        memo_text: memo,
        fee,
        expiry_height,
        pool,
        rng_seed,
    })?;

    // Built, then read back through the same check every signer runs.
    let checked = spend::check(&proposal, &policy)?;
    write_json_new(&out, &proposal)?;

    for line in spend::summary(&checked, &policy) {
        println!("{line}");
    }
    println!("proposal_file     {}", out.display());
    Ok(())
}

fn spend_show(args: &[String]) -> Result<()> {
    let args = Arguments::parse(args, &["proposal", "policy"], &[])?;
    let path = match args.get("proposal") {
        Some(path) => path.to_string(),
        None => args.required_positional("proposal")?.to_string(),
    };
    let proposal: Proposal = read_json(&path)?;
    let (policy, from_file) = spend_policy(&args, &proposal)?;
    let checked = spend::check(&proposal, &policy)?;

    for line in spend::summary(&checked, &policy) {
        println!("{line}");
    }
    println!("digests           recomputed from the raw transaction, and they match");
    if from_file {
        println!("policy            cross-checked against the policy file you gave");
    } else {
        println!(
            "policy            derived from the proposal itself — run `policy verify` on your own"
        );
        println!("                  policy.json and check the policy fingerprint above matches it");
    }
    Ok(())
}

fn spend_sign(args: &[String]) -> Result<()> {
    let args = Arguments::parse(args, &["proposal", "signer", "policy", "out"], &[])?;
    let proposal: Proposal = read_json(args.required("proposal")?)?;
    let backup_path = args.required("signer")?;
    let out = PathBuf::from(args.required("out")?);

    let (policy, _from_file) = spend_policy(&args, &proposal)?;
    let checked = spend::check(&proposal, &policy)?;

    let ciphertext = std::fs::read(backup_path)
        .map_err(|error| refuse!("could not read {backup_path}: {error}"))?;
    let passphrase = signer::read_passphrase(
        "Enter the passphrase for this signer backup. Check the summary above first: \
         signing is the point of no return.",
    )?;
    let secret = signer::decrypt_backup(&ciphertext, &passphrase)?;

    let signature = spend::sign(&checked, &policy, &secret)?;
    write_json_new(&out, &signature)?;

    println!("label            {}", signature.label);
    println!("fingerprint      {}", signature.fingerprint);
    println!("policy           {}", signature.policy_fingerprint);
    println!("proposal         {}", signature.proposal_hash);
    println!("signed inputs    {}", signature.signatures.len());
    println!("signature_file   {}", out.display());
    Ok(())
}

fn spend_combine(args: &[String]) -> Result<()> {
    let args = Arguments::parse(args, &["proposal", "sig", "policy", "out"], &["sig"])?;
    let proposal: Proposal = read_json(args.required("proposal")?)?;
    let out = PathBuf::from(args.required("out")?);

    let (policy, _from_file) = spend_policy(&args, &proposal)?;
    let checked = spend::check(&proposal, &policy)?;

    let signature_paths = args.all("sig");
    if signature_paths.is_empty() {
        return Err(refuse!("at least one --sig file is required"));
    }
    let mut signature_files = Vec::with_capacity(signature_paths.len());
    for path in &signature_paths {
        signature_files.push(read_json::<SignatureFile>(path)?);
    }

    let combined = spend::combine(&checked, &policy, &signature_files)?;

    let record_path = out.with_extension("json");
    if record_path == out {
        return Err(refuse!(
            "--out must not already end in .json: the record is written beside it as {}",
            record_path.display(),
        ));
    }
    signer::write_new_file(&out, format!("{}\n", combined.raw_hex).as_bytes())?;
    write_json_new(&record_path, &combined.record)?;

    println!("txid             {}", combined.record.txid);
    println!("network          {}", combined.record.network);
    println!("network upgrade  {}", combined.record.network_upgrade);
    println!("signers          {}", combined.record.signers.join(", "));
    println!("fee              {} zat", combined.record.fee);
    println!("amount out       {} zat", combined.record.amount_out);
    println!(
        "size             {} bytes",
        combined.record.transaction_bytes
    );
    println!("raw_transaction  {}", out.display());
    println!("record           {}", record_path.display());
    println!();
    println!(
        "Broadcast with: sendrawtransaction <the contents of {}>",
        out.display()
    );
    Ok(())
}
