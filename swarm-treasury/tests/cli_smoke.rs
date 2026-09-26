//! A smoke test that drives every `swarm-treasury` subcommand through the real binary.
//!
//! Everything happens inside one temporary directory, which the test deletes when it finishes: no
//! key material is left behind, and nothing is written into the repository. The passphrase and the
//! (deliberately weak) scrypt work factor are passed in the environment, which is exactly the path
//! the tool documents for unattended use.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::{path::Path, process::Command};

use swarm_treasury::{shielded, signer};

/// The passphrase the smoke test uses. Disposable, and the keys it protects die with the temp dir.
const PASSPHRASE: &str = "smoke test passphrase, never used for anything real";

/// Runs the tool and returns (success, stdout, stderr).
fn run(directory: &Path, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_swarm-treasury"))
        .args(args)
        .current_dir(directory)
        .env(signer::PASSPHRASE_ENV, PASSPHRASE)
        // A real backup targets about a second of scrypt; the smoke test would then spend most of
        // its time there.
        .env(signer::SCRYPT_LOG_N_ENV, "10")
        .output()
        .expect("the swarm-treasury binary runs");

    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Runs the tool and fails the test if it refused.
fn must(directory: &Path, args: &[&str]) -> String {
    let (ok, stdout, stderr) = run(directory, args);
    assert!(ok, "`swarm-treasury {}` failed: {stderr}", args.join(" "));
    stdout
}

/// Runs the tool and fails the test if it did *not* refuse.
fn must_refuse(directory: &Path, args: &[&str]) -> String {
    let (ok, stdout, stderr) = run(directory, args);
    assert!(
        !ok,
        "`swarm-treasury {}` should have been refused, it printed: {stdout}",
        args.join(" "),
    );
    stderr
}

/// The whole ceremony, through the command line, in a directory that is deleted at the end.
#[test]
fn every_subcommand_runs_in_a_temporary_directory() {
    let temporary = tempfile::tempdir().expect("a temporary directory");
    let directory = temporary.path().to_path_buf();

    // -- help and version ----------------------------------------------------
    let help = must(&directory, &["--help"]);
    assert!(help.contains("swarm-treasury signer new"));
    assert!(help.contains("never talks to a node"));
    assert!(must(&directory, &["--version"]).contains(swarm_treasury::TOOL_VERSION));
    must_refuse(&directory, &["nonsense"]);
    must_refuse(&directory, &["signer", "nonsense"]);

    // -- one key per device --------------------------------------------------
    for label in ["A", "B", "C"] {
        let out = must(
            &directory,
            &["signer", "new", "--label", label, "--out", "."],
        );
        assert!(out.contains("fingerprint"));
        assert!(
            !out.to_lowercase().contains("secret"),
            "`signer new` must not print anything about the secret: {out}",
        );
        assert!(directory.join(format!("{label}.signer.age")).exists());
        assert!(directory.join(format!("{label}.public.json")).exists());
    }

    // A signer key is never overwritten.
    let refusal = must_refuse(&directory, &["signer", "new", "--label", "A", "--out", "."]);
    assert!(refusal.contains("never overwrites"), "{refusal}");

    // The encrypted backup really is an age file, and does not contain the key in the clear.
    let backup = std::fs::read(directory.join("A.signer.age")).unwrap();
    assert!(backup.starts_with(b"age-encryption.org/"));
    let public: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("A.public.json")).unwrap()).unwrap();
    assert_eq!(public["schema"], signer::PUBLIC_SCHEMA);
    assert!(public.get("secret_key").is_none());

    // -- the policy ----------------------------------------------------------
    let assembled = must(
        &directory,
        &[
            "policy",
            "assemble",
            "--fund",
            "Core",
            "--threshold",
            "2",
            "--network",
            "testnet",
            "--public",
            "A.public.json",
            "--public",
            "B.public.json",
            "--public",
            "C.public.json",
            "--out",
            "policy.json",
        ],
    );
    assert!(assembled.contains("threshold    2 of 3"));

    let verified = must(&directory, &["policy", "verify", "policy.json"]);
    assert!(verified.contains("verified     yes"));

    // The SWARM production encoding produces an `s3…` address, never a testnet one.
    let mainnet = must(
        &directory,
        &[
            "policy",
            "assemble",
            "--fund",
            "Core",
            "--threshold",
            "2",
            "--network",
            "swarmmain",
            "--public",
            "A.public.json",
            "--public",
            "B.public.json",
            "--public",
            "C.public.json",
            "--out",
            "mainnet-policy.json",
        ],
    );
    assert!(mainnet.contains("network      swarmmain"), "{mainnet}");
    assert!(
        mainnet
            .lines()
            .any(|line| line.starts_with("address      s3")),
        "a SwarmMain policy must print an s3 address, not a testnet one: {mainnet}",
    );
    assert!(
        !mainnet.contains("address      t2"),
        "a SwarmMain policy must never be handed a testnet address: {mainnet}",
    );
    assert!(directory.join("mainnet-policy.json").exists());

    // An unknown network is still refused rather than guessed.
    let refusal = must_refuse(
        &directory,
        &[
            "policy",
            "assemble",
            "--fund",
            "Core",
            "--threshold",
            "2",
            "--network",
            "mainnet",
            "--public",
            "A.public.json",
            "--public",
            "B.public.json",
            "--public",
            "C.public.json",
            "--out",
            "unknown-policy.json",
        ],
    );
    assert!(refusal.contains("unknown network"), "{refusal}");
    assert!(!directory.join("unknown-policy.json").exists());

    // A tampered policy file does not verify.
    let policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("policy.json")).unwrap()).unwrap();
    let mut tampered = policy.clone();
    tampered["threshold"] = serde_json::json!(1);
    std::fs::write(
        directory.join("tampered-policy.json"),
        serde_json::to_vec_pretty(&tampered).unwrap(),
    )
    .unwrap();
    must_refuse(&directory, &["policy", "verify", "tampered-policy.json"]);

    // -- backups -------------------------------------------------------------
    let recovered = must(
        &directory,
        &[
            "signer",
            "recover",
            "--backup",
            "A.signer.age",
            "--expect",
            "A.public.json",
        ],
    );
    assert!(recovered.contains("recovered    yes"));

    // A backup checked against the wrong public record is refused.
    must_refuse(
        &directory,
        &[
            "signer",
            "recover",
            "--backup",
            "A.signer.age",
            "--expect",
            "B.public.json",
        ],
    );

    let checked = must(
        &directory,
        &[
            "signer",
            "check",
            "--backup",
            "B.signer.age",
            "--policy",
            "policy.json",
        ],
    );
    assert!(checked.contains("belongs      yes"));

    // -- the hand-exported UTXO list -----------------------------------------
    let script_hash = policy["script_hash"].as_str().unwrap();
    let lock_script = format!("a914{script_hash}87");
    let created_height = 4_200_000u32;
    let utxos = serde_json::json!({
        "schema": "swarm-treasury.utxos",
        "schema_version": 1,
        "network": "testnet",
        "utxos": [{
            "txid": "33".repeat(32),
            "vout": 0,
            "value": 3_1250_0000u64,
            "height": created_height,
            "is_coinbase": true,
            "script": lock_script,
        }],
    });
    std::fs::write(
        directory.join("utxos.json"),
        serde_json::to_vec_pretty(&utxos).unwrap(),
    )
    .unwrap();

    // -- the proposal --------------------------------------------------------
    let key = shielded::fixture_spending_key([0u8; 32]).unwrap();
    let recipient = hex::encode(shielded::receiver_of_spending_key(&key).to_raw_address_bytes());
    let expiry = (created_height + 200).to_string();

    let proposed = must(
        &directory,
        &[
            "spend",
            "propose",
            "--policy",
            "policy.json",
            "--utxos",
            "utxos.json",
            "--to",
            &recipient,
            "--fee",
            "20000",
            "--expiry-height",
            &expiry,
            "--network-upgrade",
            "nu6_3",
            "--memo",
            "smoke test disbursement",
            "--out",
            "proposal.json",
        ],
    );
    assert!(
        proposed.contains("312480000 zat (shielded, no change)"),
        "{proposed}"
    );
    assert!(proposed.contains("transparent outs  0"));

    // With no --fee at all, the proposal pays the conventional fee of the signed transaction:
    // 2 transparent logical actions for the one 297-byte signed input, plus the shielded action.
    let defaulted = must(
        &directory,
        &[
            "spend",
            "propose",
            "--policy",
            "policy.json",
            "--utxos",
            "utxos.json",
            "--to",
            &recipient,
            "--expiry-height",
            &expiry,
            "--network-upgrade",
            "nu6_3",
            "--out",
            "default-fee-proposal.json",
        ],
    );
    assert!(
        defaulted.contains("fee               15000 zat (ZIP-317 conventional 15000 zat)"),
        "{defaulted}"
    );

    // A fee below the ZIP-317 conventional fee is refused.
    let refusal = must_refuse(
        &directory,
        &[
            "spend",
            "propose",
            "--policy",
            "policy.json",
            "--utxos",
            "utxos.json",
            "--to",
            &recipient,
            "--fee",
            "1",
            "--expiry-height",
            &expiry,
            "--network-upgrade",
            "nu6_3",
            "--out",
            "cheap-proposal.json",
        ],
    );
    assert!(refusal.contains("conventional fee"), "{refusal}");

    // -- what a signer reads before signing ----------------------------------
    let shown = must(&directory, &["spend", "show", "proposal.json"]);
    assert!(shown.contains("digests           recomputed from the raw transaction, and they match"));
    assert!(shown.contains("derived from the proposal itself"));

    let shown_with_policy = must(
        &directory,
        &["spend", "show", "proposal.json", "--policy", "policy.json"],
    );
    assert!(shown_with_policy.contains("cross-checked against the policy file"));

    // -- two devices sign ----------------------------------------------------
    for (label, out) in [("A", "A.sig.json"), ("B", "B.sig.json")] {
        let signed = must(
            &directory,
            &[
                "spend",
                "sign",
                "--proposal",
                "proposal.json",
                "--signer",
                &format!("{label}.signer.age"),
                "--policy",
                "policy.json",
                "--out",
                out,
            ],
        );
        assert!(signed.contains("signed inputs    1"));
    }

    // The wrong passphrase does not sign.
    let output = Command::new(env!("CARGO_BIN_EXE_swarm-treasury"))
        .args([
            "spend",
            "sign",
            "--proposal",
            "proposal.json",
            "--signer",
            "C.signer.age",
            "--out",
            "C-bad.sig.json",
        ])
        .current_dir(&directory)
        .env(signer::PASSPHRASE_ENV, "the wrong passphrase")
        .env(signer::SCRYPT_LOG_N_ENV, "10")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("could not decrypt"));

    // -- the coordinator combines --------------------------------------------
    let combined = must(
        &directory,
        &[
            "spend",
            "combine",
            "--proposal",
            "proposal.json",
            "--sig",
            "A.sig.json",
            "--sig",
            "B.sig.json",
            "--policy",
            "policy.json",
            "--out",
            "final.hex",
        ],
    );
    assert!(combined.contains("A, B"), "{combined}");
    assert!(combined.contains("sendrawtransaction"));

    let raw = std::fs::read_to_string(directory.join("final.hex")).unwrap();
    assert!(raw.trim().len() > 1000, "the final transaction is hex");
    assert!(raw.trim().chars().all(|c| c.is_ascii_hexdigit()));

    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("final.json")).unwrap()).unwrap();
    assert_eq!(record["schema"], "swarm-treasury.final");
    assert_eq!(record["signers"], serde_json::json!(["A", "B"]));
    assert_eq!(record["txid"].as_str().unwrap().len(), 64);

    // One signature is not enough.
    must_refuse(
        &directory,
        &[
            "spend",
            "combine",
            "--proposal",
            "proposal.json",
            "--sig",
            "A.sig.json",
            "--out",
            "single.hex",
        ],
    );

    // Nothing this test wrote outlives it.
    let listing: Vec<_> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(!listing.is_empty());
    temporary
        .close()
        .expect("the temporary directory is deleted");
    assert!(!directory.exists(), "no key material may be left behind");
}
