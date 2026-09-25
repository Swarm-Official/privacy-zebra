//! Offline destination-address tool for the SWARM testnet funding streams.
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Zebra's funding-stream recipients must be P2SH script addresses: the
// consensus check in `zebra-consensus/src/block/check.rs` asserts
// "address must be P2SH" and the node panics on anything else. The desktop
// wallet only produces P2PKH (`tm…`) transparent addresses, so the three SWARM
// destinations are created here instead.
//
// This binary adds **no cryptography**. It only
//   * draws 32 random bytes per key from the operating system CSPRNG,
//   * asks the `secp256k1` crate for the matching compressed public key,
//   * assembles the standard Bitcoin/Zcash multisig redeem script
//     `OP_M <pubkey…> OP_N OP_CHECKMULTISIG`,
//   * hashes it with `sha2` + `ripemd` (the same HASH160 upstream Zebra uses),
//   * and hands the 20-byte hash to upstream
//     `zebra_chain::transparent::Address::from_script_hash` for encoding.
//
// Private material is written once to `DIR/LABEL.keys.json` with `create_new`
// (an existing file is never overwritten) and is never printed or logged.

use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

use rand::{rngs::OsRng, RngCore};
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use zebra_chain::{parameters::NetworkKind, transparent::Address};

const HELP: &str = "swarm-keytool — offline SWARM P2SH destination addresses\n\
\n\
Usage:\n\
  swarm-keytool new --threshold M --keys N --label NAME --out DIR [--network NET]\n\
  swarm-keytool address --redeem-script HEX [--network NET]\n\
  swarm-keytool show --keys-file PATH\n\
  swarm-keytool --help\n\
\n\
--network is `testnet` (the default, `t2…`) or `swarmmain` (SWARM production,\n\
`s3…`). The script hash is the policy and does not depend on the network; only\n\
the version byte, and so the printed prefix, changes. A SWARM production\n\
address never decodes as a Zcash address, and a Zcash address never decodes as\n\
a SWARM one.\n\
\n\
`new` generates N secp256k1 keys from the OS CSPRNG, builds the standard\n\
multisig redeem script OP_M <pubkeys in the order generated> OP_N\n\
OP_CHECKMULTISIG, and prints the P2SH address for --network, the redeem\n\
script and the public keys. 1 <= M <= N <= 15. --threshold 1 --keys 1 is a\n\
single-signature script and is allowed.\n\
\n\
Private keys are written to DIR/NAME.keys.json, created with create_new so an\n\
existing file is never overwritten, and are never printed. Keep that file\n\
offline: anyone holding M of the N keys can spend from the address.\n\
\n\
`address` recomputes the address from a redeem script and prints nothing else.\n\
\n\
`show` reprints the PUBLIC part of an existing key file -- label, threshold,\n\
address, redeem script and public keys -- so an operator never has to open a\n\
key file to recover them. It never reads or prints any private key, and it\n\
refuses if the recorded address does not match the recorded redeem script.\n\
\n\
This is a testnet engineering tool, not a key-ceremony procedure and not an\n\
audited custody solution.";

/// Maximum keys in a standard P2SH multisig: 15 * 34 + 3 = 513 bytes, inside
/// the 520-byte redeem-script limit, and OP_15 is a small-integer opcode.
const MAX_KEYS: u8 = 15;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("swarm-keytool: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("--help") | Some("-h") | Some("help") => {
            println!("{HELP}");
            Ok(())
        }
        Some("new") => cmd_new(&args[1..]),
        Some("address") => cmd_address(&args[1..]),
        Some("show") => cmd_show(&args[1..]),
        Some(other) => Err(format!("unknown subcommand {other:?}; use --help")),
    }
}

/// Parses `--key value` pairs, rejecting repeats and unknown keys.
fn options(args: &[String], allowed: &[&str]) -> Result<Vec<(String, String)>, String> {
    let mut parsed: Vec<(String, String)> = Vec::new();
    let mut iter = args.iter();
    while let Some(key) = iter.next() {
        if key == "--help" || key == "-h" {
            println!("{HELP}");
            std::process::exit(0);
        }
        let name = key
            .strip_prefix("--")
            .ok_or_else(|| format!("expected an option starting with --, found {key:?}"))?;
        if !allowed.contains(&name) {
            return Err(format!("unknown option --{name}; use --help"));
        }
        if parsed.iter().any(|(existing, _)| existing == name) {
            return Err(format!("option --{name} was given twice"));
        }
        let value = iter
            .next()
            .ok_or_else(|| format!("option --{name} needs a value"))?;
        parsed.push((name.to_string(), value.clone()));
    }
    Ok(parsed)
}

fn required<'a>(parsed: &'a [(String, String)], name: &str) -> Result<&'a str, String> {
    parsed
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| format!("--{name} is required; use --help"))
}

// -- script and address construction ----------------------------------------

/// HASH160: RIPEMD-160 of SHA-256, as used for every transparent Zcash address.
fn hash160(bytes: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(bytes);
    let ripe = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe[..]);
    out
}

/// The standard multisig redeem script `OP_M <pubkey…> OP_N OP_CHECKMULTISIG`,
/// with compressed public keys in the order they are given.
fn redeem_script(threshold: u8, pubkeys: &[[u8; 33]]) -> Result<Vec<u8>, String> {
    let keys = u8::try_from(pubkeys.len()).map_err(|_| "too many keys".to_string())?;
    check_threshold(threshold, keys)?;

    // OP_1..OP_16 are 0x51..0x60, so OP_n is 0x50 + n for 1 <= n <= 16.
    let mut script = vec![0x50 + threshold];
    for pubkey in pubkeys {
        // A bare push of 33 bytes: the length byte is the opcode.
        script.push(33);
        script.extend_from_slice(pubkey);
    }
    script.push(0x50 + keys);
    // OP_CHECKMULTISIG
    script.push(0xae);
    Ok(script)
}

fn check_threshold(threshold: u8, keys: u8) -> Result<(), String> {
    if keys == 0 || keys > MAX_KEYS {
        return Err(format!("--keys must be between 1 and {MAX_KEYS}"));
    }
    if threshold == 0 || threshold > keys {
        return Err("--threshold must be between 1 and --keys".to_string());
    }
    Ok(())
}

/// The upstream testnet P2SH encoding of a redeem script.
fn p2sh_testnet_address(script: &[u8]) -> Address {
    p2sh_address(NetworkKind::Testnet, script)
}

/// The P2SH encoding of a redeem script on a named network.
///
/// # Correctness
///
/// The script hash is the same on every network: it is the policy. Only the Base58Check version
/// bytes differ, and the SWARM production ones (`0x1C2D` for P2SH) are disjoint from every
/// upstream prefix in both directions, so an address built for one network cannot be spent to on
/// the other by accident.
fn p2sh_address(kind: NetworkKind, script: &[u8]) -> Address {
    Address::from_script_hash(kind, hash160(script))
}

/// Parses the `--network` value. `testnet` is the default, for compatibility with the SWARM
/// testnet procedures this tool was written for.
fn network_kind(parsed: &[(String, String)]) -> Result<NetworkKind, String> {
    let name = parsed
        .iter()
        .find(|(key, _)| key == "network")
        .map(|(_, value)| value.as_str())
        .unwrap_or("testnet");
    match name {
        "testnet" => Ok(NetworkKind::Testnet),
        "swarmmain" | "swarmmainnet" => Ok(NetworkKind::SwarmMainnet),
        other => Err(format!(
            "unknown --network {other:?}; expected testnet or swarmmain"
        )),
    }
}

/// The name a [`NetworkKind`] is recorded as in a key file.
fn network_name(kind: NetworkKind) -> &'static str {
    match kind {
        NetworkKind::Testnet => "testnet",
        NetworkKind::SwarmMainnet => "swarmmainnet",
        NetworkKind::Mainnet => "mainnet",
        NetworkKind::Regtest => "regtest",
    }
}

// -- subcommands -------------------------------------------------------------

fn cmd_address(args: &[String]) -> Result<(), String> {
    let parsed = options(args, &["redeem-script", "network"])?;
    let kind = network_kind(&parsed)?;
    let hex_script = required(&parsed, "redeem-script")?;
    let script = hex::decode(hex_script.trim())
        .map_err(|_| "--redeem-script must be hexadecimal".to_string())?;
    if script.is_empty() {
        return Err("--redeem-script must not be empty".to_string());
    }
    println!("{}", p2sh_address(kind, &script));
    Ok(())
}

/// The public fields of a key file, and nothing else.
///
/// An operator who lost the terminal output of `new` needs the address, the
/// redeem script and the public keys back. Opening the key file by hand to get
/// them puts the private keys on screen and in shell history; this prints only
/// the public part and never touches the private material beyond leaving it in
/// the file.
fn cmd_show(args: &[String]) -> Result<(), String> {
    let parsed = options(args, &["keys-file"])?;
    let path = PathBuf::from(required(&parsed, "keys-file")?);
    let body = std::fs::read_to_string(&path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let document: serde_json::Value = serde_json::from_str(&body)
        .map_err(|error| format!("{} is not valid JSON: {error}", path.display()))?;
    public_summary(&document).map(|lines| {
        for line in lines {
            println!("{line}");
        }
    })
}

/// Builds the printable public summary, re-deriving the address from the
/// recorded redeem script and refusing if the two disagree.
fn public_summary(document: &serde_json::Value) -> Result<Vec<String>, String> {
    let text = |key: &str| -> Result<String, String> {
        document
            .get(key)
            .and_then(|value| value.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("the key file has no string field {key:?}"))
    };
    let redeem_hex = text("redeem_script")?;
    let recorded_address = text("address")?;
    let script = hex::decode(&redeem_hex)
        .map_err(|_| "the recorded redeem script is not hexadecimal".to_string())?;
    let derived = p2sh_testnet_address(&script).to_string();
    if derived != recorded_address {
        return Err(format!(
            "the key file is inconsistent: its redeem script hashes to {derived}, \
             but it records the address {recorded_address}"
        ));
    }

    let threshold = document
        .get("threshold")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "the key file has no numeric threshold".to_string())?;
    let keys = document
        .get("keys")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "the key file has no numeric key count".to_string())?;

    let mut lines = vec![
        format!("label          {}", text("label")?),
        format!("address        {derived}"),
        format!("redeem_script  {redeem_hex}"),
    ];
    let material = document
        .get("key_material")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "the key file has no key_material array".to_string())?;
    for (index, entry) in material.iter().enumerate() {
        // Only the public key is ever taken out of the entry.
        let public_key = entry
            .get("public_key")
            .and_then(|value| value.as_str())
            .ok_or_else(|| format!("key_material[{index}] has no public_key"))?;
        lines.push(format!("public_key[{index}]  {public_key}"));
    }
    if material.len() as u64 != keys {
        return Err("the key file's key count does not match its key material".to_string());
    }
    lines.push(format!("threshold      {threshold} of {keys}"));
    Ok(lines)
}

fn cmd_new(args: &[String]) -> Result<(), String> {
    let parsed = options(args, &["threshold", "keys", "label", "out", "network"])?;
    let kind = network_kind(&parsed)?;
    let threshold: u8 = required(&parsed, "threshold")?
        .parse()
        .map_err(|_| "--threshold must be a small whole number".to_string())?;
    let keys: u8 = required(&parsed, "keys")?
        .parse()
        .map_err(|_| "--keys must be a small whole number".to_string())?;
    let label = required(&parsed, "label")?.to_string();
    let out = PathBuf::from(required(&parsed, "out")?);

    check_threshold(threshold, keys)?;
    check_label(&label)?;

    let secp = Secp256k1::new();
    let mut secrets: Vec<SecretKey> = Vec::with_capacity(usize::from(keys));
    let mut pubkeys: Vec<[u8; 33]> = Vec::with_capacity(usize::from(keys));
    for _ in 0..keys {
        let secret = random_secret_key()?;
        pubkeys.push(PublicKey::from_secret_key(&secp, &secret).serialize());
        secrets.push(secret);
    }

    let script = redeem_script(threshold, &pubkeys)?;
    let address = p2sh_address(kind, &script);

    // Write the private material first: printing an address whose keys were
    // never stored would be worse than failing.
    let path = out.join(format!("{label}.keys.json"));
    write_key_file(
        &path, &label, kind, threshold, &address, &script, &secrets, &pubkeys,
    )?;

    println!("address        {address}");
    println!("redeem_script  {}", hex::encode(&script));
    for (index, pubkey) in pubkeys.iter().enumerate() {
        println!("public_key[{index}]  {}", hex::encode(pubkey));
    }
    println!("threshold      {threshold} of {keys}");
    println!("keys_file      {}", path.display());
    Ok(())
}

/// Labels become file names, so they may not contain separators or dots.
fn check_label(label: &str) -> Result<(), String> {
    if label.is_empty() || label.len() > 64 {
        return Err("--label must be 1 to 64 characters".to_string());
    }
    if !label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("--label may only contain letters, digits, '-' and '_'".to_string());
    }
    Ok(())
}

/// 32 bytes from the operating system CSPRNG, rejected and redrawn in the
/// (astronomically unlikely) case that they are not a valid scalar.
fn random_secret_key() -> Result<SecretKey, String> {
    for _ in 0..16 {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        if let Ok(secret) = SecretKey::from_slice(&bytes) {
            return Ok(secret);
        }
    }
    Err("the operating system CSPRNG did not produce a usable key".to_string())
}

#[allow(clippy::too_many_arguments)]
fn write_key_file(
    path: &Path,
    label: &str,
    kind: NetworkKind,
    threshold: u8,
    address: &Address,
    script: &[u8],
    secrets: &[SecretKey],
    pubkeys: &[[u8; 33]],
) -> Result<(), String> {
    let keys: Vec<serde_json::Value> = secrets
        .iter()
        .zip(pubkeys)
        .enumerate()
        .map(|(index, (secret, pubkey))| {
            serde_json::json!({
                "index": index,
                "public_key": hex::encode(pubkey),
                "secret_key": hex::encode(secret.secret_bytes()),
            })
        })
        .collect();

    let document = serde_json::json!({
        "warning": "SECRET. Anyone holding `threshold` of these keys can spend from this address. \
                    Keep offline, never commit, never print.",
        "tool": "swarm-keytool",
        "purpose": "SWARM funding-stream destination (P2SH multisig); not a key ceremony",
        "label": label,
        "network": network_name(kind),
        "address": address.to_string(),
        "address_type": "P2SH",
        "threshold": threshold,
        "keys": pubkeys.len(),
        "redeem_script": hex::encode(script),
        "script_hash": hex::encode(hash160(script)),
        "key_material": keys,
    });

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
        }
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        format!(
            "could not create {} (an existing key file is never overwritten): {error}",
            path.display()
        )
    })?;
    let body = serde_json::to_string_pretty(&document)
        .map_err(|error| format!("could not serialize the key file: {error}"))?;
    file.write_all(body.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Three well-known compressed secp256k1 public keys: the points for the
    // secret scalars 1, 2 and 3.
    const P1: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const P2: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const P3: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

    fn key(hex_key: &str) -> [u8; 33] {
        let bytes = hex::decode(hex_key).expect("valid test hex");
        let mut out = [0u8; 33];
        out.copy_from_slice(&bytes);
        out
    }

    /// Upstream's own P2SH vector from `zebra-chain/src/transparent/address.rs`:
    /// a 20-byte all-zero script encodes to this testnet address. It pins the
    /// HASH160 and Base58Check path used by every other test here.
    /// The same redeem script encodes to an `s3…` address on SWARM production, over the same
    /// script hash. The policy does not change with the network; only the version byte does.
    #[test]
    fn swarmmain_encodes_the_same_script_hash_as_an_s3_address() {
        let script = [0u8; 20];

        let testnet = p2sh_address(NetworkKind::Testnet, &script);
        let swarm = p2sh_address(NetworkKind::SwarmMainnet, &script);

        assert_eq!(testnet.hash_bytes(), swarm.hash_bytes());
        assert!(swarm.is_script_hash());
        assert!(
            swarm.to_string().starts_with("s3"),
            "a SWARM production P2SH address must start with s3, found {swarm}",
        );
        assert_ne!(testnet.to_string(), swarm.to_string());

        // `--network` selects it, and an unknown network is refused rather than guessed.
        let parsed = vec![("network".to_string(), "swarmmain".to_string())];
        assert_eq!(network_kind(&parsed).unwrap(), NetworkKind::SwarmMainnet);
        assert_eq!(network_kind(&[]).unwrap(), NetworkKind::Testnet);
        assert!(network_kind(&[("network".to_string(), "mainnet".to_string())]).is_err());
    }

    #[test]
    fn upstream_zero_script_vector() {
        assert_eq!(
            p2sh_testnet_address(&[0u8; 20]).to_string(),
            "t2L51LcmpA43UMvKTw2Lwtt9LMjwyqU2V1P"
        );
    }

    /// Known vector, 1-of-1. The redeem script and the expected address were
    /// computed independently in Python (hashlib sha256 + ripemd160 and a
    /// hand-written Base58Check with the Zcash testnet P2SH prefix 0x1CBA);
    /// that Python was itself validated against the upstream vector above.
    #[test]
    fn known_vector_1_of_1() {
        let script = redeem_script(1, &[key(P1)]).expect("valid 1-of-1");
        assert_eq!(
            hex::encode(&script),
            "51210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179851ae"
        );
        assert_eq!(
            hex::encode(hash160(&script)),
            "83eebb7d79aa1d388e3b0ac65b98ac580c4da01a"
        );
        assert_eq!(
            p2sh_testnet_address(&script).to_string(),
            "t2JaQV6iQ9MA3HmWVYhfEn9mrMh3fRZpwTA"
        );
    }

    /// Known vector, 2-of-3, cross-checked the same way.
    #[test]
    fn known_vector_2_of_3() {
        let script = redeem_script(2, &[key(P1), key(P2), key(P3)]).expect("valid 2-of-3");
        assert_eq!(
            hex::encode(&script),
            concat!(
                "52",
                "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                "2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
                "53ae",
            )
        );
        assert_eq!(
            hex::encode(hash160(&script)),
            "15fc0754e73eb85d1cbce08786fadb7320ecb8dc"
        );
        assert_eq!(
            p2sh_testnet_address(&script).to_string(),
            "t28Z45qZRaD6zXBMFHTzEN7pZfGeZTtbkFp"
        );
    }

    /// Every address this tool produces must satisfy the consensus rule that
    /// funding-stream recipients are P2SH and start with `t2`.
    #[test]
    fn addresses_are_testnet_p2sh() {
        for script in [
            redeem_script(1, &[key(P1)]).unwrap(),
            redeem_script(2, &[key(P1), key(P2), key(P3)]).unwrap(),
            redeem_script(3, &[key(P1), key(P2), key(P3)]).unwrap(),
        ] {
            let address = p2sh_testnet_address(&script);
            assert!(address.is_script_hash());
            assert_eq!(address.network_kind(), NetworkKind::Testnet);
            assert!(address.to_string().starts_with("t2"), "{address}");
        }
    }

    /// The script layout itself: opcode for M, a 33-byte push per key in the
    /// order given, opcode for N, then OP_CHECKMULTISIG.
    #[test]
    fn script_layout_and_key_order() {
        let script = redeem_script(2, &[key(P3), key(P1)]).unwrap();
        assert_eq!(script[0], 0x52);
        assert_eq!(script[1], 33);
        assert_eq!(&script[2..35], &key(P3)[..]);
        assert_eq!(script[35], 33);
        assert_eq!(&script[36..69], &key(P1)[..]);
        assert_eq!(script[69], 0x52);
        assert_eq!(script[70], 0xae);
        assert_eq!(script.len(), 71);
    }

    #[test]
    fn thresholds_are_bounded() {
        assert!(check_threshold(1, 1).is_ok());
        assert!(check_threshold(2, 3).is_ok());
        assert!(check_threshold(15, 15).is_ok());
        assert!(check_threshold(0, 3).is_err());
        assert!(check_threshold(4, 3).is_err());
        assert!(check_threshold(1, 0).is_err());
        assert!(check_threshold(1, 16).is_err());
    }

    #[test]
    fn labels_are_file_safe() {
        assert!(check_label("core-development").is_ok());
        assert!(check_label("A_1").is_ok());
        assert!(check_label("").is_err());
        assert!(check_label("../escape").is_err());
        assert!(check_label("with space").is_err());
        assert!(check_label("dot.in.name").is_err());
    }

    /// Freshly generated keys must produce a usable t2 address, and two runs
    /// must not collide.
    #[test]
    fn generated_keys_make_distinct_p2sh_addresses() {
        let secp = Secp256k1::new();
        let mut addresses = Vec::new();
        for _ in 0..2 {
            let pubkeys: Vec<[u8; 33]> = (0..3)
                .map(|_| {
                    let secret = random_secret_key().expect("OS CSPRNG");
                    PublicKey::from_secret_key(&secp, &secret).serialize()
                })
                .collect();
            let script = redeem_script(2, &pubkeys).unwrap();
            let address = p2sh_testnet_address(&script);
            assert!(address.to_string().starts_with("t2"));
            addresses.push(address.to_string());
        }
        assert_ne!(addresses[0], addresses[1]);
    }

    /// A key file is written once and never overwritten.
    #[test]
    fn key_file_is_never_overwritten() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("swarm-test.keys.json");
        let secp = Secp256k1::new();
        let secrets = vec![random_secret_key().unwrap()];
        let pubkeys = vec![PublicKey::from_secret_key(&secp, &secrets[0]).serialize()];
        let script = redeem_script(1, &pubkeys).unwrap();
        let address = p2sh_testnet_address(&script);

        write_key_file(&path, "swarm-test", 1, &address, &script, &secrets, &pubkeys)
            .expect("first write succeeds");
        let second =
            write_key_file(&path, "swarm-test", 1, &address, &script, &secrets, &pubkeys);
        assert!(second.is_err(), "an existing key file must not be replaced");

        let written = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(parsed["address"], address.to_string());
        assert_eq!(parsed["redeem_script"], hex::encode(&script));
        assert_eq!(
            parsed["key_material"][0]["public_key"],
            hex::encode(pubkeys[0])
        );

        // `show` reprints the public part of that same file and never the
        // private key.
        let lines = public_summary(&parsed).expect("public summary");
        let printed = lines.join("\n");
        assert!(printed.contains(&address.to_string()));
        assert!(printed.contains(&hex::encode(&script)));
        assert!(printed.contains(&hex::encode(pubkeys[0])));
        assert!(printed.contains("threshold      1 of 1"));
        let secret = hex::encode(secrets[0].secret_bytes());
        assert!(!printed.contains(&secret), "the summary leaked a private key");
        assert!(!printed.contains("secret"), "the summary mentions a secret");
    }

    /// `show` refuses a key file whose address does not match its script.
    #[test]
    fn show_refuses_an_inconsistent_key_file() {
        let script = redeem_script(1, &[key(P1)]).unwrap();
        let mut document = serde_json::json!({
            "label": "tampered",
            "address": "t2L51LcmpA43UMvKTw2Lwtt9LMjwyqU2V1P",
            "threshold": 1,
            "keys": 1,
            "redeem_script": hex::encode(&script),
            "key_material": [{"index": 0, "public_key": P1}],
        });
        assert!(public_summary(&document).is_err());

        document["address"] = serde_json::json!(p2sh_testnet_address(&script).to_string());
        assert!(public_summary(&document).is_ok());
    }
}
