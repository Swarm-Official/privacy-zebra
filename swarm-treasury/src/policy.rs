//! The fund policy: which keys, in which order, with which threshold, on which network.
//!
//! A policy file is entirely public. It is the thing every device checks independently with
//! `policy verify`: the coordinator assembles it once, and each signer recomputes the redeem
//! script, the script hash and the address from the public keys it already holds. A coordinator
//! who swaps a key, reorders the keys or lowers the threshold does not get a policy anybody else
//! will accept.

use serde::{Deserialize, Serialize};

use crate::{
    network::TreasuryNetwork,
    refuse, script,
    signer::{self, SignerPublic},
    Result, TOOL_NAME, TOOL_VERSION,
};

/// The schema tag of a policy file.
pub const POLICY_SCHEMA: &str = "swarm-treasury.policy";
/// The version of the policy schema.
pub const POLICY_SCHEMA_VERSION: u32 = 1;

/// Which treasury fund a policy governs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fund {
    /// Core development.
    Core,
    /// Grants.
    Grants,
    /// Reserve.
    Reserve,
    /// Mining.
    Mining,
}

impl Fund {
    /// Parses the command-line name of a fund.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "Core" => Ok(Fund::Core),
            "Grants" => Ok(Fund::Grants),
            "Reserve" => Ok(Fund::Reserve),
            "Mining" => Ok(Fund::Mining),
            other => Err(refuse!(
                "unknown fund {other:?}; expected Core, Grants, Reserve or Mining"
            )),
        }
    }

    /// The name this fund is written as.
    pub fn name(self) -> &'static str {
        match self {
            Fund::Core => "Core",
            Fund::Grants => "Grants",
            Fund::Reserve => "Reserve",
            Fund::Mining => "Mining",
        }
    }
}

/// One signer's entry in a policy, in redeem-script order.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySigner {
    /// The signer's label.
    pub label: String,
    /// The compressed public key, hex.
    pub public_key: String,
    /// The public-key fingerprint, hex.
    pub fingerprint: String,
}

/// A fund's custody policy.
///
/// Field order is the order the keys were given on the command line, and the order the P2SH
/// address commits to. Nothing is sorted.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    /// The schema tag, always [`POLICY_SCHEMA`].
    pub schema: String,
    /// The schema version, always [`POLICY_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The tool that wrote this file.
    pub tool: String,
    /// The version of the tool that wrote this file.
    pub tool_version: String,
    /// The fund this policy governs.
    pub fund: String,
    /// The network the address is encoded for.
    pub network: String,
    /// How many signatures a spend needs.
    pub threshold: u8,
    /// The signers, in redeem-script key order.
    pub signers: Vec<PolicySigner>,
    /// The redeem script, hex.
    pub redeem_script: String,
    /// `HASH160(redeem script)`, hex.
    pub script_hash: String,
    /// The P2SH address, in the network's encoding.
    pub address: String,
    /// The first 16 bytes of `SHA-256` over the policy's binding fields, hex.
    ///
    /// Proposals and signatures carry this, so a signature made under one policy cannot be
    /// presented against another.
    pub policy_fingerprint: String,
    /// When the policy was assembled, RFC 3339.
    pub created: String,
}

/// Everything a checked policy yields, recomputed rather than read.
#[derive(Clone, Debug)]
pub struct CheckedPolicy {
    /// The policy as written.
    pub policy: Policy,
    /// The network it is for.
    pub network: TreasuryNetwork,
    /// The fund it governs.
    pub fund: Fund,
    /// The redeem script bytes.
    pub redeem_script: Vec<u8>,
    /// The P2SH locking script bytes: `OP_HASH160 <script hash> OP_EQUAL`.
    pub lock_script: Vec<u8>,
    /// The public keys, in redeem-script order.
    pub public_keys: Vec<[u8; script::COMPRESSED_PUBLIC_KEY_LEN]>,
}

impl CheckedPolicy {
    /// The position of a public key in the policy, if it is one of the policy's keys.
    pub fn index_of(&self, public_key: &[u8; script::COMPRESSED_PUBLIC_KEY_LEN]) -> Option<usize> {
        self.public_keys.iter().position(|key| key == public_key)
    }

    /// The policy's threshold.
    pub fn threshold(&self) -> usize {
        usize::from(self.policy.threshold)
    }
}

/// Assembles a policy from public signer records, keeping the order they were given in.
pub fn assemble(
    fund: Fund,
    network: TreasuryNetwork,
    threshold: u8,
    signers: &[SignerPublic],
) -> Result<Policy> {
    script::check_threshold(threshold, signers.len())?;

    let mut public_keys = Vec::with_capacity(signers.len());
    let mut entries = Vec::with_capacity(signers.len());
    for public in signers {
        let key = public.validate()?;
        if public_keys.contains(&key) {
            return Err(refuse!(
                "signer {} repeats a public key already in the policy; \
                 a 2-of-3 policy with a duplicated key is really a 2-of-2 under one device",
                public.label,
            ));
        }
        if entries
            .iter()
            .any(|entry: &PolicySigner| entry.label == public.label)
        {
            return Err(refuse!(
                "two signers share the label {:?}; labels identify devices and must differ",
                public.label,
            ));
        }
        entries.push(PolicySigner {
            label: public.label.clone(),
            public_key: public.public_key.clone(),
            fingerprint: public.fingerprint.clone(),
        });
        public_keys.push(key);
    }

    let redeem_script = script::redeem_script(threshold, &public_keys)?;
    let script_hash = script::hash160(&redeem_script);
    // Refuses here for a network this build cannot encode, rather than writing a policy file that
    // records an address from the wrong network.
    let address = network.p2sh_address(&redeem_script)?;

    let mut policy = Policy {
        schema: POLICY_SCHEMA.to_string(),
        schema_version: POLICY_SCHEMA_VERSION,
        tool: TOOL_NAME.to_string(),
        tool_version: TOOL_VERSION.to_string(),
        fund: fund.name().to_string(),
        network: network.name().to_string(),
        threshold,
        signers: entries,
        redeem_script: hex::encode(&redeem_script),
        script_hash: hex::encode(script_hash),
        address: address.to_string(),
        policy_fingerprint: String::new(),
        created: crate::now_rfc3339(),
    };
    policy.policy_fingerprint = policy_fingerprint(&policy);
    Ok(policy)
}

/// The policy fingerprint: the first 16 bytes of SHA-256 over the fields that bind a spend.
///
/// The timestamp, the tool version and the labels are deliberately *not* in it: re-assembling the
/// same keys, threshold, fund and network on another day must give the same fingerprint.
pub fn policy_fingerprint(policy: &Policy) -> String {
    let binding = format!(
        "{POLICY_SCHEMA}/{POLICY_SCHEMA_VERSION}\nfund={}\nnetwork={}\nthreshold={}\nredeem={}\n",
        policy.fund, policy.network, policy.threshold, policy.redeem_script,
    );
    hex::encode(&script::sha256(binding.as_bytes())[..16])
}

/// Recomputes everything in a policy from its public keys, and refuses anything that does not
/// match.
///
/// This is what every device runs before it will sign: the coordinator's file is not trusted, only
/// checked.
pub fn verify(policy: &Policy) -> Result<CheckedPolicy> {
    if policy.schema != POLICY_SCHEMA {
        return Err(refuse!(
            "expected a {POLICY_SCHEMA} file, found schema {:?}",
            policy.schema
        ));
    }
    if policy.schema_version != POLICY_SCHEMA_VERSION {
        return Err(refuse!(
            "this build reads {POLICY_SCHEMA} version {POLICY_SCHEMA_VERSION}, \
             the file is version {}",
            policy.schema_version
        ));
    }

    let fund = Fund::parse(&policy.fund)?;
    let network = TreasuryNetwork::parse(&policy.network)?;
    script::check_threshold(policy.threshold, policy.signers.len())?;

    let mut public_keys = Vec::with_capacity(policy.signers.len());
    for entry in &policy.signers {
        signer::check_label(&entry.label)?;
        let key = script::parse_public_key(&entry.public_key)?;
        let expected = signer::fingerprint(&key);
        if entry.fingerprint != expected {
            return Err(refuse!(
                "signer {}'s recorded fingerprint {} is not the fingerprint of its public key \
                 ({expected})",
                entry.label,
                entry.fingerprint,
            ));
        }
        if public_keys.contains(&key) {
            return Err(refuse!(
                "the policy repeats the public key of signer {}",
                entry.label
            ));
        }
        public_keys.push(key);
    }
    if policy.signers.iter().enumerate().any(|(index, entry)| {
        policy.signers[..index]
            .iter()
            .any(|earlier| earlier.label == entry.label)
    }) {
        return Err(refuse!("the policy has two signers with the same label"));
    }

    let redeem_script = script::redeem_script(policy.threshold, &public_keys)?;
    if hex::encode(&redeem_script) != policy.redeem_script {
        return Err(refuse!(
            "the policy's redeem script is not the script its threshold and public keys build; \
             recomputed {}, the file records {}",
            hex::encode(&redeem_script),
            policy.redeem_script,
        ));
    }

    let script_hash = script::hash160(&redeem_script);
    if hex::encode(script_hash) != policy.script_hash {
        return Err(refuse!(
            "the policy's script hash is not HASH160 of its redeem script; recomputed {}, \
             the file records {}",
            hex::encode(script_hash),
            policy.script_hash,
        ));
    }

    let address = network.p2sh_address(&redeem_script)?;
    if address.to_string() != policy.address {
        return Err(refuse!(
            "the policy's address is not the {network} address of its script hash; recomputed \
             {address}, the file records {}",
            policy.address,
        ));
    }

    let fingerprint = policy_fingerprint(policy);
    if fingerprint != policy.policy_fingerprint {
        return Err(refuse!(
            "the policy fingerprint does not match the policy; recomputed {fingerprint}, \
             the file records {}",
            policy.policy_fingerprint,
        ));
    }

    Ok(CheckedPolicy {
        policy: policy.clone(),
        network,
        fund,
        lock_script: script::p2sh_lock_script(script_hash),
        redeem_script,
        public_keys,
    })
}

/// Rebuilds a checked policy from a proposal's own fields, when the policy file is not to hand.
///
/// A proposal carries the fund, the network and the redeem script, and the policy fingerprint is a
/// hash of exactly those plus the threshold — which the redeem script itself encodes. So a signing
/// device that was handed only a proposal can still recompute the fingerprint and refuse a
/// proposal whose fingerprint was edited. What it *cannot* do is tell the operator that this is
/// the right fund's policy: only `policy verify` against the file every device checked can do
/// that, which is why `spend show` says so when it had to derive.
pub fn derive_from_proposal(
    fund_name: &str,
    network_name: &str,
    redeem_script_hex: &str,
) -> Result<CheckedPolicy> {
    let fund = Fund::parse(fund_name)?;
    let network = TreasuryNetwork::parse(network_name)?;
    let redeem_script = hex::decode(redeem_script_hex)
        .map_err(|_| refuse!("the redeem script is not hexadecimal"))?;
    let (threshold, public_keys) = script::parse_redeem_script(&redeem_script)?;

    let signers = public_keys
        .iter()
        .enumerate()
        .map(|(index, key)| PolicySigner {
            // The labels are not in the redeem script; these stand in for them, and the summary
            // says the policy was derived.
            label: format!("key{index}"),
            public_key: hex::encode(key),
            fingerprint: signer::fingerprint(key),
        })
        .collect();

    let script_hash = script::hash160(&redeem_script);
    let address = network.p2sh_address(&redeem_script)?;

    let mut policy = Policy {
        schema: POLICY_SCHEMA.to_string(),
        schema_version: POLICY_SCHEMA_VERSION,
        tool: TOOL_NAME.to_string(),
        tool_version: TOOL_VERSION.to_string(),
        fund: fund.name().to_string(),
        network: network.name().to_string(),
        threshold,
        signers,
        redeem_script: hex::encode(&redeem_script),
        script_hash: hex::encode(script_hash),
        address: address.to_string(),
        policy_fingerprint: String::new(),
        created: String::new(),
    };
    policy.policy_fingerprint = policy_fingerprint(&policy);
    verify(&policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::{SignerPublic, PUBLIC_SCHEMA, SIGNER_SCHEMA_VERSION};

    /// The public points of the published test scalars 1, 2 and 3.
    const FIXTURE_KEYS: [&str; 3] = [
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    ];

    fn fixture_public(label: &str, public_key: &str) -> SignerPublic {
        let key = script::parse_public_key(public_key).unwrap();
        SignerPublic {
            schema: PUBLIC_SCHEMA.to_string(),
            schema_version: SIGNER_SCHEMA_VERSION,
            tool: TOOL_NAME.to_string(),
            tool_version: TOOL_VERSION.to_string(),
            label: label.to_string(),
            public_key: public_key.to_string(),
            fingerprint: signer::fingerprint(&key),
            created: "2026-09-25T00:00:00Z".to_string(),
        }
    }

    fn fixture_policy() -> Policy {
        let signers = vec![
            fixture_public("A", FIXTURE_KEYS[0]),
            fixture_public("B", FIXTURE_KEYS[1]),
            fixture_public("C", FIXTURE_KEYS[2]),
        ];
        assemble(Fund::Core, TreasuryNetwork::Testnet, 2, &signers).unwrap()
    }

    /// The golden vector: the published `swarm-keytool` 2-of-3 script hash and address, reproduced
    /// by `policy assemble` from the fixture scalars' public points.
    #[test]
    fn published_golden_vector() {
        let policy = fixture_policy();
        assert_eq!(
            policy.script_hash,
            "15fc0754e73eb85d1cbce08786fadb7320ecb8dc"
        );
        assert_eq!(policy.address, "t28Z45qZRaD6zXBMFHTzEN7pZfGeZTtbkFp");
        assert_eq!(
            policy.redeem_script,
            concat!(
                "52",
                "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                "2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
                "53ae",
            )
        );
        verify(&policy).unwrap();
    }

    /// The key order is the order given, not a sorted order.
    #[test]
    fn key_order_is_preserved() {
        let reversed = vec![
            fixture_public("C", FIXTURE_KEYS[2]),
            fixture_public("B", FIXTURE_KEYS[1]),
            fixture_public("A", FIXTURE_KEYS[0]),
        ];
        let policy = assemble(Fund::Core, TreasuryNetwork::Testnet, 2, &reversed).unwrap();
        assert_ne!(policy.address, fixture_policy().address);
        verify(&policy).unwrap();
    }

    /// Every tampering `policy verify` must catch.
    #[test]
    fn verify_rejects_tampering() {
        let good = fixture_policy();

        let mut swapped_key = good.clone();
        swapped_key.signers[0].public_key = FIXTURE_KEYS[2].to_string();
        assert!(
            verify(&swapped_key).is_err(),
            "a swapped key must be caught"
        );

        let mut lowered = good.clone();
        lowered.threshold = 1;
        assert!(
            verify(&lowered).is_err(),
            "a lowered threshold must be caught"
        );

        let mut wrong_address = good.clone();
        wrong_address.address = "t2L51LcmpA43UMvKTw2Lwtt9LMjwyqU2V1P".to_string();
        assert!(verify(&wrong_address).is_err());

        let mut wrong_hash = good.clone();
        wrong_hash.script_hash = "00".repeat(20);
        assert!(verify(&wrong_hash).is_err());

        let mut wrong_fingerprint = good.clone();
        wrong_fingerprint.policy_fingerprint = "00".repeat(16);
        assert!(verify(&wrong_fingerprint).is_err());

        let mut reordered = good.clone();
        reordered.signers.reverse();
        assert!(
            verify(&reordered).is_err(),
            "reordering the keys changes the script the address commits to",
        );

        let mut wrong_network = good;
        wrong_network.network = "swarmmain".to_string();
        assert!(
            verify(&wrong_network).is_err(),
            "a policy claiming an encoding this build does not have must be refused",
        );
    }

    /// A duplicated signer is refused at assembly and at verification.
    #[test]
    fn duplicate_signers_are_refused() {
        let duplicated = vec![
            fixture_public("A", FIXTURE_KEYS[0]),
            fixture_public("B", FIXTURE_KEYS[0]),
            fixture_public("C", FIXTURE_KEYS[2]),
        ];
        assert!(assemble(Fund::Core, TreasuryNetwork::Testnet, 2, &duplicated).is_err());

        let mut policy = fixture_policy();
        policy.signers[1] = policy.signers[0].clone();
        assert!(verify(&policy).is_err());
    }

    /// Repeating a label, even with different keys, is refused: labels identify devices.
    #[test]
    fn duplicate_labels_are_refused() {
        let same_label = vec![
            fixture_public("A", FIXTURE_KEYS[0]),
            fixture_public("A", FIXTURE_KEYS[1]),
            fixture_public("C", FIXTURE_KEYS[2]),
        ];
        assert!(assemble(Fund::Core, TreasuryNetwork::Testnet, 2, &same_label).is_err());
    }

    /// A thresholds outside 1..=N never produces a policy.
    #[test]
    fn bad_thresholds_are_refused() {
        let signers = vec![
            fixture_public("A", FIXTURE_KEYS[0]),
            fixture_public("B", FIXTURE_KEYS[1]),
            fixture_public("C", FIXTURE_KEYS[2]),
        ];
        assert!(assemble(Fund::Core, TreasuryNetwork::Testnet, 0, &signers).is_err());
        assert!(assemble(Fund::Core, TreasuryNetwork::Testnet, 4, &signers).is_err());
    }

    /// The same fixture scalars assemble into a SwarmMain policy: the same 2-of-3 script and the
    /// same script hash, encoded as an `s3…` address.
    ///
    /// The script hash is the policy. It does not depend on the network, so a SwarmMain treasury
    /// destination is the very same multisig the published testnet vector pins, re-encoded for a
    /// chain whose address prefixes are disjoint from Zcash's in both directions.
    #[test]
    fn swarmmain_policies_encode_the_published_script_hash_as_an_s3_address() {
        let signers = vec![
            fixture_public("A", FIXTURE_KEYS[0]),
            fixture_public("B", FIXTURE_KEYS[1]),
            fixture_public("C", FIXTURE_KEYS[2]),
        ];
        let policy = assemble(Fund::Core, TreasuryNetwork::SwarmMain, 2, &signers)
            .expect("SwarmMain policy");
        let testnet = fixture_policy();

        // Same policy: same redeem script, same script hash as the published vector.
        assert_eq!(policy.redeem_script, testnet.redeem_script);
        assert_eq!(
            policy.script_hash,
            "15fc0754e73eb85d1cbce08786fadb7320ecb8dc"
        );

        // Different encoding: a SWARM production P2SH address, not a Zcash one.
        assert!(
            policy.address.starts_with("s3"),
            "a SwarmMain treasury address must start with s3, found {}",
            policy.address,
        );
        assert_ne!(policy.address, testnet.address);
        assert_eq!(policy.network, "swarmmain");

        // The fingerprint binds the network, so the two policies are not interchangeable.
        assert_ne!(policy.policy_fingerprint, testnet.policy_fingerprint);

        // And it round-trips back through the policy reader.
        let derived =
            derive_from_proposal(&policy.fund, &policy.network, &policy.redeem_script).unwrap();
        assert_eq!(derived.policy.address, policy.address);
        assert_eq!(derived.network, TreasuryNetwork::SwarmMain);
    }

    /// A policy derived from a proposal's fields has the same fingerprint, address and keys as the
    /// policy file itself.
    #[test]
    fn derived_policies_match_the_file() {
        let policy = fixture_policy();
        let derived =
            derive_from_proposal(&policy.fund, &policy.network, &policy.redeem_script).unwrap();

        assert_eq!(derived.policy.policy_fingerprint, policy.policy_fingerprint);
        assert_eq!(derived.policy.address, policy.address);
        assert_eq!(derived.policy.threshold, policy.threshold);
        assert_eq!(derived.public_keys.len(), 3);
        assert!(derive_from_proposal("Core", "testnet", "deadbeef").is_err());
    }

    /// The fingerprint depends on the keys, the threshold, the fund and the network — and not on
    /// when the policy was written.
    #[test]
    fn fingerprint_binds_the_policy() {
        let first = fixture_policy();
        let mut later = first.clone();
        later.created = "2030-01-01T00:00:00Z".to_string();
        later.tool_version = "9.9.9".to_string();
        assert_eq!(policy_fingerprint(&later), first.policy_fingerprint);

        let signers = vec![
            fixture_public("A", FIXTURE_KEYS[0]),
            fixture_public("B", FIXTURE_KEYS[1]),
            fixture_public("C", FIXTURE_KEYS[2]),
        ];
        let other_fund = assemble(Fund::Grants, TreasuryNetwork::Testnet, 2, &signers).unwrap();
        assert_ne!(other_fund.policy_fingerprint, first.policy_fingerprint);
    }
}
