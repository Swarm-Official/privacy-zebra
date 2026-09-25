//! Offline 2-of-3 treasury multisig fixtures for the SWARM mainnet plan (task T1).
//!
//! These tests are entirely offline and deterministic. They never generate a key, never read a
//! key file, never touch the network and never touch a live testnet. Every secret used here is one
//! of the well-known *public* test scalars 1, 2 and 3, whose public points are published in the
//! `swarm-keytool` known-vector test. They are disposable public test vectors and must never be
//! funded.
//!
//! What is proven here:
//!
//! * a 2-of-3 redeem script built exactly the way `swarm-keytool` builds it, matching its published
//!   script hash `15fc0754e73eb85d1cbce08786fadb7320ecb8dc` and address
//!   `t28Z45qZRaD6zXBMFHTzEN7pZfGeZTtbkFp`;
//! * real `secp256k1` ECDSA signatures over the real Zebra ZIP-244 sighash, with the redeem script
//!   as the script code and canonical `SIGHASH_ALL`;
//! * a deterministic combiner that canonicalises contributions by the key order committed to in the
//!   redeem script (no BIP-67 sorting is applied, because the address already commits to the
//!   original order);
//! * final verification by the maintained script interpreter through
//!   [`zebra_script::CachedFfiTransaction::is_valid`].
//!
//! What is **not** proven here: nothing in this file is a treasury *coinbase* spend proof. The
//! transparent-change mechanics exercised in [`noncoinbase_change_output_respent_with_other_pair`]
//! are explicitly labelled non-coinbase; the consensus rule that forbids a coinbase spend from
//! having any transparent output is covered separately in
//! `zebra-state/tests/swarm_treasury_coinbase_policy.rs`. No shielded proof is constructed or
//! claimed valid here; the V5 and V6 skeletons carry transparent authorization only.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use ripemd::Ripemd160;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use zebra_chain::{
    amount::{Amount, NonNegative},
    block::Height,
    parameters::{ConsensusBranchId, NetworkKind, NetworkUpgrade},
    transaction::{self, HashType, LockTime, Transaction},
    transparent::{self, Address},
};
use zebra_script::CachedFfiTransaction;

// -- script opcodes ----------------------------------------------------------

/// `OP_0`, the CHECKMULTISIG dummy element.
const OP_0: u8 = 0x00;
/// `OP_PUSHDATA1`: the next byte is the length of the data to push.
const OP_PUSHDATA1: u8 = 0x4c;
/// The first length byte that is an opcode rather than a direct push length.
const MAX_DIRECT_PUSH: usize = 75;
/// `OP_HASH160`.
const OP_HASH160: u8 = 0xa9;
/// `OP_EQUAL`.
const OP_EQUAL: u8 = 0x87;
/// `OP_CHECKMULTISIG`.
const OP_CHECKMULTISIG: u8 = 0xae;
/// The canonical `SIGHASH_ALL` byte appended to each DER signature in a scriptSig.
const SIGHASH_ALL_BYTE: u8 = 0x01;
/// The largest `N` a standard bare CHECKMULTISIG redeem script can encode.
const MAX_KEYS: usize = 15;

/// Domain separator for the in-memory spend-intent commitment.
const INTENT_DOMAIN: &[u8] = b"SWARM-treasury-spend-intent-v1";

/// The compressed public point of the public test scalar 1.
const PUBLIC_KEY_1: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// The compressed public point of the public test scalar 2.
const PUBLIC_KEY_2: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
/// The compressed public point of the public test scalar 3.
const PUBLIC_KEY_3: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

/// The `swarm-keytool` published 2-of-3 redeem script for the public test scalars 1, 2 and 3.
const KNOWN_REDEEM_SCRIPT: &str = concat!(
    "52",
    "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    "2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    "53ae",
);
/// The `swarm-keytool` published script hash for [`KNOWN_REDEEM_SCRIPT`].
const KNOWN_SCRIPT_HASH: &str = "15fc0754e73eb85d1cbce08786fadb7320ecb8dc";
/// The `swarm-keytool` published testnet P2SH address for [`KNOWN_REDEEM_SCRIPT`].
const KNOWN_ADDRESS: &str = "t28Z45qZRaD6zXBMFHTzEN7pZfGeZTtbkFp";
/// The byte length of a 2-of-3 bare CHECKMULTISIG redeem script.
const KNOWN_REDEEM_SCRIPT_LEN: usize = 105;

// -- low-level helpers -------------------------------------------------------

/// `RIPEMD160(SHA256(bytes))`, the Bitcoin/Zcash `HASH160`.
fn hash160(bytes: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(bytes);
    let ripe = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe[..]);
    out
}

/// Returns the secret key for the public test scalar `scalar`.
///
/// These are the published, disposable fixture scalars 1, 2 and 3. No key is generated here.
fn fixture_secret_key(scalar: u8) -> SecretKey {
    let mut bytes = [0u8; 32];
    bytes[31] = scalar;
    SecretKey::from_slice(&bytes).expect("small non-zero scalars are valid secret keys")
}

/// Returns the compressed public key for the public test scalar `scalar`.
fn fixture_public_key(scalar: u8) -> [u8; 33] {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, &fixture_secret_key(scalar)).serialize()
}

/// Appends a minimal data push of `data` to `script`.
///
/// A 105-byte redeem script cannot use a one-byte direct push: the length byte 105 (`0x69`) is an
/// opcode, not a push length, so `OP_PUSHDATA1` is required. This helper picks the encoding by
/// length rather than assuming one.
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    if data.len() <= MAX_DIRECT_PUSH {
        script.push(u8::try_from(data.len()).expect("checked against MAX_DIRECT_PUSH"));
    } else {
        script.push(OP_PUSHDATA1);
        script.push(u8::try_from(data.len()).expect("test pushes are far below 256 bytes"));
    }
    script.extend_from_slice(data);
}

/// Builds the standard `OP_M <pubkey…> OP_N OP_CHECKMULTISIG` redeem script.
///
/// The public keys are kept in the order they are given. No BIP-67 sorting is applied: the P2SH
/// address commits to this exact byte string, so reordering after the address exists produces a
/// different address.
fn redeem_script(threshold: u8, public_keys: &[[u8; 33]]) -> Vec<u8> {
    let keys = u8::try_from(public_keys.len()).expect("test policies have at most 15 keys");
    // OP_1..OP_16 are 0x51..0x60, so OP_n is 0x50 + n for 1 <= n <= 16.
    let mut script = vec![0x50 + threshold];
    for public_key in public_keys {
        script.push(33);
        script.extend_from_slice(public_key);
    }
    script.push(0x50 + keys);
    script.push(OP_CHECKMULTISIG);
    script
}

/// Builds the P2SH locking script `OP_HASH160 <20-byte script hash> OP_EQUAL`.
fn p2sh_lock_script(redeem: &[u8]) -> Vec<u8> {
    let mut script = vec![OP_HASH160, 20];
    script.extend_from_slice(&hash160(redeem));
    script.push(OP_EQUAL);
    script
}

/// Builds a [`transparent::Output`] of `zatoshis` locked by `lock_script`.
fn output(zatoshis: i64, lock_script: &[u8]) -> transparent::Output {
    transparent::Output {
        value: amount(zatoshis),
        lock_script: transparent::Script::new(lock_script),
    }
}

/// Builds a non-negative [`Amount`] from a zatoshi count.
fn amount(zatoshis: i64) -> Amount<NonNegative> {
    Amount::try_from(zatoshis).expect("test amounts are valid")
}

// -- public treasury policy (contract test 5) --------------------------------

/// The *public* part of a treasury custody policy: everything an operator can check without ever
/// opening a key file.
///
/// This is deliberately independent of the current `swarm-keytool` `show` subcommand, which parses
/// the whole key file (including secret material) into memory and therefore cannot be used as proof
/// that these checks hold.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TreasuryPolicy {
    /// The number of signatures required to spend.
    threshold: u8,
    /// The compressed public keys, in the order committed to by the redeem script.
    public_keys: Vec<[u8; 33]>,
    /// The declared redeem script.
    redeem_script: Vec<u8>,
    /// The declared `HASH160` of the redeem script.
    script_hash: [u8; 20],
    /// The declared testnet P2SH address.
    address: String,
}

/// A way a declared [`TreasuryPolicy`] can fail its own public consistency checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PolicyError {
    /// The key count is zero or above the 15-key CHECKMULTISIG limit.
    BadKeyCount,
    /// The threshold is zero or larger than the key count.
    BadThreshold,
    /// One of the declared public keys is not a valid compressed secp256k1 point.
    InvalidPublicKey,
    /// The same public key appears more than once.
    DuplicatePublicKey,
    /// The declared redeem script is not the script the threshold and keys produce.
    RedeemScriptMismatch,
    /// The declared script hash is not the `HASH160` of the declared redeem script.
    ScriptHashMismatch,
    /// The declared address is not the testnet P2SH address of the declared script hash.
    AddressMismatch,
}

impl TreasuryPolicy {
    /// Builds a self-consistent policy from a threshold and an ordered key list.
    fn new(threshold: u8, public_keys: Vec<[u8; 33]>) -> Self {
        let redeem_script = redeem_script(threshold, &public_keys);
        let script_hash = hash160(&redeem_script);
        let address = Address::from_script_hash(NetworkKind::Testnet, script_hash).to_string();

        Self {
            threshold,
            public_keys,
            redeem_script,
            script_hash,
            address,
        }
    }

    /// The published 2-of-3 fixture policy over the public test scalars 1, 2 and 3.
    fn fixture() -> Self {
        Self::new(
            2,
            vec![
                fixture_public_key(1),
                fixture_public_key(2),
                fixture_public_key(3),
            ],
        )
    }

    /// Checks every public claim this policy makes against the others.
    ///
    /// This reconstructs the redeem script from the declared threshold and keys, rather than
    /// trusting the declared script, so altered metadata is caught rather than echoed back.
    fn validate(&self) -> Result<(), PolicyError> {
        if self.public_keys.is_empty() || self.public_keys.len() > MAX_KEYS {
            return Err(PolicyError::BadKeyCount);
        }
        if self.threshold == 0 || usize::from(self.threshold) > self.public_keys.len() {
            return Err(PolicyError::BadThreshold);
        }

        for public_key in &self.public_keys {
            if PublicKey::from_slice(public_key).is_err() {
                return Err(PolicyError::InvalidPublicKey);
            }
        }

        for (index, public_key) in self.public_keys.iter().enumerate() {
            if self.public_keys[index + 1..].contains(public_key) {
                return Err(PolicyError::DuplicatePublicKey);
            }
        }

        if redeem_script(self.threshold, &self.public_keys) != self.redeem_script {
            return Err(PolicyError::RedeemScriptMismatch);
        }
        if hash160(&self.redeem_script) != self.script_hash {
            return Err(PolicyError::ScriptHashMismatch);
        }
        if Address::from_script_hash(NetworkKind::Testnet, self.script_hash).to_string()
            != self.address
        {
            return Err(PolicyError::AddressMismatch);
        }

        Ok(())
    }

    /// The P2SH locking script that pays this policy.
    fn lock_script(&self) -> Vec<u8> {
        p2sh_lock_script(&self.redeem_script)
    }
}

// -- in-memory spend intent --------------------------------------------------

/// Which transaction skeleton a fixture spend uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TxVersion {
    /// A version 5 (NU5) skeleton.
    V5,
    /// A version 6 (NU6.3 / Ironwood) skeleton.
    V6,
}

impl TxVersion {
    /// The network upgrade whose branch ID this skeleton commits to.
    fn network_upgrade(self) -> NetworkUpgrade {
        match self {
            TxVersion::V5 => NetworkUpgrade::Nu5,
            TxVersion::V6 => NetworkUpgrade::Nu6_3,
        }
    }

    /// The consensus branch ID stored in the skeleton.
    fn branch_id(self) -> ConsensusBranchId {
        self.network_upgrade()
            .branch_id()
            .expect("NU5 and NU6.3 both have branch IDs")
    }
}

/// One input of a spend, together with the signer's own view of the output being spent.
#[derive(Clone, Debug)]
struct IntentInput {
    /// The outpoint being spent.
    outpoint: transparent::OutPoint,
    /// The input's sequence number.
    sequence: u32,
    /// The previous output: its value and its locking script.
    ///
    /// This is what the signer commits to. It is *not* authoritative on its own: a coordinator can
    /// claim any amount here, and the ZIP-244 sighash is what makes a false claim fail.
    previous_output: transparent::Output,
}

/// An in-memory description of a spend, shared between signers before any signature exists.
#[derive(Clone, Debug)]
struct SpendIntent {
    /// The skeleton version.
    version: TxVersion,
    /// The consensus branch context the signers commit to.
    consensus_branch_id: ConsensusBranchId,
    /// The transaction lock time.
    lock_time: LockTime,
    /// The transaction expiry height.
    expiry_height: Height,
    /// The inputs, in transaction input order.
    inputs: Vec<IntentInput>,
    /// The transparent outputs, in transaction output order.
    outputs: Vec<transparent::Output>,
}

impl SpendIntent {
    /// The outputs being spent, in input order, as the verifier needs them.
    fn previous_outputs(&self) -> Vec<transparent::Output> {
        self.inputs
            .iter()
            .map(|input| input.previous_output.clone())
            .collect()
    }

    /// Builds the transaction with the given unlock scripts, one per input.
    fn to_transaction(&self, unlock_scripts: &[Vec<u8>]) -> Transaction {
        assert_eq!(
            unlock_scripts.len(),
            self.inputs.len(),
            "one unlock script per input",
        );

        let inputs = self
            .inputs
            .iter()
            .zip(unlock_scripts)
            .map(|(input, unlock_script)| transparent::Input::PrevOut {
                outpoint: input.outpoint,
                unlock_script: transparent::Script::new(unlock_script),
                sequence: input.sequence,
            })
            .collect();

        match self.version {
            TxVersion::V5 => Transaction::V5 {
                consensus_branch_id: self.consensus_branch_id,
                lock_time: self.lock_time,
                expiry_height: self.expiry_height,
                inputs,
                outputs: self.outputs.clone(),
                sapling_shielded_data: None,
                orchard_shielded_data: None,
            },
            TxVersion::V6 => Transaction::V6 {
                consensus_branch_id: self.consensus_branch_id,
                lock_time: self.lock_time,
                expiry_height: self.expiry_height,
                inputs,
                outputs: self.outputs.clone(),
                sapling_shielded_data: None,
                orchard_shielded_data: None,
                ironwood_shielded_data: None,
            },
        }
    }

    /// The transaction with empty unlock scripts, used to compute sighashes.
    ///
    /// The V5/V6 (ZIP-244) sighash does not depend on unlock script contents, so signing over this
    /// skeleton and then rebuilding with the real scriptSigs is sound.
    fn skeleton(&self) -> Transaction {
        self.to_transaction(&vec![Vec::new(); self.inputs.len()])
    }

    /// A commitment to everything a signer agreed to.
    ///
    /// It covers the branch context, the skeleton txid (which commits to the prevouts, sequences,
    /// outputs, lock time and expiry) and, separately, each previous output's value and locking
    /// script. The previous-output part is included because it is exactly the part a coordinator
    /// supplies out of band; binding it here means two signers who were handed different UTXO
    /// metadata produce contributions that refuse to combine.
    fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(INTENT_DOMAIN);
        hasher.update([match self.version {
            TxVersion::V5 => 5u8,
            TxVersion::V6 => 6u8,
        }]);
        hasher.update(u32::from(self.consensus_branch_id).to_le_bytes());
        hasher.update(self.skeleton().hash().0);
        hasher.update(
            u32::try_from(self.inputs.len())
                .expect("few inputs")
                .to_le_bytes(),
        );

        for input in &self.inputs {
            hasher.update(input.outpoint.hash.0);
            hasher.update(input.outpoint.index.to_le_bytes());
            hasher.update(input.sequence.to_le_bytes());
            hasher.update(input.previous_output.value.zatoshis().to_le_bytes());
            let lock_script = input.previous_output.lock_script.as_raw_bytes();
            hasher.update(
                u32::try_from(lock_script.len())
                    .expect("short scripts")
                    .to_le_bytes(),
            );
            hasher.update(lock_script);
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }
}

// -- signing and combining ---------------------------------------------------

/// One signer's contribution to one input of one spend.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SignatureContribution {
    /// The signer's index in the redeem script's key order.
    key_index: usize,
    /// The input this signature authorises.
    input_index: usize,
    /// The spend intent this signature commits to.
    intent_digest: [u8; 32],
    /// The DER-encoded ECDSA signature, without the hash-type byte.
    der_signature: Vec<u8>,
}

/// A way a set of contributions can fail to combine into a scriptSig.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CombineError {
    /// A contribution commits to a different spend intent.
    IntentMismatch,
    /// A contribution authorises a different input.
    InputIndexMismatch,
    /// The same signer contributed twice.
    DuplicateSigner,
    /// A contribution names a key index that is not in the redeem script.
    UnknownSigner,
    /// The number of distinct contributions is not the policy threshold.
    WrongSignatureCount,
}

/// Signs one input of `intent` with the public test scalar at `key_index` in `policy`.
///
/// The script code is the redeem script, the hash type is canonical `SIGHASH_ALL`, and every
/// previous output is supplied in input order so the ZIP-244 sighash binds all of them.
fn sign_input(
    policy: &TreasuryPolicy,
    intent: &SpendIntent,
    input_index: usize,
    key_index: usize,
    scalar: u8,
) -> SignatureContribution {
    let secp = Secp256k1::new();
    let secret_key = fixture_secret_key(scalar);

    let sighasher = intent
        .skeleton()
        .sighasher(
            intent.version.network_upgrade(),
            Arc::new(intent.previous_outputs()),
        )
        .expect("the skeleton's branch ID matches its network upgrade");

    let sighash = sighasher.sighash(
        HashType::ALL,
        Some((input_index, policy.redeem_script.clone())),
    );

    let message = Message::from_digest(*sighash.as_ref());
    let signature = secp.sign_ecdsa(&message, &secret_key);

    SignatureContribution {
        key_index,
        input_index,
        intent_digest: intent.digest(),
        der_signature: signature.serialize_der().to_vec(),
    }
}

/// Combines contributions into a P2SH multisig scriptSig.
///
/// Contributions may arrive in any order; the combiner canonicalises them by the key order the
/// redeem script (and therefore the address) already commits to. It refuses contributions that
/// commit to a different intent, authorise a different input, name an unknown signer, or repeat a
/// signer.
fn combine(
    policy: &TreasuryPolicy,
    intent: &SpendIntent,
    input_index: usize,
    contributions: &[SignatureContribution],
) -> Result<Vec<u8>, CombineError> {
    let expected_digest = intent.digest();

    for contribution in contributions {
        if contribution.intent_digest != expected_digest {
            return Err(CombineError::IntentMismatch);
        }
        if contribution.input_index != input_index {
            return Err(CombineError::InputIndexMismatch);
        }
        if contribution.key_index >= policy.public_keys.len() {
            return Err(CombineError::UnknownSigner);
        }
    }

    let mut ordered = contributions.to_vec();
    ordered.sort_by_key(|contribution| contribution.key_index);

    for pair in ordered.windows(2) {
        if pair[0].key_index == pair[1].key_index {
            return Err(CombineError::DuplicateSigner);
        }
    }

    if ordered.len() != usize::from(policy.threshold) {
        return Err(CombineError::WrongSignatureCount);
    }

    // OP_0 absorbs the off-by-one element CHECKMULTISIG pops and discards.
    let mut script_sig = vec![OP_0];
    for contribution in &ordered {
        let mut signature = contribution.der_signature.clone();
        signature.push(SIGHASH_ALL_BYTE);
        push_data(&mut script_sig, &signature);
    }
    push_data(&mut script_sig, &policy.redeem_script);

    Ok(script_sig)
}

/// Verifies input `input_index` of the transaction built from `intent` and `unlock_scripts`.
fn verify(intent: &SpendIntent, unlock_scripts: &[Vec<u8>], input_index: usize) -> bool {
    let transaction = Arc::new(intent.to_transaction(unlock_scripts));
    let previous_outputs = Arc::new(intent.previous_outputs());

    match CachedFfiTransaction::new(
        transaction,
        previous_outputs,
        intent.version.network_upgrade(),
    ) {
        Ok(verifier) => verifier.is_valid(input_index).is_ok(),
        Err(_) => false,
    }
}

/// Signs, combines and verifies a single-input spend with the two given signers.
///
/// Returns whether the maintained script interpreter accepts the result.
fn sign_combine_verify(
    policy: &TreasuryPolicy,
    intent: &SpendIntent,
    signers: [(usize, u8); 2],
) -> bool {
    let contributions: Vec<_> = signers
        .iter()
        .map(|&(key_index, scalar)| sign_input(policy, intent, 0, key_index, scalar))
        .collect();

    let script_sig = combine(policy, intent, 0, &contributions).expect("contributions combine");

    verify(intent, &[script_sig], 0)
}

// -- fixture spends ----------------------------------------------------------

/// The value of the synthetic non-coinbase output the fixture spends, in zatoshis.
const FIXTURE_INPUT_VALUE: i64 = 5_0000_0000;
/// The approved fee for the fixture spend, in zatoshis.
const FIXTURE_FEE: i64 = 1_0000;

/// A recipient locking script that is not the treasury policy's own script.
fn recipient_lock_script() -> Vec<u8> {
    let mut script = vec![OP_HASH160, 20];
    script.extend_from_slice(&[0x11u8; 20]);
    script.push(OP_EQUAL);
    script
}

/// A single-input, single-output spend of a synthetic **non-coinbase** treasury output.
///
/// The input is deliberately not a coinbase output: this file proves script mechanics only.
fn fixture_intent(policy: &TreasuryPolicy, version: TxVersion) -> SpendIntent {
    SpendIntent {
        version,
        consensus_branch_id: version.branch_id(),
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        inputs: vec![IntentInput {
            outpoint: transparent::OutPoint {
                hash: transaction::Hash([0x22u8; 32]),
                index: 0,
            },
            sequence: u32::MAX,
            previous_output: output(FIXTURE_INPUT_VALUE, &policy.lock_script()),
        }],
        outputs: vec![output(
            FIXTURE_INPUT_VALUE - FIXTURE_FEE,
            &recipient_lock_script(),
        )],
    }
}

// -- contract test 5: public policy integrity --------------------------------

/// The fixture policy reproduces the `swarm-keytool` published 2-of-3 vector exactly, and the
/// 105-byte redeem script is pushed with `OP_PUSHDATA1`.
///
/// Covers contract test 5 (fixture binding).
#[test]
fn redeem_script_matches_keytool_public_vector() {
    let _init_guard = zebra_test::init();

    let policy = TreasuryPolicy::fixture();

    assert_eq!(hex::encode(&policy.public_keys[0]), PUBLIC_KEY_1);
    assert_eq!(hex::encode(&policy.public_keys[1]), PUBLIC_KEY_2);
    assert_eq!(hex::encode(&policy.public_keys[2]), PUBLIC_KEY_3);

    assert_eq!(hex::encode(&policy.redeem_script), KNOWN_REDEEM_SCRIPT);
    assert_eq!(hex::encode(policy.script_hash), KNOWN_SCRIPT_HASH);
    assert_eq!(policy.address, KNOWN_ADDRESS);
    assert!(
        policy.address.starts_with("t2"),
        "a testnet P2SH address must start with t2",
    );

    assert_eq!(
        policy.redeem_script.len(),
        KNOWN_REDEEM_SCRIPT_LEN,
        "a 2-of-3 redeem script is 1 + 3 * 34 + 1 + 1 = 105 bytes",
    );
    assert!(
        policy.redeem_script.len() > MAX_DIRECT_PUSH,
        "105 is an opcode, not a direct push length, so OP_PUSHDATA1 is required",
    );

    let mut pushed = Vec::new();
    push_data(&mut pushed, &policy.redeem_script);
    assert_eq!(
        pushed[0], OP_PUSHDATA1,
        "the redeem script push must use OP_PUSHDATA1 (0x4c)",
    );
    assert_eq!(
        pushed[1], 0x69,
        "the OP_PUSHDATA1 length byte for a 105-byte script is 0x69",
    );
    assert_eq!(&pushed[2..], &policy.redeem_script[..]);
}

/// Public metadata is checked against itself, and every altered field is rejected, without opening
/// any key file.
///
/// Covers contract test 5.
#[test]
fn public_policy_integrity_is_checked_without_secrets() {
    let _init_guard = zebra_test::init();

    let policy = TreasuryPolicy::fixture();
    assert_eq!(policy.validate(), Ok(()));

    // A threshold above the key count, and a zero threshold.
    let mut bad = policy.clone();
    bad.threshold = 4;
    assert_eq!(bad.validate(), Err(PolicyError::BadThreshold));
    let mut bad = policy.clone();
    bad.threshold = 0;
    assert_eq!(bad.validate(), Err(PolicyError::BadThreshold));

    // An empty key list.
    let mut bad = policy.clone();
    bad.public_keys = Vec::new();
    assert_eq!(bad.validate(), Err(PolicyError::BadKeyCount));

    // A key that is not a valid compressed secp256k1 point. The x coordinate is all `0xff`,
    // which is larger than the secp256k1 field prime, so no curve point can ever have it. A
    // `0x02` prefix over an arbitrary-looking x is not enough: `0x0202..02` happens to be a
    // valid x coordinate, and would be accepted here.
    let mut bad = policy.clone();
    let mut off_curve = [0xffu8; 33];
    off_curve[0] = 0x02;
    bad.public_keys[1] = off_curve;
    assert_eq!(bad.validate(), Err(PolicyError::InvalidPublicKey));

    // A duplicated signer disguised as three-of-three material.
    let duplicated = TreasuryPolicy::new(
        2,
        vec![
            fixture_public_key(1),
            fixture_public_key(2),
            fixture_public_key(2),
        ],
    );
    assert_eq!(duplicated.validate(), Err(PolicyError::DuplicatePublicKey));

    // A declared redeem script that does not follow from the declared threshold and keys.
    let mut bad = policy.clone();
    bad.redeem_script[0] = 0x51;
    assert_eq!(bad.validate(), Err(PolicyError::RedeemScriptMismatch));

    // A reordered key list: the redeem script (and therefore the address) no longer follows.
    // Key order is never silently normalised, because the address already committed to it.
    let mut bad = policy.clone();
    bad.public_keys.swap(0, 2);
    assert_eq!(bad.validate(), Err(PolicyError::RedeemScriptMismatch));
    let reordered = TreasuryPolicy::new(
        2,
        vec![
            fixture_public_key(3),
            fixture_public_key(2),
            fixture_public_key(1),
        ],
    );
    assert_eq!(reordered.validate(), Ok(()));
    assert_ne!(
        reordered.address, policy.address,
        "reordering keys must change the address, so no BIP-67 sorting may be applied",
    );

    // A declared script hash, and a declared address, that do not match.
    let mut bad = policy.clone();
    bad.script_hash = [0u8; 20];
    assert_eq!(bad.validate(), Err(PolicyError::ScriptHashMismatch));
    let mut bad = policy.clone();
    bad.address = KNOWN_ADDRESS.replace('t', "T");
    assert_eq!(bad.validate(), Err(PolicyError::AddressMismatch));
}

// -- contract test 1: all pairs, and every failure mode ----------------------

/// Every one of the three 2-of-3 signing pairs produces a scriptSig the maintained interpreter
/// accepts.
///
/// Covers contract test 1 (success half).
#[test]
fn all_signing_pairs_verify() {
    let _init_guard = zebra_test::init();

    let policy = TreasuryPolicy::fixture();
    let intent = fixture_intent(&policy, TxVersion::V5);

    for signers in [[(0usize, 1u8), (1, 2)], [(0, 1), (2, 3)], [(1, 2), (2, 3)]] {
        assert!(
            sign_combine_verify(&policy, &intent, signers),
            "signing pair {signers:?} must satisfy the 2-of-3 policy",
        );
    }
}

/// The combiner canonicalises by the redeem script's key order, whatever order contributions
/// arrive in.
///
/// Covers contract test 1 (ordering half).
#[test]
fn combiner_canonicalises_contribution_order() {
    let _init_guard = zebra_test::init();

    let policy = TreasuryPolicy::fixture();
    let intent = fixture_intent(&policy, TxVersion::V5);

    let first = sign_input(&policy, &intent, 0, 0, 1);
    let third = sign_input(&policy, &intent, 0, 2, 3);

    let ascending = combine(&policy, &intent, 0, &[first.clone(), third.clone()])
        .expect("ascending order combines");
    let descending =
        combine(&policy, &intent, 0, &[third, first]).expect("descending order combines");

    assert_eq!(
        ascending, descending,
        "the combiner must produce one canonical scriptSig regardless of caller order",
    );
    assert!(verify(&intent, &[ascending], 0));
}

/// One signature, a duplicated signer, a foreign key, a corrupted DER signature and a wrong redeem
/// script are all rejected.
///
/// Covers contract test 1 (failure half).
#[test]
fn insufficient_or_invalid_contributions_are_rejected() {
    let _init_guard = zebra_test::init();

    let policy = TreasuryPolicy::fixture();
    let intent = fixture_intent(&policy, TxVersion::V5);

    let first = sign_input(&policy, &intent, 0, 0, 1);
    let second = sign_input(&policy, &intent, 0, 1, 2);

    // One signature is below the threshold: the combiner refuses, and hand-building the same
    // scriptSig anyway does not satisfy the interpreter either.
    assert_eq!(
        combine(&policy, &intent, 0, &[first.clone()]),
        Err(CombineError::WrongSignatureCount),
    );
    let mut single = vec![OP_0];
    let mut signature = first.der_signature.clone();
    signature.push(SIGHASH_ALL_BYTE);
    push_data(&mut single, &signature);
    push_data(&mut single, &policy.redeem_script);
    assert!(
        !verify(&intent, &[single], 0),
        "a single signature must not satisfy a 2-of-3 policy",
    );

    // The same signer twice.
    assert_eq!(
        combine(&policy, &intent, 0, &[first.clone(), first.clone()]),
        Err(CombineError::DuplicateSigner),
    );
    let duplicated = {
        let mut script_sig = vec![OP_0];
        for _ in 0..2 {
            let mut signature = first.der_signature.clone();
            signature.push(SIGHASH_ALL_BYTE);
            push_data(&mut script_sig, &signature);
        }
        push_data(&mut script_sig, &policy.redeem_script);
        script_sig
    };
    assert!(
        !verify(&intent, &[duplicated], 0),
        "CHECKMULTISIG consumes keys in order, so the same signature twice must fail",
    );

    // A key index that is not in the redeem script at all.
    let unknown = SignatureContribution {
        key_index: 3,
        ..first.clone()
    };
    assert_eq!(
        combine(&policy, &intent, 0, &[first.clone(), unknown]),
        Err(CombineError::UnknownSigner),
    );

    // A foreign key: the public test scalar 4 is not in this policy. The contribution is
    // structurally well-formed and combines, but the interpreter rejects it.
    let foreign = sign_input(&policy, &intent, 0, 1, 4);
    let script_sig =
        combine(&policy, &intent, 0, &[first.clone(), foreign]).expect("shape is well-formed");
    assert!(
        !verify(&intent, &[script_sig], 0),
        "a signature from a key outside the redeem script must fail",
    );

    // A corrupted DER signature.
    let mut corrupted = second.clone();
    let last = corrupted.der_signature.len() - 1;
    corrupted.der_signature[last] ^= 0x01;
    let script_sig =
        combine(&policy, &intent, 0, &[first.clone(), corrupted]).expect("shape is well-formed");
    assert!(
        !verify(&intent, &[script_sig], 0),
        "a corrupted DER signature must fail",
    );

    // A redeem script that is not the one the P2SH output committed to.
    let wrong_policy = TreasuryPolicy::new(
        2,
        vec![
            fixture_public_key(1),
            fixture_public_key(2),
            fixture_public_key(4),
        ],
    );
    let script_sig = combine(&wrong_policy, &intent, 0, &[first, second])
        .expect("shape is well-formed against the wrong policy");
    assert!(
        !verify(&intent, &[script_sig], 0),
        "a redeem script whose HASH160 is not the locked script hash must fail",
    );
}

// -- contract test 2: post-signing mutation --------------------------------

/// Changing any part of the spend after signing breaks verification, and the intent commitment
/// catches the same changes before the interpreter does.
///
/// Covers contract test 2.
#[test]
fn post_signing_mutations_break_verification() {
    let _init_guard = zebra_test::init();

    let policy = TreasuryPolicy::fixture();
    let intent = fixture_intent(&policy, TxVersion::V5);

    let contributions = [
        sign_input(&policy, &intent, 0, 0, 1),
        sign_input(&policy, &intent, 0, 1, 2),
    ];
    let script_sig = combine(&policy, &intent, 0, &contributions).expect("contributions combine");
    assert!(
        verify(&intent, &[script_sig.clone()], 0),
        "the unmodified spend must verify first",
    );

    // The signed skeleton's txid does not depend on the scriptSigs, which is why signing over the
    // skeleton and rebuilding with the real unlock scripts is sound.
    assert_eq!(
        intent.skeleton().hash(),
        intent.to_transaction(&[script_sig.clone()]).hash(),
        "ZIP-244 txid must not depend on unlock script contents",
    );

    // Each entry is the original spend with exactly one field changed after signing.
    let mut mutations: Vec<(&str, SpendIntent)> = Vec::new();

    let mut mutated = intent.clone();
    mutated.outputs[0].lock_script = transparent::Script::new(&p2sh_lock_script(&[0xff]));
    mutations.push(("recipient script", mutated));

    let mut mutated = intent.clone();
    mutated.outputs[0].value = amount(FIXTURE_INPUT_VALUE - FIXTURE_FEE - 1);
    mutations.push(("recipient value", mutated));

    let mut mutated = intent.clone();
    mutated.outputs[0].value = amount(FIXTURE_INPUT_VALUE - 10 * FIXTURE_FEE);
    mutations.push(("fee, by lowering the paid amount", mutated));

    let mut mutated = intent.clone();
    mutated.outputs[0].value = amount(FIXTURE_INPUT_VALUE - FIXTURE_FEE - 1000);
    mutated.outputs.push(output(1000, &policy.lock_script()));
    mutations.push(("an added transparent change output", mutated));

    let mut mutated = intent.clone();
    mutated.inputs[0].outpoint.index = 1;
    mutations.push(("selected outpoint", mutated));

    let mut mutated = intent.clone();
    mutated.inputs[0].previous_output.value = amount(FIXTURE_INPUT_VALUE + 1);
    mutations.push(("previous amount", mutated));

    let mut mutated = intent.clone();
    mutated.inputs[0].sequence = u32::MAX - 1;
    mutations.push(("sequence", mutated));

    let mut mutated = intent.clone();
    mutated.expiry_height = Height(500_000);
    mutations.push(("expiry height", mutated));

    for (name, mutated) in &mutations {
        assert_ne!(
            mutated.digest(),
            intent.digest(),
            "mutating the {name} must change the spend intent commitment",
        );
        assert_eq!(
            combine(&policy, mutated, 0, &contributions),
            Err(CombineError::IntentMismatch),
            "contributions for the original spend must not combine against a mutated {name}",
        );
        assert!(
            !verify(mutated, &[script_sig.clone()], 0),
            "the signed scriptSig must not authorise a spend with a mutated {name}",
        );
    }

    // Changing the branch context after signing. The stored branch ID and the network upgrade used
    // to verify must agree, so this fails when the verifier is built, not at script evaluation.
    let mut wrong_branch = intent.clone();
    wrong_branch.consensus_branch_id = NetworkUpgrade::Nu6
        .branch_id()
        .expect("NU6 has a branch ID");
    assert_ne!(wrong_branch.digest(), intent.digest());
    assert_eq!(
        combine(&policy, &wrong_branch, 0, &contributions),
        Err(CombineError::IntentMismatch),
    );
    assert!(
        !verify(&wrong_branch, &[script_sig], 0),
        "a transaction whose branch ID no longer matches its network upgrade must not verify",
    );
}

/// A coordinator's claim about a UTXO is not authoritative: signing over a false previous amount
/// produces a signature the interpreter rejects against the real UTXO.
///
/// Covers contract test 2 (independent binding of amount and prevout metadata).
#[test]
fn coordinator_claimed_utxo_metadata_is_not_authoritative() {
    let _init_guard = zebra_test::init();

    let policy = TreasuryPolicy::fixture();
    let real = fixture_intent(&policy, TxVersion::V5);

    // The coordinator hands both signers a UTXO amount that is not the real one. Both signers sign
    // honestly, and the contributions agree with each other, so nothing at the coordination layer
    // detects the lie.
    let mut claimed = real.clone();
    claimed.inputs[0].previous_output.value = amount(FIXTURE_INPUT_VALUE * 2);

    let contributions = [
        sign_input(&policy, &claimed, 0, 0, 1),
        sign_input(&policy, &claimed, 0, 1, 2),
    ];
    let script_sig =
        combine(&policy, &claimed, 0, &contributions).expect("the signers agree with each other");

    // Against the real UTXO the signatures are worthless: the ZIP-244 sighash commits to the real
    // amount, which is what makes the amount independently bound rather than merely asserted.
    assert!(
        !verify(&real, &[script_sig.clone()], 0),
        "signatures over a falsely claimed amount must not spend the real UTXO",
    );

    // The same is true for the previous locking script.
    let mut wrong_script = real.clone();
    wrong_script.inputs[0].previous_output.lock_script =
        transparent::Script::new(&recipient_lock_script());
    let contributions = [
        sign_input(&policy, &wrong_script, 0, 0, 1),
        sign_input(&policy, &wrong_script, 0, 1, 2),
    ];
    let script_sig = combine(&policy, &wrong_script, 0, &contributions).expect("signers agree");
    assert!(
        !verify(&real, &[script_sig], 0),
        "signatures over a falsely claimed previous script must not spend the real UTXO",
    );
}

// -- contract test 3: non-coinbase change, respent ---------------------------

/// A **non-coinbase** synthetic input is spent to a recipient plus a 2-of-3 change output, and that
/// change is then spent again by a different signing pair.
///
/// This proves the transparent script, signing, combining and change mechanics, and the
/// missing-signer behaviour on the second spend. It is explicitly **not** a treasury coinbase spend
/// proof: consensus forbids a coinbase spend from having any transparent output, including this
/// change output, which is covered in `zebra-state/tests/swarm_treasury_coinbase_policy.rs`.
#[test]
fn noncoinbase_change_output_respent_with_other_pair() {
    let _init_guard = zebra_test::init();

    let policy = TreasuryPolicy::fixture();

    let funding_value = 10_0000_0000i64;
    let first_payment = 6_0000_0000i64;
    let change_value = funding_value - first_payment - FIXTURE_FEE;

    // First spend: one non-coinbase 2-of-3 input, a recipient output and a 2-of-3 change output.
    let first_intent = SpendIntent {
        version: TxVersion::V5,
        consensus_branch_id: TxVersion::V5.branch_id(),
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        inputs: vec![IntentInput {
            outpoint: transparent::OutPoint {
                // A synthetic, non-coinbase previous transaction.
                hash: transaction::Hash([0x33u8; 32]),
                index: 0,
            },
            sequence: u32::MAX,
            previous_output: output(funding_value, &policy.lock_script()),
        }],
        outputs: vec![
            output(first_payment, &recipient_lock_script()),
            // Change back to the same 2-of-3 policy.
            output(change_value, &policy.lock_script()),
        ],
    };

    let first_script_sig = combine(
        &policy,
        &first_intent,
        0,
        &[
            sign_input(&policy, &first_intent, 0, 0, 1),
            sign_input(&policy, &first_intent, 0, 1, 2),
        ],
    )
    .expect("signers 1 and 2 combine");

    assert!(
        verify(&first_intent, &[first_script_sig.clone()], 0),
        "the non-coinbase spend with transparent change must verify at the script level",
    );

    let first_transaction = first_intent.to_transaction(&[first_script_sig]);

    // Second spend: the change output, spent by a different pair (signers 1 and 3).
    let second_payment = change_value - FIXTURE_FEE;
    let second_intent = SpendIntent {
        version: TxVersion::V5,
        consensus_branch_id: TxVersion::V5.branch_id(),
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        inputs: vec![IntentInput {
            outpoint: transparent::OutPoint {
                hash: first_transaction.hash(),
                // The change output is the second output of the first transaction.
                index: 1,
            },
            sequence: u32::MAX,
            previous_output: output(change_value, &policy.lock_script()),
        }],
        outputs: vec![output(second_payment, &recipient_lock_script())],
    };

    let second_script_sig = combine(
        &policy,
        &second_intent,
        0,
        &[
            sign_input(&policy, &second_intent, 0, 0, 1),
            sign_input(&policy, &second_intent, 0, 2, 3),
        ],
    )
    .expect("signers 1 and 3 combine");

    assert!(
        verify(&second_intent, &[second_script_sig], 0),
        "the change output must be respendable by a different 2-of-3 pair",
    );

    // Missing-signer behaviour on the second spend: signer 2 alone cannot move the change.
    assert_eq!(
        combine(
            &policy,
            &second_intent,
            0,
            &[sign_input(&policy, &second_intent, 0, 1, 2)],
        ),
        Err(CombineError::WrongSignatureCount),
        "one of three signers must not be able to move the change",
    );
}

// -- contract test 4: V5 and V6 skeletons ------------------------------------

/// The same signing, combining and verification runs on both the V5/NU5 and the V6/NU6.3
/// skeletons, so the current SWARM V6 transaction version is not silently skipped.
///
/// These skeletons carry transparent authorization only. Neither one contains a shielded bundle,
/// and nothing here claims a shielded proof is valid.
///
/// Covers contract test 4.
#[test]
fn v5_and_v6_skeletons_both_authorise_transparent_inputs() {
    let _init_guard = zebra_test::init();

    let policy = TreasuryPolicy::fixture();

    for version in [TxVersion::V5, TxVersion::V6] {
        let intent = fixture_intent(&policy, version);

        assert_eq!(
            intent.skeleton().consensus_branch_id(),
            Some(version.branch_id()),
            "the {version:?} skeleton must store the branch ID of {:?}",
            version.network_upgrade(),
        );
        assert!(
            !intent.skeleton().has_shielded_data(),
            "the skeletons carry transparent authorization only",
        );

        for signers in [[(0usize, 1u8), (1, 2)], [(0, 1), (2, 3)], [(1, 2), (2, 3)]] {
            assert!(
                sign_combine_verify(&policy, &intent, signers),
                "pair {signers:?} must verify on the {version:?} skeleton",
            );
        }

        // A single signature still fails on both versions.
        let mut single = vec![OP_0];
        let contribution = sign_input(&policy, &intent, 0, 0, 1);
        let mut signature = contribution.der_signature;
        signature.push(SIGHASH_ALL_BYTE);
        push_data(&mut single, &signature);
        push_data(&mut single, &policy.redeem_script);
        assert!(
            !verify(&intent, &[single], 0),
            "a single signature must fail on the {version:?} skeleton too",
        );
    }
}

/// A V5 signature does not authorise the same spend re-encoded as V6, and vice versa: the branch
/// context is part of what is signed.
///
/// Covers contract test 4 (branch separation).
#[test]
fn signatures_do_not_cross_transaction_versions() {
    let _init_guard = zebra_test::init();

    let policy = TreasuryPolicy::fixture();
    let v5 = fixture_intent(&policy, TxVersion::V5);
    let v6 = fixture_intent(&policy, TxVersion::V6);

    assert_ne!(
        v5.digest(),
        v6.digest(),
        "the V5 and V6 spend intents must not share a commitment",
    );

    let v5_contributions = [
        sign_input(&policy, &v5, 0, 0, 1),
        sign_input(&policy, &v5, 0, 1, 2),
    ];
    assert_eq!(
        combine(&policy, &v6, 0, &v5_contributions),
        Err(CombineError::IntentMismatch),
        "V5 contributions must not combine into a V6 spend",
    );

    let v5_script_sig = combine(&policy, &v5, 0, &v5_contributions).expect("V5 combines");
    assert!(
        !verify(&v6, &[v5_script_sig], 0),
        "a V5 signature must not authorise the V6 re-encoding of the same spend",
    );
}
