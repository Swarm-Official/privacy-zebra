//! Offline proof that a mature 2-of-3 P2SH treasury coinbase output can be disbursed into a real
//! shielded note, for the SWARM mainnet plan (task T2).
//!
//! # The policy this file proves
//!
//! A treasury collector output is a *coinbase* output. Under the preserved consensus rules a
//! transaction that spends a coinbase output may not have **any** transparent output — not even
//! change back to the same 2-of-3 address (see
//! `zebra-state/tests/swarm_treasury_coinbase_policy.rs`, task T1). So the smallest usable
//! disbursement policy is:
//!
//! > select whole mature collector UTXOs, and pay **all** of their value minus the approved fee to
//! > the intended shielded recipient, with **no change output of any kind**.
//!
//! This file builds exactly such a transaction and runs it past the real verifiers:
//!
//! * one transparent input spending a synthetic mature coinbase UTXO locked to the published
//!   `swarm-keytool` 2-of-3 P2SH script;
//! * zero transparent outputs;
//! * one Orchard action paying `value - fee` to the recipient, with a **real Halo2 proof** created
//!   by the `orchard` crate, real spend-authorization signatures and a real binding signature;
//! * two of the three fixture signatures over the real ZIP-244 v5 sighash (which commits to the
//!   shielded bundle), combined into a P2SH scriptSig exactly as task T1 does.
//!
//! # Construction path
//!
//! Zebra has no wallet transaction builder, and the `zcash_primitives` builder's transparent
//! input support is limited to keys it can sign for itself, so it cannot spend an arbitrary P2SH
//! redeem script. This file therefore takes the smaller path: it builds the Orchard bundle with
//! the `orchard` crate (real prover), encodes it in the consensus wire format, and lets Zebra's own
//! `ZcashDeserialize` impl parse it into [`zebra_chain::orchard::ShieldedData`]. The transparent
//! side is assembled directly in Zebra types and signed with the T1 helpers. Nothing here invents
//! a serializer, a sighash or a proof system: the bundle bytes go through Zebra's parser, the
//! sighash comes from Zebra's `SigHasher`, and the proof is verified by `zebra-consensus`.
//!
//! The ZIP-244 signature digest excludes proofs and signatures, so the bundle's actions are fixed
//! before the sighash is taken and the proof and signatures are filled in afterwards. That
//! ordering is *checked*, not assumed: [`SpendFixture`] asserts that the sighash over the
//! placeholder-authorization transaction equals the sighash over the fully authorized one.
//!
//! # What this file does NOT prove
//!
//! * **No separate-device ceremony.** Both fixture signatures are produced in one process from
//!   public test scalars. Nothing here shows that a signer device never sees the other keys.
//! * **No backups or recovery.** There is no encrypted per-signer backup, no import, and no
//!   clean-machine restore.
//! * **No real network broadcast.** No node, no RPC, no chain. The note commitment tree anchor is
//!   the empty-tree root and the state service is a fixture that answers
//!   `CheckBestChainTipNullifiersAndAnchors` affirmatively, so anchor membership and nullifier
//!   uniqueness against a real chain are *not* checked here.
//! * **No production domain.** The transactions use the upstream NU5 / NU6.3 consensus branch IDs.
//!   The SWARM domain re-run is separate work.
//! * **No key custody claim.** Every secret in this file — the transparent scalars 1, 2 and 3 and
//!   the all-zero Orchard spending key — is a published, disposable test vector. None of them may
//!   ever be funded.
//!
//! The P2SH binding to the published script hash `15fc0754e73eb85d1cbce08786fadb7320ecb8dc` is not
//! re-derived here (this crate has no `ripemd`/`sha2` dependency, and task T1 already pins it);
//! instead the locking script is built from the published hash and the script interpreter itself
//! enforces that the redeem script hashes to it, so a mismatch would fail verification.

#![allow(clippy::unwrap_used)]

use std::{
    collections::HashMap,
    future::Future,
    io::Cursor,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
};

use chrono::{DateTime, TimeZone, Utc};
use orchard::{
    builder::{Builder as OrchardBuilder, BundleType},
    bundle::{Authorization as OrchardAuthorization, Bundle as OrchardBundle, BundleVersion},
    circuit::ProvingKey,
    keys::{FullViewingKey, IncomingViewingKey, Scope, SpendingKey},
    value::NoteValue,
    Anchor,
};
use rand::{rngs::StdRng, SeedableRng};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use tower::{Service, ServiceExt};

use zebra_chain::{
    amount::{Amount, NonNegative},
    block::Height,
    parameters::{testnet::Parameters, Network, NetworkUpgrade},
    serialization::{DateTime32, ZcashDeserialize},
    transaction::{self, zip317, HashType, LockTime, Transaction, UnminedTx},
    transparent::{
        self, CoinbaseSpendRestriction, OrderedUtxo, Utxo, MIN_TRANSPARENT_COINBASE_MATURITY,
    },
};
use zebra_consensus::transaction::{
    check as consensus_check, BlockRequest, BlockTxVerifier, MempoolRequest, MempoolTxVerifier,
};
use zebra_script::CachedFfiTransaction;

/// A boxed error, matching the error type the state service uses.
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

// -- published fixture material ----------------------------------------------

/// The compressed public points of the public test scalars 1, 2 and 3, in the order the published
/// `swarm-keytool` 2-of-3 vector commits to.
const FIXTURE_SCALARS: [u8; 3] = [1, 2, 3];

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

/// `OP_0`, the CHECKMULTISIG dummy element.
const OP_0: u8 = 0x00;
/// `OP_PUSHDATA1`: the next byte is the length of the data to push.
const OP_PUSHDATA1: u8 = 0x4c;
/// The largest length byte that is a direct push rather than an opcode.
const MAX_DIRECT_PUSH: usize = 75;
/// `OP_HASH160`.
const OP_HASH160: u8 = 0xa9;
/// `OP_EQUAL`.
const OP_EQUAL: u8 = 0x87;
/// `OP_CHECKMULTISIG`.
const OP_CHECKMULTISIG: u8 = 0xae;
/// The canonical `SIGHASH_ALL` byte appended to each DER signature in a scriptSig.
const SIGHASH_ALL_BYTE: u8 = 0x01;

/// The **disposable** Orchard spending key used as the disbursement recipient.
///
/// All-zero bytes: a published constant, never a generated key, and never to be funded. The
/// fixture asserts that it is a valid Orchard spending key rather than assuming it.
const RECIPIENT_SPENDING_KEY_BYTES: [u8; 32] = [0u8; 32];

/// The memo the fixture disbursement carries, so the recipient-side check recovers something that
/// could only have come from this transaction.
const DISBURSEMENT_MEMO: &[u8] = b"SWARM treasury disbursement fixture T2";

// -- fixture amounts and heights ---------------------------------------------

/// The value of the synthetic treasury coinbase output, in zatoshis.
const COLLECTOR_VALUE: u64 = 3_1250_0000;

/// The approved fee for the fixture disbursement, in zatoshis.
///
/// This is above the ZIP-317 conventional fee for this transaction shape; the fixture asserts that
/// relationship against [`zip317::conventional_fee`] rather than hard-coding the expected value,
/// so a change to the rule shows up as a test failure instead of silently passing.
const APPROVED_FEE: u64 = 2_0000;

/// The transparent change the negative fixture tries to keep under the 2-of-3 policy.
const ATTEMPTED_CHANGE: u64 = 1_0000_0000;

/// The height at which the v5 fixture's treasury coinbase output is created.
///
/// Chosen between the default Testnet NU5 and NU6 activation heights, so the spend is a v5/NU5
/// transaction under the unmodified default activation heights.
const V5_CREATED_HEIGHT: Height = Height(2_000_000);

/// The height at which the v6 fixture's treasury coinbase output is created.
///
/// Chosen above the default Testnet NU6.3 activation height. It is also above NU6.2, which ends
/// the temporary Orchard-disabling soft fork, so that soft fork does not apply here.
const V6_CREATED_HEIGHT: Height = Height(4_200_000);

/// The number of blocks a transparent coinbase output must age before it can be spent.
const MATURITY: u32 = MIN_TRANSPARENT_COINBASE_MATURITY as u32;

// -- small script helpers (the subset of the task T1 helpers this file needs) -
//
// These are duplicated rather than shared: an integration test target cannot import another
// crate's integration test module, and introducing a shared test-support crate would add a new
// cross-crate dependency for four short functions. Task T1's file is left byte-identical so its
// gate keeps passing.

/// Returns the secret key for the public test scalar `scalar`.
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
/// The 105-byte 2-of-3 redeem script cannot use a one-byte direct push, because the length byte
/// 105 (`0x69`) is an opcode; `OP_PUSHDATA1` is required.
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    if data.len() <= MAX_DIRECT_PUSH {
        script.push(u8::try_from(data.len()).expect("checked against MAX_DIRECT_PUSH"));
    } else {
        script.push(OP_PUSHDATA1);
        script.push(u8::try_from(data.len()).expect("test pushes are far below 256 bytes"));
    }
    script.extend_from_slice(data);
}

/// Builds the published 2-of-3 `OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG` redeem script.
///
/// The key order is the order the published P2SH address commits to; no BIP-67 sorting is applied.
fn treasury_redeem_script() -> Vec<u8> {
    let mut script = vec![0x50 + 2];
    for scalar in FIXTURE_SCALARS {
        let public_key = fixture_public_key(scalar);
        script.push(33);
        script.extend_from_slice(&public_key);
    }
    script.push(0x50 + 3);
    script.push(OP_CHECKMULTISIG);
    script
}

/// Builds the P2SH locking script `OP_HASH160 <published script hash> OP_EQUAL`.
fn treasury_lock_script() -> Vec<u8> {
    let mut script = vec![OP_HASH160, 20];
    script.extend_from_slice(&hex::decode(KNOWN_SCRIPT_HASH).expect("hard-coded hash is hex"));
    script.push(OP_EQUAL);
    script
}

/// Builds a non-negative [`Amount`] from a zatoshi count.
fn amount(zatoshis: u64) -> Amount<NonNegative> {
    Amount::try_from(i64::try_from(zatoshis).expect("fixture amounts fit in i64"))
        .expect("fixture amounts are valid")
}

/// Signs `sighash` with the public test scalar `scalar` and returns the DER encoding with the
/// canonical `SIGHASH_ALL` byte appended.
fn der_signature(scalar: u8, sighash: &[u8; 32]) -> Vec<u8> {
    let secp = Secp256k1::new();
    let message = Message::from_digest(*sighash);
    let signature = secp.sign_ecdsa(&message, &fixture_secret_key(scalar));
    let mut der = signature.serialize_der().to_vec();
    der.push(SIGHASH_ALL_BYTE);
    der
}

/// Builds a P2SH multisig scriptSig from signatures in redeem-script key order.
///
/// `OP_0` absorbs the off-by-one element CHECKMULTISIG pops and discards; the redeem script is
/// pushed last.
fn multisig_script_sig(signatures: &[Vec<u8>]) -> Vec<u8> {
    let mut script_sig = vec![OP_0];
    for signature in signatures {
        push_data(&mut script_sig, signature);
    }
    push_data(&mut script_sig, &treasury_redeem_script());
    script_sig
}

// -- the network fixture -----------------------------------------------------

/// The custom Testnet used for custody rehearsals.
///
/// `should_allow_unshielded_coinbase_spends` is set to `false` **explicitly**, so no fixture here
/// can pass because of a permissive default. The default Regtest constructor sets it to `true`,
/// which would make a production-incompatible transparent-change path look valid; the activation
/// heights are the unmodified Testnet defaults, so the network upgrade active at a fixture height
/// is whatever the real height schedule says.
fn custody_rehearsal_network() -> Network {
    Parameters::build()
        .with_unshielded_coinbase_spends(false)
        .to_network()
        .expect("the custody rehearsal Testnet parameters are valid")
}

// -- the fixture state service -----------------------------------------------

/// A minimal state service that serves exactly the fixture's UTXO and accepts the fixture's
/// anchors and nullifiers.
///
/// It is deliberately narrow: any request the verifier makes that this fixture does not model
/// fails loudly rather than being answered with a default.
#[derive(Clone, Debug)]
struct FixtureState {
    outpoint: transparent::OutPoint,
    utxo: Utxo,
}

impl Service<zebra_state::Request> for FixtureState {
    type Response = zebra_state::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: zebra_state::Request) -> Self::Future {
        let outpoint = self.outpoint;
        let utxo = self.utxo.clone();

        let response: Result<zebra_state::Response, BoxError> = match request {
            zebra_state::Request::AwaitUtxo(requested) if requested == outpoint => {
                Ok(zebra_state::Response::Utxo(utxo))
            }
            zebra_state::Request::UnspentBestChainUtxo(requested) if requested == outpoint => {
                Ok(zebra_state::Response::UnspentBestChainUtxo(Some(utxo)))
            }
            // The fixture has no chain, so the note commitment tree anchor and nullifier set are
            // not checked against one. This is recorded in the file's "does NOT prove" list.
            zebra_state::Request::CheckBestChainTipNullifiersAndAnchors(_) => {
                Ok(zebra_state::Response::ValidBestChainTipNullifiersAndAnchors)
            }
            // A median-time-past far in the past, so the fixture's unlocked lock time passes.
            zebra_state::Request::BestChainNextMedianTimePast => Ok(
                zebra_state::Response::BestChainNextMedianTimePast(DateTime32::MAX),
            ),
            other => {
                Err(format!("fixture state service got an unmodelled request: {other:?}").into())
            }
        };

        Box::pin(async move { response })
    }
}

/// The mempool service type the mempool verifier is generic over.
///
/// The fixture never provides a mempool: the setup channel's sender is dropped, so the verifier
/// keeps `mempool: None` and all UTXOs must come from the (fixture) chain state.
type FixtureMempool = tower::buffer::Buffer<
    tower::util::BoxService<
        zebra_node_services::mempool::Request,
        zebra_node_services::mempool::Response,
        BoxError,
    >,
    zebra_node_services::mempool::Request,
>;

// -- the Orchard bundle wire encoding ----------------------------------------

/// One Action description's non-authorizing fields, in consensus wire order.
#[derive(Clone, Debug)]
struct WireAction {
    cv: [u8; 32],
    nullifier: [u8; 32],
    rk: [u8; 32],
    cmx: [u8; 32],
    ephemeral_key: [u8; 32],
    enc_ciphertext: [u8; 580],
    out_ciphertext: [u8; 80],
}

/// A whole Orchard-protocol bundle in the consensus wire format.
///
/// The encoding is the one Zebra's `deserialize_orchard_shielded_data` reads, so building these
/// bytes and handing them to Zebra's parser is how a real bundle reaches [`Transaction`] here.
#[derive(Clone, Debug)]
struct WireBundle {
    actions: Vec<WireAction>,
    flag_byte: u8,
    value_balance: i64,
    anchor: [u8; 32],
    proof: Vec<u8>,
    spend_auth_sigs: Vec<[u8; 64]>,
    binding_sig: [u8; 64],
}

/// Writes a Bitcoin-style CompactSize prefix.
fn write_compact_size(bytes: &mut Vec<u8>, value: usize) {
    if value < 253 {
        bytes.push(value as u8);
    } else if value <= u16::MAX as usize {
        bytes.push(0xfd);
        bytes.extend_from_slice(&(value as u16).to_le_bytes());
    } else {
        bytes.push(0xfe);
        bytes.extend_from_slice(&(value as u32).to_le_bytes());
    }
}

impl WireBundle {
    /// Extracts the non-authorizing fields of `bundle` and pairs them with the given proof and
    /// signatures.
    ///
    /// The proof and the signatures are supplied separately because the ZIP-244 signature digest
    /// excludes both: the fixture first builds this with placeholders to take the sighash, then
    /// rebuilds it with the real proof and signatures.
    fn new<A: OrchardAuthorization>(
        bundle: &OrchardBundle<A, i64>,
        proof: Vec<u8>,
        spend_auth_sigs: Vec<[u8; 64]>,
        binding_sig: [u8; 64],
    ) -> Self {
        let actions = bundle
            .actions()
            .iter()
            .map(|action| {
                let encrypted_note = action.encrypted_note();
                WireAction {
                    cv: action.cv_net().to_bytes(),
                    nullifier: action.nullifier().to_bytes(),
                    rk: <[u8; 32]>::from(action.rk()),
                    cmx: action.cmx().to_bytes(),
                    ephemeral_key: encrypted_note.epk_bytes,
                    enc_ciphertext: encrypted_note.enc_ciphertext,
                    out_ciphertext: encrypted_note.out_ciphertext,
                }
            })
            .collect();

        WireBundle {
            actions,
            flag_byte: bundle.flag_byte(),
            value_balance: *bundle.value_balance(),
            anchor: bundle.anchor().to_bytes(),
            proof,
            spend_auth_sigs,
            binding_sig,
        }
    }

    /// The bundle's consensus wire encoding, as it appears inside a v5 or v6 transaction.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        write_compact_size(&mut bytes, self.actions.len());
        for action in &self.actions {
            bytes.extend_from_slice(&action.cv);
            bytes.extend_from_slice(&action.nullifier);
            bytes.extend_from_slice(&action.rk);
            bytes.extend_from_slice(&action.cmx);
            bytes.extend_from_slice(&action.ephemeral_key);
            bytes.extend_from_slice(&action.enc_ciphertext);
            bytes.extend_from_slice(&action.out_ciphertext);
        }

        bytes.push(self.flag_byte);
        bytes.extend_from_slice(&self.value_balance.to_le_bytes());
        bytes.extend_from_slice(&self.anchor);
        write_compact_size(&mut bytes, self.proof.len());
        bytes.extend_from_slice(&self.proof);
        for signature in &self.spend_auth_sigs {
            bytes.extend_from_slice(signature);
        }
        bytes.extend_from_slice(&self.binding_sig);

        bytes
    }

    /// Parses these bytes with Zebra's own v5 Orchard bundle deserializer.
    fn to_orchard_shielded_data(&self) -> zebra_chain::orchard::ShieldedData {
        let bytes = self.to_bytes();
        let mut reader = Cursor::new(bytes);
        Option::<zebra_chain::orchard::ShieldedData>::zcash_deserialize(&mut reader)
            .expect("the fixture bundle is a valid v5 Orchard bundle encoding")
            .expect("the fixture bundle has at least one action")
    }

    /// Parses these bytes with Zebra's own Ironwood bundle deserializer.
    fn to_ironwood_shielded_data(&self) -> zebra_chain::ironwood::ShieldedData {
        let bytes = self.to_bytes();
        let mut reader = Cursor::new(bytes);
        Option::<zebra_chain::ironwood::ShieldedData>::zcash_deserialize(&mut reader)
            .expect("the fixture bundle is a valid Ironwood bundle encoding")
            .expect("the fixture bundle has at least one action")
    }
}

// -- proving keys ------------------------------------------------------------

/// The proving key for the pre-NU6.2 Orchard Action circuit, built once per test binary.
fn pre_nu6_2_proving_key() -> &'static ProvingKey {
    static KEY: OnceLock<ProvingKey> = OnceLock::new();
    KEY.get_or_init(|| ProvingKey::build(BundleVersion::orchard_insecure_v1().circuit_version()))
}

/// The proving key for the NU6.3 Action circuit, built once per test binary.
fn nu6_3_proving_key() -> &'static ProvingKey {
    static KEY: OnceLock<ProvingKey> = OnceLock::new();
    KEY.get_or_init(|| ProvingKey::build(BundleVersion::ironwood_v3().circuit_version()))
}

// -- the recipient -----------------------------------------------------------

/// The disposable recipient's Orchard spending key.
fn recipient_spending_key() -> SpendingKey {
    let key = SpendingKey::from_bytes(RECIPIENT_SPENDING_KEY_BYTES);
    assert!(
        bool::from(key.is_some()),
        "the documented all-zero fixture bytes must be a valid Orchard spending key",
    );
    key.unwrap()
}

/// The disposable recipient's full viewing key.
fn recipient_full_viewing_key() -> FullViewingKey {
    FullViewingKey::from(&recipient_spending_key())
}

/// The disposable recipient's incoming viewing key, the key a receiving wallet would hold.
fn recipient_incoming_viewing_key() -> IncomingViewingKey {
    recipient_full_viewing_key().to_ivk(Scope::External)
}

/// The disposable recipient's external receiver address.
fn recipient_address() -> orchard::Address {
    recipient_full_viewing_key().address_at(0u32, Scope::External)
}

/// The fixture memo, padded to the 512-byte memo field.
fn disbursement_memo() -> [u8; 512] {
    let mut memo = [0u8; 512];
    memo[..DISBURSEMENT_MEMO.len()].copy_from_slice(DISBURSEMENT_MEMO);
    memo
}

// -- the spend fixture -------------------------------------------------------

/// Which transaction format and shielded pool a fixture uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pool {
    /// A v5 transaction at NU5, paying into the Orchard pool.
    V5Orchard,
    /// A v6 transaction at NU6.3, paying into the Ironwood pool.
    ///
    /// From NU6.3 the Orchard pool is frozen against new inflows
    /// (`zebra_consensus::transaction::check::orchard_value_balance_non_negative`), so a v6
    /// disbursement of transparent treasury value must target Ironwood.
    V6Ironwood,
}

impl Pool {
    /// The network upgrade the fixture's spend happens under.
    fn network_upgrade(self) -> NetworkUpgrade {
        match self {
            Pool::V5Orchard => NetworkUpgrade::Nu5,
            Pool::V6Ironwood => NetworkUpgrade::Nu6_3,
        }
    }

    /// The `orchard` crate bundle version to build with.
    fn bundle_version(self) -> BundleVersion {
        match self {
            Pool::V5Orchard => BundleVersion::orchard_insecure_v1(),
            Pool::V6Ironwood => BundleVersion::ironwood_v3(),
        }
    }

    /// The proving key whose circuit matches [`Self::bundle_version`].
    fn proving_key(self) -> &'static ProvingKey {
        match self {
            Pool::V5Orchard => pre_nu6_2_proving_key(),
            Pool::V6Ironwood => nu6_3_proving_key(),
        }
    }

    /// The height at which the fixture's treasury coinbase output is created.
    fn created_height(self) -> Height {
        match self {
            Pool::V5Orchard => V5_CREATED_HEIGHT,
            Pool::V6Ironwood => V6_CREATED_HEIGHT,
        }
    }
}

/// One fully built and authorized treasury disbursement, plus the pieces needed to build its
/// negative variants without paying for another Halo2 proof.
struct SpendFixture {
    pool: Pool,
    outpoint: transparent::OutPoint,
    previous_output: transparent::Output,
    transparent_outputs: Vec<transparent::Output>,
    /// The authorized bundle: real proof, real spend-authorization signatures, real binding
    /// signature.
    wire: WireBundle,
    /// The ZIP-244 sighash the shielded bundle is bound to.
    shielded_sighash: [u8; 32],
    /// The valid 2-of-3 scriptSig for input 0.
    script_sig: Vec<u8>,
    /// The value of the note paid to the recipient, in zatoshis.
    note_value: u64,
}

impl SpendFixture {
    /// The height at which the fixture's coinbase output was created.
    fn created_height(&self) -> Height {
        self.pool.created_height()
    }

    /// The first height at which the fixture's coinbase output is mature.
    fn mature_height(&self) -> Height {
        Height(self.created_height().0 + MATURITY)
    }

    /// The last height at which the fixture's coinbase output is still immature.
    fn immature_height(&self) -> Height {
        Height(self.created_height().0 + MATURITY - 1)
    }

    /// The previous outputs the sighash and the script verifier need, in input order.
    fn previous_outputs(&self) -> Arc<Vec<transparent::Output>> {
        Arc::new(vec![self.previous_output.clone()])
    }

    /// Builds the transaction from a given bundle encoding and scriptSig.
    fn transaction_with(&self, wire: &WireBundle, script_sig: &[u8]) -> Transaction {
        let inputs = vec![transparent::Input::PrevOut {
            outpoint: self.outpoint,
            unlock_script: transparent::Script::new(script_sig),
            sequence: u32::MAX,
        }];
        let consensus_branch_id = self
            .pool
            .network_upgrade()
            .branch_id()
            .expect("NU5 and NU6.3 both have branch IDs");
        let expiry_height = Height(self.mature_height().0 + 100);

        match self.pool {
            Pool::V5Orchard => Transaction::V5 {
                consensus_branch_id,
                lock_time: LockTime::unlocked(),
                expiry_height,
                inputs,
                outputs: self.transparent_outputs.clone(),
                sapling_shielded_data: None,
                orchard_shielded_data: Some(wire.to_orchard_shielded_data()),
            },
            Pool::V6Ironwood => Transaction::V6 {
                consensus_branch_id,
                lock_time: LockTime::unlocked(),
                expiry_height,
                inputs,
                outputs: self.transparent_outputs.clone(),
                sapling_shielded_data: None,
                orchard_shielded_data: None,
                ironwood_shielded_data: Some(wire.to_ironwood_shielded_data()),
            },
        }
    }

    /// The valid, fully authorized disbursement transaction.
    fn transaction(&self) -> Transaction {
        self.transaction_with(&self.wire, &self.script_sig)
    }

    /// The sighash for input 0 of `transaction`, computed under `network_upgrade`.
    fn transparent_sighash(&self, transaction: &Transaction, nu: NetworkUpgrade) -> [u8; 32] {
        let sighasher = transaction
            .sighasher(nu, self.previous_outputs())
            .expect("the fixture transaction's branch ID matches its network upgrade");
        *sighasher
            .sighash(HashType::ALL, Some((0, treasury_redeem_script())))
            .as_ref()
    }

    /// The UTXO the fixture spends: a coinbase output created at [`Self::created_height`].
    fn utxo(&self) -> Utxo {
        Utxo::new(self.previous_output.clone(), self.created_height(), true)
    }

    /// The fixture state service, serving exactly this fixture's UTXO.
    fn state(&self) -> FixtureState {
        FixtureState {
            outpoint: self.outpoint,
            utxo: self.utxo(),
        }
    }

    /// The spent-UTXO map the consensus coinbase checks take.
    fn spent_utxos(&self) -> HashMap<transparent::OutPoint, Utxo> {
        let mut spent = HashMap::new();
        spent.insert(self.outpoint, self.utxo());
        spent
    }

    /// The block-context known-UTXO map the block verifier takes.
    fn known_utxos(&self) -> Arc<HashMap<transparent::OutPoint, OrderedUtxo>> {
        let mut known = HashMap::new();
        known.insert(self.outpoint, OrderedUtxo::from_utxo(self.utxo(), 0));
        Arc::new(known)
    }

    /// Runs the whole `zebra-consensus` block transaction verifier over `transaction` at `height`.
    async fn verify_in_block(
        &self,
        transaction: Transaction,
        height: Height,
    ) -> Result<(), BoxError> {
        let network = custody_rehearsal_network();
        let verifier = BlockTxVerifier::new(&network, self.state());
        let transaction = Arc::new(transaction);

        verifier
            .oneshot(BlockRequest {
                transaction_hash: transaction.hash(),
                transaction,
                known_utxos: self.known_utxos(),
                height,
                time: block_time(),
            })
            .await
            .map(|_response| ())
            .map_err(|error| Box::new(error) as BoxError)
    }

    /// Runs the whole `zebra-consensus` mempool transaction verifier over `transaction` at
    /// `height`.
    ///
    /// The mempool path is the one that applies the coinbase maturity rule
    /// (`check_maturity_height`) and the ZIP-317 fee policy to the transaction itself; the block
    /// path leaves the coinbase rules to the state's contextual validation.
    async fn verify_in_mempool(
        &self,
        transaction: Transaction,
        height: Height,
    ) -> Result<(), BoxError> {
        let network = custody_rehearsal_network();
        // Dropping the sender leaves the verifier with no mempool service, so every UTXO must come
        // from the fixture chain state.
        let (_sender, receiver) = tokio::sync::oneshot::channel::<FixtureMempool>();
        let verifier = MempoolTxVerifier::new(&network, self.state(), receiver);

        verifier
            .oneshot(MempoolRequest {
                transaction: UnminedTx::from(Arc::new(transaction)),
                height,
            })
            .await
            .map(|_response| ())
            .map_err(|error| Box::new(error) as BoxError)
    }
}

/// The block time the fixture's block context uses.
fn block_time() -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000, 0)
        .single()
        .expect("the fixture timestamp is valid")
}

/// Builds, proves and authorizes one treasury disbursement.
///
/// The ordering matters and is asserted rather than assumed:
///
/// 1. build the unproven Orchard bundle, which fixes every field the sighash commits to;
/// 2. encode it with a zero-filled proof and zero-filled signatures and take the ZIP-244 sighash;
/// 3. create the real proof and apply the real signatures over that sighash;
/// 4. re-encode with the real proof and signatures, and check the sighash is unchanged;
/// 5. sign the transparent input over the final transaction with two of the three fixture scalars.
fn build_spend(pool: Pool, transparent_change: Option<u64>) -> SpendFixture {
    let mut rng = StdRng::seed_from_u64(0x5741524d_u64);

    let change = transparent_change.unwrap_or(0);
    let note_value = COLLECTOR_VALUE - APPROVED_FEE - change;

    let bundle_version = pool.bundle_version();
    let mut builder = OrchardBuilder::new(
        // The transaction's shape is already public (one transparent input, no transparent
        // outputs), so the bundle is not padded beyond the one-action consensus minimum.
        BundleType::UNPADDED,
        bundle_version,
        bundle_version.default_flags(),
        Anchor::empty_tree(),
    )
    .expect("the fixture bundle version and flags are consistent");

    builder
        .add_output(
            None,
            recipient_address(),
            NoteValue::from_raw(note_value),
            disbursement_memo(),
        )
        .expect("the fixture bundle enables outputs and cross-address transfers");

    let (unproven, _metadata) = builder
        .build::<i64>(&mut rng)
        .expect("the fixture bundle builds")
        .expect("the fixture bundle has an output, so it is produced");

    assert_eq!(
        unproven.actions().len(),
        1,
        "an unpadded one-output bundle must have exactly one action",
    );
    assert_eq!(
        *unproven.value_balance(),
        -i64::try_from(note_value).expect("fixture amounts fit in i64"),
        "value flowing into the shielded pool is a negative value balance",
    );

    // Step 2: placeholder authorization, so the sighash can be taken before the proof exists.
    let placeholder_proof =
        vec![0u8; orchard::Proof::expected_proof_size(unproven.actions().len())];
    let placeholder = WireBundle::new(
        &unproven,
        placeholder_proof,
        vec![[0u8; 64]; unproven.actions().len()],
        [0u8; 64],
    );

    let transparent_outputs = match transparent_change {
        // The policy under test: whole selected UTXOs minus the fee to the shielded recipient,
        // with no change output at all.
        None => Vec::new(),
        Some(change) => vec![transparent::Output {
            value: amount(change),
            lock_script: transparent::Script::new(&treasury_lock_script()),
        }],
    };

    let mut fixture = SpendFixture {
        pool,
        outpoint: transparent::OutPoint {
            hash: transaction::Hash([0x33u8; 32]),
            index: 0,
        },
        previous_output: transparent::Output {
            value: amount(COLLECTOR_VALUE),
            lock_script: transparent::Script::new(&treasury_lock_script()),
        },
        transparent_outputs,
        wire: placeholder,
        shielded_sighash: [0u8; 32],
        script_sig: Vec::new(),
        note_value,
    };

    let placeholder_transaction = fixture.transaction_with(&fixture.wire, &[]);
    let shielded_sighash: [u8; 32] = {
        let sighasher = placeholder_transaction
            .sighasher(pool.network_upgrade(), fixture.previous_outputs())
            .expect("the fixture transaction's branch ID matches its network upgrade");
        *sighasher.sighash(HashType::ALL, None).as_ref()
    };

    // Step 3: the real proof and the real signatures.
    //
    // The bundle has no real spends, so no spend authorizing key is supplied: the builder's
    // fabricated dummy spend is signed by `prepare` with the dummy's own key.
    let authorized = unproven
        .create_proof(pool.proving_key(), &mut rng)
        .expect("the fixture bundle proves under the matching circuit key")
        .apply_signatures(&mut rng, shielded_sighash, &[])
        .expect("the fixture bundle has no spends needing an external signature");

    let spend_auth_sigs = authorized
        .actions()
        .iter()
        .map(|action| <[u8; 64]>::from(action.authorization()))
        .collect();
    let authorized_wire = WireBundle::new(
        &authorized,
        authorized.authorization().proof().as_ref().to_vec(),
        spend_auth_sigs,
        <[u8; 64]>::from(authorized.authorization().binding_signature()),
    );

    fixture.wire = authorized_wire;
    fixture.shielded_sighash = shielded_sighash;

    // Step 4: the ZIP-244 signature digest excludes the proof and the signatures, so filling them
    // in must not have moved the sighash. Everything else in this file depends on that.
    let authorized_transaction = fixture.transaction_with(&fixture.wire, &[]);
    let reconfirmed_sighash: [u8; 32] = {
        let sighasher = authorized_transaction
            .sighasher(pool.network_upgrade(), fixture.previous_outputs())
            .expect("the fixture transaction's branch ID matches its network upgrade");
        *sighasher.sighash(HashType::ALL, None).as_ref()
    };
    assert_eq!(
        reconfirmed_sighash, shielded_sighash,
        "the ZIP-244 signature digest must not commit to the proof or the signatures",
    );

    // Step 5: two of the three fixture signers authorize the transparent input, in redeem-script
    // key order, over the sighash that commits to the shielded bundle.
    let transparent_sighash =
        fixture.transparent_sighash(&authorized_transaction, pool.network_upgrade());
    fixture.script_sig = multisig_script_sig(&[
        der_signature(FIXTURE_SCALARS[0], &transparent_sighash),
        der_signature(FIXTURE_SCALARS[1], &transparent_sighash),
    ]);

    fixture
}

/// The v5 / NU5 treasury disbursement with no transparent output: the policy under test.
///
/// Built once per test binary, because the Halo2 proof is expensive.
fn v5_spend() -> &'static SpendFixture {
    static FIXTURE: OnceLock<SpendFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| build_spend(Pool::V5Orchard, None))
}

/// The same disbursement, but keeping transparent change under the 2-of-3 policy.
///
/// This is the shape the custody rules forbid for a coinbase input.
fn v5_spend_with_change() -> &'static SpendFixture {
    static FIXTURE: OnceLock<SpendFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| build_spend(Pool::V5Orchard, Some(ATTEMPTED_CHANGE)))
}

/// The v6 / NU6.3 treasury disbursement into the Ironwood pool.
fn v6_spend() -> &'static SpendFixture {
    static FIXTURE: OnceLock<SpendFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| build_spend(Pool::V6Ironwood, None))
}

// -- (a) the transparent input is authorized ---------------------------------

/// The published 2-of-3 redeem script is reproduced exactly, and the script interpreter accepts
/// the combined scriptSig against the P2SH locking script built from the published script hash.
///
/// Because the locking script commits to the published `HASH160`, acceptance here also proves the
/// redeem script hashes to it.
#[test]
fn treasury_input_is_authorised_by_two_of_three_fixture_signatures() {
    let _init_guard = zebra_test::init();

    assert_eq!(
        hex::encode(treasury_redeem_script()),
        KNOWN_REDEEM_SCRIPT,
        "the fixture must reproduce the published swarm-keytool 2-of-3 redeem script",
    );

    let fixture = v5_spend();
    let transaction = Arc::new(fixture.transaction());

    let verifier = CachedFfiTransaction::new(
        transaction,
        fixture.previous_outputs(),
        fixture.pool.network_upgrade(),
    )
    .expect("the fixture transaction is supported by NU5");

    assert!(
        verifier.is_valid(0).is_ok(),
        "the maintained script interpreter must accept the 2-of-3 P2SH treasury input",
    );
}

// -- (b) the whole verifier accepts the disbursement -------------------------

/// A mature treasury coinbase UTXO spent entirely into one shielded note, with no transparent
/// output, is accepted by the real `zebra-consensus` transaction verifier on both its block and
/// its mempool path, and by the real state-side coinbase rule.
#[tokio::test(flavor = "multi_thread")]
async fn mature_treasury_coinbase_spends_into_a_real_shielded_output() {
    let _init_guard = zebra_test::init();

    let fixture = v5_spend();
    let transaction = fixture.transaction();

    // The policy: whole UTXO in, nothing transparent out.
    assert!(
        transaction.outputs().is_empty(),
        "a treasury coinbase disbursement must have no transparent output at all",
    );
    assert_eq!(
        fixture.note_value,
        COLLECTOR_VALUE - APPROVED_FEE,
        "the recipient receives the whole selected UTXO minus the approved fee",
    );

    // The fee the verifier computes from the value balance is the approved fee.
    let value_balance = transaction
        .value_balance(&fixture.spent_utxos())
        .expect("the fixture transaction's value balance is computable");
    let miner_fee = value_balance
        .remaining_transaction_value()
        .expect("the fixture transaction has a non-negative remaining value");
    assert_eq!(
        miner_fee,
        amount(APPROVED_FEE),
        "the miner fee must be exactly the approved fee",
    );

    // The ZIP-317 rule the verifier applies on the mempool path: a transaction with unpaid
    // actions is rejected, so the approved fee must cover the conventional fee.
    let unmined = UnminedTx::from(Arc::new(transaction.clone()));
    let conventional_fee = zip317::conventional_fee(&transaction);
    assert!(
        miner_fee >= conventional_fee,
        "the approved fee {miner_fee:?} must be at least the ZIP-317 conventional fee \
         {conventional_fee:?}",
    );
    assert_eq!(
        zip317::unpaid_actions(&unmined, miner_fee),
        0,
        "the disbursement must have no ZIP-317 unpaid actions",
    );

    // The state-side coinbase rule, at the first mature height.
    let restriction = transaction
        .coinbase_spend_restriction(&custody_rehearsal_network(), fixture.mature_height());
    assert_eq!(
        restriction,
        CoinbaseSpendRestriction::CheckCoinbaseMaturity {
            spend_height: fixture.mature_height(),
        },
        "with no transparent output the spend is subject only to the maturity rule",
    );
    assert_eq!(
        zebra_state::check::transparent_coinbase_spend(
            fixture.outpoint,
            restriction,
            &fixture.utxo(),
        ),
        Ok(()),
        "a mature coinbase spend with no transparent output passes the state coinbase rule",
    );

    // The same rule as `zebra-consensus` applies it to the transaction.
    consensus_check::tx_transparent_coinbase_spends_maturity(
        &custody_rehearsal_network(),
        Arc::new(transaction.clone()),
        fixture.mature_height(),
        Arc::new(HashMap::new()),
        &fixture.spent_utxos(),
    )
    .expect("the mature disbursement passes the consensus coinbase maturity rule");

    // The whole verifier: script interpreter, Halo2 proof, RedPallas signatures, structure and
    // network rules.
    fixture
        .verify_in_block(transaction.clone(), fixture.mature_height())
        .await
        .expect("the block transaction verifier must accept the mature shielded disbursement");

    fixture
        .verify_in_mempool(transaction, fixture.mature_height())
        .await
        .expect("the mempool transaction verifier must accept the mature shielded disbursement");
}

// -- (c) the recipient can decrypt the note ----------------------------------

/// The intended recipient recovers the note from the transaction with its incoming viewing key,
/// and the recovered value, address and memo are the ones the disbursement intended.
///
/// The bundle used here is the one recovered from the built transaction through Zebra's own
/// conversion to the `orchard` crate's `Bundle`, not the builder's in-memory object, so this is a
/// decryption of what the transaction actually carries.
#[test]
fn recipient_decrypts_the_disbursed_note() {
    let _init_guard = zebra_test::init();

    let fixture = v5_spend();
    let transaction = fixture.transaction();

    let sighasher = transaction
        .sighasher(fixture.pool.network_upgrade(), fixture.previous_outputs())
        .expect("the fixture transaction's branch ID matches its network upgrade");
    let bundle = sighasher
        .orchard_bundle()
        .expect("the fixture transaction carries an Orchard bundle");

    let (note, address, memo) = bundle
        .decrypt_output_with_key(0, &recipient_incoming_viewing_key())
        .expect("the intended recipient's incoming viewing key must decrypt the note");

    assert_eq!(
        note.value().inner(),
        COLLECTOR_VALUE - APPROVED_FEE,
        "the recipient receives the whole selected UTXO minus the approved fee",
    );
    assert_eq!(
        address,
        recipient_address(),
        "the note must be addressed to the intended recipient's receiver",
    );
    assert_eq!(
        &memo[..DISBURSEMENT_MEMO.len()],
        DISBURSEMENT_MEMO,
        "the recipient must recover the disbursement memo",
    );
    assert!(
        memo[DISBURSEMENT_MEMO.len()..]
            .iter()
            .all(|byte| *byte == 0),
        "the memo must be zero-padded",
    );

    // A key that is not the recipient's must not decrypt the note.
    let other_ivk = FullViewingKey::from(
        &SpendingKey::from_bytes([7u8; 32])
            .expect("the documented fixture bytes are a valid Orchard spending key"),
    )
    .to_ivk(Scope::External);
    assert!(
        bundle.decrypt_output_with_key(0, &other_ivk).is_none(),
        "an unrelated incoming viewing key must not decrypt the note",
    );
}

// -- (d) negative variants ---------------------------------------------------

/// The same disbursement, plus one transparent change output back to the 2-of-3 treasury address,
/// is rejected by the coinbase rule — even though the change goes back to the same policy.
#[tokio::test(flavor = "multi_thread")]
async fn coinbase_spend_with_transparent_change_is_rejected() {
    let _init_guard = zebra_test::init();

    let fixture = v5_spend_with_change();
    let transaction = fixture.transaction();
    let network = custody_rehearsal_network();

    assert_eq!(
        transaction.outputs().len(),
        1,
        "this fixture deliberately keeps transparent change",
    );

    // The transparent input itself is correctly signed: the rejection is the custody rule, not a
    // broken signature.
    let cached = CachedFfiTransaction::new(
        Arc::new(transaction.clone()),
        fixture.previous_outputs(),
        fixture.pool.network_upgrade(),
    )
    .expect("the fixture transaction is supported by NU5");
    assert!(
        cached.is_valid(0).is_ok(),
        "the change variant's transparent input is still correctly signed",
    );

    let restriction = transaction.coinbase_spend_restriction(&network, fixture.mature_height());
    assert_eq!(
        restriction,
        CoinbaseSpendRestriction::DisallowCoinbaseSpend,
        "any transparent output disallows the coinbase spend outright",
    );
    assert!(
        zebra_state::check::transparent_coinbase_spend(
            fixture.outpoint,
            restriction,
            &fixture.utxo(),
        )
        .is_err(),
        "a coinbase spend with a transparent change output must be rejected by the state rule",
    );

    assert!(
        consensus_check::tx_transparent_coinbase_spends_maturity(
            &network,
            Arc::new(transaction.clone()),
            fixture.mature_height(),
            Arc::new(HashMap::new()),
            &fixture.spent_utxos(),
        )
        .is_err(),
        "a coinbase spend with a transparent change output must be rejected by the consensus rule",
    );

    assert!(
        fixture
            .verify_in_mempool(transaction, fixture.mature_height())
            .await
            .is_err(),
        "the mempool verifier must reject a coinbase spend that keeps transparent change",
    );
}

/// The same disbursement one block before maturity is rejected.
#[tokio::test(flavor = "multi_thread")]
async fn coinbase_spend_one_block_before_maturity_is_rejected() {
    let _init_guard = zebra_test::init();

    let fixture = v5_spend();
    let transaction = fixture.transaction();
    let network = custody_rehearsal_network();

    let restriction = transaction.coinbase_spend_restriction(&network, fixture.immature_height());
    assert!(
        zebra_state::check::transparent_coinbase_spend(
            fixture.outpoint,
            restriction,
            &fixture.utxo(),
        )
        .is_err(),
        "one block before maturity the state rule must reject the spend",
    );

    assert!(
        consensus_check::tx_transparent_coinbase_spends_maturity(
            &network,
            Arc::new(transaction.clone()),
            fixture.immature_height(),
            Arc::new(HashMap::new()),
            &fixture.spent_utxos(),
        )
        .is_err(),
        "one block before maturity the consensus rule must reject the spend",
    );

    assert!(
        fixture
            .verify_in_mempool(transaction, fixture.immature_height())
            .await
            .is_err(),
        "the mempool verifier must reject the spend one block before maturity",
    );
}

/// One of the three fixture signatures does not authorize the treasury input.
#[tokio::test(flavor = "multi_thread")]
async fn one_signature_does_not_authorise_the_treasury_input() {
    let _init_guard = zebra_test::init();

    let fixture = v5_spend();
    let authorized = fixture.transaction();
    let sighash = fixture.transparent_sighash(&authorized, fixture.pool.network_upgrade());

    let one_signature = multisig_script_sig(&[der_signature(FIXTURE_SCALARS[0], &sighash)]);
    let transaction = fixture.transaction_with(&fixture.wire, &one_signature);

    let cached = CachedFfiTransaction::new(
        Arc::new(transaction.clone()),
        fixture.previous_outputs(),
        fixture.pool.network_upgrade(),
    )
    .expect("the fixture transaction is supported by NU5");
    assert!(
        cached.is_valid(0).is_err(),
        "one of three signatures must not satisfy the 2-of-3 policy",
    );

    assert!(
        fixture
            .verify_in_block(transaction, fixture.mature_height())
            .await
            .is_err(),
        "the block verifier must reject a treasury input with only one signature",
    );
}

/// A tampered Orchard proof is rejected by the real Halo2 verifier.
#[tokio::test(flavor = "multi_thread")]
async fn tampered_orchard_proof_is_rejected() {
    let _init_guard = zebra_test::init();

    let fixture = v5_spend();

    let mut tampered = fixture.wire.clone();
    tampered.proof[0] ^= 0x01;
    assert_ne!(
        tampered.proof, fixture.wire.proof,
        "the tampered proof must differ from the real one",
    );
    assert_eq!(
        tampered.proof.len(),
        fixture.wire.proof.len(),
        "the tampered proof keeps the canonical length, so only the Halo2 check can reject it",
    );

    let transaction = fixture.transaction_with(&tampered, &fixture.script_sig);

    assert!(
        fixture
            .verify_in_block(transaction, fixture.mature_height())
            .await
            .is_err(),
        "the block verifier must reject a transaction whose Orchard proof was tampered with",
    );
}

/// A transparent signature made under the NU6.3 domain does not authorize an NU5 transaction.
///
/// The ZIP-244 sighash commits to the consensus branch ID, so a signature produced against the
/// wrong network upgrade is worthless even though every other field is identical.
#[test]
fn wrong_domain_signature_does_not_authorise_the_treasury_input() {
    let _init_guard = zebra_test::init();

    let fixture = v5_spend();
    let authorized = fixture.transaction();

    let nu5_sighash = fixture.transparent_sighash(&authorized, NetworkUpgrade::Nu5);

    // The same transaction body under the NU6.3 branch ID, used only to produce a sighash: v5
    // transactions stay valid at NU6.3, so this is a domain a signer could plausibly be handed.
    let nu6_3_twin = match authorized.clone() {
        Transaction::V5 {
            lock_time,
            expiry_height,
            inputs,
            outputs,
            sapling_shielded_data,
            orchard_shielded_data,
            ..
        } => Transaction::V5 {
            consensus_branch_id: NetworkUpgrade::Nu6_3
                .branch_id()
                .expect("NU6.3 has a branch ID"),
            lock_time,
            expiry_height,
            inputs,
            outputs,
            sapling_shielded_data,
            orchard_shielded_data,
        },
        _ => unreachable!("the v5 fixture builds a v5 transaction"),
    };
    let nu6_3_sighash = fixture.transparent_sighash(&nu6_3_twin, NetworkUpgrade::Nu6_3);

    assert_ne!(
        nu5_sighash, nu6_3_sighash,
        "the NU5 and NU6.3 sighashes of the same transaction body must differ",
    );

    let wrong_domain = multisig_script_sig(&[
        der_signature(FIXTURE_SCALARS[0], &nu6_3_sighash),
        der_signature(FIXTURE_SCALARS[1], &nu6_3_sighash),
    ]);
    let transaction = fixture.transaction_with(&fixture.wire, &wrong_domain);

    let cached = CachedFfiTransaction::new(
        Arc::new(transaction),
        fixture.previous_outputs(),
        NetworkUpgrade::Nu5,
    )
    .expect("the fixture transaction is supported by NU5");
    assert!(
        cached.is_valid(0).is_err(),
        "signatures made under the NU6.3 domain must not authorise an NU5 transaction",
    );
}

// -- the v6 / NU6.3 variant --------------------------------------------------

/// From NU6.3 the Orchard pool is frozen against new inflows, so the v5 Orchard disbursement — the
/// very transaction this file proves valid at NU5 — becomes invalid at NU6.3.
///
/// This is why the v6 variant targets the Ironwood pool rather than reusing the Orchard bundle.
#[test]
fn orchard_pool_is_frozen_against_inflows_at_nu6_3() {
    let _init_guard = zebra_test::init();

    let transaction = v5_spend().transaction();

    consensus_check::orchard_value_balance_non_negative(&transaction, NetworkUpgrade::Nu5)
        .expect("shielding into the Orchard pool is allowed at NU5");

    assert!(
        consensus_check::orchard_value_balance_non_negative(&transaction, NetworkUpgrade::Nu6_3)
            .is_err(),
        "from NU6.3 new value may not flow into the Orchard pool",
    );
}

/// The same policy in a v6 transaction at NU6.3: the whole mature treasury coinbase UTXO minus the
/// approved fee goes into one real Ironwood note, with no transparent output.
#[tokio::test(flavor = "multi_thread")]
async fn mature_treasury_coinbase_spends_into_a_real_ironwood_output() {
    let _init_guard = zebra_test::init();

    let fixture = v6_spend();
    let transaction = fixture.transaction();

    assert!(
        transaction.outputs().is_empty(),
        "a treasury coinbase disbursement must have no transparent output at all",
    );
    assert!(
        transaction.ironwood_shielded_data().is_some(),
        "the v6 disbursement must carry an Ironwood bundle",
    );
    assert!(
        transaction.orchard_shielded_data().is_none(),
        "the v6 disbursement must not carry an Orchard bundle: that pool is frozen at NU6.3",
    );

    let cached = CachedFfiTransaction::new(
        Arc::new(transaction.clone()),
        fixture.previous_outputs(),
        NetworkUpgrade::Nu6_3,
    )
    .expect("the fixture transaction is supported by NU6.3");
    assert!(
        cached.is_valid(0).is_ok(),
        "the maintained script interpreter must accept the v6 treasury input",
    );

    fixture
        .verify_in_block(transaction.clone(), fixture.mature_height())
        .await
        .expect("the block transaction verifier must accept the v6 Ironwood disbursement");

    fixture
        .verify_in_mempool(transaction.clone(), fixture.mature_height())
        .await
        .expect("the mempool transaction verifier must accept the v6 Ironwood disbursement");

    // The recipient decrypts the Ironwood note from the built transaction.
    let sighasher = transaction
        .sighasher(NetworkUpgrade::Nu6_3, fixture.previous_outputs())
        .expect("the fixture transaction's branch ID matches its network upgrade");
    let bundle = sighasher
        .ironwood_bundle()
        .expect("the fixture transaction carries an Ironwood bundle");
    let (note, address, memo) = bundle
        .decrypt_output_with_key(0, &recipient_incoming_viewing_key())
        .expect("the intended recipient's incoming viewing key must decrypt the Ironwood note");

    assert_eq!(note.value().inner(), COLLECTOR_VALUE - APPROVED_FEE);
    assert_eq!(address, recipient_address());
    assert_eq!(&memo[..DISBURSEMENT_MEMO.len()], DISBURSEMENT_MEMO);
}
