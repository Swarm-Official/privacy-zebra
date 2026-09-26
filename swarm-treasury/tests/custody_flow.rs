//! The whole custody flow, end to end, with disposable keys that exist only for this test binary.
//!
//! Three signers are generated in memory, a policy is assembled from their public records, a
//! proposal is built against a synthetic mature treasury coinbase UTXO, two of the three signers
//! sign it, and the combined transaction is put past the same `zebra-consensus` block and mempool
//! verifiers task T2 used.
//!
//! # Nothing here touches a real key, a real chain or the filesystem
//!
//! The signer keys are drawn from the OS CSPRNG inside this process and dropped when it exits;
//! they are never written anywhere. The recipient is the documented all-zero Orchard spending key.
//! The state service is a fixture, so anchors and nullifiers are *not* checked against a chain —
//! the same limit task T2 recorded.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
};

use chrono::{DateTime, TimeZone, Utc};
use tower::{Service, ServiceExt};

use zebra_chain::{
    amount::{Amount, NonNegative},
    block::Height,
    parameters::{testnet::Parameters, Network, NetworkUpgrade},
    serialization::{DateTime32, ZcashDeserializeInto},
    transaction::{self, zip317, Transaction, UnminedTx},
    transparent::{self, CoinbaseSpendRestriction, OrderedUtxo, Utxo},
};
use zebra_consensus::transaction::{
    BlockRequest, BlockTxVerifier, MempoolRequest, MempoolTxVerifier,
};
use zebra_script::CachedFfiTransaction;

use swarm_treasury::{
    network::TreasuryNetwork,
    policy::{self, CheckedPolicy, Fund},
    script,
    shielded::{self, Pool},
    signer::{self, SignerSecret},
    spend::{self, CheckedProposal, Proposal, SignatureFile},
    utxo::{UtxoEntry, UtxoFile, UTXO_SCHEMA, UTXO_SCHEMA_VERSION},
};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The value of the synthetic treasury coinbase output, in zatoshis.
const COLLECTOR_VALUE: u64 = 3_1250_0000;
/// The approved fee, comfortably above the ZIP-317 conventional fee for this shape.
const APPROVED_FEE: u64 = 2_0000;
/// The number of blocks a transparent coinbase output must age before it can be spent.
const MATURITY: u32 = 100;
/// The height the v6 fixture's coinbase output is created at: above the Testnet NU6.3 activation.
const V6_CREATED_HEIGHT: u32 = 4_200_000;
/// The height the v5 fixture's coinbase output is created at: between NU5 and NU6.
const V5_CREATED_HEIGHT: u32 = 2_000_000;
/// The memo the fixture disbursement carries.
const MEMO: &str = "SWARM treasury disbursement fixture T3";
/// The passphrase the fixture backups use. Disposable, and never near a real key.
const PASSPHRASE: &str = "fixture passphrase, never used for anything real";
/// A deliberately weak scrypt work factor, so the suite is not spent in a key derivation function.
const TEST_LOG_N: Option<u8> = Some(10);

// -- the custody rehearsal network -------------------------------------------

/// The custom Testnet used for custody rehearsals.
///
/// `should_allow_unshielded_coinbase_spends` is set to `false` **explicitly**, so nothing here can
/// pass because of a permissive default: the Regtest constructor defaults it to `true`, which
/// would make a production-incompatible transparent-change path look valid.
fn custody_rehearsal_network() -> Network {
    Parameters::build()
        .with_unshielded_coinbase_spends(false)
        .to_network()
        .expect("the custody rehearsal Testnet parameters are valid")
}

// -- the fixture state service -----------------------------------------------

/// A minimal state service that serves exactly the fixture's UTXOs.
///
/// Any request the verifier makes that this fixture does not model fails loudly rather than being
/// answered with a default.
#[derive(Clone, Debug)]
struct FixtureState {
    utxos: HashMap<transparent::OutPoint, Utxo>,
}

impl Service<zebra_state::Request> for FixtureState {
    type Response = zebra_state::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: zebra_state::Request) -> Self::Future {
        let utxos = self.utxos.clone();

        let response: Result<zebra_state::Response, BoxError> = match request {
            zebra_state::Request::AwaitUtxo(requested) if utxos.contains_key(&requested) => {
                Ok(zebra_state::Response::Utxo(utxos[&requested].clone()))
            }
            zebra_state::Request::UnspentBestChainUtxo(requested)
                if utxos.contains_key(&requested) =>
            {
                Ok(zebra_state::Response::UnspentBestChainUtxo(Some(
                    utxos[&requested].clone(),
                )))
            }
            // The fixture has no chain, so the note commitment tree anchor and the nullifier set
            // are not checked against one. That limit is recorded in docs/swarm-treasury.md.
            zebra_state::Request::CheckBestChainTipNullifiersAndAnchors(_) => {
                Ok(zebra_state::Response::ValidBestChainTipNullifiersAndAnchors)
            }
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
type FixtureMempool = tower::buffer::Buffer<
    tower::util::BoxService<
        zebra_node_services::mempool::Request,
        zebra_node_services::mempool::Response,
        BoxError,
    >,
    zebra_node_services::mempool::Request,
>;

fn block_time() -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000, 0)
        .single()
        .expect("the fixture timestamp is valid")
}

// -- the fixture custody set -------------------------------------------------

/// Three signers, their encrypted backups and the policy they form.
struct Custody {
    secrets: Vec<SignerSecret>,
    backups: Vec<Vec<u8>>,
    checked: CheckedPolicy,
}

impl Custody {
    /// Generates three fresh signers on "three devices", and assembles the 2-of-3 policy.
    fn new() -> Self {
        let secrets: Vec<SignerSecret> = ["A", "B", "C"]
            .iter()
            .map(|label| signer::generate(label).expect("a key is generated"))
            .collect();
        let passphrase = signer::Passphrase::new(PASSPHRASE).unwrap();
        let backups = secrets
            .iter()
            .map(|secret| {
                signer::encrypt_backup_with(secret, &passphrase, TEST_LOG_N).expect("encrypts")
            })
            .collect();

        let publics: Vec<_> = secrets.iter().map(SignerSecret::public).collect();
        let policy =
            policy::assemble(Fund::Core, TreasuryNetwork::Testnet, 2, &publics).expect("assembles");
        let checked = policy::verify(&policy).expect("the assembled policy verifies");

        Custody {
            secrets,
            backups,
            checked,
        }
    }

    /// The hand-exported UTXO list: one mature treasury coinbase output.
    fn utxo_file(&self, created_height: u32) -> UtxoFile {
        UtxoFile {
            schema: UTXO_SCHEMA.to_string(),
            schema_version: UTXO_SCHEMA_VERSION,
            network: self.checked.policy.network.clone(),
            utxos: vec![UtxoEntry {
                txid: "33".repeat(32),
                vout: 0,
                value: COLLECTOR_VALUE,
                height: created_height,
                is_coinbase: true,
                script: hex::encode(&self.checked.lock_script),
            }],
        }
    }
}

/// One built proposal, and the fixture state that serves the UTXOs it spends.
struct Fixture {
    custody: Custody,
    proposal: Proposal,
    created_height: u32,
    pool: Pool,
}

impl Fixture {
    fn build(pool: Pool, fee: u64) -> Result<Self, swarm_treasury::Error> {
        Self::build_with(pool, Some(fee))
    }

    /// The same, with no approved fee at all: the proposal pays the conventional fee.
    fn build_with(pool: Pool, fee: Option<u64>) -> Result<Self, swarm_treasury::Error> {
        let custody = Custody::new();
        let created_height = match pool {
            Pool::V6Ironwood => V6_CREATED_HEIGHT,
            Pool::V5Orchard => V5_CREATED_HEIGHT,
        };
        let utxo_file = custody.utxo_file(created_height);
        let selected = swarm_treasury::utxo::select_all(
            &utxo_file,
            &custody.checked.lock_script,
            &custody.checked.policy.network,
        )?;

        let key = shielded::fixture_spending_key([0u8; 32])?;
        let recipient = shielded::receiver_of_spending_key(&key);
        let recipient_text = hex::encode(recipient.to_raw_address_bytes());

        let proposal = spend::propose(spend::ProposalRequest {
            policy: &custody.checked,
            selected: &selected,
            recipient_text: &recipient_text,
            recipient,
            memo_text: MEMO,
            fee,
            expiry_height: created_height + MATURITY + 100,
            pool,
            // Deterministic: the same bytes every run, so a failure is reproducible.
            rng_seed: [0x5au8; 32],
        })?;

        Ok(Fixture {
            custody,
            proposal,
            created_height,
            pool,
        })
    }

    fn policy(&self) -> &CheckedPolicy {
        &self.custody.checked
    }

    fn checked(&self) -> CheckedProposal {
        spend::check(&self.proposal, self.policy()).expect("the built proposal checks out")
    }

    fn mature_height(&self) -> Height {
        Height(self.created_height + MATURITY)
    }

    fn immature_height(&self) -> Height {
        Height(self.created_height + MATURITY - 1)
    }

    /// Signs with the signers at the given indices, through the encrypted backups.
    fn sign_with(&self, indices: &[usize]) -> Vec<SignatureFile> {
        let checked = self.checked();
        let passphrase = signer::Passphrase::new(PASSPHRASE).unwrap();
        indices
            .iter()
            .map(|index| {
                let secret = signer::decrypt_backup(&self.custody.backups[*index], &passphrase)
                    .expect("the backup decrypts");
                spend::sign(&checked, self.policy(), &secret).expect("signs")
            })
            .collect()
    }

    /// The UTXOs the fixture spends, as the state sees them.
    fn utxos(&self) -> HashMap<transparent::OutPoint, Utxo> {
        let checked = self.checked();
        checked
            .transaction
            .inputs()
            .iter()
            .zip(&checked.previous_outputs)
            .filter_map(|(input, output)| match input {
                transparent::Input::PrevOut { outpoint, .. } => Some((
                    *outpoint,
                    Utxo::new(output.clone(), Height(self.created_height), true),
                )),
                transparent::Input::Coinbase { .. } => None,
            })
            .collect()
    }

    fn state(&self) -> FixtureState {
        FixtureState {
            utxos: self.utxos(),
        }
    }

    fn known_utxos(&self) -> Arc<HashMap<transparent::OutPoint, OrderedUtxo>> {
        Arc::new(
            self.utxos()
                .into_iter()
                .map(|(outpoint, utxo)| (outpoint, OrderedUtxo::from_utxo(utxo, 0)))
                .collect(),
        )
    }

    /// Runs the whole `zebra-consensus` block transaction verifier over `transaction`.
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

    /// Runs the whole `zebra-consensus` mempool transaction verifier over `transaction`.
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

/// The v6 / NU6.3 Ironwood fixture, built once: a Halo2 proof is expensive.
fn v6_fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        Fixture::build(Pool::V6Ironwood, APPROVED_FEE).expect("the v6 fixture builds")
    })
}

/// The v5 / NU5 Orchard fixture, kept as the task T2 test path.
fn v5_fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        Fixture::build(Pool::V5Orchard, APPROVED_FEE).expect("the v5 fixture builds")
    })
}

// -- (a) the golden vector ---------------------------------------------------

/// With the published fixture scalars 1, 2 and 3, `policy assemble` reproduces the published
/// `swarm-keytool` 2-of-3 script hash and address.
///
/// These are disposable public test vectors and must never be funded.
#[test]
fn fixture_scalars_reproduce_the_published_policy() {
    let publics: Vec<_> = [
        (
            "A",
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
        (
            "B",
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        ),
        (
            "C",
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        ),
    ]
    .iter()
    .map(|(label, key)| {
        let parsed = script::parse_public_key(key).unwrap();
        signer::SignerPublic {
            schema: signer::PUBLIC_SCHEMA.to_string(),
            schema_version: signer::SIGNER_SCHEMA_VERSION,
            tool: swarm_treasury::TOOL_NAME.to_string(),
            tool_version: swarm_treasury::TOOL_VERSION.to_string(),
            label: (*label).to_string(),
            public_key: (*key).to_string(),
            fingerprint: signer::fingerprint(&parsed),
            created: "2026-09-25T00:00:00Z".to_string(),
        }
    })
    .collect();

    let policy = policy::assemble(Fund::Core, TreasuryNetwork::Testnet, 2, &publics).unwrap();
    assert_eq!(
        policy.script_hash,
        "15fc0754e73eb85d1cbce08786fadb7320ecb8dc"
    );
    assert_eq!(policy.address, "t28Z45qZRaD6zXBMFHTzEN7pZfGeZTtbkFp");
    policy::verify(&policy).unwrap();
}

// -- (b) the whole flow ------------------------------------------------------

/// Three in-memory signers, a policy, a proposal, two signatures and a combine — and the result is
/// accepted by the real block **and** mempool verifiers at the first mature height.
#[tokio::test(flavor = "multi_thread")]
async fn full_v6_ironwood_flow_is_accepted_by_both_verifiers() {
    let _init_guard = zebra_test::init();
    let fixture = v6_fixture();
    let checked = fixture.checked();

    // The policy the tool implements: whole UTXO in, nothing transparent out.
    assert!(
        checked.transaction.outputs().is_empty(),
        "a treasury coinbase disbursement must have no transparent output at all",
    );
    assert_eq!(fixture.proposal.total_in, COLLECTOR_VALUE);
    assert_eq!(fixture.proposal.fee, APPROVED_FEE);
    assert_eq!(fixture.proposal.amount_out, COLLECTOR_VALUE - APPROVED_FEE);
    assert!(fixture.proposal.fee >= fixture.proposal.conventional_fee);
    assert!(
        checked.transaction.ironwood_shielded_data().is_some(),
        "the mainnet disbursement path pays into Ironwood, not Orchard",
    );
    assert!(checked.transaction.orchard_shielded_data().is_none());

    let signatures = fixture.sign_with(&[0, 1]);
    let combined = spend::combine(&checked, fixture.policy(), &signatures).unwrap();
    assert_eq!(
        combined.record.signers,
        vec!["A".to_string(), "B".to_string()]
    );

    // The hex is what would go to `sendrawtransaction`, and it re-parses to the same transaction.
    let raw = hex::decode(&combined.raw_hex).unwrap();
    let reparsed: Transaction = raw.as_slice().zcash_deserialize_into().unwrap();
    assert_eq!(reparsed.hash().to_string(), combined.record.txid);

    // The state-side coinbase rule, at the first mature height.
    let network = custody_rehearsal_network();
    let restriction = reparsed.coinbase_spend_restriction(&network, fixture.mature_height());
    assert_eq!(
        restriction,
        CoinbaseSpendRestriction::CheckCoinbaseMaturity {
            spend_height: fixture.mature_height(),
        },
        "with no transparent output the spend is subject only to the maturity rule",
    );
    for (outpoint, utxo) in fixture.utxos() {
        assert_eq!(
            zebra_state::check::transparent_coinbase_spend(outpoint, restriction, &utxo),
            Ok(()),
        );
    }

    // The whole verifiers: script interpreter, Halo2 proof, RedPallas signatures, structure, fees.
    fixture
        .verify_in_block(reparsed.clone(), fixture.mature_height())
        .await
        .expect("the block verifier must accept the combined disbursement");
    fixture
        .verify_in_mempool(reparsed, fixture.mature_height())
        .await
        .expect("the mempool verifier must accept the combined disbursement");
}

/// Every 2-of-3 pair authorizes the spend, and the combiner canonicalizes by policy key order
/// however the files arrive.
#[tokio::test(flavor = "multi_thread")]
async fn every_signing_pair_authorises_the_spend() {
    let _init_guard = zebra_test::init();
    let fixture = v6_fixture();
    let checked = fixture.checked();

    for pair in [[0usize, 1], [0, 2], [1, 2]] {
        let signatures = fixture.sign_with(&pair);
        let combined = spend::combine(&checked, fixture.policy(), &signatures).unwrap();

        let expected: Vec<String> = pair
            .iter()
            .map(|index| fixture.custody.secrets[*index].label.clone())
            .collect();
        assert_eq!(combined.record.signers, expected, "pair {pair:?}");

        fixture
            .verify_in_block(combined.transaction.clone(), fixture.mature_height())
            .await
            .unwrap_or_else(|error| panic!("pair {pair:?} must be accepted: {error}"));
    }

    // The order the coordinator receives the files in does not change the result.
    let mut reversed = fixture.sign_with(&[0, 1]);
    reversed.reverse();
    let combined = spend::combine(&checked, fixture.policy(), &reversed).unwrap();
    assert_eq!(
        combined.record.signers,
        vec!["A".to_string(), "B".to_string()]
    );
}

/// The same flow on the v5 / NU5 Orchard path, kept so the task T2 construction stays exercised.
#[tokio::test(flavor = "multi_thread")]
async fn full_v5_orchard_flow_is_accepted() {
    let _init_guard = zebra_test::init();
    let fixture = v5_fixture();
    let checked = fixture.checked();

    assert!(checked.transaction.orchard_shielded_data().is_some());
    let signatures = fixture.sign_with(&[0, 2]);
    let combined = spend::combine(&checked, fixture.policy(), &signatures).unwrap();

    fixture
        .verify_in_block(combined.transaction.clone(), fixture.mature_height())
        .await
        .expect("the block verifier must accept the v5 Orchard disbursement");
    fixture
        .verify_in_mempool(combined.transaction, fixture.mature_height())
        .await
        .expect("the mempool verifier must accept the v5 Orchard disbursement");
}

/// The intended recipient decrypts the note out of the transaction the tool produced, and nobody
/// else can.
#[test]
fn the_recipient_decrypts_the_disbursed_note() {
    let _init_guard = zebra_test::init();
    let fixture = v6_fixture();
    let checked = fixture.checked();
    let signatures = fixture.sign_with(&[0, 1]);
    let combined = spend::combine(&checked, fixture.policy(), &signatures).unwrap();

    let previous_outputs = Arc::new(checked.previous_outputs.clone());
    let sighasher = combined
        .transaction
        .sighasher(NetworkUpgrade::Nu6_3, previous_outputs)
        .unwrap();
    let bundle = sighasher.ironwood_bundle().expect("an Ironwood bundle");

    let key = shielded::fixture_spending_key([0u8; 32]).unwrap();
    let viewing_key =
        orchard::keys::FullViewingKey::from(&key).to_ivk(orchard::keys::Scope::External);
    let (note, address, memo) = bundle
        .decrypt_output_with_key(0, &viewing_key)
        .expect("the intended recipient decrypts the note");

    assert_eq!(note.value().inner(), COLLECTOR_VALUE - APPROVED_FEE);
    assert_eq!(address, shielded::receiver_of_spending_key(&key));
    assert_eq!(&memo[..MEMO.len()], MEMO.as_bytes());

    let stranger =
        orchard::keys::FullViewingKey::from(&shielded::fixture_spending_key([7u8; 32]).unwrap())
            .to_ivk(orchard::keys::Scope::External);
    assert!(bundle.decrypt_output_with_key(0, &stranger).is_none());
}

// -- (c) negatives -----------------------------------------------------------

/// Editing the proposal after it was written, in any field a signer reads, is caught before a
/// signature is made — and the signatures already made stop combining.
#[test]
fn a_proposal_edited_after_signing_is_refused() {
    let _init_guard = zebra_test::init();
    let fixture = v6_fixture();
    let checked = fixture.checked();
    let signatures = fixture.sign_with(&[0, 1]);

    // Each of these is an edit a dishonest or careless coordinator could make.
    let edits: Vec<(&str, Box<dyn Fn(&mut Proposal)>)> = vec![
        (
            "recipient",
            Box::new(|proposal: &mut Proposal| {
                let other = shielded::receiver_of_spending_key(
                    &shielded::fixture_spending_key([9u8; 32]).unwrap(),
                );
                proposal.recipient = hex::encode(other.to_raw_address_bytes());
                proposal.recipient_raw_receiver = proposal.recipient.clone();
            }),
        ),
        (
            "amount",
            Box::new(|proposal: &mut Proposal| proposal.amount_out -= 1),
        ),
        ("fee", Box::new(|proposal: &mut Proposal| proposal.fee += 1)),
        (
            "expiry",
            Box::new(|proposal: &mut Proposal| proposal.expiry_height += 1),
        ),
        (
            "memo",
            Box::new(|proposal: &mut Proposal| proposal.memo = "pay me instead".to_string()),
        ),
        (
            "digest",
            Box::new(|proposal: &mut Proposal| {
                proposal.inputs[0].sighash_all_digest = "00".repeat(32)
            }),
        ),
        (
            "input value",
            Box::new(|proposal: &mut Proposal| proposal.inputs[0].value += 1),
        ),
    ];

    for (what, edit) in edits {
        // (1) With the proposal hash left alone, the edit is caught before anyone signs.
        let mut tampered = fixture.proposal.clone();
        edit(&mut tampered);
        assert!(
            spend::check(&tampered, fixture.policy()).is_err(),
            "an edited {what} must be refused by `spend show` / `spend sign`",
        );

        // (2) With the proposal hash recomputed, the signatures no longer belong to it — and for
        // the edits that contradict the transaction, the check still refuses on its own.
        let mut rehashed = tampered;
        rehashed.proposal_hash = spend::proposal_hash(&rehashed);
        match spend::check(&rehashed, fixture.policy()) {
            Err(_) => {}
            Ok(rechecked) => {
                let error = spend::combine(&rechecked, fixture.policy(), &signatures)
                    .expect_err("signatures must not combine onto an edited proposal");
                assert!(
                    error.to_string().contains("proposal"),
                    "an edited {what} must be refused at combine: {error}",
                );
            }
        }
    }

    // The untouched proposal still combines, so the negatives above are not passing by accident.
    spend::combine(&checked, fixture.policy(), &signatures).unwrap();
}

/// A transparent change output injected into the proposal's transaction is refused — even though
/// it pays back to the same 2-of-3 address.
#[test]
fn an_injected_transparent_change_output_is_refused() {
    let _init_guard = zebra_test::init();
    let fixture = v6_fixture();
    let checked = fixture.checked();

    let change = transparent::Output {
        value: Amount::<NonNegative>::try_from(1_0000_0000i64).unwrap(),
        lock_script: transparent::Script::new(&fixture.policy().lock_script),
    };
    let with_change = match checked.transaction.clone() {
        Transaction::V6 {
            consensus_branch_id,
            lock_time,
            expiry_height,
            inputs,
            sapling_shielded_data,
            orchard_shielded_data,
            ironwood_shielded_data,
            ..
        } => Transaction::V6 {
            consensus_branch_id,
            lock_time,
            expiry_height,
            inputs,
            outputs: vec![change],
            sapling_shielded_data,
            orchard_shielded_data,
            ironwood_shielded_data,
        },
        _ => unreachable!("the v6 fixture builds a v6 transaction"),
    };

    let mut tampered = fixture.proposal.clone();
    tampered.transaction = hex::encode(
        zebra_chain::serialization::ZcashSerialize::zcash_serialize_to_vec(&with_change).unwrap(),
    );
    tampered.proposal_hash = spend::proposal_hash(&tampered);

    let error = spend::check(&tampered, fixture.policy())
        .expect_err("a transparent output must be refused");
    assert!(
        error.to_string().contains("transparent output"),
        "the refusal must name the transparent output: {error}",
    );

    // And the consensus rule agrees: any transparent output disallows the coinbase spend outright.
    let network = custody_rehearsal_network();
    assert_eq!(
        with_change.coinbase_spend_restriction(&network, fixture.mature_height()),
        CoinbaseSpendRestriction::DisallowCoinbaseSpend,
    );
}

/// One signature does not satisfy a 2-of-3 policy, and neither does the same signer twice.
#[test]
fn a_single_signature_or_a_repeated_signer_is_refused() {
    let _init_guard = zebra_test::init();
    let fixture = v6_fixture();
    let checked = fixture.checked();

    let single = fixture.sign_with(&[0]);
    let error = spend::combine(&checked, fixture.policy(), &single).unwrap_err();
    assert!(error.to_string().contains("needs exactly 2"), "{error}");

    let mut doubled = fixture.sign_with(&[0]);
    doubled.push(doubled[0].clone());
    let error = spend::combine(&checked, fixture.policy(), &doubled).unwrap_err();
    assert!(error.to_string().contains("same policy key"), "{error}");

    // Relabelling the second copy does not help: the key is what counts.
    let mut relabelled = fixture.sign_with(&[0]);
    let mut copy = relabelled[0].clone();
    copy.label = "B".to_string();
    relabelled.push(copy);
    assert!(spend::combine(&checked, fixture.policy(), &relabelled).is_err());

    // Three signatures are also refused: the threshold is exact, so a spend never carries more
    // authority than the policy asks for.
    let three = fixture.sign_with(&[0, 1, 2]);
    assert!(spend::combine(&checked, fixture.policy(), &three).is_err());
}

/// A signature from a key that is not in the policy is never combined in.
#[test]
fn a_foreign_signer_is_refused() {
    let _init_guard = zebra_test::init();
    let fixture = v6_fixture();
    let checked = fixture.checked();

    let outsider = signer::generate("D").unwrap();
    // `spend::sign` refuses outright.
    assert!(spend::sign(&checked, fixture.policy(), &outsider).is_err());

    // And a hand-written signature file with a foreign key is refused at combine.
    let mut forged = fixture.sign_with(&[0, 1]);
    forged[1].label = outsider.label.clone();
    forged[1].public_key = outsider.public_key.clone();
    forged[1].fingerprint = outsider.fingerprint.clone();
    let error = spend::combine(&checked, fixture.policy(), &forged).unwrap_err();
    assert!(
        error.to_string().contains("not one of this policy's keys"),
        "{error}"
    );
}

/// A signature whose DER bytes were edited does not verify, and never reaches the script
/// interpreter.
#[test]
fn a_corrupted_signature_is_refused() {
    let _init_guard = zebra_test::init();
    let fixture = v6_fixture();
    let checked = fixture.checked();

    let mut corrupted = fixture.sign_with(&[0, 1]);
    let der = &mut corrupted[0].signatures[0].der;
    let mut bytes = hex::decode(&*der).unwrap();
    // Flip a byte inside the DER body, keeping the trailing SIGHASH_ALL byte.
    bytes[10] ^= 0x01;
    *der = hex::encode(bytes);

    assert!(spend::combine(&checked, fixture.policy(), &corrupted).is_err());
}

/// A wrong passphrase, or a backup that does not match the public record it claims, is refused.
#[test]
fn backup_recovery_refuses_a_wrong_passphrase_or_a_mismatch() {
    let _init_guard = zebra_test::init();
    let custody = Custody::new();
    let right = signer::Passphrase::new(PASSPHRASE).unwrap();

    // The right passphrase recovers the key that the public record names.
    let recovered = signer::decrypt_backup(&custody.backups[0], &right).unwrap();
    assert_eq!(recovered.public_key, custody.secrets[0].public_key);
    assert_eq!(recovered.fingerprint, custody.secrets[0].fingerprint);

    // The wrong passphrase does not.
    let wrong = signer::Passphrase::new("not the passphrase").unwrap();
    assert!(signer::decrypt_backup(&custody.backups[0], &wrong).is_err());

    // A backup checked against the wrong public record is a mismatch, and it is visible without
    // ever printing the secret: the fingerprints differ.
    assert_ne!(recovered.fingerprint, custody.secrets[1].fingerprint);

    // And the backup belongs to the policy, while a stranger's does not.
    let (_secret, public_key) = recovered.key_pair().unwrap();
    assert!(custody.checked.index_of(&public_key).is_some());
    let stranger = signer::generate("Z").unwrap();
    let (_stranger_secret, stranger_key) = stranger.key_pair().unwrap();
    assert!(custody.checked.index_of(&stranger_key).is_none());
}

/// A fee below the ZIP-317 conventional fee is refused at proposal time: a node would not relay it.
#[test]
fn a_fee_below_the_conventional_fee_is_refused() {
    let _init_guard = zebra_test::init();
    let error = match Fixture::build(Pool::V6Ironwood, 1) {
        Ok(_) => panic!("a fee below the ZIP-317 conventional fee must be refused"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("below the ZIP-317 conventional fee"),
        "{error}",
    );
}

/// One block before maturity the verifier rejects the spend, however well signed it is.
#[tokio::test(flavor = "multi_thread")]
async fn an_immature_input_is_rejected_by_the_verifier() {
    let _init_guard = zebra_test::init();
    let fixture = v6_fixture();
    let checked = fixture.checked();
    let signatures = fixture.sign_with(&[0, 1]);
    let combined = spend::combine(&checked, fixture.policy(), &signatures).unwrap();

    // The transparent input itself is correctly signed: the rejection is the maturity rule.
    let cached = CachedFfiTransaction::new(
        Arc::new(combined.transaction.clone()),
        Arc::new(checked.previous_outputs.clone()),
        NetworkUpgrade::Nu6_3,
    )
    .unwrap();
    assert!(cached.is_valid(0).is_ok());

    let network = custody_rehearsal_network();
    let restriction = combined
        .transaction
        .coinbase_spend_restriction(&network, fixture.immature_height());
    for (outpoint, utxo) in fixture.utxos() {
        assert!(
            zebra_state::check::transparent_coinbase_spend(outpoint, restriction, &utxo).is_err(),
            "one block before maturity the state rule must reject the spend",
        );
    }

    assert!(
        fixture
            .verify_in_mempool(combined.transaction, fixture.immature_height())
            .await
            .is_err(),
        "the mempool verifier must reject the spend one block before maturity",
    );
}

/// A proposal built for one policy cannot be signed or combined under another.
#[test]
fn a_proposal_from_another_policy_is_refused() {
    let _init_guard = zebra_test::init();
    let fixture = v6_fixture();
    let other = Custody::new();

    assert!(
        spend::check(&fixture.proposal, &other.checked).is_err(),
        "a proposal must not check out against a policy it was not built for",
    );

    let checked = fixture.checked();
    let mut foreign = fixture.sign_with(&[0, 1]);
    foreign[0].policy_fingerprint = other.checked.policy.policy_fingerprint.clone();
    assert!(spend::combine(&checked, fixture.policy(), &foreign).is_err());
}

/// A UTXO list that is not locked to the policy address is refused before anything is built.
#[test]
fn utxos_for_another_address_are_refused() {
    let _init_guard = zebra_test::init();
    let custody = Custody::new();
    let mut list = custody.utxo_file(V6_CREATED_HEIGHT);
    list.utxos[0].script = hex::encode(script::p2sh_lock_script([0x99u8; 20]));

    assert!(swarm_treasury::utxo::select_all(
        &list,
        &custody.checked.lock_script,
        &custody.checked.policy.network,
    )
    .is_err());
}

/// The proposal's raw transaction really is the transaction that gets signed: the digests
/// recomputed from it are the ones recorded.
#[test]
fn digests_are_recomputed_from_the_raw_transaction() {
    let _init_guard = zebra_test::init();
    let fixture = v6_fixture();
    let checked = fixture.checked();

    let raw = hex::decode(&fixture.proposal.transaction).unwrap();
    let parsed: Transaction = raw.as_slice().zcash_deserialize_into().unwrap();
    let digests = spend::input_digests(
        fixture.policy().network,
        &parsed,
        &checked.previous_outputs,
        &fixture.policy().redeem_script,
        fixture.pool,
    )
    .unwrap();

    assert_eq!(digests, checked.digests);
    for (digest, input) in digests.iter().zip(&fixture.proposal.inputs) {
        assert_eq!(hex::encode(digest), input.sighash_all_digest);
    }
    // A sanity check that the outpoint is the one the UTXO list named.
    assert_eq!(
        fixture.proposal.inputs[0].txid,
        transaction::Hash([0x33u8; 32]).to_string(),
    );
}

/// The default fee is the fee the mempool asks for -- on the 2-input, 1-action shape the
/// treasury actually disburses with, not just the 1-input fixture.
///
/// This is the regression behind "Unpaid actions is higher than the limit". `spend propose` used
/// to price the transaction in the proposal, whose scriptSigs are empty, and advertise 10 000
/// zat; the node priced the signed transaction, which weighs four transparent logical actions
/// plus the shielded one, and dropped it. The two numbers here are computed by different code on
/// different transactions: `required_fee` from the policy and an input count, before any
/// signature exists, and `zip317` from the bytes of a fully signed transaction.
#[test]
fn the_default_fee_is_what_the_mempool_requires() {
    let fixture = v6_fixture();
    let policy = fixture.policy();
    let signatures = fixture.sign_with(&[0, 1]);
    let combined = spend::combine(&fixture.checked(), policy, &signatures).unwrap();

    // One input: the fixture, signed, on the wire.
    let one_input = combined.transaction.clone();
    assert_eq!(one_input.inputs().len(), 1);
    assert_eq!(
        spend::required_fee(policy, 1).unwrap(),
        u64::try_from(i64::from(zip317::conventional_fee(&one_input))).unwrap(),
        "the fee charged for one input must be the fee ZIP-317 charges the signed transaction",
    );

    // Two inputs: the same signed input twice, which is the shape of a real disbursement that
    // sweeps two matured treasury coinbase outputs. Only the sizes matter here.
    let mut two_inputs = one_input.clone();
    match &mut two_inputs {
        Transaction::V6 { inputs, .. } => inputs.push(inputs[0].clone()),
        other => panic!("the v6 fixture must build a v6 transaction, not {other:?}"),
    }
    assert_eq!(two_inputs.inputs().len(), 2);

    let two_input_fee = spend::required_fee(policy, 2).unwrap();
    assert_eq!(
        two_input_fee,
        u64::try_from(i64::from(zip317::conventional_fee(&two_inputs))).unwrap(),
    );
    // Four transparent logical actions (2 x 297 bytes, 150 bytes each) plus one shielded action.
    assert_eq!(two_input_fee, 5 * zip317::MARGINAL_FEE);

    // And that is exactly what the mempool's own check requires: it passes at the default fee
    // and fails one marginal fee below it.
    let unmined = UnminedTx::from(Arc::new(two_inputs));
    let size = unmined.size;
    for (fee, accepted) in [
        (two_input_fee, true),
        (two_input_fee - zip317::MARGINAL_FEE, false),
    ] {
        let fee = Amount::<NonNegative>::try_from(fee).unwrap();
        let result = zip317::mempool_checks(zip317::unpaid_actions(&unmined, fee), fee, size);
        assert_eq!(
            result.is_ok(),
            accepted,
            "{fee:?} zat should {} the mempool: {result:?}",
            if accepted { "pass" } else { "be refused by" },
        );
    }
}

/// A proposal built without an approved fee pays the conventional fee, and an approved fee below
/// it is refused rather than quietly raised.
#[test]
fn an_underpaying_approved_fee_is_refused() {
    let fixture = v6_fixture();
    let required = spend::required_fee(fixture.policy(), 1).unwrap();
    assert!(
        required < APPROVED_FEE,
        "the fixture must approve at least the conventional fee"
    );

    let defaulted = Fixture::build_with(Pool::V6Ironwood, None).expect("the default fee builds");
    assert_eq!(defaulted.proposal.fee, required);
    assert_eq!(defaulted.proposal.conventional_fee, required);
    spend::check(&defaulted.proposal, defaulted.policy()).expect("a default-fee proposal checks");

    let error = match Fixture::build_with(Pool::V6Ironwood, Some(required - 1)) {
        Err(error) => error,
        Ok(_) => panic!("a fee below the conventional fee must be refused"),
    };
    assert!(
        error
            .to_string()
            .contains("below the ZIP-317 conventional fee"),
        "unexpected error: {error}",
    );
}
