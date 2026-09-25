//! Offline coinbase maturity and transparent-change policy fixtures for the SWARM mainnet treasury
//! plan (task T1).
//!
//! These tests are entirely offline: no node, no network, no database, no keys. They exercise the
//! real preserved consensus rules through the real functions:
//!
//! * [`zebra_state::check::transparent_coinbase_spend`], the rule as the state service applies it;
//! * [`zebra_chain::transaction::Transaction::coinbase_spend_restriction`], which derives the
//!   restriction from the actual transaction and the actual network.
//!
//! Why this file exists separately from `zebra-script/tests/swarm_treasury_multisig.rs`: the script
//! fixture proves that a 2-of-3 P2SH input can be signed, combined and verified, including a
//! transparent change output back to the same 2-of-3 address. That is *not* sufficient for a
//! treasury coinbase spend. A mature treasury coinbase output cannot be spent by a transaction that
//! has any transparent output at all, so the "recipient plus 2-of-3 change" shape the script
//! fixture demonstrates is invalid for coinbase inputs under the preserved rules. These tests pin
//! that difference down.
//!
//! The custom-testnet fixture here sets `should_allow_unshielded_coinbase_spends` to `false`
//! explicitly. The default Regtest constructor defaults it to `true`, which would make a
//! production-incompatible transparent-change path look valid. Nothing here relies on Regtest
//! defaults.
//!
//! Nothing in this file constructs or validates a shielded proof, and the selection fixture is an
//! accounting check only, not a real spend.

#![allow(clippy::unwrap_used)]

use zebra_chain::{
    amount::{Amount, NonNegative},
    block::Height,
    parameters::{
        testnet::{Parameters, RegtestParameters},
        Network,
    },
    transaction::{self, LockTime, Transaction},
    transparent::{self, CoinbaseSpendRestriction, Utxo, MIN_TRANSPARENT_COINBASE_MATURITY},
};
use zebra_state::{check::transparent_coinbase_spend, ValidateContextError};

/// The `swarm-keytool` published 2-of-3 script hash for the public test scalars 1, 2 and 3.
///
/// Only the hash is needed here, so this file stays independent of the signing
/// fixture and needs no new cross-crate dependency. The signing fixture in
/// `zebra-script` derives this same hash from the public test scalars and
/// asserts that it matches.
const TREASURY_SCRIPT_HASH: &str = "15fc0754e73eb85d1cbce08786fadb7320ecb8dc";

/// `OP_HASH160`.
const OP_HASH160: u8 = 0xa9;
/// `OP_EQUAL`.
const OP_EQUAL: u8 = 0x87;

/// The height at which the fixture treasury coinbase output is created.
const CREATED_HEIGHT: Height = Height(1_000);

/// The value of the fixture treasury coinbase output, in zatoshis.
const COLLECTOR_VALUE: i64 = 3_1250_0000;

// -- fixtures ----------------------------------------------------------------

/// The P2SH locking script for the 2-of-3 treasury policy.
fn treasury_lock_script() -> transparent::Script {
    let script_hash = hex::decode(TREASURY_SCRIPT_HASH).expect("a valid hex script hash");
    let mut script = vec![OP_HASH160, 20];
    script.extend_from_slice(&script_hash);
    script.push(OP_EQUAL);
    transparent::Script::new(&script)
}

/// A recipient P2SH locking script that is not the treasury policy's own script.
fn recipient_lock_script() -> transparent::Script {
    let mut script = vec![OP_HASH160, 20];
    script.extend_from_slice(&[0x11u8; 20]);
    script.push(OP_EQUAL);
    transparent::Script::new(&script)
}

/// Builds a non-negative [`Amount`] from a zatoshi count.
fn amount(zatoshis: i64) -> Amount<NonNegative> {
    Amount::try_from(zatoshis).expect("test amounts are valid")
}

/// The outpoint of the fixture treasury collector output.
fn collector_outpoint() -> transparent::OutPoint {
    transparent::OutPoint {
        hash: transaction::Hash([0x44u8; 32]),
        index: 0,
    }
}

/// The fixture treasury UTXO.
///
/// With `from_coinbase` set, this stands for a mature miner coinbase output or a transparent
/// funding-stream output: the rule applies to both.
fn collector_utxo(from_coinbase: bool) -> Utxo {
    Utxo::new(
        transparent::Output {
            value: amount(COLLECTOR_VALUE),
            lock_script: treasury_lock_script(),
        },
        CREATED_HEIGHT,
        from_coinbase,
    )
}

/// A transaction spending the collector output, with the given transparent outputs.
///
/// An empty `outputs` list stands for a disbursement whose entire value goes to shielded
/// recipients. This fixture builds no shielded bundle and makes no claim that such a transaction is
/// fully valid; it exists only so that `coinbase_spend_restriction` sees a transaction with no
/// transparent outputs, which is the condition the consensus rule actually tests.
fn spending_transaction(outputs: Vec<transparent::Output>) -> Transaction {
    Transaction::V5 {
        consensus_branch_id: zebra_chain::parameters::NetworkUpgrade::Nu5
            .branch_id()
            .expect("NU5 has a branch ID"),
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        inputs: vec![transparent::Input::PrevOut {
            outpoint: collector_outpoint(),
            unlock_script: transparent::Script::new(&[]),
            sequence: u32::MAX,
        }],
        outputs,
        sapling_shielded_data: None,
        orchard_shielded_data: None,
    }
}

/// The custom Testnet used for custody rehearsals.
///
/// `should_allow_unshielded_coinbase_spends` is set to `false` **explicitly**, so a rehearsal can
/// never pass because of a permissive default.
fn custody_rehearsal_network() -> Network {
    Parameters::build()
        .with_unshielded_coinbase_spends(false)
        .to_network()
        .expect("the custody rehearsal Testnet parameters are valid")
}

/// The first height at which the fixture coinbase output is mature.
fn first_mature_height() -> Height {
    Height(CREATED_HEIGHT.0 + MIN_TRANSPARENT_COINBASE_MATURITY)
}

// -- the network fixture itself ----------------------------------------------

/// The custody rehearsal network keeps the unshielded-coinbase-spend exception disabled, and the
/// default Regtest constructor does not.
#[test]
fn custody_rehearsal_network_disables_the_unshielded_exception() {
    let _init_guard = zebra_test::init();

    let network = custody_rehearsal_network();
    assert!(
        !network.should_allow_unshielded_coinbase_spends(),
        "the custody rehearsal network must never allow transparent outputs on a coinbase spend",
    );

    // The default custom-Testnet builder already defaults this to false; the fixture sets it
    // explicitly anyway, so a change to the default cannot silently weaken these tests.
    let default_testnet = Parameters::build()
        .to_network()
        .expect("the default custom Testnet parameters are valid");
    assert!(!default_testnet.should_allow_unshielded_coinbase_spends());

    // Regtest defaults the exception to true. A rehearsal run on default Regtest would make a
    // transparent-change path that production rejects look valid, which is exactly the trap this
    // fixture avoids.
    let regtest = Network::new_regtest(RegtestParameters::default());
    assert!(
        regtest.should_allow_unshielded_coinbase_spends(),
        "default Regtest is permissive here, so it must never be used for custody rehearsals",
    );

    // The same transaction gets opposite restrictions on the two networks.
    let with_change = spending_transaction(vec![transparent::Output {
        value: amount(COLLECTOR_VALUE - 1_0000),
        lock_script: treasury_lock_script(),
    }]);
    let spend_height = first_mature_height();

    assert_eq!(
        with_change.coinbase_spend_restriction(&network, spend_height),
        CoinbaseSpendRestriction::DisallowCoinbaseSpend,
    );
    assert_eq!(
        with_change.coinbase_spend_restriction(&regtest, spend_height),
        CoinbaseSpendRestriction::CheckCoinbaseMaturity { spend_height },
    );
}

// -- maturity ----------------------------------------------------------------

/// A coinbase output created at `H` is immature at `H + 99` and mature at `H + 100`, when the
/// spending transaction has no transparent outputs.
#[test]
fn coinbase_maturity_boundary_is_one_hundred_blocks() {
    let _init_guard = zebra_test::init();

    let network = custody_rehearsal_network();
    let utxo = collector_utxo(true);
    let outpoint = collector_outpoint();

    // A disbursement with no transparent outputs at all: whole selected value, minus the approved
    // fee, to shielded recipients. No shielded bundle is built or claimed valid here.
    let no_transparent_outputs = spending_transaction(Vec::new());

    let too_early = Height(CREATED_HEIGHT.0 + MIN_TRANSPARENT_COINBASE_MATURITY - 1);
    let restriction = no_transparent_outputs.coinbase_spend_restriction(&network, too_early);
    assert_eq!(
        restriction,
        CoinbaseSpendRestriction::CheckCoinbaseMaturity {
            spend_height: too_early
        },
        "a transaction with no transparent outputs is only subject to the maturity rule",
    );

    let error = transparent_coinbase_spend(outpoint, restriction, &utxo)
        .expect_err("H + 99 is one block too early");
    match error {
        ValidateContextError::ImmatureTransparentCoinbaseSpend {
            spend_height,
            min_spend_height,
            created_height,
            ..
        } => {
            assert_eq!(spend_height, too_early);
            assert_eq!(min_spend_height, first_mature_height());
            assert_eq!(created_height, CREATED_HEIGHT);
        }
        other => panic!("expected an immature coinbase spend error, got {other:?}"),
    }

    // One block later the maturity rule is satisfied.
    let mature = first_mature_height();
    let restriction = no_transparent_outputs.coinbase_spend_restriction(&network, mature);
    assert_eq!(
        restriction,
        CoinbaseSpendRestriction::CheckCoinbaseMaturity {
            spend_height: mature
        },
    );
    assert_eq!(
        transparent_coinbase_spend(outpoint, restriction, &utxo),
        Ok(()),
        "at H + 100 a coinbase spend with no transparent outputs passes the maturity rule",
    );
}

/// Any transparent output makes a coinbase spend invalid, no matter how mature the output is, and
/// a 2-of-3 change output is no exception.
#[test]
fn mature_coinbase_spend_with_any_transparent_output_is_rejected() {
    let _init_guard = zebra_test::init();

    let network = custody_rehearsal_network();
    let utxo = collector_utxo(true);
    let outpoint = collector_outpoint();

    let fee = 1_0000i64;
    let shapes: Vec<(&str, Vec<transparent::Output>)> = vec![
        (
            "a single transparent recipient output",
            vec![transparent::Output {
                value: amount(COLLECTOR_VALUE - fee),
                lock_script: recipient_lock_script(),
            }],
        ),
        (
            "a 2-of-3 treasury change output",
            vec![transparent::Output {
                value: amount(COLLECTOR_VALUE - fee),
                lock_script: treasury_lock_script(),
            }],
        ),
        (
            "a recipient output plus 2-of-3 change, exactly the shape the script fixture proves",
            vec![
                transparent::Output {
                    value: amount(1_0000_0000),
                    lock_script: recipient_lock_script(),
                },
                transparent::Output {
                    value: amount(COLLECTOR_VALUE - 1_0000_0000 - fee),
                    lock_script: treasury_lock_script(),
                },
            ],
        ),
    ];

    // Well past maturity, to make it unambiguous that this is not a maturity failure.
    for spend_height in [first_mature_height(), Height(CREATED_HEIGHT.0 + 100_000)] {
        for (name, outputs) in &shapes {
            let transaction = spending_transaction(outputs.clone());
            let restriction = transaction.coinbase_spend_restriction(&network, spend_height);

            assert_eq!(
                restriction,
                CoinbaseSpendRestriction::DisallowCoinbaseSpend,
                "{name} must disallow the coinbase spend outright",
            );

            let error = transparent_coinbase_spend(outpoint, restriction, &utxo)
                .expect_err("a coinbase spend with transparent outputs is always invalid");
            assert!(
                matches!(
                    error,
                    ValidateContextError::UnshieldedTransparentCoinbaseSpend { .. }
                ),
                "{name} at {spend_height:?} must fail as unshielded, got {error:?}",
            );
        }
    }
}

/// A non-coinbase UTXO is not subject to either rule.
///
/// This is why the `zebra-script` fixture, which spends a synthetic non-coinbase input to a
/// recipient plus 2-of-3 change and verifies, is insufficient on its own: flipping exactly one
/// flag, `from_coinbase`, turns the same shape from accepted into rejected.
#[test]
fn noncoinbase_utxo_is_unrestricted_which_is_why_the_script_fixture_is_insufficient() {
    let _init_guard = zebra_test::init();

    let network = custody_rehearsal_network();
    let outpoint = collector_outpoint();

    let recipient_and_change = vec![
        transparent::Output {
            value: amount(1_0000_0000),
            lock_script: recipient_lock_script(),
        },
        transparent::Output {
            value: amount(COLLECTOR_VALUE - 1_0000_0000 - 1_0000),
            lock_script: treasury_lock_script(),
        },
    ];
    let transaction = spending_transaction(recipient_and_change);

    // Immediately, in the same block it was created, with transparent change: accepted.
    let restriction = transaction.coinbase_spend_restriction(&network, CREATED_HEIGHT);
    assert_eq!(restriction, CoinbaseSpendRestriction::DisallowCoinbaseSpend);
    assert_eq!(
        transparent_coinbase_spend(outpoint, restriction, &collector_utxo(false)),
        Ok(()),
        "a non-coinbase UTXO is exempt from the coinbase rules entirely",
    );

    // The identical transaction and height against the identical output, with only `from_coinbase`
    // flipped, is rejected.
    assert!(
        matches!(
            transparent_coinbase_spend(outpoint, restriction, &collector_utxo(true)),
            Err(ValidateContextError::UnshieldedTransparentCoinbaseSpend { .. })
        ),
        "the only difference between the accepted and rejected cases is `from_coinbase`",
    );
}

// -- selection and payout accounting -----------------------------------------

/// One mature collector output available for selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Collector {
    /// The output being selected.
    outpoint: transparent::OutPoint,
    /// Its value, in zatoshis.
    value: i64,
    /// The height at which it was created.
    created_height: Height,
}

/// A planned disbursement: whole selected outputs in, one payment out, no change.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Disbursement {
    /// The outpoints selected, in selection order.
    selected: Vec<transparent::OutPoint>,
    /// The total value of the selected outputs, in zatoshis.
    selected_value: i64,
    /// The approved fee, in zatoshis.
    fee: i64,
    /// The single payment amount, in zatoshis.
    payment: i64,
}

/// A way a requested disbursement can fail the no-change policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectionError {
    /// No outputs were selected.
    NothingSelected,
    /// An outpoint that is not among the available collectors was selected.
    UnknownOutpoint,
    /// The same outpoint was selected twice.
    DuplicateSelection,
    /// The selected value does not cover the approved fee.
    FeeExceedsSelectedValue,
    /// The selected outputs are not mature at the spend height.
    ImmatureSelection,
    /// The request would leave a remainder, and no approved change policy exists.
    ///
    /// Under the proposed policy the remainder must not silently become a change output, because a
    /// coinbase spend cannot carry one at all, and because placing it anywhere other than the same
    /// 2-of-3 script would quietly move value out of threshold control.
    RemainderRequiresApprovedChangePolicy {
        /// The value that would be left over, in zatoshis.
        remainder: i64,
    },
}

/// Plans a whole-output disbursement: the entire selected value, minus the approved fee, becomes
/// one payment. No change output is ever produced.
fn plan_whole_utxo_disbursement(
    available: &[Collector],
    selection: &[transparent::OutPoint],
    fee: i64,
    spend_height: Height,
) -> Result<Disbursement, SelectionError> {
    if selection.is_empty() {
        return Err(SelectionError::NothingSelected);
    }

    let mut selected_value = 0i64;
    for (index, outpoint) in selection.iter().enumerate() {
        if selection[index + 1..].contains(outpoint) {
            return Err(SelectionError::DuplicateSelection);
        }

        let collector = available
            .iter()
            .find(|collector| collector.outpoint == *outpoint)
            .ok_or(SelectionError::UnknownOutpoint)?;

        let min_spend_height =
            Height(collector.created_height.0 + MIN_TRANSPARENT_COINBASE_MATURITY);
        if spend_height < min_spend_height {
            return Err(SelectionError::ImmatureSelection);
        }

        selected_value += collector.value;
    }

    if fee > selected_value {
        return Err(SelectionError::FeeExceedsSelectedValue);
    }

    Ok(Disbursement {
        selected: selection.to_vec(),
        selected_value,
        fee,
        payment: selected_value - fee,
    })
}

/// Plans a disbursement for an exact requested payment amount.
///
/// This succeeds only when some selection of whole outputs happens to equal the requested amount
/// plus the fee. Otherwise it refuses, and surfaces the remainder as a custody decision rather than
/// silently creating a change output.
fn plan_exact_payment(
    available: &[Collector],
    selection: &[transparent::OutPoint],
    requested_payment: i64,
    fee: i64,
    spend_height: Height,
) -> Result<Disbursement, SelectionError> {
    let plan = plan_whole_utxo_disbursement(available, selection, fee, spend_height)?;

    if plan.payment != requested_payment {
        return Err(SelectionError::RemainderRequiresApprovedChangePolicy {
            remainder: plan.payment - requested_payment,
        });
    }

    Ok(plan)
}

/// The fixture set of available mature collectors.
fn available_collectors() -> Vec<Collector> {
    (0u32..4)
        .map(|index| Collector {
            outpoint: transparent::OutPoint {
                hash: transaction::Hash([0x44u8; 32]),
                index,
            },
            value: COLLECTOR_VALUE,
            created_height: CREATED_HEIGHT,
        })
        .collect()
}

/// Whole selected outputs minus the approved fee equal exactly one payment amount, with no
/// residual and no change output, and the unselected collectors are untouched.
#[test]
fn whole_utxo_disbursement_leaves_no_change_and_no_residual() {
    let _init_guard = zebra_test::init();

    let available = available_collectors();
    let before = available.clone();
    let fee = 1_0000i64;
    let spend_height = first_mature_height();

    let selection: Vec<_> = available[..2]
        .iter()
        .map(|collector| collector.outpoint)
        .collect();

    let plan = plan_whole_utxo_disbursement(&available, &selection, fee, spend_height)
        .expect("two mature collectors are selectable");

    assert_eq!(plan.selected_value, COLLECTOR_VALUE * 2);
    assert_eq!(
        plan.payment + plan.fee,
        plan.selected_value,
        "selected value minus the approved fee must equal the payment exactly, with no residual",
    );

    // The plan produces exactly one payment and no change output of any kind.
    assert_eq!(plan.selected.len(), 2);
    assert!(plan.payment > 0);

    // The unselected collectors are unchanged and remain in their original 2-of-3 P2SH.
    assert_eq!(available, before, "planning must not mutate the UTXO set");
    let unselected: Vec<_> = available
        .iter()
        .filter(|collector| !plan.selected.contains(&collector.outpoint))
        .collect();
    assert_eq!(unselected.len(), 2);
    for collector in unselected {
        assert_eq!(collector.value, COLLECTOR_VALUE);
        assert_eq!(collector.created_height, CREATED_HEIGHT);
    }
}

/// An exact requested amount that does not fall on a whole-output boundary is refused rather than
/// silently given a change output.
#[test]
fn exact_payment_leaving_a_remainder_is_refused() {
    let _init_guard = zebra_test::init();

    let available = available_collectors();
    let fee = 1_0000i64;
    let spend_height = first_mature_height();
    let selection: Vec<_> = available[..2]
        .iter()
        .map(|collector| collector.outpoint)
        .collect();

    // The amount that does fall on the boundary is accepted.
    let exact = COLLECTOR_VALUE * 2 - fee;
    let plan = plan_exact_payment(&available, &selection, exact, fee, spend_height)
        .expect("a whole-output amount is payable");
    assert_eq!(plan.payment, exact);

    // One zatoshi less is not, and the refusal names the remainder instead of hiding it.
    assert_eq!(
        plan_exact_payment(&available, &selection, exact - 1, fee, spend_height),
        Err(SelectionError::RemainderRequiresApprovedChangePolicy { remainder: 1 }),
    );

    // A round number an operator would plausibly ask for is refused the same way.
    let requested = 1_0000_0000i64;
    assert_eq!(
        plan_exact_payment(&available, &selection, requested, fee, spend_height),
        Err(SelectionError::RemainderRequiresApprovedChangePolicy {
            remainder: exact - requested
        }),
    );
}

/// The selection fixture rejects malformed and immature requests.
#[test]
fn selection_rejects_malformed_and_immature_requests() {
    let _init_guard = zebra_test::init();

    let available = available_collectors();
    let fee = 1_0000i64;
    let spend_height = first_mature_height();
    let outpoint = available[0].outpoint;

    assert_eq!(
        plan_whole_utxo_disbursement(&available, &[], fee, spend_height),
        Err(SelectionError::NothingSelected),
    );

    assert_eq!(
        plan_whole_utxo_disbursement(&available, &[outpoint, outpoint], fee, spend_height),
        Err(SelectionError::DuplicateSelection),
    );

    let unknown = transparent::OutPoint {
        hash: transaction::Hash([0x99u8; 32]),
        index: 0,
    };
    assert_eq!(
        plan_whole_utxo_disbursement(&available, &[unknown], fee, spend_height),
        Err(SelectionError::UnknownOutpoint),
    );

    assert_eq!(
        plan_whole_utxo_disbursement(
            &available,
            &[outpoint],
            fee,
            Height(first_mature_height().0 - 1),
        ),
        Err(SelectionError::ImmatureSelection),
        "the accounting fixture must use the same 100-block maturity boundary as consensus",
    );

    assert_eq!(
        plan_whole_utxo_disbursement(&available, &[outpoint], COLLECTOR_VALUE + 1, spend_height),
        Err(SelectionError::FeeExceedsSelectedValue),
    );
}
