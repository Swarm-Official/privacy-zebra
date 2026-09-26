//! Proposals, per-signer signatures and the combiner.
//!
//! A disbursement moves between devices as three kinds of file:
//!
//! 1. the coordinator writes a **proposal** — the whole unsigned transaction, plus the per-input
//!    `SIGHASH_ALL` digests and the amounts and scripts they commit to;
//! 2. each signing device reads it with `spend show`, checks the human-readable summary against
//!    what it expects, and writes a **signature file** with `spend sign`;
//! 3. the coordinator **combines** the signature files into the final raw transaction.
//!
//! Nothing in step 2 or 3 trusts step 1: `show`, `sign` and `combine` all recompute the digests
//! from the raw transaction bytes and refuse a proposal whose recorded digests disagree. A
//! coordinator who edits the recipient, an amount, the fee or the expiry after the digests were
//! written is caught before a signature is made; a coordinator who edits them after the signatures
//! are made produces a transaction the script interpreter rejects.

use std::{collections::HashMap, sync::Arc};

use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use zebra_chain::{
    amount::{Amount, NonNegative},
    block::Height,
    serialization::{ZcashDeserializeInto, ZcashSerialize},
    transaction::{self, zip317, HashType, LockTime, Transaction},
    transparent::{self, OutPoint},
};
use zebra_script::CachedFfiTransaction;

use crate::{
    network::TreasuryNetwork,
    policy::CheckedPolicy,
    refuse, script,
    shielded::{self, Pool, WireBundle, MEMO_LEN},
    signer::{self, SignerSecret},
    utxo::SelectedUtxo,
    Result, TOOL_NAME, TOOL_VERSION,
};

/// The schema tag of a proposal file.
pub const PROPOSAL_SCHEMA: &str = "swarm-treasury.proposal";
/// The schema tag of a signature file.
pub const SIGNATURE_SCHEMA: &str = "swarm-treasury.signature";
/// The schema tag of the record written beside the final raw transaction.
pub const FINAL_SCHEMA: &str = "swarm-treasury.final";
/// The version shared by the proposal, signature and final schemas.
pub const SPEND_SCHEMA_VERSION: u32 = 1;

// -- the ZIP-317 fee ---------------------------------------------------------

/// The largest DER-encoded ECDSA signature, plus the `SIGHASH_ALL` byte a scriptSig appends to
/// it.
///
/// A low-s DER signature over secp256k1 is at most 72 bytes; real ones are usually 70 or 71.
/// The fee is computed from the largest, so the size this tool charges for is never smaller than
/// the transaction it finally broadcasts.
pub const MAX_SIGNATURE_LEN: usize = 73;

/// The number of shielded actions in every bundle this tool builds.
///
/// One output note, no spends, `BundleType::UNPADDED`: [`shielded::build_bundle`] refuses a
/// bundle with any other action count, so this is a fact about the tool and not an estimate.
pub const SHIELDED_ACTIONS: u32 = 1;

/// The ZIP-317 conventional fee, in zatoshis, of the transaction this tool will finally
/// broadcast when it spends `input_count` outputs of `policy`.
///
/// # Why this is not the conventional fee of the proposal's own transaction
///
/// ZIP-317 charges *logical actions*, and a transparent input's logical actions are
/// `ceil(serialized size / 150)`, which depends on the size of its scriptSig. A proposal carries
/// no signatures yet, so the transaction inside it has empty scriptSigs and weighs one logical
/// action where the signed transaction weighs four. Pricing that shape produced a transaction
/// every node refused with "Unpaid actions is higher than the limit": a node counts the actions
/// of the transaction it is handed, which is the signed one.
///
/// So this prices the *signed* transaction before it exists: `threshold` signatures of the
/// largest size, plus the redeem script, in each input's scriptSig, plus the one shielded
/// action -- with ZIP-317's own constants, taken from `zebra-chain` rather than restated here.
pub fn required_fee(policy: &CheckedPolicy, input_count: usize) -> Result<u64> {
    if input_count == 0 {
        return Err(refuse!("there is nothing to spend"));
    }

    let signatures = vec![vec![0u8; MAX_SIGNATURE_LEN]; usize::from(policy.policy.threshold)];
    let script_sig = script::multisig_script_sig(&signatures, &policy.redeem_script)?;
    let signed_input = transparent::Input::PrevOut {
        outpoint: OutPoint {
            hash: transaction::Hash([0u8; 32]),
            index: 0,
        },
        unlock_script: transparent::Script::new(&script_sig),
        sequence: 0,
    };

    let tx_in_total_size = signed_input
        .zcash_serialized_size()
        .checked_mul(input_count)
        .ok_or_else(|| refuse!("too many inputs to weigh"))?;

    // There is never a transparent output, so ZIP-317's `tx_out_logical_actions` is zero.
    let transparent_actions =
        u32::try_from(tx_in_total_size.div_ceil(zip317::P2PKH_STANDARD_INPUT_SIZE))
            .map_err(|_| refuse!("too many inputs to weigh"))?;
    let logical_actions = transparent_actions
        .checked_add(SHIELDED_ACTIONS)
        .ok_or_else(|| refuse!("too many inputs to weigh"))?;

    let conventional_actions = std::cmp::max(zip317::GRACE_ACTIONS, logical_actions);
    zip317::MARGINAL_FEE
        .checked_mul(u64::from(conventional_actions))
        .ok_or_else(|| refuse!("the conventional fee overflows"))
}

// -- the proposal ------------------------------------------------------------

/// One input of a proposal: what is being spent, and the digest that must be signed for it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposalInput {
    /// The transaction id of the output being spent, in display order.
    pub txid: String,
    /// The index of the output being spent.
    pub vout: u32,
    /// The value of the output being spent, in zatoshis.
    pub value: u64,
    /// The height the output was created at.
    pub height: u32,
    /// Whether the output is a coinbase output.
    pub is_coinbase: bool,
    /// The `SIGHASH_ALL` digest each signer signs for this input, hex.
    pub sighash_all_digest: String,
}

/// A disbursement proposal: an unsigned transaction and everything needed to check and sign it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    /// The schema tag, always [`PROPOSAL_SCHEMA`].
    pub schema: String,
    /// The schema version, always [`SPEND_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The tool that wrote this file.
    pub tool: String,
    /// The version of the tool that wrote this file.
    pub tool_version: String,
    /// The network the policy is for.
    pub network: String,
    /// The network upgrade the transaction is built under: `nu6_3` on the mainnet path.
    pub network_upgrade: String,
    /// The fund the policy governs.
    pub fund: String,
    /// The policy fingerprint this proposal is bound to.
    pub policy_fingerprint: String,
    /// The policy's P2SH address, so a signer can read where the money is coming from.
    pub policy_address: String,
    /// The policy's redeem script, hex: the scriptCode every input digest is taken over.
    pub redeem_script: String,
    /// The recipient, as it was given on the command line.
    pub recipient: String,
    /// The raw 43-byte Orchard/Ironwood receiver the note is actually paid to, hex.
    pub recipient_raw_receiver: String,
    /// The memo carried with the note, as text if it is text.
    pub memo: String,
    /// The transaction's expiry height.
    pub expiry_height: u32,
    /// The approved fee, in zatoshis.
    pub fee: u64,
    /// The ZIP-317 conventional fee for this transaction, in zatoshis.
    pub conventional_fee: u64,
    /// The total value of the selected inputs, in zatoshis.
    pub total_in: u64,
    /// The value of the shielded note: `total_in - fee`.
    pub amount_out: u64,
    /// The selected inputs, in transaction input order.
    pub inputs: Vec<ProposalInput>,
    /// The unsigned transaction, hex.
    pub transaction: String,
    /// `SHA-256` over the raw transaction and the inputs it spends, hex.
    ///
    /// Every signature file records it, so a signature cannot be moved to another proposal.
    pub proposal_hash: String,
    /// When the proposal was written, RFC 3339.
    pub created: String,
}

/// A proposal that has been checked against its own raw transaction.
#[derive(Clone, Debug)]
pub struct CheckedProposal {
    /// The proposal as written.
    pub proposal: Proposal,
    /// The unsigned transaction, parsed from the recorded bytes.
    pub transaction: Transaction,
    /// The outputs being spent, in input order.
    pub previous_outputs: Vec<transparent::Output>,
    /// The digests recomputed from the raw transaction, in input order.
    pub digests: Vec<[u8; 32]>,
    /// The pool and network upgrade the transaction is built under.
    pub pool: Pool,
    /// The redeem script the digests are taken over.
    pub redeem_script: Vec<u8>,
}

/// What `spend propose` needs.
//
// Not `Debug`: `orchard::Address` is a recipient, and a request struct that prints itself is a
// request struct that ends up in a log.
pub struct ProposalRequest<'a> {
    /// The checked policy the inputs are locked to.
    pub policy: &'a CheckedPolicy,
    /// Every listed UTXO: the whole-UTXO policy selects all of them.
    pub selected: &'a [SelectedUtxo],
    /// The recipient, as given on the command line, for the record.
    pub recipient_text: &'a str,
    /// The recipient's Orchard/Ironwood receiver.
    pub recipient: orchard::Address,
    /// The memo text.
    pub memo_text: &'a str,
    /// The approved fee, in zatoshis, or `None` to pay the ZIP-317 conventional fee of the
    /// signed transaction -- [`required_fee`]. An approved fee below that is refused.
    pub fee: Option<u64>,
    /// The transaction's expiry height.
    pub expiry_height: u32,
    /// The pool to pay into.
    pub pool: Pool,
    /// The seed for the bundle's randomness. Real runs draw it from the OS CSPRNG.
    pub rng_seed: [u8; 32],
}

/// Builds a proposal.
///
/// The policy this implements, and the only one it implements:
///
/// * **every** listed UTXO is spent, whole;
/// * there is **no** transparent output of any kind, so no change and no remainder;
/// * the recipient's note is `total_in - fee`;
/// * the fee must be at least the ZIP-317 conventional fee for the transaction that results.
pub fn propose(request: ProposalRequest<'_>) -> Result<Proposal> {
    let policy = request.policy;
    let selected = request.selected;
    if selected.is_empty() {
        return Err(refuse!("there is nothing to spend"));
    }

    // The fee the mempool will require of the *signed* transaction. It depends only on the
    // transaction's shape -- how many inputs, how large their scriptSigs will be, one shielded
    // action -- and not on any amount, so it is settled before the bundle is built.
    let conventional_fee = required_fee(policy, selected.len())?;
    let fee = match request.fee {
        None => conventional_fee,
        Some(approved) if approved < conventional_fee => {
            return Err(refuse!(
                "the approved fee of {approved} zat is below the ZIP-317 conventional fee of \
                 {conventional_fee} zat for a {}-input disbursement from this policy; a node \
                 will not relay it. Leave the fee out to pay {conventional_fee} zat.",
                selected.len(),
            ))
        }
        Some(approved) => approved,
    };

    let total_in = crate::utxo::total_value(selected)?;
    if fee >= total_in {
        return Err(refuse!(
            "the fee ({fee} zat) is not less than the selected value ({total_in} zat)",
        ));
    }
    let amount_out = total_in - fee;

    let memo = shielded::memo_from_text(request.memo_text)?;
    let expiry_height = Height(request.expiry_height);
    let outpoints: Vec<OutPoint> = selected.iter().map(|utxo| utxo.outpoint).collect();
    let previous_outputs: Vec<transparent::Output> =
        selected.iter().map(|utxo| utxo.output.clone()).collect();

    // Step 1-3: build the bundle, take the sighash of the transaction that carries it with a
    // placeholder authorization, then prove and sign the bundle over that sighash.
    let empty_script_sigs = vec![Vec::new(); outpoints.len()];
    let (wire, placeholder_sighash) = shielded::build_bundle(
        request.pool,
        request.recipient,
        amount_out,
        memo,
        request.rng_seed,
        |placeholder| {
            let transaction = assemble_transaction(
                policy.network,
                request.pool,
                &outpoints,
                &empty_script_sigs,
                expiry_height,
                placeholder,
            )?;
            shielded_sighash(
                policy.network,
                &transaction,
                request.pool,
                &previous_outputs,
            )
        },
    )?;

    let transaction = assemble_transaction(
        policy.network,
        request.pool,
        &outpoints,
        &empty_script_sigs,
        expiry_height,
        &wire,
    )?;

    // Step 4: the ZIP-244 signature digest excludes the proof and the signatures, so filling them
    // in must not have moved the sighash. Everything below depends on that.
    let authorized_sighash = shielded_sighash(
        policy.network,
        &transaction,
        request.pool,
        &previous_outputs,
    )?;
    if authorized_sighash != placeholder_sighash {
        return Err(refuse!(
            "the shielded signature digest changed when the proof and signatures were filled in; \
             this build cannot produce a valid transaction"
        ));
    }

    // The policy checks, on the transaction that was actually built.
    if !transaction.outputs().is_empty() {
        return Err(refuse!(
            "this tool never builds a transparent output: a coinbase treasury spend with any \
             transparent output — including change back to the same 2-of-3 address — is invalid"
        ));
    }

    // The unsigned transaction's own conventional fee is a lower bound on the signed one's:
    // scriptSigs only grow. If it ever came out higher, the shape priced above was wrong, and
    // the proposal would advertise a fee the mempool refuses.
    let unsigned_fee = i64::from(zip317::conventional_fee(&transaction));
    if unsigned_fee > i64::try_from(conventional_fee).unwrap_or(i64::MAX) {
        return Err(refuse!(
            "the unsigned transaction already costs {unsigned_fee} zat, more than the \
             {conventional_fee} zat computed for the signed one; this build cannot price itself"
        ));
    }

    let digests = input_digests(
        policy.network,
        &transaction,
        &previous_outputs,
        &policy.redeem_script,
        request.pool,
    )?;

    let raw = transaction
        .zcash_serialize_to_vec()
        .map_err(|error| refuse!("could not serialize the transaction: {error}"))?;

    let inputs: Vec<ProposalInput> = selected
        .iter()
        .zip(&digests)
        .map(|(utxo, digest)| ProposalInput {
            txid: utxo.entry.txid.clone(),
            vout: utxo.entry.vout,
            value: utxo.entry.value,
            height: utxo.entry.height,
            is_coinbase: utxo.entry.is_coinbase,
            sighash_all_digest: hex::encode(digest),
        })
        .collect();

    let proposal = Proposal {
        schema: PROPOSAL_SCHEMA.to_string(),
        schema_version: SPEND_SCHEMA_VERSION,
        tool: TOOL_NAME.to_string(),
        tool_version: TOOL_VERSION.to_string(),
        network: policy.policy.network.clone(),
        network_upgrade: request.pool.name().to_string(),
        fund: policy.policy.fund.clone(),
        policy_fingerprint: policy.policy.policy_fingerprint.clone(),
        policy_address: policy.policy.address.clone(),
        redeem_script: policy.policy.redeem_script.clone(),
        recipient: request.recipient_text.to_string(),
        recipient_raw_receiver: hex::encode(request.recipient.to_raw_address_bytes()),
        memo: request.memo_text.to_string(),
        expiry_height: request.expiry_height,
        fee,
        conventional_fee,
        total_in,
        amount_out,
        inputs,
        transaction: hex::encode(&raw),
        proposal_hash: String::new(),
        created: crate::now_rfc3339(),
    };

    Ok(Proposal {
        proposal_hash: proposal_hash(&proposal),
        ..proposal
    })
}

/// The proposal hash: SHA-256 over everything a signer is shown and everything it signs.
///
/// It covers the raw transaction, the outputs being spent, and *also* the fields a signer reads on
/// screen but cannot re-derive from the transaction — the recipient and the memo. The note is
/// encrypted, so no offline tool can prove that a transaction's bundle pays the address a proposal
/// claims it pays; what this hash does guarantee is that the claim a signer approved is the claim
/// the signature was made against, and that changing it afterwards invalidates every signature.
///
/// The digests are deliberately *not* in it: they are derived from the transaction and the
/// previous outputs, and are recomputed everywhere rather than trusted.
pub fn proposal_hash(proposal: &Proposal) -> String {
    let mut binding = format!(
        "{PROPOSAL_SCHEMA}/{SPEND_SCHEMA_VERSION}\n\
         policy={}\nnetwork={}\nnu={}\nfund={}\n\
         to={}\nreceiver={}\nmemo={}\n\
         expiry={}\nfee={}\nin_total={}\nout={}\n\
         tx={}\n",
        proposal.policy_fingerprint,
        proposal.network,
        proposal.network_upgrade,
        proposal.fund,
        proposal.recipient,
        proposal.recipient_raw_receiver,
        hex::encode(proposal.memo.as_bytes()),
        proposal.expiry_height,
        proposal.fee,
        proposal.total_in,
        proposal.amount_out,
        proposal.transaction,
    );
    for input in &proposal.inputs {
        binding.push_str(&format!(
            "in={}:{}:{}:{}:{}\n",
            input.txid, input.vout, input.value, input.height, input.is_coinbase,
        ));
    }
    hex::encode(script::sha256(binding.as_bytes()))
}

/// Re-derives everything in a proposal from its raw transaction bytes.
///
/// This is the check `show`, `sign` and `combine` all run before they do anything else. It is the
/// reason a signer does not have to trust the coordinator's arithmetic: the amounts, the recipient
/// commitment, the expiry and the digests all come out of the transaction the proposal carries.
pub fn check(proposal: &Proposal, policy: &CheckedPolicy) -> Result<CheckedProposal> {
    if proposal.schema != PROPOSAL_SCHEMA {
        return Err(refuse!(
            "expected a {PROPOSAL_SCHEMA} file, found schema {:?}",
            proposal.schema
        ));
    }
    if proposal.schema_version != SPEND_SCHEMA_VERSION {
        return Err(refuse!(
            "this build reads {PROPOSAL_SCHEMA} version {SPEND_SCHEMA_VERSION}, \
             the file is version {}",
            proposal.schema_version
        ));
    }
    if proposal.policy_fingerprint != policy.policy.policy_fingerprint {
        return Err(refuse!(
            "the proposal is for policy {}, this policy is {}",
            proposal.policy_fingerprint,
            policy.policy.policy_fingerprint,
        ));
    }
    if proposal.redeem_script != policy.policy.redeem_script {
        return Err(refuse!(
            "the proposal's redeem script is not the policy's redeem script"
        ));
    }
    if proposal.network != policy.policy.network {
        return Err(refuse!(
            "the proposal is for network {:?}, the policy is for {:?}",
            proposal.network,
            policy.policy.network,
        ));
    }
    let recomputed_hash = proposal_hash(proposal);
    if recomputed_hash != proposal.proposal_hash {
        return Err(refuse!(
            "the proposal hash does not match the proposal; recomputed {recomputed_hash}, \
             the file records {}",
            proposal.proposal_hash,
        ));
    }

    let pool = Pool::parse(&proposal.network_upgrade)?;
    let raw = hex::decode(&proposal.transaction)
        .map_err(|_| refuse!("the proposal's transaction is not hexadecimal"))?;
    let transaction: Transaction = raw
        .as_slice()
        .zcash_deserialize_into()
        .map_err(|error| refuse!("the proposal's transaction does not parse: {error}"))?;

    if transaction.inputs().len() != proposal.inputs.len() {
        return Err(refuse!(
            "the proposal lists {} inputs but its transaction has {}",
            proposal.inputs.len(),
            transaction.inputs().len(),
        ));
    }
    if !transaction.outputs().is_empty() {
        return Err(refuse!(
            "the proposal's transaction has {} transparent output(s); a treasury coinbase spend \
             must have none at all, and this tool never signs one that does",
            transaction.outputs().len(),
        ));
    }
    if transaction.expiry_height() != Some(Height(proposal.expiry_height)) {
        return Err(refuse!(
            "the proposal records expiry height {} but its transaction expires at {:?}",
            proposal.expiry_height,
            transaction.expiry_height(),
        ));
    }

    // The previous outputs, rebuilt from the proposal's own claims, checked against the policy's
    // locking script and against the outpoints the transaction actually spends.
    let mut previous_outputs = Vec::with_capacity(proposal.inputs.len());
    let mut total_in: u64 = 0;
    for (index, input) in proposal.inputs.iter().enumerate() {
        let hash = <transaction::Hash as hex::FromHex>::from_hex(&input.txid)
            .map_err(|_| refuse!("input {index}'s transaction id is not 32 bytes of hex"))?;
        let expected = OutPoint {
            hash,
            index: input.vout,
        };
        match &transaction.inputs()[index] {
            transparent::Input::PrevOut { outpoint, .. } if *outpoint == expected => {}
            transparent::Input::PrevOut { outpoint, .. } => {
                return Err(refuse!(
                    "input {index} of the transaction spends {outpoint:?}, but the proposal lists \
                     {}:{}",
                    input.txid,
                    input.vout,
                ))
            }
            transparent::Input::Coinbase { .. } => {
                return Err(refuse!("input {index} is a coinbase input"))
            }
        }
        total_in = total_in
            .checked_add(input.value)
            .ok_or_else(|| refuse!("the proposal's input values overflow"))?;
        previous_outputs.push(transparent::Output {
            value: zatoshis_to_amount(input.value)?,
            lock_script: transparent::Script::new(&policy.lock_script),
        });
    }

    if total_in != proposal.total_in {
        return Err(refuse!(
            "the proposal records {} zat in, its inputs total {total_in} zat",
            proposal.total_in,
        ));
    }
    if proposal.fee.checked_add(proposal.amount_out) != Some(total_in) {
        return Err(refuse!(
            "the proposal does not balance: {} zat in, {} zat out, {} zat fee",
            proposal.total_in,
            proposal.amount_out,
            proposal.fee,
        ));
    }

    // The value balance the consensus rule computes, from the transaction itself.
    let miner_fee = miner_fee_of(&transaction, &previous_outputs)?;
    if u64::try_from(i64::from(miner_fee)).ok() != Some(proposal.fee) {
        return Err(refuse!(
            "the proposal records a fee of {} zat, but its transaction pays {} zat",
            proposal.fee,
            i64::from(miner_fee),
        ));
    }
    // The fee the signed transaction will owe, not the fee the unsigned one appears to owe:
    // a signing device must refuse a proposal the mempool would drop after it is signed.
    let conventional_fee = required_fee(policy, proposal.inputs.len())?;
    if proposal.conventional_fee != conventional_fee {
        return Err(refuse!(
            "the proposal records a ZIP-317 conventional fee of {} zat, this shape owes \
             {conventional_fee} zat",
            proposal.conventional_fee,
        ));
    }
    let conventional_fee = zatoshis_to_amount(conventional_fee)?;
    if miner_fee < conventional_fee {
        return Err(refuse!(
            "the transaction's fee of {} zat is below the ZIP-317 conventional fee of {} zat",
            i64::from(miner_fee),
            i64::from(conventional_fee),
        ));
    }

    let digests = input_digests(
        policy.network,
        &transaction,
        &previous_outputs,
        &policy.redeem_script,
        pool,
    )?;
    for (index, (digest, input)) in digests.iter().zip(&proposal.inputs).enumerate() {
        if hex::encode(digest) != input.sighash_all_digest {
            return Err(refuse!(
                "the digest recorded for input {index} is not the digest of this transaction; \
                 recomputed {}, the proposal records {}",
                hex::encode(digest),
                input.sighash_all_digest,
            ));
        }
    }

    Ok(CheckedProposal {
        proposal: proposal.clone(),
        transaction,
        previous_outputs,
        digests,
        pool,
        redeem_script: policy.redeem_script.clone(),
    })
}

/// The human-readable summary a signer reads on the offline device before signing.
///
/// Every line is derived from the checked proposal, so a line that is wrong means the proposal is
/// wrong, not that the summary was written badly.
pub fn summary(checked: &CheckedProposal, policy: &CheckedPolicy) -> Vec<String> {
    let proposal = &checked.proposal;
    let mut lines = vec![
        format!("fund              {}", proposal.fund),
        format!("network           {}", proposal.network),
        format!("network upgrade   {}", proposal.network_upgrade),
        format!(
            "from              {} ({}-of-{})",
            proposal.policy_address,
            policy.policy.threshold,
            policy.policy.signers.len(),
        ),
        format!("policy            {}", proposal.policy_fingerprint),
        format!("recipient         {}", proposal.recipient),
        format!("recipient receiver {}", proposal.recipient_raw_receiver),
        format!("memo              {:?}", proposal.memo),
        format!("total in          {} zat", proposal.total_in),
        format!(
            "fee               {} zat (ZIP-317 conventional {} zat)",
            proposal.fee, proposal.conventional_fee,
        ),
        format!(
            "amount out        {} zat (shielded, no change)",
            proposal.amount_out
        ),
        format!("expiry height     {}", proposal.expiry_height),
        format!("transparent outs  {}", checked.transaction.outputs().len()),
        format!("inputs            {}", proposal.inputs.len()),
    ];
    for (index, input) in proposal.inputs.iter().enumerate() {
        lines.push(format!(
            "  [{index}] {}:{}  {} zat  height {}  coinbase {}",
            input.txid, input.vout, input.value, input.height, input.is_coinbase,
        ));
        lines.push(format!("       digest {}", input.sighash_all_digest));
    }
    lines.push(format!("proposal hash     {}", proposal.proposal_hash));
    lines
}

// -- signing -----------------------------------------------------------------

/// One input's signature.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputSignature {
    /// The index of the input this signs.
    pub input: usize,
    /// The digest that was signed, hex.
    pub digest: String,
    /// The DER signature with the `SIGHASH_ALL` byte appended, hex.
    pub der: String,
}

/// One signer's contribution to a proposal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureFile {
    /// The schema tag, always [`SIGNATURE_SCHEMA`].
    pub schema: String,
    /// The schema version, always [`SPEND_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The tool that wrote this file.
    pub tool: String,
    /// The version of the tool that wrote this file.
    pub tool_version: String,
    /// The signer's label.
    pub label: String,
    /// The signer's compressed public key, hex.
    pub public_key: String,
    /// The signer's fingerprint, hex.
    pub fingerprint: String,
    /// The policy the signature is made under.
    pub policy_fingerprint: String,
    /// The proposal the signature is made over.
    pub proposal_hash: String,
    /// One signature per input, in input order.
    pub signatures: Vec<InputSignature>,
    /// When the signature was made, RFC 3339.
    pub created: String,
}

/// Signs every input of a checked proposal with one signer's key.
///
/// The digests come from [`check`], which recomputed them from the raw transaction — the
/// coordinator's recorded digests are never what gets signed.
pub fn sign(
    checked: &CheckedProposal,
    policy: &CheckedPolicy,
    secret: &SignerSecret,
) -> Result<SignatureFile> {
    let (secret_key, public_key) = secret.key_pair()?;
    if policy.index_of(&public_key).is_none() {
        return Err(refuse!(
            "signer {} is not one of this policy's keys; this backup does not belong to the \
             {} fund",
            secret.label,
            policy.policy.fund,
        ));
    }

    let signatures = checked
        .digests
        .iter()
        .enumerate()
        .map(|(index, digest)| InputSignature {
            input: index,
            digest: hex::encode(digest),
            der: hex::encode(der_signature(&secret_key, digest)),
        })
        .collect();

    Ok(SignatureFile {
        schema: SIGNATURE_SCHEMA.to_string(),
        schema_version: SPEND_SCHEMA_VERSION,
        tool: TOOL_NAME.to_string(),
        tool_version: TOOL_VERSION.to_string(),
        label: secret.label.clone(),
        public_key: secret.public_key.clone(),
        fingerprint: secret.fingerprint.clone(),
        policy_fingerprint: policy.policy.policy_fingerprint.clone(),
        proposal_hash: checked.proposal.proposal_hash.clone(),
        signatures,
        created: crate::now_rfc3339(),
    })
}

/// Signs one digest and appends the canonical `SIGHASH_ALL` byte.
fn der_signature(secret_key: &SecretKey, digest: &[u8; 32]) -> Vec<u8> {
    let secp = Secp256k1::signing_only();
    let signature = secp.sign_ecdsa(&Message::from_digest(*digest), secret_key);
    let mut der = signature.serialize_der().to_vec();
    der.push(script::SIGHASH_ALL_BYTE);
    der
}

// -- combining ---------------------------------------------------------------

/// What `spend combine` produced.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalRecord {
    /// The schema tag, always [`FINAL_SCHEMA`].
    pub schema: String,
    /// The schema version, always [`SPEND_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The tool that wrote this file.
    pub tool: String,
    /// The version of the tool that wrote this file.
    pub tool_version: String,
    /// The transaction id, in display order — what a block explorer will show.
    pub txid: String,
    /// The network the transaction is for.
    pub network: String,
    /// The network upgrade it was built under.
    pub network_upgrade: String,
    /// The fund it spends from.
    pub fund: String,
    /// The policy fingerprint.
    pub policy_fingerprint: String,
    /// The proposal it came from.
    pub proposal_hash: String,
    /// The labels of the signers whose signatures were used, in policy key order.
    pub signers: Vec<String>,
    /// The fee, in zatoshis.
    pub fee: u64,
    /// The shielded amount paid, in zatoshis.
    pub amount_out: u64,
    /// The size of the final transaction, in bytes.
    pub transaction_bytes: usize,
    /// When it was combined, RFC 3339.
    pub created: String,
}

/// The output of a successful combine.
#[derive(Clone, Debug)]
pub struct Combined {
    /// The final transaction, ready for `sendrawtransaction`.
    pub raw_hex: String,
    /// The record written beside it.
    pub record: FinalRecord,
    /// The final transaction.
    pub transaction: Transaction,
}

/// Verifies the signature files, assembles the scriptSigs and checks the result.
///
/// Refusals, in the order they are checked:
///
/// * a signature file for another proposal or another policy;
/// * a public key that is not one of the policy's keys;
/// * the same signer twice;
/// * fewer (or more) signatures than the threshold;
/// * a signature that does not verify against the digest this tool recomputed;
/// * a final transaction the script interpreter rejects, or whose value balance is not the fee.
///
/// Signatures are ordered by the policy's key order, which is what `OP_CHECKMULTISIG` requires;
/// the order the files were given in does not matter.
pub fn combine(
    checked: &CheckedProposal,
    policy: &CheckedPolicy,
    signature_files: &[SignatureFile],
) -> Result<Combined> {
    let mut contributions: Vec<(usize, &SignatureFile)> = Vec::new();

    for file in signature_files {
        if file.schema != SIGNATURE_SCHEMA {
            return Err(refuse!(
                "expected a {SIGNATURE_SCHEMA} file, found schema {:?}",
                file.schema
            ));
        }
        if file.schema_version != SPEND_SCHEMA_VERSION {
            return Err(refuse!(
                "this build reads {SIGNATURE_SCHEMA} version {SPEND_SCHEMA_VERSION}, \
                 signer {}'s file is version {}",
                file.label,
                file.schema_version,
            ));
        }
        if file.proposal_hash != checked.proposal.proposal_hash {
            return Err(refuse!(
                "signer {}'s signature is for proposal {}, this proposal is {}",
                file.label,
                file.proposal_hash,
                checked.proposal.proposal_hash,
            ));
        }
        if file.policy_fingerprint != policy.policy.policy_fingerprint {
            return Err(refuse!(
                "signer {}'s signature is for policy {}, this policy is {}",
                file.label,
                file.policy_fingerprint,
                policy.policy.policy_fingerprint,
            ));
        }

        let public_key = script::parse_public_key(&file.public_key)?;
        if signer::fingerprint(&public_key) != file.fingerprint {
            return Err(refuse!(
                "signer {}'s fingerprint does not match its public key",
                file.label
            ));
        }
        let index = policy.index_of(&public_key).ok_or_else(|| {
            refuse!(
                "signer {} is not one of this policy's keys; a foreign signature is never \
                 combined in",
                file.label,
            )
        })?;
        if let Some((_, existing)) = contributions.iter().find(|(seen, _)| *seen == index) {
            return Err(refuse!(
                "signer {} and signer {} are the same policy key; a threshold is not met by \
                 signing twice with one device",
                existing.label,
                file.label,
            ));
        }
        if file.signatures.len() != checked.digests.len() {
            return Err(refuse!(
                "signer {} signed {} input(s), the proposal has {}",
                file.label,
                file.signatures.len(),
                checked.digests.len(),
            ));
        }
        contributions.push((index, file));
    }

    if contributions.len() != policy.threshold() {
        return Err(refuse!(
            "this policy needs exactly {} signatures to spend, {} were given",
            policy.threshold(),
            contributions.len(),
        ));
    }

    // Canonical order: the policy's key order, not the order the files were handed over.
    contributions.sort_by_key(|(index, _)| *index);

    let secp = Secp256k1::verification_only();
    let mut script_sigs = Vec::with_capacity(checked.digests.len());
    for (input_index, digest) in checked.digests.iter().enumerate() {
        let mut ordered = Vec::with_capacity(contributions.len());
        for (key_index, file) in &contributions {
            let entry = file
                .signatures
                .iter()
                .find(|signature| signature.input == input_index)
                .ok_or_else(|| refuse!("signer {} did not sign input {input_index}", file.label))?;
            if entry.digest != hex::encode(digest) {
                return Err(refuse!(
                    "signer {} signed a different digest for input {input_index} than this \
                     transaction has; the proposal was changed after it was signed",
                    file.label,
                ));
            }

            let der = hex::decode(&entry.der).map_err(|_| {
                refuse!(
                    "signer {}'s signature for input {input_index} is not hex",
                    file.label
                )
            })?;
            let (body, hash_type) = der.split_at(der.len().saturating_sub(1));
            if hash_type != [script::SIGHASH_ALL_BYTE] {
                return Err(refuse!(
                    "signer {}'s signature for input {input_index} is not SIGHASH_ALL",
                    file.label,
                ));
            }
            let signature = Signature::from_der(body).map_err(|error| {
                refuse!(
                    "signer {}'s signature for input {input_index} is not valid DER: {error}",
                    file.label,
                )
            })?;
            let public_key = PublicKey::from_slice(&policy.public_keys[*key_index])
                .map_err(|error| refuse!("the policy holds an unusable public key: {error}"))?;
            secp.verify_ecdsa(&Message::from_digest(*digest), &signature, &public_key)
                .map_err(|error| {
                    refuse!(
                        "signer {}'s signature for input {input_index} does not verify: {error}",
                        file.label,
                    )
                })?;

            ordered.push(der);
        }
        script_sigs.push(script::multisig_script_sig(
            &ordered,
            &policy.redeem_script,
        )?);
    }

    let outpoints: Vec<OutPoint> = checked
        .transaction
        .inputs()
        .iter()
        .map(|input| match input {
            transparent::Input::PrevOut { outpoint, .. } => Ok(*outpoint),
            transparent::Input::Coinbase { .. } => Err(refuse!("a coinbase input cannot be spent")),
        })
        .collect::<Result<Vec<_>>>()?;

    let final_transaction =
        rebuild_with_script_sigs(&checked.transaction, &outpoints, &script_sigs)?;

    // The maintained script interpreter, on every input.
    let previous_outputs = Arc::new(checked.previous_outputs.clone());
    let cached = CachedFfiTransaction::new_in(
        Arc::new(final_transaction.clone()),
        previous_outputs,
        &policy.network.consensus_context(checked.pool)?,
    )
    .map_err(|error| refuse!("the final transaction is not supported by its branch: {error}"))?;
    for index in 0..final_transaction.inputs().len() {
        cached.is_valid(index).map_err(|error| {
            refuse!(
                "the script interpreter rejected input {index} of the final transaction: {error}"
            )
        })?;
    }

    // The value-balance rule: what a node will compute as the miner fee.
    let miner_fee = miner_fee_of(&final_transaction, &checked.previous_outputs)?;
    if u64::try_from(i64::from(miner_fee)).ok() != Some(checked.proposal.fee) {
        return Err(refuse!(
            "the final transaction pays {} zat in fees, the proposal approved {} zat",
            i64::from(miner_fee),
            checked.proposal.fee,
        ));
    }

    let raw = final_transaction
        .zcash_serialize_to_vec()
        .map_err(|error| refuse!("could not serialize the final transaction: {error}"))?;

    let record = FinalRecord {
        schema: FINAL_SCHEMA.to_string(),
        schema_version: SPEND_SCHEMA_VERSION,
        tool: TOOL_NAME.to_string(),
        tool_version: TOOL_VERSION.to_string(),
        txid: final_transaction.hash().to_string(),
        network: checked.proposal.network.clone(),
        network_upgrade: checked.proposal.network_upgrade.clone(),
        fund: checked.proposal.fund.clone(),
        policy_fingerprint: policy.policy.policy_fingerprint.clone(),
        proposal_hash: checked.proposal.proposal_hash.clone(),
        signers: contributions
            .iter()
            .map(|(_, file)| file.label.clone())
            .collect(),
        fee: checked.proposal.fee,
        amount_out: checked.proposal.amount_out,
        transaction_bytes: raw.len(),
        created: crate::now_rfc3339(),
    };

    Ok(Combined {
        raw_hex: hex::encode(&raw),
        record,
        transaction: final_transaction,
    })
}

// -- shared transaction plumbing ---------------------------------------------

/// Builds the transaction for a pool, given outpoints, scriptSigs and a bundle.
///
/// The `outputs` field is always empty: this is the whole-UTXO, no-change policy, and there is no
/// code path here that adds a transparent output.
pub fn assemble_transaction(
    network: TreasuryNetwork,
    pool: Pool,
    outpoints: &[OutPoint],
    script_sigs: &[Vec<u8>],
    expiry_height: Height,
    wire: &WireBundle,
) -> Result<Transaction> {
    if outpoints.len() != script_sigs.len() {
        return Err(refuse!(
            "the transaction has {} inputs but {} scriptSigs",
            outpoints.len(),
            script_sigs.len(),
        ));
    }

    let inputs = outpoints
        .iter()
        .zip(script_sigs)
        .map(|(outpoint, script_sig)| transparent::Input::PrevOut {
            outpoint: *outpoint,
            unlock_script: transparent::Script::new(script_sig),
            sequence: u32::MAX,
        })
        .collect();

    // The domain comes from the *network*, not from the network upgrade. SwarmMain runs the same
    // NU6.3 rules as upstream under its own domain `0x53574d31`, so deriving it from the upgrade
    // would build a SwarmMain spend that a SwarmMain node rejects and a Zcash node might accept.
    let consensus_branch_id = network.consensus_context(pool)?.branch();

    Ok(match pool {
        Pool::V5Orchard => Transaction::V5 {
            consensus_branch_id,
            lock_time: LockTime::unlocked(),
            expiry_height,
            inputs,
            outputs: Vec::new(),
            sapling_shielded_data: None,
            orchard_shielded_data: Some(wire.to_orchard_shielded_data()?),
        },
        Pool::V6Ironwood => Transaction::V6 {
            consensus_branch_id,
            lock_time: LockTime::unlocked(),
            expiry_height,
            inputs,
            outputs: Vec::new(),
            sapling_shielded_data: None,
            orchard_shielded_data: None,
            ironwood_shielded_data: Some(wire.to_ironwood_shielded_data()?),
        },
    })
}

/// Returns a copy of `transaction` with new scriptSigs.
fn rebuild_with_script_sigs(
    transaction: &Transaction,
    outpoints: &[OutPoint],
    script_sigs: &[Vec<u8>],
) -> Result<Transaction> {
    let inputs: Vec<transparent::Input> = outpoints
        .iter()
        .zip(script_sigs)
        .map(|(outpoint, script_sig)| transparent::Input::PrevOut {
            outpoint: *outpoint,
            unlock_script: transparent::Script::new(script_sig),
            sequence: u32::MAX,
        })
        .collect();

    Ok(match transaction.clone() {
        Transaction::V5 {
            consensus_branch_id,
            lock_time,
            expiry_height,
            outputs,
            sapling_shielded_data,
            orchard_shielded_data,
            ..
        } => Transaction::V5 {
            consensus_branch_id,
            lock_time,
            expiry_height,
            inputs,
            outputs,
            sapling_shielded_data,
            orchard_shielded_data,
        },
        Transaction::V6 {
            consensus_branch_id,
            lock_time,
            expiry_height,
            outputs,
            sapling_shielded_data,
            orchard_shielded_data,
            ironwood_shielded_data,
            ..
        } => Transaction::V6 {
            consensus_branch_id,
            lock_time,
            expiry_height,
            inputs,
            outputs,
            sapling_shielded_data,
            orchard_shielded_data,
            ironwood_shielded_data,
        },
        _ => return Err(refuse!("this tool only builds v5 and v6 transactions")),
    })
}

/// The ZIP-244 signature digest the shielded bundle is bound to.
fn shielded_sighash(
    network: TreasuryNetwork,
    transaction: &Transaction,
    pool: Pool,
    previous_outputs: &[transparent::Output],
) -> Result<[u8; 32]> {
    let ctx = network.consensus_context(pool)?;
    let sighasher = transaction
        .sighasher_in(&ctx, Arc::new(previous_outputs.to_vec()))
        .map_err(|error| refuse!("could not build the sighasher: {error}"))?;
    Ok(*sighasher.sighash(HashType::ALL, None).as_ref())
}

/// The `SIGHASH_ALL` digest for every input, taken over the redeem script as scriptCode.
///
/// The ZIP-244 transparent signature digest does not commit to the scriptSigs, so these are the
/// same before and after signing — which is why a proposal can carry them.
pub fn input_digests(
    network: TreasuryNetwork,
    transaction: &Transaction,
    previous_outputs: &[transparent::Output],
    redeem_script: &[u8],
    pool: Pool,
) -> Result<Vec<[u8; 32]>> {
    let ctx = network.consensus_context(pool)?;
    let sighasher = transaction
        .sighasher_in(&ctx, Arc::new(previous_outputs.to_vec()))
        .map_err(|error| refuse!("could not build the sighasher: {error}"))?;

    Ok((0..transaction.inputs().len())
        .map(|index| {
            *sighasher
                .sighash(HashType::ALL, Some((index, redeem_script.to_vec())))
                .as_ref()
        })
        .collect())
}

/// The miner fee a node computes from the transaction's value balance.
fn miner_fee_of(
    transaction: &Transaction,
    previous_outputs: &[transparent::Output],
) -> Result<Amount<NonNegative>> {
    let mut spent: HashMap<OutPoint, transparent::Utxo> = HashMap::new();
    for (input, output) in transaction.inputs().iter().zip(previous_outputs) {
        if let transparent::Input::PrevOut { outpoint, .. } = input {
            spent.insert(
                *outpoint,
                // The height and coinbase flag do not affect the value balance; the maturity rule
                // is a chain rule, checked by the node that receives this transaction.
                transparent::Utxo::new(output.clone(), Height(0), false),
            );
        }
    }

    transaction
        .value_balance(&spent)
        .map_err(|error| refuse!("the transaction's value balance is not computable: {error}"))?
        .remaining_transaction_value()
        .map_err(|error| {
            refuse!("the transaction spends more than it takes in, or does not balance: {error}")
        })
}

/// Converts zatoshis into a checked non-negative [`Amount`].
fn zatoshis_to_amount(zatoshis: u64) -> Result<Amount<NonNegative>> {
    let signed =
        i64::try_from(zatoshis).map_err(|_| refuse!("{zatoshis} zat does not fit in an amount"))?;
    Amount::try_from(signed)
        .map_err(|error| refuse!("{zatoshis} zat is not a valid amount: {error}"))
}

/// The number of bytes a memo occupies, exposed so callers can size their own checks.
pub const fn memo_len() -> usize {
    MEMO_LEN
}
