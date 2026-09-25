//! The hand-exported UTXO list.
//!
//! This tool never talks to a node. The coordinator exports the fund's unspent outputs from a node
//! *they* run — by hand, into JSON — and carries the file to the offline machine. The tool then
//! treats that file as a claim, not as truth: it checks every entry against the policy's locking
//! script, and the signature digests commit to the values and scripts it was given, so a coordinator
//! who misstates an amount produces signatures that do not verify against the real chain.

use hex::FromHex;
use serde::{Deserialize, Serialize};
use zebra_chain::{
    amount::{Amount, NonNegative},
    block::Height,
    transaction,
    transparent::{self, OutPoint},
};

use crate::{refuse, Result};

/// The schema tag of a UTXO list.
pub const UTXO_SCHEMA: &str = "swarm-treasury.utxos";
/// The version of the UTXO schema.
pub const UTXO_SCHEMA_VERSION: u32 = 1;

/// One unspent output offered for selection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UtxoEntry {
    /// The transaction id, in the byte order block explorers and `sendrawtransaction` print.
    pub txid: String,
    /// The index of the output in that transaction.
    pub vout: u32,
    /// The output's value in zatoshis.
    pub value: u64,
    /// The height of the block the output was created in.
    pub height: u32,
    /// Whether the output is a coinbase output. Treasury collector outputs are.
    pub is_coinbase: bool,
    /// The output's locking script, hex. Must be the policy's P2SH locking script.
    pub script: String,
}

/// A hand-exported list of unspent outputs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UtxoFile {
    /// The schema tag, always [`UTXO_SCHEMA`].
    pub schema: String,
    /// The schema version, always [`UTXO_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The network the outputs are on.
    pub network: String,
    /// The outputs, in the order they were exported.
    pub utxos: Vec<UtxoEntry>,
}

/// One selected output, parsed into the types the transaction builder needs.
#[derive(Clone, Debug)]
pub struct SelectedUtxo {
    /// The outpoint being spent.
    pub outpoint: OutPoint,
    /// The output being spent: value and locking script.
    pub output: transparent::Output,
    /// The height the output was created at.
    pub height: Height,
    /// Whether it is a coinbase output.
    pub is_coinbase: bool,
    /// The entry this was parsed from, for the human-readable summary.
    pub entry: UtxoEntry,
}

/// Parses and checks a UTXO list against a policy's locking script and network.
///
/// Every listed output is selected: this tool implements the whole-UTXO policy, so there is no
/// coin selection to get wrong and no remainder to place.
pub fn select_all(
    file: &UtxoFile,
    policy_lock_script: &[u8],
    policy_network: &str,
) -> Result<Vec<SelectedUtxo>> {
    if file.schema != UTXO_SCHEMA {
        return Err(refuse!(
            "expected a {UTXO_SCHEMA} file, found schema {:?}",
            file.schema
        ));
    }
    if file.schema_version != UTXO_SCHEMA_VERSION {
        return Err(refuse!(
            "this build reads {UTXO_SCHEMA} version {UTXO_SCHEMA_VERSION}, \
             the file is version {}",
            file.schema_version
        ));
    }
    if file.network != policy_network {
        return Err(refuse!(
            "the UTXO list is for network {:?}, the policy is for {policy_network:?}",
            file.network,
        ));
    }
    if file.utxos.is_empty() {
        return Err(refuse!("the UTXO list is empty; there is nothing to spend"));
    }

    let expected_script = hex::encode(policy_lock_script);
    let mut selected: Vec<SelectedUtxo> = Vec::with_capacity(file.utxos.len());

    for entry in &file.utxos {
        if entry.script.to_lowercase() != expected_script {
            return Err(refuse!(
                "the output {}:{} is not locked to the policy address: its script is {}, \
                 the policy's is {expected_script}",
                entry.txid,
                entry.vout,
                entry.script,
            ));
        }
        if entry.value == 0 {
            return Err(refuse!(
                "the output {}:{} has zero value",
                entry.txid,
                entry.vout
            ));
        }

        let hash = transaction::Hash::from_hex(&entry.txid)
            .map_err(|_| refuse!("{:?} is not a 32-byte transaction id", entry.txid))?;
        let outpoint = OutPoint {
            hash,
            index: entry.vout,
        };
        if selected.iter().any(|already| already.outpoint == outpoint) {
            return Err(refuse!(
                "the output {}:{} is listed twice",
                entry.txid,
                entry.vout
            ));
        }

        let value = Amount::<NonNegative>::try_from(
            i64::try_from(entry.value)
                .map_err(|_| refuse!("the value of {}:{} is too large", entry.txid, entry.vout))?,
        )
        .map_err(|error| {
            refuse!(
                "the value of {}:{} is not a valid amount: {error}",
                entry.txid,
                entry.vout
            )
        })?;

        selected.push(SelectedUtxo {
            outpoint,
            output: transparent::Output {
                value,
                lock_script: transparent::Script::new(policy_lock_script),
            },
            height: Height(entry.height),
            is_coinbase: entry.is_coinbase,
            entry: entry.clone(),
        });
    }

    Ok(selected)
}

/// The total value of a selection, in zatoshis.
pub fn total_value(selected: &[SelectedUtxo]) -> Result<u64> {
    let mut total: u64 = 0;
    for utxo in selected {
        total = total
            .checked_add(utxo.entry.value)
            .ok_or_else(|| refuse!("the selected outputs overflow a 64-bit total"))?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script;

    fn lock_script() -> Vec<u8> {
        script::p2sh_lock_script([0x11u8; 20])
    }

    fn entry(txid: &str, vout: u32) -> UtxoEntry {
        UtxoEntry {
            txid: txid.to_string(),
            vout,
            value: 312_500_000,
            height: 4_200_000,
            is_coinbase: true,
            script: hex::encode(lock_script()),
        }
    }

    fn file(utxos: Vec<UtxoEntry>) -> UtxoFile {
        UtxoFile {
            schema: UTXO_SCHEMA.to_string(),
            schema_version: UTXO_SCHEMA_VERSION,
            network: "testnet".to_string(),
            utxos,
        }
    }

    #[test]
    fn every_listed_output_is_selected() {
        let list = file(vec![entry(&"33".repeat(32), 0), entry(&"44".repeat(32), 1)]);
        let selected = select_all(&list, &lock_script(), "testnet").unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(total_value(&selected).unwrap(), 625_000_000);
    }

    #[test]
    fn a_foreign_locking_script_is_refused() {
        let mut list = file(vec![entry(&"33".repeat(32), 0)]);
        list.utxos[0].script = hex::encode(script::p2sh_lock_script([0x22u8; 20]));
        assert!(select_all(&list, &lock_script(), "testnet").is_err());
    }

    #[test]
    fn a_repeated_outpoint_is_refused() {
        let list = file(vec![entry(&"33".repeat(32), 0), entry(&"33".repeat(32), 0)]);
        assert!(select_all(&list, &lock_script(), "testnet").is_err());
    }

    #[test]
    fn a_wrong_network_or_empty_list_is_refused() {
        let list = file(vec![entry(&"33".repeat(32), 0)]);
        assert!(select_all(&list, &lock_script(), "swarmrehearsal").is_err());
        assert!(select_all(&file(vec![]), &lock_script(), "testnet").is_err());
    }
}
