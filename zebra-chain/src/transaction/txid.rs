//! Transaction ID computation. Contains code for generating the Transaction ID
//! from the transaction.

use super::{Hash, Transaction};
use crate::parameters::{ConsensusContext, DomainRegistry};
use crate::serialization::{sha256d, ZcashSerialize};

/// A Transaction ID builder. It computes the transaction ID by hashing
/// different parts of the transaction, depending on the transaction version.
/// For V5 transactions, it follows [ZIP-244] and [ZIP-225].
///
/// [ZIP-244]: https://zips.z.cash/zip-0244
/// [ZIP-225]: https://zips.z.cash/zip-0225
pub(super) struct TxIdBuilder<'a> {
    trans: &'a Transaction,
}

impl<'a> TxIdBuilder<'a> {
    /// Return a new TxIdBuilder for the given transaction.
    pub fn new(trans: &'a Transaction) -> Self {
        TxIdBuilder { trans }
    }

    /// Compute the Transaction ID for the previously specified transaction.
    ///
    /// For V5 and V6 the context is derived from the domain the transaction stores, looked up in
    /// the production `DomainRegistry::UPSTREAM` table. Returns `None` for a domain that table
    /// does not admit, exactly as the previous derived-network-upgrade lookup did.
    pub(super) fn txid(self) -> Option<Hash> {
        match self.trans {
            Transaction::V1 { .. }
            | Transaction::V2 { .. }
            | Transaction::V3 { .. }
            | Transaction::V4 { .. } => self.txid_v1_to_v4(),
            Transaction::V5 { .. } | Transaction::V6 { .. } => {
                let ctx = DomainRegistry::UPSTREAM
                    .context_for_branch(self.trans.consensus_branch_id()?)?;
                self.txid_v5_v6(&ctx)
            }
        }
    }

    /// Compute the Transaction ID for the previously specified transaction in `ctx`.
    ///
    /// Returns `None` if the transaction does not belong to `ctx`'s domain.
    pub(super) fn txid_in(self, ctx: &ConsensusContext) -> Option<Hash> {
        match self.trans {
            Transaction::V1 { .. }
            | Transaction::V2 { .. }
            | Transaction::V3 { .. }
            | Transaction::V4 { .. } => self.txid_v1_to_v4(),
            Transaction::V5 { .. } | Transaction::V6 { .. } => self.txid_v5_v6(ctx),
        }
    }

    /// Compute the Transaction ID for transactions V1 to V4.
    /// In these cases it's simply the hash of the serialized transaction.
    fn txid_v1_to_v4(self) -> Option<Hash> {
        let mut hash_writer = sha256d::Writer::default();
        self.trans.zcash_serialize(&mut hash_writer).ok()?;
        Some(Hash(hash_writer.finish()))
    }

    /// Compute the Transaction ID for a V5 or V6 transaction in the given consensus context.
    /// In this case it's the hash of a tree of hashes of specific parts of the
    /// transaction, as specified in ZIP-244 and ZIP-225.
    ///
    /// The domain in `ctx` is part of the ZIP-244 personalization, so two contexts that select the
    /// same rules but different domains produce different transaction IDs.
    fn txid_v5_v6(self, ctx: &ConsensusContext) -> Option<Hash> {
        // We compute v5 txid (from ZIP-244) using librustzcash.
        Some(Hash(
            *self.trans.to_librustzcash_in(ctx).ok()?.txid().as_ref(),
        ))
    }
}
