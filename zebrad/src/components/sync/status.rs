//! Syncer chain tip status, based on recent block locator responses from peers.

use tokio::sync::watch;
use zebra_chain::chain_sync_status::ChainSyncStatus;

use super::RecentSyncLengths;

#[cfg(any(test, feature = "proptest-impl"))]
pub mod mock;
#[cfg(test)]
mod tests;

/// A helper type to determine if the synchronizer has likely reached the chain tip.
///
/// This type can be used as a handle, so cloning it is cheap.
#[derive(Clone, Debug)]
pub struct SyncStatus {
    latest_sync_length: watch::Receiver<Vec<usize>>,
    is_regtest: bool,
    is_alone: bool,
}

impl SyncStatus {
    /// The threshold that determines if the synchronization is at the chain
    /// tip.
    ///
    /// This is based on the fact that sync lengths are around 2-20 blocks long
    /// once Zebra reaches the tip.
    const MIN_DIST_FROM_TIP: usize = 20;

    /// Create an instance of [`SyncStatus`] for a network configuration.
    ///
    /// The status is determined based on the latest counts of synchronized blocks, observed
    /// through `latest_sync_length`. On Regtest, and on a node the configuration leaves with no
    /// peer to sync from, [`ChainSyncStatus::is_close_to_tip`] always returns `true`.
    pub fn new_for_config(config: &zebra_network::Config) -> (Self, RecentSyncLengths) {
        let (recent_sync_lengths, latest_sync_length) = RecentSyncLengths::new();
        let status = SyncStatus {
            latest_sync_length,
            is_regtest: config.network.is_regtest(),
            is_alone: config.has_no_peer_sources(),
        };

        (status, recent_sync_lengths)
    }

    /// Create an instance of [`SyncStatus`].
    ///
    /// The status is determined based on the latest counts of synchronized blocks, observed
    /// through `latest_sync_length`.
    pub fn new() -> (Self, RecentSyncLengths) {
        let (recent_sync_lengths, latest_sync_length) = RecentSyncLengths::new();
        let status = SyncStatus {
            latest_sync_length,
            is_regtest: false,
            is_alone: false,
        };

        (status, recent_sync_lengths)
    }

    /// Wait until the synchronization is likely close to the tip.
    ///
    /// Returns an error if communication with the synchronizer is lost.
    pub async fn wait_until_close_to_tip(&mut self) -> Result<(), watch::error::RecvError> {
        while !self.is_close_to_tip() {
            self.latest_sync_length.changed().await?;
        }

        Ok(())
    }
}

impl ChainSyncStatus for SyncStatus {
    /// Check if the synchronization is likely close to the chain tip.
    fn is_close_to_tip(&self) -> bool {
        if self.is_regtest {
            return true;
        }

        // A node with no seed list and no peer cache has nobody to be behind. `sync_lengths` stays
        // empty forever in that state, because the syncer never completes an attempt, so the
        // average below can never be computed and this function would answer `false` for the life
        // of the process. That answer stops the mempool activating and makes `getblocktemplate`
        // refuse a template, so the first node on a brand-new chain could never mine its first
        // block -- on Regtest that is already special-cased above, and every other private chain
        // Zebra has run so far was a Testnet, where `check_synced_to_tip` skips the question
        // entirely. `Network::SwarmMain` is neither, which is where it surfaced.
        if self.is_alone {
            return true;
        }

        let sync_lengths = self.latest_sync_length.borrow();

        // Return early if sync_lengths is empty.
        if sync_lengths.is_empty() {
            return false;
        }

        // Compute the sum of the `sync_lengths`.
        // The sum is computed by saturating addition in order to avoid overflowing.
        let sum = sync_lengths
            .iter()
            .fold(0usize, |sum, rhs| sum.saturating_add(*rhs));

        // Compute the average sync length.
        // This value effectively represents a simple moving average.
        let avg = sum / sync_lengths.len();

        // The synchronization process is close to the chain tip once the
        // average sync length falls below the threshold.
        avg < Self::MIN_DIST_FROM_TIP
    }
}
