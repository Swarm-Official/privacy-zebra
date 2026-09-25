//! Consensus parameters for each Zcash network.
//!
//! This module contains the consensus parameters which are required for
//! parsing.
//!
//! Some consensus parameters change based on network upgrades. Each network
//! upgrade happens at a particular block height. Some parameters have a value
//! (or function) before the upgrade height, at the upgrade height, and after
//! the upgrade height. (For example, the value of the reserved field in the
//! block header during the Heartwood upgrade.)
//!
//! Typically, consensus parameters are accessed via a function that takes a
//! `Network` and `block::Height`.

pub mod checkpoint;
mod consensus_context;
pub mod constants;
mod genesis;
mod network;
mod network_upgrade;
mod transaction;

#[cfg(any(test, feature = "proptest-impl"))]
pub mod arbitrary;

#[cfg(test)]
pub(crate) use consensus_context::FIXTURE_NU6_3_DOMAIN;
pub use consensus_context::{ConsensusContext, DomainRegistry, SWARM_PRODUCTION_DOMAIN};
pub use genesis::*;
pub use network::{magic::Magic, subsidy, swarm_main, testnet, Network, NetworkKind};
pub use network_upgrade::*;
pub use transaction::*;

#[cfg(test)]
mod tests;
