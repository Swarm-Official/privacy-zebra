//! Offline 2-of-3 custody for the SWARM treasury.
//!
//! This crate turns the task T1 and T2 fixtures — real 2-of-3 P2SH signatures over a real
//! shielded-output transaction — into a tool that separate, offline owner devices can actually
//! use. It is *file based and offline*: nothing here opens a socket, talks to a node, or reads a
//! chain. The coordinator moves JSON files between devices by hand.
//!
//! # The custody policy
//!
//! A treasury collector output is a coinbase output, and the preserved consensus rules forbid a
//! transaction that spends a coinbase output from having **any** transparent output — not even
//! change back to the same 2-of-3 address. So the only disbursement policy this tool implements is
//! the one task T2 proved valid:
//!
//! > select **whole** mature collector UTXOs, and pay **all** of their value minus the approved fee
//! > to the intended shielded recipient, with **no change output of any kind**.
//!
//! [`spend::propose`] refuses to build anything else.
//!
//! # What lives where
//!
//! * [`script`] — HASH160, the multisig redeem script, `OP_PUSHDATA1`, scriptSig assembly.
//! * [`network`] — which networks this build can encode a P2SH address for.
//! * [`signer`] — one signer key per device, its public record, and its `age` backup.
//! * [`policy`] — the fund policy: threshold, ordered public keys, redeem script, address.
//! * [`utxo`] — the hand-exported UTXO list the coordinator feeds to a proposal.
//! * [`shielded`] — the real Orchard/Ironwood bundle, its proof and its wire encoding (the task T2
//!   construction, moved here so the tool and the T2 fixture share one implementation).
//! * [`spend`] — proposals, per-input digests, per-signer signatures and the combiner.
//!
//! # What this crate is not
//!
//! It is not a hardware wallet, it holds no chain state, and it validates neither anchors nor
//! nullifiers against a live chain: the transaction it produces is checked by the script
//! interpreter and the value-balance rule, and everything contextual is left to the node that
//! finally receives it. See `docs/swarm-treasury.md` for the full list of limits.

#![doc(html_root_url = "https://docs.rs/swarm-treasury")]
// This crate builds and signs transactions from JSON a human typed: every fallible step returns an
// error rather than panicking, so no `unwrap` is allowed outside the unit tests.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod error;
pub mod network;
pub mod policy;
pub mod script;
pub mod shielded;
pub mod signer;
pub mod spend;
pub mod utxo;

pub use error::{Error, Result};

/// The version of this tool, recorded in every file it writes.
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The tool name, recorded in every file it writes.
pub const TOOL_NAME: &str = "swarm-treasury";

/// Returns the current time in RFC 3339 form, for the `created` field of a written file.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
