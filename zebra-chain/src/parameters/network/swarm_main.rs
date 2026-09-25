//! The SWARM production network profile (`SwarmMainnet`).
//!
//! This module defines the SWARM production network as an *explicit* profile. It is not upstream
//! Zcash Mainnet, and it is not a test network. Nothing here is derived from, defaulted to, or
//! cast into another network: every value is either a reviewed constant in this file or a field
//! the operator must supply, and a profile that is missing a required field cannot be built.
//!
//! # Why a separate variant
//!
//! SWARM runs the NU6.3 (Ironwood) consensus *rules* from height 1, but under its own ZIP-200
//! transaction *domain* (`0x53574d31`, see [`DomainRegistry::SWARM_PRODUCTION`]). A transaction is
//! therefore not replayable in either direction between SWARM and Zcash. Expressing that as "a
//! configured Testnet" would be wrong twice over: it would hand SWARM the testnet minimum
//! difficulty exception and the testnet address prefixes, and it would report SWARM to every
//! `is_a_test_network()` caller as a throwaway chain.
//!
//! # What must come from configuration
//!
//! Two things have no reviewed value yet and are therefore *required* inputs, not defaults:
//!
//! - the genesis block hash, which is generated at the P6 ceremony from a public unpredictable
//!   input. [`SwarmMainParametersBuilder::finish`] fails with
//!   [`SwarmMainParametersError::GenesisHashUnresolved`] until one is supplied. There is
//!   deliberately no placeholder constant: a copied testnet or upstream genesis would make a
//!   misconfigured node silently follow the wrong chain.
//! - the three funding stream recipient addresses, whose keys are generated at the same ceremony.
//!   The *numerators* and the *height range* are reviewed economics and are constants here; only
//!   the destinations are operator input, and each one must be a SWARM production P2SH address.
//!
//! # What is fixed
//!
//! Everything else in [`SwarmMainParameters`] is a constant in this module, taken from
//! `Mainnet identity proposal 2026-09-25.md`. No checkpoint list, no peer seed list and no
//! founders' reward list is defined: SWARM has no history to checkpoint, and copying upstream
//! seeds would point a SWARM node at Zcash nodes.

use std::{collections::HashMap, sync::Arc};

use thiserror::Error;

use crate::{
    amount::{Amount, NonNegative},
    block::{self, Height, HeightDiff},
    parameters::{
        network::{
            magic::Magic,
            subsidy::{FundingStreamReceiver, FundingStreamRecipient, FundingStreams},
        },
        NetworkKind,
    },
    transparent,
    work::difficulty::{ExpandedDifficulty, U256},
};

/// The `Display` name of the SWARM production network.
pub const NETWORK_NAME: &str = "SwarmMainnet";

/// The chain label used by the indexer, the wallet and the RPC `chain` field.
///
/// This is the identifier those components compare against before they open a database, so it
/// must differ from the SWARM testnet's `swarm-testnet` and from upstream's `main`/`test`.
pub const CHAIN_LABEL: &str = "swarm-mainnet";

/// The P2P network magic: the ASCII bytes `SWMN`.
///
/// Distinct from Zcash Mainnet (`24 e9 27 64`), Zcash Testnet (`fa 1a f9 bf`) and the SWARM
/// testnet's `SWRM` (`53 57 52 4d`), so a node on one network drops a peer from another during
/// the version handshake rather than part way through a sync.
pub const MAGIC: Magic = Magic([0x53, 0x57, 0x4d, 0x4e]);

/// The default P2P listener port.
pub const DEFAULT_P2P_PORT: u16 = 28233;

/// The default JSON-RPC port.
///
/// Loopback only, with cookie authentication; the profile does not open it.
pub const DEFAULT_RPC_PORT: u16 = 28232;

/// The SLIP-44 coin type, confirmed unregistered in `slip-0044` at the time of the proposal.
pub const COIN_TYPE: u32 = 9767;

/// The first height of the SWARM production chain after genesis.
///
/// Every network upgrade activates here, so the NU6.3 rules and the SWARM transaction domain are
/// in force from the first block that can contain a transaction.
pub const ACTIVATION_HEIGHT: Height = Height(1);

/// The coinbase maturity, in blocks.
pub const COINBASE_MATURITY: u32 = 100;

/// The slow start interval: SWARM pays the full era-0 subsidy from block 1.
pub const SLOW_START_INTERVAL: Height = Height(0);

/// The pre-Blossom halving interval.
pub const PRE_BLOSSOM_HALVING_INTERVAL: HeightDiff = 840_000;

/// The post-Blossom halving interval.
///
/// SWARM's economics are identical to the SWARM testnet's: 6.25 SWM in era 0 and a halving every
/// 1,680,000 blocks.
pub const POST_BLOSSOM_HALVING_INTERVAL: HeightDiff = 1_680_000;

/// The first height of the funding stream range.
pub const FUNDING_STREAM_START_HEIGHT: Height = Height(1);

/// The exclusive end height of the funding stream range.
///
/// One range covers the whole emission schedule: every block with a non-zero reward.
pub const FUNDING_STREAM_END_HEIGHT_EXCLUSIVE: Height = Height(50_399_999);

/// The funding stream numerator of the Core Development allocation, out of 100.
pub const CORE_DEVELOPMENT_NUMERATOR: u64 = 8;

/// The funding stream numerator of the Grants & Ecosystem allocation, out of 100.
pub const GRANTS_ECOSYSTEM_NUMERATOR: u64 = 4;

/// The funding stream numerator of the Community & Development Reserve allocation, out of 100.
pub const COMMUNITY_RESERVE_NUMERATOR: u64 = 8;

/// The easiest target difficulty allowed on the SWARM production network.
///
/// # Reviewed value
///
/// This is `0x07ff…ff`, the same limit the SWARM testnet uses and the same limit upstream uses for
/// its Testnet. It is deliberately **not** the upstream Mainnet limit (`2^243 - 1`): that bound
/// assumes a hash rate SWARM does not have at launch, and a launch-day chain that cannot find a
/// block is worse than an easy one. It is also deliberately not easier than `0x07ff…ff`, because
/// the 17-target difficulty average overflows above that. Changing it is a consensus change and
/// requires a new reviewed value here, not a configuration field.
pub const TARGET_DIFFICULTY_LIMIT_BYTES: [u8; 32] = [
    0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// Returns the reviewed target difficulty limit for the SWARM production network.
///
/// The value is round-tripped through the compact representation, exactly as the upstream
/// Mainnet limit and the configured-Testnet builder both do: `zcashd` performs the difficulty
/// filter check against the compact form, so the limit a node compares against must be the
/// expanded form of the compact encoding, not the raw 32 bytes.
pub fn target_difficulty_limit() -> ExpandedDifficulty {
    ExpandedDifficulty::from(U256::from_big_endian(&TARGET_DIFFICULTY_LIMIT_BYTES))
        .to_compact()
        .to_expanded()
        .expect("the reviewed SWARM production difficulty limit is a valid expanded value")
}

/// The three funding stream slots SWARM uses, and the numerator each one is paid.
///
/// The upstream [`FundingStreamReceiver`] slot names are Zcash's; SWARM reuses the slots because
/// the consensus code keys on them, and relabels them for display. The mapping is fixed here so
/// that a configuration cannot move an allocation from one slot to another.
pub const FUNDING_STREAM_SLOTS: [(FundingStreamReceiver, u64, &str); 3] = [
    (
        FundingStreamReceiver::Ecc,
        CORE_DEVELOPMENT_NUMERATOR,
        "Core Development",
    ),
    (
        FundingStreamReceiver::MajorGrants,
        GRANTS_ECOSYSTEM_NUMERATOR,
        "Grants & Ecosystem",
    ),
    (
        FundingStreamReceiver::ZcashFoundation,
        COMMUNITY_RESERVE_NUMERATOR,
        "Community & Development Reserve",
    ),
];

/// A SWARM production profile that could not be built.
///
/// Every variant is a refusal to start: the node has no complete definition of the network, and
/// guessing the missing part is what this whole profile exists to prevent.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SwarmMainParametersError {
    /// No genesis block hash was supplied.
    #[error(
        "the SwarmMain genesis block hash is unresolved: it is generated at the launch ceremony \
         and must be supplied in the node configuration as `network.swarm_main.genesis_hash`. \
         There is no default: a copied testnet or upstream genesis would make this node follow \
         the wrong chain."
    )]
    GenesisHashUnresolved,

    /// The supplied genesis block hash is one this profile must never accept.
    #[error(
        "the configured SwarmMain genesis block hash {0} is the genesis of another network; \
         SwarmMain must have its own genesis block"
    )]
    GenesisHashBelongsToAnotherNetwork(block::Hash),

    /// A funding stream slot has no configured recipient address.
    #[error(
        "the SwarmMain funding stream recipient for {0} is missing: configure \
         `network.swarm_main.funding_stream_addresses.{1}`. The numerators and the height range \
         are fixed by the network definition; only the destinations are configured."
    )]
    FundingStreamRecipientMissing(&'static str, &'static str),

    /// A configured funding stream recipient address does not parse.
    #[error("the configured SwarmMain funding stream recipient for {0} is not a valid transparent address: {1}")]
    FundingStreamRecipientMalformed(&'static str, String),

    /// A configured funding stream recipient address belongs to another network.
    #[error(
        "the configured SwarmMain funding stream recipient {1} for {0} is a {2} address, not a \
         SwarmMain address; paying a funding stream to another network's address would burn it"
    )]
    FundingStreamRecipientWrongNetwork(&'static str, String, NetworkKind),

    /// A configured funding stream recipient address is not pay-to-script-hash.
    #[error(
        "the configured SwarmMain funding stream recipient {1} for {0} is a pay-to-public-key-hash \
         address; the reviewed funding stream destinations are multisig P2SH addresses (s3…)"
    )]
    FundingStreamRecipientNotP2sh(&'static str, String),
}

/// The complete, validated definition of the SWARM production network.
///
/// # Correctness
///
/// Every field is private and there is no `Default`. The only way to obtain one is
/// [`SwarmMainParametersBuilder::finish`], which returns an error unless every required field has
/// been supplied and validated. That is what makes "the node is configured for SwarmMain" a
/// statement the type system can carry: a `SwarmMainParameters` value in hand means the profile
/// was complete before any listener or database was opened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwarmMainParameters {
    /// The genesis block hash, supplied by configuration.
    genesis_hash: block::Hash,
    /// The funding streams, with configured recipient addresses and fixed numerators and range.
    funding_streams: FundingStreams,
    /// The P2P listener port.
    p2p_port: u16,
    /// The JSON-RPC port.
    rpc_port: u16,
}

impl SwarmMainParameters {
    /// Returns a builder for the SWARM production profile.
    pub fn build() -> SwarmMainParametersBuilder {
        SwarmMainParametersBuilder::default()
    }

    /// Returns the network name used by the `Display` impl.
    pub fn network_name(&self) -> &'static str {
        NETWORK_NAME
    }

    /// Returns the chain label used by the indexer, the wallet and the RPC `chain` field.
    pub fn chain_label(&self) -> &'static str {
        CHAIN_LABEL
    }

    /// Returns the P2P network magic.
    pub fn network_magic(&self) -> Magic {
        MAGIC
    }

    /// Returns the configured genesis block hash.
    pub fn genesis_hash(&self) -> block::Hash {
        self.genesis_hash
    }

    /// Returns the P2P listener port.
    pub fn p2p_port(&self) -> u16 {
        self.p2p_port
    }

    /// Returns the JSON-RPC port.
    pub fn rpc_port(&self) -> u16 {
        self.rpc_port
    }

    /// Returns the SLIP-44 coin type.
    pub fn coin_type(&self) -> u32 {
        COIN_TYPE
    }

    /// Returns the funding streams.
    pub fn funding_streams(&self) -> &FundingStreams {
        &self.funding_streams
    }

    /// Returns the easiest target difficulty allowed on this network.
    pub fn target_difficulty_limit(&self) -> ExpandedDifficulty {
        target_difficulty_limit()
    }

    /// Returns whether transparent outputs may spend coinbase outputs.
    ///
    /// Always `false`: SWARM production keeps the shielded-coinbase rule that the SWARM testnet
    /// relaxes for its own convenience.
    pub fn should_allow_unshielded_coinbase_spends(&self) -> bool {
        false
    }

    /// Returns the pre-Blossom halving interval.
    pub fn pre_blossom_halving_interval(&self) -> HeightDiff {
        PRE_BLOSSOM_HALVING_INTERVAL
    }

    /// Returns the post-Blossom halving interval.
    pub fn post_blossom_halving_interval(&self) -> HeightDiff {
        POST_BLOSSOM_HALVING_INTERVAL
    }

    /// Returns the slow start interval.
    pub fn slow_start_interval(&self) -> Height {
        SLOW_START_INTERVAL
    }

    /// Returns the slow start shift, always half the slow start interval.
    pub fn slow_start_shift(&self) -> Height {
        Height(SLOW_START_INTERVAL.0 / 2)
    }

    /// Returns the expected total of the NU6.1 one-time lockbox disbursements.
    ///
    /// Always zero: SWARM has no lockbox disbursement, because it has no pre-NU6.1 lockbox to
    /// disburse. Every upgrade activates at height 1.
    pub fn lockbox_disbursement_total_amount(&self) -> Amount<NonNegative> {
        Amount::zero()
    }

    /// Returns the expected NU6.1 one-time lockbox disbursement outputs.
    ///
    /// Always empty, for the reason in [`Self::lockbox_disbursement_total_amount`].
    pub fn lockbox_disbursements(&self) -> Vec<(transparent::Address, Amount<NonNegative>)> {
        Vec::new()
    }
}

/// A builder for [`SwarmMainParameters`].
///
/// Required fields start as `None` and stay that way until they are supplied, so
/// [`SwarmMainParametersBuilder::finish`] can tell a complete definition from an incomplete one.
#[derive(Clone, Debug, Default)]
pub struct SwarmMainParametersBuilder {
    /// The genesis block hash. Required.
    genesis_hash: Option<block::Hash>,
    /// The configured funding stream recipient address for each slot, keyed by slot. Required.
    funding_stream_addresses: HashMap<FundingStreamReceiver, String>,
    /// The P2P listener port, defaulting to [`DEFAULT_P2P_PORT`].
    p2p_port: Option<u16>,
    /// The JSON-RPC port, defaulting to [`DEFAULT_RPC_PORT`].
    rpc_port: Option<u16>,
}

impl SwarmMainParametersBuilder {
    /// Supplies the genesis block hash.
    pub fn with_genesis_hash(mut self, genesis_hash: block::Hash) -> Self {
        self.genesis_hash = Some(genesis_hash);
        self
    }

    /// Supplies the recipient address for one funding stream slot.
    pub fn with_funding_stream_address(
        mut self,
        receiver: FundingStreamReceiver,
        address: impl Into<String>,
    ) -> Self {
        self.funding_stream_addresses
            .insert(receiver, address.into());
        self
    }

    /// Supplies the P2P listener port, overriding [`DEFAULT_P2P_PORT`].
    pub fn with_p2p_port(mut self, port: u16) -> Self {
        self.p2p_port = Some(port);
        self
    }

    /// Supplies the JSON-RPC port, overriding [`DEFAULT_RPC_PORT`].
    pub fn with_rpc_port(mut self, port: u16) -> Self {
        self.rpc_port = Some(port);
        self
    }

    /// Validates the definition and builds the profile.
    ///
    /// # Errors
    ///
    /// Returns a [`SwarmMainParametersError`] if the genesis hash is unresolved, if it is another
    /// network's genesis, or if any funding stream recipient is missing, malformed, on another
    /// network, or not a P2SH address.
    pub fn finish(self) -> Result<SwarmMainParameters, SwarmMainParametersError> {
        let Self {
            genesis_hash,
            funding_stream_addresses,
            p2p_port,
            rpc_port,
        } = self;

        let genesis_hash = genesis_hash.ok_or(SwarmMainParametersError::GenesisHashUnresolved)?;

        // A node that was handed another network's genesis would sync that network's chain under
        // SWARM's rules, which is the failure mode this whole profile exists to make impossible.
        // The upstream Mainnet genesis is a constant; the SWARM testnet's is checked by the
        // caller's own manifest comparison, but the two hard-coded ones are cheap to reject here.
        for (_network, foreign) in FOREIGN_GENESIS_HASHES {
            let foreign: block::Hash = foreign
                .parse()
                .expect("hard-coded foreign genesis hash parses");
            if genesis_hash == foreign {
                return Err(
                    SwarmMainParametersError::GenesisHashBelongsToAnotherNetwork(genesis_hash),
                );
            }
        }

        let mut recipients = HashMap::new();
        for (receiver, numerator, label) in FUNDING_STREAM_SLOTS {
            let config_key = funding_stream_config_key(receiver);
            let address = funding_stream_addresses.get(&receiver).ok_or(
                SwarmMainParametersError::FundingStreamRecipientMissing(label, config_key),
            )?;

            let parsed: transparent::Address = address.parse().map_err(|error| {
                SwarmMainParametersError::FundingStreamRecipientMalformed(label, format!("{error}"))
            })?;

            let kind = parsed.network_kind();
            if kind != NetworkKind::SwarmMainnet {
                return Err(
                    SwarmMainParametersError::FundingStreamRecipientWrongNetwork(
                        label,
                        address.clone(),
                        kind,
                    ),
                );
            }

            if !parsed.is_script_hash() {
                return Err(SwarmMainParametersError::FundingStreamRecipientNotP2sh(
                    label,
                    address.clone(),
                ));
            }

            recipients.insert(
                receiver,
                FundingStreamRecipient::new(numerator, [address.clone()]),
            );
        }

        Ok(SwarmMainParameters {
            genesis_hash,
            funding_streams: FundingStreams::new(
                FUNDING_STREAM_START_HEIGHT..FUNDING_STREAM_END_HEIGHT_EXCLUSIVE,
                recipients,
            ),
            p2p_port: p2p_port.unwrap_or(DEFAULT_P2P_PORT),
            rpc_port: rpc_port.unwrap_or(DEFAULT_RPC_PORT),
        })
    }
}

/// Genesis block hashes that belong to other networks and must never be accepted as SwarmMain's.
///
/// This is a cheap sanity check, not the whole defence: the operator's manifest comparison is. It
/// catches the copy-paste that a rushed launch is most likely to produce.
const FOREIGN_GENESIS_HASHES: [(&str, &str); 2] = [
    (
        "Zcash Mainnet",
        "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08",
    ),
    (
        "SWARM testnet",
        "045993f5c91ea160c7ebda573dd97b0016816bca68d395bfff202779b88e2a28",
    ),
];

/// Returns the configuration key under `network.swarm_main.funding_stream_addresses` for a slot.
pub fn funding_stream_config_key(receiver: FundingStreamReceiver) -> &'static str {
    match receiver {
        FundingStreamReceiver::Ecc => "core_development",
        FundingStreamReceiver::MajorGrants => "grants_ecosystem",
        FundingStreamReceiver::ZcashFoundation => "community_reserve",
        FundingStreamReceiver::Deferred => "deferred",
    }
}

/// Returns the SWARM production activation list: every network upgrade at height 1.
///
/// Genesis occupies height 0, exactly as it does on every other network, so that
/// `NetworkUpgrade::current` has an answer there.
pub fn activation_list() -> std::collections::BTreeMap<Height, crate::parameters::NetworkUpgrade> {
    use crate::parameters::NetworkUpgrade;

    let mut list = std::collections::BTreeMap::new();
    list.insert(Height(0), NetworkUpgrade::Genesis);
    // The last upgrade wins for a shared height, and `full_activation_list` fills in the
    // intermediate ones, so listing the latest revision at height 1 activates them all there.
    list.insert(ACTIVATION_HEIGHT, NetworkUpgrade::Nu6_3);
    list
}

/// Convenience alias for an `Arc`'d profile, which is what [`crate::parameters::Network`] holds.
pub type SwarmMainParametersArc = Arc<SwarmMainParameters>;

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        parameters::{
            ConsensusBranchId, DomainRegistry, Network, NetworkUpgrade, CONSENSUS_BRANCH_IDS,
            SWARM_PRODUCTION_DOMAIN,
        },
        work::difficulty::ParameterDifficulty,
    };

    /// A genesis hash that is neither upstream's nor the SWARM testnet's.
    ///
    /// Test data: it stands in for the hash the launch ceremony will produce, and proves only
    /// that the builder accepts a supplied one. It is not a candidate value.
    const FIXTURE_GENESIS: &str =
        "0000000000000000000000000000000000000000000000000000000000000abc";

    /// SWARM production P2SH (`s3...`) addresses derived from fixed test strings. Test data only:
    /// the real destinations are generated at the launch ceremony.
    const FIXTURE_CORE: &str = "s3SMKDUgQ2JoZxEArhrUw5ofKtZG5YjknAC";
    const FIXTURE_GRANTS: &str = "s3X7hSqNZJJXDfq28SRQ7JvbJbF43vfGpiQ";
    const FIXTURE_RESERVE: &str = "s3Nv3ARoQTLNkhHhbShTP9pRjhRWBXVP7n4";
    /// A SWARM production P2PKH (`s1...`) address: the right network, the wrong address kind.
    const FIXTURE_P2PKH: &str = "s1Zxp3fq9J8ewT6tnQyQFci1Hhe37vHf8US";
    /// A SWARM *testnet* P2SH address, from `network/swarm-testnet/manifest.json`.
    const FIXTURE_TESTNET_P2SH: &str = "t2DGVURG5tAyXXSkj85JV5xbvTobYv7H99n";
    /// An upstream Zcash Mainnet P2SH address.
    const FIXTURE_UPSTREAM_P2SH: &str = "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd";

    /// A builder with every required field supplied.
    fn complete_builder() -> SwarmMainParametersBuilder {
        SwarmMainParameters::build()
            .with_genesis_hash(FIXTURE_GENESIS.parse().expect("fixture genesis parses"))
            .with_funding_stream_address(FundingStreamReceiver::Ecc, FIXTURE_CORE)
            .with_funding_stream_address(FundingStreamReceiver::MajorGrants, FIXTURE_GRANTS)
            .with_funding_stream_address(FundingStreamReceiver::ZcashFoundation, FIXTURE_RESERVE)
    }

    fn complete_network() -> Network {
        Network::SwarmMain(Arc::new(
            complete_builder()
                .finish()
                .expect("the fixture profile is complete"),
        ))
    }

    /// The identity constants, pinned. If any of these changes the network is a different
    /// network, and every node, wallet and indexer that already joined is forked off it.
    #[test]
    fn swarm_main_identity_is_pinned() {
        let network = complete_network();
        let params = network
            .swarm_main_parameters()
            .expect("the fixture network is SwarmMain");

        assert_eq!(params.network_name(), "SwarmMainnet");
        assert_eq!(network.to_string(), "SwarmMainnet");
        assert_eq!(params.chain_label(), "swarm-mainnet");
        assert_eq!(network.chain_label(), "swarm-mainnet");

        // `SWMN`, distinct from Zcash Mainnet `24 e9 27 64`, Zcash Testnet `fa 1a f9 bf` and the
        // SWARM testnet's `SWRM` (`53 57 52 4d`).
        assert_eq!(network.magic().0, [0x53, 0x57, 0x4d, 0x4e]);
        assert_eq!(&network.magic().0, b"SWMN");
        assert_ne!(network.magic(), Network::Mainnet.magic());
        assert_ne!(network.magic(), Network::new_default_testnet().magic());

        assert_eq!(network.default_port(), 28233);
        assert_eq!(params.p2p_port(), 28233);
        assert_eq!(params.rpc_port(), 28232);
        assert_eq!(params.coin_type(), 9767);
        assert_eq!(
            params.coin_type(),
            zcash_protocol::constants::swarm_mainnet::COIN_TYPE
        );

        assert_eq!(network.kind(), NetworkKind::SwarmMainnet);
        assert_eq!(network.t_addr_kind(), NetworkKind::SwarmMainnet);
        assert_eq!(
            zcash_protocol::consensus::NetworkType::from(network.kind()),
            zcash_protocol::consensus::NetworkType::SwarmMain
        );

        // Economics identical to the SWARM testnet.
        assert_eq!(params.pre_blossom_halving_interval(), 840_000);
        assert_eq!(params.post_blossom_halving_interval(), 1_680_000);
        assert_eq!(params.slow_start_interval(), Height(0));
        assert_eq!(COINBASE_MATURITY, 100);
        assert!(!params.should_allow_unshielded_coinbase_spends());
        assert!(!network.should_allow_unshielded_coinbase_spends());

        // The reviewed target difficulty limit: the same bound the SWARM testnet uses, and
        // deliberately not the upstream Mainnet one.
        assert_eq!(
            network.target_difficulty_limit(),
            Network::new_default_testnet().target_difficulty_limit(),
        );
        assert_ne!(
            network.target_difficulty_limit(),
            Network::Mainnet.target_difficulty_limit()
        );

        // No checkpoints beyond genesis, and no founders' reward addresses.
        assert_eq!(network.checkpoint_list().len(), 1);
        assert!(network.founder_address_list().is_empty());
    }

    /// Every network upgrade is active from height 1, and the SWARM production domain is the one
    /// in force there. No upstream domain is ever reachable on this network.
    #[test]
    fn swarm_main_activates_everything_at_height_one_under_its_own_domain() {
        let network = complete_network();

        assert_eq!(
            NetworkUpgrade::current(&network, Height(0)),
            NetworkUpgrade::Genesis
        );
        assert_eq!(
            ConsensusBranchId::current(&network, Height(0)),
            None,
            "genesis has no consensus branch ID on any network"
        );

        for height in [Height(1), Height(2), Height(1_000_000), Height::MAX] {
            assert_eq!(
                NetworkUpgrade::current(&network, height),
                NetworkUpgrade::Nu6_3,
                "the NU6.3 rules are in force from height 1"
            );
            let branch = ConsensusBranchId::current(&network, height)
                .expect("SwarmMain has a transaction domain from height 1");
            assert_eq!(branch, SWARM_PRODUCTION_DOMAIN);
            assert_eq!(u32::from(branch), 0x5357_4d31);
            assert!(
                !CONSENSUS_BRANCH_IDS.iter().any(|(_, id)| *id == branch),
                "SwarmMain must never resolve to an upstream consensus branch ID"
            );
        }

        assert_eq!(network.domain_registry(), DomainRegistry::SWARM_PRODUCTION);
        assert!(network.domain_registry().admits(SWARM_PRODUCTION_DOMAIN));
        for (_, upstream_id) in CONSENSUS_BRANCH_IDS {
            assert!(
                !network.domain_registry().admits(*upstream_id),
                "the SwarmMain registry must not admit upstream domain {upstream_id:?}"
            );
        }
    }

    /// SwarmMain is a production network: it is not a test network, and it is not upstream
    /// Mainnet either. Both halves matter, so a refactor that collapses one into the other fails
    /// here.
    #[test]
    fn swarm_main_is_neither_a_test_network_nor_upstream_mainnet() {
        let network = complete_network();

        assert!(!network.is_a_test_network());
        assert!(network.is_swarm_main());
        assert!(!network.is_default_testnet());
        assert!(!network.is_regtest());
        assert_ne!(network, Network::Mainnet);
        assert_ne!(network.kind(), NetworkKind::Mainnet);

        // The upstream networks keep their existing answers, unchanged.
        assert!(!Network::Mainnet.is_a_test_network());
        assert!(Network::new_default_testnet().is_a_test_network());
        assert!(!Network::Mainnet.is_swarm_main());
        assert!(!Network::new_default_testnet().is_swarm_main());

        // The testnet minimum-difficulty exception is off, at every height.
        for height in [Height(1), Height(299_187), Height(299_188), Height(299_189)] {
            assert_eq!(
                NetworkUpgrade::minimum_difficulty_spacing_for_height(&network, height),
                None,
                "the minimum difficulty exception must be off on SwarmMain at {height:?}"
            );
        }

        // The max-block-time rule is in force from height 1, with no start-height exemption.
        assert!(!network.is_max_block_time_enforced(Height(0)));
        assert!(network.is_max_block_time_enforced(Height(1)));
        assert!(network.is_max_block_time_enforced(Height(653_605)));
    }

    /// A profile missing the genesis hash is not buildable. There is no placeholder and no
    /// default: a node cannot be configured for SwarmMain until a real genesis is supplied.
    #[test]
    fn builder_rejects_an_unresolved_genesis() {
        let incomplete = SwarmMainParameters::build()
            .with_funding_stream_address(FundingStreamReceiver::Ecc, FIXTURE_CORE)
            .with_funding_stream_address(FundingStreamReceiver::MajorGrants, FIXTURE_GRANTS)
            .with_funding_stream_address(FundingStreamReceiver::ZcashFoundation, FIXTURE_RESERVE)
            .finish();

        assert_eq!(
            incomplete,
            Err(SwarmMainParametersError::GenesisHashUnresolved)
        );
    }

    /// Another network's genesis is refused outright.
    #[test]
    fn builder_rejects_another_networks_genesis() {
        for foreign in [
            Network::Mainnet.genesis_hash(),
            "045993f5c91ea160c7ebda573dd97b0016816bca68d395bfff202779b88e2a28"
                .parse()
                .expect("the SWARM testnet genesis parses"),
        ] {
            let result = complete_builder().with_genesis_hash(foreign).finish();
            assert_eq!(
                result,
                Err(SwarmMainParametersError::GenesisHashBelongsToAnotherNetwork(foreign)),
                "a foreign genesis must be refused"
            );
        }
    }

    /// Every funding stream slot must have a configured recipient.
    #[test]
    fn builder_rejects_a_missing_funding_stream_recipient() {
        let genesis = FIXTURE_GENESIS.parse().expect("fixture genesis parses");

        let missing_one = SwarmMainParameters::build()
            .with_genesis_hash(genesis)
            .with_funding_stream_address(FundingStreamReceiver::Ecc, FIXTURE_CORE)
            .with_funding_stream_address(FundingStreamReceiver::MajorGrants, FIXTURE_GRANTS)
            .finish();

        assert_eq!(
            missing_one,
            Err(SwarmMainParametersError::FundingStreamRecipientMissing(
                "Community & Development Reserve",
                "community_reserve",
            ))
        );

        let none_at_all = SwarmMainParameters::build()
            .with_genesis_hash(genesis)
            .finish();
        assert!(matches!(
            none_at_all,
            Err(SwarmMainParametersError::FundingStreamRecipientMissing(..))
        ));
    }

    /// A recipient address from another network is refused: paying a funding stream to a testnet
    /// or upstream address would burn it.
    #[test]
    fn builder_rejects_a_foreign_funding_stream_recipient() {
        for (address, expected_kind) in [
            (FIXTURE_TESTNET_P2SH, NetworkKind::Testnet),
            (FIXTURE_UPSTREAM_P2SH, NetworkKind::Mainnet),
        ] {
            let result = complete_builder()
                .with_funding_stream_address(FundingStreamReceiver::Ecc, address)
                .finish();

            assert_eq!(
                result,
                Err(
                    SwarmMainParametersError::FundingStreamRecipientWrongNetwork(
                        "Core Development",
                        address.to_string(),
                        expected_kind,
                    )
                ),
                "{address} must be refused as a SwarmMain funding stream recipient"
            );
        }
    }

    /// The right network but the wrong address kind is still refused: the reviewed destinations
    /// are multisig P2SH addresses.
    #[test]
    fn builder_rejects_a_non_p2sh_funding_stream_recipient() {
        let result = complete_builder()
            .with_funding_stream_address(FundingStreamReceiver::MajorGrants, FIXTURE_P2PKH)
            .finish();

        assert_eq!(
            result,
            Err(SwarmMainParametersError::FundingStreamRecipientNotP2sh(
                "Grants & Ecosystem",
                FIXTURE_P2PKH.to_string(),
            ))
        );
    }

    /// Garbage in the configuration is refused with an explicit error rather than a panic.
    #[test]
    fn builder_rejects_a_malformed_funding_stream_recipient() {
        let result = complete_builder()
            .with_funding_stream_address(FundingStreamReceiver::Ecc, "not-an-address")
            .finish();

        assert!(matches!(
            result,
            Err(SwarmMainParametersError::FundingStreamRecipientMalformed(
                "Core Development",
                _
            ))
        ));
    }

    /// A complete definition builds, and the funding streams it produces carry the reviewed
    /// numerators and range with the configured destinations.
    #[test]
    fn builder_accepts_a_complete_definition() {
        let params = complete_builder()
            .finish()
            .expect("the definition is complete");
        let streams = params.funding_streams();

        assert_eq!(
            *streams.height_range(),
            Height(1)..Height(50_399_999),
            "one range covers the whole emission schedule"
        );

        for (receiver, expected_numerator, expected_address) in [
            (FundingStreamReceiver::Ecc, 8, FIXTURE_CORE),
            (FundingStreamReceiver::MajorGrants, 4, FIXTURE_GRANTS),
            (FundingStreamReceiver::ZcashFoundation, 8, FIXTURE_RESERVE),
        ] {
            let recipient = streams
                .recipients()
                .get(&receiver)
                .unwrap_or_else(|| panic!("{receiver:?} must be present"));
            assert_eq!(recipient.numerator(), expected_numerator);
            assert_eq!(recipient.addresses().len(), 1);
            assert_eq!(recipient.addresses()[0].to_string(), expected_address);
            assert_eq!(
                recipient.addresses()[0].network_kind(),
                NetworkKind::SwarmMainnet
            );
        }

        assert!(
            !streams
                .recipients()
                .contains_key(&FundingStreamReceiver::Deferred),
            "SwarmMain defines no deferred lockbox slot"
        );

        // 8 + 4 + 8 = 20% of the subsidy, leaving 80% and all fees to the miner.
        let total: u64 = streams.recipients().values().map(|r| r.numerator()).sum();
        assert_eq!(total, 20);

        // SwarmMain has no NU6.1 lockbox to disburse: every upgrade activates at height 1.
        assert_eq!(
            params.lockbox_disbursement_total_amount(),
            Amount::<NonNegative>::zero()
        );
        assert!(params.lockbox_disbursements().is_empty());
    }

    /// The upstream networks' registries and predicates are untouched by everything above.
    #[test]
    fn upstream_networks_keep_their_registries_and_predicates() {
        for network in Network::iter() {
            assert_eq!(network.domain_registry(), DomainRegistry::UPSTREAM);
            assert!(!network.is_swarm_main());
            assert!(network.swarm_main_parameters().is_none());

            for (_, id) in CONSENSUS_BRANCH_IDS {
                assert!(network.domain_registry().admits(*id));
            }
            assert!(
                !network.domain_registry().admits(SWARM_PRODUCTION_DOMAIN),
                "an upstream network must never admit the SWARM production domain"
            );
        }
    }
}
