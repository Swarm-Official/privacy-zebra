use std::{cmp::max, fmt};

use zebra_chain::{
    block,
    parameters::{
        Network::{self, *},
        NetworkUpgrade::{self, *},
    },
};

use crate::constants::{self, CURRENT_NETWORK_PROTOCOL_VERSION};

#[cfg(any(test, feature = "proptest-impl"))]
use proptest_derive::Arbitrary;

/// A protocol version number.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Version(pub u32);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string())
    }
}

impl Version {
    /// Returns the minimum remote node network protocol version for `network` and
    /// `height`. Zebra disconnects from peers with lower versions.
    ///
    /// # Panics
    ///
    /// If we are incompatible with our own minimum remote protocol version.
    pub fn min_remote_for_height(
        network: &Network,
        height: impl Into<Option<block::Height>>,
    ) -> Version {
        let height = height.into().unwrap_or(block::Height(0));
        let min_spec = Version::min_specified_for_height(network, height);

        // shut down if our own version is too old
        assert!(
            constants::CURRENT_NETWORK_PROTOCOL_VERSION >= min_spec,
            "Zebra does not implement the minimum specified {:?} protocol version for {:?} at {:?}",
            NetworkUpgrade::current(network, height),
            network,
            height,
        );

        max(min_spec, Version::initial_min_for_network(network))
    }

    /// Returns the minimum supported network protocol version for `network`.
    ///
    /// This is the minimum peer version when Zebra is significantly behind current tip:
    /// - during the initial block download,
    /// - after Zebra restarts, and
    /// - after Zebra's local network is slow or shut down.
    /// # Correctness
    ///
    /// The lookup table is a cache of the three upstream answers, not the source of truth. A
    /// network that is not in it falls through to the value the network itself implies, so a
    /// newly added [`Network`] variant cannot make this function panic. It used to be an
    /// infallible `.get(..).expect(..)`, and [`Network::SwarmMain`] was missing from the table,
    /// which aborted `zebrad` during peer-set initialization before the RPC server started.
    fn initial_min_for_network(network: &Network) -> Version {
        if let Some(version) = constants::INITIAL_MIN_NETWORK_PROTOCOL_VERSION.get(&network.kind())
        {
            return *version;
        }

        // The fallback is the same expression the table's own entries are built from, evaluated
        // for this network instead of for one of the three it happens to list. On SwarmMain that
        // is `CURRENT_NETWORK_PROTOCOL_VERSION`, because SWARM production starts at the NU6.3
        // rules and has no legacy peer to stay compatible with.
        Version::min_specified_for_upgrade(network, Nu6_2)
    }

    /// Returns the minimum specified network protocol version for `network` and
    /// `height`.
    ///
    /// This is the minimum peer version when Zebra is close to the current tip.
    fn min_specified_for_height(network: &Network, height: block::Height) -> Version {
        let network_upgrade = NetworkUpgrade::current(network, height);
        Version::min_specified_for_upgrade(network, network_upgrade)
    }

    /// Returns the minimum specified network protocol version for `network` and
    /// `network_upgrade`.
    ///
    /// ## ZIP-253
    ///
    /// > Nodes compatible with a network upgrade activation MUST advertise a network protocol
    /// > version that is greater than or equal to the MIN_NETWORK_PROTOCOL_VERSION for that
    /// > activation.
    ///
    /// <https://zips.z.cash/zip-0253>
    ///
    /// ### Notes
    ///
    /// - The citation above is a generalization of a statement in ZIP-253 since that ZIP is
    ///   concerned only with NU6 on Mainnet and Testnet.
    pub(crate) fn min_specified_for_upgrade(
        network: &Network,
        network_upgrade: NetworkUpgrade,
    ) -> Version {
        Version(match (network, network_upgrade) {
            (_, Genesis) | (_, BeforeOverwinter) => 170_002,
            (Testnet(params), Overwinter) if params.is_default_testnet() => 170_003,
            (Mainnet, Overwinter) => 170_005,
            (Testnet(params), Sapling) if params.is_default_testnet() => 170_007,
            (Testnet(params), Sapling) if params.is_regtest() => 170_006,
            (Mainnet, Sapling) => 170_007,
            (Testnet(params), Blossom) if params.is_default_testnet() || params.is_regtest() => {
                170_008
            }
            (Mainnet, Blossom) => 170_009,
            (Testnet(params), Heartwood) if params.is_default_testnet() || params.is_regtest() => {
                170_010
            }
            (Mainnet, Heartwood) => 170_011,
            (Testnet(params), Canopy) if params.is_default_testnet() || params.is_regtest() => {
                170_012
            }
            (Mainnet, Canopy) => 170_013,
            (Testnet(params), Nu5) if params.is_default_testnet() || params.is_regtest() => 170_050,
            (Mainnet, Nu5) => 170_100,
            (Testnet(params), Nu6) if params.is_default_testnet() || params.is_regtest() => 170_110,
            (Mainnet, Nu6) => 170_120,
            (Testnet(params), Nu6_1) if params.is_default_testnet() || params.is_regtest() => {
                170_130
            }
            (Mainnet, Nu6_1) => 170_140,
            (Testnet(params), Nu6_2) if params.is_default_testnet() || params.is_regtest() => {
                170_150
            }
            (Mainnet, Nu6_2) => 170_150,
            // TODO: these NU6.3 (Ironwood) and Nu7 protocol versions are provisional, bumped above
            // Nu6_2's 170_150. Update them when the real values are specified.
            (Testnet(params), Nu6_3) if params.is_default_testnet() || params.is_regtest() => {
                170_160
            }
            (Mainnet, Nu6_3) => 170_160,
            (Testnet(params), Nu7) if params.is_default_testnet() || params.is_regtest() => 170_170,
            (Mainnet, Nu7) => 170_180,

            // It should be fine to reject peers with earlier network protocol versions on custom testnets for now.
            (Testnet(_), _) => CURRENT_NETWORK_PROTOCOL_VERSION.0,

            // SWARM production starts at the NU6.3 rules, so there is no earlier upgrade for a
            // SWARM peer to have implemented and no legacy peer to stay compatible with: every
            // peer must speak the current version. Borrowing an upstream number here would be
            // worse than useless, because those numbers encode Zcash's deployment history, which
            // SWARM does not share. The network magic already keeps the two peer sets apart; this
            // makes the version floor say the same thing.
            (SwarmMain(_), _) => CURRENT_NETWORK_PROTOCOL_VERSION.0,

            #[cfg(zcash_unstable = "zfuture")]
            (Mainnet, ZFuture) => {
                panic!("ZFuture network upgrade should not be active on Mainnet")
            }
        })
    }
}

bitflags! {
    /// A bitflag describing services advertised by a node in the network.
    ///
    /// Note that bits 24-31 are reserved for temporary experiments; other
    /// service bits should be allocated via the ZIP process.
    #[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
    pub struct PeerServices: u64 {
        /// NODE_NETWORK means that the node is a full node capable of serving
        /// blocks, as opposed to a light client that makes network requests but
        /// does not provide network services.
        const NODE_NETWORK = 1;
    }
}

/// A nonce used in the networking layer to identify messages.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(any(test, feature = "proptest-impl"), derive(Arbitrary))]
pub struct Nonce(pub u64);

impl Default for Nonce {
    fn default() -> Self {
        use rand::{thread_rng, Rng};
        Self(thread_rng().gen())
    }
}

/// A random value to add to the seed value in a hash function.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(any(test, feature = "proptest-impl"), derive(Arbitrary))]
pub struct Tweak(pub u32);

impl Default for Tweak {
    fn default() -> Self {
        use rand::{thread_rng, Rng};
        Self(thread_rng().gen())
    }
}

/// A Bloom filter consisting of a bit field of arbitrary byte-aligned
/// size, maximum size is 36,000 bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(any(test, feature = "proptest-impl"), derive(Arbitrary))]
pub struct Filter(pub Vec<u8>);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn version_extremes_mainnet() {
        version_extremes(&Mainnet)
    }

    #[test]
    fn version_extremes_testnet() {
        version_extremes(&Network::new_default_testnet())
    }

    /// Test the min_specified_for_upgrade and min_specified_for_height functions for `network` with
    /// extreme values.
    fn version_extremes(network: &Network) {
        let _init_guard = zebra_test::init();

        assert_eq!(
            Version::min_specified_for_height(network, block::Height(0)),
            Version::min_specified_for_upgrade(network, BeforeOverwinter),
        );

        // We assume that the last version we know about continues forever
        // (even if we suspect that won't be true)
        assert_ne!(
            Version::min_specified_for_height(network, block::Height::MAX),
            Version::min_specified_for_upgrade(network, BeforeOverwinter),
        );
    }

    #[test]
    fn version_consistent_mainnet() {
        version_consistent(&Mainnet)
    }

    #[test]
    fn version_consistent_testnet() {
        version_consistent(&Network::new_default_testnet())
    }

    /// Check that the min_specified_for_upgrade and min_specified_for_height functions
    /// are consistent for `network`.
    fn version_consistent(network: &Network) {
        let _init_guard = zebra_test::init();

        let highest_network_upgrade = NetworkUpgrade::current(network, block::Height::MAX);
        assert!(
            matches!(highest_network_upgrade, Nu6 | Nu6_1 | Nu6_2 | Nu6_3 | Nu7),
            "expected coverage of all network upgrades: \
            add the new network upgrade to the list in this test"
        );

        for &network_upgrade in &[
            BeforeOverwinter,
            Overwinter,
            Sapling,
            Blossom,
            Heartwood,
            Canopy,
            Nu5,
            Nu6,
            Nu6_1,
            Nu6_2,
            Nu6_3,
            Nu7,
        ] {
            let height = network_upgrade.activation_height(network);
            if let Some(height) = height {
                assert_eq!(
                    Version::min_specified_for_upgrade(network, network_upgrade),
                    Version::min_specified_for_height(network, height)
                );
            }
        }
    }
}

#[cfg(test)]
mod swarm_main_tests {
    use std::sync::Arc;

    use zebra_chain::{
        block::Height,
        parameters::{
            network::swarm_main::{self, fixture},
            Network, NetworkKind, NetworkUpgrade,
        },
    };

    use super::*;
    use crate::{constants::CURRENT_NETWORK_PROTOCOL_VERSION, Config};

    /// The disposable genesis hash the 2026-09-25 production-domain rehearsal generated.
    ///
    /// It is a fixture here for the same reason it was disposable there: a network definition
    /// that is pinned by hash has to be exercised with a hash, and this one is public, belongs to
    /// no live chain and is not a candidate for the launch ceremony's.
    const REHEARSAL_GENESIS: &str =
        "007e6673cb1f970523cc60927a2fca00876c67bbeef6b3843230fd8f7546ce65";

    /// A validated `Network::SwarmMain` with the rehearsal genesis and the three `s3…` fixture
    /// funding stream recipients.
    fn rehearsal_swarm_main() -> Network {
        let params = fixture::builder()
            .with_genesis_hash(REHEARSAL_GENESIS.parse().expect("rehearsal genesis parses"))
            .finish()
            .expect("the fixture profile is complete");

        Network::SwarmMain(Arc::new(params))
    }

    /// Every network-keyed lookup a starting node makes must answer on SwarmMain, with a
    /// SWARM-specific value and without panicking.
    ///
    /// `zebrad` at `8ff13f817` aborted during peer-set initialization on SwarmMain, because
    /// `Version::initial_min_for_network` indexed a three-entry table infallibly. There was no
    /// test that constructed a SwarmMain network and called it; this is that test, extended to
    /// the rest of the lookups the same startup path makes.
    #[test]
    fn swarm_main_network_lookups_do_not_panic() {
        let _init_guard = zebra_test::init();

        let network = rehearsal_swarm_main();

        assert_eq!(network.kind(), NetworkKind::SwarmMainnet);
        assert!(
            !network.is_a_test_network(),
            "SWARM production must not be treated as a test network"
        );

        // 1. The lookup that panicked, and the two callers above it.
        assert_eq!(
            Version::initial_min_for_network(&network),
            CURRENT_NETWORK_PROTOCOL_VERSION,
            "SWARM production starts at the NU6.3 rules, so its peer floor is the current version"
        );
        for height in [0, 1, 2, 100, 35_001, 1_680_001] {
            let height = Height(height);
            let min_remote = Version::min_remote_for_height(&network, height);
            assert!(
                min_remote >= Version::min_specified_for_height(&network, height),
                "the remote floor is never below the specified floor at {height:?}"
            );
            assert!(min_remote <= CURRENT_NETWORK_PROTOCOL_VERSION);
        }
        assert_eq!(
            Version::min_remote_for_height(&network, Height(1)),
            CURRENT_NETWORK_PROTOCOL_VERSION
        );

        // 2. Every network upgrade, not only the ones in the activation list.
        for upgrade in NetworkUpgrade::iter() {
            let _version = Version::min_specified_for_upgrade(&network, upgrade);
        }
        assert_eq!(
            Version::min_specified_for_upgrade(&network, NetworkUpgrade::Nu6_3),
            CURRENT_NETWORK_PROTOCOL_VERSION
        );

        // 3. Seeds: SWARM must not inherit either upstream DNS seeder list.
        let config = Config {
            network: network.clone(),
            ..Config::default()
        };
        assert!(
            config.initial_peer_hostnames().is_empty(),
            "a SWARM node must not dial the Zcash DNS seeders"
        );

        // 4. Ports and magic.
        assert_eq!(network.default_port(), swarm_main::DEFAULT_P2P_PORT);
        assert_eq!(network.default_port(), 28233);
        assert_eq!(network.magic(), swarm_main::MAGIC);
        assert_ne!(network.magic(), Network::Mainnet.magic());
        assert_ne!(network.magic(), Network::new_default_testnet().magic());

        // 5. Checkpoints: the genesis checkpoint is the whole list, and it is SWARM's genesis.
        let checkpoints = network.checkpoint_list();
        assert_eq!(checkpoints.max_height(), Height(0));
        assert_eq!(
            checkpoints.hash(Height(0)),
            Some(network.genesis_hash()),
            "the only checkpoint must be the configured SWARM genesis"
        );
        assert_ne!(network.genesis_hash(), Network::Mainnet.genesis_hash());

        // 6. The state database namespace, which is `Network::lowercase_name()`.
        assert_eq!(network.lowercase_name(), "swarmmainnet");
        assert_ne!(network.lowercase_name(), Network::Mainnet.lowercase_name());

        // 7. The RPC `chain` field, which is `Network::bip70_network_name()`.
        assert_eq!(network.bip70_network_name(), swarm_main::CHAIN_LABEL);
        assert_eq!(network.chain_label(), "swarm-mainnet");
        assert_ne!(network.bip70_network_name(), "main");
        assert_ne!(network.bip70_network_name(), "test");
    }
}
