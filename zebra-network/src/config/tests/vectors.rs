//! Fixed test vectors for zebra-network configuration.

use indexmap::IndexSet;
use static_assertions::const_assert;
use zebra_chain::{
    block::Height,
    parameters::{
        testnet::{self, ConfiguredFundingStreams},
        Network,
    },
};

use crate::{
    constants::{INBOUND_PEER_LIMIT_MULTIPLIER, OUTBOUND_PEER_LIMIT_MULTIPLIER},
    Config,
};

#[test]
fn parse_config_listen_addr() {
    let _init_guard = zebra_test::init();

    let fixtures = vec![
        ("listen_addr = '0.0.0.0'", "0.0.0.0:8233"),
        ("listen_addr = '0.0.0.0:9999'", "0.0.0.0:9999"),
        (
            "listen_addr = '0.0.0.0'\nnetwork = 'Testnet'",
            "0.0.0.0:18233",
        ),
        (
            "listen_addr = '0.0.0.0:8233'\nnetwork = 'Testnet'",
            "0.0.0.0:8233",
        ),
        ("listen_addr = '[::]'", "[::]:8233"),
        ("listen_addr = '[::]:9999'", "[::]:9999"),
        ("listen_addr = '[::]'\nnetwork = 'Testnet'", "[::]:18233"),
        (
            "listen_addr = '[::]:8233'\nnetwork = 'Testnet'",
            "[::]:8233",
        ),
        ("listen_addr = '[::1]:8233'", "[::1]:8233"),
        ("listen_addr = '[2001:db8::1]:8233'", "[2001:db8::1]:8233"),
    ];

    for (config, value) in fixtures {
        let config: Config = toml::from_str(config).unwrap();
        assert_eq!(config.listen_addr.to_string(), value);
    }
}

/// Make sure the peer connection limits are consistent with each other.
#[test]
fn ensure_peer_connection_limits_consistent() {
    let _init_guard = zebra_test::init();

    // Zebra should allow more inbound connections, to avoid connection exhaustion
    const_assert!(INBOUND_PEER_LIMIT_MULTIPLIER > OUTBOUND_PEER_LIMIT_MULTIPLIER);

    let config = Config::default();

    assert!(
        config.peerset_inbound_connection_limit() - config.peerset_outbound_connection_limit()
            >= 50,
        "default config should allow more inbound connections, to avoid connection exhaustion",
    );
}

#[test]
fn testnet_params_serialization_roundtrip() {
    let _init_guard = zebra_test::init();

    let config = Config {
        network: testnet::Parameters::build()
            .with_disable_pow(true)
            .to_network()
            .expect("failed to build configured network"),
        initial_testnet_peers: [].into(),
        ..Config::default()
    };

    let serialized = toml::to_string(&config).unwrap();
    let deserialized: Config = toml::from_str(&serialized).unwrap();

    assert_eq!(config, deserialized);
}

#[test]
fn default_config_uses_ipv6() {
    let _init_guard = zebra_test::init();
    let config = Config::default();

    assert_eq!(config.listen_addr.to_string(), "[::]:8233");
    assert!(config.listen_addr.is_ipv6());
}

#[test]
fn funding_streams_serialization_roundtrip() {
    let _init_guard = zebra_test::init();

    let fs = testnet::Parameters::default()
        .funding_streams()
        .iter()
        .map(ConfiguredFundingStreams::from)
        .collect();

    let config = Config {
        network: testnet::Parameters::build()
            .with_funding_streams(fs)
            .to_network()
            .expect("failed to build configured network"),
        initial_testnet_peers: [].into(),
        ..Config::default()
    };

    let serialized = toml::to_string(&config).unwrap();
    let deserialized: Config = toml::from_str(&serialized).unwrap();

    assert_eq!(config, deserialized);
}

/// Checks that a configured Testnet's temporary Orchard-disabling soft fork height
/// survives a serialization round-trip.
#[test]
fn temporary_orchard_disabling_soft_fork_height_serialization_roundtrip() {
    let _init_guard = zebra_test::init();

    let soft_fork_height = Height(2_000_000);

    let config = Config {
        network: testnet::Parameters::build()
            .with_temporary_orchard_disabling_soft_fork_height(soft_fork_height)
            .to_network()
            .expect("failed to build configured network"),
        initial_testnet_peers: [].into(),
        ..Config::default()
    };

    let serialized = toml::to_string(&config).unwrap();
    let deserialized: Config = toml::from_str(&serialized).unwrap();

    assert_eq!(config, deserialized);

    // The configured height must be preserved through the round-trip.
    let Network::Testnet(params) = &deserialized.network else {
        panic!("deserialized network must be a Testnet");
    };
    assert_eq!(
        params.temporary_orchard_disabling_soft_fork_height(),
        Some(soft_fork_height),
    );
}

/// Checks that a Regtest configured to forbid unshielded coinbase spends survives a
/// serialization round-trip, and that the flag does not change the network's identity.
#[test]
fn regtest_should_allow_unshielded_coinbase_spends_serialization_roundtrip() {
    let _init_guard = zebra_test::init();

    let config = Config {
        network: Network::new_regtest(testnet::RegtestParameters {
            should_allow_unshielded_coinbase_spends: Some(false),
            ..Default::default()
        }),
        initial_testnet_peers: [].into(),
        ..Config::default()
    };

    // Forbidding unshielded coinbase spends must not stop the network from being Regtest.
    assert!(config.network.is_regtest());

    let serialized = toml::to_string(&config).unwrap();
    let deserialized: Config = toml::from_str(&serialized).unwrap();

    assert_eq!(config, deserialized);
    assert!(deserialized.network.is_regtest());

    let Network::Testnet(params) = &deserialized.network else {
        panic!("deserialized network must be Regtest");
    };
    assert!(!params.should_allow_unshielded_coinbase_spends());
}

/// Checks that the Regtest-only `should_allow_unshielded_coinbase_spends` knob is rejected
/// on a configured Testnet rather than silently ignored.
#[test]
fn should_allow_unshielded_coinbase_spends_rejected_on_testnet() {
    let _init_guard = zebra_test::init();

    let toml = "network = 'Testnet'\n\n[testnet_parameters]\nshould_allow_unshielded_coinbase_spends = true\n";
    let err = toml::from_str::<Config>(toml)
        .expect_err("configured Testnet must reject the Regtest-only field");

    assert!(
        err.to_string()
            .contains("should_allow_unshielded_coinbase_spends"),
        "unexpected error: {err}"
    );
}

/// A complete `[network]` section selecting the SWARM production network.
const SWARM_MAIN_CONFIG: &str = "\
network = 'SwarmMainnet'

[swarm_main]
genesis_hash = '0000000000000000000000000000000000000000000000000000000000000abc'
[swarm_main.funding_stream_addresses]
core_development = 's3SMKDUgQ2JoZxEArhrUw5ofKtZG5YjknAC'
grants_ecosystem = 's3X7hSqNZJJXDfq28SRQ7JvbJbF43vfGpiQ'
community_reserve = 's3Nv3ARoQTLNkhHhbShTP9pRjhRWBXVP7n4'
";

/// A complete SwarmMain configuration deserializes into the validated profile, and the listen
/// address defaults to the SWARM production P2P port.
#[test]
fn parse_complete_swarm_main_config() {
    let _init_guard = zebra_test::init();

    let config: Config = toml::from_str(SWARM_MAIN_CONFIG).expect("a complete config parses");

    assert!(config.network.is_swarm_main());
    assert!(!config.network.is_a_test_network());
    assert_eq!(config.network.to_string(), "SwarmMainnet");
    assert_eq!(config.listen_addr.port(), 28233);

    let params = config
        .network
        .swarm_main_parameters()
        .expect("the configured network is SwarmMain");
    assert_eq!(params.rpc_port(), 28232);
    assert_eq!(
        params.genesis_hash().to_string(),
        "0000000000000000000000000000000000000000000000000000000000000abc"
    );

    // No upstream seed peers are used: the upstream lists name Zcash DNS seeders.
    assert!(config.initial_peer_hostnames().is_empty());
}

/// SwarmMain seed peers come from `initial_swarm_main_peers`, and naming one takes the node out
/// of the "alone on its network" state that lets the first node of a new chain mine at once.
///
/// This is the difference between the node that starts the chain and every node that joins it:
/// with a peer named, the miner waits until the syncer says it is close to the tip, so a joining
/// node cannot mine onto a stale height it has not finished downloading.
#[test]
fn swarm_main_seed_peers_are_configurable() {
    let _init_guard = zebra_test::init();

    // The scalars go first: `SWARM_MAIN_CONFIG` ends inside a table.
    let alone: Config = toml::from_str(&format!("cache_dir = false\n{SWARM_MAIN_CONFIG}"))
        .expect("a complete config parses");
    assert!(alone.initial_peer_hostnames().is_empty());
    assert!(
        alone.has_no_peer_sources(),
        "a SwarmMain node with no seed list and no peer cache is alone on its network",
    );

    let joined: Config = toml::from_str(&format!(
        "cache_dir = false\ninitial_swarm_main_peers = ['zebra:28233', '10.0.0.7:28233']\n\
         {SWARM_MAIN_CONFIG}"
    ))
    .expect("a config naming SwarmMain peers parses");

    assert_eq!(
        joined.initial_peer_hostnames(),
        ["zebra:28233".to_string(), "10.0.0.7:28233".to_string()]
            .into_iter()
            .collect::<IndexSet<String>>(),
    );
    assert!(
        !joined.has_no_peer_sources(),
        "a SwarmMain node that names a peer is not alone: it must sync before it mines",
    );

    // The upstream lists are not consulted on SwarmMain, and the SWARM list is not consulted on
    // the upstream networks.
    let upstream: Config =
        toml::from_str("network = 'Mainnet'\ninitial_swarm_main_peers = ['zebra:28233']\n")
            .expect("the SWARM peer list parses on any network");
    assert!(!upstream.initial_peer_hostnames().contains("zebra:28233"));

    // A non-empty list survives a round trip; an empty one is not written out at all.
    let serialized = toml::to_string(&joined).expect("the config serializes");
    assert!(
        serialized.contains("initial_swarm_main_peers"),
        "configured SWARM peers must round trip:\n{serialized}"
    );
    let deserialized: Config = toml::from_str(&serialized).expect("the round trip parses");
    assert_eq!(
        joined.initial_peer_hostnames(),
        deserialized.initial_peer_hostnames()
    );

    assert!(
        !toml::to_string(&Config::default())
            .expect("the default config serializes")
            .contains("initial_swarm_main_peers"),
        "an empty SWARM peer list is not written into a Zcash operator's config",
    );
}

/// A SwarmMain configuration missing any required field fails to parse, with a message naming
/// what to fix. This happens during deserialization, so it happens before any listener is bound
/// or any database is opened.
#[test]
fn swarm_main_config_rejects_incomplete_definitions() {
    let _init_guard = zebra_test::init();

    // No `[swarm_main]` section at all.
    let error = toml::from_str::<Config>("network = 'SwarmMainnet'\n")
        .expect_err("a bare SwarmMainnet name must not parse");
    assert!(
        error.to_string().contains("[network.swarm_main]"),
        "the error must name the missing section, got: {error}"
    );

    // A section with no genesis hash.
    let no_genesis = SWARM_MAIN_CONFIG.replace(
        "genesis_hash = '0000000000000000000000000000000000000000000000000000000000000abc'\n",
        "",
    );
    let error =
        toml::from_str::<Config>(&no_genesis).expect_err("a missing genesis hash must not parse");
    assert!(
        error
            .to_string()
            .contains("genesis block hash is unresolved"),
        "the error must name the unresolved genesis, got: {error}"
    );

    // A section with a missing funding stream destination.
    let no_reserve = SWARM_MAIN_CONFIG.replace(
        "community_reserve = 's3Nv3ARoQTLNkhHhbShTP9pRjhRWBXVP7n4'\n",
        "",
    );
    let error = toml::from_str::<Config>(&no_reserve)
        .expect_err("a missing funding stream destination must not parse");
    assert!(
        error.to_string().contains("community_reserve"),
        "the error must name the missing destination key, got: {error}"
    );

    // A funding stream destination on another network.
    let testnet_recipient = SWARM_MAIN_CONFIG.replace(
        "s3SMKDUgQ2JoZxEArhrUw5ofKtZG5YjknAC",
        "t2DGVURG5tAyXXSkj85JV5xbvTobYv7H99n",
    );
    let error = toml::from_str::<Config>(&testnet_recipient)
        .expect_err("a testnet funding stream destination must not parse");
    assert!(
        error.to_string().contains("not a SwarmMain address"),
        "the error must say the address is on another network, got: {error}"
    );

    // Another network's genesis.
    let testnet_genesis = SWARM_MAIN_CONFIG.replace(
        "0000000000000000000000000000000000000000000000000000000000000abc",
        "045993f5c91ea160c7ebda573dd97b0016816bca68d395bfff202779b88e2a28",
    );
    let error = toml::from_str::<Config>(&testnet_genesis)
        .expect_err("the SWARM testnet genesis must not parse as SwarmMain's");
    assert!(
        error.to_string().contains("genesis of another network"),
        "the error must say the genesis belongs to another network, got: {error}"
    );
}

/// A `[swarm_main]` section on any other network is refused, so SWARM production values cannot
/// sit in the configuration of a node that is quietly running somewhere else.
#[test]
fn swarm_main_parameters_are_rejected_on_other_networks() {
    let _init_guard = zebra_test::init();

    let mismatched = SWARM_MAIN_CONFIG.replace("network = 'SwarmMainnet'", "network = 'Testnet'");
    let error = toml::from_str::<Config>(&mismatched)
        .expect_err("swarm_main parameters on Testnet must not parse");
    assert!(
        error
            .to_string()
            .contains("only valid when `network` is `SwarmMainnet`"),
        "the error must say the section is on the wrong network, got: {error}"
    );
}

/// The existing network configurations are unaffected by the new section.
#[test]
fn upstream_configs_are_unaffected_by_swarm_main() {
    let _init_guard = zebra_test::init();

    for (source, expected_port, is_test) in [
        ("", 8233, false),
        ("network = 'Mainnet'\n", 8233, false),
        ("network = 'Testnet'\n", 18233, true),
    ] {
        let config: Config = toml::from_str(source).expect("an upstream config parses");
        assert_eq!(config.listen_addr.port(), expected_port);
        assert_eq!(config.network.is_a_test_network(), is_test);
        assert!(!config.network.is_swarm_main());
        assert!(!config.initial_peer_hostnames().is_empty());
    }
}

/// A configured SwarmMain profile survives a serialization round trip with its required fields
/// intact: serializing it as the bare name would silently drop the genesis hash and the funding
/// stream destinations.
#[test]
fn swarm_main_config_serialization_roundtrip() {
    let _init_guard = zebra_test::init();

    let config: Config = toml::from_str(SWARM_MAIN_CONFIG).expect("a complete config parses");
    let serialized = toml::to_string(&config).expect("the config serializes");
    assert!(
        serialized.contains("s3SMKDUgQ2JoZxEArhrUw5ofKtZG5YjknAC"),
        "the serialized config must keep the funding stream destinations:\n{serialized}"
    );

    let deserialized: Config = toml::from_str(&serialized).expect("the round trip parses");
    assert_eq!(config.network, deserialized.network);
}
