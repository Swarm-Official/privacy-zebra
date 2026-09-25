//! Tests for funding streams.

#![allow(clippy::unwrap_in_result)]

use std::collections::HashMap;

use color_eyre::Report;
use zebra_chain::amount::Amount;
use zebra_chain::parameters::NetworkUpgrade::*;
use zebra_chain::parameters::{subsidy::FundingStreamReceiver, NetworkKind};

use super::*;

/// Checks that the Mainnet funding stream values are correct.
#[test]
fn test_funding_stream_values() -> Result<(), Report> {
    let _init_guard = zebra_test::init();
    let network = &Network::Mainnet;

    let canopy_activation_height = Canopy.activation_height(network).unwrap();
    let nu6_activation_height = Nu6.activation_height(network).unwrap();
    let nu6_1_activation_height = Nu6_1.activation_height(network).unwrap();

    let dev_fund_height_range = network.all_funding_streams()[0].height_range();
    let nu6_fund_height_range = network.all_funding_streams()[1].height_range();
    let nu6_1_fund_height_range = network.all_funding_streams()[2].height_range();

    let nu6_fund_end = Height(3_146_400);
    let nu6_1_fund_end = Height(4_406_400);

    assert_eq!(canopy_activation_height, Height(1_046_400));
    assert_eq!(nu6_activation_height, Height(2_726_400));
    assert_eq!(nu6_1_activation_height, Height(3_146_400));

    assert_eq!(dev_fund_height_range.start, canopy_activation_height);
    assert_eq!(dev_fund_height_range.end, nu6_activation_height);

    assert_eq!(nu6_fund_height_range.start, nu6_activation_height);
    assert_eq!(nu6_fund_height_range.end, nu6_fund_end);

    assert_eq!(nu6_1_fund_height_range.start, nu6_1_activation_height);
    assert_eq!(nu6_1_fund_height_range.end, nu6_1_fund_end);

    assert_eq!(dev_fund_height_range.end, nu6_fund_height_range.start);

    let mut expected_dev_fund = HashMap::new();

    expected_dev_fund.insert(FundingStreamReceiver::Ecc, Amount::try_from(21_875_000)?);
    expected_dev_fund.insert(
        FundingStreamReceiver::ZcashFoundation,
        Amount::try_from(15_625_000)?,
    );
    expected_dev_fund.insert(
        FundingStreamReceiver::MajorGrants,
        Amount::try_from(25_000_000)?,
    );
    let expected_dev_fund = expected_dev_fund;

    let mut expected_nu6_fund = HashMap::new();
    expected_nu6_fund.insert(
        FundingStreamReceiver::Deferred,
        Amount::try_from(18_750_000)?,
    );
    expected_nu6_fund.insert(
        FundingStreamReceiver::MajorGrants,
        Amount::try_from(12_500_000)?,
    );
    let expected_nu6_fund = expected_nu6_fund;

    for height in [
        dev_fund_height_range.start.previous().unwrap(),
        dev_fund_height_range.start,
        dev_fund_height_range.start.next().unwrap(),
        dev_fund_height_range.end.previous().unwrap(),
        dev_fund_height_range.end,
        dev_fund_height_range.end.next().unwrap(),
        nu6_fund_height_range.start.previous().unwrap(),
        nu6_fund_height_range.start,
        nu6_fund_height_range.start.next().unwrap(),
        nu6_fund_height_range.end.previous().unwrap(),
        nu6_fund_height_range.end,
        nu6_fund_height_range.end.next().unwrap(),
        nu6_1_fund_height_range.start.previous().unwrap(),
        nu6_1_fund_height_range.start,
        nu6_1_fund_height_range.start.next().unwrap(),
        nu6_1_fund_height_range.end.previous().unwrap(),
        nu6_1_fund_height_range.end,
        nu6_1_fund_height_range.end.next().unwrap(),
    ] {
        let fsv = funding_stream_values(height, network, block_subsidy(height, network)?).unwrap();

        if height < canopy_activation_height {
            assert!(fsv.is_empty());
        } else if height < nu6_activation_height {
            assert_eq!(fsv, expected_dev_fund);
        } else if height < nu6_1_fund_end {
            // NU6 and NU6.1 funding streams are in the same halving and expected to have the same values
            assert_eq!(fsv, expected_nu6_fund);
        } else {
            assert!(fsv.is_empty());
        }
    }

    Ok(())
}

/// Check mainnet and testnet funding stream addresses are valid transparent P2SH addresses.
#[test]
fn test_funding_stream_addresses() -> Result<(), Report> {
    let _init_guard = zebra_test::init();
    for network in Network::iter() {
        for (receiver, recipient) in network
            .all_funding_streams()
            .iter()
            .flat_map(|fs| fs.recipients())
        {
            for address in recipient.addresses() {
                let expected_network_kind = match network.kind() {
                    NetworkKind::Mainnet => NetworkKind::Mainnet,
                    // `Regtest` uses `Testnet` transparent addresses.
                    NetworkKind::Testnet | NetworkKind::Regtest => NetworkKind::Testnet,
                    // Unlike `Regtest`, SwarmMain has its own transparent prefixes and never
                    // borrows another network's. `Network::iter()` does not yield it, because it
                    // has no default; its funding stream addresses are checked by
                    // `swarm_main::tests::builder_accepts_a_complete_definition`.
                    NetworkKind::SwarmMainnet => NetworkKind::SwarmMainnet,
                };

                assert_eq!(
                    address.network_kind(),
                    expected_network_kind,
                    "incorrect network for {receiver:?} funding stream address constant: {address}",
                );

                assert!(
                    address.is_script_hash(),
                    "funding stream address is not P2SH: {address}"
                );

                let _script = address.script();
            }
        }
    }

    Ok(())
}

//Test if funding streams ranges do not overlap
#[test]
fn test_funding_stream_ranges_dont_overlap() -> Result<(), Report> {
    let _init_guard = zebra_test::init();
    for network in Network::iter() {
        let funding_streams = network.all_funding_streams();
        // This is quadratic but it's fine since the number of funding streams is small.
        for i in 0..funding_streams.len() {
            for j in (i + 1)..funding_streams.len() {
                let range_a = funding_streams[i].height_range();
                let range_b = funding_streams[j].height_range();
                assert!(
                    // https://stackoverflow.com/a/325964
                    !(range_a.start < range_b.end && range_b.start < range_a.end),
                    "Funding streams {i} and {j} overlap: {range_a:?} and {range_b:?}",
                );
            }
        }
    }
    Ok(())
}

/// The SWARM production funding stream destinations must resolve at every height in the range,
/// including past the first upstream address-rotation boundary.
///
/// SWARM configures exactly one address per recipient for the whole range, while the upstream
/// formula assumes 48 rotating ones. Before this was special-cased, `funding_stream_address_index`
/// computed index 1 into a one-element slice at height 35_001 (`post_blossom_halving_interval /
/// 48` past the range start) and the `assert!` there aborted the node.
#[test]
fn swarm_main_funding_stream_addresses_resolve_at_every_height() -> Result<(), Report> {
    let _init_guard = zebra_test::init();

    let network = zebra_chain::parameters::swarm_main::fixture::network();
    let receivers = [
        FundingStreamReceiver::Ecc,
        FundingStreamReceiver::MajorGrants,
        FundingStreamReceiver::ZcashFoundation,
    ];

    // Height 1 is the range start; 35_000 and 35_001 straddle the first upstream address period
    // boundary; the rest are later periods and the last height in the range.
    for height in [
        1, 2, 100, 34_999, 35_000, 35_001, 70_001, 1_680_001, 50_399_998,
    ] {
        let height = Height(height);
        for receiver in receivers {
            let address = funding_stream_address(height, &network, receiver)
                .unwrap_or_else(|| panic!("{receiver:?} must have an address at {height:?}"));

            assert_eq!(
                address.network_kind(),
                NetworkKind::SwarmMainnet,
                "a SWARM funding stream must never pay to another network's address"
            );
            assert!(
                address.to_string().starts_with("s3"),
                "SWARM funding stream destinations are P2SH: {address}"
            );

            // The destination does not rotate: it is the same one the profile configured.
            assert_eq!(
                Some(address),
                funding_stream_address(Height(1), &network, receiver)
            );
        }
    }

    // Past the end of the range there is no funding stream at all, and no panic.
    assert_eq!(
        funding_stream_address(Height(50_399_999), &network, FundingStreamReceiver::Ecc),
        None
    );

    Ok(())
}
