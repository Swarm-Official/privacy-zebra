//! Which networks this build can encode a treasury address for.
//!
//! The address encoding is upstream Zebra's
//! ([`zebra_chain::transparent::Address::from_script_hash`]); this module only decides which
//! encoding a named network gets, and refuses to guess.
//!
//! # SwarmMain
//!
//! The SWARM mainnet address prefixes live on another branch. Rather than quietly handing back a
//! Testnet address — which would be a real way to lose real money — [`TreasuryNetwork::SwarmMain`]
//! is accepted as a *name* everywhere and refused at the point where an encoding is needed. When
//! the mainnet prefixes land, the only change required here is to give `SwarmMain` a
//! [`NetworkKind`] (or its own encoder) in [`TreasuryNetwork::address_encoding`].

use std::fmt;

use zcash_protocol::consensus::NetworkType;
use zebra_chain::{parameters::NetworkKind, transparent::Address};

use crate::{refuse, script, Result};

/// A network a treasury policy can be built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreasuryNetwork {
    /// The public Zcash-style testnet encoding (`t2…`), which the SWARM testnet also uses.
    Testnet,
    /// The custody rehearsal network: a custom testnet, sharing the Testnet address encoding.
    SwarmRehearsal,
    /// The SWARM production mainnet.
    ///
    /// Named here so policies and proposals can record it, but **not encodable in this build**.
    SwarmMain,
}

/// How a network's transparent addresses are encoded, when this build knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressEncoding {
    /// An upstream Zebra [`NetworkKind`] encoding.
    Upstream(NetworkKind),
    /// This build has no encoder for the network.
    NotAvailable,
}

impl TreasuryNetwork {
    /// Parses the command-line name of a network.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "testnet" => Ok(TreasuryNetwork::Testnet),
            "swarmrehearsal" => Ok(TreasuryNetwork::SwarmRehearsal),
            "swarmmain" => Ok(TreasuryNetwork::SwarmMain),
            other => Err(refuse!(
                "unknown network {other:?}; expected testnet, swarmrehearsal or swarmmain"
            )),
        }
    }

    /// The name this network is written as, in files and on the command line.
    pub fn name(self) -> &'static str {
        match self {
            TreasuryNetwork::Testnet => "testnet",
            TreasuryNetwork::SwarmRehearsal => "swarmrehearsal",
            TreasuryNetwork::SwarmMain => "swarmmain",
        }
    }

    /// The address encoding this build uses for the network, if it has one.
    pub fn address_encoding(self) -> AddressEncoding {
        match self {
            // The rehearsal network is a custom testnet: same address encoding as Testnet.
            TreasuryNetwork::Testnet | TreasuryNetwork::SwarmRehearsal => {
                AddressEncoding::Upstream(NetworkKind::Testnet)
            }
            // Deliberately not `NetworkKind::Mainnet`: the SWARM mainnet prefixes are not upstream
            // Zcash mainnet prefixes, and emitting a wrong-network address is worse than failing.
            TreasuryNetwork::SwarmMain => AddressEncoding::NotAvailable,
        }
    }

    /// The upstream [`NetworkKind`] for the network, or an explicit refusal.
    pub fn network_kind(self) -> Result<NetworkKind> {
        match self.address_encoding() {
            AddressEncoding::Upstream(kind) => Ok(kind),
            AddressEncoding::NotAvailable => Err(refuse!(
                "the {} address encoding is not available in this build: \
                 the SWARM mainnet address prefixes are on another branch, and this tool will not \
                 hand back a testnet address for a mainnet policy",
                self.name(),
            )),
        }
    }

    /// The unified-address network type used when decoding a shielded recipient address.
    pub fn unified_network_type(self) -> Result<NetworkType> {
        match self {
            TreasuryNetwork::Testnet | TreasuryNetwork::SwarmRehearsal => Ok(NetworkType::Test),
            TreasuryNetwork::SwarmMain => Err(refuse!(
                "unified address decoding for {} is not available in this build",
                self.name(),
            )),
        }
    }

    /// The P2SH address for a redeem script on this network.
    pub fn p2sh_address(self, redeem_script: &[u8]) -> Result<Address> {
        let kind = self.network_kind()?;
        Ok(Address::from_script_hash(
            kind,
            script::hash160(redeem_script),
        ))
    }
}

impl fmt::Display for TreasuryNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published `swarm-keytool` 2-of-3 address, reproduced through this module.
    #[test]
    fn published_testnet_address() {
        let keys = [
            script::parse_public_key(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            )
            .unwrap(),
            script::parse_public_key(
                "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            )
            .unwrap(),
            script::parse_public_key(
                "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            )
            .unwrap(),
        ];
        let redeem = script::redeem_script(2, &keys).unwrap();

        assert_eq!(
            TreasuryNetwork::Testnet
                .p2sh_address(&redeem)
                .unwrap()
                .to_string(),
            "t28Z45qZRaD6zXBMFHTzEN7pZfGeZTtbkFp",
        );
        assert_eq!(
            TreasuryNetwork::SwarmRehearsal
                .p2sh_address(&redeem)
                .unwrap()
                .to_string(),
            "t28Z45qZRaD6zXBMFHTzEN7pZfGeZTtbkFp",
            "the rehearsal network shares the testnet encoding",
        );
    }

    /// `swarmmain` is a name this build accepts and an encoding it refuses.
    #[test]
    fn swarmmain_is_named_but_not_encodable() {
        let network = TreasuryNetwork::parse("swarmmain").unwrap();
        assert_eq!(network, TreasuryNetwork::SwarmMain);
        assert_eq!(network.address_encoding(), AddressEncoding::NotAvailable);

        let error = network.p2sh_address(&[0u8; 105]).unwrap_err().to_string();
        assert!(
            error.contains("not available in this build"),
            "the refusal must say the encoding is missing, not produce an address: {error}",
        );
        assert!(
            !error.starts_with("t2"),
            "a mainnet policy must never be handed a testnet address",
        );
    }

    #[test]
    fn unknown_networks_are_refused() {
        assert!(TreasuryNetwork::parse("mainnet").is_err());
        assert!(TreasuryNetwork::parse("regtest").is_err());
        assert!(TreasuryNetwork::parse("").is_err());
    }
}
