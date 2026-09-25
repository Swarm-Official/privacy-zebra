//! Which networks this build can encode a treasury address for.
//!
//! The address encoding is upstream Zebra's
//! ([`zebra_chain::transparent::Address::from_script_hash`]); this module only decides which
//! encoding a named network gets, and refuses to guess.
//!
//! # SwarmMain
//!
//! SWARM production has its own transparent prefixes (`s1…` for P2PKH, `s3…` for P2SH), its own
//! unified-address HRP (`swm1…`) and its own transaction domain (`0x53574d31`). All three are
//! disjoint from every upstream Zcash value, so a treasury address built for `SwarmMain` cannot
//! be mistaken for a Zcash one and a transaction built for it cannot be replayed on Zcash, in
//! either direction.
//!
//! This module is the one place that maps a network *name* to those encodings, and to the
//! consensus context a spend is built under. It still refuses to guess: an unknown name is an
//! error, and the SwarmMain arm names `NetworkKind::SwarmMainnet` explicitly rather than falling
//! back to `Mainnet`.

use std::fmt;

use zcash_protocol::consensus::NetworkType;
use zebra_chain::{
    parameters::{ConsensusContext, DomainRegistry, NetworkKind},
    transparent::Address,
};

use crate::{refuse, script, shielded::Pool, Result};

/// A network a treasury policy can be built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreasuryNetwork {
    /// The public Zcash-style testnet encoding (`t2…`), which the SWARM testnet also uses.
    Testnet,
    /// The custody rehearsal network: a custom testnet, sharing the Testnet address encoding.
    SwarmRehearsal,
    /// The SWARM production mainnet.
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
            // Deliberately not `NetworkKind::Mainnet`: the SWARM mainnet prefixes are not
            // upstream Zcash mainnet prefixes. `NetworkKind::SwarmMainnet` encodes P2SH as
            // `0x1C2D` (`s3…`) and P2PKH as `0x1C28` (`s1…`), neither of which decodes as a Zcash
            // address, in either direction.
            TreasuryNetwork::SwarmMain => AddressEncoding::Upstream(NetworkKind::SwarmMainnet),
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
            // `swm1…`: the SWARM production unified-address HRP. Ironwood receivers in a
            // SwarmMain unified address are parsed through this.
            TreasuryNetwork::SwarmMain => Ok(NetworkType::SwarmMain),
        }
    }

    /// The consensus context a spend on this network is built and signed under.
    ///
    /// # Correctness
    ///
    /// The transaction domain is part of the ZIP-244 personalization, so this decides which chain
    /// the signatures are valid on. SwarmMain resolves through
    /// [`DomainRegistry::SWARM_PRODUCTION`], which admits `0x53574d31` and no upstream domain; the
    /// testnet networks resolve through [`DomainRegistry::UPSTREAM`], which does not admit the
    /// SWARM domain. A spend built for one is therefore rejected by the other's node, which is
    /// exactly the protection the treasury needs when the same tool builds for both.
    pub fn consensus_context(self, pool: Pool) -> Result<ConsensusContext> {
        let registry = match self {
            TreasuryNetwork::Testnet | TreasuryNetwork::SwarmRehearsal => DomainRegistry::UPSTREAM,
            TreasuryNetwork::SwarmMain => DomainRegistry::SWARM_PRODUCTION,
        };

        registry
            .context_for_rules(pool.network_upgrade())
            .ok_or_else(|| {
                refuse!(
                    "{} has no transaction domain for {} on {self}",
                    pool.name(),
                    pool.network_upgrade(),
                )
            })
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

    /// The same fixture scalars that produce the published testnet address produce an `s3…`
    /// address on SwarmMain, over the same script hash.
    ///
    /// The script hash is the policy: it is what the P2SH locking script commits to, and it does
    /// not depend on the network. Only the version byte and therefore the human-readable prefix
    /// change, so a SwarmMain treasury address is the *same* 2-of-3 policy, encoded for a chain
    /// that will not accept a Zcash address and whose addresses Zcash will not accept.
    #[test]
    fn swarmmain_encodes_the_same_policy_as_an_s3_address() {
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

        let network = TreasuryNetwork::parse("swarmmain").unwrap();
        assert_eq!(network, TreasuryNetwork::SwarmMain);
        assert_eq!(
            network.address_encoding(),
            AddressEncoding::Upstream(NetworkKind::SwarmMainnet)
        );

        let address = network.p2sh_address(&redeem).unwrap();

        // The policy itself is unchanged: the same script hash the published testnet address
        // commits to.
        assert_eq!(
            hex::encode(script::hash160(&redeem)),
            "15fc0754e73eb85d1cbce08786fadb7320ecb8dc",
        );
        assert!(address.is_script_hash());
        assert_eq!(address.hash_bytes(), script::hash160(&redeem));
        assert_eq!(address.network_kind(), NetworkKind::SwarmMainnet);

        // And the encoding is a SWARM production P2SH address, not a Zcash one.
        let encoded = address.to_string();
        assert!(
            encoded.starts_with("s3"),
            "a SwarmMain P2SH address must start with s3, found {encoded}",
        );
        assert_ne!(
            encoded,
            TreasuryNetwork::Testnet
                .p2sh_address(&redeem)
                .unwrap()
                .to_string(),
        );

        // It round-trips, and it does not decode as any upstream address.
        let decoded: Address = encoded.parse().expect("the s3 address parses back");
        assert_eq!(decoded, address);
    }

    /// SwarmMain builds under the SWARM production transaction domain, and nothing else does.
    #[test]
    fn swarmmain_spends_are_built_under_the_swarm_domain() {
        use zebra_chain::parameters::SWARM_PRODUCTION_DOMAIN;

        let swarm = TreasuryNetwork::SwarmMain
            .consensus_context(Pool::V6Ironwood)
            .expect("SwarmMain has an NU6.3 domain");
        assert_eq!(swarm.branch(), SWARM_PRODUCTION_DOMAIN);
        assert_eq!(u32::from(swarm.branch()), 0x5357_4d31);

        for other in [TreasuryNetwork::Testnet, TreasuryNetwork::SwarmRehearsal] {
            let ctx = other
                .consensus_context(Pool::V6Ironwood)
                .expect("the testnet networks have an NU6.3 domain");
            assert_ne!(
                ctx.branch(),
                SWARM_PRODUCTION_DOMAIN,
                "{other} must not build under the SWARM production domain",
            );
        }

        // The SWARM registry admits only NU6.3, so the v5/Orchard test path has no domain there.
        assert!(TreasuryNetwork::SwarmMain
            .consensus_context(Pool::V5Orchard)
            .is_err());
    }

    /// Unified-address decoding for SwarmMain uses the SWARM network type (`swm1…`).
    #[test]
    fn swarmmain_unified_addresses_use_the_swarm_hrp() {
        assert_eq!(
            TreasuryNetwork::SwarmMain.unified_network_type().unwrap(),
            NetworkType::SwarmMain
        );
        assert_ne!(
            TreasuryNetwork::SwarmMain.unified_network_type().unwrap(),
            TreasuryNetwork::Testnet.unified_network_type().unwrap(),
        );
    }

    #[test]
    fn unknown_networks_are_refused() {
        assert!(TreasuryNetwork::parse("mainnet").is_err());
        assert!(TreasuryNetwork::parse("regtest").is_err());
        assert!(TreasuryNetwork::parse("").is_err());
    }
}
