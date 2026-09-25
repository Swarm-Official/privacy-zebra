//! `zcash_address` conversion to `zebra_chain` address types.
//!
//! Usage: <https://docs.rs/zcash_address/0.2.0/zcash_address/trait.TryFromAddress.html#examples>

use zcash_address::unified::{self, Container};
use zcash_protocol::consensus::NetworkType;

use crate::{parameters::NetworkKind, transparent, BoxError};

/// A [`NetworkType`] that `zebra_chain` has no [`NetworkKind`] for.
///
/// Every [`NetworkType`] the shared protocol crates define now has a [`NetworkKind`], including
/// [`NetworkType::SwarmMain`], which maps to [`NetworkKind::SwarmMainnet`]. This error is kept so
/// that the conversion stays fallible: a new protocol-crate network type must be given an
/// explicit kind here rather than falling through to `Mainnet` or `Testnet`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("network type {0:?} has no zebra network kind")]
pub struct UnsupportedNetworkType(pub NetworkType);

/// Zcash address variants
pub enum Address {
    /// Transparent address
    Transparent(transparent::Address),

    /// Sapling address
    Sapling {
        /// Address' network kind
        network: NetworkKind,

        /// Sapling address
        address: sapling_crypto::PaymentAddress,
    },

    /// Unified address
    Unified {
        /// Address' network kind
        network: NetworkKind,

        /// Unified address
        unified_address: zcash_address::unified::Address,

        /// Orchard address
        orchard: Option<orchard::Address>,

        /// Sapling address
        sapling: Option<sapling_crypto::PaymentAddress>,

        /// Transparent address
        transparent: Option<transparent::Address>,
    },
}

impl zcash_address::TryFromAddress for Address {
    // TODO: crate::serialization::SerializationError
    type Error = BoxError;

    fn try_from_transparent_p2pkh(
        network: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        Ok(Self::Transparent(transparent::Address::from_pub_key_hash(
            NetworkKind::try_from(network).map_err(BoxError::from)?,
            data,
        )))
    }

    fn try_from_transparent_p2sh(
        network: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        Ok(Self::Transparent(transparent::Address::from_script_hash(
            NetworkKind::try_from(network).map_err(BoxError::from)?,
            data,
        )))
    }

    fn try_from_sapling(
        network: NetworkType,
        data: [u8; 43],
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        let network = NetworkKind::try_from(network).map_err(BoxError::from)?;
        sapling_crypto::PaymentAddress::from_bytes(&data)
            .map(|address| Self::Sapling { address, network })
            .ok_or_else(|| BoxError::from("not a valid sapling address").into())
    }

    fn try_from_unified(
        network: NetworkType,
        unified_address: zcash_address::unified::Address,
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        let network = NetworkKind::try_from(network).map_err(BoxError::from)?;
        let mut orchard = None;
        let mut sapling = None;
        let mut transparent = None;

        for receiver in unified_address.items().into_iter() {
            match receiver {
                unified::Receiver::Orchard(data) => {
                    orchard = orchard::Address::from_raw_address_bytes(&data).into();
                    // ZIP 316: Consumers MUST reject Unified Addresses/Viewing Keys in
                    // which any constituent Item does not meet the validation
                    // requirements of its encoding.
                    if orchard.is_none() {
                        return Err(BoxError::from(
                            "Unified Address contains an invalid Orchard receiver.",
                        )
                        .into());
                    }
                }
                unified::Receiver::Sapling(data) => {
                    sapling = sapling_crypto::PaymentAddress::from_bytes(&data);
                    // ZIP 316: Consumers MUST reject Unified Addresses/Viewing Keys in
                    // which any constituent Item does not meet the validation
                    // requirements of its encoding.
                    if sapling.is_none() {
                        return Err(BoxError::from(
                            "Unified Address contains an invalid Sapling receiver",
                        )
                        .into());
                    }
                }
                unified::Receiver::P2pkh(data) => {
                    transparent = Some(transparent::Address::from_pub_key_hash(network, data));
                }
                unified::Receiver::P2sh(data) => {
                    transparent = Some(transparent::Address::from_script_hash(network, data));
                }
                unified::Receiver::Unknown { .. } => {
                    return Err(BoxError::from("Unsupported receiver in a Unified Address.").into());
                }
            }
        }

        Ok(Self::Unified {
            network,
            unified_address,
            orchard,
            sapling,
            transparent,
        })
    }

    /// # Correctness
    ///
    /// [`NetworkType::SwarmMain`] is refused. ZIP-320 assigns a TEX address its own two-byte
    /// version prefix per network, and SWARM has no reviewed assignment, so a SWARM TEX address
    /// has no encoding this node could serialize back out. Accepting one here would build an
    /// address that cannot round-trip; see `NetworkKind::tex_address_prefix`.
    fn try_from_tex(
        network: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        if network == NetworkType::SwarmMain {
            return Err(BoxError::from(
                "TEX addresses are not defined for the SWARM production network",
            )
            .into());
        }

        Ok(Self::Transparent(transparent::Address::from_tex(
            NetworkKind::try_from(network).map_err(BoxError::from)?,
            data,
        )))
    }
}

impl Address {
    /// Returns the network for the address.
    pub fn network(&self) -> NetworkKind {
        match &self {
            Self::Transparent(address) => address.network_kind(),
            Self::Sapling { network, .. } | Self::Unified { network, .. } => *network,
        }
    }

    /// Returns true if the address is PayToScriptHash
    /// Returns false if the address is PayToPublicKeyHash or shielded.
    pub fn is_script_hash(&self) -> bool {
        match &self {
            Self::Transparent(address) => address.is_script_hash(),
            Self::Sapling { .. } | Self::Unified { .. } => false,
        }
    }

    /// Returns true if address is of the [`Address::Transparent`] variant.
    /// Returns false if otherwise.
    pub fn is_transparent(&self) -> bool {
        matches!(self, Self::Transparent(_))
    }

    /// Returns the payment address for transparent or sapling addresses.
    pub fn payment_address(&self) -> Option<String> {
        use zcash_address::{ToAddress, ZcashAddress};

        match &self {
            Self::Transparent(address) => Some(address.to_string()),
            Self::Sapling { address, network } => {
                let data = address.to_bytes();
                let address = ZcashAddress::from_sapling(network.into(), data);
                Some(address.encode())
            }
            Self::Unified { .. } => None,
        }
    }
}

impl TryFrom<NetworkType> for NetworkKind {
    type Error = UnsupportedNetworkType;

    fn try_from(network: NetworkType) -> Result<Self, Self::Error> {
        Ok(match network {
            NetworkType::Main => NetworkKind::Mainnet,
            NetworkType::Test => NetworkKind::Testnet,
            NetworkType::Regtest => NetworkKind::Regtest,
            // Deliberately its own kind, never Mainnet or Testnet: a SWARM production address
            // that silently became a Zcash address is exactly the cross-network confusion this
            // variant exists to prevent.
            NetworkType::SwarmMain => NetworkKind::SwarmMainnet,
        })
    }
}

impl From<NetworkKind> for NetworkType {
    fn from(network: NetworkKind) -> Self {
        match network {
            NetworkKind::Mainnet => NetworkType::Main,
            NetworkKind::Testnet => NetworkType::Test,
            NetworkKind::Regtest => NetworkType::Regtest,
            NetworkKind::SwarmMainnet => NetworkType::SwarmMain,
        }
    }
}

impl From<&NetworkKind> for NetworkType {
    fn from(network: &NetworkKind) -> Self {
        (*network).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use zcash_address::{TryFromAddress, ZcashAddress};

    /// The existing network kinds must keep converting both ways, byte for byte.
    #[test]
    fn upstream_network_kinds_round_trip() {
        for (net, kind) in [
            (NetworkType::Main, NetworkKind::Mainnet),
            (NetworkType::Test, NetworkKind::Testnet),
            (NetworkType::Regtest, NetworkKind::Regtest),
        ] {
            assert_eq!(NetworkKind::try_from(net), Ok(kind));
            assert_eq!(NetworkType::from(kind), net);
        }
    }

    /// The SWARM production network type converts to its own `NetworkKind`, and never to
    /// Mainnet or Testnet.
    #[test]
    fn swarm_main_converts_to_its_own_network_kind() {
        assert_eq!(
            NetworkKind::try_from(NetworkType::SwarmMain),
            Ok(NetworkKind::SwarmMainnet),
        );
        assert_eq!(
            NetworkType::from(NetworkKind::SwarmMainnet),
            NetworkType::SwarmMain,
        );

        // A SWARM production address converts to a zebra address whose kind is SwarmMainnet, and
        // re-encodes to the very same string. Both halves matter: the first says the address is
        // usable, the second says it is not silently re-encoded under another network's prefix.
        for (encoded, is_script_hash) in [
            ("s1MCkDhVejM4RqDyRR1rEJkudd26FVWipPD", false),
            ("s3Mtm9Ez6HFNovPfrY7WpjPGZmYNxztrxbb", true),
        ] {
            let parsed: ZcashAddress = encoded.parse().expect("parses in zcash_address");
            let address = parsed.convert::<Address>().expect("converts for zebra");
            assert_eq!(address.network(), NetworkKind::SwarmMainnet);
            assert_ne!(address.network(), NetworkKind::Mainnet);
            assert_ne!(address.network(), NetworkKind::Testnet);
            assert_eq!(address.is_script_hash(), is_script_hash);
            assert_eq!(address.payment_address().as_deref(), Some(encoded));
        }
    }

    /// TEX addresses are refused on the SWARM production network: ZIP-320 assigns their version
    /// prefix per network and SWARM has no reviewed assignment, so an accepted one could not be
    /// serialized back out.
    #[test]
    fn swarm_main_tex_addresses_are_refused() {
        let error = <Address as TryFromAddress>::try_from_tex(NetworkType::SwarmMain, [0u8; 20])
            .err()
            .expect("a SWARM TEX address must be refused");
        assert!(
            format!("{error:?}").contains("not defined for the SWARM production network"),
            "the error must say TEX is undefined for SWARM, got: {error:?}"
        );

        // The upstream networks still accept them.
        for network in [NetworkType::Main, NetworkType::Test] {
            <Address as TryFromAddress>::try_from_tex(network, [0u8; 20])
                .unwrap_or_else(|error| panic!("{network:?} must still accept TEX: {error:?}"));
        }
    }

    /// A SWARM production address and a Zcash address are mutually unreadable: neither decodes
    /// under the other's network kind. This is the transparent half of the two-way separation.
    #[test]
    fn swarm_main_and_upstream_transparent_addresses_are_disjoint() {
        let swarm = [
            "s1MCkDhVejM4RqDyRR1rEJkudd26FVWipPD",
            "s3Mtm9Ez6HFNovPfrY7WpjPGZmYNxztrxbb",
        ];
        let upstream = [
            "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs",
            "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd",
            "t2DGVURG5tAyXXSkj85JV5xbvTobYv7H99n",
        ];

        for encoded in swarm {
            let address: transparent::Address =
                encoded.parse().expect("a SWARM address parses for zebra");
            assert_eq!(address.network_kind(), NetworkKind::SwarmMainnet);
        }

        for encoded in upstream {
            let address: transparent::Address = encoded
                .parse()
                .expect("an upstream address parses for zebra");
            assert_ne!(
                address.network_kind(),
                NetworkKind::SwarmMainnet,
                "{encoded} must not decode as a SwarmMain address",
            );
        }
    }

    /// The published SwarmTestnet destinations keep converting as Testnet addresses.
    #[test]
    fn swarm_testnet_destinations_still_convert() {
        for encoded in [
            "t2DGVURG5tAyXXSkj85JV5xbvTobYv7H99n",
            "t2LVPzRYpZ4QtRRmQMS1zWUmG7TZaYcMjBR",
            "t2UHhsicXnapNJrfewHqgwXef5HDwCHd7wk",
            "t2Li46A4YNFqRDvdKA212w7DtsLkbGMG2xU",
        ] {
            let parsed: ZcashAddress = encoded.parse().expect("parses in zcash_address");
            let address = parsed.convert::<Address>().expect("converts for zebra");
            assert_eq!(address.network(), NetworkKind::Testnet);
            assert!(address.is_script_hash());
            assert_eq!(address.payment_address().as_deref(), Some(encoded));
        }
    }
}
