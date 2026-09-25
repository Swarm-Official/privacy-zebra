//! `zcash_address` conversion to `zebra_chain` address types.
//!
//! Usage: <https://docs.rs/zcash_address/0.2.0/zcash_address/trait.TryFromAddress.html#examples>

use zcash_address::unified::{self, Container};
use zcash_protocol::consensus::NetworkType;

use crate::{parameters::NetworkKind, transparent, BoxError};

/// A [`NetworkType`] that `zebra_chain` has no [`NetworkKind`] for.
///
/// Today this is only [`NetworkType::SwarmMain`]: the SWARM production network type
/// exists in the shared protocol crates (so its address encodings can be defined and
/// tested) but the node has no production network profile yet. Converting it silently
/// into `Mainnet` or `Testnet` would be exactly the cross-network confusion this
/// variant exists to prevent, so the conversion fails instead.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("network type {0:?} has no zebra network kind: production schedule admitted by P1c")]
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

    fn try_from_tex(
        network: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
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
            // Deliberately NOT mapped to Mainnet or Testnet: production schedule
            // admitted by P1c. Until the node has a SWARM production network profile,
            // a `SwarmMain` address has no `NetworkKind` and must be refused.
            NetworkType::SwarmMain => return Err(UnsupportedNetworkType(network)),
        })
    }
}

impl From<NetworkKind> for NetworkType {
    fn from(network: NetworkKind) -> Self {
        match network {
            NetworkKind::Mainnet => NetworkType::Main,
            NetworkKind::Testnet => NetworkType::Test,
            NetworkKind::Regtest => NetworkType::Regtest,
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

    /// The SWARM production network type has no `NetworkKind`, so a `SwarmMain` address
    /// can never be converted into a zebra address and treated as Mainnet or Testnet.
    #[test]
    fn swarm_main_has_no_network_kind() {
        assert_eq!(
            NetworkKind::try_from(NetworkType::SwarmMain),
            Err(UnsupportedNetworkType(NetworkType::SwarmMain)),
        );

        // The shared crate parses SWARM production encodings ...
        for encoded in [
            "s1MCkDhVejM4RqDyRR1rEJkudd26FVWipPD",
            "s3Mtm9Ez6HFNovPfrY7WpjPGZmYNxztrxbb",
        ] {
            let parsed: ZcashAddress = encoded.parse().expect("parses in zcash_address");
            // ... and zebra refuses to convert them into one of its own address types.
            assert!(
                parsed.convert::<Address>().is_err(),
                "{encoded} must not convert to a zebra address",
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
