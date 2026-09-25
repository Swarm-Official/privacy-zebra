use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryInto;
use core::fmt;
use core::str::FromStr;

#[cfg(feature = "std")]
use std::error::Error;

use bech32::{Bech32, Bech32m, Checksum, Hrp, primitives::decode::CheckedHrpstring};
use zcash_protocol::consensus::{NetworkConstants, NetworkType};
use zcash_protocol::constants::{mainnet, regtest, swarm_mainnet, testnet};

use crate::kind::unified::Encoding;
use crate::{AddressKind, ZcashAddress, kind::*};

/// An error while attempting to parse a string as a Zcash address.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The string is an invalid encoding.
    InvalidEncoding,
    /// The string is not a Zcash address.
    NotZcash,
    /// Errors specific to unified addresses.
    Unified(unified::ParseError),
}

impl From<unified::ParseError> for ParseError {
    fn from(e: unified::ParseError) -> Self {
        match e {
            unified::ParseError::InvalidEncoding(_) => Self::InvalidEncoding,
            unified::ParseError::UnknownPrefix(_) => Self::NotZcash,
            _ => Self::Unified(e),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidEncoding => write!(f, "Invalid encoding"),
            ParseError::NotZcash => write!(f, "Not a Zcash address"),
            ParseError::Unified(e) => e.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl Error for ParseError {}

impl FromStr for ZcashAddress {
    type Err = ParseError;

    /// Attempts to parse the given string as a Zcash address.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Remove leading and trailing whitespace, to handle copy-paste errors.
        let s = s.trim();

        // Try decoding as a unified address
        match unified::Address::decode(s) {
            Ok((net, data)) => {
                return Ok(ZcashAddress {
                    net,
                    kind: AddressKind::Unified(data),
                });
            }
            Err(unified::ParseError::NotUnified | unified::ParseError::UnknownPrefix(_)) => {
                // allow decoding to fall through to Sapling/TEX/Transparent
            }
            Err(e) => {
                return Err(ParseError::from(e));
            }
        }

        // Try decoding as a Sapling address (Bech32)
        if let Ok(parsed) = CheckedHrpstring::new::<Bech32>(s) {
            // If we reached this point, the encoding is found to be valid Bech32.
            let net = match parsed.hrp().as_str() {
                mainnet::HRP_SAPLING_PAYMENT_ADDRESS => NetworkType::Main,
                testnet::HRP_SAPLING_PAYMENT_ADDRESS => NetworkType::Test,
                regtest::HRP_SAPLING_PAYMENT_ADDRESS => NetworkType::Regtest,
                // The SWARM production network is a distinct network identity, not a new
                // Zcash address encoding; its HRP is disjoint from every arm above.
                swarm_mainnet::HRP_SAPLING_PAYMENT_ADDRESS => NetworkType::SwarmMain,
                // We will not define new Bech32 address encodings.
                _ => {
                    return Err(ParseError::NotZcash);
                }
            };

            let data = parsed.byte_iter().collect::<Vec<_>>();

            return data
                .try_into()
                .map(AddressKind::Sapling)
                .map_err(|_| ParseError::InvalidEncoding)
                .map(|kind| ZcashAddress { net, kind });
        }

        // Try decoding as a TEX address (Bech32m)
        if let Ok(parsed) = CheckedHrpstring::new::<Bech32m>(s) {
            // If we reached this point, the encoding is found to be valid Bech32m.
            let net = match parsed.hrp().as_str() {
                mainnet::HRP_TEX_ADDRESS => NetworkType::Main,
                testnet::HRP_TEX_ADDRESS => NetworkType::Test,
                regtest::HRP_TEX_ADDRESS => NetworkType::Regtest,
                swarm_mainnet::HRP_TEX_ADDRESS => NetworkType::SwarmMain,
                // Not recognized as a Zcash address type
                _ => {
                    return Err(ParseError::NotZcash);
                }
            };

            let data = parsed.byte_iter().collect::<Vec<_>>();

            return data
                .try_into()
                .map(AddressKind::Tex)
                .map_err(|_| ParseError::InvalidEncoding)
                .map(|kind| ZcashAddress { net, kind });
        }

        // The rest use Base58Check.
        if let Ok(decoded) = bs58::decode(s).with_check(None).into_vec()
            && decoded.len() >= 2
        {
            let (prefix, net) = match decoded[..2].try_into().unwrap() {
                prefix @ (mainnet::B58_PUBKEY_ADDRESS_PREFIX
                | mainnet::B58_SCRIPT_ADDRESS_PREFIX
                | mainnet::B58_SPROUT_ADDRESS_PREFIX) => (prefix, NetworkType::Main),
                prefix @ (testnet::B58_PUBKEY_ADDRESS_PREFIX
                | testnet::B58_SCRIPT_ADDRESS_PREFIX
                | testnet::B58_SPROUT_ADDRESS_PREFIX) => (prefix, NetworkType::Test),
                // The SWARM production network. Sprout is deliberately absent: it is not
                // supported on SwarmMain, so `swarm_mainnet::B58_SPROUT_ADDRESS_PREFIX`
                // never parses.
                prefix @ (swarm_mainnet::B58_PUBKEY_ADDRESS_PREFIX
                | swarm_mainnet::B58_SCRIPT_ADDRESS_PREFIX) => (prefix, NetworkType::SwarmMain),
                // We will not define new Base58Check address encodings.
                _ => return Err(ParseError::NotZcash),
            };

            return match prefix {
                mainnet::B58_SPROUT_ADDRESS_PREFIX | testnet::B58_SPROUT_ADDRESS_PREFIX => {
                    decoded[2..].try_into().map(AddressKind::Sprout)
                }
                mainnet::B58_PUBKEY_ADDRESS_PREFIX
                | testnet::B58_PUBKEY_ADDRESS_PREFIX
                | swarm_mainnet::B58_PUBKEY_ADDRESS_PREFIX => {
                    decoded[2..].try_into().map(AddressKind::P2pkh)
                }
                mainnet::B58_SCRIPT_ADDRESS_PREFIX
                | testnet::B58_SCRIPT_ADDRESS_PREFIX
                | swarm_mainnet::B58_SCRIPT_ADDRESS_PREFIX => {
                    decoded[2..].try_into().map(AddressKind::P2sh)
                }
                _ => unreachable!(),
            }
            .map_err(|_| ParseError::InvalidEncoding)
            .map(|kind| ZcashAddress { kind, net });
        };

        // If it's not valid Bech32, Bech32m, or Base58Check, it's not a Zcash address.
        Err(ParseError::NotZcash)
    }
}

fn encode_bech32<Ck: Checksum>(hrp: &str, data: &[u8]) -> String {
    bech32::encode::<Ck>(Hrp::parse_unchecked(hrp), data).expect("encoding is short enough")
}

fn encode_b58(prefix: [u8; 2], data: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(2 + data.len());
    bytes.extend_from_slice(&prefix);
    bytes.extend_from_slice(data);
    bs58::encode(bytes).with_check().into_string()
}

impl fmt::Display for ZcashAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = match &self.kind {
            AddressKind::Sprout(data) => encode_b58(self.net.b58_sprout_address_prefix(), data),
            AddressKind::Sapling(data) => {
                encode_bech32::<Bech32>(self.net.hrp_sapling_payment_address(), data)
            }
            AddressKind::Unified(addr) => addr.encode(&self.net),
            AddressKind::P2pkh(data) => encode_b58(self.net.b58_pubkey_address_prefix(), data),
            AddressKind::P2sh(data) => encode_b58(self.net.b58_script_address_prefix(), data),
            AddressKind::Tex(data) => encode_bech32::<Bech32m>(self.net.hrp_tex_address(), data),
        };
        write!(f, "{encoded}")
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use assert_matches::assert_matches;

    use super::*;
    use crate::kind::unified;
    use crate::kind::unified::private::SealedContainer;
    use zcash_protocol::consensus::NetworkType;

    fn encoding(encoded: &str, decoded: ZcashAddress) {
        if encoded.starts_with("utest1") {
            let canonical = decoded.to_string();
            assert!(canonical.starts_with("swarm1"));
            assert_eq!(canonical.parse(), Ok(decoded.clone()));
        } else {
            assert_eq!(decoded.to_string(), encoded);
        }
        assert_eq!(encoded.parse(), Ok(decoded));
    }

    #[test]
    fn sprout() {
        encoding(
            "zc8E5gYid86n4bo2Usdq1cpr7PpfoJGzttwBHEEgGhGkLUg7SPPVFNB2AkRFXZ7usfphup5426dt1buMmY3fkYeRrQGLa8y",
            ZcashAddress {
                net: NetworkType::Main,
                kind: AddressKind::Sprout([0; 64]),
            },
        );
        encoding(
            "ztJ1EWLKcGwF2S4NA17pAJVdco8Sdkz4AQPxt1cLTEfNuyNswJJc2BbBqYrsRZsp31xbVZwhF7c7a2L9jsF3p3ZwRWpqqyS",
            ZcashAddress {
                net: NetworkType::Test,
                kind: AddressKind::Sprout([0; 64]),
            },
        );
    }

    #[test]
    fn sapling() {
        encoding(
            "zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpq6d8g",
            ZcashAddress {
                net: NetworkType::Main,
                kind: AddressKind::Sapling([0; 43]),
            },
        );
        encoding(
            "ztestsapling1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfhgwqu",
            ZcashAddress {
                net: NetworkType::Test,
                kind: AddressKind::Sapling([0; 43]),
            },
        );
        encoding(
            "zregtestsapling1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqknpr3m",
            ZcashAddress {
                net: NetworkType::Regtest,
                kind: AddressKind::Sapling([0; 43]),
            },
        );
    }

    #[test]
    fn unified() {
        encoding(
            "u1qpatys4zruk99pg59gcscrt7y6akvl9vrhcfyhm9yxvxz7h87q6n8cgrzzpe9zru68uq39uhmlpp5uefxu0su5uqyqfe5zp3tycn0ecl",
            ZcashAddress {
                net: NetworkType::Main,
                kind: AddressKind::Unified(unified::Address(vec![
                    unified::address::Receiver::Sapling([0; 43]),
                ])),
            },
        );
        encoding(
            "utest10c5kutapazdnf8ztl3pu43nkfsjx89fy3uuff8tsmxm6s86j37pe7uz94z5jhkl49pqe8yz75rlsaygexk6jpaxwx0esjr8wm5ut7d5s",
            ZcashAddress {
                net: NetworkType::Test,
                kind: AddressKind::Unified(unified::Address(vec![
                    unified::address::Receiver::Sapling([0; 43]),
                ])),
            },
        );
        encoding(
            "uregtest15xk7vj4grjkay6mnfl93dhsflc2yeunhxwdh38rul0rq3dfhzzxgm5szjuvtqdha4t4p2q02ks0jgzrhjkrav70z9xlvq0plpcjkd5z3",
            ZcashAddress {
                net: NetworkType::Regtest,
                kind: AddressKind::Unified(unified::Address(vec![
                    unified::address::Receiver::Sapling([0; 43]),
                ])),
            },
        );

        let badencoded = "uinvalid1ck5navqwcng43gvsxwrxsplc22p7uzlcag6qfa0zh09e87efq6rq8wsnv25umqjjravw70rl994n5ueuhza2fghge5gl7zrl2qp6cwmp";
        assert_eq!(
            badencoded.parse::<ZcashAddress>(),
            Err(ParseError::NotZcash)
        );
    }

    #[test]
    fn transparent() {
        encoding(
            "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs",
            ZcashAddress {
                net: NetworkType::Main,
                kind: AddressKind::P2pkh([0; 20]),
            },
        );
        encoding(
            "tm9iMLAuYMzJ6jtFLcA7rzUmfreGuKvr7Ma",
            ZcashAddress {
                net: NetworkType::Test,
                kind: AddressKind::P2pkh([0; 20]),
            },
        );
        encoding(
            "t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ",
            ZcashAddress {
                net: NetworkType::Main,
                kind: AddressKind::P2sh([0; 20]),
            },
        );
        encoding(
            "t26YoyZ1iPgiMEWL4zGUm74eVWfhyDMXzY2",
            ZcashAddress {
                net: NetworkType::Test,
                kind: AddressKind::P2sh([0; 20]),
            },
        );
    }

    #[test]
    fn tex() {
        let p2pkh_str = "t1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC";
        let tex_str = "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte";

        // Transcode P2PKH to TEX
        let p2pkh_zaddr: ZcashAddress = p2pkh_str.parse().unwrap();
        assert_matches!(p2pkh_zaddr.net, NetworkType::Main);
        if let AddressKind::P2pkh(zaddr_data) = p2pkh_zaddr.kind {
            let tex_zaddr = ZcashAddress {
                net: p2pkh_zaddr.net,
                kind: AddressKind::Tex(zaddr_data),
            };

            assert_eq!(tex_zaddr.to_string(), tex_str);
        } else {
            panic!("Decoded address should have been a P2PKH address.");
        }

        // Transcode TEX to P2PKH
        let tex_zaddr: ZcashAddress = tex_str.parse().unwrap();
        assert_matches!(tex_zaddr.net, NetworkType::Main);
        if let AddressKind::Tex(zaddr_data) = tex_zaddr.kind {
            let p2pkh_zaddr = ZcashAddress {
                net: tex_zaddr.net,
                kind: AddressKind::P2pkh(zaddr_data),
            };

            assert_eq!(p2pkh_zaddr.to_string(), p2pkh_str);
        } else {
            panic!("Decoded address should have been a TEX address.");
        }
    }

    #[test]
    fn tex_testnet() {
        let p2pkh_str = "tm9ofD7kHR7AF8MsJomEzLqGcrLCBkD9gDj";
        let tex_str = "textest1qyqszqgpqyqszqgpqyqszqgpqyqszqgpfcjgfy";

        // Transcode P2PKH to TEX
        let p2pkh_zaddr: ZcashAddress = p2pkh_str.parse().unwrap();
        assert_matches!(p2pkh_zaddr.net, NetworkType::Test);
        if let AddressKind::P2pkh(zaddr_data) = p2pkh_zaddr.kind {
            let tex_zaddr = ZcashAddress {
                net: p2pkh_zaddr.net,
                kind: AddressKind::Tex(zaddr_data),
            };

            assert_eq!(tex_zaddr.to_string(), tex_str);
        } else {
            panic!("Decoded address should have been a P2PKH address.");
        }

        // Transcode TEX to P2PKH
        let tex_zaddr: ZcashAddress = tex_str.parse().unwrap();
        assert_matches!(tex_zaddr.net, NetworkType::Test);
        if let AddressKind::Tex(zaddr_data) = tex_zaddr.kind {
            let p2pkh_zaddr = ZcashAddress {
                net: tex_zaddr.net,
                kind: AddressKind::P2pkh(zaddr_data),
            };

            assert_eq!(p2pkh_zaddr.to_string(), p2pkh_str);
        } else {
            panic!("Decoded address should have been a TEX address.");
        }
    }

    // ---------------------------------------------------------------------------
    // SWARM production network (`NetworkType::SwarmMain`).
    //
    // Golden vectors come from `Mainnet identity constants research 2026-09-25`
    // (transparent) and from the single PROVISIONAL HRP root in
    // `zcash_protocol::constants::swarm_mainnet`. The historical SWARM testnet strings
    // used in the negative tests come from `network/swarm-testnet/DESTINATIONS.md`.
    // ---------------------------------------------------------------------------

    /// The three SwarmTestnet funding-stream destinations and the baseline miner
    /// payout address, exactly as published in `network/swarm-testnet/DESTINATIONS.md`.
    const SWARM_TESTNET_P2SH: &[&str] = &[
        "t2DGVURG5tAyXXSkj85JV5xbvTobYv7H99n",
        "t2LVPzRYpZ4QtRRmQMS1zWUmG7TZaYcMjBR",
        "t2UHhsicXnapNJrfewHqgwXef5HDwCHd7wk",
        "t2Li46A4YNFqRDvdKA212w7DtsLkbGMG2xU",
    ];

    /// A `TryFromAddress` target that accepts every address kind, so that
    /// `convert_if_network` exercises only the network check.
    #[derive(Debug, PartialEq, Eq)]
    struct AnyAddress;

    impl crate::TryFromAddress for AnyAddress {
        type Error = &'static str;

        fn try_from_sprout(
            _net: NetworkType,
            _data: [u8; 64],
        ) -> Result<Self, crate::ConversionError<Self::Error>> {
            Ok(AnyAddress)
        }

        fn try_from_sapling(
            _net: NetworkType,
            _data: [u8; 43],
        ) -> Result<Self, crate::ConversionError<Self::Error>> {
            Ok(AnyAddress)
        }

        fn try_from_unified(
            _net: NetworkType,
            _data: unified::Address,
        ) -> Result<Self, crate::ConversionError<Self::Error>> {
            Ok(AnyAddress)
        }

        fn try_from_transparent_p2pkh(
            _net: NetworkType,
            _data: [u8; 20],
        ) -> Result<Self, crate::ConversionError<Self::Error>> {
            Ok(AnyAddress)
        }

        fn try_from_transparent_p2sh(
            _net: NetworkType,
            _data: [u8; 20],
        ) -> Result<Self, crate::ConversionError<Self::Error>> {
            Ok(AnyAddress)
        }

        fn try_from_tex(
            _net: NetworkType,
            _data: [u8; 20],
        ) -> Result<Self, crate::ConversionError<Self::Error>> {
            Ok(AnyAddress)
        }
    }

    /// Asserts that `encoded` parses, but is refused when the caller asks for `net`.
    fn rejected_for(encoded: &str, net: NetworkType) {
        let addr: ZcashAddress = encoded
            .parse()
            .unwrap_or_else(|e| panic!("{encoded} should still parse: {e:?}"));
        assert_ne!(addr.net, net, "{encoded} must not be a {net:?} address");
        assert_matches!(
            addr.convert_if_network::<AnyAddress>(net),
            Err(crate::ConversionError::IncorrectNetwork { .. }),
            "{encoded} must be refused when {net:?} is expected",
        );
    }

    /// Golden: the two transparent sample encodings from the constants research.
    #[test]
    fn swarm_main_transparent() {
        encoding(
            "s1MCkDhVejM4RqDyRR1rEJkudd26FVWipPD",
            ZcashAddress {
                net: NetworkType::SwarmMain,
                kind: AddressKind::P2pkh([0; 20]),
            },
        );
        encoding(
            "s3Mtm9Ez6HFNovPfrY7WpjPGZmYNxztrxbb",
            ZcashAddress {
                net: NetworkType::SwarmMain,
                kind: AddressKind::P2sh([0; 20]),
            },
        );
    }

    /// Golden: the Sapling and TEX encodings derived from the PROVISIONAL HRP root.
    #[test]
    fn swarm_main_sapling_and_tex() {
        encoding(
            "zsvmsapling1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq32jyug",
            ZcashAddress {
                net: NetworkType::SwarmMain,
                kind: AddressKind::Sapling([0; 43]),
            },
        );
        encoding(
            "texsvm1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0e5x6p",
            ZcashAddress {
                net: NetworkType::SwarmMain,
                kind: AddressKind::Tex([0; 20]),
            },
        );
    }

    /// Golden: a unified address round trips under `SwarmMain` and is distinct from the
    /// same receivers encoded for every other network.
    #[test]
    fn swarm_main_unified_round_trip() {
        let kind =
            AddressKind::Unified(unified::Address(vec![unified::address::Receiver::Sapling(
                [0; 43],
            )]));
        let addr = ZcashAddress {
            net: NetworkType::SwarmMain,
            kind: kind.clone(),
        };

        let encoded = addr.to_string();
        assert!(
            encoded.starts_with("svm1"),
            "unexpected SWARM production unified prefix: {encoded}",
        );
        assert_eq!(encoded.parse(), Ok(addr));

        for other in [NetworkType::Main, NetworkType::Test, NetworkType::Regtest] {
            let other_encoded = ZcashAddress {
                net: other,
                kind: kind.clone(),
            }
            .to_string();
            assert_ne!(encoded, other_encoded);
            // and the other network's string never decodes as SwarmMain
            let parsed: ZcashAddress = other_encoded.parse().unwrap();
            assert_ne!(parsed.net, NetworkType::SwarmMain);
        }
    }

    /// Negative: every historical SWARM testnet encoding is refused for `SwarmMain`.
    #[test]
    fn swarm_testnet_encodings_are_rejected_for_swarm_main() {
        // Unified: the legacy `utest1...` alias and its canonical `swarm1...` form.
        let utest = "utest10c5kutapazdnf8ztl3pu43nkfsjx89fy3uuff8tsmxm6s86j37pe7uz94z5jhkl49pqe8yz75rlsaygexk6jpaxwx0esjr8wm5ut7d5s";
        let swarm1 = utest.parse::<ZcashAddress>().unwrap().to_string();
        assert!(
            swarm1.starts_with("swarm1"),
            "unexpected canonical: {swarm1}"
        );
        rejected_for(utest, NetworkType::SwarmMain);
        rejected_for(&swarm1, NetworkType::SwarmMain);

        // Sapling and transparent testnet encodings.
        rejected_for(
            "ztestsapling1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfhgwqu",
            NetworkType::SwarmMain,
        );
        rejected_for(
            "tm9iMLAuYMzJ6jtFLcA7rzUmfreGuKvr7Ma",
            NetworkType::SwarmMain,
        );
        rejected_for(
            "t26YoyZ1iPgiMEWL4zGUm74eVWfhyDMXzY2",
            NetworkType::SwarmMain,
        );
        for addr in SWARM_TESTNET_P2SH {
            let parsed: ZcashAddress = addr.parse().unwrap();
            assert_eq!(
                parsed.net,
                NetworkType::Test,
                "{addr} is a SwarmTestnet address",
            );
            rejected_for(addr, NetworkType::SwarmMain);
        }

        // The unified viewing-key HRPs of the testnet, and their legacy aliases, must
        // never resolve to the SWARM production network.
        for hrp in [
            "swarm",
            "utest",
            "uviewswarm",
            "uviewtest",
            "uivkswarm",
            "uivktest",
        ] {
            assert_ne!(
                <unified::Address as SealedContainer>::hrp_network(hrp),
                Some(NetworkType::SwarmMain),
            );
            assert_ne!(
                <unified::Ufvk as SealedContainer>::hrp_network(hrp),
                Some(NetworkType::SwarmMain),
            );
            assert_ne!(
                <unified::Uivk as SealedContainer>::hrp_network(hrp),
                Some(NetworkType::SwarmMain),
            );
        }
    }

    /// Negative: SWARM production encodings are refused for `Test`, `Regtest` and `Main`.
    #[test]
    fn swarm_main_encodings_are_rejected_for_other_networks() {
        let unified_svm = ZcashAddress {
            net: NetworkType::SwarmMain,
            kind: AddressKind::Unified(unified::Address(vec![
                unified::address::Receiver::Sapling([0; 43]),
            ])),
        }
        .to_string();

        for encoded in [
            "s1MCkDhVejM4RqDyRR1rEJkudd26FVWipPD",
            "s3Mtm9Ez6HFNovPfrY7WpjPGZmYNxztrxbb",
            "zsvmsapling1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq32jyug",
            "texsvm1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0e5x6p",
            unified_svm.as_str(),
        ] {
            for net in [NetworkType::Main, NetworkType::Test, NetworkType::Regtest] {
                rejected_for(encoded, net);
            }
        }

        // The SWARM production unified HRPs never resolve to another network.
        for hrp in ["svm", "uviewsvm", "uivksvm"] {
            for resolved in [
                <unified::Address as SealedContainer>::hrp_network(hrp),
                <unified::Ufvk as SealedContainer>::hrp_network(hrp),
                <unified::Uivk as SealedContainer>::hrp_network(hrp),
            ] {
                assert!(
                    resolved.is_none() || resolved == Some(NetworkType::SwarmMain),
                    "{hrp} resolved to {resolved:?}",
                );
            }
        }
    }

    /// Negative: Sprout is not supported on `SwarmMain`, so its placeholder prefix does
    /// not decode at all.
    #[test]
    fn swarm_main_sprout_is_not_an_address() {
        let sprout = "2EqJRP64tuw6vyc5SodsJ3bVKSsDEE5uLaRkjMJBoyXinouuQjfQupwqAvBkJUSBCjzhCefffWVBxHjrxEDJyQFELqCVJxdE";
        assert_eq!(sprout.parse::<ZcashAddress>(), Err(ParseError::NotZcash));
    }

    #[test]
    fn whitespace() {
        assert_eq!(
            " t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs".parse(),
            Ok(ZcashAddress {
                net: NetworkType::Main,
                kind: AddressKind::P2pkh([0; 20])
            }),
        );
        assert_eq!(
            "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs ".parse(),
            Ok(ZcashAddress {
                net: NetworkType::Main,
                kind: AddressKind::P2pkh([0; 20])
            }),
        );
        assert_eq!(
            "something t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs".parse::<ZcashAddress>(),
            Err(ParseError::NotZcash),
        );
    }
}
