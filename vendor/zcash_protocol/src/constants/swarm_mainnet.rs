//! Constants for the SWARM production network (`NetworkType::SwarmMain`).
//!
//! This is **not** Zcash Mainnet and **not** any test network. Every value below is
//! SWARM-owned and deliberately disjoint from the upstream `mainnet`, `testnet` and
//! `regtest` modules, so that a string encoded for one network can never be decoded
//! as another.
//!
//! Provenance of the values: `Mainnet identity constants research 2026-09-25` and
//! `Mainnet identity proposal 2026-09-25`.
//!
//! No consensus activation heights or branch IDs live here: the SWARM production
//! schedule is admitted by P1c, not by this crate.

/// The **single** source of truth for the SWARM production Bech32m HRP root.
///
/// CONFIRMED by the owner on 2026-09-25 as `swm`, matching the SWM ticker. The earlier
/// `svm` was provisional and is superseded; it was never published, so nothing encoded
/// with it exists to migrate. Every SWARM production HRP in this module is derived from
/// this macro, so the root is still a one-line change.
///
/// The root must be lowercase US-ASCII, must not contain `1`, and must be at most 16
/// characters (the ZIP 316 padding length). `swarm_mainnet_hrp_root_is_usable` in the
/// tests of this crate asserts those properties.
macro_rules! swarm_mainnet_hrp_root {
    () => {
        "swm"
    };
}

/// The SWARM production Bech32m HRP root, as a constant.
///
/// `swm`, owner-confirmed on 2026-09-25. See the `swarm_mainnet_hrp_root!` macro above:
/// this is the one value the whole module derives from.
pub const HRP_ROOT: &str = swarm_mainnet_hrp_root!();

/// The SWARM production coin type, as it will be registered in [SLIP 44].
///
/// Confirmed unregistered in `slip-0044.md` on 2026-09-25; the registration PR is
/// filed separately, so until it merges this is a private convention.
///
/// [SLIP 44]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
pub const COIN_TYPE: u32 = 9767;

/// The HRP for a Bech32-encoded SWARM production Sapling `ExtendedSpendingKey`.
///
/// SWARM testnet did not fork the Sapling HRPs away from upstream
/// (it still uses `secret-extended-key-test`), so there is no existing SWARM
/// derivation to mirror. This follows the upstream shape
/// `secret-extended-key-<network tag>` with the SWARM HRP root as the tag.
pub const HRP_SAPLING_EXTENDED_SPENDING_KEY: &str =
    concat!("secret-extended-key-", swarm_mainnet_hrp_root!());

/// The HRP for a Bech32-encoded SWARM production Sapling `ExtendedFullViewingKey`.
///
/// Derived from the owner-confirmed HRP root, like [`HRP_SAPLING_EXTENDED_SPENDING_KEY`]. This
/// follows the upstream non-mainnet shape `zxview<network tag>sapling`.
pub const HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY: &str =
    concat!("zxview", swarm_mainnet_hrp_root!(), "sapling");

/// The HRP for a Bech32-encoded SWARM production Sapling `PaymentAddress`.
///
/// Derived from the owner-confirmed HRP root, like [`HRP_SAPLING_EXTENDED_SPENDING_KEY`]. This
/// follows the upstream non-mainnet shape `z<network tag>sapling`, giving a string
/// that cannot be confused with Zcash `zs…`, `ztestsapling…` or `zregtestsapling…`.
pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = concat!("z", swarm_mainnet_hrp_root!(), "sapling");

/// The prefix that a Base58Check-encoded SWARM production Sprout address *would* use.
///
/// Sprout is not supported on the SWARM production network: this value exists only so
/// that `NetworkConstants` stays total, and it is deliberately **not** recognised by
/// the `zcash_address` decoder, so a string produced with it fails to parse instead of
/// being mistaken for a Zcash address. `0x1c2f` is inside the unclaimed `0x1c2x`
/// sub-range checked in the constants research.
pub const B58_SPROUT_ADDRESS_PREFIX: [u8; 2] = [0x1c, 0x2f];

/// The prefix for a Base58Check-encoded DER-encoded SWARM production `SecretKey`.
///
/// PROVISIONAL. Nothing in this repository encodes or decodes WIF secret keys, so this
/// value has no on-chain effect today; it is chosen to be distinct from the well-known
/// WIF prefixes (Bitcoin/Zcash main `0x80`, Bitcoin/Zcash test `0xef`, Litecoin `0xb0`,
/// Dash `0xcc`, Komodo `0xbc`) and must be reviewed before the identity freeze.
pub const B58_SECRET_KEY_PREFIX: [u8; 1] = [0x91];

/// The prefix for a Base58Check-encoded SWARM production transparent `PublicKeyHash`.
///
/// `0x1c28` encodes as `s1…`. Verified in the constants research against Zcash,
/// Bitcoin, Litecoin, Dash, Komodo and Horizen: no collision.
pub const B58_PUBKEY_ADDRESS_PREFIX: [u8; 2] = [0x1c, 0x28];

/// The prefix for a Base58Check-encoded SWARM production transparent `ScriptHash`.
///
/// `0x1c2d` encodes as `s3…`. Verified in the constants research against Zcash,
/// Bitcoin, Litecoin, Dash, Komodo and Horizen: no collision.
pub const B58_SCRIPT_ADDRESS_PREFIX: [u8; 2] = [0x1c, 0x2d];

/// The HRP for a Bech32m-encoded SWARM production [ZIP 320] TEX address.
///
/// Derived from the SWARM HRP root the same way upstream derives `textest` and
/// `texregtest` from their network tags.
///
/// [ZIP 320]: https://zips.z.cash/zip-0320
pub const HRP_TEX_ADDRESS: &str = concat!("tex", swarm_mainnet_hrp_root!());

/// The HRP for a Bech32m-encoded SWARM production Unified Address.
///
/// This is the HRP root itself, mirroring how the vendored testnet uses the bare
/// `swarm` HRP for its unified addresses. It must never be added as an alias of any
/// other network.
///
/// Defined in [ZIP 316][zip-0316].
///
/// [zip-0316]: https://zips.z.cash/zip-0316
pub const HRP_UNIFIED_ADDRESS: &str = swarm_mainnet_hrp_root!();

/// The HRP for a Bech32m-encoded SWARM production Unified FVK.
///
/// Derived from the HRP root exactly as the vendored testnet derives `uviewswarm`
/// from `swarm`.
///
/// Defined in [ZIP 316][zip-0316].
///
/// [zip-0316]: https://zips.z.cash/zip-0316
pub const HRP_UNIFIED_FVK: &str = concat!("uview", swarm_mainnet_hrp_root!());

/// The HRP for a Bech32m-encoded SWARM production Unified IVK.
///
/// Derived from the HRP root exactly as the vendored testnet derives `uivkswarm`
/// from `swarm`.
///
/// Defined in [ZIP 316][zip-0316].
///
/// [zip-0316]: https://zips.z.cash/zip-0316
pub const HRP_UNIFIED_IVK: &str = concat!("uivk", swarm_mainnet_hrp_root!());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{mainnet, regtest, testnet};

    /// The HRP root has to satisfy BIP 173/350 and the ZIP 316 padding limit, and it
    /// must not collide with any HRP of another network.
    #[test]
    fn swarm_mainnet_hrp_root_is_usable() {
        assert!(!HRP_ROOT.is_empty());
        assert!(HRP_ROOT.len() <= 16, "ZIP 316 padding is 16 bytes");
        assert!(
            HRP_ROOT
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "HRP must be lowercase US-ASCII",
        );
        assert!(!HRP_ROOT.contains('1'), "`1` is the bech32 separator");
    }

    /// Nothing SWARM-production may be equal to an upstream or testnet constant.
    #[test]
    fn swarm_mainnet_constants_are_disjoint() {
        for other in [
            mainnet::HRP_UNIFIED_ADDRESS,
            mainnet::HRP_UNIFIED_FVK,
            mainnet::HRP_UNIFIED_IVK,
            mainnet::HRP_TEX_ADDRESS,
            mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            testnet::HRP_UNIFIED_ADDRESS,
            testnet::HRP_UNIFIED_FVK,
            testnet::HRP_UNIFIED_IVK,
            testnet::HRP_TEX_ADDRESS,
            testnet::HRP_SAPLING_PAYMENT_ADDRESS,
            regtest::HRP_UNIFIED_ADDRESS,
            regtest::HRP_UNIFIED_FVK,
            regtest::HRP_UNIFIED_IVK,
            regtest::HRP_TEX_ADDRESS,
            regtest::HRP_SAPLING_PAYMENT_ADDRESS,
            // The historical testnet aliases that the unified codec still accepts.
            "utest",
            "uviewtest",
            "uivktest",
        ] {
            for ours in [
                HRP_UNIFIED_ADDRESS,
                HRP_UNIFIED_FVK,
                HRP_UNIFIED_IVK,
                HRP_TEX_ADDRESS,
                HRP_SAPLING_PAYMENT_ADDRESS,
            ] {
                assert_ne!(ours, other, "SWARM production HRP collides with {other}");
            }
        }

        for other in [
            mainnet::B58_PUBKEY_ADDRESS_PREFIX,
            mainnet::B58_SCRIPT_ADDRESS_PREFIX,
            mainnet::B58_SPROUT_ADDRESS_PREFIX,
            testnet::B58_PUBKEY_ADDRESS_PREFIX,
            testnet::B58_SCRIPT_ADDRESS_PREFIX,
            testnet::B58_SPROUT_ADDRESS_PREFIX,
        ] {
            assert_ne!(B58_PUBKEY_ADDRESS_PREFIX, other);
            assert_ne!(B58_SCRIPT_ADDRESS_PREFIX, other);
            assert_ne!(B58_SPROUT_ADDRESS_PREFIX, other);
        }

        assert_ne!(COIN_TYPE, mainnet::COIN_TYPE);
        assert_ne!(COIN_TYPE, testnet::COIN_TYPE);
    }

    /// The derived HRPs must follow the same rule the vendored testnet uses.
    #[test]
    fn swarm_mainnet_unified_hrps_are_derived_from_the_root() {
        assert_eq!(HRP_UNIFIED_ADDRESS, HRP_ROOT);
        assert_eq!(HRP_UNIFIED_FVK, format!("uview{HRP_ROOT}"));
        assert_eq!(HRP_UNIFIED_IVK, format!("uivk{HRP_ROOT}"));
        assert_eq!(HRP_TEX_ADDRESS, format!("tex{HRP_ROOT}"));
        // The same rule the vendored testnet applies: testnet's own unified HRPs are
        // `swarm` / `uviewswarm` / `uivkswarm`.
        assert_eq!(testnet::HRP_UNIFIED_FVK, "uviewswarm");
        assert_eq!(testnet::HRP_UNIFIED_IVK, "uivkswarm");
    }
}
