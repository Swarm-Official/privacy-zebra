//! Mining config

use std::{collections::HashMap, ops::Deref};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, DisplayFromStr};

use strum_macros::EnumIter;
use zcash_address::ZcashAddress;
use zcash_transparent::coinbase::{MAX_COINBASE_HEIGHT_LEN, MAX_COINBASE_SCRIPT_LEN};
use zebra_chain::parameters::NetworkKind;

/// The maximum length of the optional, arbitrary data in the script sig field of a coinbase tx.
pub(crate) const MAX_MINER_DATA_LEN: usize = MAX_COINBASE_SCRIPT_LEN - MAX_COINBASE_HEIGHT_LEN;

/// The marker Zebra prepends to the coinbase input of every block it builds.
///
/// The zebra emoji (`U+1F993`), 4 UTF-8 bytes.
pub(crate) const ZEBRA_COINBASE_MARKER: &str = "🦓";

/// Separates [`ZEBRA_COINBASE_MARKER`] from `extra_coinbase_data`. Present only when that is set.
pub(crate) const ZEBRA_COINBASE_SEPARATOR: &str = ": ";

/// The maximum length of the user-configurable `extra_coinbase_data`.
///
/// The coinbase data is the marker, separator, and user data in a single push, so the user
/// portion is [`MAX_MINER_DATA_LEN`] minus the marker, separator, and the 2-byte `OP_PUSHDATA1`
/// opcode (for pushes over 75 bytes).
pub(crate) const MAX_USER_COINBASE_DATA_LEN: usize =
    MAX_MINER_DATA_LEN - ZEBRA_COINBASE_MARKER.len() - ZEBRA_COINBASE_SEPARATOR.len() - 2;

/// Mining configuration section.
#[serde_as]
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Address for receiving miner subsidy and tx fees.
    ///
    /// Used in coinbase tx constructed in `getblocktemplate` RPC.
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub miner_address: Option<ZcashAddress>,

    /// Optional tag that Zebra appends to the coinbase input of every block it builds, after the
    /// Zebra `🦓` marker and a `: ` separator.
    ///
    /// Limited to `MAX_USER_COINBASE_DATA_LEN` bytes.
    pub extra_coinbase_data: Option<ExtraCoinbaseData>,

    /// Optional shielded memo that Zebra will include in the output of a shielded coinbase
    /// transaction. Limited to 512 bytes.
    ///
    /// Applies only if [`Self::miner_address`] contains a shielded component.
    pub miner_memo: Option<String>,

    /// Mine blocks using Zebra's internal miner, without an external mining pool or equihash solver.
    ///
    /// This experimental feature is only supported on regtest as it uses null solutions and skips checking
    /// for a valid Proof of Work.
    ///
    /// The internal miner is off by default.
    #[serde(default)]
    pub internal_miner: bool,

    /// How many Equihash solver threads the internal miner runs.
    ///
    /// The node builds one block template — including a shielded coinbase, when
    /// [`Self::miner_address`] is a unified address — and each solver searches a
    /// different nonce range of that same template. Only the search is duplicated,
    /// so this is a solver setting and not a consensus one: the block that is
    /// submitted is the same block whichever thread happened to find it.
    ///
    /// Each thread uses one CPU core and about 144 MB of RAM. Zebra caps the value
    /// at the number of cores the machine reports.
    ///
    /// Unset means one thread, which is what Zebra has always done. A node that
    /// should not spend its cores on solving — a seed or RPC server — keeps that
    /// behaviour by leaving this out of its config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal_miner_threads: Option<usize>,
}

impl Config {
    /// How many solver threads the internal miner should run on a machine with
    /// `available_threads` cores.
    ///
    /// Always at least one, never more than the machine has, and never more than
    /// the operator asked for.
    pub fn internal_miner_solver_count(&self, available_threads: usize) -> usize {
        let configured = self.internal_miner_threads.unwrap_or(1).max(1);

        configured.min(available_threads.max(1))
    }

    /// Is the internal miner enabled using at least one thread?
    #[cfg(feature = "internal-miner")]
    pub fn is_internal_miner_enabled(&self) -> bool {
        // TODO: Changed to return always false so internal miner is never started. Part of https://github.com/ZcashFoundation/zebra/issues/8180
        // Find the removed code at https://github.com/ZcashFoundation/zebra/blob/v1.5.1/zebra-rpc/src/config/mining.rs#L83
        // Restore the code when conditions are met. https://github.com/ZcashFoundation/zebra/issues/8183
        self.internal_miner
    }
}

/// Operator-configured data appended to the coinbase input of every block Zebra builds, after
/// Zebra's `🦓` marker and `: ` separator.
///
/// Validated on construction to fit within the coinbase data budget, so an oversized value can't
/// be represented — and an oversized `mining.extra_coinbase_data` in the config makes Zebra fail
/// to start.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtraCoinbaseData(String);

impl Deref for ExtraCoinbaseData {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The error returned when [`ExtraCoinbaseData`] is constructed from too many bytes.
#[derive(Clone, Debug, thiserror::Error)]
#[error("extra_coinbase_data is {0} bytes, but the maximum is {MAX_USER_COINBASE_DATA_LEN}")]
pub struct ExtraCoinbaseDataTooLong(usize);

impl TryFrom<String> for ExtraCoinbaseData {
    type Error = ExtraCoinbaseDataTooLong;

    fn try_from(data: String) -> Result<Self, Self::Error> {
        if data.len() > MAX_USER_COINBASE_DATA_LEN {
            Err(ExtraCoinbaseDataTooLong(data.len()))
        } else {
            Ok(Self(data))
        }
    }
}

impl<'de> Deserialize<'de> for ExtraCoinbaseData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_from(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl Serialize for ExtraCoinbaseData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// The desired address type for the `mining.miner_address` field in the config.
#[derive(EnumIter, Eq, PartialEq, Default, Hash)]
pub enum MinerAddressType {
    /// A unified address, containing the components of all the other address types.
    Unified,
    /// A Sapling address.
    Sapling,
    /// A transparent address.
    #[default]
    Transparent,
}

/// Returns the hard-coded default miner address string for a given network and address type,
/// or `None` when the network has no hard-coded default.
///
/// All addresses come from a single address:
///
/// - addresses for different networks are only different encodings of the same address;
/// - addresses of different types are components of the same unified address.
///
/// # Correctness
///
/// [`NetworkKind::SwarmMainnet`] has no entry and returns `None`. There is deliberately no
/// built-in SWARM production payout address: the only addresses that could be put here are
/// re-encodings of an upstream test vector whose key is public, so a node that silently used one
/// would mine SWARM blocks to a destination anybody can spend. The operator must configure
/// `mining.miner_address`. This used to be an infallible `MINER_ADDRESS[&kind][addr_type]`, which
/// panicked on SwarmMain.
pub fn default_miner_address(
    kind: NetworkKind,
    addr_type: &MinerAddressType,
) -> Option<&'static str> {
    MINER_ADDRESS.get(&kind)?.get(addr_type).copied()
}

#[cfg(test)]
mod swarm_prefix_tests {
    use super::*;

    #[test]
    fn swarm_and_legacy_miner_addresses_have_identical_receivers() {
        let legacy = default_miner_address(NetworkKind::Testnet, &MinerAddressType::Unified)
            .expect("Testnet has a hard-coded default miner address");
        let parsed: ZcashAddress = legacy.parse().expect("the built-in test vector is valid");
        let canonical = parsed.to_string();
        assert!(canonical.starts_with("swarm1"));
        assert_eq!(canonical.parse::<ZcashAddress>(), Ok(parsed));
        assert!(canonical
            .replacen("swarm", "SwarM", 1)
            .parse::<ZcashAddress>()
            .is_err());
    }

    #[test]
    fn swarm_main_has_no_hard_coded_miner_address() {
        for addr_type in [
            MinerAddressType::Unified,
            MinerAddressType::Sapling,
            MinerAddressType::Transparent,
        ] {
            assert_eq!(
                default_miner_address(NetworkKind::SwarmMainnet, &addr_type),
                None,
                "SWARM production must not fall back to an upstream test-vector payout address"
            );
        }
    }
}

lazy_static::lazy_static! {
    static ref MINER_ADDRESS: HashMap<NetworkKind, HashMap<MinerAddressType, &'static str>> = [
        (NetworkKind::Mainnet, [
            (MinerAddressType::Unified, "u1cymdny2u2vllkx7t5jnelp0kde0dgnwu0jzmggzguxvxj6fe7gpuqehywejndlrjwgk9snr6g69azs8jfet78s9zy60uepx6tltk7ee57jlax49dezkhkgvjy2puuue6dvaevt53nah7t2cc2k4p0h0jxmlu9sx58m2xdm5f9sy2n89jdf8llflvtml2ll43e334avu2fwytuna404a"),
            // (MinerAddressType::Orchard, "u1hmfjpqdxaec3mvqypl7fkqcy53u438csydljpuepsfs7jx6sjwyznuzlna8qsslj3tg6sn9ua4q653280aqv4m2fjd4csptwxq3fjpwy"),
            (MinerAddressType::Sapling, "zs1xl84ekz6stprmvrp39s77mf9t953nqjndwlcjtzfrr3cgjjez87639xm4u9pfuvylrhec3uryy5"),
            (MinerAddressType::Transparent, "t1T92bmyoPM7PTSWUnaWnLGcxkF6Jp1AwMY"),
        ].into()),
        (NetworkKind::Testnet, [
            (MinerAddressType::Unified, "utest10a8k6aw5w33kvyt7x6fryzu7vvsjru5vgcfnvr288qx2zm6p63ygcajtaze0px08t583dyrgr42vasazjhhnntus2tqrpkzu0dm2l4cgf3ld6wdqdrf3jv8mvfx9c80e73syer9l2wlgawjtf7yvj0eqwdf354trtelxnr0fhpw9792eaf49ghstkyftc9lwqqwy4ye0cleagp4nzyt"),
            // (MinerAddressType::Orchard, "utest10zg6frxk32ma8980kdv9473e4aclw7clq9hydzcj6l349pkqzxk2mmj3cn7j5x38w6l4wyryv50whnlrw0k9agzpdf5fxyj7kq96ukcp"),
            (MinerAddressType::Sapling, "ztestsapling1xl84ekz6stprmvrp39s77mf9t953nqjndwlcjtzfrr3cgjjez87639xm4u9pfuvylrhecet38rq"),
            (MinerAddressType::Transparent, "tmJymvcUCn1ctbghvTJpXBwHiMEB8P6wxNV"),
        ].into()),
        (NetworkKind::Regtest, [
            (MinerAddressType::Unified, "uregtest1efxggx6lduhm2fx5lnrhxv7h7kpztlpa3ahf3n4w0q0zj5epj4av9xjq6ljsja3xk8z7rzd067kc7mgpy9448rdfzpfjz5gq389zdmpgnk6rp4ykk0xk6cmqw6zqcrnmsuaxv3yzsvcwsd4gagtalh0uzrdvy03nhmltjz2eu0232qlcs0zvxuqyut73yucd9gy5jaudnyt7yqhgpqv"),
            // (MinerAddressType::Orchard, "uregtest1pszqlgxaf5w8mu2yd9uygg8cswp0ec4f7eejqnqc35tztw4tk0sxnt3pym2f3s2872cy2ruuc5n8y9cen5q6ngzlmzu8ztrjesv8zm9j"),
            (MinerAddressType::Sapling, "zregtestsapling1xl84ekz6stprmvrp39s77mf9t953nqjndwlcjtzfrr3cgjjez87639xm4u9pfuvylrhecx0c2j8"),
            (MinerAddressType::Transparent, "tmJymvcUCn1ctbghvTJpXBwHiMEB8P6wxNV"),
        ].into()),
    ].into();
}
