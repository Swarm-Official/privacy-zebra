//! The shielded output: a real Orchard or Ironwood bundle with a real Halo2 proof.
//!
//! This is the task T2 construction (`zebra-consensus/tests/swarm_treasury_shielded_spend.rs`),
//! moved into a library so the tool and that fixture share one implementation rather than two that
//! can drift.
//!
//! Zebra has no wallet transaction builder, and the `zcash_primitives` builder's transparent input
//! support is limited to keys it can sign for itself, so it cannot spend an arbitrary P2SH redeem
//! script. This module therefore takes the smaller path: it builds the bundle with the `orchard`
//! crate (real prover), encodes it in the consensus wire format, and lets Zebra's own
//! `ZcashDeserialize` impl parse it into [`zebra_chain::orchard::ShieldedData`] or
//! [`zebra_chain::ironwood::ShieldedData`]. Nothing here invents a serializer, a sighash or a proof
//! system.
//!
//! # Why the disbursement must be Ironwood on the mainnet path
//!
//! From NU6.3 the Orchard pool is frozen against new inflows
//! (`zebra_consensus::transaction::check::orchard_value_balance_non_negative`), so a v6
//! disbursement of transparent treasury value **must** target Ironwood. [`Pool::V5Orchard`] is kept
//! only as a test path.

use std::{io::Cursor, sync::OnceLock};

use orchard::{
    builder::{Builder as OrchardBuilder, BundleType},
    bundle::{Authorization as OrchardAuthorization, Bundle as OrchardBundle, BundleVersion},
    circuit::ProvingKey,
    keys::{FullViewingKey, Scope, SpendingKey},
    value::NoteValue,
    Anchor,
};
use rand::{rngs::StdRng, SeedableRng};
use zcash_address::unified::{self, Container};
use zcash_protocol::consensus::NetworkType;
use zebra_chain::{parameters::NetworkUpgrade, serialization::ZcashDeserialize};

use crate::{network::TreasuryNetwork, refuse, Result};

/// The length of a raw Orchard/Ironwood receiver, in bytes.
pub const RAW_RECEIVER_LEN: usize = 43;

/// The length of the memo field, in bytes.
pub const MEMO_LEN: usize = 512;

/// Which transaction format and shielded pool a disbursement uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pool {
    /// A v5 transaction at NU5, paying into the Orchard pool.
    ///
    /// A test path only: at NU6.3 the Orchard pool rejects inflows.
    V5Orchard,
    /// A v6 transaction at NU6.3, paying into the Ironwood pool. The mainnet case.
    V6Ironwood,
}

impl Pool {
    /// Parses the `--network-upgrade` value.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "nu6_3" | "nu6.3" => Ok(Pool::V6Ironwood),
            "nu5" => Ok(Pool::V5Orchard),
            other => Err(refuse!(
                "unknown network upgrade {other:?}; expected nu6_3 (the mainnet case) or nu5"
            )),
        }
    }

    /// The name this pool's network upgrade is written as.
    pub fn name(self) -> &'static str {
        match self {
            Pool::V5Orchard => "nu5",
            Pool::V6Ironwood => "nu6_3",
        }
    }

    /// The network upgrade the disbursement happens under.
    pub fn network_upgrade(self) -> NetworkUpgrade {
        match self {
            Pool::V5Orchard => NetworkUpgrade::Nu5,
            Pool::V6Ironwood => NetworkUpgrade::Nu6_3,
        }
    }

    /// The `orchard` crate bundle version to build with.
    pub fn bundle_version(self) -> BundleVersion {
        match self {
            Pool::V5Orchard => BundleVersion::orchard_insecure_v1(),
            Pool::V6Ironwood => BundleVersion::ironwood_v3(),
        }
    }

    /// The proving key whose circuit matches [`Self::bundle_version`].
    ///
    /// Built once per process: a proving key costs seconds to construct.
    pub fn proving_key(self) -> &'static ProvingKey {
        static PRE_NU6_2: OnceLock<ProvingKey> = OnceLock::new();
        static NU6_3: OnceLock<ProvingKey> = OnceLock::new();
        match self {
            Pool::V5Orchard => {
                PRE_NU6_2.get_or_init(|| ProvingKey::build(self.bundle_version().circuit_version()))
            }
            Pool::V6Ironwood => {
                NU6_3.get_or_init(|| ProvingKey::build(self.bundle_version().circuit_version()))
            }
        }
    }
}

// -- the recipient -----------------------------------------------------------

/// Parses a `--to` recipient.
///
/// Two forms are accepted:
///
/// * a unified address for the network, from which the Orchard receiver is taken (Ironwood notes
///   use the same 43-byte receiver encoding);
/// * the raw 43-byte receiver as hex, which is what a fixture recipient is.
///
/// Anything else — a transparent address, a Sapling address, a unified address with no Orchard
/// receiver — is refused rather than silently paid somewhere else.
pub fn parse_recipient(value: &str, network: TreasuryNetwork) -> Result<orchard::Address> {
    let value = value.trim();

    if value.len() == RAW_RECEIVER_LEN * 2 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes =
            hex::decode(value).map_err(|_| refuse!("the raw receiver is not hexadecimal"))?;
        let raw: [u8; RAW_RECEIVER_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| refuse!("a raw receiver is {RAW_RECEIVER_LEN} bytes"))?;
        return Option::from(orchard::Address::from_raw_address_bytes(&raw))
            .ok_or_else(|| refuse!("the raw receiver is not a valid Orchard/Ironwood address"));
    }

    let expected_network = network.unified_network_type()?;
    let address = zcash_address::ZcashAddress::try_from_encoded(value)
        .map_err(|error| refuse!("{value:?} is not an address this tool can read: {error}"))?;
    let recipient: OrchardRecipient = address
        .convert()
        .map_err(|error| refuse!("{value:?} cannot be paid by this tool: {error}"))?;

    if recipient.network != expected_network {
        return Err(refuse!(
            "the recipient address is for a different network than the policy ({})",
            network.name(),
        ));
    }
    Ok(recipient.address)
}

/// The Orchard receiver taken out of a unified address.
struct OrchardRecipient {
    network: NetworkType,
    address: orchard::Address,
}

impl zcash_address::TryFromAddress for OrchardRecipient {
    type Error = String;

    fn try_from_unified(
        network: NetworkType,
        unified_address: unified::Address,
    ) -> std::result::Result<Self, zcash_address::ConversionError<Self::Error>> {
        for receiver in unified_address.items() {
            if let unified::Receiver::Orchard(data) = receiver {
                let address: Option<orchard::Address> =
                    orchard::Address::from_raw_address_bytes(&data).into();
                return match address {
                    Some(address) => Ok(OrchardRecipient { network, address }),
                    None => Err(zcash_address::ConversionError::User(
                        "the unified address contains an invalid Orchard receiver".to_string(),
                    )),
                };
            }
        }
        Err(zcash_address::ConversionError::User(
            "the unified address has no Orchard receiver, so it cannot receive an Ironwood or \
             Orchard note"
                .to_string(),
        ))
    }
}

/// Pads a memo string into the 512-byte memo field.
pub fn memo_from_text(text: &str) -> Result<[u8; MEMO_LEN]> {
    let bytes = text.as_bytes();
    if bytes.len() > MEMO_LEN {
        return Err(refuse!(
            "a memo is at most {MEMO_LEN} bytes, this one is {}",
            bytes.len()
        ));
    }
    let mut memo = [0u8; MEMO_LEN];
    memo[..bytes.len()].copy_from_slice(bytes);
    Ok(memo)
}

/// The external receiver of an Orchard spending key, used by fixtures and by `spend show` when a
/// caller wants to check a recipient they hold the key for.
pub fn receiver_of_spending_key(key: &SpendingKey) -> orchard::Address {
    FullViewingKey::from(key).address_at(0u32, Scope::External)
}

// -- the wire encoding -------------------------------------------------------

/// One Action description's non-authorizing fields, in consensus wire order.
#[derive(Clone, Debug)]
pub struct WireAction {
    /// The value commitment.
    pub cv: [u8; 32],
    /// The nullifier of the spent note.
    pub nullifier: [u8; 32],
    /// The randomized validating key.
    pub rk: [u8; 32],
    /// The note commitment of the output note.
    pub cmx: [u8; 32],
    /// The ephemeral key of the note encryption.
    pub ephemeral_key: [u8; 32],
    /// The encrypted note.
    pub enc_ciphertext: [u8; 580],
    /// The outgoing ciphertext.
    pub out_ciphertext: [u8; 80],
}

/// A whole Orchard-protocol bundle in the consensus wire format.
///
/// The encoding is the one Zebra's `deserialize_orchard_shielded_data` reads, so building these
/// bytes and handing them to Zebra's parser is how a real bundle reaches a
/// [`zebra_chain::transaction::Transaction`].
#[derive(Clone, Debug)]
pub struct WireBundle {
    /// The bundle's actions.
    pub actions: Vec<WireAction>,
    /// The encoded bundle flags.
    pub flag_byte: u8,
    /// The bundle's value balance.
    pub value_balance: i64,
    /// The note commitment tree anchor the bundle proves against.
    pub anchor: [u8; 32],
    /// The Halo2 proof.
    pub proof: Vec<u8>,
    /// One spend-authorization signature per action.
    pub spend_auth_sigs: Vec<[u8; 64]>,
    /// The binding signature.
    pub binding_sig: [u8; 64],
}

/// Writes a Bitcoin-style CompactSize prefix.
fn write_compact_size(bytes: &mut Vec<u8>, value: usize) {
    if value < 253 {
        bytes.push(value as u8);
    } else if value <= u16::MAX as usize {
        bytes.push(0xfd);
        bytes.extend_from_slice(&(value as u16).to_le_bytes());
    } else {
        bytes.push(0xfe);
        bytes.extend_from_slice(&(value as u32).to_le_bytes());
    }
}

impl WireBundle {
    /// Extracts the non-authorizing fields of `bundle` and pairs them with the given proof and
    /// signatures.
    ///
    /// The proof and the signatures are supplied separately because the ZIP-244 signature digest
    /// excludes both: the builder first makes this with placeholders to take the sighash, then
    /// remakes it with the real proof and signatures.
    fn new<A: OrchardAuthorization>(
        bundle: &OrchardBundle<A, i64>,
        proof: Vec<u8>,
        spend_auth_sigs: Vec<[u8; 64]>,
        binding_sig: [u8; 64],
    ) -> Self {
        let actions = bundle
            .actions()
            .iter()
            .map(|action| {
                let encrypted_note = action.encrypted_note();
                WireAction {
                    cv: action.cv_net().to_bytes(),
                    nullifier: action.nullifier().to_bytes(),
                    rk: <[u8; 32]>::from(action.rk()),
                    cmx: action.cmx().to_bytes(),
                    ephemeral_key: encrypted_note.epk_bytes,
                    enc_ciphertext: encrypted_note.enc_ciphertext,
                    out_ciphertext: encrypted_note.out_ciphertext,
                }
            })
            .collect();

        WireBundle {
            actions,
            flag_byte: bundle.flag_byte(),
            value_balance: *bundle.value_balance(),
            anchor: bundle.anchor().to_bytes(),
            proof,
            spend_auth_sigs,
            binding_sig,
        }
    }

    /// The bundle's consensus wire encoding, as it appears inside a v5 or v6 transaction.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        write_compact_size(&mut bytes, self.actions.len());
        for action in &self.actions {
            bytes.extend_from_slice(&action.cv);
            bytes.extend_from_slice(&action.nullifier);
            bytes.extend_from_slice(&action.rk);
            bytes.extend_from_slice(&action.cmx);
            bytes.extend_from_slice(&action.ephemeral_key);
            bytes.extend_from_slice(&action.enc_ciphertext);
            bytes.extend_from_slice(&action.out_ciphertext);
        }

        bytes.push(self.flag_byte);
        bytes.extend_from_slice(&self.value_balance.to_le_bytes());
        bytes.extend_from_slice(&self.anchor);
        write_compact_size(&mut bytes, self.proof.len());
        bytes.extend_from_slice(&self.proof);
        for signature in &self.spend_auth_sigs {
            bytes.extend_from_slice(signature);
        }
        bytes.extend_from_slice(&self.binding_sig);

        bytes
    }

    /// Parses these bytes with Zebra's own v5 Orchard bundle deserializer.
    pub fn to_orchard_shielded_data(&self) -> Result<zebra_chain::orchard::ShieldedData> {
        let mut reader = Cursor::new(self.to_bytes());
        Option::<zebra_chain::orchard::ShieldedData>::zcash_deserialize(&mut reader)
            .map_err(|error| refuse!("the built Orchard bundle does not re-parse: {error}"))?
            .ok_or_else(|| refuse!("the built Orchard bundle has no actions"))
    }

    /// Parses these bytes with Zebra's own Ironwood bundle deserializer.
    pub fn to_ironwood_shielded_data(&self) -> Result<zebra_chain::ironwood::ShieldedData> {
        let mut reader = Cursor::new(self.to_bytes());
        Option::<zebra_chain::ironwood::ShieldedData>::zcash_deserialize(&mut reader)
            .map_err(|error| refuse!("the built Ironwood bundle does not re-parse: {error}"))?
            .ok_or_else(|| refuse!("the built Ironwood bundle has no actions"))
    }
}

/// Builds, proves and authorizes one single-output shielded bundle.
///
/// The ordering matters and is checked rather than assumed:
///
/// 1. build the unproven bundle, which fixes every field the sighash commits to;
/// 2. encode it with a zero-filled proof and zero-filled signatures, and let `sighash_of` take the
///    ZIP-244 sighash of the transaction that carries it;
/// 3. create the real proof and apply the real signatures over that sighash;
/// 4. hand back the authorized bundle and the sighash it is bound to.
///
/// The caller must confirm that the sighash of the *authorized* transaction is unchanged; the
/// ZIP-244 signature digest excludes proofs and signatures, and [`crate::spend`] asserts it.
pub fn build_bundle<F>(
    pool: Pool,
    recipient: orchard::Address,
    note_value: u64,
    memo: [u8; MEMO_LEN],
    rng_seed: [u8; 32],
    sighash_of: F,
) -> Result<(WireBundle, [u8; 32])>
where
    F: FnOnce(&WireBundle) -> Result<[u8; 32]>,
{
    let mut rng = StdRng::from_seed(rng_seed);

    let bundle_version = pool.bundle_version();
    let mut builder = OrchardBuilder::new(
        // The transaction's shape is already public (transparent inputs, no transparent outputs),
        // so the bundle is not padded beyond the one-action consensus minimum.
        BundleType::UNPADDED,
        bundle_version,
        bundle_version.default_flags(),
        Anchor::empty_tree(),
    )
    .map_err(|error| refuse!("the bundle version and flags are inconsistent: {error}"))?;

    builder
        .add_output(None, recipient, NoteValue::from_raw(note_value), memo)
        .map_err(|error| refuse!("could not add the disbursement output: {error}"))?;

    let (unproven, _metadata) = builder
        .build::<i64>(&mut rng)
        .map_err(|error| refuse!("could not build the shielded bundle: {error}"))?
        .ok_or_else(|| refuse!("the shielded bundle has no output"))?;

    if unproven.actions().len() != 1 {
        return Err(refuse!(
            "an unpadded one-output bundle must have exactly one action, this has {}",
            unproven.actions().len(),
        ));
    }
    let expected_balance = -i64::try_from(note_value)
        .map_err(|_| refuse!("the disbursement amount does not fit in a signed 64-bit value"))?;
    if *unproven.value_balance() != expected_balance {
        return Err(refuse!(
            "value flowing into the shielded pool must be a negative value balance; \
             expected {expected_balance}, the bundle has {}",
            unproven.value_balance(),
        ));
    }

    let placeholder_proof =
        vec![0u8; orchard::Proof::expected_proof_size(unproven.actions().len())];
    let placeholder = WireBundle::new(
        &unproven,
        placeholder_proof,
        vec![[0u8; 64]; unproven.actions().len()],
        [0u8; 64],
    );

    let sighash = sighash_of(&placeholder)?;

    // The bundle has no real spends, so no spend authorizing key is supplied: the builder's
    // fabricated dummy spend is signed by `apply_signatures` with the dummy's own key.
    let authorized = unproven
        .create_proof(pool.proving_key(), &mut rng)
        .map_err(|error| refuse!("could not prove the shielded bundle: {error}"))?
        .apply_signatures(&mut rng, sighash, &[])
        .map_err(|error| refuse!("could not sign the shielded bundle: {error}"))?;

    let spend_auth_sigs = authorized
        .actions()
        .iter()
        .map(|action| <[u8; 64]>::from(action.authorization()))
        .collect();
    let wire = WireBundle::new(
        &authorized,
        authorized.authorization().proof().as_ref().to_vec(),
        spend_auth_sigs,
        <[u8; 64]>::from(authorized.authorization().binding_signature()),
    );

    Ok((wire, sighash))
}

/// A disposable Orchard spending key built from documented bytes, for fixtures.
///
/// It is not generated and must never be funded; it exists so a test can decrypt the note it just
/// paid to itself.
pub fn fixture_spending_key(bytes: [u8; 32]) -> Result<SpendingKey> {
    Option::from(SpendingKey::from_bytes(bytes))
        .ok_or_else(|| refuse!("the given bytes are not a valid Orchard spending key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pools_are_named_and_parsed() {
        assert_eq!(Pool::parse("nu6_3").unwrap(), Pool::V6Ironwood);
        assert_eq!(Pool::parse("nu5").unwrap(), Pool::V5Orchard);
        assert!(Pool::parse("nu5.5").is_err());
        assert_eq!(Pool::V6Ironwood.name(), "nu6_3");
        assert_eq!(
            Pool::V6Ironwood.network_upgrade(),
            NetworkUpgrade::Nu6_3,
            "the mainnet disbursement path is NU6.3 / Ironwood",
        );
    }

    #[test]
    fn a_raw_receiver_round_trips() {
        let key = fixture_spending_key([0u8; 32]).unwrap();
        let address = receiver_of_spending_key(&key);
        let raw = hex::encode(address.to_raw_address_bytes());

        assert_eq!(
            parse_recipient(&raw, TreasuryNetwork::Testnet).unwrap(),
            address,
        );
    }

    #[test]
    fn unusable_recipients_are_refused() {
        // A transparent address cannot receive a shielded note.
        assert!(parse_recipient(
            "t28Z45qZRaD6zXBMFHTzEN7pZfGeZTtbkFp",
            TreasuryNetwork::Testnet
        )
        .is_err());
        assert!(parse_recipient("", TreasuryNetwork::Testnet).is_err());
        assert!(parse_recipient(&"00".repeat(RAW_RECEIVER_LEN), TreasuryNetwork::Testnet).is_err());
        // The mainnet encoding is not in this build, so no address can be parsed for it.
        assert!(parse_recipient("u1whatever", TreasuryNetwork::SwarmMain).is_err());
    }

    #[test]
    fn memos_are_padded_and_bounded() {
        let memo = memo_from_text("hello").unwrap();
        assert_eq!(&memo[..5], b"hello");
        assert!(memo[5..].iter().all(|byte| *byte == 0));
        assert!(memo_from_text(&"x".repeat(MEMO_LEN + 1)).is_err());
    }
}
