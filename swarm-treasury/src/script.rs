//! The transparent script layer: HASH160, the multisig redeem script, and scriptSig assembly.
//!
//! This is the task T1 logic (`zebra-script/tests/swarm_treasury_multisig.rs`), moved into a
//! library so the tool and the fixtures share one implementation. Nothing here is new
//! cryptography: `sha2` + `ripemd` are the same hashes upstream Zebra uses, and the script layout
//! is the standard `OP_M <pubkey…> OP_N OP_CHECKMULTISIG` P2SH multisig.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::{refuse, Result};

/// `OP_0`, the element `OP_CHECKMULTISIG` pops and discards.
pub const OP_0: u8 = 0x00;
/// `OP_PUSHDATA1`: the next byte is the length of the data to push.
pub const OP_PUSHDATA1: u8 = 0x4c;
/// The largest length byte that is a direct push rather than an opcode.
pub const MAX_DIRECT_PUSH: usize = 75;
/// `OP_HASH160`.
pub const OP_HASH160: u8 = 0xa9;
/// `OP_EQUAL`.
pub const OP_EQUAL: u8 = 0x87;
/// `OP_CHECKMULTISIG`.
pub const OP_CHECKMULTISIG: u8 = 0xae;
/// The canonical `SIGHASH_ALL` byte appended to each DER signature in a scriptSig.
pub const SIGHASH_ALL_BYTE: u8 = 0x01;

/// The length of a compressed secp256k1 public key.
pub const COMPRESSED_PUBLIC_KEY_LEN: usize = 33;

/// The largest N a standard P2SH multisig can hold: `15 * 34 + 3 = 513` bytes, inside the 520-byte
/// redeem-script limit, and `OP_15` is still a small-integer opcode.
pub const MAX_KEYS: usize = 15;

/// HASH160: RIPEMD-160 of SHA-256, as used for every transparent Zcash address.
pub fn hash160(bytes: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(bytes);
    let ripe = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe[..]);
    out
}

/// SHA-256, used for the signer and policy fingerprints.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes)[..]);
    out
}

/// Appends a minimal data push of `data` to `script`.
///
/// A 2-of-3 redeem script is 105 bytes, and the length byte 105 (`0x69`) is an opcode, not a push
/// length — so anything above [`MAX_DIRECT_PUSH`] must use `OP_PUSHDATA1`.
pub fn push_data(script: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    if data.len() <= MAX_DIRECT_PUSH {
        script.push(u8::try_from(data.len()).map_err(|_| refuse!("push length does not fit"))?);
    } else if data.len() < 256 {
        script.push(OP_PUSHDATA1);
        script.push(u8::try_from(data.len()).map_err(|_| refuse!("push length does not fit"))?);
    } else {
        return Err(refuse!(
            "a {}-byte push is larger than this tool builds",
            data.len()
        ));
    }
    script.extend_from_slice(data);
    Ok(())
}

/// The standard multisig redeem script `OP_M <pubkey…> OP_N OP_CHECKMULTISIG`, with compressed
/// public keys in exactly the order given.
///
/// The key order is the order the P2SH address commits to. No BIP-67 sorting is applied: the
/// policy file records the order, and the combiner canonicalizes signatures against it.
pub fn redeem_script(
    threshold: u8,
    public_keys: &[[u8; COMPRESSED_PUBLIC_KEY_LEN]],
) -> Result<Vec<u8>> {
    check_threshold(threshold, public_keys.len())?;

    // OP_1..OP_16 are 0x51..0x60, so OP_n is 0x50 + n for 1 <= n <= 16.
    let mut script = vec![0x50 + threshold];
    for public_key in public_keys {
        script.push(
            u8::try_from(COMPRESSED_PUBLIC_KEY_LEN)
                .map_err(|_| refuse!("public key length does not fit"))?,
        );
        script.extend_from_slice(public_key);
    }
    script.push(0x50 + u8::try_from(public_keys.len()).map_err(|_| refuse!("too many keys"))?);
    script.push(OP_CHECKMULTISIG);
    Ok(script)
}

/// Rejects a threshold or key count outside the standard multisig bounds.
pub fn check_threshold(threshold: u8, keys: usize) -> Result<()> {
    if keys == 0 || keys > MAX_KEYS {
        return Err(refuse!("a policy must have between 1 and {MAX_KEYS} keys"));
    }
    if threshold == 0 || usize::from(threshold) > keys {
        return Err(refuse!(
            "the threshold must be between 1 and the number of keys ({keys})"
        ));
    }
    Ok(())
}

/// The P2SH locking script `OP_HASH160 <script hash> OP_EQUAL`.
pub fn p2sh_lock_script(script_hash: [u8; 20]) -> Vec<u8> {
    let mut script = vec![OP_HASH160, 20];
    script.extend_from_slice(&script_hash);
    script.push(OP_EQUAL);
    script
}

/// Builds a P2SH multisig scriptSig from DER signatures already in redeem-script key order.
///
/// `OP_0` absorbs the off-by-one element `OP_CHECKMULTISIG` pops and discards; the redeem script is
/// pushed last, and the interpreter checks that it hashes to the locking script's hash.
pub fn multisig_script_sig(signatures: &[Vec<u8>], redeem_script: &[u8]) -> Result<Vec<u8>> {
    let mut script_sig = vec![OP_0];
    for signature in signatures {
        push_data(&mut script_sig, signature)?;
    }
    push_data(&mut script_sig, redeem_script)?;
    Ok(script_sig)
}

/// Parses a standard multisig redeem script back into its threshold and its keys, in order.
///
/// This is how a signing device reads a proposal that arrived without the policy file: the
/// threshold and the keys are recovered from the script the address commits to, so the device can
/// still recompute the policy fingerprint and refuse a proposal that does not match it.
pub fn parse_redeem_script(script: &[u8]) -> Result<(u8, Vec<[u8; COMPRESSED_PUBLIC_KEY_LEN]>)> {
    let malformed = || refuse!("the redeem script is not a standard M-of-N multisig script");

    if script.len() < 4 {
        return Err(malformed());
    }
    if script[script.len() - 1] != OP_CHECKMULTISIG {
        return Err(malformed());
    }
    let threshold = script[0].checked_sub(0x50).ok_or_else(malformed)?;
    let key_count = script[script.len() - 2]
        .checked_sub(0x50)
        .ok_or_else(malformed)?;

    let mut keys = Vec::with_capacity(usize::from(key_count));
    let mut offset = 1;
    while offset < script.len() - 2 {
        if script[offset] as usize != COMPRESSED_PUBLIC_KEY_LEN {
            return Err(malformed());
        }
        offset += 1;
        let end = offset
            .checked_add(COMPRESSED_PUBLIC_KEY_LEN)
            .ok_or_else(malformed)?;
        if end > script.len() - 2 {
            return Err(malformed());
        }
        let mut key = [0u8; COMPRESSED_PUBLIC_KEY_LEN];
        key.copy_from_slice(&script[offset..end]);
        secp256k1::PublicKey::from_slice(&key)
            .map_err(|_| refuse!("the redeem script holds a key that is not on the curve"))?;
        keys.push(key);
        offset = end;
    }

    if keys.len() != usize::from(key_count) {
        return Err(malformed());
    }
    check_threshold(threshold, keys.len())?;
    // Round-trips, so a script with the right shape but odd encoding is still refused.
    if redeem_script(threshold, &keys)? != script {
        return Err(malformed());
    }
    Ok((threshold, keys))
}

/// Parses a compressed secp256k1 public key from hex, rejecting anything that is not a valid point.
pub fn parse_public_key(hex_key: &str) -> Result<[u8; COMPRESSED_PUBLIC_KEY_LEN]> {
    let bytes = hex::decode(hex_key.trim())
        .map_err(|_| refuse!("a public key must be hexadecimal, found {hex_key:?}"))?;
    let key: [u8; COMPRESSED_PUBLIC_KEY_LEN] = bytes.as_slice().try_into().map_err(|_| {
        refuse!(
            "a compressed public key is {COMPRESSED_PUBLIC_KEY_LEN} bytes, found {}",
            bytes.len()
        )
    })?;
    // Not just a length check: the bytes must be a point on the curve.
    secp256k1::PublicKey::from_slice(&key).map_err(|error| {
        refuse!("{hex_key} is not a valid compressed secp256k1 public key: {error}")
    })?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published `swarm-keytool` 2-of-3 vector for the public test scalars 1, 2 and 3.
    const P1: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const P2: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const P3: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

    #[test]
    fn published_two_of_three_vector() {
        let keys = [
            parse_public_key(P1).unwrap(),
            parse_public_key(P2).unwrap(),
            parse_public_key(P3).unwrap(),
        ];
        let script = redeem_script(2, &keys).unwrap();
        assert_eq!(script.len(), 105, "the 2-of-3 redeem script is 105 bytes");
        assert_eq!(
            hex::encode(hash160(&script)),
            "15fc0754e73eb85d1cbce08786fadb7320ecb8dc",
        );
    }

    /// A 105-byte push must use `OP_PUSHDATA1`; 105 as a bare length byte would be an opcode.
    #[test]
    fn long_pushes_use_pushdata1() {
        let mut script = Vec::new();
        push_data(&mut script, &[0u8; 105]).unwrap();
        assert_eq!(script[0], OP_PUSHDATA1);
        assert_eq!(script[1], 105);

        let mut short = Vec::new();
        push_data(&mut short, &[0u8; 71]).unwrap();
        assert_eq!(short[0], 71);
    }

    #[test]
    fn thresholds_are_bounded() {
        assert!(check_threshold(2, 3).is_ok());
        assert!(check_threshold(0, 3).is_err());
        assert!(check_threshold(4, 3).is_err());
        assert!(check_threshold(1, 0).is_err());
        assert!(check_threshold(1, 16).is_err());
    }

    #[test]
    fn redeem_scripts_round_trip() {
        let keys = [
            parse_public_key(P1).unwrap(),
            parse_public_key(P2).unwrap(),
            parse_public_key(P3).unwrap(),
        ];
        let script = redeem_script(2, &keys).unwrap();
        let (threshold, parsed) = parse_redeem_script(&script).unwrap();
        assert_eq!(threshold, 2);
        assert_eq!(parsed, keys.to_vec());

        assert!(parse_redeem_script(&[]).is_err());
        assert!(parse_redeem_script(&[0x52, 0xae]).is_err());
        let mut truncated = script.clone();
        truncated.pop();
        assert!(parse_redeem_script(&truncated).is_err());
        let mut wrong_count = script;
        let last_but_one = wrong_count.len() - 2;
        wrong_count[last_but_one] = 0x52;
        assert!(parse_redeem_script(&wrong_count).is_err());
    }

    #[test]
    fn invalid_public_keys_are_refused() {
        assert!(parse_public_key("not hex").is_err());
        assert!(parse_public_key("0279be66").is_err());
        // Valid length and prefix, but not a point on the curve.
        assert!(parse_public_key(&format!("02{}", "00".repeat(32))).is_err());
    }
}
