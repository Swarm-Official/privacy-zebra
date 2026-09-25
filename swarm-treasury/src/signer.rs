//! One signer key, its public record, and its encrypted backup.
//!
//! Each owner device generates **exactly one** key, on that device, and never sees the others.
//! This is the whole difference from `swarm-keytool`, which generates all N secrets in one process
//! and writes them to one plaintext JSON file.
//!
//! The backup is an [age](https://c2sp.org/age) file with a passphrase (scrypt) recipient. This
//! crate writes no cryptography of its own; `age` provides the authenticated encryption, and a
//! modified backup fails to decrypt rather than decrypting to something else.

use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use rand::{rngs::OsRng, RngCore};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

use crate::{refuse, script, Result, TOOL_NAME, TOOL_VERSION};

/// The schema tag of a public signer record.
pub const PUBLIC_SCHEMA: &str = "swarm-treasury.signer-public";
/// The schema tag of the plaintext inside a signer backup.
pub const SECRET_SCHEMA: &str = "swarm-treasury.signer-secret";
/// The version of both signer schemas.
pub const SIGNER_SCHEMA_VERSION: u32 = 1;

/// The environment variable a backup passphrase may be read from.
///
/// A passphrase is never taken from the command line, where it would land in shell history and in
/// every process listing on the machine.
pub const PASSPHRASE_ENV: &str = "SWARM_TREASURY_PASSPHRASE";

/// The environment variable that lowers the scrypt work factor.
///
/// This exists so the test suite does not spend a second of CPU per backup. Production runs leave
/// it unset, and `age` then picks a work factor targeting about one second on the device.
pub const SCRYPT_LOG_N_ENV: &str = "SWARM_TREASURY_SCRYPT_LOG_N";

/// A passphrase, kept out of `Debug` output.
#[derive(Clone)]
pub struct Passphrase(String);

impl Passphrase {
    /// Wraps a passphrase, refusing an empty one.
    pub fn new(passphrase: impl Into<String>) -> Result<Self> {
        let passphrase = passphrase.into();
        if passphrase.trim().is_empty() {
            return Err(refuse!("the backup passphrase must not be empty"));
        }
        Ok(Passphrase(passphrase))
    }

    /// The passphrase as an `age` secret.
    fn to_secret(&self) -> age::secrecy::SecretString {
        age::secrecy::SecretString::from(self.0.clone())
    }
}

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Passphrase(<redacted>)")
    }
}

/// The public record of a signer: everything the other devices need, and nothing else.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignerPublic {
    /// The schema tag, always [`PUBLIC_SCHEMA`].
    pub schema: String,
    /// The schema version, always [`SIGNER_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The tool that wrote this file.
    pub tool: String,
    /// The version of the tool that wrote this file.
    pub tool_version: String,
    /// The signer's label, for example `A`.
    pub label: String,
    /// The compressed secp256k1 public key, hex.
    pub public_key: String,
    /// The first 8 bytes of `SHA-256(public key)`, hex.
    pub fingerprint: String,
    /// When the key was generated, RFC 3339.
    pub created: String,
}

impl SignerPublic {
    /// Checks the record's schema and recomputes its fingerprint from its public key.
    pub fn validate(&self) -> Result<[u8; script::COMPRESSED_PUBLIC_KEY_LEN]> {
        if self.schema != PUBLIC_SCHEMA {
            return Err(refuse!(
                "expected a {PUBLIC_SCHEMA} file, found schema {:?}",
                self.schema
            ));
        }
        if self.schema_version != SIGNER_SCHEMA_VERSION {
            return Err(refuse!(
                "this build reads {PUBLIC_SCHEMA} version {SIGNER_SCHEMA_VERSION}, \
                 the file is version {}",
                self.schema_version
            ));
        }
        check_label(&self.label)?;
        let public_key = script::parse_public_key(&self.public_key)?;
        let expected = fingerprint(&public_key);
        if self.fingerprint != expected {
            return Err(refuse!(
                "signer {}'s fingerprint does not match its public key: the file says {}, \
                 the key hashes to {expected}",
                self.label,
                self.fingerprint,
            ));
        }
        Ok(public_key)
    }
}

/// The plaintext inside a signer backup.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerSecret {
    /// The schema tag, always [`SECRET_SCHEMA`].
    pub schema: String,
    /// The schema version, always [`SIGNER_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The signer's label.
    pub label: String,
    /// The secret scalar, hex. Never written anywhere but inside the `age` file.
    pub secret_key: String,
    /// The compressed public key, hex.
    pub public_key: String,
    /// The public-key fingerprint, hex.
    pub fingerprint: String,
    /// When the key was generated, RFC 3339.
    pub created: String,
}

impl SignerSecret {
    /// Parses and checks the secret, returning the key pair it holds.
    ///
    /// The public key is **recomputed** from the secret rather than trusted, so a backup whose
    /// public key was edited is rejected instead of signing with a key nobody expects.
    pub fn key_pair(&self) -> Result<(SecretKey, [u8; script::COMPRESSED_PUBLIC_KEY_LEN])> {
        if self.schema != SECRET_SCHEMA {
            return Err(refuse!("the backup does not hold a {SECRET_SCHEMA} record"));
        }
        if self.schema_version != SIGNER_SCHEMA_VERSION {
            return Err(refuse!(
                "this build reads {SECRET_SCHEMA} version {SIGNER_SCHEMA_VERSION}, \
                 the backup is version {}",
                self.schema_version
            ));
        }
        let bytes = hex::decode(&self.secret_key)
            .map_err(|_| refuse!("the backup's secret key is not hexadecimal"))?;
        let secret = SecretKey::from_slice(&bytes)
            .map_err(|_| refuse!("the backup's secret key is not a valid secp256k1 scalar"))?;
        let derived = PublicKey::from_secret_key(&Secp256k1::new(), &secret).serialize();

        let recorded = script::parse_public_key(&self.public_key)?;
        if recorded != derived {
            return Err(refuse!(
                "the backup is inconsistent: its recorded public key is not the one its secret \
                 key derives to"
            ));
        }
        Ok((secret, derived))
    }

    /// The public record matching this secret.
    pub fn public(&self) -> SignerPublic {
        SignerPublic {
            schema: PUBLIC_SCHEMA.to_string(),
            schema_version: SIGNER_SCHEMA_VERSION,
            tool: TOOL_NAME.to_string(),
            tool_version: TOOL_VERSION.to_string(),
            label: self.label.clone(),
            public_key: self.public_key.clone(),
            fingerprint: self.fingerprint.clone(),
            created: self.created.clone(),
        }
    }
}

/// The first 8 bytes of `SHA-256(compressed public key)`, hex.
pub fn fingerprint(public_key: &[u8; script::COMPRESSED_PUBLIC_KEY_LEN]) -> String {
    hex::encode(&script::sha256(public_key)[..8])
}

/// Labels become file names, so they may not contain separators or dots.
pub fn check_label(label: &str) -> Result<()> {
    if label.is_empty() || label.len() > 64 {
        return Err(refuse!("a signer label must be 1 to 64 characters"));
    }
    if !label
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '-' || character == '_')
    {
        return Err(refuse!(
            "a signer label may only contain letters, digits, '-' and '_', found {label:?}"
        ));
    }
    Ok(())
}

/// Generates one signer key from the operating system CSPRNG.
///
/// One key, in one process, on one device. The caller never gets the chance to generate three.
pub fn generate(label: &str) -> Result<SignerSecret> {
    check_label(label)?;
    let secret = random_secret_key()?;
    let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret).serialize();

    Ok(SignerSecret {
        schema: SECRET_SCHEMA.to_string(),
        schema_version: SIGNER_SCHEMA_VERSION,
        label: label.to_string(),
        secret_key: hex::encode(secret.secret_bytes()),
        public_key: hex::encode(public_key),
        fingerprint: fingerprint(&public_key),
        created: crate::now_rfc3339(),
    })
}

/// 32 bytes from the operating system CSPRNG, redrawn in the astronomically unlikely case that
/// they are not a valid scalar.
fn random_secret_key() -> Result<SecretKey> {
    for _ in 0..16 {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        if let Ok(secret) = SecretKey::from_slice(&bytes) {
            return Ok(secret);
        }
    }
    Err(refuse!(
        "the operating system CSPRNG did not produce a usable key"
    ))
}

/// The scrypt work factor to encrypt a new backup with.
///
/// `None` means "let `age` target about one second on this device", which is what a real ceremony
/// wants. [`SCRYPT_LOG_N_ENV`] overrides it so tests stay fast.
fn configured_work_factor() -> Result<Option<u8>> {
    match std::env::var(SCRYPT_LOG_N_ENV) {
        Err(_) => Ok(None),
        Ok(value) => {
            let log_n: u8 = value.trim().parse().map_err(|_| {
                refuse!("{SCRYPT_LOG_N_ENV} must be a small whole number, found {value:?}")
            })?;
            if log_n == 0 || log_n >= 64 {
                return Err(refuse!("{SCRYPT_LOG_N_ENV} must be between 1 and 63"));
            }
            Ok(Some(log_n))
        }
    }
}

/// Encrypts a signer secret into an `age` passphrase (scrypt) file, with the work factor
/// [`SCRYPT_LOG_N_ENV`] asks for.
pub fn encrypt_backup(secret: &SignerSecret, passphrase: &Passphrase) -> Result<Vec<u8>> {
    encrypt_backup_with(secret, passphrase, configured_work_factor()?)
}

/// Encrypts a signer secret into an `age` passphrase (scrypt) file.
///
/// `work_factor` of `None` lets `age` target about one second on this device, which is what a real
/// ceremony wants; the tests pass a small value so the suite does not spend minutes in scrypt.
pub fn encrypt_backup_with(
    secret: &SignerSecret,
    passphrase: &Passphrase,
    work_factor: Option<u8>,
) -> Result<Vec<u8>> {
    let plaintext = serde_json::to_vec_pretty(secret)
        .map_err(|error| refuse!("could not serialize the signer record: {error}"))?;

    let mut recipient = age::scrypt::Recipient::new(passphrase.to_secret());
    if let Some(log_n) = work_factor {
        recipient.set_work_factor(log_n);
    }

    age::encrypt(&recipient, &plaintext)
        .map_err(|error| refuse!("could not encrypt the signer backup: {error}"))
}

/// Decrypts a signer backup.
///
/// A wrong passphrase, or any modification of the file, fails here: `age` is an authenticated
/// format, so there is no "decrypts to garbage" outcome to guard against separately.
pub fn decrypt_backup(ciphertext: &[u8], passphrase: &Passphrase) -> Result<SignerSecret> {
    let identity = age::scrypt::Identity::new(passphrase.to_secret());
    let plaintext = age::decrypt(&identity, ciphertext).map_err(|error| {
        refuse!("could not decrypt the signer backup (wrong passphrase, or the file was modified): {error}")
    })?;
    let secret: SignerSecret = serde_json::from_slice(&plaintext)
        .map_err(|error| refuse!("the backup does not contain a signer record: {error}"))?;
    // Recomputes the public key from the secret, so a tampered plaintext cannot slip through.
    secret.key_pair()?;
    Ok(secret)
}

/// Writes `bytes` to `path`, refusing to overwrite an existing file.
///
/// On Unix the file is created with mode `0600`. Windows has no equivalent call here: the file
/// inherits the directory's ACL, so `docs/swarm-treasury.md` tells the operator to keep signer
/// files in a directory only that user can read (and, in a real ceremony, on removable media).
pub fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|error| refuse!("could not create {}: {error}", parent.display()))?;
        }
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        refuse!(
            "could not create {} (an existing file is never overwritten): {error}",
            path.display()
        )
    })?;
    file.write_all(bytes)
        .map_err(|error| refuse!("could not write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| refuse!("could not flush {}: {error}", path.display()))?;
    Ok(())
}

/// Reads the backup passphrase, from [`PASSPHRASE_ENV`] if it is set, otherwise from a prompt.
///
/// The passphrase never comes from the command line, where it would be in the shell history and in
/// every process listing. The prompt reads a whole line from standard input; this terminal echoes
/// it, which is why the prompt says so and why an unattended run should use the environment
/// variable instead.
#[allow(clippy::print_stderr)]
pub fn read_passphrase(purpose: &str) -> Result<Passphrase> {
    if let Ok(value) = std::env::var(PASSPHRASE_ENV) {
        return Passphrase::new(value);
    }

    eprintln!("{purpose}");
    eprintln!(
        "passphrase (it will be shown as you type; set {PASSPHRASE_ENV} instead to avoid that):"
    );
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|error| refuse!("could not read the passphrase: {error}"))?;
    Passphrase::new(line.trim_end_matches(['\r', '\n']))
}

/// The two file names a `signer new` run produces, in `directory`.
pub fn signer_paths(directory: &Path, label: &str) -> (PathBuf, PathBuf) {
    (
        directory.join(format!("{label}.signer.age")),
        directory.join(format!("{label}.public.json")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_passphrase() -> Passphrase {
        Passphrase::new("correct horse battery staple").unwrap()
    }

    /// A deliberately weak scrypt work factor, so the test suite is not spent in a key derivation
    /// function. A real backup uses the default.
    const TEST_LOG_N: Option<u8> = Some(10);

    /// Generation, backup and recovery round-trip, entirely in memory.
    #[test]
    fn backup_round_trip() {
        let signer = generate("A").unwrap();
        let (secret, public_key) = signer.key_pair().unwrap();
        assert_eq!(signer.fingerprint, fingerprint(&public_key));

        let backup = encrypt_backup_with(&signer, &test_passphrase(), TEST_LOG_N).unwrap();
        assert!(
            !backup
                .windows(signer.secret_key.len())
                .any(|window| window == signer.secret_key.as_bytes()),
            "the encrypted backup must not contain the hex secret",
        );
        assert!(
            backup.starts_with(b"age-encryption.org/"),
            "the backup must be a real age file",
        );

        let recovered = decrypt_backup(&backup, &test_passphrase()).unwrap();
        let (recovered_secret, recovered_public) = recovered.key_pair().unwrap();
        assert_eq!(recovered_secret, secret);
        assert_eq!(recovered_public, public_key);
        assert_eq!(recovered.label, "A");
    }

    /// The wrong passphrase is refused, and the message does not leak the right one.
    #[test]
    fn wrong_passphrase_is_refused() {
        let signer = generate("B").unwrap();
        let backup = encrypt_backup_with(&signer, &test_passphrase(), TEST_LOG_N).unwrap();

        let error = decrypt_backup(&backup, &Passphrase::new("wrong").unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("could not decrypt"), "{error}");
        assert!(
            !error.contains(&signer.secret_key),
            "the refusal leaked the key"
        );
    }

    /// A modified backup fails the authentication tag rather than decrypting.
    #[test]
    fn modified_backup_is_refused() {
        let signer = generate("C").unwrap();
        let mut backup = encrypt_backup_with(&signer, &test_passphrase(), TEST_LOG_N).unwrap();
        let last = backup.len() - 1;
        backup[last] ^= 0x01;

        assert!(decrypt_backup(&backup, &test_passphrase()).is_err());
    }

    #[test]
    fn two_generated_keys_differ() {
        let first = generate("A").unwrap();
        let second = generate("A").unwrap();
        assert_ne!(first.public_key, second.public_key);
        assert_ne!(first.fingerprint, second.fingerprint);
    }

    #[test]
    fn labels_are_file_safe() {
        assert!(check_label("A").is_ok());
        assert!(check_label("device-1").is_ok());
        assert!(check_label("").is_err());
        assert!(check_label("../escape").is_err());
        assert!(check_label("with space").is_err());
        assert!(check_label("dot.in.name").is_err());
    }

    /// A public record whose fingerprint was edited is rejected.
    #[test]
    fn tampered_public_record_is_refused() {
        let signer = generate("A").unwrap();
        let mut public = signer.public();
        public.validate().unwrap();

        public.fingerprint = "00".repeat(8);
        assert!(public.validate().is_err());
    }

    #[test]
    fn empty_passphrases_are_refused() {
        assert!(Passphrase::new("").is_err());
        assert!(Passphrase::new("   ").is_err());
    }
}
