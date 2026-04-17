use crate::errors::BvfError;
use crate::locked::Locked;
use crate::public_key_format;
use base64::prelude::*;
use libsodium_rs::crypto_box;
use libsodium_rs::crypto_pwhash;
use libsodium_rs::crypto_secretbox;
use libsodium_rs::ensure_init;
use libsodium_rs::random;
use serde_json::json;

/// An X25519 keypair. The private key is mlocked and zeroized on drop.
pub struct Keypair {
    /// Base64-encoded public key with checksum prefix, suitable for
    /// passing to [`Encrypter::new`](crate::Encrypter::new).
    pub public_key: String,
    private_key: Locked<Vec<u8>>,
}

impl Keypair {
    /// Generates a new X25519 keypair.
    ///
    /// # Panics
    /// Panics if libsodium fails to initialize or if `mlock` is unavailable.
    #[must_use]
    pub fn generate() -> Keypair {
        ensure_init().expect("Failed to initialize libsodium");
        let kp = crypto_box::KeyPair::generate();
        Keypair {
            public_key: public_key_format::encode(kp.public_key.as_bytes()),
            private_key: Locked::new(kp.secret_key.as_bytes().to_vec())
                .expect("mlock failed: system memory locking unavailable"),
        }
    }

    /// Encrypts the private key for storage using Argon2id + XSalsa20-Poly1305.
    ///
    /// # Errors
    /// Returns [`BvfError::EncryptionFailed`] if key derivation or encryption fails.
    /// Returns [`BvfError::MemoryLockFailed`] if `mlock` fails.
    #[allow(clippy::needless_pass_by_value)] // passphrase consumed to prevent reuse
    pub fn export_encrypted_private_key(
        &self,
        passphrase: Locked<String>,
    ) -> Result<Vec<u8>, BvfError> {
        let mut salt = [0u8; crypto_pwhash::SALTBYTES];
        random::fill_bytes(&mut salt);

        let key = Locked::new(
            crypto_pwhash::pwhash(
                crypto_box::SECRETKEYBYTES,
                passphrase.as_bytes(),
                &salt,
                crypto_pwhash::OPSLIMIT_SENSITIVE,
                crypto_pwhash::MEMLIMIT_SENSITIVE,
                crypto_pwhash::ALG_DEFAULT,
            )
            .map_err(|_| BvfError::EncryptionFailed)?,
        )?;

        let nonce = crypto_secretbox::Nonce::generate();
        let key = crypto_secretbox::Key::from_bytes(&key)
            .map_err(|_| BvfError::EncryptionFailed)?;
        let ciphertext = crypto_secretbox::seal(&self.private_key, &nonce, &key);

        let data = json!({
                "salt": BASE64_STANDARD.encode(salt),
                "nonce": BASE64_STANDARD.encode(nonce),
                "ct": BASE64_STANDARD.encode(ciphertext)
        });

        Ok(data.to_string().into())
    }
}
