use crate::errors::BvfError;
use crate::locked::Locked;
use crate::private_key_format;
use crate::public_key_format;
use libsodium_rs::crypto_pwhash;
use libsodium_rs::crypto_scalarmult::curve25519;
use libsodium_rs::crypto_secretbox;
use libsodium_rs::ensure_init;

pub(crate) struct KeyManager {
    pub public_key: String,
    pub(crate) private_key: Locked<Vec<u8>>,
}

impl KeyManager {
    /// Decrypts and validates a private key using the given passphrase.
    ///
    /// # Errors
    /// Returns `BvfError::InvalidPrivateKeyFormat` if the key file is malformed.
    /// Returns `BvfError::DecryptionFailed` if key derivation fails.
    /// Returns `BvfError::WrongPassphrase` if secretbox decryption fails.
    /// Returns `BvfError::InvalidKey` if the decrypted key is invalid.
    /// Returns `BvfError::MemoryLockFailed` if `mlock` fails.
    ///
    /// # Panics
    /// Panics if libsodium fails to initialize.
    #[allow(clippy::needless_pass_by_value)] // passphrase consumed to prevent reuse
    pub(crate) fn new(
        encrypted_private_key: &[u8],
        passphrase: Locked<String>,
    ) -> Result<KeyManager, BvfError> {
        ensure_init().expect("Failed to initialize libsodium");
        let private_key = private_key_format::validate(encrypted_private_key)?;

        let symmetric_key = Locked::new(
            crypto_pwhash::pwhash(
                crypto_secretbox::KEYBYTES,
                passphrase.as_bytes(),
                &private_key.salt,
                crypto_pwhash::OPSLIMIT_SENSITIVE,
                crypto_pwhash::MEMLIMIT_SENSITIVE,
                crypto_pwhash::ALG_DEFAULT,
            )
            .map_err(|_| BvfError::DecryptionFailed)?,
        )?;

        let nonce = crypto_secretbox::Nonce::from_bytes(
            private_key
                .nonce
                .try_into()
                .map_err(|_| BvfError::InvalidPrivateKeyFormat)?,
        );
        let secretbox_key = crypto_secretbox::Key::from_bytes(&symmetric_key)
            .map_err(|_| BvfError::InvalidPrivateKeyFormat)?;
        let decrypted_private_key = Locked::new(
            crypto_secretbox::open(&private_key.ciphertext, &nonce, &secretbox_key)
                .map_err(|_| BvfError::WrongPassphrase)?,
        )?;

        let pubkey_raw = curve25519::scalarmult_base(&decrypted_private_key)
            .map_err(|_| BvfError::InvalidKey)?;
        let pubkey = public_key_format::encode(&pubkey_raw);

        Ok(KeyManager {
            public_key: pubkey,
            private_key: decrypted_private_key,
        })
    }
}
