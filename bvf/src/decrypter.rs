use crate::config::{
    CIPHERTEXT_CHUNK_SIZE, HEADER_SIZE, HPKE_EXPORT_CONTEXT, HPKE_INFO, VERSION_HEADER,
};
use crate::errors::BvfError;
use crate::io::read_exact_or_less;
use crate::key_manager::KeyManager;
use crate::locked::Locked;
use hpke::aead::ExportOnlyAead;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, setup_receiver};
use libsodium_rs::crypto_scalarmult::BYTES as X25519_BYTES;
use libsodium_rs::crypto_secretstream::xchacha20poly1305::{
    self, ABYTES, HEADERBYTES as SS_HEADERBYTES, KEYBYTES as SS_KEYBYTES, TAG_FINAL,
};
use libsodium_rs::crypto_secretstream::{Key, PullState};
use libsodium_rs::ensure_init;
use std::io::{Read, Write};
use zeroize::Zeroizing;

/// Per-decryption state obtained from [`Decrypter::start`]; call
/// [`decrypt_chunk`](DecryptionState::decrypt_chunk) to pull chunks.
pub struct DecryptionState {
    state: xchacha20poly1305::PullState,
    finalized: bool,
}

impl DecryptionState {
    /// Decrypts a single ciphertext chunk.
    ///
    /// # Errors
    /// Returns `BvfError::DecryptionFailed` if already finalized, or ciphertext is empty/too short.
    /// Returns `BvfError::AuthenticationFailed` if the chunk fails authentication.
    pub fn decrypt_chunk(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, BvfError> {
        if self.finalized {
            return Err(BvfError::DecryptionFailed);
        }
        if ciphertext.is_empty() {
            return Err(BvfError::DecryptionFailed);
        }
        if ciphertext.len() < ABYTES {
            return Err(BvfError::DecryptionFailed);
        }
        let (plaintext, tag) = self
            .state
            .pull(ciphertext, None)
            .map_err(|_| BvfError::AuthenticationFailed)?;
        if tag == TAG_FINAL {
            self.finalized = true;
        }
        Ok(plaintext)
    }

    /// Checks that the stream ended with a final tag.
    ///
    /// # Errors
    /// Returns `BvfError::Truncated` if no final tag was received.
    pub fn validate_complete(&self) -> Result<(), BvfError> {
        if !self.finalized {
            return Err(BvfError::Truncated);
        }
        Ok(())
    }
}

/// Holds a recipient's decrypted private key (mlocked, zeroized on drop);
/// reuse a single instance to decrypt any number of streams.
pub struct Decrypter {
    key_manager: KeyManager,
}

impl Decrypter {
    /// Returns the public key string derived from the decrypted private key.
    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.key_manager.public_key
    }

    /// Creates a decrypter by unlocking a private key with the given passphrase.
    ///
    /// # Errors
    /// Returns [`BvfError::InvalidPrivateKeyFormat`] if the key data is malformed.
    /// Returns [`BvfError::DecryptionFailed`] if Argon2id key derivation fails.
    /// Returns [`BvfError::WrongPassphrase`] if secretbox decryption fails.
    /// Returns [`BvfError::InvalidKey`] if the decrypted key is invalid.
    /// Returns [`BvfError::MemoryLockFailed`] if `mlock` fails.
    ///
    /// # Panics
    /// Panics if libsodium fails to initialize.
    pub fn new(
        encrypted_private_key: &[u8],
        passphrase: Locked<String>,
    ) -> Result<Decrypter, BvfError> {
        ensure_init().expect("Failed to initialize libsodium");
        let km = KeyManager::new(encrypted_private_key, passphrase)?;
        Ok(Decrypter { key_manager: km })
    }

    /// Parses a bvf-v1 header and initializes the decryption secretstream.
    ///
    /// # Errors
    /// Returns `BvfError::InvalidFormat` if the header version or structure is wrong.
    /// Returns `BvfError::DecryptionFailed` if HPKE decapsulation or secretstream init fails.
    /// Returns `BvfError::InvalidKey` if the private key is invalid.
    // all slicing on &[u8; HEADER_SIZE] with const offsets
    #[allow(clippy::indexing_slicing)]
    pub fn start(&self, header: &[u8; HEADER_SIZE]) -> Result<DecryptionState, BvfError> {
        let mut offset = VERSION_HEADER.len();
        let version = &header[0..offset];
        if version != VERSION_HEADER {
            return Err(BvfError::InvalidFormat);
        }
        let enc = &header[offset..offset + X25519_BYTES];
        offset += X25519_BYTES;
        let ss_header: &[u8; SS_HEADERBYTES] = &header[offset..offset + SS_HEADERBYTES]
            .try_into()
            .map_err(|_| BvfError::InvalidFormat)?;
        let encapped_key = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(enc)
            .map_err(|_| BvfError::DecryptionFailed)?;

        let hpke_private_key = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(
            &self.key_manager.private_key,
        )
        .map_err(|_| BvfError::InvalidKey)?;

        let receiver = setup_receiver::<ExportOnlyAead, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &hpke_private_key,
            &encapped_key,
            HPKE_INFO,
        )
        .map_err(|_| BvfError::DecryptionFailed)?;
        let mut master_key = Zeroizing::new([0u8; SS_KEYBYTES]);
        receiver
            .export(HPKE_EXPORT_CONTEXT, &mut *master_key)
            .map_err(|_| BvfError::DecryptionFailed)?;
        let ss_key =
            Key::from_bytes(&*master_key).map_err(|_| BvfError::DecryptionFailed)?;
        let state = PullState::init_pull(ss_header, &ss_key)
            .map_err(|_| BvfError::DecryptionFailed)?;
        Ok(DecryptionState {
            state,
            finalized: false,
        })
    }

    /// Decrypts a bvf-v1 source stream to a destination.
    ///
    /// # Errors
    /// Returns `BvfError::InvalidFormat` if the header is invalid or trailing data exists.
    /// Returns `BvfError::DecryptionFailed` if any I/O or crypto operation fails.
    /// Returns `BvfError::AuthenticationFailed` if a chunk fails authentication.
    /// Returns `BvfError::Truncated` if the stream ends without a final tag.
    /// Returns `BvfError::InvalidKey` if the private key is invalid.
    pub fn decrypt<W: Write, R: Read>(
        &self,
        src: &mut R,
        dst: &mut W,
    ) -> Result<(), BvfError> {
        let mut header = [0u8; HEADER_SIZE];
        src.read_exact(&mut header)
            .map_err(|_| BvfError::InvalidFormat)?;
        let mut state = self.start(&header)?;
        let mut chunk = vec![0u8; CIPHERTEXT_CHUNK_SIZE];
        loop {
            let chunklen = read_exact_or_less(src, &mut chunk)
                .map_err(|_| BvfError::DecryptionFailed)?;
            if chunklen == 0 {
                return state.validate_complete();
            }

            // Read contract guarantees chunklen <= buf.len(); panic correct if violated
            #[allow(clippy::indexing_slicing)]
            let pt = state.decrypt_chunk(&chunk[..chunklen])?;
            dst.write_all(&pt).map_err(|_| BvfError::DecryptionFailed)?;

            if state.finalized {
                let mut trailing = [0u8; 1];
                let trailinglen = src
                    .read(&mut trailing)
                    .map_err(|_| BvfError::DecryptionFailed)?;
                if trailinglen > 0 {
                    return Err(BvfError::InvalidFormat);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsodium_rs::crypto_secretstream::xchacha20poly1305::{
        HEADERBYTES as SS_HEADERBYTES, KEYBYTES,
    };

    #[test]
    fn after_finalized() -> Result<(), Box<dyn std::error::Error>> {
        let master_key = Zeroizing::new([0u8; KEYBYTES]);
        let ss_key = Key::from_bytes(&*master_key)?;
        let ss_header = [0u8; SS_HEADERBYTES];
        let ss_state = PullState::init_pull(&ss_header, &ss_key)?;
        let mut state = DecryptionState {
            state: ss_state,
            finalized: true,
        };
        let chunk = [0u8; CIPHERTEXT_CHUNK_SIZE];
        let result = state.decrypt_chunk(&chunk);
        assert!(matches!(result, Err(BvfError::DecryptionFailed)));
        Ok(())
    }

    #[test]
    fn validate_incomplete() -> Result<(), Box<dyn std::error::Error>> {
        let master_key = Zeroizing::new([0u8; KEYBYTES]);
        let ss_key = Key::from_bytes(&*master_key)?;
        let ss_header = [0u8; SS_HEADERBYTES];
        let ss_state = PullState::init_pull(&ss_header, &ss_key)?;
        let state = DecryptionState {
            state: ss_state,
            finalized: false,
        };
        let result = state.validate_complete();
        assert!(matches!(result, Err(BvfError::Truncated)));
        Ok(())
    }
}
