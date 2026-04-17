use crate::config::{CHUNK_SIZE, HPKE_EXPORT_CONTEXT, HPKE_INFO, VERSION_HEADER};
use crate::errors::BvfError;
use crate::io::read_exact_or_less;
use crate::public_key_format;
use hpke::aead::ExportOnlyAead;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeS, Serializable, setup_sender};
use libsodium_rs::crypto_secretstream::xchacha20poly1305::{
    self, KEYBYTES, TAG_FINAL, TAG_MESSAGE,
};
use libsodium_rs::crypto_secretstream::{Key, PushState};
use libsodium_rs::ensure_init;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::io::{Read, Write};
use std::mem::swap;
use zeroize::Zeroizing;

/// Per-encryption state obtained from [`Encrypter::start`]; call
/// [`encrypt_chunk`](EncryptionState::encrypt_chunk) to push chunks.
pub struct EncryptionState {
    state: xchacha20poly1305::PushState,
    finalized: bool,
}

impl EncryptionState {
    /// Encrypts a single plaintext chunk.
    ///
    /// # Errors
    /// Returns `BvfError::EncryptionFailed` if already finalized, chunk size is wrong, or encryption fails.
    pub fn encrypt_chunk(
        &mut self,
        plaintext: &[u8],
        is_last: bool,
    ) -> Result<Vec<u8>, BvfError> {
        if self.finalized {
            return Err(BvfError::EncryptionFailed);
        }
        if !is_last && plaintext.len() != CHUNK_SIZE {
            return Err(BvfError::EncryptionFailed);
        }
        let tag = if is_last { TAG_FINAL } else { TAG_MESSAGE };
        let ciphertext = self
            .state
            .push(plaintext, None, tag)
            .map_err(|_| BvfError::EncryptionFailed)?;
        if is_last {
            self.finalized = true;
        }
        Ok(ciphertext)
    }
}

/// Holds a recipient's public key. Reuse a single instance to encrypt
/// any number of streams.
pub struct Encrypter {
    public_key: <X25519HkdfSha256 as Kem>::PublicKey,
}

impl Encrypter {
    /// Creates an encrypter for the given public key.
    ///
    /// # Errors
    /// Returns `BvfError::InvalidPublicKeyFormat` if the key string is malformed.
    /// Returns `BvfError::EncryptionFailed` if the key bytes are invalid.
    ///
    /// # Panics
    /// Panics if libsodium fails to initialize.
    pub fn new(encoded_pubkey: &str) -> Result<Encrypter, BvfError> {
        ensure_init().expect("Failed to initialize libsodium");
        let pubkey = public_key_format::decode(encoded_pubkey)?;
        let hpke_key = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&pubkey)
            .map_err(|_| BvfError::EncryptionFailed)?;
        Ok(Encrypter {
            public_key: hpke_key,
        })
    }

    /// Performs HPKE key encapsulation and initializes the secretstream.
    ///
    /// # Errors
    /// Returns `BvfError::EncryptionFailed` if HPKE setup or secretstream init fails.
    pub fn start(&self) -> Result<(Vec<u8>, EncryptionState), BvfError> {
        let mut rng = StdRng::from_os_rng();
        let (enc, sender) =
            setup_sender::<ExportOnlyAead, HkdfSha256, X25519HkdfSha256, _>(
                &OpModeS::Base,
                &self.public_key,
                HPKE_INFO,
                &mut rng,
            )
            .map_err(|_| BvfError::EncryptionFailed)?;
        let mut master_key = Zeroizing::new([0u8; KEYBYTES]);
        sender
            .export(HPKE_EXPORT_CONTEXT, &mut *master_key)
            .map_err(|_| BvfError::EncryptionFailed)?;

        let ss_key =
            Key::from_bytes(&*master_key).map_err(|_| BvfError::EncryptionFailed)?;
        let (state, ss_header) =
            PushState::init_push(&ss_key).map_err(|_| BvfError::EncryptionFailed)?;
        let mut header = VERSION_HEADER.to_vec();
        header.extend_from_slice(&enc.to_bytes());
        header.extend_from_slice(&ss_header);

        Ok((
            header,
            EncryptionState {
                state,
                finalized: false,
            },
        ))
    }

    /// Encrypts a source stream to a destination in bvf-v1 format.
    ///
    /// # Errors
    /// Returns `BvfError::EncryptionFailed` if any I/O or crypto operation fails.
    pub fn encrypt<W: Write, R: Read>(
        &self,
        src: &mut R,
        dst: &mut W,
    ) -> Result<(), BvfError> {
        let (header, mut state) = self.start()?;
        dst.write_all(&header)
            .map_err(|_| BvfError::EncryptionFailed)?;

        let mut current = vec![0u8; CHUNK_SIZE];
        let mut currlen = read_exact_or_less(src, &mut current)
            .map_err(|_| BvfError::EncryptionFailed)?;

        if current.is_empty() {
            let ct = state.encrypt_chunk(b"", true)?;
            dst.write_all(&ct).map_err(|_| BvfError::EncryptionFailed)?;
            return Ok(());
        }

        let mut next = vec![0u8; CHUNK_SIZE];
        loop {
            let mut nextlen = read_exact_or_less(src, &mut next)
                .map_err(|_| BvfError::EncryptionFailed)?;

            let is_last = nextlen == 0;
            // Read contract guarantees chunklen <= buf.len(); panic correct if violated
            #[allow(clippy::indexing_slicing)]
            let ct = state.encrypt_chunk(&current[..currlen], is_last)?;
            dst.write_all(&ct).map_err(|_| BvfError::EncryptionFailed)?;
            if is_last {
                break Ok(());
            }
            swap(&mut current, &mut next);
            swap(&mut currlen, &mut nextlen);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn after_finalized() -> Result<(), Box<dyn std::error::Error>> {
        let master_key = Zeroizing::new([0u8; KEYBYTES]);
        let ss_key = Key::from_bytes(&*master_key)?;
        let (state, _) = PushState::init_push(&ss_key)?;
        let mut state = EncryptionState {
            state,
            finalized: true,
        };
        let result = state.encrypt_chunk(b"wee", true);
        assert!(matches!(result, Err(BvfError::EncryptionFailed)));
        Ok(())
    }
}
