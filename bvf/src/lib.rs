//! # Library for personal encryption
//!
//! Built on HPKE (RFC 9180) + XChaCha20-Poly1305 secretstream +
//! Argon2id. Minimization of crypto surface and amenability to
//! plaintext never touching disk, both in storage and consumption,
//! were primary in design. Sensitive material is mlocked and zeroized
//! on drop.
//!
//! # Two-tier API
//!
//! **High-level**: [`Encrypter::encrypt`] / [`Decrypter::decrypt`] — streaming
//! [`Read`](std::io::Read)/[`Write`](std::io::Write), chunking handled automatically.
//!
//! **Low-level** — push-based, one chunk at a time:
//! - [`Encrypter::start`] + [`EncryptionState::encrypt_chunk`]
//! - [`Decrypter::start`] + [`DecryptionState::decrypt_chunk`]
//!
//! # Examples
//! ## High-level
//! ```
//! use std::io::{Cursor, Seek, SeekFrom};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a keypair and export the private key protected by a passphrase
//! let keypair = bvf::Keypair::generate()?;
//! let passphrase = bvf::Locked::new("my passphrase".to_string())?;
//! let encrypted_key = keypair.export_encrypted_private_key(passphrase)?;
//!
//! // Encrypt
//! let mut plaintext = Cursor::new(b"hello world");
//! let mut ciphertext = Cursor::new(vec![]);
//! let encrypter = bvf::Encrypter::new(&keypair.public_key)?;
//! encrypter.encrypt(&mut plaintext, &mut ciphertext)?;
//!
//! // Decrypt
//! ciphertext.seek(SeekFrom::Start(0))?;
//! let mut recovered = Cursor::new(vec![]);
//! let passphrase = bvf::Locked::new("my passphrase".to_string())?;
//! let decrypter = bvf::Decrypter::new(&encrypted_key, passphrase)?;
//! decrypter.decrypt(&mut ciphertext, &mut recovered)?;
//!
//! assert_eq!(recovered.into_inner(), b"hello world");
//! # Ok(())
//! # }
//! ```
//! ## Low-level
//! ```
//! use bvf::config::HEADER_SIZE;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let keypair = bvf::Keypair::generate()?;
//! let passphrase = bvf::Locked::new("my passphrase".to_string())?;
//! let encrypted_key = keypair.export_encrypted_private_key(passphrase)?;
//!
//! // Encrypt
//! let encrypter = bvf::Encrypter::new(&keypair.public_key)?;
//! let (header, mut state) = encrypter.start()?;
//! let mut ciphertext = header;
//! ciphertext.extend(state.encrypt_chunk(b"hello world", true)?);
//!
//! // Decrypt
//! let passphrase = bvf::Locked::new("my passphrase".to_string())?;
//! let decrypter = bvf::Decrypter::new(&encrypted_key, passphrase)?;
//! let header: [u8; HEADER_SIZE] = ciphertext[..HEADER_SIZE].try_into()?;
//! let mut state = decrypter.start(&header)?;
//! let plaintext = state.decrypt_chunk(&ciphertext[HEADER_SIZE..])?;
//! state.validate_complete()?;
//!
//! assert_eq!(plaintext, b"hello world");
//! # Ok(())
//! # }
//! ```

pub mod config;
pub mod decrypter;
pub mod encrypter;
pub mod errors;
mod io;
mod key_manager;
pub mod keypair;
pub mod locked;
mod private_key_format;
mod public_key_format;

pub use decrypter::Decrypter;
pub use encrypter::Encrypter;
pub use errors::BvfError;
pub use keypair::Keypair;
pub use locked::Locked;
