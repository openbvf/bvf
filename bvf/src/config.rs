use libsodium_rs::crypto_scalarmult::BYTES as X25519_BYTES;
use libsodium_rs::crypto_secretstream::xchacha20poly1305::HEADERBYTES as SS_HEADERBYTES;

pub(crate) const VERSION_HEADER: &[u8; 7] = b"bvf-v1\n";
pub(crate) const HPKE_INFO: &[u8] = b"bvf.hpke.x25519-sha256-exportonly";
pub(crate) const HPKE_EXPORT_CONTEXT: &[u8] = b"bvf-master";
/// Plaintext chunk size
pub const CHUNK_SIZE: usize = 64 * 1024;

/// bvf-v1 header size in bytes; read this many bytes before passing
/// to [`Decrypter::start`](crate::Decrypter::start).
pub const HEADER_SIZE: usize = VERSION_HEADER.len() + X25519_BYTES + SS_HEADERBYTES;
