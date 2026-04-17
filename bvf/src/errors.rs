#[derive(Debug)]
pub enum BvfError {
    /// Invalid encrypted private key format (bad JSON, missing fields, bad base64, or ct too short).
    InvalidPrivateKeyFormat,
    /// Invalid public key format string (missing prefix, bad base64, wrong length, or checksum mismatch).
    InvalidPublicKeyFormat,
    /// Secretbox decryption of private key failed (wrong passphrase).
    WrongPassphrase,
    /// Argon2id key derivation, secretstream init/pull, or state misuse (e.g. decrypt after `TAG_FINAL`).
    DecryptionFailed,
    /// Public or private key has wrong length or failed to construct.
    InvalidKey,
    /// HPKE setup, secretstream init/push, secretbox, random generation, or JSON serialization failed.
    EncryptionFailed,
    /// mlock failed (system memory locking unavailable).
    MemoryLockFailed,
    /// Header too short, version mismatch, or trailing data after `TAG_FINAL`.
    InvalidFormat,
    /// Stream ended without `TAG_FINAL` (truncated file).
    Truncated,
    /// Secretstream authentication tag verification failed (tampered or corrupted ciphertext).
    AuthenticationFailed,
}

impl std::fmt::Display for BvfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPrivateKeyFormat => {
                write!(f, "invalid encrypted private key format")
            }
            Self::InvalidPublicKeyFormat => write!(f, "invalid public key format"),
            Self::WrongPassphrase => write!(f, "wrong passphrase"),
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::InvalidKey => write!(f, "invalid key"),
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::MemoryLockFailed => write!(f, "failed to lock memory"),
            Self::InvalidFormat => write!(f, "not a valid bvf file"),
            Self::Truncated => write!(f, "file is truncated"),
            Self::AuthenticationFailed => {
                write!(f, "file is corrupted or was encrypted for a different key")
            }
        }
    }
}

impl std::error::Error for BvfError {}
