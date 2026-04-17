use crate::errors::BvfError;
use base64::prelude::*;
use libsodium_rs::crypto_scalarmult;
use sha2::{Digest, Sha256};

pub(crate) fn encode(raw_key: &[u8; crypto_scalarmult::BYTES]) -> String {
    let b64_key = BASE64_STANDARD.encode(raw_key);
    let digest = Sha256::digest(raw_key);
    #[allow(clippy::indexing_slicing)] // SHA-256 digest 32
    let checksum = BASE64_STANDARD.encode(&digest[..4]);
    format!("bvf-pub:{b64_key}.{checksum}")
}

pub(crate) fn decode(key: &str) -> Result<[u8; crypto_scalarmult::BYTES], BvfError> {
    let (header, rest) = key
        .split_at_checked(8)
        .ok_or(BvfError::InvalidPublicKeyFormat)?;
    if header != "bvf-pub:" {
        return Err(BvfError::InvalidPublicKeyFormat);
    }
    let (key_b64, checksum) = rest
        .split_once('.')
        .ok_or(BvfError::InvalidPublicKeyFormat)?;
    if checksum.len() != 8 {
        return Err(BvfError::InvalidPublicKeyFormat);
    }
    let key_vec = BASE64_STANDARD
        .decode(key_b64)
        .map_err(|_| BvfError::InvalidPublicKeyFormat)?;
    let key_bytes: [u8; crypto_scalarmult::BYTES] = key_vec
        .try_into()
        .map_err(|_| BvfError::InvalidPublicKeyFormat)?;
    let digest = Sha256::digest(key_bytes);
    #[allow(clippy::indexing_slicing)] // SHA-256 digest 32
    let key_check = BASE64_STANDARD.encode(&digest[..4]);
    if key_check != checksum {
        return Err(BvfError::InvalidPublicKeyFormat);
    }
    Ok(key_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_checksum() -> Result<(), Box<dyn std::error::Error>> {
        let raw_key = [0u8; crypto_scalarmult::BYTES];
        let key = encode(&raw_key);
        let mut bytes = key.into_bytes();
        let i = bytes.len() - 3;
        bytes[i] ^= 1;
        let bad_key = String::from_utf8(bytes)?;
        let result = decode(&bad_key);
        assert!(matches!(result, Err(BvfError::InvalidPublicKeyFormat)));
        Ok(())
    }
}
