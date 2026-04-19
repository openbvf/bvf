use crate::errors::BvfError;
use base64::prelude::*;
use libsodium_rs::crypto_pwhash;
use libsodium_rs::crypto_secretbox;
use serde::Deserialize;

pub struct PrivateKey {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Deserialize, Debug)]
struct PrivateKeyB64 {
    salt: String,
    nonce: String,
    ct: String,
}

pub(crate) fn validate(data: &[u8]) -> Result<PrivateKey, BvfError> {
    let encoded_private_key: PrivateKeyB64 =
        serde_json::from_slice(data).map_err(|_| BvfError::InvalidPrivateKeyFormat)?;
    let salt = BASE64_STANDARD
        .decode(encoded_private_key.salt)
        .map_err(|_| BvfError::InvalidPrivateKeyFormat)?;
    let nonce = BASE64_STANDARD
        .decode(encoded_private_key.nonce)
        .map_err(|_| BvfError::InvalidPrivateKeyFormat)?;
    let ciphertext = BASE64_STANDARD
        .decode(encoded_private_key.ct)
        .map_err(|_| BvfError::InvalidPrivateKeyFormat)?;
    let ct_len = crypto_secretbox::KEYBYTES + crypto_secretbox::MACBYTES;
    if salt.len() != crypto_pwhash::SALTBYTES
        || nonce.len() != crypto_secretbox::NONCEBYTES
        || ciphertext.len() != ct_len
    {
        return Err(BvfError::InvalidPrivateKeyFormat);
    }
    Ok(PrivateKey {
        salt,
        nonce,
        ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate_bad(
        salt: &str,
        nonce: &str,
        ct: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = format!(
            r#"{{ "salt": "{}", "nonce": "{}", "ct": "{}" }}"#,
            salt, nonce, ct
        );
        let result = validate(json.as_bytes());
        assert!(matches!(result, Err(BvfError::InvalidPrivateKeyFormat)));
        Ok(())
    }

    fn good_parts() -> (String, String, String) {
        let salt = BASE64_STANDARD.encode(&[0u8; crypto_pwhash::SALTBYTES]);
        let nonce = BASE64_STANDARD.encode(&[0u8; crypto_secretbox::NONCEBYTES]);
        let ct = BASE64_STANDARD
            .encode(&[0u8; crypto_secretbox::KEYBYTES + crypto_secretbox::MACBYTES]);
        (salt, nonce, ct)
    }

    #[test]
    fn bad_salt_length() -> Result<(), Box<dyn std::error::Error>> {
        let (_, nonce, ct) = good_parts();
        let bad_salt = BASE64_STANDARD.encode(&[0u8; crypto_pwhash::SALTBYTES - 1]);
        validate_bad(&bad_salt, &nonce, &ct)?;
        Ok(())
    }

    #[test]
    fn bad_nonce_length() -> Result<(), Box<dyn std::error::Error>> {
        let (salt, _, ct) = good_parts();
        let bad_nonce = BASE64_STANDARD.encode(&[0u8; crypto_secretbox::NONCEBYTES - 1]);
        validate_bad(&salt, &bad_nonce, &ct)?;
        Ok(())
    }

    #[test]
    fn bad_ct_length() -> Result<(), Box<dyn std::error::Error>> {
        let (salt, nonce, _) = good_parts();
        let bad_ct = BASE64_STANDARD
            .encode(&[0u8; crypto_secretbox::KEYBYTES + crypto_secretbox::MACBYTES - 1]);
        validate_bad(&salt, &nonce, &bad_ct)?;
        Ok(())
    }
}
