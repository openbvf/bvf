use bvf::config::CHUNK_SIZE;
use bvf::decrypter::Decrypter;
use bvf::encrypter::Encrypter;
use bvf::errors::BvfError;
use bvf::keypair::Keypair;
use bvf::locked::Locked;
use rand::RngCore;
use std::io::Cursor;
use std::io::{Seek, SeekFrom};

fn e2e(plaintext: &mut [u8]) {
    let kp = Keypair::generate().expect("generate bomb");
    let passphrase = Locked::new("hi".to_string()).unwrap();
    let key = kp
        .export_encrypted_private_key(passphrase)
        .expect("key export bomb");

    let encrypter = Encrypter::new(&kp.public_key).expect("encrypter bomb");
    let mut source = Cursor::new(plaintext);
    let mut target = Cursor::new(vec![]);
    encrypter
        .encrypt(&mut source, &mut target)
        .expect("Encryption failed");

    let passphrase = Locked::new("hi".to_string()).unwrap();
    let decrypter = Decrypter::new(&key, passphrase).expect("decrypter bomb");
    let mut back_again = Cursor::new(vec![]);

    target.seek(SeekFrom::Start(0)).expect("seek bomb");
    decrypter
        .decrypt(&mut target, &mut back_again)
        .expect("Decryption failed");
    let orig = source.into_inner();
    let endup = back_again.into_inner();
    assert_eq!(orig, &endup);
}

#[test]
fn roundtrip_multichunk() {
    let mut plaintext = vec![0u8; CHUNK_SIZE * 3 * 1024];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut plaintext);
    e2e(&mut plaintext);
}

#[test]
fn roundtrip_empty() {
    let mut plaintext = vec![0u8; 0];
    e2e(&mut plaintext);
}

#[test]
fn wrong_passphrase() {
    let kp = Keypair::generate().expect("generate bomb");
    let passphrase = Locked::new("hi".to_string()).unwrap();
    let key = kp
        .export_encrypted_private_key(passphrase)
        .expect("key export bomb");
    let passphrase = Locked::new("bye".to_string()).unwrap();
    let result = Decrypter::new(&key, passphrase);
    assert!(matches!(result, Err(BvfError::WrongPassphrase)));
}

#[test]
fn truncated_ciphertext() -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = vec![0u8; CHUNK_SIZE];
    let keypair = Keypair::generate().expect("generate bomb");
    let passphrase = Locked::new("hi".to_string())?;
    let encrypted_key = keypair.export_encrypted_private_key(passphrase)?;

    let encrypter = Encrypter::new(&keypair.public_key)?;
    let (header, mut state) = encrypter.start()?;
    let mut ciphertext = header;
    ciphertext.extend(state.encrypt_chunk(&plaintext, false)?);
    ciphertext.extend(state.encrypt_chunk(&plaintext, false)?);

    let mut orig = Cursor::new(&ciphertext);
    let mut recovered = Cursor::new(vec![]);
    let passphrase = Locked::new("hi".to_string())?;
    let decrypter = Decrypter::new(&encrypted_key, passphrase)?;
    let result = decrypter.decrypt(&mut orig, &mut recovered);
    assert!(matches!(result, Err(BvfError::Truncated)));
    Ok(())
}

#[test]
fn trailing_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = vec![0u8; CHUNK_SIZE];
    let keypair = Keypair::generate().expect("generate bomb");
    let passphrase = Locked::new("hi".to_string())?;
    let encrypted_key = keypair.export_encrypted_private_key(passphrase)?;

    let encrypter = Encrypter::new(&keypair.public_key)?;
    let (header, mut state) = encrypter.start()?;
    let mut ciphertext = header;
    ciphertext.extend(state.encrypt_chunk(&plaintext, true)?);
    ciphertext.extend(&plaintext[..4]);

    let mut orig = Cursor::new(&ciphertext);
    let mut recovered = Cursor::new(vec![]);
    let passphrase = Locked::new("hi".to_string())?;
    let decrypter = Decrypter::new(&encrypted_key, passphrase)?;
    let result = decrypter.decrypt(&mut orig, &mut recovered);
    assert!(matches!(result, Err(BvfError::InvalidFormat)));
    Ok(())
}

#[test]
fn ciphertext_corruption() -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = vec![0u8; CHUNK_SIZE];
    let keypair = Keypair::generate().expect("generate bomb");
    let passphrase = Locked::new("hi".to_string())?;
    let encrypted_key = keypair.export_encrypted_private_key(passphrase)?;

    let encrypter = Encrypter::new(&keypair.public_key)?;
    let (header, mut state) = encrypter.start()?;
    let mut ciphertext = header;
    ciphertext.extend(state.encrypt_chunk(&plaintext, false)?);
    ciphertext.extend(state.encrypt_chunk(&plaintext, true)?);
    ciphertext[CHUNK_SIZE / 2] ^= 1;

    let mut orig = Cursor::new(&ciphertext);
    let mut recovered = Cursor::new(vec![]);
    let passphrase = Locked::new("hi".to_string())?;
    let decrypter = Decrypter::new(&encrypted_key, passphrase)?;
    let result = decrypter.decrypt(&mut orig, &mut recovered);
    assert!(matches!(result, Err(BvfError::AuthenticationFailed)));
    Ok(())
}

#[test]
fn rng_ephemeral_uniqueness() -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = vec![0u8; 5];
    let kp = Keypair::generate().expect("generate bomb");
    let encrypter = Encrypter::new(&kp.public_key).expect("encrypter bomb");
    let mut source = Cursor::new(plaintext);
    let mut target = Cursor::new(vec![]);
    encrypter
        .encrypt(&mut source, &mut target)
        .expect("Encryption failed");

    let uno = target.into_inner();
    source.seek(SeekFrom::Start(0)).expect("seek bomb");
    let mut target = Cursor::new(vec![]);
    encrypter
        .encrypt(&mut source, &mut target)
        .expect("Encryption failed");
    let due = target.into_inner();
    assert_ne!(uno, due);
    Ok(())
}

#[test]
fn invalid_version_header() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Keypair::generate().expect("generate bomb");
    let passphrase = Locked::new("hi".to_string())?;
    let encrypted_key = keypair.export_encrypted_private_key(passphrase)?;

    let encrypter = Encrypter::new(&keypair.public_key)?;
    let (header, _) = encrypter.start()?;
    let mut ciphertext = header;
    ciphertext[1] = b'X';

    let mut orig = Cursor::new(&ciphertext);
    let mut recovered = Cursor::new(vec![]);
    let passphrase = Locked::new("hi".to_string())?;
    let decrypter = Decrypter::new(&encrypted_key, passphrase)?;
    let result = decrypter.decrypt(&mut orig, &mut recovered);
    assert!(matches!(result, Err(BvfError::InvalidFormat)));
    Ok(())
}
