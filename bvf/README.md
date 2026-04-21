<!-- cargo-rdme start -->

# Library for personal encryption

Built on HPKE (RFC 9180) + XChaCha20-Poly1305 secretstream +
Argon2id. Minimization of crypto surface and amenability to
plaintext never touching disk, both in storage and consumption,
were primary in design. Sensitive material is mlocked and zeroized
on drop.

Every line lovingly crafted by a human.

# Two-tier API

**High-level**: [`Encrypter::encrypt`] / [`Decrypter::decrypt`] — streaming
[`Read`](std::io::Read)/[`Write`](std::io::Write), chunking handled automatically.

**Low-level** — push-based, one chunk at a time:
- [`Encrypter::start`] + [`encrypter::EncryptionState::encrypt_chunk`]
- [`Decrypter::start`] + [`decrypter::DecryptionState::decrypt_chunk`]

# Examples
## High-level
```rust
use std::io::{Cursor, Seek, SeekFrom};

// Generate a keypair and export the private key protected by a passphrase
let keypair = bvf::Keypair::generate()?;
let passphrase = bvf::Locked::new("my passphrase".to_string())?;
let encrypted_key = keypair.export_encrypted_private_key(passphrase)?;

// Encrypt
let mut plaintext = Cursor::new(b"hello world");
let mut ciphertext = Cursor::new(vec![]);
let encrypter = bvf::Encrypter::new(&keypair.public_key)?;
encrypter.encrypt(&mut plaintext, &mut ciphertext)?;

// Decrypt
ciphertext.seek(SeekFrom::Start(0))?;
let mut recovered = Cursor::new(vec![]);
let passphrase = bvf::Locked::new("my passphrase".to_string())?;
let decrypter = bvf::Decrypter::new(&encrypted_key, passphrase)?;
decrypter.decrypt(&mut ciphertext, &mut recovered)?;

assert_eq!(recovered.into_inner(), b"hello world");
```
## Low-level
```rust
use bvf::config::{CHUNK_SIZE, CIPHERTEXT_CHUNK_SIZE, HEADER_SIZE};
let keypair = bvf::Keypair::generate()?;
let passphrase = bvf::Locked::new("my passphrase".to_string())?;
let encrypted_key = keypair.export_encrypted_private_key(passphrase)?;
let big_secret = [1u8; CHUNK_SIZE];

// Encrypt
let encrypter = bvf::Encrypter::new(&keypair.public_key)?;
let (header, mut state) = encrypter.start()?;
let mut ciphertext = header;
ciphertext.extend(state.encrypt_chunk(&big_secret, false)?);
ciphertext.extend(state.encrypt_chunk(&big_secret, true)?);

// Decrypt
let passphrase = bvf::Locked::new("my passphrase".to_string())?;
let decrypter = bvf::Decrypter::new(&encrypted_key, passphrase)?;
let header: [u8; HEADER_SIZE] = ciphertext[..HEADER_SIZE].try_into()?;
let mut state = decrypter.start(&header)?;
let body = &ciphertext[HEADER_SIZE..];
let mut plaintext = state.decrypt_chunk(&body[..CIPHERTEXT_CHUNK_SIZE])?;
plaintext.extend(state.decrypt_chunk(&body[CIPHERTEXT_CHUNK_SIZE..])?);
state.validate_complete()?;
assert_eq!(plaintext, [1u8; CHUNK_SIZE * 2]);  // big_secret * 2
```

<!-- cargo-rdme end -->
