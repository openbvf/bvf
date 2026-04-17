# bvf-v1

The format is deliberately simple — a fixed-size header followed by chunked ciphertext. No variable-length fields, no parsing logic, no negotiation. A decoder reads 63 bytes, splits at known offsets, and starts decrypting.

## Header (63 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 7 | Magic: `bvf-v1\n` |
| 7 | 32 | HPKE encapsulated key (ephemeral public key) |
| 39 | 24 | Secretstream nonce |

The magic string identifies the format and version. The encapsulated key is the ephemeral public key from HPKE — the recipient needs it to re-derive the master key via DH. The secretstream nonce initializes the stream cipher's state.

The header is not encrypted — all three fields must be readable to begin decryption. Tampering with the encapsulated key changes the HPKE derivation, causing the first chunk's authentication to fail.

## Chunks

Plaintext is split into 64 KB chunks. Each encrypts to plaintext length + 17 bytes: 16 for the Poly1305 authentication tag and 1 for the secretstream tag byte. Empty plaintext allowed.

## Cryptographic parameters

| Parameter | Value |
|-----------|-------|
| HPKE mode | Base |
| KEM | X25519 + HKDF-SHA256 (HPKE export-only) |
| AEAD | XChaCha20-Poly1305 secretstream |
| Chunk size | 64 KB |
| HPKE info | `bvf.hpke.x25519-sha256-exportonly` |
| HPKE export context | `bvf-master` |
| HPKE export length | 32 bytes (secretstream XChaCha20-Poly1305 key size) |
| Key protection | Argon2id, 4 iterations, 1 GiB memory, parallelism 1 |
