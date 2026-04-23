# Security

## Reporting vulnerabilities

If you find a security issue, **do not open a public issue.** Instead:

- **GitHub Security Advisories** (preferred): [Submit a private advisory](https://github.com/openbvf/bvf/security/advisories/new)
- **Email**: bvf@newvoll.net

## Status

This library has not been independently audited. Use at your own risk.

## Threat model

Designed for apps that need to encrypt and decrypt without plaintext touching disk — media, documents, journal entries. The primary adversary is passive filesystem access: cloud sync, OS indexing, accidental sharing. The library operates on streams and never writes plaintext to disk.

Key protection uses Argon2id at libsodium SENSITIVE parameters (4 iterations, 1 GiB memory) to resist offline brute-force of the encrypted private key.

## Known limitations

- **Plaintext size**: ciphertext reveals plaintext size.
- **Core dumps**: key material may appear in core files. The library does not call `setrlimit`, but the CLI does; calling applications should disable core dumps if required.
- **Timing**: no constant-time guarantees across failure modes.
- **Key authenticity**: the library encrypts to whatever public key is provided. Verifying key ownership is the application's responsibility.
