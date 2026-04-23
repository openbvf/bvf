# bvf

Library and CLI for cross-platform streaming of media that minimizes any decrypted content ever touching disk.

Threat focus is mostly on passive filesystem access via cloud sync, OS indexing, accidental sharing, family members.

I tried age. Passphrases are first-class here and scrypt broke the only [Swift SDK](https://github.com/jamesog/AgeKit), inactive for years. Secretstream means we own no crypto code, just the glue. Bonus: argon2id instead of scrypt.

- **[bvf](bvf/)** — Rust library
- **[spec](SPEC.md)** — Crypto spec and file format
- **[bvf-cli](bvf-cli/)** — command-line tool (`brew install openbvf/tap/bvf`)
