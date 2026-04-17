# bvf CLI

Command-line tool for encrypting and decrypting files using the bvf format.

## Installation

### Homebrew (macOS Apple Silicon)

```
brew install openbvf/tap/bvf
```

### From source

```
cargo install --path .
```

## Setup

Generate a keypair once:

```
bvf keygen
```

You will be prompted for a passphrase to protect the private key. Use a strong passphrase — it is the only protection for your private key at rest.

## Commands

Run `bvf <command> --help` for exact flags and usage.

### keygen

Generates an X25519 keypair. The private key is encrypted with Argon2id + XSalsa20-Poly1305 and written as `private.key.enc`. The public key is written as `public.key` (a base64-encoded string with a checksum prefix). Output directory defaults to `~/.bvf/` or `$BVF_KEY_DIR`.

### encrypt

Encrypts one or more files. Output files get a `.bvf` extension appended. Reads the public key from `~/.bvf/public.key` or `$BVF_KEY_DIR/public.key` unless `-k` is given.

Use `-` as input to encrypt stdin data (requires `-o`). Use `-o -` to write to stdout.

Use `--from`/`-F` to read input paths from a file or stdin (see batch examples below).

### decrypt

Decrypts one or more files. The `.bvf` extension is stripped from output filenames. Prompts for the passphrase that protects the private key.

Use `-o -` to write to stdout. Use `--from`/`-F` to read input paths from a file or stdin (e.g. piped from `find`).

### pubkey

Derives and prints the public key from an encrypted private key file. Useful for sharing your public key or verifying which key pair you have.

## Usage patterns

```sh
# Encrypt a file
bvf encrypt document.pdf                        # -> document.pdf.bvf

# Encrypt multiple files
bvf encrypt *.pdf

# Encrypt stdin data
echo secret | bvf encrypt - -o secret.bvf

# Encrypt stdin to stdout
echo secret | bvf encrypt - -o -

# Batch encrypt via find
find . -name '*.pdf' | bvf encrypt --from -

# Decrypt a file
bvf decrypt document.pdf.bvf                    # -> document.pdf

# Batch decrypt (one passphrase prompt)
bvf decrypt *.bvf

# Decrypt from stdin
bvf decrypt - -o output.pdf

# Decrypt to stdout (peek without writing)
bvf decrypt document.pdf.bvf -o -

# Batch decrypt via find (one passphrase prompt)
find . -name '*.bvf' | bvf decrypt --from -

# Batch decrypt from a file list
bvf decrypt --from paths.txt

# Batch peek to stdout via find
find . -name '*.bvf' | bvf decrypt --from - -o -

# Use a non-default key directory
BVF_KEY_DIR=/path/to/keys bvf encrypt file.txt

# Use an explicit key file
bvf encrypt file.txt -k /path/to/public.key
bvf decrypt file.txt.bvf -k /path/to/private.key.enc

# Verbose output (per-file progress)
bvf decrypt --verbose *.bvf

# Skip overwrite prompts (for scripting)
bvf encrypt --yes *.pdf
```

## Key resolution

For encrypt: looks for `public.key` in `$BVF_KEY_DIR` or `~/.bvf/`.

For decrypt/pubkey: looks for `private.key.enc` in `$BVF_KEY_DIR` or `~/.bvf/`.

Override with `-k`. For encrypt, `-k` takes a public key; for decrypt/pubkey, `-k` takes an encrypted private key.

## Security notes

- Core dumps are disabled on startup to reduce risk of key material in crash files.
- Private key files are created with permissions `0600`. A warning is printed if looser permissions are detected at use time.
- Public key files are created with permissions `0644`.
- Encryption uses a fresh ephemeral keypair per file; encrypting the same file twice produces different ciphertext.
- Existing output files trigger an interactive overwrite prompt. Respond `y`/`n` for one file, or `Y`/`N` to apply the choice to all remaining files. Use `--yes`/`-y` to skip prompts entirely. If `/dev/tty` is unavailable, the operation exits with an error rather than silently overwriting.
