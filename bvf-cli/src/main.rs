use bvf::decrypter::Decrypter;
use bvf::encrypter::Encrypter;
use bvf::errors::BvfError;
use bvf::keypair::Keypair;
use bvf::locked::Locked;
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process;

#[derive(Parser)]
#[command(
    name = "bvf",
    about = "Encrypt/decrypt bvf files",
    version,
    after_help = "\
Examples:
  bvf keygen                                    # keys -> ~/.bvf/
  bvf keygen --output ./keys                    # keys -> ./keys/
  bvf encrypt document.pdf                      # -> document.pdf.bvf
  bvf encrypt document.pdf -k other/public.key  # explicit key
  bvf encrypt *.pdf                             # batch encrypt
  bvf encrypt - -o secret.bvf                   # encrypt stdin data
  echo secret | bvf encrypt - -o -               # encrypt stdin to stdout
  find . -name '*.pdf' | bvf encrypt --from -   # batch encrypt via find
  bvf decrypt document.pdf.bvf                  # -> document.pdf
  bvf decrypt - -o output.pdf                   # decrypt stdin
  bvf decrypt *.bvf                             # batch decrypt
  bvf decrypt document.pdf.bvf -o -             # decrypt to stdout
  bvf decrypt --from paths.txt                  # batch from file list
  find . -name '*.bvf' | bvf decrypt --from -  # batch via find
  find . -name '*.bvf' | bvf decrypt --from - -o -  # batch peek to stdout
  bvf pubkey                                    # uses ~/.bvf/private.key.enc
  BVF_KEY_DIR=/path/to/keys bvf encrypt file.txt

Run 'bvf <command> --help' for more information on a command."
)]
struct Cli {
    #[arg(short, long, global = true, help = "Print per-file progress")]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate new keypair
    Keygen {
        #[arg(
            short,
            long,
            help = "Output directory for keys (default: $BVF_KEY_DIR or ~/.bvf/)"
        )]
        output: Option<PathBuf>,
    },
    /// Encrypt one or more files
    Encrypt {
        #[command(flatten)]
        files: FileArgs,
    },
    /// Decrypt one or more files
    Decrypt {
        #[command(flatten)]
        files: FileArgs,
        #[arg(short = 't', long, help = "Allow truncated files (missing final tag)")]
        allow_truncated: bool,
    },
    /// Derive public key from private key
    Pubkey {
        #[arg(short, long, help = "Encrypted private key file (default: $BVF_KEY_DIR/private.key.enc or ~/.bvf/private.key.enc)")]
        key: Option<PathBuf>,
    },
}

#[derive(clap::Args)]
struct FileArgs {
    #[arg(help = "Input file(s), use - for stdin data")]
    input: Vec<PathBuf>,
    #[arg(
        short = 'F',
        long = "from",
        help = "File containing input paths, one per line (- for stdin)"
    )]
    from: Option<PathBuf>,
    #[arg(
        short,
        long,
        help = "Output path (- for stdout)"
    )]
    output: Option<PathBuf>,
    #[arg(short, long, help = "Key file (default: $BVF_KEY_DIR/<key> or ~/.bvf/<key>)")]
    key: Option<PathBuf>,
    #[arg(short, long, help = "Overwrite existing files without prompting")]
    yes: bool,
}

fn is_stdio(p: &Path) -> bool {
    p.to_str() == Some("-")
}

fn resolve_key_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("BVF_KEY_DIR") {
        PathBuf::from(dir)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| {
            eprintln!("Error: Cannot determine home directory");
            process::exit(1);
        });
        PathBuf::from(home).join(".bvf")
    }
}

fn resolve_key(explicit: Option<&PathBuf>, needs_public: bool) -> PathBuf {
    if let Some(k) = explicit {
        return k.clone();
    }
    let dir = resolve_key_dir();
    let name = if needs_public {
        "public.key"
    } else {
        "private.key.enc"
    };
    let path = dir.join(name);
    if !path.exists() {
        eprintln!("Error: No key specified and {} not found", path.display());
        process::exit(1);
    }
    path
}

fn disable_core_dumps() {
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &raw const rlim);
    }
}

fn check_private_key_permissions(path: &PathBuf) {
    if let Ok(meta) = fs::metadata(path)
        && meta.permissions().mode() & 0o077 != 0
    {
        eprintln!(
            "Warning: {} has permissions {:04o} — should be 0600",
            path.display(),
            meta.permissions().mode() & 0o777
        );
    }
}

fn prompt_passphrase(prompt: &str) -> String {
    rpassword::prompt_password(prompt).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        process::exit(1);
    })
}

fn get_passphrase(prompt: &str) -> String {
    if let Ok(p) = std::env::var("BVF_PASSPHRASE") {
        return p;
    }
    prompt_passphrase(prompt)
}

fn read_file_list(source: &Path) -> Vec<PathBuf> {
    let buf: Vec<u8> = if is_stdio(source) {
        if io::stdin().is_terminal() {
            eprintln!("Error: --from - specified but stdin is not a pipe");
            process::exit(1);
        }
        let mut v = Vec::new();
        io::stdin().read_to_end(&mut v).unwrap_or_else(|e| {
            eprintln!("Error: reading stdin: {e}");
            process::exit(1);
        });
        v
    } else {
        fs::read(source).unwrap_or_else(|e| {
            eprintln!("Error: {}: {e}", source.display());
            process::exit(1);
        })
    };

    let entries: Vec<&[u8]> = if buf.contains(&0) {
        buf.split(|&b| b == 0).collect()
    } else {
        buf.split(|&b| b == b'\n').collect()
    };
    entries
        .into_iter()
        .filter(|e| !e.is_empty())
        .map(|e| PathBuf::from(String::from_utf8_lossy(e).into_owned()))
        .collect()
}

fn resolve_file_pairs(files: &FileArgs, is_encrypt: bool) -> Vec<(PathBuf, PathBuf)> {
    // --from and positional args are mutually exclusive
    if files.from.is_some() && !files.input.is_empty() {
        eprintln!("Error: --from and positional file arguments cannot be combined");
        process::exit(1);
    }

    let input_files: Vec<PathBuf> = if let Some(ref from_path) = files.from {
        // --from - conflicts with positional - (stdin already consumed by file list)
        // positional args are empty here (checked above), so no conflict possible with stdin data
        read_file_list(from_path)
    } else {
        // Positional args: each is a real file path or - for stdin data
        // - as stdin data is allowed; it is NOT expanded into a file list
        files.input.clone()
    };

    if input_files.is_empty() {
        eprintln!("Error: No input files specified");
        process::exit(1);
    }

    // Stdin data (-) requires explicit -o
    for f in &input_files {
        if is_stdio(f) && files.output.is_none() {
            eprintln!("Error: -o is required when input is -");
            process::exit(1);
        }
    }

    // For encrypt: -o with multiple files is always an error (concatenated ciphertext is unusable)
    // For decrypt: -o <file> with multiple files is an error, but -o - (stdout) is allowed
    if let Some(ref o) = files.output
        && input_files.len() > 1 && (is_encrypt || !is_stdio(o))
    {
        eprintln!("Error: --output cannot be used with multiple input files");
        process::exit(1);
    }

    let pairs: Vec<(PathBuf, PathBuf)> = input_files
        .into_iter()
        .map(|f| {
            let out = if let Some(ref o) = files.output {
                o.clone()
            } else if is_encrypt {
                PathBuf::from(format!("{}.bvf", f.display()))
            } else {
                let s = f.to_string_lossy();
                PathBuf::from(s.strip_suffix(".bvf").unwrap_or(&s).to_string())
            };
            (f, out)
        })
        .collect();

    // Input-equals-output guard: error if src and dst resolve to the same path
    for (src, dst) in &pairs {
        if is_stdio(src) || is_stdio(dst) {
            continue;
        }
        let src_canon = fs::canonicalize(src);
        let dst_canon = fs::canonicalize(dst);
        if let (Ok(s), Ok(d)) = (src_canon, dst_canon)
            && s == d
        {
            eprintln!(
                "Error: input and output paths resolve to the same file: {}",
                src.display()
            );
            process::exit(1);
        }
    }

    pairs
}

/// Overwrite state shared across a batch operation.
enum OverwriteDecision {
    AskEach,
    YesToAll,
    NoToAll,
}

struct Tty {
    reader: io::BufReader<fs::File>,
    writer: fs::File,
}

/// Returns true if the file should be written, false if it should be skipped.
fn should_overwrite(path: &Path, decision: &mut OverwriteDecision, tty: &mut Tty) -> bool {
    match decision {
        OverwriteDecision::YesToAll => return true,
        OverwriteDecision::NoToAll => return false,
        OverwriteDecision::AskEach => {}
    }

    let prompt = format!("Overwrite {}? [y/n/Y/N] ", path.display());
    loop {
        tty.writer.write_all(prompt.as_bytes()).unwrap_or_else(|e| {
            eprintln!("Error: writing to /dev/tty: {e}");
            process::exit(1);
        });
        tty.writer.flush().unwrap_or_else(|e| {
            eprintln!("Error: flushing /dev/tty: {e}");
            process::exit(1);
        });

        let mut line = String::new();
        tty.reader.read_line(&mut line).unwrap_or_else(|e| {
            eprintln!("Error: reading from /dev/tty: {e}");
            process::exit(1);
        });

        match line.trim() {
            "y" => return true,
            "n" => return false,
            "Y" => {
                *decision = OverwriteDecision::YesToAll;
                return true;
            }
            "N" => {
                *decision = OverwriteDecision::NoToAll;
                return false;
            }
            _ => {
                // re-prompt
            }
        }
    }
}

/// Open /dev/tty for overwrite prompting. Exits with error if unavailable.
fn open_tty() -> Tty {
    let writer = fs::File::options()
        .write(true)
        .open("/dev/tty")
        .unwrap_or_else(|e| {
            eprintln!("Error: cannot open /dev/tty for overwrite prompting: {e}");
            process::exit(1);
        });
    let reader = io::BufReader::new(
        fs::File::open("/dev/tty").unwrap_or_else(|e| {
            eprintln!("Error: cannot open /dev/tty for overwrite prompting: {e}");
            process::exit(1);
        }),
    );
    Tty { reader, writer }
}

fn cmd_keygen(output: &PathBuf, verbose: bool) {
    // Existence checks and directory creation before passphrase prompt
    fs::create_dir_all(output).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        process::exit(1);
    });

    let private_path = output.join("private.key.enc");
    let public_path = output.join("public.key");

    for path in [&private_path, &public_path] {
        if path.exists() {
            eprintln!("Error: {} already exists", path.display());
            process::exit(1);
        }
    }

    let from_env = std::env::var("BVF_PASSPHRASE").is_ok();
    if !from_env {
        eprintln!("Tip: a passphrase of 3+ unrelated words works well (e.g. \"lamp tiger notebook\")");
    }
    let passphrase = get_passphrase("Enter passphrase: ");

    if !from_env {
        if passphrase.is_empty() {
            eprintln!("Error: Passphrase cannot be empty");
            process::exit(1);
        }
        if passphrase.len() < 12 {
            eprintln!("Warning: Passphrase is weak (< 12 characters)");
        }
        let confirm = prompt_passphrase("Confirm passphrase: ");
        if passphrase != confirm {
            eprintln!("Error: Passphrases do not match");
            process::exit(1);
        }
    }

    if verbose {
        eprintln!("Generating X25519 keypair...");
    }
    let keypair = Keypair::generate();

    let passphrase = Locked::new(passphrase).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        process::exit(1);
    });
    let encrypted = keypair
        .export_encrypted_private_key(passphrase)
        .unwrap_or_else(|e| {
            eprintln!("Error: {e}");
            process::exit(1);
        });

    fs::write(&private_path, encrypted).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        process::exit(1);
    });
    fs::set_permissions(&private_path, fs::Permissions::from_mode(0o600)).unwrap_or_else(
        |e| {
            eprintln!("Error: {e}");
            process::exit(1);
        },
    );

    fs::write(&public_path, &keypair.public_key).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        process::exit(1);
    });
    fs::set_permissions(&public_path, fs::Permissions::from_mode(0o644)).unwrap_or_else(
        |e| {
            eprintln!("Error: {e}");
            process::exit(1);
        },
    );

    eprintln!();
    eprintln!("Keys generated successfully:");
    eprintln!("  Private key: {}", private_path.display());
    eprintln!("  Public key:  {}", public_path.display());
}

fn cmd_encrypt(files: &FileArgs, verbose: bool) {
    let pairs = resolve_file_pairs(files, true);

    let key_path = resolve_key(files.key.as_ref(), true);
    let pubkey_str = fs::read_to_string(&key_path)
        .unwrap_or_else(|e| {
            eprintln!("Error: {}: {e}", key_path.display());
            process::exit(1);
        })
        .trim()
        .to_string();

    let encrypter = Encrypter::new(&pubkey_str).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        process::exit(1);
    });
    let total = pairs.len();
    let mut errors = 0;
    let mut skipped = 0;

    // Open /dev/tty once if any non-stdout output file already exists
    let needs_tty = !files.yes && pairs.iter().any(|(_, dst)| !is_stdio(dst) && dst.exists());
    let mut tty = if needs_tty { Some(open_tty()) } else { None };
    let mut overwrite = OverwriteDecision::AskEach;

    for (src, dst) in &pairs {
        if !files.yes && !is_stdio(dst) && dst.exists() {
            let t = tty.get_or_insert_with(open_tty);
            if !should_overwrite(dst, &mut overwrite, t) {
                skipped += 1;
                continue;
            }
        }
        if let Err(msg) = encrypt_one(&encrypter, src, dst) {
            eprintln!("Error: {}: {msg}", src.display());
            errors += 1;
        } else if verbose {
            eprintln!("Encrypted: {} -> {}", src.display(), dst.display());
        }
    }

    print_summary("Encrypted", total, errors, skipped);
    if errors > 0 || (total > 0 && errors + skipped == total) {
        process::exit(1);
    }
}

fn encrypt_one(
    encrypter: &Encrypter,
    src: &PathBuf,
    dst: &PathBuf,
) -> Result<(), String> {
    let mut src_read: Box<dyn Read> = if is_stdio(src) {
        Box::new(io::stdin())
    } else {
        Box::new(fs::File::open(src).map_err(|e| e.to_string())?)
    };
    let mut dst_write: Box<dyn Write> = if is_stdio(dst) {
        Box::new(io::stdout())
    } else {
        Box::new(fs::File::create(dst).map_err(|e| e.to_string())?)
    };
    encrypter.encrypt(&mut src_read, &mut dst_write).map_err(|e| format!("{e}"))
}

fn cmd_decrypt(files: &FileArgs, verbose: bool, allow_truncated: bool) {
    let pairs = resolve_file_pairs(files, false);

    let key_path = resolve_key(files.key.as_ref(), false);
    check_private_key_permissions(&key_path);
    let key_data = fs::read(&key_path).unwrap_or_else(|e| {
        eprintln!("Error: {}: {e}", key_path.display());
        process::exit(1);
    });

    let passphrase = get_passphrase("Enter passphrase: ");
    let passphrase = Locked::new(passphrase).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        process::exit(1);
    });
    let decrypter = Decrypter::new(&key_data, passphrase).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        process::exit(1);
    });
    let total = pairs.len();
    let mut errors = 0;
    let mut skipped = 0;

    // Open /dev/tty once if any non-stdout output file already exists
    let needs_tty = !files.yes && pairs.iter().any(|(_, dst)| !is_stdio(dst) && dst.exists());
    let mut tty = if needs_tty { Some(open_tty()) } else { None };
    let mut overwrite = OverwriteDecision::AskEach;

    for (src, dst) in &pairs {
        if !files.yes && !is_stdio(dst) && dst.exists() {
            let t = tty.get_or_insert_with(open_tty);
            if !should_overwrite(dst, &mut overwrite, t) {
                skipped += 1;
                continue;
            }
        }
        match decrypt_one(&decrypter, src, dst) {
            Ok(()) => {
                if verbose {
                    eprintln!("Decrypted: {} -> {}", src.display(), dst.display());
                }
            }
            Err(DecryptOneError::Bvf(BvfError::Truncated)) if allow_truncated => {
                if verbose {
                    eprintln!("Decrypted (truncated): {} -> {}", src.display(), dst.display());
                }
            }
            Err(e) => {
                eprintln!("Error: {}: {e}", src.display());
                errors += 1;
            }
        }
    }

    print_summary("Decrypted", total, errors, skipped);
    if errors > 0 || (total > 0 && errors + skipped == total) {
        process::exit(1);
    }
}

enum DecryptOneError {
    Io(String),
    Bvf(BvfError),
}

impl std::fmt::Display for DecryptOneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "{msg}"),
            Self::Bvf(e) => write!(f, "{e}"),
        }
    }
}

fn decrypt_one(
    decrypter: &Decrypter,
    src: &PathBuf,
    dst: &PathBuf,
) -> Result<(), DecryptOneError> {
    let mut src_read: Box<dyn Read> = if is_stdio(src) {
        Box::new(io::stdin())
    } else {
        Box::new(fs::File::open(src).map_err(|e| DecryptOneError::Io(e.to_string()))?)
    };
    let mut dst_write: Box<dyn Write> = if is_stdio(dst) {
        Box::new(io::stdout())
    } else {
        Box::new(fs::File::create(dst).map_err(|e| DecryptOneError::Io(e.to_string()))?)
    };
    decrypter.decrypt(&mut src_read, &mut dst_write).map_err(DecryptOneError::Bvf)
}

fn cmd_pubkey(key: &PathBuf) {
    check_private_key_permissions(key);
    let key_data = fs::read(key).unwrap_or_else(|e| {
        eprintln!("Error: {}: {e}", key.display());
        process::exit(1);
    });

    let passphrase = get_passphrase("Enter passphrase: ");
    let passphrase = Locked::new(passphrase).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        process::exit(1);
    });
    let decrypter = Decrypter::new(&key_data, passphrase).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        process::exit(1);
    });

    println!("{}", decrypter.public_key());
}

fn print_summary(verb: &str, total: usize, errors: usize, skipped: usize) {
    if total <= 1 {
        return;
    }
    let done = total - errors - skipped;
    if errors > 0 || skipped > 0 {
        let mut parts = Vec::new();
        if errors > 0 {
            parts.push(format!("{errors} failed"));
        }
        if skipped > 0 {
            parts.push(format!("{skipped} skipped"));
        }
        eprintln!("{verb} {done}/{total} files ({})", parts.join(", "));
    } else {
        eprintln!("{verb} {total} files");
    }
}

fn main() {
    disable_core_dumps();
    let cli = Cli::parse();

    match &cli.command {
        Command::Keygen { output } => {
            let output = output.clone().unwrap_or_else(resolve_key_dir);
            cmd_keygen(&output, cli.verbose);
        }
        Command::Encrypt { files } => cmd_encrypt(files, cli.verbose),
        Command::Decrypt { files, allow_truncated } => cmd_decrypt(files, cli.verbose, *allow_truncated),
        Command::Pubkey { key } => {
            let key = resolve_key(key.as_ref(), false);
            cmd_pubkey(&key);
        }
    }
}
