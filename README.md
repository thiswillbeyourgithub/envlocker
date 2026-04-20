# envlocker

A minimal, self-contained shell script to encrypt and decrypt your environment variables with a password.

Built with [Claude Code](https://claude.ai/code).

## Why?

Shell profiles (`.bashrc`, `.zshrc`) often contain secrets — API keys, tokens, credentials — exported as plain-text environment variables. That means a single point of failure that can be accessed by any program on your system.

envlocker lets you store encrypted values in your shell rc instead. You only need a password to unlock them when you need them. The goal is a **minimal, portable, and secure** setup: to move to a new device, all you need is a shell with `uv` and this  script.

## How it works

envlocker is a single shell script (`envlocker.sh`) that embeds a Python script. The shell wrapper handles what Python can't do — persistently modifying the current shell's environment variables. The embedded Python handles the cryptography and provides interactive autocomplete when selecting which variable to decrypt.

- **Encryption**: AES-256-GCM with PBKDF2 key derivation (600,000 iterations)
- **Dependencies**: [`cryptography==46.0.5`](https://pypi.org/project/cryptography/) and [`prompt_toolkit==3.0.52`](https://pypi.org/project/prompt-toolkit/), pinned for reproducibility
- **Runtime**: [uv](https://docs.astral.sh/uv/) manages the Python environment and dependencies automatically

Each variable is encrypted with a key derived from your password + a per-install salt (`ENVLOCKER_SALT`) + the variable name itself. Encrypted variable names are prefixed with `EVL_` and their values with `EVL:`, so they're easy to identify. For example, encrypting `MY_API_KEY` produces `EVL_MY_API_KEY=EVL:...`, and the original `MY_API_KEY` is unset. On decryption, the original name is restored.

## Setup

1. Install [uv](https://docs.astral.sh/uv/)
2. Source the script in your shell rc:

```bash
source /path/to/envlocker.sh
```

3. On first encrypt, envlocker generates a salt — add the printed `export ENVLOCKER_SALT="..."` line to your shell rc.

## Usage

### Encrypt

Encrypt all env vars whose names contain common secret-related keywords (`PASS`, `PSWD`, `PASSWORD`, `PASSPHRASE`, `KEY`, `SECRET`, `TOKEN`, `SALT`, `TKN`):

```bash
envlocker encrypt
```

Encrypt vars matching custom patterns:

```bash
envlocker --keys 'OPENAI_.*' 'ANTHROPIC_.*' encrypt
```

You'll be prompted for a password (with confirmation). The output is a set of `export EVL_<NAME>=EVL:...` lines along with `unset <NAME>` lines — replace the originals in your shell rc.

### Decrypt a single variable

Interactive mode (with tab-autocomplete):

```bash
envlocker decrypt
```

Or decrypt a specific variable by name:

```bash
envlocker decrypt MY_API_KEY
```

You can also use a prefix — if exactly one encrypted variable's name starts with the given string, it is selected automatically:

```bash
envlocker decrypt MY_API   # selects MY_API_KEY if it's the only match
```

If the prefix matches multiple variables, an error lists the candidates.

### Decrypt all

Decrypt all matching encrypted variables at once:

```bash
envlocker decrypt-all
```

### Key patterns

The `--keys` flag accepts regex patterns matched against variable names. The default pattern matches names containing `PASS`, `PSWD`, `PASSWORD`, `PASSPHRASE`, `KEY`, `SECRET`, `TOKEN`, `SALT`, or `TKN` anywhere in the name. Examples:

```bash
envlocker --keys '.*' decrypt-all          # all encrypted vars
envlocker --keys 'AWS_.*' decrypt-all      # only AWS-related vars
```

### Ignoring variables

The `--ignore` flag excludes specific variable names from matching. This is useful when a default keyword appears in a non-secret context (e.g. a company name containing "SALT"):

```bash
envlocker --ignore 'COMPANY_SALT_NAME' encrypt
envlocker --ignore 'COMPANY_SALT_.*' decrypt-all
```

`--ignore` accepts regex patterns, just like `--keys`.

## Portability

To set up on a new device:

1. Copy `envlocker.sh` (or sync it with your dotfiles)
2. Copy your shell rc with the encrypted `export EVL_...` lines and the `ENVLOCKER_SALT`
3. Install `uv`
4. `source envlocker.sh` and `envlocker decrypt-all` — done

No Python virtualenv to manage, no config files, no database. Everything lives in your shell rc and one script.

## Security notes

- AES-256-GCM provides authenticated encryption — tampered ciphertexts are detected
- PBKDF2 with 600,000 iterations slows brute-force attacks on the password
- The salt is unique per install, so identical passwords on different machines produce different ciphertexts
- The variable name is mixed into both the key derivation and the authentication tag, preventing value-swapping between variables
- Both encrypt and decrypt perform roundtrip verification to catch corruption
- The `EVL_` name prefix ensures the original (plaintext) variable is never set alongside the encrypted one
- Decrypted values only exist in shell memory — they are never written to persistent storage

## License

[AGPLv3](https://www.gnu.org/licenses/agpl-3.0.html)
