# envlocker — encrypt/decrypt env vars with a password.
# Source this file in your shell rc.
# Built with Claude Code.
#
# Usage: envlocker [--keys PATTERN...] [--ignore PATTERN...] encrypt|decrypt [KEY]|decrypt-all

_ENVLOCKER_PY='#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "cryptography==46.0.5",
#     "prompt_toolkit==3.0.52",
# ]
# ///
# Built with Claude Code

"""envlocker (EVL) - Encrypt/decrypt environment variables with a password."""

import argparse
import base64
import os
import re
import secrets
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from getpass import getpass


PREFIX = "EVL:"
SALT_ENV = "ENVLOCKER_SALT"
TMPFILE_ENV = "ENVLOCKER_TMPFILE"
MIN_SALT_LEN = 256


def _write_export(key: str, value: str) -> None:
    """Write an export line to ENVLOCKER_TMPFILE (if set) or stdout."""
    line = f'"'"'export {key}="{value}"'"'"'
    tmpfile = os.environ.get(TMPFILE_ENV, "")
    if tmpfile:
        with open(tmpfile, "a") as f:
            f.write(line + "\n")
        print(line, file=sys.stderr)
    else:
        print(line)


def get_or_create_salt() -> str:
    """Return existing salt or generate and print a new one."""
    salt = os.environ.get(SALT_ENV, "")
    if len(salt) < MIN_SALT_LEN:
        salt = secrets.token_hex(MIN_SALT_LEN // 2)
        print(
            f"# No valid {SALT_ENV} found. Generated one — add this to your shell rc:\n"
            f'"'"'export {SALT_ENV}="{salt}"'"'"',
            file=sys.stderr,
        )
    return salt


def derive_key(password: str, salt: str, key_name: str) -> bytes:
    """Derive a 256-bit AES key from password + salt + variable name."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=(salt + key_name).encode(),
        iterations=600_000,
    )
    return kdf.derive(password.encode())


def encrypt_value(password: str, salt: str, key_name: str, plaintext: str) -> str:
    """Encrypt a value, return PREFIX + base64(nonce + ciphertext)."""
    key = derive_key(password, salt, key_name)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), key_name.encode())
    return PREFIX + base64.urlsafe_b64encode(nonce + ct).decode()


def decrypt_value(password: str, salt: str, key_name: str, token: str) -> str:
    """Decrypt an EVL: prefixed value."""
    raw = base64.urlsafe_b64decode(token[len(PREFIX) :])
    nonce, ct = raw[:12], raw[12:]
    key = derive_key(password, salt, key_name)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, key_name.encode()).decode()


def collect_env_vars(key_patterns: list[str], value_patterns: list[str]) -> dict[str, str]:
    """Return env vars matching any key pattern AND any value pattern."""
    key_res = [re.compile(p) for p in key_patterns]
    val_res = [re.compile(p) for p in value_patterns]
    result = {}
    for k, v in os.environ.items():
        if any(r.fullmatch(k) for r in key_res) and any(r.fullmatch(v) for r in val_res):
            result[k] = v
    return result


def _is_ignored(name: str, ignore_patterns: list[str]) -> bool:
    """Return True if name matches any ignore pattern."""
    return any(re.fullmatch(p, name) for p in ignore_patterns)


def collect_encrypted_vars(key_patterns: list[str], ignore_patterns: list[str] | None = None) -> dict[str, str]:
    """Return env vars matching key patterns whose values start with EVL:."""
    key_res = [re.compile(p) for p in key_patterns]
    ignore = ignore_patterns or []
    result = {}
    for k, v in os.environ.items():
        if v.startswith(PREFIX) and any(r.fullmatch(k) for r in key_res) and not _is_ignored(k, ignore):
            result[k] = v
    return result


def cmd_encrypt(args: argparse.Namespace) -> None:
    salt = get_or_create_salt()
    # For encrypt: match keys, exclude already-encrypted values
    key_res = [re.compile(p) for p in args.keys]
    candidates = {}
    own_vars = {SALT_ENV, TMPFILE_ENV}
    for k, v in os.environ.items():
        if k in own_vars:
            continue
        if not v.startswith(PREFIX) and any(r.fullmatch(k) for r in key_res) and not _is_ignored(k, args.ignore):
            candidates[k] = v

    if not candidates:
        print("# No matching unencrypted env vars found.", file=sys.stderr)
        return

    print(f"# Found {len(candidates)} variable(s) to encrypt:", file=sys.stderr)
    for k in sorted(candidates):
        print(f"#   {k}", file=sys.stderr)

    password = getpass("Password: ")
    confirm = getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match.", file=sys.stderr)
        sys.exit(1)

    print("\n# Paste these into your shell rc, replacing the current values:", file=sys.stderr)
    for k in sorted(candidates):
        encrypted = encrypt_value(password, salt, k, candidates[k])
        # Verify roundtrip
        decrypted = decrypt_value(password, salt, k, encrypted)
        if decrypted != candidates[k]:
            print(f"ERROR: roundtrip verification failed for {k}!", file=sys.stderr)
            sys.exit(1)
        _write_export(k, encrypted)


def _decrypt_vars(encrypted: dict[str, str], salt: str, password: str) -> None:
    """Decrypt and export a dict of encrypted vars."""
    for k in sorted(encrypted):
        try:
            value = decrypt_value(password, salt, k, encrypted[k])
        except Exception:
            print(f"Decryption failed for {k} — wrong password or corrupted data.", file=sys.stderr)
            sys.exit(1)
        # Roundtrip sanity check: re-encrypt then decrypt again
        reencrypted = encrypt_value(password, salt, k, value)
        redecrypted = decrypt_value(password, salt, k, reencrypted)
        if redecrypted != value:
            print(f"ERROR: roundtrip verification failed for {k}!", file=sys.stderr)
            sys.exit(1)
        _write_export(k, value)


def cmd_decrypt(args: argparse.Namespace) -> None:
    salt = os.environ.get(SALT_ENV, "")
    if not salt:
        print(f"Error: {SALT_ENV} not set.", file=sys.stderr)
        sys.exit(1)

    encrypted = collect_encrypted_vars(args.keys, args.ignore)

    # Warn about matching keys that are NOT encrypted
    key_res = [re.compile(p) for p in args.keys]
    unencrypted = [
        k for k, v in os.environ.items()
        if not v.startswith(PREFIX) and any(r.fullmatch(k) for r in key_res) and not _is_ignored(k, args.ignore)
    ]
    if unencrypted:
        print(f"# WARNING: {len(unencrypted)} matching variable(s) are NOT encrypted:", file=sys.stderr)
        for k in sorted(unencrypted):
            print(f"#   {k}", file=sys.stderr)

    if not encrypted:
        print("# No matching encrypted env vars found.", file=sys.stderr)
        return

    # If a specific key name was given, decrypt it directly
    if args.name:
        selection = args.name
        if selection not in encrypted:
            print(f"Unknown variable: {selection}", file=sys.stderr)
            sys.exit(1)
        password = getpass("Password: ")
        _decrypt_vars({selection: encrypted[selection]}, salt, password)
        return

    # Interactive selection with autocomplete
    from prompt_toolkit import prompt as pt_prompt
    from prompt_toolkit.completion import WordCompleter

    var_names = sorted(encrypted.keys())
    completer = WordCompleter(var_names, sentence=True, ignore_case=True)

    print(f"# {len(var_names)} encrypted variable(s) available.", file=sys.stderr)
    selection = pt_prompt(
        "Variable to decrypt (tab to autocomplete): ", completer=completer
    ).strip()

    if selection not in encrypted:
        print(f"Unknown variable: {selection}", file=sys.stderr)
        sys.exit(1)

    password = getpass("Password: ")
    _decrypt_vars({selection: encrypted[selection]}, salt, password)


def cmd_decrypt_all(args: argparse.Namespace) -> None:
    salt = os.environ.get(SALT_ENV, "")
    if not salt:
        print(f"Error: {SALT_ENV} not set.", file=sys.stderr)
        sys.exit(1)

    encrypted = collect_encrypted_vars(args.keys, args.ignore)
    if not encrypted:
        print("# No matching encrypted env vars found.", file=sys.stderr)
        return

    print(f"# Decrypting {len(encrypted)} variable(s):", file=sys.stderr)
    for k in sorted(encrypted):
        print(f"#   {k}", file=sys.stderr)

    password = getpass("Password: ")
    _decrypt_vars(encrypted, salt, password)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="envlocker (EVL) — encrypt/decrypt env vars with a password"
    )
    parser.add_argument(
        "--keys",
        nargs="*",
        default=[r".*(?:^|_)(?:PASS|PSWD|PASSWORD|PASSPHRASE|KEY|SECRET|TOKEN|SALT|TKN)(?:_.*|$)"],
        help="Regex patterns matching env var names (default: names containing PASS, PSWD, PASSWORD, PASSPHRASE, KEY, SECRET, TOKEN, SALT, or TKN as word segments)",
    )
    parser.add_argument(
        "--ignore",
        nargs="*",
        default=[],
        help="Regex patterns for env var names to exclude (e.g. COMPANY_SALT)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("encrypt", help="Encrypt matching env vars")
    dec = sub.add_parser("decrypt", help="Decrypt a selected env var")
    dec.add_argument("name", nargs="?", default=None, help="Variable name to decrypt (skip interactive prompt)")
    sub.add_parser("decrypt-all", help="Decrypt all matching encrypted env vars")

    args = parser.parse_args()
    if args.command == "encrypt":
        cmd_encrypt(args)
    elif args.command == "decrypt":
        cmd_decrypt(args)
    elif args.command == "decrypt-all":
        cmd_decrypt_all(args)


if __name__ == "__main__":
    main()
'

envlocker() {
    if [ -n "${ENVLOCKER_TMPFILE:-}" ]; then
        echo "Error: ENVLOCKER_TMPFILE is already set — another envlocker may be running." >&2
        return 1
    fi

    local tmpfile pytmp
    tmpfile="$(mktemp)" || { echo "Error: failed to create temp file." >&2; return 1; }
    pytmp="$(mktemp --suffix=.py)" || { rm -f "$tmpfile"; echo "Error: failed to create temp file." >&2; return 1; }
    export ENVLOCKER_TMPFILE="$tmpfile"

    printf '%s' "$_ENVLOCKER_PY" > "$pytmp"
    uv run "$pytmp" "$@"
    local rc=$?

    if [ $rc -eq 0 ] && [ -s "$tmpfile" ]; then
        . "$tmpfile"
    fi

    rm -f "$tmpfile" "$pytmp"
    unset ENVLOCKER_TMPFILE
    return $rc
}
