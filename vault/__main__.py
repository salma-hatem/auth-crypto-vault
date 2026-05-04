"""ACV Vault command-line interface.

Usage:
    python -m vault encrypt --in plaintext.bin --out vault.bin
    python -m vault decrypt --in vault.bin     --out recovered.bin
    python -m vault encrypt --in pt --out ct --password-file pw.txt
    python -m vault encrypt --in pt --out ct --backend v2

Password sources (in order of precedence):
    --password-file PATH    read bytes from a file (trailing '\\n' stripped)
    --password STRING       *insecure* — appears in shell history; only for
                            scripted demos. Prefer --password-file or stdin.
    (none)                  prompt with getpass() on stdin (no echo)
"""

import argparse
import getpass
import os
import sys


def _bootstrap_path() -> None:
    """Make `python -m vault` runnable directly from the repo root."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)


_bootstrap_path()

from vault import (  # noqa: E402  (path bootstrap must run first)
    VaultError,
    vault_decrypt_file,
    vault_encrypt_file,
)


def _read_password(args: argparse.Namespace, *, prompt: str) -> bytes:
    if args.password_file is not None:
        with open(args.password_file, "rb") as f:
            data = f.read()
        # Strip exactly one trailing newline if present; preserve any
        # leading/internal bytes (passwords may contain whitespace).
        if data.endswith(b"\r\n"):
            data = data[:-2]
        elif data.endswith(b"\n"):
            data = data[:-1]
        return data
    if args.password is not None:
        return args.password.encode("utf-8")
    return getpass.getpass(prompt).encode("utf-8")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m vault",
        description="Authenticated Cryptographic Vault (AES-128-CTR + HMAC-SHA-512).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    for name, help_text in (("encrypt", "Encrypt a file into a vault blob."),
                            ("decrypt", "Authenticate and decrypt a vault blob.")):
        p = sub.add_parser(name, help=help_text, description=help_text)
        p.add_argument("--in", dest="in_path", required=True, metavar="PATH",
                       help="input file path")
        p.add_argument("--out", dest="out_path", required=True, metavar="PATH",
                       help="output file path")
        p.add_argument("--backend", choices=("v1", "v2"), default="v1",
                       help="AES-CTR backend (default: v1)")
        group = p.add_mutually_exclusive_group()
        group.add_argument(
            "--password-file", metavar="PATH",
            help="read password bytes from PATH (trailing newline stripped)",
        )
        group.add_argument(
            "--password", metavar="STRING",
            help=("WARNING: passing the password on the command line leaks it "
                  "to shell history and process listings. Prefer "
                  "--password-file or the interactive stdin prompt."),
        )
    return parser


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "encrypt":
        password = _read_password(args, prompt="Password: ")
        try:
            vault_encrypt_file(args.in_path, args.out_path, password,
                               backend=args.backend)
        except OSError as e:
            sys.stderr.write(f"error: {e}\n")
            return 1
        return 0

    if args.cmd == "decrypt":
        password = _read_password(args, prompt="Password: ")
        try:
            vault_decrypt_file(args.in_path, args.out_path, password,
                               backend=args.backend)
        except VaultError:
            # vault_decrypt_file already printed the SECURITY WARNING.
            return 2
        except OSError as e:
            sys.stderr.write(f"error: {e}\n")
            return 1
        return 0

    parser.error(f"unknown command: {args.cmd}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
