import argparse
import base64
import binascii
import getpass
import json
import os
import shlex
import sys
from typing import Optional

from src.auth.auth import AuthManager, AuthenticationError, AuthError
from src.core.vault import VaultManager, VaultError
from src.kv.engine import KVEngine, KVError
from src.storage.storage import FileStorage
from src.transit.engine import TransitEngine, TransitError


DATA_DIR = os.getenv("DATA_DIR", "data")


def build_app(data_dir: str = DATA_DIR):
    storage = FileStorage(data_dir)
    vault = VaultManager(storage)
    auth = AuthManager(storage)
    kv = KVEngine(storage, vault)
    transit = TransitEngine(storage, vault)
    return storage, vault, auth, kv, transit


def build_parser():
    parser = argparse.ArgumentParser(description="Mini Vault CLI")
    parser.add_argument("--data-dir", default=DATA_DIR, help="Directory to store vault data")
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser("init", help="Initialize the vault")
    init_parser.add_argument("--master-passphrase", help="Master passphrase for vault initialization")

    unlock_parser = subparsers.add_parser("unlock", help="Unlock the vault temporarily")
    unlock_parser.add_argument("--master-passphrase", help="Master passphrase to unlock the vault")

    subparsers.add_parser("lock", help="Lock the vault and clear the in-memory DEK")
    subparsers.add_parser("shell", help="Start an interactive shell with persistent in-memory unlock state")

    status_parser = subparsers.add_parser("status", help="Show vault initialization status")

    register_parser = subparsers.add_parser("register", help="Register a new user")
    register_parser.add_argument("email")
    register_parser.add_argument("--passphrase")
    register_parser.add_argument("--confirm-passphrase")

    login_parser = subparsers.add_parser("login", help="Login and obtain a session token")
    login_parser.add_argument("email")
    login_parser.add_argument("--passphrase")
    login_parser.add_argument("--otp", help="Six-digit TOTP code when MFA is enabled")

    enable_mfa_parser = subparsers.add_parser("enable-mfa", help="Enable TOTP MFA for the current user")
    enable_mfa_parser.add_argument("--token", required=True)
    enable_mfa_parser.add_argument("--passphrase")

    mfa_status_parser = subparsers.add_parser("mfa-status", help="Show whether TOTP MFA is enabled")
    mfa_status_parser.add_argument("--token", required=True)

    write_parser = subparsers.add_parser("write", help="Write a secret to the KV engine")
    write_parser.add_argument("--token", required=True)
    write_parser.add_argument("--path", required=True)
    write_parser.add_argument("--data", required=True)
    write_parser.add_argument("--master-passphrase")

    read_parser = subparsers.add_parser("read", help="Read a secret from the KV engine")
    read_parser.add_argument("--token", required=True)
    read_parser.add_argument("--path", required=True)
    read_parser.add_argument("--version", type=int, help="Read a specific KV version")
    read_parser.add_argument("--master-passphrase")

    list_versions_parser = subparsers.add_parser("list-versions", help="List encrypted KV record versions")
    list_versions_parser.add_argument("--token", required=True)
    list_versions_parser.add_argument("--path", required=True)
    list_versions_parser.add_argument("--master-passphrase")

    delete_parser = subparsers.add_parser("delete", help="Delete a secret from the KV engine")
    delete_parser.add_argument("--token", required=True)
    delete_parser.add_argument("--path", required=True)
    delete_parser.add_argument("--master-passphrase")

    create_key_parser = subparsers.add_parser("create-key", help="Create a transit encryption key")
    create_key_parser.add_argument("--token", required=True)
    create_key_parser.add_argument("--key-name", required=True)
    create_key_parser.add_argument("--master-passphrase")

    list_keys_parser = subparsers.add_parser("list-keys", help="List transit keys")
    list_keys_parser.add_argument("--token", required=True)
    list_keys_parser.add_argument("--master-passphrase")

    revoke_key_parser = subparsers.add_parser("revoke-key", help="Revoke a transit key")
    revoke_key_parser.add_argument("--token", required=True)
    revoke_key_parser.add_argument("--key-name", required=True)
    revoke_key_parser.add_argument("--master-passphrase")

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt plaintext with a transit key")
    encrypt_parser.add_argument("--token", required=True)
    encrypt_parser.add_argument("--key-name", required=True)
    encrypt_parser.add_argument("--plaintext-b64", required=True)
    encrypt_parser.add_argument("--master-passphrase")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt ciphertext from a transit key")
    decrypt_parser.add_argument("--token", required=True)
    decrypt_parser.add_argument("--ciphertext", required=True)
    decrypt_parser.add_argument("--master-passphrase")

    create_signing_key_parser = subparsers.add_parser("create-signing-key", help="Create a signing key")
    create_signing_key_parser.add_argument("--token", required=True)
    create_signing_key_parser.add_argument("--key-name", required=True)
    create_signing_key_parser.add_argument("--algorithm", default="ED25519")
    create_signing_key_parser.add_argument("--master-passphrase")

    sign_parser = subparsers.add_parser("sign", help="Sign a message")
    sign_parser.add_argument("--token", required=True)
    sign_parser.add_argument("--key-name", required=True)
    sign_parser.add_argument("--message-b64", required=True)
    sign_parser.add_argument("--message-type", choices=["RAW", "DIGEST"], default="RAW")
    sign_parser.add_argument("--master-passphrase")

    verify_parser = subparsers.add_parser("verify", help="Verify a signature")
    verify_parser.add_argument("--token", required=True)
    verify_parser.add_argument("--key-name", required=True)
    verify_parser.add_argument("--message-b64", required=True)
    verify_parser.add_argument("--message-type", choices=["RAW", "DIGEST"], default="RAW")
    verify_parser.add_argument("--signature-b64", required=True)
    verify_parser.add_argument("--master-passphrase")

    verify_audit_parser = subparsers.add_parser("verify-audit", help="Verify the audit log hash chain")
    verify_audit_parser.add_argument("--token", required=True)

    return parser


def parse_args(argv=None):
    return build_parser().parse_args(argv)


def prompt_passphrase(prompt: str) -> str:
    return getpass.getpass(prompt=prompt)


def maybe_unlock(vault: VaultManager, passphrase: Optional[str]):
    if passphrase:
        vault.unlock(passphrase)


def require_token(auth: AuthManager, token: str) -> str:
    try:
        return auth.validate_token(token)
    except AuthenticationError as exc:
        raise AuthError(str(exc)) from exc


def decode_base64(value: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TransitError(f"Invalid base64 for {field_name}") from exc


def execute_command(args, app):
    _, vault, auth, kv, transit = app

    if args.command == "init":
        master_passphrase = args.master_passphrase or prompt_passphrase("Master passphrase: ")
        confirm = master_passphrase if args.master_passphrase else prompt_passphrase("Confirm master passphrase: ")
        if master_passphrase != confirm:
            raise VaultError("Master passphrases do not match")
        vault.initialize(master_passphrase)
        print("Vault initialized. Please unlock the vault before using it.")
        return

    if args.command == "unlock":
        master_passphrase = args.master_passphrase or prompt_passphrase("Master passphrase: ")
        vault.unlock(master_passphrase)
        print("Vault unlocked for current process.")
        return

    if args.command == "lock":
        vault.lock()
        print("Vault locked.")
        return

    if args.command == "status":
        print("initialized" if vault.is_initialized() else "not initialized")
        print(f"vault status: {'unlocked' if vault.is_unlocked() else 'locked'}")
        return

    if args.command == "register":
        passphrase = args.passphrase or prompt_passphrase("Passphrase: ")
        confirm = args.confirm_passphrase or prompt_passphrase("Confirm passphrase: ")
        auth.register(args.email, passphrase, confirm)
        print("User registered.")
        return

    if args.command == "login":
        passphrase = args.passphrase or prompt_passphrase("Passphrase: ")
        print(auth.login(args.email, passphrase, args.otp))
        return

    if args.command == "enable-mfa":
        owner_email = require_token(auth, args.token)
        passphrase = args.passphrase or prompt_passphrase("Passphrase: ")
        print(json.dumps(auth.enable_mfa(owner_email, passphrase), indent=2))
        return

    if args.command == "mfa-status":
        owner_email = require_token(auth, args.token)
        print(json.dumps(auth.mfa_status(owner_email), indent=2))
        return

    if args.command == "verify-audit":
        require_token(auth, args.token)
        print(json.dumps(app[0].verify_audit_log(), indent=2))
        return

    protected_commands = {
        "write", "read", "list-versions", "delete", "create-key", "list-keys", "revoke-key",
        "encrypt", "decrypt", "create-signing-key", "sign", "verify",
    }
    if args.command in protected_commands:
        maybe_unlock(vault, args.master_passphrase)

    if args.command == "write":
        owner_email = require_token(auth, args.token)
        try:
            data = json.loads(args.data)
        except json.JSONDecodeError as exc:
            raise KVError("Invalid JSON data") from exc
        print(json.dumps(kv.write(owner_email, args.path, data), indent=2))
        return

    if args.command == "read":
        owner_email = require_token(auth, args.token)
        print(json.dumps(kv.read(owner_email, args.path, args.version), indent=2))
        return

    if args.command == "list-versions":
        owner_email = require_token(auth, args.token)
        print(json.dumps(kv.list_versions(owner_email, args.path), indent=2))
        return

    if args.command == "delete":
        owner_email = require_token(auth, args.token)
        kv.delete(owner_email, args.path)
        print("Deleted")
        return

    if args.command == "create-key":
        owner_email = require_token(auth, args.token)
        print(json.dumps(transit.create_key(owner_email, args.key_name), indent=2))
        return

    if args.command == "list-keys":
        owner_email = require_token(auth, args.token)
        print(json.dumps([key.__dict__ for key in transit.list_keys(owner_email)], indent=2))
        return

    if args.command == "revoke-key":
        owner_email = require_token(auth, args.token)
        transit.revoke_key(owner_email, args.key_name)
        print("Revoked")
        return

    if args.command == "encrypt":
        owner_email = require_token(auth, args.token)
        plaintext = decode_base64(args.plaintext_b64, "plaintext")
        print(transit.encrypt(owner_email, args.key_name, plaintext))
        return

    if args.command == "decrypt":
        owner_email = require_token(auth, args.token)
        plaintext = transit.decrypt(owner_email, args.ciphertext)
        print(base64.b64encode(plaintext).decode("ascii"))
        return

    if args.command == "create-signing-key":
        owner_email = require_token(auth, args.token)
        print(json.dumps(transit.create_signing_key(owner_email, args.key_name, args.algorithm), indent=2))
        return

    if args.command == "sign":
        owner_email = require_token(auth, args.token)
        result = transit.sign(owner_email, args.key_name, args.message_b64, args.message_type)
        print(json.dumps(result, indent=2))
        return

    if args.command == "verify":
        owner_email = require_token(auth, args.token)
        result = transit.verify(owner_email, args.key_name, args.message_b64, args.message_type, args.signature_b64)
        print(json.dumps(result, indent=2))
        return

    print("No command specified. Use --help.")


def interactive_shell(data_dir: str):
    app = build_app(data_dir)
    parser = build_parser()
    print("Mini Vault interactive shell. Type 'help' for commands or 'exit' to quit.")
    while True:
        try:
            line = input("mini-vault> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line in {"exit", "quit"}:
            break
        if line == "help":
            parser.print_help()
            continue
        try:
            command_args = parser.parse_args(shlex.split(line))
            if command_args.command == "shell":
                print("Already running inside the interactive shell.", file=sys.stderr)
                continue
            execute_command(command_args, app)
        except SystemExit:
            continue
        except (VaultError, AuthError, KVError, TransitError) as exc:
            print(str(exc), file=sys.stderr)
    app[1].lock()
    print("Vault locked. Goodbye.")


def main():
    args = parse_args()
    if args.command == "shell":
        interactive_shell(args.data_dir)
        return
    try:
        execute_command(args, build_app(args.data_dir))
    except (VaultError, AuthError, KVError, TransitError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
