import base64
import hashlib
import json
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from main import build_app, execute_command, parse_args
from src.auth.auth import AuthManager, AuthenticationError
from src.core.vault import VaultLockedError, VaultManager
from src.kv.engine import KVEngine, NotFoundError, PermissionDenied
from src.storage.storage import FileStorage
from src.transit.engine import BadCiphertextError, InvalidKeyUsageError
from src.transit.engine import NotFoundError as TransitNotFound
from src.transit.engine import PermissionDenied as TransitPermissionDenied
from src.transit.engine import TransitEngine, TransitError


def create_environment():
    temp_dir = tempfile.TemporaryDirectory()
    storage = FileStorage(temp_dir.name)
    vault = VaultManager(storage)
    auth = AuthManager(storage)
    kv = KVEngine(storage, vault)
    transit = TransitEngine(storage, vault)
    return temp_dir, storage, vault, auth, kv, transit


def test_vault_initialize_and_unlock():
    temp_dir, storage, vault, auth, kv, transit = create_environment()
    vault.initialize("strong-master-passphrase")
    state = storage.read_json("vault_state.json")
    assert state["kdf"] == "argon2id"
    assert state["status"] == "locked"

    with pytest.raises(VaultLockedError):
        vault.get_dek()

    assert vault.unlock("strong-master-passphrase") is True
    assert vault.is_unlocked()

    restarted_vault = VaultManager(storage)
    assert not restarted_vault.is_unlocked()
    with pytest.raises(VaultLockedError):
        restarted_vault.get_dek()
    vault.lock()
    with pytest.raises(VaultLockedError):
        vault.get_dek()
    temp_dir.cleanup()


def test_auth_register_login_lockout():
    temp_dir, storage, vault, auth, kv, transit = create_environment()
    auth.register("alice@example.com", "supersecurepassword", "supersecurepassword")
    token = auth.login("alice@example.com", "supersecurepassword")
    assert isinstance(token, str)
    assert auth.validate_token(token) == "alice@example.com"

    for _ in range(4):
        with pytest.raises(AuthenticationError):
            auth.login("alice@example.com", "wrong-password")

    with pytest.raises(AuthenticationError):
        auth.login("alice@example.com", "wrong-password")

    with pytest.raises(AuthenticationError):
        auth.login("alice@example.com", "supersecurepassword")

    users = storage.read_json("users.json")
    assert users["alice@example.com"]["failed_attempts"] >= 5
    assert users["alice@example.com"]["locked_until"] is not None
    locked_until = datetime.fromisoformat(users["alice@example.com"]["locked_until"].replace("Z", "+00:00"))
    remaining = locked_until - datetime.now(timezone.utc)
    assert timedelta(minutes=4, seconds=58) <= remaining <= timedelta(minutes=5)

    sessions = storage.read_json("sessions.json")
    sessions[token]["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    storage.write_json("sessions.json", sessions)
    with pytest.raises(AuthenticationError):
        auth.validate_token(token)
    with pytest.raises(AuthenticationError):
        auth.validate_token("invalid-token")
    temp_dir.cleanup()


def test_totp_mfa_is_required_after_enrollment():
    temp_dir, storage, vault, auth, kv, transit = create_environment()
    auth.register("mfa@example.com", "supersecurepassword", "supersecurepassword")
    first_token = auth.login("mfa@example.com", "supersecurepassword")
    enrollment = auth.enable_mfa(auth.validate_token(first_token), "supersecurepassword")
    assert enrollment["mfa_enabled"] is True
    assert enrollment["otpauth_uri"].startswith("otpauth://totp/")
    assert auth.mfa_status("mfa@example.com") == {"mfa_enabled": True}
    stored_user = storage.read_json("users.json")["mfa@example.com"]
    assert "totp_secret" not in stored_user
    assert enrollment["secret"] not in json.dumps(stored_user)

    with pytest.raises(AuthenticationError, match="MFA"):
        auth.login("mfa@example.com", "supersecurepassword")
    with pytest.raises(AuthenticationError, match="MFA"):
        auth.login("mfa@example.com", "supersecurepassword", "000000")

    otp = AuthManager.generate_totp(enrollment["secret"])
    token = auth.login("mfa@example.com", "supersecurepassword", otp)
    assert auth.validate_token(token) == "mfa@example.com"
    temp_dir.cleanup()


def test_kv_write_read_delete_and_ownership():
    temp_dir, storage, vault, auth, kv, transit = create_environment()
    vault.initialize("master-passphrase")
    vault.unlock("master-passphrase")
    auth.register("alice@example.com", "password12345", "password12345")
    auth.register("bob@example.com", "password12345", "password12345")
    token = auth.login("alice@example.com", "password12345")
    email = auth.validate_token(token)
    assert email == "alice@example.com"

    write_record = kv.write(email, "secret/db", {"password": "hunter2"})
    assert write_record["path"] == "secret/alice@example.com/db"

    read_data = kv.read(email, "secret/db")
    assert read_data == {"password": "hunter2"}

    with pytest.raises(PermissionDenied):
        kv.read("bob@example.com", "secret/alice@example.com/db")
    audit = storage.read_json("audit_log.json")
    assert audit[-1]["requester"] == "bob@example.com"
    assert audit[-1]["resource"] == "secret/alice@example.com/db"

    raw_store = json.dumps(storage.read_json("kv_store.json"))
    assert "hunter2" not in raw_store

    created_at = write_record["created_at"]
    updated_record = kv.write(email, "secret/db", {"password": "changed"})
    assert updated_record["created_at"] == created_at
    assert updated_record["version"] == 2
    versions = kv.list_versions(email, "secret/db")
    assert [item["version"] for item in versions] == [1, 2]
    assert kv.read(email, "secret/db", version=1) == {"password": "hunter2"}
    assert kv.read(email, "secret/db", version=2) == {"password": "changed"}
    with pytest.raises(NotFoundError, match="VERSION_NOT_FOUND"):
        kv.read(email, "secret/db", version=99)

    store = storage.read_json("kv_store.json")
    store["secret/alice@example.com/db"]["tag_b64"] = base64.b64encode(b"x" * 16).decode("ascii")
    storage.write_json("kv_store.json", store)
    with pytest.raises(Exception, match="DATA_TAMPERED"):
        kv.read(email, "secret/db")

    kv.delete(email, "secret/db")
    with pytest.raises(NotFoundError):
        kv.read(email, "secret/db")
    temp_dir.cleanup()


def test_audit_log_hash_chain_detects_tampering():
    with tempfile.TemporaryDirectory() as data_dir:
        storage = FileStorage(data_dir)
        storage.append_audit({"timestamp": storage.now_iso(), "type": "TEST", "resource": "one"})
        storage.append_audit({"timestamp": storage.now_iso(), "type": "TEST", "resource": "two"})

        result = storage.verify_audit_log()
        assert result == {"valid": True, "event_count": 2, "invalid_index": None}

        events = storage.read_json("audit_log.json")
        original_events = json.loads(json.dumps(events))
        events[0]["resource"] = "tampered"
        storage.write_json("audit_log.json", events)
        result = storage.verify_audit_log()
        assert result["valid"] is False
        assert result["invalid_index"] == 0

        storage.write_json("audit_log.json", original_events)
        storage.append_audit({"timestamp": storage.now_iso(), "type": "TEST", "resource": "three"})
        events = storage.read_json("audit_log.json")
        storage.write_json("audit_log.json", events[:-1])
        result = storage.verify_audit_log()
        assert result["valid"] is False

        storage.write_json("audit_log.json", [])
        result = storage.verify_audit_log()
        assert result["valid"] is False


def test_transit_encrypt_decrypt_and_sign_verify():
    temp_dir, storage, vault, auth, kv, transit = create_environment()
    vault.initialize("master-passphrase")
    vault.unlock("master-passphrase")
    auth.register("alice@example.com", "password12345", "password12345")
    auth.register("bob@example.com", "password12345", "password12345")
    token = auth.login("alice@example.com", "password12345")

    key = transit.create_key("alice@example.com", "my-key")
    assert key["key_usage"] == "ENCRYPT_DECRYPT"
    stored_key = storage.read_json("transit_keys.json")["alice@example.com|my-key"]
    assert "encrypted_key_material_b64" in stored_key
    assert "key_material" not in key

    plaintext = b"hello world"
    ciphertext = transit.encrypt("alice@example.com", "my-key", plaintext)
    assert ciphertext.startswith("vault:my-key:")

    decrypted = transit.decrypt("alice@example.com", ciphertext)
    assert decrypted == plaintext

    prefix, key_name, payload = ciphertext.split(":", 2)
    raw = bytearray(base64.b64decode(payload))
    raw[-1] ^= 1
    tampered = f"{prefix}:{key_name}:{base64.b64encode(raw).decode('ascii')}"
    with pytest.raises(TransitError):
        transit.decrypt("alice@example.com", tampered)
    with pytest.raises(BadCiphertextError):
        transit.decrypt("alice@example.com", "vault:my-key:not-base64!")

    signing = transit.create_signing_key("alice@example.com", "my-sign", "ED25519")
    assert signing["key_usage"] == "SIGN_VERIFY"

    message = base64.b64encode(b"payload bytes").decode("ascii")
    sign_result = transit.sign("alice@example.com", "my-sign", message, "RAW")
    assert sign_result["key_name"] == "my-sign"
    assert sign_result["signing_algorithm"] == "ED25519"
    signature = sign_result["signature_b64"]
    result = transit.verify("alice@example.com", "my-sign", message, "RAW", signature)
    assert result["signature_valid"] is True

    bad_message = base64.b64encode(b"tampered").decode("ascii")
    result_bad = transit.verify("alice@example.com", "my-sign", bad_message, "RAW", signature)
    assert result_bad["signature_valid"] is False

    digest = base64.b64encode(hashlib.sha256(b"payload bytes").digest()).decode("ascii")
    digest_result = transit.sign("alice@example.com", "my-sign", digest, "DIGEST")
    assert transit.verify("alice@example.com", "my-sign", digest, "DIGEST", digest_result["signature_b64"])["signature_valid"]
    short_digest = base64.b64encode(b"short").decode("ascii")
    with pytest.raises(TransitError, match="Digest length mismatch"):
        transit.sign("alice@example.com", "my-sign", short_digest, "DIGEST")
    assert transit.verify("alice@example.com", "my-sign", message, "RAW", "not-base64!")["signature_valid"] is False
    wrong_length_signature = base64.b64encode(b"short").decode("ascii")
    assert transit.verify("alice@example.com", "my-sign", message, "RAW", wrong_length_signature)["signature_valid"] is False

    transit.create_signing_key("alice@example.com", "other-sign", "ED25519")
    assert transit.verify("alice@example.com", "other-sign", message, "RAW", signature)["signature_valid"] is False

    with pytest.raises(InvalidKeyUsageError):
        transit.sign("alice@example.com", "my-key", message, "RAW")
    with pytest.raises(InvalidKeyUsageError):
        transit.encrypt("alice@example.com", "my-sign", b"data")

    with pytest.raises(TransitPermissionDenied):
        transit.encrypt("bob@example.com", "my-key", b"data")
    audit = storage.read_json("audit_log.json")
    assert audit[-1]["resource"] == "my-key"

    transit.revoke_key("alice@example.com", "my-key")
    with pytest.raises(TransitNotFound):
        transit.decrypt("alice@example.com", ciphertext)
    temp_dir.cleanup()


def test_all_transit_operations_refuse_while_locked():
    temp_dir, storage, vault, auth, kv, transit = create_environment()
    vault.initialize("master-passphrase")

    operations = [
        lambda: transit.create_key("alice@example.com", "key"),
        lambda: transit.list_keys("alice@example.com"),
        lambda: transit.revoke_key("alice@example.com", "key"),
        lambda: transit.encrypt("alice@example.com", "key", b"data"),
        lambda: transit.decrypt("alice@example.com", "vault:key:AAAA"),
        lambda: transit.create_signing_key("alice@example.com", "sign", "ED25519"),
        lambda: transit.sign("alice@example.com", "sign", "ZGF0YQ==", "RAW"),
        lambda: transit.verify("alice@example.com", "sign", "ZGF0YQ==", "RAW", "AAAA"),
    ]
    for operation in operations:
        with pytest.raises(VaultLockedError, match="VAULT_LOCKED"):
            operation()
    temp_dir.cleanup()


def test_commands_share_unlock_state_in_one_process(capsys):
    with tempfile.TemporaryDirectory() as data_dir:
        app = build_app(data_dir)
        execute_command(parse_args(["init", "--master-passphrase", "master-passphrase"]), app)
        execute_command(parse_args(["unlock", "--master-passphrase", "master-passphrase"]), app)
        assert app[1].is_unlocked()

        execute_command(
            parse_args([
                "register", "alice@example.com", "--passphrase", "password12345",
                "--confirm-passphrase", "password12345",
            ]),
            app,
        )
        token = app[2].login("alice@example.com", "password12345")
        execute_command(
            parse_args(["create-key", "--token", token, "--key-name", "shell-key"]),
            app,
        )
        assert app[4].list_keys("alice@example.com")[0].key_name == "shell-key"

        execute_command(parse_args(["lock"]), app)
        assert not app[1].is_unlocked()
        capsys.readouterr()
