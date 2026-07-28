import base64
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from src.core.vault import VaultLockedError, VaultManager
from src.storage.storage import FileStorage


class TransitError(Exception):
    pass


class PermissionDenied(TransitError):
    pass


class NotFoundError(TransitError):
    pass


class InvalidKeyUsageError(TransitError):
    pass


class BadCiphertextError(TransitError):
    pass


@dataclass
class TransitKeyInfo:
    key_name: str
    owner_email: str
    key_usage: str
    signing_algorithm: Optional[str] = None


class TransitEngine:
    STORE_FILE = "transit_keys.json"
    CIPHERTEXT_PREFIX = "vault"
    ENCRYPT_DECRYPT = "ENCRYPT_DECRYPT"
    SIGN_VERIFY = "SIGN_VERIFY"
    SIGNING_ALGORITHM = "ED25519"

    def __init__(self, storage: FileStorage, vault: VaultManager):
        self.storage = storage
        self.vault = vault

    def create_key(self, owner_email: str, key_name: str):
        self._ensure_unlocked()
        self._ensure_name(key_name)
        store = self.storage.read_json(self.STORE_FILE, {})
        key_id = self._storage_key(owner_email, key_name)
        if key_id in store:
            raise TransitError("Key already exists")

        key_material = os.urandom(32)
        encrypted_key, nonce = self._encrypt_key_material(key_material)
        store[key_id] = {
            "key_name": key_name,
            "owner_email": owner_email,
            "key_usage": self.ENCRYPT_DECRYPT,
            "encrypted_key_material_b64": base64.b64encode(encrypted_key).decode("ascii"),
            "encrypted_key_nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "signing_algorithm": None,
            "public_key_b64": None,
            "created_at": self.storage.now_iso(),
            "updated_at": self.storage.now_iso(),
        }
        self.storage.write_json(self.STORE_FILE, store)
        return {"key_name": key_name, "key_usage": self.ENCRYPT_DECRYPT}

    def create_signing_key(self, owner_email: str, key_name: str, signing_algorithm: str):
        self._ensure_unlocked()
        if signing_algorithm != self.SIGNING_ALGORITHM:
            raise TransitError("Unsupported signing algorithm")
        self._ensure_name(key_name)
        store = self.storage.read_json(self.STORE_FILE, {})
        key_id = self._storage_key(owner_email, key_name)
        if key_id in store:
            raise TransitError("Key already exists")

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_bytes = private_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )
        public_bytes = public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        encrypted_key, nonce = self._encrypt_key_material(private_bytes)
        store[key_id] = {
            "key_name": key_name,
            "owner_email": owner_email,
            "key_usage": self.SIGN_VERIFY,
            "encrypted_private_key_b64": base64.b64encode(encrypted_key).decode("ascii"),
            "encrypted_key_nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "signing_algorithm": signing_algorithm,
            "public_key_b64": base64.b64encode(public_bytes).decode("ascii"),
            "created_at": self.storage.now_iso(),
            "updated_at": self.storage.now_iso(),
        }
        self.storage.write_json(self.STORE_FILE, store)
        return {
            "key_name": key_name,
            "key_usage": self.SIGN_VERIFY,
            "signing_algorithm": signing_algorithm,
        }

    def list_keys(self, owner_email: str) -> List[TransitKeyInfo]:
        self._ensure_unlocked()
        store = self.storage.read_json(self.STORE_FILE, {})
        return [
            TransitKeyInfo(
                key_name=record["key_name"],
                owner_email=record["owner_email"],
                key_usage=record["key_usage"],
                signing_algorithm=record.get("signing_algorithm"),
            )
            for record in store.values()
            if record["owner_email"] == owner_email
        ]

    def revoke_key(self, owner_email: str, key_name: str):
        self._ensure_unlocked()
        store = self.storage.read_json(self.STORE_FILE, {})
        key_id = self._storage_key(owner_email, key_name)
        if key_id not in store:
            if self._key_name_exists_elsewhere(key_name, owner_email, store):
                self._log_denied(owner_email, key_name, "TRANSIT")
                raise PermissionDenied("PERMISSION_DENIED")
            raise NotFoundError("NOT_FOUND")
        del store[key_id]
        self.storage.write_json(self.STORE_FILE, store)

    def encrypt(self, owner_email: str, key_name: str, plaintext: bytes) -> str:
        self._ensure_unlocked()
        record = self._require_key_record(owner_email, key_name)
        if record["key_usage"] != self.ENCRYPT_DECRYPT:
            raise InvalidKeyUsageError("InvalidKeyUsageException")

        key_material = self._decrypt_key_material(record)
        nonce = os.urandom(12)
        ciphertext = AESGCM(key_material).encrypt(nonce, plaintext, None)
        payload = base64.b64encode(nonce + ciphertext).decode("ascii")
        return f"{self.CIPHERTEXT_PREFIX}:{key_name}:{payload}"

    def decrypt(self, owner_email: str, ciphertext: str) -> bytes:
        self._ensure_unlocked()
        parts = ciphertext.split(":", 2)
        if len(parts) != 3 or parts[0] != self.CIPHERTEXT_PREFIX:
            raise BadCiphertextError("Malformed ciphertext")
        key_name = parts[1]
        payload = parts[2]
        try:
            raw = base64.b64decode(payload, validate=True)
            if len(raw) < 12 + 16:
                raise ValueError("ciphertext is too short")
            nonce, token = raw[:12], raw[12:]
        except (ValueError, TypeError) as exc:
            raise BadCiphertextError("Malformed ciphertext") from exc

        record = self._require_key_record(owner_email, key_name)
        if record["key_usage"] != self.ENCRYPT_DECRYPT:
            raise InvalidKeyUsageError("InvalidKeyUsageException")

        key_material = self._decrypt_key_material(record)
        try:
            return AESGCM(key_material).decrypt(nonce, token, None)
        except Exception:
            raise TransitError("GCM tag mismatch")

    def sign(self, owner_email: str, key_name: str, message_b64: str, message_type: str) -> Dict[str, str]:
        self._ensure_unlocked()
        record = self._require_key_record(owner_email, key_name)
        if record["key_usage"] != self.SIGN_VERIFY:
            raise InvalidKeyUsageError("InvalidKeyUsageException")
        if record.get("signing_algorithm") != self.SIGNING_ALGORITHM:
            raise TransitError("Signing key algorithm mismatch")

        message = self._get_message_bytes(message_b64)
        digest = self._digest_message(message, message_type)
        private_bytes = self._decrypt_key_material(record)
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        signature = private_key.sign(digest)
        return {
            "signature_b64": base64.b64encode(signature).decode("ascii"),
            "key_name": key_name,
            "signing_algorithm": record["signing_algorithm"],
        }

    def verify(
        self,
        owner_email: str,
        key_name: str,
        message_b64: str,
        message_type: str,
        signature_b64: str,
    ) -> Dict[str, Any]:
        self._ensure_unlocked()
        record = self._require_key_record(owner_email, key_name)
        if record["key_usage"] != self.SIGN_VERIFY:
            raise InvalidKeyUsageError("InvalidKeyUsageException")
        if record.get("signing_algorithm") != self.SIGNING_ALGORITHM:
            raise TransitError("Signing key algorithm mismatch")

        message = self._get_message_bytes(message_b64)
        digest = self._digest_message(message, message_type)
        try:
            signature = base64.b64decode(signature_b64, validate=True)
        except (ValueError, TypeError):
            return {
                "key_name": key_name,
                "signature_valid": False,
                "signing_algorithm": record.get("signing_algorithm"),
            }

        public_bytes = base64.b64decode(record["public_key_b64"])
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        try:
            public_key.verify(signature, digest)
            return {
                "key_name": key_name,
                "signature_valid": True,
                "signing_algorithm": record.get("signing_algorithm"),
            }
        except (InvalidSignature, ValueError):
            return {
                "key_name": key_name,
                "signature_valid": False,
                "signing_algorithm": record.get("signing_algorithm"),
            }

    def _require_key_record(self, owner_email: str, key_name: str) -> Dict[str, Any]:
        store = self.storage.read_json(self.STORE_FILE, {})
        key_id = self._storage_key(owner_email, key_name)
        if key_id in store:
            return store[key_id]
        if self._key_name_exists_elsewhere(key_name, owner_email, store):
            self._log_denied(owner_email, key_name, "TRANSIT")
            raise PermissionDenied("PERMISSION_DENIED")
        raise NotFoundError("NOT_FOUND")

    def _key_name_exists_elsewhere(self, key_name: str, owner_email: str, store: Dict[str, dict]) -> bool:
        return any(
            record["key_name"] == key_name and record["owner_email"] != owner_email
            for record in store.values()
        )

    def _decrypt_key_material(self, record: Dict[str, Any]) -> bytes:
        material_field = (
            "encrypted_private_key_b64"
            if record["key_usage"] == self.SIGN_VERIFY
            else "encrypted_key_material_b64"
        )
        encrypted_key = base64.b64decode(record[material_field], validate=True)
        nonce = base64.b64decode(record["encrypted_key_nonce_b64"])
        try:
            return AESGCM(self.vault.get_dek()).decrypt(nonce, encrypted_key, None)
        except Exception:
            raise TransitError("Failed to decrypt key material")

    def _encrypt_key_material(self, key_material: bytes):
        nonce = os.urandom(12)
        encrypted = AESGCM(self.vault.get_dek()).encrypt(nonce, key_material, None)
        return encrypted, nonce

    def _ensure_unlocked(self):
        if not self.vault.is_unlocked():
            raise VaultLockedError("VAULT_LOCKED")

    def _ensure_name(self, key_name: str):
        if not key_name or ":" in key_name or key_name.strip() == "":
            raise TransitError("Invalid key name")

    def _storage_key(self, owner_email: str, key_name: str) -> str:
        return f"{owner_email}|{key_name}"

    def _get_message_bytes(self, message_b64: str) -> bytes:
        try:
            return base64.b64decode(message_b64, validate=True)
        except (ValueError, TypeError) as exc:
            raise TransitError("Invalid base64 message") from exc

    def _digest_message(self, message: bytes, message_type: str) -> bytes:
        if message_type == "RAW":
            digest = hashes.Hash(hashes.SHA256())
            digest.update(message)
            return digest.finalize()
        if message_type == "DIGEST":
            if len(message) != 32:
                raise TransitError("Digest length mismatch")
            return message
        raise TransitError("Unsupported message_type")

    def _log_denied(self, owner_email: str, key_name: str, source: str):
        self.storage.append_audit(
            {
                "timestamp": self.storage.now_iso(),
                "type": "PERMISSION_DENIED",
                "source": source,
                "requester": owner_email,
                "resource": key_name,
            }
        )
