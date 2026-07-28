import base64
import os
from typing import Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.storage.storage import FileStorage


class VaultError(Exception):
    pass


class VaultLockedError(VaultError):
    pass


class VaultManager:
    STATE_FILE = "vault_state.json"
    KDF = "argon2id"

    def __init__(self, storage: FileStorage):
        self.storage = storage
        self._dek: Optional[bytes] = None

    def is_initialized(self) -> bool:
        return self.storage.read_json(self.STATE_FILE) is not None

    def initialize(self, master_passphrase: str):
        if self.is_initialized():
            raise VaultError("Vault already initialized")
        if not master_passphrase or len(master_passphrase) < 12:
            raise VaultError("Master passphrase must be at least 12 characters")

        salt = os.urandom(16)
        kek = self._derive_kek(master_passphrase.encode("utf-8"), salt)
        dek = os.urandom(32)
        nonce = os.urandom(12)
        aesgcm = AESGCM(kek)
        encrypted_dek = aesgcm.encrypt(nonce, dek, None)

        state = {
            "kdf": self.KDF,
            "kdf_salt_b64": base64.b64encode(salt).decode("ascii"),
            "encrypted_dek_b64": base64.b64encode(encrypted_dek).decode("ascii"),
            "encrypted_dek_nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "status": "locked",
        }
        self.storage.write_json(self.STATE_FILE, state)
        return state

    def unlock(self, master_passphrase: str):
        state = self.storage.read_json(self.STATE_FILE)
        if state is None:
            raise VaultError("Vault is not initialized")
        try:
            salt = base64.b64decode(state["kdf_salt_b64"])
            nonce = base64.b64decode(state["encrypted_dek_nonce_b64"])
            encrypted_dek = base64.b64decode(state["encrypted_dek_b64"])
        except Exception as exc:
            raise VaultError("Vault state is corrupted") from exc

        kek = self._derive_kek(master_passphrase.encode("utf-8"), salt)
        try:
            self._dek = AESGCM(kek).decrypt(nonce, encrypted_dek, None)
        except Exception as exc:
            raise VaultError("Invalid master passphrase") from exc
        return True

    def lock(self):
        self._dek = None

    def is_unlocked(self) -> bool:
        return self._dek is not None

    def get_dek(self) -> bytes:
        if not self.is_unlocked():
            raise VaultLockedError("VAULT_LOCKED")
        return self._dek

    def encrypt_with_dek(self, plaintext: bytes, associated_data: Optional[bytes] = None):
        dek = self.get_dek()
        nonce = os.urandom(12)
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

    def decrypt_with_dek(self, nonce: bytes, ciphertext: bytes, associated_data: Optional[bytes] = None):
        dek = self.get_dek()
        aesgcm = AESGCM(dek)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)

    @staticmethod
    def _derive_kek(passphrase: bytes, salt: bytes) -> bytes:
        return hash_secret_raw(
            secret=passphrase,
            salt=salt,
            time_cost=2,
            memory_cost=65536,
            parallelism=2,
            hash_len=32,
            type=Type.ID,
        )
