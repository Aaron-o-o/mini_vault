import base64
import json
from typing import Any

from src.core.vault import VaultLockedError, VaultManager
from src.storage.storage import FileStorage


class KVError(Exception):
    pass


class PermissionDenied(KVError):
    pass


class NotFoundError(KVError):
    pass


class KVEngine:
    STORE_FILE = "kv_store.json"

    def __init__(self, storage: FileStorage, vault: VaultManager):
        self.storage = storage
        self.vault = vault

    def write(self, owner_email: str, path: str, data: Any):
        if not self.vault.is_unlocked():
            raise VaultLockedError("VAULT_LOCKED")

        path = self._normalize_path(owner_email, path)
        payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
        nonce, ciphertext = self.vault.encrypt_with_dek(payload)

        ciphertext_b64 = base64.b64encode(ciphertext[:-16]).decode("ascii")
        tag_b64 = base64.b64encode(ciphertext[-16:]).decode("ascii")
        store = self.storage.read_json(self.STORE_FILE, {})
        now = self.storage.now_iso()
        existing = store.get(path)
        versions = list(existing.get("versions", [])) if existing else []
        if existing:
            versions.append(self._snapshot(existing))
        version = int(existing.get("version", 1)) + 1 if existing else 1
        record = {
            "path": path,
            "version": version,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ciphertext_b64": ciphertext_b64,
            "tag_b64": tag_b64,
            "created_at": store.get(path, {}).get("created_at", now),
            "updated_at": now,
            "versions": versions,
        }
        store[path] = record
        self.storage.write_json(self.STORE_FILE, store)
        return self._metadata(record)

    def read(self, owner_email: str, path: str, version: int = None) -> Any:
        if not self.vault.is_unlocked():
            raise VaultLockedError("VAULT_LOCKED")

        path = self._normalize_path(owner_email, path)
        store = self.storage.read_json(self.STORE_FILE, {})
        record = store.get(path)
        if record is None:
            raise NotFoundError("NOT_FOUND")

        selected = self._select_version(record, version)

        try:
            nonce = base64.b64decode(selected["nonce_b64"])
            ciphertext = base64.b64decode(selected["ciphertext_b64"])
            tag = base64.b64decode(selected["tag_b64"])
            plaintext = self.vault.decrypt_with_dek(nonce, ciphertext + tag)
            return json.loads(plaintext.decode("utf-8"))
        except Exception:
            raise KVError("DATA_TAMPERED")

    def list_versions(self, owner_email: str, path: str) -> list:
        if not self.vault.is_unlocked():
            raise VaultLockedError("VAULT_LOCKED")
        path = self._normalize_path(owner_email, path)
        record = self.storage.read_json(self.STORE_FILE, {}).get(path)
        if record is None:
            raise NotFoundError("NOT_FOUND")
        history = [self._metadata(item) for item in record.get("versions", [])]
        history.append(self._metadata(record))
        return history

    def delete(self, owner_email: str, path: str):
        if not self.vault.is_unlocked():
            raise VaultLockedError("VAULT_LOCKED")

        path = self._normalize_path(owner_email, path)
        store = self.storage.read_json(self.STORE_FILE, {})
        if path not in store:
            raise NotFoundError("NOT_FOUND")
        del store[path]
        self.storage.write_json(self.STORE_FILE, store)

    @staticmethod
    def _snapshot(record: dict) -> dict:
        return {
            "path": record["path"],
            "version": int(record.get("version", 1)),
            "nonce_b64": record["nonce_b64"],
            "ciphertext_b64": record["ciphertext_b64"],
            "tag_b64": record["tag_b64"],
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
        }

    @staticmethod
    def _metadata(record: dict) -> dict:
        return {
            "path": record["path"],
            "version": int(record.get("version", 1)),
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
        }

    def _select_version(self, record: dict, version: int = None) -> dict:
        current_version = int(record.get("version", 1))
        if version is None or version == current_version:
            return record
        for item in record.get("versions", []):
            if int(item.get("version", 1)) == version:
                return item
        raise NotFoundError("VERSION_NOT_FOUND")

    def _normalize_path(self, owner_email: str, path: str) -> str:
        path = path.strip().lstrip("/")
        if path.startswith("secret/"):
            candidate = path.split("/", 2)
            if candidate[1] == owner_email:
                if len(candidate) < 3 or not candidate[2]:
                    raise KVError("Invalid secret path")
                return path
            if "@" in candidate[1]:
                self._log_denied(owner_email, path, "KV")
                raise PermissionDenied("PERMISSION_DENIED")
            path = path[len("secret/"):]
        if not path:
            raise KVError("Invalid secret path")
        return f"secret/{owner_email}/{path}"

    def _log_denied(self, owner_email: str, path: str, source: str):
        self.storage.append_audit(
            {
                "timestamp": self.storage.now_iso(),
                "type": "PERMISSION_DENIED",
                "source": source,
                "requester": owner_email,
                "resource": path,
            }
        )
