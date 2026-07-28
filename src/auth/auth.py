import base64
import hashlib
import hmac
import os
import re
import struct
import time
from urllib.parse import quote
from datetime import datetime, timedelta, timezone
from typing import Dict

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.storage.storage import FileStorage


class AuthError(Exception):
    pass


class AuthenticationError(AuthError):
    pass


class PermissionError(AuthError):
    pass


class AuthManager:
    USERS_FILE = "users.json"
    SESSIONS_FILE = "sessions.json"
    SESSION_TTL = timedelta(minutes=30)
    LOCK_DURATION = timedelta(minutes=5)
    MAX_FAILURES = 5

    def __init__(self, storage: FileStorage):
        self.storage = storage
        self.password_hasher = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=2)

    def register(self, email: str, passphrase: str, confirm_passphrase: str):
        email = email.strip().lower()
        if not self._validate_email(email):
            raise AuthError("Invalid email address")
        if passphrase != confirm_passphrase:
            raise AuthError("Passphrases do not match")
        if len(passphrase) < 12:
            raise AuthError("Passphrase must be at least 12 characters")

        users = self._load_users()
        if email in users:
            raise AuthError("Email already registered")

        password_hash = self.password_hasher.hash(passphrase)
        users[email] = {
            "email": email,
            "password_hash": password_hash,
            "failed_attempts": 0,
            "locked_until": None,
            "created_at": self.storage.now_iso(),
        }
        self._save_users(users)
        return users[email]

    def login(self, email: str, passphrase: str, otp: str = None) -> str:
        email = email.strip().lower()
        users = self._load_users()
        user = users.get(email)
        if user is None:
            raise AuthenticationError("Account does not exist")

        locked_until = user.get("locked_until")
        if locked_until:
            if datetime.fromisoformat(locked_until.replace("Z", "+00:00")) > datetime.now(timezone.utc):
                raise AuthenticationError("Account is temporarily locked")
            user["locked_until"] = None
            user["failed_attempts"] = 0

        try:
            self.password_hasher.verify(user["password_hash"], passphrase)
        except VerifyMismatchError:
            user["failed_attempts"] = user.get("failed_attempts", 0) + 1
            if user["failed_attempts"] >= self.MAX_FAILURES:
                lock_until = datetime.now(timezone.utc) + self.LOCK_DURATION
                user["locked_until"] = lock_until.replace(microsecond=0).isoformat().replace("+00:00", "Z")
            self._save_users(users)
            raise AuthenticationError("Invalid credentials")

        if user.get("mfa_enabled"):
            secret = self._decrypt_totp_secret(user, passphrase)
            if not self.verify_totp(secret, otp):
                raise AuthenticationError("Valid MFA code required")

        if self.password_hasher.check_needs_rehash(user["password_hash"]):
            user["password_hash"] = self.password_hasher.hash(passphrase)

        user["failed_attempts"] = 0
        user["locked_until"] = None
        self._save_users(users)

        token = self._generate_token()
        sessions = self._load_sessions()
        expires_at = (datetime.now(timezone.utc) + self.SESSION_TTL).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        sessions[token] = {
            "token": token,
            "email": email,
            "expires_at": expires_at,
            "created_at": self.storage.now_iso(),
        }
        self._save_sessions(sessions)
        return token

    def enable_mfa(self, email: str, passphrase: str) -> dict:
        users = self._load_users()
        user = users.get(email)
        if user is None:
            raise AuthenticationError("Account does not exist")
        if user.get("mfa_enabled"):
            raise AuthError("MFA is already enabled")
        try:
            self.password_hasher.verify(user["password_hash"], passphrase)
        except VerifyMismatchError as exc:
            raise AuthenticationError("Invalid credentials") from exc

        secret = base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")
        salt = os.urandom(16)
        nonce = os.urandom(12)
        encryption_key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 200_000, dklen=32)
        encrypted_secret = AESGCM(encryption_key).encrypt(nonce, secret.encode("ascii"), email.encode("utf-8"))
        user["totp_secret_encrypted_b64"] = base64.b64encode(encrypted_secret).decode("ascii")
        user["totp_secret_salt_b64"] = base64.b64encode(salt).decode("ascii")
        user["totp_secret_nonce_b64"] = base64.b64encode(nonce).decode("ascii")
        user["mfa_enabled"] = True
        self._save_users(users)
        label = quote(f"Mini Vault:{email}")
        uri = f"otpauth://totp/{label}?secret={secret}&issuer=Mini%20Vault&algorithm=SHA1&digits=6&period=30"
        return {"mfa_enabled": True, "secret": secret, "otpauth_uri": uri}

    def mfa_status(self, email: str) -> dict:
        user = self._load_users().get(email)
        if user is None:
            raise AuthenticationError("Account does not exist")
        return {"mfa_enabled": bool(user.get("mfa_enabled"))}

    @staticmethod
    def _decrypt_totp_secret(user: dict, passphrase: str) -> str:
        try:
            salt = base64.b64decode(user["totp_secret_salt_b64"], validate=True)
            nonce = base64.b64decode(user["totp_secret_nonce_b64"], validate=True)
            encrypted = base64.b64decode(user["totp_secret_encrypted_b64"], validate=True)
            key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 200_000, dklen=32)
            plaintext = AESGCM(key).decrypt(nonce, encrypted, user["email"].encode("utf-8"))
            return plaintext.decode("ascii")
        except Exception as exc:
            raise AuthenticationError("MFA configuration is invalid") from exc

    @classmethod
    def generate_totp(cls, secret: str, timestamp: int = None) -> str:
        if not secret:
            raise AuthError("Invalid TOTP secret")
        timestamp = int(time.time()) if timestamp is None else int(timestamp)
        padded = secret + "=" * ((8 - len(secret) % 8) % 8)
        key = base64.b32decode(padded, casefold=True)
        counter = struct.pack(">Q", timestamp // 30)
        digest = hmac.new(key, counter, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
        return f"{code:06d}"

    @classmethod
    def verify_totp(cls, secret: str, otp: str, timestamp: int = None) -> bool:
        if not otp or not re.fullmatch(r"\d{6}", str(otp)):
            return False
        timestamp = int(time.time()) if timestamp is None else int(timestamp)
        try:
            return any(
                hmac.compare_digest(cls.generate_totp(secret, timestamp + offset * 30), str(otp))
                for offset in (-1, 0, 1)
            )
        except (ValueError, TypeError, AuthError):
            return False

    def validate_token(self, token: str) -> str:
        sessions = self._load_sessions()
        session = sessions.get(token)
        if not session:
            raise AuthenticationError("UNAUTHENTICATED")
        expires_at = datetime.fromisoformat(session["expires_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) >= expires_at:
            del sessions[token]
            self._save_sessions(sessions)
            raise AuthenticationError("Session token expired")
        return session["email"]

    def _generate_token(self) -> str:
        return base64.urlsafe_b64encode(os.urandom(24)).decode("ascii").rstrip("=")

    def _load_users(self) -> Dict[str, dict]:
        return self.storage.read_json(self.USERS_FILE, {})

    def _save_users(self, users: Dict[str, dict]):
        self.storage.write_json(self.USERS_FILE, users)

    def _load_sessions(self) -> Dict[str, dict]:
        return self.storage.read_json(self.SESSIONS_FILE, {})

    def _save_sessions(self, sessions: Dict[str, dict]):
        self.storage.write_json(self.SESSIONS_FILE, sessions)

    @staticmethod
    def _validate_email(email: str) -> bool:
        return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))
