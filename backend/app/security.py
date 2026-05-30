import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any

from cryptography.fernet import Fernet

from .config import get_settings


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    iterations = 260_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64url(salt)}${_b64url(digest)}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations_raw, salt_raw, digest_raw = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_raw)
        salt = _b64url_decode(salt_raw)
        expected = _b64url_decode(digest_raw)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def _sign(payload: str) -> str:
    settings = get_settings()
    return _b64url(hmac.new(settings.secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest())


def create_access_token(user_id: int) -> str:
    settings = get_settings()
    payload = {
        "sub": str(user_id),
        "iat": int(time.time()),
        "exp": int(time.time()) + settings.access_token_ttl_seconds,
    }
    encoded = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{encoded}.{_sign(encoded)}"


def verify_access_token(token: str) -> int | None:
    try:
        encoded, signature = token.split(".", 1)
        if not hmac.compare_digest(_sign(encoded), signature):
            return None
        payload = json.loads(_b64url_decode(encoded))
        if int(payload["exp"]) < int(time.time()):
            return None
        return int(payload["sub"])
    except Exception:
        return None


def _fernet_key() -> bytes:
    settings = get_settings()
    raw = settings.app_encryption_key.encode("utf-8")
    try:
        Fernet(raw)
        return raw
    except Exception:
        digest = hashlib.sha256(raw + settings.secret_key.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)


def encrypt_secret(value: str) -> str:
    return Fernet(_fernet_key()).encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str) -> str:
    return Fernet(_fernet_key()).decrypt(value.encode("ascii")).decode("utf-8")


def hash_token(token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).digest()
    return _b64url(digest)


def verify_token_hash(token: str, token_hash: str) -> bool:
    return hmac.compare_digest(hash_token(token), token_hash)


def sign_webhook_payload(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def json_dumps(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))

