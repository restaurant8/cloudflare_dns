"""Cloudflare Access JWT verification.

The legacy check only asserted that the `Cf-Access-*` headers were present, which
anyone able to reach the origin directly could spoof. When a team domain and AUD
are configured we instead verify the RS256 signature of the assertion against the
team's published JWKS, plus its expiry and audience.
"""
import base64
import json
import time
from threading import Lock

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_JWKS_TTL_SECONDS = 3600
_jwks_cache: dict[str, tuple[float, dict[str, rsa.RSAPublicKey]]] = {}
_jwks_lock = Lock()


def _b64url_decode(data: str) -> bytes:
    padding_len = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding_len).encode("ascii"))


def _int_from_b64(value: str) -> int:
    return int.from_bytes(_b64url_decode(value), "big")


def _certs_url(team_domain: str) -> str:
    domain = team_domain.strip().rstrip("/")
    if not domain.startswith("http://") and not domain.startswith("https://"):
        domain = f"https://{domain}"
    return f"{domain}/cdn-cgi/access/certs"


def _load_jwks(team_domain: str) -> dict[str, rsa.RSAPublicKey]:
    now = time.time()
    with _jwks_lock:
        cached = _jwks_cache.get(team_domain)
        if cached and cached[0] > now:
            return cached[1]
    response = httpx.get(_certs_url(team_domain), timeout=10.0)
    response.raise_for_status()
    keys: dict[str, rsa.RSAPublicKey] = {}
    for jwk in response.json().get("keys", []):
        if jwk.get("kty") != "RSA" or "kid" not in jwk:
            continue
        public_numbers = rsa.RSAPublicNumbers(_int_from_b64(jwk["e"]), _int_from_b64(jwk["n"]))
        keys[jwk["kid"]] = public_numbers.public_key()
    with _jwks_lock:
        _jwks_cache[team_domain] = (now + _JWKS_TTL_SECONDS, keys)
    return keys


def verify_access_jwt(token: str, team_domain: str, audience: str) -> bool:
    """Return True only if the JWT signature, expiry and audience all check out."""
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        if header.get("alg") != "RS256":
            return False
        keys = _load_jwks(team_domain)
        public_key = keys.get(header.get("kid"))
        if public_key is None:
            return False
        public_key.verify(
            _b64url_decode(signature_b64),
            f"{header_b64}.{payload_b64}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        payload = json.loads(_b64url_decode(payload_b64))
        if int(payload.get("exp", 0)) < int(time.time()):
            return False
        aud = payload.get("aud", [])
        aud_list = aud if isinstance(aud, list) else [aud]
        return audience in aud_list
    except (ValueError, KeyError, InvalidSignature, httpx.HTTPError):
        return False
