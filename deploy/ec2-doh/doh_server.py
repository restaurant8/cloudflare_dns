#!/usr/bin/env python3
"""Small authoritative DoH allowlist service for a CloudFront VPC origin.

It intentionally performs no recursive DNS lookups. Records are atomically
replaced by cloudflare_dns through a timestamped, nonce-protected HMAC request.
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import struct
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


CONFIG_PATH = Path(os.environ.get("DOH_CONFIG_PATH", "/var/lib/private-doh/records.json"))
QUERY_PATH = os.environ.get("DOH_QUERY_PATH", "/dns-query")
ADMIN_PATH = os.environ.get("DOH_ADMIN_PATH", "/_admin/doh-sync")
LEGACY_PATHS = {item.strip() for item in os.environ.get("DOH_LEGACY_QUERY_PATHS", "").split(",") if item.strip()}
HMAC_SECRET = os.environ.get("DOH_HMAC_SECRET", "")
MAX_ADMIN_SKEW_SECONDS = int(os.environ.get("DOH_MAX_ADMIN_SKEW_SECONDS", "300"))
MAX_BODY_BYTES = 1024 * 1024
TYPE_TO_CODE = {"A": 1, "AAAA": 28}
CODE_TO_TYPE = {value: key for key, value in TYPE_TO_CODE.items()}

_lock = threading.RLock()
_snapshot = {"version": 1, "revision": "empty", "records": []}
_seen_nonces: dict[str, int] = {}


def normalize_name(value: str) -> str:
    return value.strip().rstrip(".").lower().encode("idna").decode("ascii")


def load_snapshot() -> None:
    global _snapshot
    if not CONFIG_PATH.exists():
        return
    data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    validate_snapshot(data)
    with _lock:
        _snapshot = data


def validate_snapshot(data: object) -> None:
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("records"), list):
        raise ValueError("invalid snapshot envelope")
    seen: set[tuple[str, str, str]] = set()
    for record in data["records"]:
        if not isinstance(record, dict):
            raise ValueError("invalid record")
        name = normalize_name(str(record.get("name") or ""))
        record_type = str(record.get("type") or "").upper()
        value = str(record.get("value") or "").strip()
        if not name or record_type not in TYPE_TO_CODE:
            raise ValueError("unsupported record name or type")
        expected = 4 if record_type == "A" else 6
        if ipaddress.ip_address(value).version != expected:
            raise ValueError(f"invalid {record_type} value")
        key = (name, record_type, value)
        if key in seen:
            raise ValueError(f"duplicate record: {name} {record_type} {value}")
        seen.add(key)
        ttl = int(record.get("ttl", 60))
        if ttl < 0 or ttl > 86400:
            raise ValueError("invalid TTL")


def persist_snapshot(data: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=CONFIG_PATH.parent, delete=False) as handle:
        json.dump(data, handle, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    os.replace(temporary, CONFIG_PATH)
    os.chmod(CONFIG_PATH, 0o600)


def current_records(name: str, query_type: str) -> tuple[bool, list[dict]]:
    normalized = normalize_name(name)
    with _lock:
        records = list(_snapshot.get("records", []))
    allowed = any(normalize_name(str(item["name"])) == normalized for item in records)
    answers = [
        item
        for item in records
        if normalize_name(str(item["name"])) == normalized
        and str(item["type"]).upper() == query_type
    ]
    return allowed, answers


def encode_name(name: str) -> bytes:
    output = bytearray()
    for label in normalize_name(name).split("."):
        encoded = label.encode("ascii")
        output.append(len(encoded))
        output.extend(encoded)
    output.append(0)
    return bytes(output)


def read_name(message: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 20:
        raise ValueError("DNS compression loop")
    labels = []
    next_offset = offset
    jumped = False
    while True:
        if offset >= len(message):
            raise ValueError("truncated DNS name")
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            suffix, _ = read_name(message, pointer, depth + 1)
            labels.extend(suffix.split(".") if suffix else [])
            if not jumped:
                next_offset = offset + 2
            jumped = True
            break
        if length == 0:
            if not jumped:
                next_offset = offset + 1
            break
        offset += 1
        if length > 63 or offset + length > len(message):
            raise ValueError("invalid DNS label")
        labels.append(message[offset : offset + length].decode("ascii"))
        offset += length
        if not jumped:
            next_offset = offset
    return normalize_name(".".join(labels)), next_offset


def parse_dns_question(message: bytes) -> tuple[int, int, bytes, str, int]:
    if len(message) < 12:
        raise ValueError("truncated DNS message")
    message_id, query_flags, question_count = struct.unpack("!HHH", message[:6])
    if question_count != 1:
        raise ValueError("exactly one DNS question is required")
    name, offset = read_name(message, 12)
    if offset + 4 > len(message):
        raise ValueError("truncated DNS question")
    query_type, query_class = struct.unpack("!HH", message[offset : offset + 4])
    if query_class != 1:
        raise ValueError("only IN class is supported")
    return message_id, query_flags, message[12 : offset + 4], name, query_type


def answer_rdata(record_type: str, value: str) -> bytes:
    if record_type in {"A", "AAAA"}:
        return ipaddress.ip_address(value).packed
    return encode_name(value)


def dns_wire_response(message: bytes) -> bytes:
    message_id, query_flags, question, name, query_code = parse_dns_question(message)
    query_type = CODE_TO_TYPE.get(query_code, str(query_code))
    allowed, records = current_records(name, query_type)
    rcode = 0 if allowed else 5
    answers = bytearray()
    if allowed:
        for record in records:
            record_type = str(record["type"]).upper()
            rdata = answer_rdata(record_type, str(record["value"]))
            answers.extend(b"\xc0\x0c")
            answers.extend(struct.pack("!HHIH", TYPE_TO_CODE[record_type], 1, int(record.get("ttl", 60)), len(rdata)))
            answers.extend(rdata)
    flags = 0x8000 | 0x0400 | (query_flags & 0x0100) | rcode  # QR + AA + copied RD + RCODE
    header = struct.pack("!HHHHHH", message_id, flags, 1, len(records) if allowed else 0, 0, 0)
    return header + question + bytes(answers)


def json_response(name: str, query_type: str) -> dict:
    query_type = query_type.upper()
    allowed, records = current_records(name, query_type)
    result = {
        "Status": 0 if allowed else 5,
        "TC": False,
        "RD": True,
        "RA": False,
        "AA": True,
        "AD": False,
        "CD": False,
        "Question": [{"name": normalize_name(name) + ".", "type": TYPE_TO_CODE.get(query_type, 1)}],
    }
    if allowed and records:
        result["Answer"] = [
            {
                "name": normalize_name(str(record["name"])) + ".",
                "type": TYPE_TO_CODE[str(record["type"]).upper()],
                "TTL": int(record.get("ttl", 60)),
                "data": str(record["value"]),
            }
            for record in records
        ]
    return result


def verify_admin(headers, body: bytes) -> None:
    if len(HMAC_SECRET) < 32:
        raise PermissionError("server HMAC secret is not configured")
    timestamp = headers.get("x-doh-timestamp", "")
    nonce = headers.get("x-doh-nonce", "")
    signature = headers.get("x-doh-signature", "")
    try:
        timestamp_value = int(timestamp)
    except ValueError as exc:
        raise PermissionError("invalid timestamp") from exc
    now = int(time.time())
    if abs(now - timestamp_value) > MAX_ADMIN_SKEW_SECONDS:
        raise PermissionError("expired request")
    if len(nonce) < 16 or len(nonce) > 128:
        raise PermissionError("invalid nonce")
    with _lock:
        for item, seen_at in list(_seen_nonces.items()):
            if seen_at < now - MAX_ADMIN_SKEW_SECONDS * 2:
                _seen_nonces.pop(item, None)
        if nonce in _seen_nonces:
            raise PermissionError("replayed request")
    signed = timestamp.encode("ascii") + b"\n" + nonce.encode("ascii") + b"\n" + body
    expected = hmac.new(HMAC_SECRET.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise PermissionError("invalid signature")
    with _lock:
        _seen_nonces[nonce] = now


class Handler(BaseHTTPRequestHandler):
    server_version = "PrivateDoH/1.0"

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.client_address[0]} - {fmt % args}", flush=True)

    def send_bytes(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, data: object) -> None:
        self.send_bytes(status, "application/json", json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/healthz":
            with _lock:
                revision = _snapshot.get("revision")
                count = len(_snapshot.get("records", []))
            self.send_json(200, {"ok": True, "revision": revision, "record_count": count})
            return
        if parsed.path not in {QUERY_PATH, *LEGACY_PATHS}:
            self.send_json(404, {"error": "not found"})
            return
        params = parse_qs(parsed.query)
        if params.get("dns"):
            try:
                encoded = params["dns"][0]
                wire = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
                self.send_bytes(200, "application/dns-message", dns_wire_response(wire))
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        name = (params.get("name") or [""])[0]
        query_type = (params.get("type") or ["A"])[0]
        try:
            self.send_json(200, json_response(name, query_type))
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        length = int(self.headers.get("content-length", "0"))
        if length < 0 or length > MAX_BODY_BYTES:
            self.send_json(413, {"error": "body too large"})
            return
        body = self.rfile.read(length)
        if parsed.path == ADMIN_PATH:
            try:
                verify_admin(self.headers, body)
                data = json.loads(body.decode("utf-8"))
                validate_snapshot(data)
                persist_snapshot(data)
                global _snapshot
                with _lock:
                    _snapshot = data
                self.send_json(200, {"ok": True, "revision": data.get("revision"), "record_count": len(data["records"])})
            except PermissionError as exc:
                self.send_json(401, {"error": str(exc)})
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        if parsed.path in {QUERY_PATH, *LEGACY_PATHS}:
            try:
                self.send_bytes(200, "application/dns-message", dns_wire_response(body))
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        self.send_json(404, {"error": "not found"})


if __name__ == "__main__":
    if len(HMAC_SECRET) < 32:
        raise SystemExit("DOH_HMAC_SECRET must contain at least 32 characters")
    load_snapshot()
    bind = os.environ.get("DOH_BIND", "0.0.0.0")
    port = int(os.environ.get("DOH_PORT", "80"))
    ThreadingHTTPServer((bind, port), Handler).serve_forever()
