import ipaddress
import re
import socket
import time
from dataclasses import dataclass


HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{2,63}\.?$")


@dataclass(frozen=True)
class TargetInfo:
    value: str
    target_type: str
    record_type: str


@dataclass(frozen=True)
class TcpCheckResult:
    success: bool
    rtt_ms: float | None
    error: str | None
    resolved_ip: str | None = None


def normalize_hostname(value: str) -> str:
    cleaned = value.strip().rstrip(".").lower()
    if not cleaned or "://" in cleaned or "/" in cleaned or any(ch.isspace() for ch in cleaned):
        raise ValueError("域名格式无效")
    try:
        cleaned.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("域名格式无效") from exc
    ascii_name = cleaned.encode("idna").decode("ascii")
    if not HOSTNAME_RE.match(ascii_name + "."):
        raise ValueError("域名格式无效")
    return ascii_name


def parse_target(value: str) -> TargetInfo:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("目标不能为空")
    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        hostname = normalize_hostname(cleaned)
        return TargetInfo(value=hostname, target_type="hostname", record_type="CNAME")
    if ip.version == 4:
        return TargetInfo(value=str(ip), target_type="ipv4", record_type="A")
    return TargetInfo(value=str(ip), target_type="ipv6", record_type="AAAA")


def record_type_for_target_type(target_type: str) -> str:
    if target_type == "ipv4":
        return "A"
    if target_type == "ipv6":
        return "AAAA"
    if target_type == "hostname":
        return "CNAME"
    raise ValueError(f"不支持的目标类型: {target_type}")


def tcp_check(target: str, port: int, timeout: float) -> TcpCheckResult:
    started = time.perf_counter()
    try:
        addresses = socket.getaddrinfo(target, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return TcpCheckResult(False, None, f"resolve failed: {exc}", None)

    last_error = None
    for family, socktype, proto, _, sockaddr in addresses:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            elapsed = (time.perf_counter() - started) * 1000
            resolved_ip = sockaddr[0]
            return TcpCheckResult(True, round(elapsed, 2), None, resolved_ip)
        except OSError as exc:
            last_error = str(exc)
        finally:
            sock.close()
    elapsed = (time.perf_counter() - started) * 1000
    return TcpCheckResult(False, round(elapsed, 2), last_error or "connect failed", None)
