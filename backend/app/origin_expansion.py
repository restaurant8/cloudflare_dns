import ipaddress
import json
import socket
from typing import Any


DIRECT_PUBLISH_MODE = "direct"
EXPANDED_PUBLISH_MODE = "expanded"


def publish_mode(origin: Any) -> str:
    return getattr(origin, "publish_mode", None) or DIRECT_PUBLISH_MODE


def is_expanded_origin(origin: Any) -> bool:
    return publish_mode(origin) == EXPANDED_PUBLISH_MODE


def _json_list(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        items = json.loads(value)
    except (TypeError, ValueError):
        return []
    if not isinstance(items, list):
        return []
    return [str(item) for item in items if item]


def _set_json_list(origin: Any, attr: str, values: list[str]) -> None:
    unique = sorted(set(values), key=lambda item: (ipaddress.ip_address(item).version, ipaddress.ip_address(item)))
    setattr(origin, attr, json.dumps(unique))


def resolved_ips(origin: Any) -> list[str]:
    return _json_list(getattr(origin, "resolved_ips_json", None))


def set_resolved_ips(origin: Any, values: list[str]) -> None:
    _set_json_list(origin, "resolved_ips_json", values)


def healthy_ips(origin: Any) -> list[str]:
    return _json_list(getattr(origin, "healthy_ips_json", None))


def set_healthy_ips(origin: Any, values: list[str]) -> None:
    _set_json_list(origin, "healthy_ips_json", values)


def published_ips(origin: Any) -> list[str]:
    return _json_list(getattr(origin, "published_ips_json", None))


def set_published_ips(origin: Any, values: list[str]) -> None:
    _set_json_list(origin, "published_ips_json", values)


def expanded_source_key(source_key: str, ip: str) -> str:
    return f"{source_key}|{ip}"


def split_expanded_source_key(source_key: str) -> tuple[str, str | None]:
    if "|" not in source_key:
        return source_key, None
    source, ip = source_key.split("|", 1)
    return source, ip or None


def resolve_hostname_ips(hostname: str) -> list[str]:
    addresses = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    ips: set[str] = set()
    for family, _, _, _, sockaddr in addresses:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        try:
            ips.add(str(ipaddress.ip_address(sockaddr[0])))
        except ValueError:
            continue
    return sorted(ips, key=lambda item: (ipaddress.ip_address(item).version, ipaddress.ip_address(item)))


def record_type_for_ip(ip: str) -> str:
    return "A" if ipaddress.ip_address(ip).version == 4 else "AAAA"

