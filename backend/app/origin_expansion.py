import ipaddress
import json
import socket
from collections.abc import Mapping
from typing import Any


DIRECT_PUBLISH_MODE = "direct"
EXPANDED_PUBLISH_MODE = "expanded"
DEFAULT_EXPANDED_IP_PRIORITY = 100


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


def _json_priority_map(value: str | None) -> dict[str, int]:
    if not value:
        return {}
    try:
        items = json.loads(value)
    except (TypeError, ValueError):
        return {}
    if not isinstance(items, dict):
        return {}
    try:
        return normalize_expanded_ip_priorities(items)
    except ValueError:
        return {}


def normalize_expanded_ip_priorities(values: Mapping[str, Any] | None) -> dict[str, int]:
    result: dict[str, int] = {}
    for raw_ip, raw_priority in (values or {}).items():
        try:
            ip = str(ipaddress.ip_address(str(raw_ip).strip()))
        except ValueError as exc:
            raise ValueError(f"Invalid expanded IP priority target: {raw_ip}") from exc
        try:
            priority = int(raw_priority)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid expanded IP priority for {ip}: {raw_priority}") from exc
        if priority < 0 or priority > 100000:
            raise ValueError(f"Expanded IP priority for {ip} must be between 0 and 100000")
        result[ip] = priority
    return result


def set_expanded_ip_priorities(origin: Any, values: Mapping[str, Any] | None) -> None:
    normalized = normalize_expanded_ip_priorities(values)
    setattr(origin, "expanded_ip_priorities_json", json.dumps(normalized, sort_keys=True))


def expanded_ip_priorities(origin: Any) -> dict[str, int]:
    return _json_priority_map(getattr(origin, "expanded_ip_priorities_json", None))


def selected_healthy_ip(origin: Any) -> str | None:
    ips = healthy_ips(origin)
    if not ips:
        return None
    current_published = published_ips(origin)
    if current_published and current_published[0] in ips:
        return current_published[0]
    priorities = expanded_ip_priorities(origin)
    return sorted(
        ips,
        key=lambda item: (
            priorities.get(item, DEFAULT_EXPANDED_IP_PRIORITY),
            ipaddress.ip_address(item).version,
            ipaddress.ip_address(item),
        ),
    )[0]


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
