from ipaddress import ip_address
from typing import Any


def _clean_ip(value: str) -> str:
    cleaned = value.strip().strip('"').strip("'")
    if cleaned.startswith("[") and "]" in cleaned:
        return cleaned[1:cleaned.index("]")]
    if cleaned.count(":") == 1 and "." in cleaned:
        return cleaned.split(":", 1)[0]
    return cleaned


def _is_public_ip(value: str) -> bool:
    try:
        parsed = ip_address(_clean_ip(value))
    except ValueError:
        return False
    return parsed.is_global


def client_ip_from_request(request: Any) -> str | None:
    single_value_headers = ("cf-connecting-ip", "x-real-ip", "x-client-ip")
    for header in single_value_headers:
        value = request.headers.get(header)
        if value:
            return _clean_ip(value)

    forwarded_for = request.headers.get("x-forwarded-for", "")
    forwarded_items = [_clean_ip(item) for item in forwarded_for.split(",") if item.strip()]
    for item in forwarded_items:
        if _is_public_ip(item):
            return item
    if forwarded_items:
        return forwarded_items[0]

    return request.client.host if request.client else None
