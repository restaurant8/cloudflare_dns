import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlparse, urlunparse

from sqlalchemy.orm import Session
from websockets.sync.client import connect

from .dns_utils import parse_target
from .events import add_event
from .models import ExternalIpItem, ExternalIpSource, Origin
from .runtime_settings import get_runtime_settings
from .security import decrypt_secret


@dataclass(frozen=True)
class ImportedExternalIp:
    name: str
    group_name: str | None
    machine_key: str | None
    country: str | None
    target: str
    target_type: str
    port: int


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _nyanpass_ws_url(base_url: str, token: str) -> str:
    parsed = urlparse(base_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    path = "/api/v1/system/node/status_ws"
    query = urlencode({"token": token})
    return urlunparse((scheme, parsed.netloc, path, "", query, ""))


def _clean_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, (dict, list, tuple, set)):
        return None
    text = str(value).strip()
    return text or None


def _first_text(data: dict, keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = _clean_text(data.get(key))
        if value:
            return value
    return None


def _first_nested_text(data: dict, containers: tuple[str, ...], keys: tuple[str, ...]) -> str | None:
    direct = _first_text(data, keys)
    if direct:
        return direct
    for container in containers:
        nested = data.get(container)
        if isinstance(nested, dict):
            value = _first_text(nested, keys)
            if value:
                return value
    return None


def _server_machine_key(group_name: str | None, server: dict, server_name: str) -> str | None:
    value = _first_nested_text(server, ("server", "node", "host", "info"), ("id", "uuid", "node_id", "server_id", "handle"))
    if value:
        return f"{group_name or ''}:{value}"
    if server_name:
        return f"{group_name or ''}:{server_name}"
    return None


def _server_country(group: dict, server: dict) -> str | None:
    country_keys = ("country", "country_name", "countryCode", "country_code", "location", "region", "region_name", "geo")
    containers = ("location", "geo", "geoip", "ip_info", "host", "server", "node", "info")
    return _first_nested_text(server, containers, country_keys) or _first_nested_text(group, containers, country_keys)


def extract_nyanpass_ips(payload: object, default_port: int) -> list[ImportedExternalIp]:
    if not isinstance(payload, list):
        return []
    items: dict[tuple[str, int], ImportedExternalIp] = {}
    for group in payload:
        if not isinstance(group, dict):
            continue
        group_name = str(group.get("name") or "").strip() or None
        servers = group.get("servers")
        if not isinstance(servers, list):
            continue
        for server in servers:
            if not isinstance(server, dict) or not server.get("online"):
                continue
            server_name = str(server.get("name") or server.get("handle") or "").strip()
            display_name = " / ".join(part for part in [group_name, server_name] if part) or "Nyanpass 节点"
            machine_key = _server_machine_key(group_name, server, server_name)
            country = _server_country(group, server)
            for key in ("ip4", "ip6"):
                value = str(server.get(key) or "").strip()
                if not value or not _is_public_ip(value):
                    continue
                target = parse_target(value)
                item = ImportedExternalIp(
                    name=display_name,
                    group_name=group_name,
                    machine_key=machine_key,
                    country=country,
                    target=target.value,
                    target_type=target.target_type,
                    port=default_port,
                )
                items[(item.target, item.port)] = item
    return sorted(items.values(), key=lambda item: (item.group_name or "", item.name, item.target))


def fetch_nyanpass_ips(source: ExternalIpSource, timeout_seconds: float = 15) -> list[ImportedExternalIp]:
    token = decrypt_secret(source.token_encrypted)
    ws_url = _nyanpass_ws_url(source.base_url, token)
    with connect(ws_url, open_timeout=timeout_seconds, close_timeout=2) as websocket:
        raw = websocket.recv(timeout=timeout_seconds)
    payload = json.loads(raw)
    return extract_nyanpass_ips(payload, source.default_port)


def sync_external_ip_source(db: Session, source: ExternalIpSource) -> int:
    if source.source_type != "nyanpass":
        raise ValueError(f"不支持的外部来源类型: {source.source_type}")

    now = datetime.utcnow()
    imported_items = fetch_nyanpass_ips(source)
    existing = {(item.target, item.port): item for item in source.items}
    seen_keys: set[tuple[str, int]] = set()

    for imported in imported_items:
        key = (imported.target, imported.port)
        seen_keys.add(key)
        item = existing.get(key)
        if item is None:
            item = ExternalIpItem(source_id=source.id, target=imported.target, port=imported.port)
            db.add(item)
        item.name = imported.name
        item.group_name = imported.group_name
        item.machine_key = imported.machine_key
        item.country = imported.country
        item.target_type = imported.target_type
        item.status = "healthy"
        item.last_seen_at = now

    for key, item in existing.items():
        if key not in seen_keys:
            db.delete(item)

    source.status = "ok"
    source.last_error = None
    source.last_synced_at = now
    _sync_bound_origins(db, source, imported_items)
    db.flush()
    return len(imported_items)


def _sync_bound_origins(db: Session, source: ExternalIpSource, imported_items: list[ImportedExternalIp]) -> int:
    """把机器的新 IP 跟随到绑定的故障切换备用目标。

    绑定按 machine_key（而不是 item id）：机器换 IP 后列表项是删旧建新的，
    只有 machine_key 能跨 IP 变化定位同一台机器。
    """
    by_key: dict[str, list[ImportedExternalIp]] = {}
    for imported in imported_items:
        if imported.machine_key:
            by_key.setdefault(imported.machine_key, []).append(imported)
    origins = (
        db.query(Origin)
        .filter(Origin.external_source_id == source.id, Origin.external_machine_key.isnot(None))
        .all()
    )
    updated = 0
    for origin in origins:
        candidates = by_key.get(origin.external_machine_key or "")
        if not candidates:
            # 机器暂时不在线/没上报不代表被删了，保留绑定等它回来
            continue
        # 同一台机器可能同时有 v4/v6，优先跟随源站现有的地址类型
        chosen = next((item for item in candidates if item.target_type == origin.target_type), candidates[0])
        if origin.target == chosen.target and origin.target_type == chosen.target_type:
            continue
        old_target = origin.target
        origin.target = chosen.target
        origin.target_type = chosen.target_type
        origin.status = "unknown"
        origin.last_error = "外部 IP 已更换，等待本地和探针探测结果"
        origin.last_checked_at = None
        origin.last_rtt_ms = None
        origin.probe_states.clear()
        updated += 1
        add_event(
            db,
            "external_ip.origin_synced",
            "info",
            f"{chosen.name} 外部 IP 变为 {chosen.target}，已同步到备用目标（原 {old_target}）",
            {
                "origin_id": origin.id,
                "source_id": source.id,
                "machine_key": origin.external_machine_key,
                "old_target": old_target,
                "new_target": chosen.target,
            },
        )
    return updated


def mark_external_ip_sources_due(db: Session) -> int:
    """把所有启用的外部来源标记为到期，下个调度周期立即重新同步。

    云资源换 IP 成功后调用：机器的新 IP 要尽快同步回来，绑定的备用目标才能跟上。
    """
    sources = db.query(ExternalIpSource).filter(ExternalIpSource.enabled.is_(True)).all()
    for source in sources:
        source.last_synced_at = None
    if sources:
        db.flush()
    return len(sources)


def sync_due_external_ip_sources(db: Session) -> int:
    settings = get_runtime_settings(db)
    now = datetime.utcnow()
    sources = db.query(ExternalIpSource).filter(ExternalIpSource.enabled.is_(True)).all()
    synced = 0
    for source in sources:
        interval = max(source.sync_interval_seconds or settings.external_ip_sync_interval_seconds, 10)
        if source.last_synced_at and source.last_synced_at > now - timedelta(seconds=interval):
            continue
        try:
            sync_external_ip_source(db, source)
        except Exception as exc:
            source.status = "error"
            source.last_error = str(exc)
            source.last_synced_at = now
        synced += 1
    return synced
