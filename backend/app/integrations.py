import json
import re
from datetime import datetime
from typing import Any

import httpx
from sqlalchemy.orm import Session

from .dns_utils import parse_target
from .events import add_event
from .models import AppSetting, AzPanelRemoteResource, AzPanelResource, IpChangeJob, Origin, XboardNodeBinding
from .notifier import send_webhooks
from .security import decrypt_secret, encrypt_secret, json_dumps


AZPANEL_ENABLED = "azpanel.enabled"
AZPANEL_BASE_URL = "azpanel.base_url"
AZPANEL_API_TOKEN = "azpanel.api_token"
AZPANEL_TIMEOUT = "azpanel.timeout_seconds"
AZPANEL_DEFAULT_COOLDOWN = "azpanel.default_cooldown_seconds"

XBOARD_ENABLED = "xboard.enabled"
XBOARD_BASE_URL = "xboard.base_url"
XBOARD_API_TOKEN = "xboard.api_token"
XBOARD_TIMEOUT = "xboard.timeout_seconds"

IP_RE = re.compile(r"(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,})")


def get_setting(db: Session, key: str, default: str = "") -> str:
    row = db.get(AppSetting, key)
    return row.value if row is not None else default


def set_setting(db: Session, key: str, value: str) -> None:
    row = db.get(AppSetting, key)
    if row is None:
        row = AppSetting(key=key, value=value)
        db.add(row)
    else:
        row.value = value
    db.flush()


def _decrypt_setting(value: str) -> str:
    if not value:
        return ""
    try:
        return decrypt_secret(value)
    except Exception:
        return value


def _bool_setting(db: Session, key: str, default: bool = False) -> bool:
    return get_setting(db, key, "1" if default else "0") == "1"


def _int_setting(db: Session, key: str, default: int) -> int:
    try:
        return int(get_setting(db, key, str(default)))
    except ValueError:
        return default


def azpanel_settings(db: Session) -> dict[str, Any]:
    return {
        "enabled": _bool_setting(db, AZPANEL_ENABLED),
        "base_url": get_setting(db, AZPANEL_BASE_URL),
        "api_token_configured": bool(get_setting(db, AZPANEL_API_TOKEN)),
        "timeout_seconds": _int_setting(db, AZPANEL_TIMEOUT, 60),
        "default_cooldown_seconds": _int_setting(db, AZPANEL_DEFAULT_COOLDOWN, 1800),
    }


def xboard_settings(db: Session) -> dict[str, Any]:
    return {
        "enabled": _bool_setting(db, XBOARD_ENABLED),
        "base_url": get_setting(db, XBOARD_BASE_URL),
        "api_token_configured": bool(get_setting(db, XBOARD_API_TOKEN)),
        "timeout_seconds": _int_setting(db, XBOARD_TIMEOUT, 30),
    }


def update_azpanel_settings(db: Session, updates: dict[str, Any]) -> dict[str, Any]:
    if "enabled" in updates and updates["enabled"] is not None:
        set_setting(db, AZPANEL_ENABLED, "1" if updates["enabled"] else "0")
    if "base_url" in updates and updates["base_url"] is not None:
        set_setting(db, AZPANEL_BASE_URL, str(updates["base_url"]).strip().rstrip("/"))
    if "api_token" in updates and updates["api_token"] is not None and updates["api_token"] != "":
        set_setting(db, AZPANEL_API_TOKEN, encrypt_secret(str(updates["api_token"]).strip()))
    if "timeout_seconds" in updates and updates["timeout_seconds"] is not None:
        set_setting(db, AZPANEL_TIMEOUT, str(int(updates["timeout_seconds"])))
    if "default_cooldown_seconds" in updates and updates["default_cooldown_seconds"] is not None:
        set_setting(db, AZPANEL_DEFAULT_COOLDOWN, str(int(updates["default_cooldown_seconds"])))
    return azpanel_settings(db)


def update_xboard_settings(db: Session, updates: dict[str, Any]) -> dict[str, Any]:
    if "enabled" in updates and updates["enabled"] is not None:
        set_setting(db, XBOARD_ENABLED, "1" if updates["enabled"] else "0")
    if "base_url" in updates and updates["base_url"] is not None:
        set_setting(db, XBOARD_BASE_URL, str(updates["base_url"]).strip().rstrip("/"))
    if "api_token" in updates and updates["api_token"] is not None and updates["api_token"] != "":
        set_setting(db, XBOARD_API_TOKEN, encrypt_secret(str(updates["api_token"]).strip()))
    if "timeout_seconds" in updates and updates["timeout_seconds"] is not None:
        set_setting(db, XBOARD_TIMEOUT, str(int(updates["timeout_seconds"])))
    return xboard_settings(db)


def _raise_for_status_with_body(response: httpx.Response, label: str) -> None:
    """Like response.raise_for_status() but keeps the upstream body in the message.

    httpx's default error only carries the status code and URL, so the real
    reason returned by azpanel/Xboard (e.g. quota exceeded, bad resource_id)
    is lost. Surfacing the body makes failures debuggable from this side.
    """
    if response.is_success:
        return
    body = (response.text or "").strip()
    if len(body) > 500:
        body = body[:500] + "…"
    detail = f": {body}" if body else ""
    raise RuntimeError(
        f"{label} returned HTTP {response.status_code} for {response.request.url}{detail}"
    )


def _extract_payload(data: Any) -> dict[str, Any]:
    if isinstance(data, dict):
        nested = data.get("data")
        if isinstance(nested, dict):
            return {**data, **nested}
        return data
    return {}


def _extract_ip(data: dict[str, Any]) -> str | None:
    for key in ("new_ip", "ip", "public_ip", "ipv4", "ipv6", "address"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    # Text fallback: only trust the message when it contains exactly one distinct IP.
    # Messages like "changed from 1.2.3.4 to 5.6.7.8" are ambiguous — picking the
    # first match would propagate the OLD ip to origins and Xboard nodes.
    message = " ".join(str(data.get(key, "")) for key in ("message", "msg", "content"))
    candidates: list[str] = []
    for match in IP_RE.findall(message):
        try:
            info = parse_target(match)
        except ValueError:
            continue
        if info.target_type not in {"ipv4", "ipv6"}:
            continue
        if info.value not in candidates:
            candidates.append(info.value)
    if len(candidates) == 1:
        return candidates[0]
    return None


def _azpanel_token(db: Session) -> str:
    return _decrypt_setting(get_setting(db, AZPANEL_API_TOKEN))


def _xboard_token(db: Session) -> str:
    return _decrypt_setting(get_setting(db, XBOARD_API_TOKEN))


def call_azpanel_change_ip(db: Session, resource: AzPanelResource, reason: str | None = None) -> dict[str, Any]:
    settings = azpanel_settings(db)
    if not settings["enabled"]:
        raise RuntimeError("azpanel integration is disabled")
    if not settings["base_url"]:
        raise RuntimeError("azpanel base URL is not configured")
    token = _azpanel_token(db)
    if not token:
        raise RuntimeError("azpanel API token is not configured")

    payload = {
        "provider": resource.provider,
        "resource_id": resource.resource_id,
        "account_id": resource.account_id,
        "region": resource.region,
        "ip_version": resource.ip_version,
        "method": getattr(resource, "ip_change_method", "eip") or "eip",
        "current_ip": resource.current_ip,
        "port": resource.port,
        "reason": reason or "manual",
        "source": "cloudflare_dns",
    }
    response = httpx.post(
        f"{settings['base_url']}/api/internal/cloudflare-dns/change-ip",
        json=payload,
        headers={"Authorization": f"Bearer {token}", "X-Cloudflare-Dns-Token": token},
        timeout=settings["timeout_seconds"],
    )
    _raise_for_status_with_body(response, "azpanel change-ip")
    data = _extract_payload(response.json())
    new_ip = _extract_ip(data)
    if not new_ip:
        raise RuntimeError("azpanel did not return a new IP")
    data["new_ip"] = new_ip
    return data


def _remote_resource_key(item: dict[str, Any]) -> str:
    provider = str(item.get("provider") or "").strip().lower()
    resource_id = str(item.get("resource_id") or item.get("instance_id") or item.get("vm_id") or "").strip()
    account_id = str(item.get("account_id") or "").strip()
    region = str(item.get("region") or item.get("location") or "").strip()
    ip_version = str(item.get("ip_version") or "ipv4").strip().lower()
    return "|".join([provider, account_id, region, resource_id, ip_version])


def _remote_resource_identity(item: dict[str, Any]) -> tuple[str, str, str, str, str]:
    provider = str(item.get("provider") or "").strip().lower()
    account_id = str(item.get("account_id") or "").strip()
    region = str(item.get("region") or item.get("location") or "").strip()
    resource_id = str(item.get("resource_id") or item.get("instance_id") or item.get("vm_id") or "").strip()
    ip_version = str(item.get("ip_version") or "ipv4").strip().lower()
    return provider, account_id, region, resource_id, ip_version


def _normalize_remote_resource(item: dict[str, Any]) -> dict[str, Any] | None:
    provider = str(item.get("provider") or "").strip().lower()
    if provider not in {"azure", "aws"}:
        return None
    resource_id = str(item.get("resource_id") or item.get("instance_id") or item.get("vm_id") or "").strip()
    if not resource_id:
        return None
    ip_version = str(item.get("ip_version") or "ipv4").strip().lower()
    if ip_version not in {"ipv4", "ipv6"}:
        ip_version = "ipv4"
    current_ip = str(item.get("current_ip") or item.get("ip") or item.get("public_ip") or "").strip() or None
    name = str(item.get("name") or item.get("label") or resource_id).strip()
    account_id = str(item.get("account_id") or "").strip() or None
    region = str(item.get("region") or item.get("location") or "").strip() or None
    try:
        port = int(item.get("port") or 22)
    except (TypeError, ValueError):
        port = 22
    normalized = {
        "key": str(item.get("key") or _remote_resource_key(item)),
        "name": name,
        "provider": provider,
        "resource_id": resource_id,
        "account_id": account_id,
        "region": region,
        "ip_version": ip_version,
        "current_ip": current_ip,
        "status": str(item.get("status") or "").strip() or None,
        "remark": str(item.get("remark") or "").strip() or None,
        "port": max(1, min(65535, port)),
        "cached": False,
        "last_seen_at": None,
    }
    if not normalized["key"]:
        normalized["key"] = _remote_resource_key(normalized)
    return normalized


def _remote_resource_from_cache(row: AzPanelRemoteResource) -> dict[str, Any]:
    return {
        "key": row.key,
        "name": row.name,
        "provider": row.provider,
        "resource_id": row.resource_id,
        "account_id": row.account_id or None,
        "region": row.region or None,
        "ip_version": row.ip_version,
        "current_ip": row.current_ip,
        "status": row.status,
        "remark": row.remark,
        "port": row.port,
        "cached": True,
        "last_seen_at": row.last_seen_at,
    }


def _list_cached_remote_resources(db: Session, provider: str | None = None) -> list[dict[str, Any]]:
    query = db.query(AzPanelRemoteResource)
    if provider:
        query = query.filter(AzPanelRemoteResource.provider == provider)
    rows = query.order_by(
        AzPanelRemoteResource.provider.asc(),
        AzPanelRemoteResource.region.asc(),
        AzPanelRemoteResource.name.asc(),
        AzPanelRemoteResource.resource_id.asc(),
        AzPanelRemoteResource.ip_version.asc(),
    ).all()
    return [_remote_resource_from_cache(row) for row in rows]


def _cache_remote_resources(db: Session, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    now = datetime.utcnow()
    saved: list[dict[str, Any]] = []
    for item in items:
        provider, account_id, region, resource_id, ip_version = _remote_resource_identity(item)
        if not provider or not resource_id:
            continue
        row = (
            db.query(AzPanelRemoteResource)
            .filter(
                AzPanelRemoteResource.provider == provider,
                AzPanelRemoteResource.account_id == account_id,
                AzPanelRemoteResource.region == region,
                AzPanelRemoteResource.resource_id == resource_id,
                AzPanelRemoteResource.ip_version == ip_version,
            )
            .one_or_none()
        )
        if row is None:
            row = AzPanelRemoteResource(
                provider=provider,
                account_id=account_id,
                region=region,
                resource_id=resource_id,
                ip_version=ip_version,
            )
            db.add(row)
        row.key = str(item.get("key") or _remote_resource_key(item))
        row.name = str(item.get("name") or resource_id).strip() or resource_id
        row.current_ip = str(item.get("current_ip") or "").strip() or None
        row.status = str(item.get("status") or "").strip() or None
        row.remark = str(item.get("remark") or "").strip() or None
        row.port = int(item.get("port") or 22)
        row.last_seen_at = now
        row.source_json = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        saved_item = dict(item)
        saved_item["cached"] = False
        saved_item["last_seen_at"] = now
        saved.append(saved_item)
    db.flush()
    return saved


def _sync_local_resources_from_remote_items(db: Session, items: list[dict[str, Any]]) -> int:
    synced = 0
    for item in items:
        current_ip = str(item.get("current_ip") or "").strip()
        if not current_ip:
            continue
        provider, account_id, region, resource_id, ip_version = _remote_resource_identity(item)
        resources = (
            db.query(AzPanelResource)
            .filter(
                AzPanelResource.provider == provider,
                AzPanelResource.resource_id == resource_id,
                AzPanelResource.ip_version == ip_version,
            )
            .all()
        )
        for resource in resources:
            if (resource.account_id or "") != account_id or (resource.region or "") != region:
                continue
            if resource.current_ip == current_ip:
                continue
            resource.current_ip = current_ip
            try:
                sync_resource_current_ip_to_origin(db, resource)
            except ValueError as exc:
                resource.last_error = f"远端 IP 无法同步到源站: {exc}"
            else:
                resource.last_error = None
            synced += 1
    if synced:
        db.flush()
    return synced


def list_azpanel_remote_resources(db: Session, provider: str | None = None) -> list[dict[str, Any]]:
    settings = azpanel_settings(db)
    if not settings["base_url"]:
        raise RuntimeError("azpanel base URL is not configured")
    token = _azpanel_token(db)
    if not token:
        raise RuntimeError("azpanel API token is not configured")
    cached_items = _list_cached_remote_resources(db, provider)
    params = {}
    if provider and provider in {"azure", "aws"}:
        params["provider"] = provider
    try:
        response = httpx.get(
            f"{settings['base_url']}/api/internal/cloudflare-dns/resources",
            params=params,
            headers={"Authorization": f"Bearer {token}", "X-Cloudflare-Dns-Token": token},
            timeout=settings["timeout_seconds"],
        )
        response.raise_for_status()
        payload = response.json()
    except Exception:
        if cached_items:
            return cached_items
        raise
    data = _extract_payload(payload)
    raw_items = data.get("resources") or data.get("items") or data.get("data")
    if raw_items is None and isinstance(payload, list):
        raw_items = payload
    if isinstance(raw_items, dict):
        raw_items = list(raw_items.values())
    if not isinstance(raw_items, list):
        return cached_items
    normalized = [_normalize_remote_resource(item) for item in raw_items if isinstance(item, dict)]
    remote_items = _cache_remote_resources(db, [item for item in normalized if item is not None])
    _sync_local_resources_from_remote_items(db, remote_items)
    merged = {_remote_resource_identity(item): item for item in cached_items}
    merged.update({_remote_resource_identity(item): item for item in remote_items})
    return sorted(
        list(merged.values()),
        key=lambda item: (item["provider"], item.get("region") or "", item["name"], item["resource_id"], item["ip_version"]),
    )


def call_xboard_update_node_ip(db: Session, node: XboardNodeBinding, new_ip: str, reason: str | None = None) -> dict[str, Any]:
    settings = xboard_settings(db)
    if not settings["enabled"]:
        raise RuntimeError("Xboard integration is disabled")
    if not settings["base_url"]:
        raise RuntimeError("Xboard base URL is not configured")
    token = _xboard_token(db)
    if not token:
        raise RuntimeError("Xboard API token is not configured")

    payload = {
        "node_id": node.xboard_node_id,
        "host": new_ip,
        "reason": reason or "ip changed by cloudflare_dns",
        "source": "cloudflare_dns",
    }
    response = httpx.post(
        f"{settings['base_url']}/api/internal/cloudflare-dns/nodes/{node.xboard_node_id}/ip",
        json=payload,
        headers={"Authorization": f"Bearer {token}", "X-Cloudflare-Dns-Token": token},
        timeout=settings["timeout_seconds"],
    )
    _raise_for_status_with_body(response, "Xboard node update")
    data = _extract_payload(response.json())
    return data


def _resource_on_cooldown(resource: AzPanelResource, now: datetime) -> bool:
    last_attempt_at = getattr(resource, "last_attempt_at", None) or resource.last_change_at
    if last_attempt_at is None:
        return False
    return (now - last_attempt_at).total_seconds() < max(resource.cooldown_seconds, 60)


def sync_resource_current_ip_to_origin(db: Session, resource: AzPanelResource) -> bool:
    if not resource.origin_id or not resource.auto_update_origin or not resource.current_ip:
        return False
    origin = db.get(Origin, resource.origin_id)
    if origin is None:
        return False
    target_info = parse_target(resource.current_ip)
    changed = origin.target != target_info.value or origin.target_type != target_info.target_type or origin.port != resource.port
    if not changed:
        return False
    origin.target = target_info.value
    origin.target_type = target_info.target_type
    origin.port = resource.port
    origin.status = "unknown"
    origin.last_error = "资源 IP 已同步，等待本地和探针探测结果"
    origin.last_checked_at = None
    origin.last_rtt_ms = None
    origin.probe_states.clear()
    return True


def _resource_current_ip_matches_origin(resource: AzPanelResource, origin: Origin) -> bool:
    if not resource.current_ip:
        return True
    target_info = parse_target(resource.current_ip)
    return origin.target == target_info.value and origin.target_type == target_info.target_type and origin.port == resource.port


def change_resource_ip(
    db: Session,
    resource: AzPanelResource,
    trigger_type: str = "manual",
    reason: str | None = None,
) -> IpChangeJob | None:
    now = datetime.utcnow()
    if _resource_on_cooldown(resource, now):
        # Auto triggers fire every scheduler tick while an origin stays blocked, so
        # recording a "skipped" job each time floods ip_change_jobs (~60 rows per
        # 30-min cooldown) and drowns out real success/failure history. Manual
        # attempts still get a visible skipped record as user feedback.
        if trigger_type == "auto_blocked":
            return None
        last_attempt_at = getattr(resource, "last_attempt_at", None) or resource.last_change_at or now
        remaining = max(resource.cooldown_seconds, 60) - int((now - last_attempt_at).total_seconds())
        job = IpChangeJob(
            trigger_type=trigger_type,
            status="skipped",
            reason=reason,
            provider=resource.provider,
            azpanel_resource_id=resource.id,
            origin_id=resource.origin_id,
            old_ip=resource.current_ip,
            error=f"cooldown active, retry after {remaining} seconds",
            started_at=now,
            finished_at=now,
        )
        db.add(job)
        db.flush()
        return job

    job = IpChangeJob(
        trigger_type=trigger_type,
        status="running",
        reason=reason,
        provider=resource.provider,
        azpanel_resource_id=resource.id,
        origin_id=resource.origin_id,
        old_ip=resource.current_ip,
        request_json=json_dumps(
            {
                "provider": resource.provider,
                "resource_id": resource.resource_id,
                "account_id": resource.account_id,
                "region": resource.region,
                "ip_version": resource.ip_version,
            }
        ),
        started_at=now,
    )
    db.add(job)
    resource.last_attempt_at = now
    db.flush()

    try:
        result = call_azpanel_change_ip(db, resource, reason=reason)
        new_ip = str(result["new_ip"]).strip()
        target_info = parse_target(new_ip)
        resource.current_ip = target_info.value
        resource.last_change_at = datetime.utcnow()
        resource.last_error = None
        job.new_ip = target_info.value
        job.response_json = json.dumps(result, ensure_ascii=False, separators=(",", ":"))

        sync_resource_current_ip_to_origin(db, resource)

        xboard_config = xboard_settings(db)
        for node in list(resource.xboard_nodes):
            if not node.enabled or not node.auto_update_after_change:
                continue
            node.host = target_info.value
            node.last_sync_at = datetime.utcnow()
            if not xboard_config["enabled"]:
                node.last_error = None
                continue
            try:
                xboard_result = call_xboard_update_node_ip(db, node, target_info.value, reason=reason)
                node.last_error = None
                if job.response_json:
                    merged = json.loads(job.response_json)
                    merged.setdefault("xboard", []).append({"node_id": node.xboard_node_id, "result": xboard_result})
                    job.response_json = json.dumps(merged, ensure_ascii=False, separators=(",", ":"))
            except Exception as exc:
                node.last_error = str(exc)
                add_event(
                    db,
                    "xboard.node_update_failed",
                    "warning",
                    f"Xboard node {node.xboard_node_id} update failed: {exc}",
                    {"node_binding_id": node.id, "node_id": node.xboard_node_id, "error": str(exc)},
                )

        job.status = "success"
        job.finished_at = datetime.utcnow()
        payload = {
            "resource_id": resource.id,
            "provider": resource.provider,
            "old_ip": job.old_ip,
            "new_ip": job.new_ip,
            "origin_id": resource.origin_id,
            "trigger_type": trigger_type,
        }
        add_event(db, "azpanel.ip_changed", "info", f"{resource.name} changed IP to {job.new_ip}", payload)
        send_webhooks(db, "azpanel.ip_changed", payload)
    except Exception as exc:
        message = str(exc)
        resource.last_error = message
        job.status = "failed"
        job.error = message
        job.finished_at = datetime.utcnow()
        payload = {
            "resource_id": resource.id,
            "provider": resource.provider,
            "old_ip": job.old_ip,
            "origin_id": resource.origin_id,
            "trigger_type": trigger_type,
            "error": message,
        }
        add_event(db, "azpanel.ip_change_failed", "error", f"{resource.name} IP change failed: {message}", payload)
        send_webhooks(db, "azpanel.ip_change_failed", payload)
    db.flush()
    return job


def trigger_ip_change_for_origin(db: Session, origin: Origin, reason: str) -> IpChangeJob | None:
    if not azpanel_settings(db)["enabled"]:
        return None
    resources = (
        db.query(AzPanelResource)
        .filter(AzPanelResource.enabled.is_(True), AzPanelResource.auto_change_on_blocked.is_(True))
        .filter(AzPanelResource.origin_id == origin.id)
        .order_by(AzPanelResource.id.asc())
        .all()
    )
    for resource in resources:
        if not resource.auto_update_origin or not resource.current_ip:
            continue
        try:
            resource_matches_origin = _resource_current_ip_matches_origin(resource, origin)
        except ValueError as exc:
            resource.last_error = f"resource current IP invalid: {exc}"
            continue
        if resource_matches_origin:
            continue
        sync_resource_current_ip_to_origin(db, resource)
        add_event(
            db,
            "azpanel.resource_ip_synced",
            "info",
            f"{resource.name} current IP synced to bound origin before auto change",
            {
                "resource_id": resource.id,
                "provider": resource.provider,
                "origin_id": origin.id,
                "current_ip": resource.current_ip,
                "reason": reason,
            },
        )
        return None
    if not resources and origin.target_type in {"ipv4", "ipv6"}:
        resources = (
            db.query(AzPanelResource)
            .filter(AzPanelResource.enabled.is_(True), AzPanelResource.auto_change_on_blocked.is_(True))
            .filter(AzPanelResource.current_ip == origin.target, AzPanelResource.port == origin.port)
            .order_by(AzPanelResource.id.asc())
            .all()
        )
    if not resources:
        return None
    return change_resource_ip(db, resources[0], trigger_type="auto_blocked", reason=reason)
