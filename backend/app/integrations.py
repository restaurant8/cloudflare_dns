import json
import re
from datetime import datetime
from typing import Any

import httpx
from sqlalchemy.orm import Session

from .dns_utils import parse_target
from .events import add_event
from .models import AppSetting, AzPanelResource, IpChangeJob, Origin, XboardNodeBinding
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
    message = " ".join(str(data.get(key, "")) for key in ("message", "msg", "content"))
    for match in IP_RE.findall(message):
        try:
            return parse_target(match).value
        except ValueError:
            continue
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
    response.raise_for_status()
    data = _extract_payload(response.json())
    new_ip = _extract_ip(data)
    if not new_ip:
        raise RuntimeError("azpanel did not return a new IP")
    data["new_ip"] = new_ip
    return data


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
    response.raise_for_status()
    data = _extract_payload(response.json())
    return data


def _resource_on_cooldown(resource: AzPanelResource, now: datetime) -> bool:
    last_attempt_at = getattr(resource, "last_attempt_at", None) or resource.last_change_at
    if last_attempt_at is None:
        return False
    return (now - last_attempt_at).total_seconds() < max(resource.cooldown_seconds, 60)


def change_resource_ip(
    db: Session,
    resource: AzPanelResource,
    trigger_type: str = "manual",
    reason: str | None = None,
) -> IpChangeJob:
    now = datetime.utcnow()
    if _resource_on_cooldown(resource, now):
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

        origin = db.get(Origin, resource.origin_id) if resource.origin_id else None
        if origin is not None and resource.auto_update_origin:
            origin.target = target_info.value
            origin.target_type = target_info.target_type
            origin.port = resource.port
            origin.status = "unknown"
            origin.last_error = None

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
