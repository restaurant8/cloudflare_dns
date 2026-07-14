import json
import re
import time
from datetime import datetime
from typing import Any

import httpx
from sqlalchemy.orm import Session

from .dns_utils import parse_target
from .events import add_event
from .external_ips import mark_external_ip_sources_due
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

# SynexVM（WHMCS pvewhmcs 面板）按服务直连接口。地址和 Token 都可配置：
# 全局设置提供默认值，AzPanelResource.api_url / api_token 可按服务覆盖。
SYNEXVM_ENABLED = "synexvm.enabled"
SYNEXVM_API_URL = "synexvm.api_url"
SYNEXVM_API_TOKEN = "synexvm.api_token"
SYNEXVM_TIMEOUT = "synexvm.timeout_seconds"
SYNEXVM_WAIT = "synexvm.wait_seconds"
SYNEXVM_DEFAULT_COOLDOWN = "synexvm.default_cooldown_seconds"

SYNEXVM_DEFAULT_API_URL = "https://www.synexvm.com/modules/servers/pvewhmcs/api.php"
SYNEXVM_POLL_INTERVAL_SECONDS = 5
# 手动"查询状态"时两次读取之间的间隔：新 IP 必须两次一致才采纳，防止过渡 IP
SYNEXVM_MANUAL_CONFIRM_DELAY_SECONDS = 3

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


def synexvm_settings(db: Session) -> dict[str, Any]:
    return {
        "enabled": _bool_setting(db, SYNEXVM_ENABLED),
        "api_url": get_setting(db, SYNEXVM_API_URL, "") or SYNEXVM_DEFAULT_API_URL,
        "api_token_configured": bool(get_setting(db, SYNEXVM_API_TOKEN)),
        "timeout_seconds": _int_setting(db, SYNEXVM_TIMEOUT, 30),
        "wait_seconds": _int_setting(db, SYNEXVM_WAIT, 120),
        "default_cooldown_seconds": _int_setting(db, SYNEXVM_DEFAULT_COOLDOWN, 1800),
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


def update_synexvm_settings(db: Session, updates: dict[str, Any]) -> dict[str, Any]:
    if "enabled" in updates and updates["enabled"] is not None:
        set_setting(db, SYNEXVM_ENABLED, "1" if updates["enabled"] else "0")
    if "api_url" in updates and updates["api_url"] is not None:
        set_setting(db, SYNEXVM_API_URL, str(updates["api_url"]).strip().rstrip("/"))
    if "api_token" in updates and updates["api_token"] is not None and updates["api_token"] != "":
        set_setting(db, SYNEXVM_API_TOKEN, encrypt_secret(str(updates["api_token"]).strip()))
    if "timeout_seconds" in updates and updates["timeout_seconds"] is not None:
        set_setting(db, SYNEXVM_TIMEOUT, str(int(updates["timeout_seconds"])))
    if "wait_seconds" in updates and updates["wait_seconds"] is not None:
        set_setting(db, SYNEXVM_WAIT, str(int(updates["wait_seconds"])))
    if "default_cooldown_seconds" in updates and updates["default_cooldown_seconds"] is not None:
        set_setting(db, SYNEXVM_DEFAULT_COOLDOWN, str(int(updates["default_cooldown_seconds"])))
    return synexvm_settings(db)


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


def _synexvm_token(db: Session) -> str:
    return _decrypt_setting(get_setting(db, SYNEXVM_API_TOKEN))


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


def _synexvm_connection(db: Session, resource: AzPanelResource) -> tuple[dict[str, Any], str, str]:
    """解析资源实际使用的 SynexVM 接口地址和 Token（资源覆盖 > 全局设置）。"""
    settings = synexvm_settings(db)
    api_url = (resource.api_url or "").strip() or settings["api_url"]
    token = _decrypt_setting(resource.api_token or "") or _synexvm_token(db)
    if not api_url:
        raise RuntimeError("SynexVM API 地址未配置")
    if not token:
        raise RuntimeError("SynexVM API Token 未配置（资源和全局设置都为空）")
    return settings, api_url, token


def _synexvm_request(api_url: str, action: str, service_id: str, token: str, timeout: int) -> dict[str, Any]:
    response = httpx.get(
        api_url,
        params={"action": action, "service_id": service_id, "token": token},
        timeout=timeout,
        follow_redirects=True,
    )
    # 不复用 _raise_for_status_with_body：它会把带 token 的完整 URL 写进错误
    # 信息，进而进入任务记录 / 事件 / webhook，造成泄漏。
    if not response.is_success:
        body = (response.text or "").strip()
        if len(body) > 500:
            body = body[:500] + "…"
        detail = f": {body}" if body else ""
        raise RuntimeError(f"SynexVM {action} (service {service_id}) 返回 HTTP {response.status_code}{detail}")
    try:
        payload = response.json()
    except Exception:
        body = (response.text or "").strip()
        if len(body) > 200:
            body = body[:200] + "…"
        raise RuntimeError(f"SynexVM {action} (service {service_id}) 返回的不是 JSON: {body or '空响应'}")
    if isinstance(payload, dict) and payload.get("success") is False:
        message = str(payload.get("message") or payload.get("error") or payload)
        if len(message) > 300:
            message = message[:300] + "…"
        raise RuntimeError(f"SynexVM {action} (service {service_id}) 调用失败: {message}")
    return payload if isinstance(payload, dict) else {}


def _synexvm_payload_ip(payload: dict[str, Any], ip_version: str = "ipv4") -> str | None:
    data = _extract_payload(payload)
    vm = data.get("vm")
    if isinstance(vm, dict):
        data = {**data, **vm}
    preferred = data.get(ip_version)
    if isinstance(preferred, str) and preferred.strip():
        return preferred.strip()
    return _extract_ip(data)


def call_synexvm_status(db: Session, resource: AzPanelResource) -> dict[str, Any]:
    settings, api_url, token = _synexvm_connection(db, resource)
    return _synexvm_request(api_url, "status", resource.resource_id, token, settings["timeout_seconds"])


def sync_synexvm_resource_status(db: Session, resource: AzPanelResource) -> dict[str, Any]:
    """查询 status 接口并把面板上的当前 IP 同步到资源和绑定源站。

    发现 IP 和本地记录不一致时会隔几秒再读一次，两次一致才采纳——
    换 IP 过程中 status 可能短暂返回过渡 IP，不能当成最终地址。
    """
    payload = call_synexvm_status(db, resource)
    panel_ip = _synexvm_payload_ip(payload, resource.ip_version)
    if panel_ip and panel_ip != resource.current_ip:
        time.sleep(SYNEXVM_MANUAL_CONFIRM_DELAY_SECONDS)
        second_payload = call_synexvm_status(db, resource)
        second_ip = _synexvm_payload_ip(second_payload, resource.ip_version)
        if second_ip != panel_ip:
            raise RuntimeError(
                f"面板返回的 IP 尚未稳定（{panel_ip} → {second_ip or '未知'}），换 IP 可能还在进行中，请稍后再试"
            )
        payload = second_payload
        target_info = parse_target(panel_ip)
        if target_info.target_type not in {"ipv4", "ipv6"}:
            raise RuntimeError(f"SynexVM status 返回的 IP 无法识别: {panel_ip}")
        resource.pending_candidate_ip = None
        resource.last_status_sync_at = datetime.utcnow()
        if resource.pending_change_at is not None:
            old_ip = resource.current_ip
            applied_ip, _ = _apply_changed_ip(db, resource, target_info.value, reason="synexvm status refresh confirmed")
            _finish_pending_job(db, resource, applied_ip, None)
            event_payload = {
                "resource_id": resource.id,
                "provider": resource.provider,
                "old_ip": old_ip,
                "new_ip": applied_ip,
                "origin_id": resource.origin_id,
                "trigger_type": "manual_status_refresh",
            }
            add_event(db, "azpanel.ip_changed", "info", f"{resource.name} changed IP to {applied_ip}", event_payload)
            send_webhooks(db, "azpanel.ip_changed", event_payload)
        else:
            resource.current_ip = target_info.value
            try:
                sync_resource_current_ip_to_origin(db, resource)
            except ValueError as exc:
                resource.last_error = f"远端 IP 无法同步到源站: {exc}"
            else:
                resource.last_error = None
        db.flush()
    return payload


def call_synexvm_change_ip(db: Session, resource: AzPanelResource, reason: str | None = None) -> dict[str, Any]:
    settings, api_url, token = _synexvm_connection(db, resource)
    if not settings["enabled"]:
        raise RuntimeError("SynexVM integration is disabled")

    old_ip = (resource.current_ip or "").strip()
    # 本地记录的 IP 可能过期，先问面板拿准确的旧 IP；查不到不阻塞换 IP
    try:
        status_payload = _synexvm_request(api_url, "status", resource.resource_id, token, settings["timeout_seconds"])
        panel_ip = _synexvm_payload_ip(status_payload, resource.ip_version)
        if panel_ip:
            old_ip = panel_ip
    except Exception:
        pass

    result = _synexvm_request(api_url, "change_ip", resource.resource_id, token, settings["timeout_seconds"])
    data = _extract_payload(result)
    # change_ip 的响应可能只是调度结果，里面的 IP 不一定是面板最终应用的 IP。
    # 只把它保留为提示；资源 current_ip 和成功记录一律以 status 回读为准，
    # 否则会出现资源卡片与最近换 IP 记录显示不同地址。
    reported_ip = _synexvm_payload_ip(result, resource.ip_version)
    data.pop("new_ip", None)
    if reported_ip and reported_ip != old_ip:
        data["reported_new_ip"] = reported_ip

    # 刚下发时 status 可能返回一个过渡 IP（看着变了、其实不是最终地址），
    # "立刻拿到的 IP"一律不信。统一返回 pending，由调度器双读确认后才落地：
    # 新 IP 必须在连续两个周期的 status 查询里保持一致。
    data["pending"] = True
    data["old_ip"] = old_ip or None
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


def _prune_stale_remote_resources(db: Session, provider: str | None, fresh_items: list[dict[str, Any]]) -> int:
    """Drop cached rows (scoped to ``provider``) that azpanel no longer reports.

    Without this the picker keeps accumulating every resource ever seen, so
    machines deleted on the azpanel side stay in the dropdown forever.
    """
    keep = {_remote_resource_identity(item) for item in fresh_items}
    query = db.query(AzPanelRemoteResource)
    if provider:
        query = query.filter(AzPanelRemoteResource.provider == provider)
    removed = 0
    for row in query.all():
        identity = (row.provider, row.account_id or "", row.region or "", row.resource_id, row.ip_version)
        if identity not in keep:
            db.delete(row)
            removed += 1
    if removed:
        db.flush()
    return removed


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
    # 空列表是有效结果（azpanel 侧已全部删除），不能用 or 链跳过，
    # 否则会错误地回退到过时的本地缓存。
    raw_items: Any = None
    for key in ("resources", "items", "data"):
        value = data.get(key)
        if isinstance(value, list):
            raw_items = value
            break
        if isinstance(value, dict):
            raw_items = list(value.values())
            break
    if raw_items is None and isinstance(payload, list):
        raw_items = payload
    if not isinstance(raw_items, list):
        # 只有响应结构无法识别时才回退到缓存
        return cached_items
    normalized = [_normalize_remote_resource(item) for item in raw_items if isinstance(item, dict)]
    remote_items = _cache_remote_resources(db, [item for item in normalized if item is not None])
    _sync_local_resources_from_remote_items(db, remote_items)
    # The cache mirrors azpanel: on a successful fetch it is rewritten to exactly
    # the fresh listing and only serves as a fallback when azpanel is unreachable.
    # Merging old cached rows back in here would resurrect deleted machines.
    _prune_stale_remote_resources(db, provider if provider in {"azure", "aws"} else None, remote_items)
    return sorted(
        remote_items,
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


def _sync_resource_xboard_nodes(db: Session, resource: AzPanelResource, new_ip: str, reason: str | None) -> list[dict[str, Any]]:
    """把新 IP 推给资源绑定的 Xboard 节点，返回成功更新的结果列表。"""
    xboard_config = xboard_settings(db)
    results: list[dict[str, Any]] = []
    for node in list(resource.xboard_nodes):
        if not node.enabled or not node.auto_update_after_change:
            continue
        node.host = new_ip
        node.last_sync_at = datetime.utcnow()
        if not xboard_config["enabled"]:
            node.last_error = None
            continue
        try:
            xboard_result = call_xboard_update_node_ip(db, node, new_ip, reason=reason)
            node.last_error = None
            results.append({"node_id": node.xboard_node_id, "result": xboard_result})
        except Exception as exc:
            node.last_error = str(exc)
            add_event(
                db,
                "xboard.node_update_failed",
                "warning",
                f"Xboard node {node.xboard_node_id} update failed: {exc}",
                {"node_binding_id": node.id, "node_id": node.xboard_node_id, "error": str(exc)},
            )
    return results


def _apply_changed_ip(db: Session, resource: AzPanelResource, new_ip: str, reason: str | None) -> tuple[str, list[dict[str, Any]]]:
    """新 IP 确认后统一落地：更新资源、同步源站、推 Xboard、催外部来源重新同步。"""
    target_info = parse_target(new_ip)
    resource.current_ip = target_info.value
    resource.last_change_at = datetime.utcnow()
    resource.last_error = None
    resource.pending_change_at = None
    sync_resource_current_ip_to_origin(db, resource)
    xboard_results = _sync_resource_xboard_nodes(db, resource, target_info.value, reason)
    # 机器换了 IP，外部 IP 来源（如 nyanpass）要尽快重新同步，
    # 绑定了这台机器的备用目标才能跟上新 IP
    mark_external_ip_sources_due(db)
    return target_info.value, xboard_results


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
        if resource.provider == "synexvm":
            result = call_synexvm_change_ip(db, resource, reason=reason)
        else:
            result = call_azpanel_change_ip(db, resource, reason=reason)

        if result.get("pending") and not result.get("new_ip"):
            # 换 IP 已下发但新 IP 还没确认（SynexVM 生效慢）。不判失败：标记 pending，
            # 由调度器后台查 status 补新 IP；同时催外部来源重新同步，绑定了这台机器的
            # 备用目标会通过 nyanpass 的新 IP 恢复。
            resource.pending_change_at = datetime.utcnow()
            resource.pending_candidate_ip = None
            resource.last_error = None
            job.status = "pending"
            job.error = None
            job.response_json = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
            job.finished_at = datetime.utcnow()
            mark_external_ip_sources_due(db)
            payload = {
                "resource_id": resource.id,
                "provider": resource.provider,
                "old_ip": job.old_ip,
                "origin_id": resource.origin_id,
                "trigger_type": trigger_type,
            }
            add_event(
                db,
                "azpanel.ip_change_pending",
                "info",
                f"{resource.name} 已下发换 IP，等待新 IP 生效（后台查询状态中）",
                payload,
            )
            db.flush()
            return job

        new_ip, xboard_results = _apply_changed_ip(db, resource, str(result["new_ip"]).strip(), reason)
        job.new_ip = new_ip
        merged = dict(result)
        if xboard_results:
            merged["xboard"] = xboard_results
        job.response_json = json.dumps(merged, ensure_ascii=False, separators=(",", ":"))

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


def _finish_pending_job(db: Session, resource: AzPanelResource, new_ip: str | None, error: str | None) -> None:
    """把该资源最近一条 pending 换 IP 任务收尾成成功或失败。"""
    job = (
        db.query(IpChangeJob)
        .filter(IpChangeJob.azpanel_resource_id == resource.id, IpChangeJob.status == "pending")
        .order_by(IpChangeJob.id.desc())
        .first()
    )
    if job is None:
        return
    job.finished_at = datetime.utcnow()
    if new_ip:
        job.status = "success"
        job.new_ip = new_ip
        job.error = None
    else:
        job.status = "failed"
        job.error = error


def reconcile_pending_synexvm_changes(db: Session) -> int:
    """调度器每个周期调用：对 pending 的 SynexVM 资源查 status 补新 IP。

    change_ip 下发后新 IP 往往几分钟才在 status 生效，所以下发时只标记 pending，
    这里非阻塞地轮询 status，拿到新 IP 就落地（更新资源/源站/Xboard/外部来源），
    超过 wait_seconds 预算仍没结果就放弃并记失败。
    """
    resources = (
        db.query(AzPanelResource)
        .filter(AzPanelResource.provider == "synexvm", AzPanelResource.pending_change_at.isnot(None))
        .all()
    )
    if not resources:
        return 0
    settings = synexvm_settings(db)
    budget = max(settings["wait_seconds"], 60)
    now = datetime.utcnow()
    resolved = 0
    for resource in resources:
        try:
            payload = call_synexvm_status(db, resource)
        except Exception:
            payload = None
        new_ip = _synexvm_payload_ip(payload, resource.ip_version) if payload else None
        if new_ip and new_ip != (resource.current_ip or "") and new_ip == resource.pending_candidate_ip:
            # 连续两个周期读到同一个新 IP，确认稳定，才真正落地。
            # 换 IP 刚下发时 status 可能短暂返回过渡 IP，只见过一次的地址不能信。
            resource.pending_candidate_ip = None
            old_ip = resource.current_ip
            applied_ip, xboard_results = _apply_changed_ip(db, resource, new_ip, reason="synexvm pending change confirmed")
            _finish_pending_job(db, resource, applied_ip, None)
            payload_evt = {
                "resource_id": resource.id,
                "provider": resource.provider,
                "old_ip": old_ip,
                "new_ip": applied_ip,
                "origin_id": resource.origin_id,
                "trigger_type": "auto_reconcile",
            }
            add_event(db, "azpanel.ip_changed", "info", f"{resource.name} changed IP to {applied_ip}", payload_evt)
            send_webhooks(db, "azpanel.ip_changed", payload_evt)
            resolved += 1
        elif new_ip and new_ip != (resource.current_ip or ""):
            # 第一次见到这个新 IP：先记为候选，下个周期再读一次一致才采纳
            resource.pending_candidate_ip = new_ip
        elif resource.pending_change_at and (now - resource.pending_change_at).total_seconds() > budget:
            resource.pending_change_at = None
            resource.pending_candidate_ip = None
            message = f"换 IP 已下发但 {int(budget)} 秒内 status 未返回新 IP，请在 SynexVM 面板确认"
            resource.last_error = message
            _finish_pending_job(db, resource, None, message)
            payload_evt = {
                "resource_id": resource.id,
                "provider": resource.provider,
                "old_ip": resource.current_ip,
                "origin_id": resource.origin_id,
                "trigger_type": "auto_reconcile",
                "error": message,
            }
            add_event(db, "azpanel.ip_change_failed", "warning", f"{resource.name} IP change unconfirmed: {message}", payload_evt)
        elif new_ip:
            # 面板又报回旧 IP：之前的候选是过渡值，作废重来
            resource.pending_candidate_ip = None
    db.flush()
    return resolved


def auto_sync_synexvm_statuses(db: Session) -> int:
    """按资源配置的间隔自动查 status 同步最新 IP（"查询状态"按钮的自动版，兜底）。

    pending 中的资源由 reconcile 负责（跳过避免重复请求）。发现的新 IP 同样要
    连续两次读取一致（pending_candidate_ip）才落地，防止把过渡 IP 当真。
    实际频率受调度检查周期限制：间隔设得比检查周期小也只会每个周期查一次。
    """
    resources = (
        db.query(AzPanelResource)
        .filter(
            AzPanelResource.provider == "synexvm",
            AzPanelResource.enabled.is_(True),
            AzPanelResource.status_sync_interval_seconds > 0,
            AzPanelResource.pending_change_at.is_(None),
        )
        .all()
    )
    if not resources:
        return 0
    now = datetime.utcnow()
    synced = 0
    for resource in resources:
        interval = max(resource.status_sync_interval_seconds, 10)
        if resource.last_status_sync_at and (now - resource.last_status_sync_at).total_seconds() < interval:
            continue
        resource.last_status_sync_at = now
        try:
            payload = call_synexvm_status(db, resource)
        except Exception:
            continue  # 面板暂时不可达不算失败，下个到期周期再试
        panel_ip = _synexvm_payload_ip(payload, resource.ip_version)
        if not panel_ip:
            continue
        if panel_ip == (resource.current_ip or ""):
            resource.pending_candidate_ip = None
            continue
        if panel_ip != resource.pending_candidate_ip:
            # 第一次见到的新 IP 先记候选，下次读取一致才采纳
            resource.pending_candidate_ip = panel_ip
            continue
        resource.pending_candidate_ip = None
        old_ip = resource.current_ip
        try:
            applied_ip, _ = _apply_changed_ip(db, resource, panel_ip, reason="synexvm auto status sync")
        except ValueError as exc:
            resource.last_error = f"自动查询到的 IP 无法应用: {exc}"
            continue
        payload_evt = {
            "resource_id": resource.id,
            "provider": resource.provider,
            "old_ip": old_ip,
            "new_ip": applied_ip,
            "origin_id": resource.origin_id,
            "trigger_type": "auto_status_sync",
        }
        add_event(db, "azpanel.ip_changed", "info", f"{resource.name} 自动查询发现 IP 变为 {applied_ip}，已同步", payload_evt)
        send_webhooks(db, "azpanel.ip_changed", payload_evt)
        synced += 1
    db.flush()
    return synced


def trigger_ip_change_for_origin(db: Session, origin: Origin, reason: str) -> IpChangeJob | None:
    azpanel_enabled = azpanel_settings(db)["enabled"]
    synexvm_enabled = synexvm_settings(db)["enabled"]
    if not azpanel_enabled and not synexvm_enabled:
        return None

    def provider_enabled(resource: AzPanelResource) -> bool:
        return synexvm_enabled if resource.provider == "synexvm" else azpanel_enabled

    resources = (
        db.query(AzPanelResource)
        .filter(AzPanelResource.enabled.is_(True), AzPanelResource.auto_change_on_blocked.is_(True))
        .filter(AzPanelResource.origin_id == origin.id)
        .order_by(AzPanelResource.id.asc())
        .all()
    )
    resources = [resource for resource in resources if provider_enabled(resource)]
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
        candidates = (
            db.query(AzPanelResource)
            .filter(AzPanelResource.enabled.is_(True), AzPanelResource.auto_change_on_blocked.is_(True))
            .filter(AzPanelResource.current_ip == origin.target)
            .order_by(AzPanelResource.id.asc())
            .all()
        )
        candidates = [resource for resource in candidates if provider_enabled(resource)]
        # 优先端口也一致的资源；没有再退到只按 IP 匹配——源站可能是外部 IP
        # 的入口端口（例如 nyanpass 转发端口），和云资源的检查端口本来就不同，
        # 而公网 IP 已经足够定位到同一台机器。
        resources = [resource for resource in candidates if resource.port == origin.port] or candidates
    if not resources:
        return None
    return change_resource_ip(db, resources[0], trigger_type="auto_blocked", reason=reason)
