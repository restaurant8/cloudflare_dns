import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy.orm import Session

from .dns_utils import parse_target
from .events import add_event
from .external_ips import mark_external_ip_sources_due
from .models import AppSetting, AzPanelRemoteResource, AzPanelResource, FailoverGlobalOrigin, IpChangeJob, Origin, XboardNodeBinding
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

# 通用换 IP 接口：每台机器填两个完整链接（换 IP、查 IP），口令写在链接里，
# 加密保存。适用于任何"请求一个链接就换 IP / 返回当前 IP"的服务商。
CUSTOM_IP_PROVIDER = "custom"
CUSTOM_IP_ENABLED = "custom_ip.enabled"
CUSTOM_IP_TIMEOUT = "custom_ip.timeout_seconds"
CUSTOM_IP_WAIT = "custom_ip.wait_seconds"
CUSTOM_IP_DEFAULT_COOLDOWN = "custom_ip.default_cooldown_seconds"
CUSTOM_IP_USER_AGENT = "custom_ip.user_agent"
# 有的服务商只接受终端发出的请求（浏览器或 python-httpx 会收到"请在终端执行"，
# 且 HTTP 状态仍是 200），所以默认以 curl 的身份请求，面板上可改。
CUSTOM_IP_DEFAULT_USER_AGENT = "curl/8.7.1"
CUSTOM_IP_DEFAULT_WAIT_SECONDS = 600
# 新 IP 必须连续两次读取一致才采纳（防止换 IP 过程中的过渡 IP）。
# 手动查询 / 换 IP 前的核对在同一次请求里读两次，这是两次之间的间隔。
CUSTOM_IP_CONFIRM_DELAY_SECONDS = 3
# 换 IP 超过等待时长仍未查到新 IP 时记为失败，但之后这么久内继续每轮查询，
# 机器晚些拿到新 IP 也能自动同步上（以前就是这里放弃得太早，经常拿不到新 IP）。
CUSTOM_IP_LATE_WATCH_SECONDS = 6 * 60 * 60
CUSTOM_IP_LATE_WATCH_INTERVAL_SECONDS = 60

IP_RE = re.compile(r"(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,})")


@dataclass
class AutoIpChangeGuard:
    """Bound automatic IP changes to one distinct resource per evaluation pass.

    A probe or routing incident can mark many origins blocked at once. Without a
    shared guard, the scheduler would rotate every matching cloud account in the
    same pass. Repeated origins for the same resource are also ignored after its
    first attempt; the resource cooldown remains the longer-term safeguard.
    """

    max_distinct_resources: int = 1
    attempted_resource_ids: set[int] = field(default_factory=set)
    reported_warning_keys: set[str] = field(default_factory=set)


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


def custom_ip_settings(db: Session) -> dict[str, Any]:
    return {
        "enabled": _bool_setting(db, CUSTOM_IP_ENABLED),
        "timeout_seconds": _int_setting(db, CUSTOM_IP_TIMEOUT, 30),
        "wait_seconds": _int_setting(db, CUSTOM_IP_WAIT, CUSTOM_IP_DEFAULT_WAIT_SECONDS),
        "default_cooldown_seconds": _int_setting(db, CUSTOM_IP_DEFAULT_COOLDOWN, 1800),
        "user_agent": get_setting(db, CUSTOM_IP_USER_AGENT, "") or CUSTOM_IP_DEFAULT_USER_AGENT,
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


def update_custom_ip_settings(db: Session, updates: dict[str, Any]) -> dict[str, Any]:
    if "enabled" in updates and updates["enabled"] is not None:
        set_setting(db, CUSTOM_IP_ENABLED, "1" if updates["enabled"] else "0")
    if "timeout_seconds" in updates and updates["timeout_seconds"] is not None:
        set_setting(db, CUSTOM_IP_TIMEOUT, str(int(updates["timeout_seconds"])))
    if "wait_seconds" in updates and updates["wait_seconds"] is not None:
        set_setting(db, CUSTOM_IP_WAIT, str(int(updates["wait_seconds"])))
    if "default_cooldown_seconds" in updates and updates["default_cooldown_seconds"] is not None:
        set_setting(db, CUSTOM_IP_DEFAULT_COOLDOWN, str(int(updates["default_cooldown_seconds"])))
    if "user_agent" in updates and updates["user_agent"] is not None:
        # 清空表示恢复默认（curl）
        set_setting(db, CUSTOM_IP_USER_AGENT, str(updates["user_agent"]).strip())
    return custom_ip_settings(db)


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


def custom_url_hint(encrypted_url: str | None) -> str | None:
    """Show where a stored link points without revealing its query (the tokens)."""
    url = _decrypt_setting(encrypted_url or "")
    if not url:
        return None
    parts = urlsplit(url)
    suffix = "?••••••" if parts.query else ""
    return f"{parts.scheme}://{parts.netloc}{parts.path}{suffix}"


def _custom_url(resource: AzPanelResource, kind: str) -> str:
    encrypted = resource.change_ip_url if kind == "change" else resource.status_url
    url = _decrypt_setting(encrypted or "")
    if not url:
        label = "换 IP 链接" if kind == "change" else "查 IP 链接"
        raise RuntimeError(f"{resource.name} 未填写{label}")
    return url


def _custom_request(db: Session, resource: AzPanelResource, kind: str) -> str:
    """GET one of the resource's links and return the response body.

    Errors never include the link itself: the query string carries the tokens and
    error text ends up in job records, events and notifications.
    """
    url = _custom_url(resource, kind)
    label = "换 IP 接口" if kind == "change" else "查 IP 接口"
    host = urlsplit(url).netloc
    settings = custom_ip_settings(db)
    headers = {"User-Agent": settings["user_agent"], "Accept": "*/*"}
    try:
        response = httpx.get(
            url,
            headers=headers,
            timeout=settings["timeout_seconds"],
            follow_redirects=True,
            verify=bool(resource.verify_tls),
        )
    except httpx.HTTPError as exc:
        raise RuntimeError(f"{label}（{host}）请求失败：{type(exc).__name__}") from None
    if not response.is_success:
        body = _readable_body(response.text)
        detail = f"：{body}" if body else ""
        raise RuntimeError(f"{label}（{host}）返回 HTTP {response.status_code}{detail}")
    return response.text or ""


def _readable_body(text: str | None, limit: int = 200) -> str:
    """Response text for an error message; an HTML page is reduced to its words."""
    body = (text or "").strip()
    if body.startswith("<"):
        body = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", body, flags=re.S | re.I)
        body = re.sub(r"<[^>]+>", " ", body)
    body = re.sub(r"\s+", " ", body).strip()
    return body[:limit] + "…" if len(body) > limit else body


def _ips_in_text(text: str) -> list[str]:
    found: list[str] = []
    for match in IP_RE.findall(text or ""):
        try:
            info = parse_target(match)
        except ValueError:
            continue
        if info.target_type in {"ipv4", "ipv6"} and info.value not in found:
            found.append(info.value)
    return found


def parse_custom_ip(body: str, ip_version: str = "ipv4") -> str | None:
    """Read the machine's IP from a response: plain text (just the IP) or JSON.

    Returns None when no IP, or more than one candidate of the wanted family, is
    found — guessing between "old" and "new" in a message would publish the wrong one.
    """
    text = (body or "").strip()
    data: Any = None
    if text[:1] in {"{", "["}:
        try:
            data = json.loads(text)
        except ValueError:
            data = None
    if isinstance(data, dict):
        if data.get("success") is False or data.get("status") in {"error", "fail", "failed"}:
            message = str(data.get("message") or data.get("msg") or data.get("error") or text)[:300]
            raise RuntimeError(f"接口返回失败：{message}")
        payload = _extract_payload(data)
        vm = payload.get("vm")
        if isinstance(vm, dict):
            payload = {**payload, **vm}
        preferred = payload.get(ip_version)
        if isinstance(preferred, str) and preferred.strip():
            return parse_target(preferred.strip()).value
        found = _extract_ip(payload)
        return parse_target(found).value if found else None
    family = 6 if ip_version == "ipv6" else 4
    candidates = [ip for ip in _ips_in_text(text) if (":" in ip) == (family == 6)]
    return candidates[0] if len(candidates) == 1 else None


def read_custom_ip(db: Session, resource: AzPanelResource) -> str:
    body = _custom_request(db, resource, "status")
    ip = parse_custom_ip(body, resource.ip_version)
    if not ip:
        snippet = _readable_body(body) or "空响应"
        raise RuntimeError(f"查 IP 接口没有返回可识别的{'IPv6' if resource.ip_version == 'ipv6' else 'IPv4'} 地址：{snippet}")
    return ip


def read_stable_custom_ip(db: Session, resource: AzPanelResource) -> str:
    """Read twice a few seconds apart; a changed IP must read the same both times."""
    first = read_custom_ip(db, resource)
    if first == (resource.current_ip or ""):
        return first
    time.sleep(CUSTOM_IP_CONFIRM_DELAY_SECONDS)
    second = read_custom_ip(db, resource)
    if second != first:
        raise RuntimeError(f"查到的 IP 还不稳定（{first} → {second}），可能正在换 IP，请稍后再试")
    return second


def _adopt_custom_ip(db: Session, resource: AzPanelResource, new_ip: str, *, trigger_type: str, reason: str) -> str:
    old_ip = resource.current_ip
    applied_ip, _ = _apply_changed_ip(db, resource, new_ip, reason=reason)
    resource.pending_candidate_ip = None
    payload = ip_change_event_payload(db, resource, old_ip=old_ip, new_ip=applied_ip, trigger_type=trigger_type)
    add_event(db, "azpanel.ip_changed", "info", f"{resource.name} 的 IP 已更新为 {applied_ip}", payload)
    send_webhooks(db, "azpanel.ip_changed", payload)
    return applied_ip


def sync_custom_resource_status(db: Session, resource: AzPanelResource) -> str:
    """「查询状态」：读取机器当前 IP，变了就同步到资源和绑定源站。"""
    ip = read_stable_custom_ip(db, resource)
    resource.last_status_sync_at = datetime.utcnow()
    resource.pending_candidate_ip = None
    if ip != (resource.current_ip or ""):
        was_pending = resource.pending_change_at is not None
        try:
            applied = _adopt_custom_ip(db, resource, ip, trigger_type="manual_status_refresh", reason="manual status refresh")
        except ValueError as exc:
            resource.last_error = f"查到的 IP 无法同步到源站: {exc}"
        else:
            if was_pending:
                _finish_pending_job(db, resource, applied, None)
            else:
                _finish_late_job(db, resource, applied)
    else:
        resource.last_error = None
    db.flush()
    return ip


def call_custom_change_ip(
    db: Session,
    resource: AzPanelResource,
    reason: str | None = None,
    *,
    adopt_if_changed: bool = False,
) -> dict[str, Any]:
    if not custom_ip_settings(db)["enabled"]:
        raise RuntimeError("通用换 IP 接口未启用")
    old_ip = (resource.current_ip or "").strip()
    # 先查一次：本地记录可能过期，拿到机器真实的旧 IP。自动触发时如果机器的 IP
    # 早就变了（例如上次换 IP 晚到），直接采用，不再重复换。
    try:
        panel_ip = read_stable_custom_ip(db, resource)
    except Exception:
        panel_ip = None
    if panel_ip and panel_ip != old_ip:
        if adopt_if_changed:
            return {"new_ip": panel_ip, "old_ip": old_ip or None, "adopted_without_change": True}
        old_ip = panel_ip
    body = _custom_request(db, resource, "change")
    # 换 IP 接口返回的内容各家不同，里面的 IP 也不一定是最终地址，只作记录；
    # 新 IP 一律以查 IP 接口连续两次一致为准。
    data: dict[str, Any] = {"pending": True, "old_ip": old_ip or None, "response": _readable_body(body, 300)}
    try:
        hinted = parse_custom_ip(body, resource.ip_version)
    except RuntimeError as exc:
        raise RuntimeError(f"换 IP {exc}") from None
    if hinted and hinted != old_ip:
        data["reported_new_ip"] = hinted
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


def resource_bound_global_origins(db: Session, resource: AzPanelResource) -> list[FailoverGlobalOrigin]:
    return (
        db.query(FailoverGlobalOrigin)
        .filter(FailoverGlobalOrigin.azpanel_resource_id == resource.id)
        .order_by(FailoverGlobalOrigin.id.asc())
        .all()
    )


def resource_bound_origins(db: Session, resource: AzPanelResource) -> list[Origin]:
    """Every failover backup whose address this resource drives.

    Both the directly bound origins and the mirrors of any global backup bound to
    this resource — binding one machine to a collection's global backup is what
    lets a single machine back every domain in it.
    """
    direct = (
        db.query(Origin)
        .filter(Origin.azpanel_resource_id == resource.id)
        .order_by(Origin.id.asc())
        .all()
    )
    global_ids = [global_origin.id for global_origin in resource_bound_global_origins(db, resource)]
    mirrored = (
        db.query(Origin).filter(Origin.global_origin_id.in_(global_ids)).order_by(Origin.id.asc()).all()
        if global_ids
        else []
    )
    seen: dict[int, Origin] = {}
    for origin in [*direct, *mirrored]:
        seen.setdefault(origin.id, origin)
    return list(seen.values())


def refresh_legacy_origin_mirror(db: Session, resource: AzPanelResource) -> None:
    """Keep AzPanelResource.origin_id as a read-only mirror of the primary binding.

    Nothing in the logic reads it any more — the binding lives on the origin — but
    the column and the API field stay so an un-upgraded frontend keeps rendering
    something true, and so a rollback still finds a usable value. It is derived,
    never authoritative: writing to it is what used to unbind other backups.
    """
    db.flush()
    bound_ids = [origin.id for origin in resource_bound_origins(db, resource)]
    resource.origin_id = min(bound_ids) if bound_ids else None


def _origin_notification_summary(origin: Origin) -> dict[str, Any]:
    group = origin.group
    return {
        "origin_id": origin.id,
        "hostname": getattr(group, "hostname", None),
        "remark": origin.remark,
        "target": origin.target,
        "port": origin.port,
    }


def ip_change_event_payload(
    db: Session,
    resource: AzPanelResource,
    *,
    old_ip: str | None = None,
    new_ip: str | None = None,
    trigger_type: str | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """Payload for the azpanel.* IP events.

    It carries the resource *name* and the affected backups (hostname + remark +
    address), not just row ids: the Telegram message is often the only place a
    change is seen, and "origin_id: 47" does not tell anyone which backup moved.
    """
    payload: dict[str, Any] = {
        "resource_id": resource.id,
        "resource_name": resource.name,
        "provider": resource.provider,
        "old_ip": old_ip,
        "new_ip": new_ip,
        "origin_id": resource.origin_id,
        "trigger_type": trigger_type,
        "targets": [_origin_notification_summary(origin) for origin in resource_bound_origins(db, resource)],
    }
    if error is not None:
        payload["error"] = error
    return payload


def _resource_on_cooldown(resource: AzPanelResource, now: datetime) -> bool:
    last_attempt_at = getattr(resource, "last_attempt_at", None) or resource.last_change_at
    if last_attempt_at is None:
        return False
    return (now - last_attempt_at).total_seconds() < max(resource.cooldown_seconds, 60)


def _apply_resource_ip_to_origin(origin: Origin, target_info, port: int) -> bool:
    changed = origin.target != target_info.value or origin.target_type != target_info.target_type or origin.port != port
    if not changed:
        return False
    origin.target = target_info.value
    origin.target_type = target_info.target_type
    origin.port = port
    origin.status = "unknown"
    origin.last_error = "资源 IP 已同步，等待本地和探针探测结果"
    origin.last_checked_at = None
    origin.last_rtt_ms = None
    origin.probe_states.clear()
    # The DNS record still contains the old address. Keeping this origin marked as
    # current lets the scheduler's steady-state consistency throttle skip the write
    # for up to five minutes. Once the endpoint changes there is no longer a current
    # origin that accurately describes published DNS, so force normal selection and
    # publication on the next evaluation.
    group = origin.group
    if group.current_origin_id == origin.id:
        group.current_origin_id = None
        group.last_switch_at = None
    return True


def sync_resource_current_ip_to_origin(db: Session, resource: AzPanelResource) -> bool:
    """Push this resource's current IP to every backup it drives.

    This used to resolve exactly one Origin from ``resource.origin_id``, so a machine
    backing several domains left all but one of them on the dead IP.
    """
    if not resource.auto_update_origin or not resource.current_ip:
        return False
    target_info = parse_target(resource.current_ip)
    changed_any = False

    # Global backups first: writing the global row and then its mirrors keeps the two
    # in step, the same ordering external_ips.py uses.
    for global_origin in resource_bound_global_origins(db, resource):
        if global_origin.external_machine_key:
            # An external IP source already observes this machine and owns the target;
            # _apply_changed_ip marks that source due so it re-reads right away.
            continue
        if global_origin.target != target_info.value or global_origin.target_type != target_info.target_type or global_origin.port != resource.port:
            global_origin.target = target_info.value
            global_origin.target_type = target_info.target_type
            global_origin.port = resource.port
            changed_any = True

    for origin in resource_bound_origins(db, resource):
        if origin.external_machine_key:
            continue
        if _apply_resource_ip_to_origin(origin, target_info, resource.port):
            changed_any = True
    return changed_any


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
        if resource.provider == CUSTOM_IP_PROVIDER:
            result = call_custom_change_ip(db, resource, reason=reason, adopt_if_changed=trigger_type != "manual")
        else:
            result = call_azpanel_change_ip(db, resource, reason=reason)

        if result.get("pending") and not result.get("new_ip"):
            # 换 IP 已下发但新 IP 还没确认（服务商生效慢）。不判失败：标记 pending，
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
            payload = ip_change_event_payload(db, resource, old_ip=job.old_ip, trigger_type=trigger_type)
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
        payload = ip_change_event_payload(db, resource, old_ip=job.old_ip, new_ip=job.new_ip, trigger_type=trigger_type)
        add_event(db, "azpanel.ip_changed", "info", f"{resource.name} changed IP to {job.new_ip}", payload)
        send_webhooks(db, "azpanel.ip_changed", payload)
    except Exception as exc:
        message = str(exc)
        resource.last_error = message
        job.status = "failed"
        job.error = message
        job.finished_at = datetime.utcnow()
        payload = ip_change_event_payload(db, resource, old_ip=job.old_ip, trigger_type=trigger_type, error=message)
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


def _pending_job(db: Session, resource: AzPanelResource) -> IpChangeJob | None:
    return (
        db.query(IpChangeJob)
        .filter(IpChangeJob.azpanel_resource_id == resource.id, IpChangeJob.status == "pending")
        .order_by(IpChangeJob.id.desc())
        .first()
    )


def _known_old_ips(db: Session, resource: AzPanelResource) -> set[str]:
    """IPs that mean "not changed yet": the stored one and the one read before the change.

    Comparing only against the stored IP was a bug: when it was stale, the machine's
    real old IP looked "new", got confirmed at once, and the actual new IP was missed.
    """
    known = {resource.current_ip or ""}
    job = _pending_job(db, resource)
    if job is not None:
        known.add(job.old_ip or "")
        try:
            response = json.loads(job.response_json or "{}")
        except ValueError:
            response = {}
        if isinstance(response, dict):
            known.add(str(response.get("old_ip") or ""))
    known.discard("")
    return known


def _finish_late_job(db: Session, resource: AzPanelResource, new_ip: str) -> None:
    """A change that timed out did happen after all: mark its job as succeeded."""
    job = (
        db.query(IpChangeJob)
        .filter(IpChangeJob.azpanel_resource_id == resource.id, IpChangeJob.status == "failed")
        .order_by(IpChangeJob.id.desc())
        .first()
    )
    if job is None or job.new_ip or not resource.last_attempt_at or job.started_at < resource.last_attempt_at:
        return
    job.status = "success"
    job.new_ip = new_ip
    job.error = "超过等待时长后才查到新 IP，已自动同步"


def reconcile_pending_custom_changes(db: Session) -> int:
    """调度器每个周期调用：对已下发换 IP 的资源查 IP，连续两次一致才落地新 IP。"""
    resources = (
        db.query(AzPanelResource)
        .filter(AzPanelResource.provider == CUSTOM_IP_PROVIDER, AzPanelResource.pending_change_at.isnot(None))
        .all()
    )
    if not resources:
        return 0
    budget = max(custom_ip_settings(db)["wait_seconds"], 60)
    now = datetime.utcnow()
    resolved = 0
    for resource in resources:
        try:
            new_ip = read_custom_ip(db, resource)
        except Exception as exc:
            new_ip = None
            resource.last_error = f"换 IP 后查询中：{exc}"
        old_ips = _known_old_ips(db, resource)
        if new_ip and new_ip not in old_ips and new_ip == resource.pending_candidate_ip:
            try:
                applied = _adopt_custom_ip(db, resource, new_ip, trigger_type="auto_reconcile", reason="pending change confirmed")
            except ValueError as exc:
                resource.last_error = f"新 IP 无法同步到源站: {exc}"
                continue
            _finish_pending_job(db, resource, applied, None)
            resolved += 1
        elif new_ip and new_ip not in old_ips:
            # 第一次见到这个新 IP：先记为候选，下个周期再读一次一致才采纳
            resource.pending_candidate_ip = new_ip
        elif (now - resource.pending_change_at).total_seconds() > budget:
            resource.pending_change_at = None
            resource.pending_candidate_ip = None
            job = _pending_job(db, resource)
            hint = ""
            if job is not None:
                try:
                    response = json.loads(job.response_json or "{}")
                except ValueError:
                    response = {}
                if isinstance(response, dict) and response.get("response"):
                    hint = f"；换 IP 接口当时返回：{response['response']}"
            message = (
                f"换 IP 已下发，但 {int(budget)} 秒内没查到新 IP{hint}。"
                f"之后 {CUSTOM_IP_LATE_WATCH_SECONDS // 3600} 小时内仍会每分钟查询，查到会自动同步"
            )
            resource.last_error = message
            _finish_pending_job(db, resource, None, message)
            payload = ip_change_event_payload(db, resource, old_ip=resource.current_ip, trigger_type="auto_reconcile", error=message)
            add_event(db, "azpanel.ip_change_failed", "warning", f"{resource.name} 换 IP 未确认：{message}", payload)
            send_webhooks(db, "azpanel.ip_change_failed", payload)
        else:
            # 还是旧 IP（或这次没读到）：之前的候选可能是过渡值，作废重来
            if new_ip:
                resource.pending_candidate_ip = None
    db.flush()
    return resolved


def _awaiting_late_ip(resource: AzPanelResource, now: datetime) -> bool:
    attempted = resource.last_attempt_at
    if attempted is None or resource.pending_change_at is not None:
        return False
    if resource.last_change_at is not None and resource.last_change_at >= attempted:
        return False
    return (now - attempted).total_seconds() < CUSTOM_IP_LATE_WATCH_SECONDS


def auto_sync_custom_statuses(db: Session) -> int:
    """定时查 IP（资源设置的间隔），以及换 IP 超时后的"迟到新 IP"补查。

    发现的新 IP 同样要连续两次读取一致（pending_candidate_ip）才落地。
    实际频率受调度检查周期限制。
    """
    resources = (
        db.query(AzPanelResource)
        .filter(
            AzPanelResource.provider == CUSTOM_IP_PROVIDER,
            AzPanelResource.enabled.is_(True),
            AzPanelResource.pending_change_at.is_(None),
        )
        .all()
    )
    now = datetime.utcnow()
    synced = 0
    for resource in resources:
        late = _awaiting_late_ip(resource, now)
        interval = resource.status_sync_interval_seconds or 0
        if late:
            interval = min(interval, CUSTOM_IP_LATE_WATCH_INTERVAL_SECONDS) if interval > 0 else CUSTOM_IP_LATE_WATCH_INTERVAL_SECONDS
        if interval <= 0:
            continue
        if resource.last_status_sync_at and (now - resource.last_status_sync_at).total_seconds() < max(interval, 10):
            continue
        resource.last_status_sync_at = now
        try:
            ip = read_custom_ip(db, resource)
        except Exception:
            continue  # 接口暂时不可达不算失败，下个到期周期再试
        if ip == (resource.current_ip or ""):
            resource.pending_candidate_ip = None
            continue
        if ip != resource.pending_candidate_ip:
            resource.pending_candidate_ip = ip
            continue
        try:
            applied = _adopt_custom_ip(db, resource, ip, trigger_type="auto_status_sync", reason="auto status sync")
        except ValueError as exc:
            resource.last_error = f"查到的 IP 无法同步到源站: {exc}"
            continue
        if late:
            _finish_late_job(db, resource, applied)
        synced += 1
    db.flush()
    return synced


def _report_auto_ip_change_warning(
    db: Session,
    origin: Origin,
    *,
    event_type: str,
    message: str,
    error: str,
    trigger_type: str,
    guard: AutoIpChangeGuard | None,
    warning_key: str,
    resource: AzPanelResource | None = None,
) -> None:
    if guard is not None:
        if warning_key in guard.reported_warning_keys:
            return
        guard.reported_warning_keys.add(warning_key)
    payload = (
        ip_change_event_payload(db, resource, old_ip=origin.target, trigger_type=trigger_type, error=error)
        if resource is not None
        else {
            "resource_id": None,
            "resource_name": "多个同 IP 云资源",
            "old_ip": origin.target,
            "new_ip": None,
            "trigger_type": trigger_type,
            "targets": [_origin_notification_summary(origin)],
            "error": error,
        }
    )
    add_event(db, event_type, "warning", message, payload)
    send_webhooks(db, event_type, payload)


def trigger_ip_change_for_origin(
    db: Session,
    origin: Origin,
    reason: str,
    *,
    guard: AutoIpChangeGuard | None = None,
) -> IpChangeJob | None:
    azpanel_enabled = azpanel_settings(db)["enabled"]
    custom_enabled = custom_ip_settings(db)["enabled"]
    if not azpanel_enabled and not custom_enabled:
        return None

    def provider_enabled(resource: AzPanelResource) -> bool:
        return custom_enabled if resource.provider == CUSTOM_IP_PROVIDER else azpanel_enabled

    # Resources bound to this backup directly, or to the global backup it mirrors —
    # a blocked mirror must still be able to rotate the machine behind it.
    bound_ids = {origin.azpanel_resource_id} if origin.azpanel_resource_id else set()
    if origin.global_origin_id:
        global_origin = db.get(FailoverGlobalOrigin, origin.global_origin_id)
        if global_origin is not None and global_origin.azpanel_resource_id:
            bound_ids.add(global_origin.azpanel_resource_id)
    resources = (
        db.query(AzPanelResource)
        .filter(AzPanelResource.enabled.is_(True), AzPanelResource.auto_change_on_blocked.is_(True))
        .filter(AzPanelResource.id.in_(bound_ids))
        .order_by(AzPanelResource.id.asc())
        .all()
        if bound_ids
        else []
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
        old_origin_target = origin.target
        sync_resource_current_ip_to_origin(db, resource)
        payload = ip_change_event_payload(
            db,
            resource,
            old_ip=old_origin_target,
            new_ip=resource.current_ip,
            trigger_type="pre_change_sync",
        )
        add_event(
            db,
            "azpanel.resource_ip_synced",
            "info",
            f"{resource.name} current IP synced to bound origin before auto change",
            payload,
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
        # IP-only matching exists for external-IP integrations whose forwarding
        # port differs from the cloud resource's check port. It is only safe for a
        # genuinely unassigned resource. A resource already bound elsewhere must
        # never be rotated because an unrelated unbound origin happens to share its
        # address.
        candidates = [
            resource
            for resource in candidates
            if resource.origin_id is None
            and not resource_bound_origins(db, resource)
            and not resource_bound_global_origins(db, resource)
        ]
        # 优先端口也一致的资源；没有再退到只按 IP 匹配——源站可能是外部 IP
        # 的入口端口（例如 nyanpass 转发端口），和云资源的检查端口本来就不同，
        # 而公网 IP 已经足够定位到同一台机器。
        exact_port_candidates = [resource for resource in candidates if resource.port == origin.port]
        resources = exact_port_candidates or candidates
        if len(resources) > 1:
            names = ", ".join(f"{resource.name} (#{resource.id})" for resource in resources[:5])
            if len(resources) > 5:
                names += f"，另有 {len(resources) - 5} 个"
            error = f"IP {origin.target} 同时匹配 {len(resources)} 个未绑定云资源：{names}；为防止连锁换号，已拒绝自动选择，请显式绑定资源"
            _report_auto_ip_change_warning(
                db,
                origin,
                event_type="azpanel.ip_change_ambiguous",
                message=f"{origin.group.hostname} 自动换 IP 已拦截：同 IP 匹配多个云资源",
                error=error,
                trigger_type="ambiguous_ip_match",
                guard=guard,
                warning_key=f"ambiguous:{origin.target}:{origin.port}",
            )
            return None
    if not resources:
        return None
    resource = resources[0]
    if guard is not None:
        if resource.id in guard.attempted_resource_ids:
            return None
        if len(guard.attempted_resource_ids) >= max(guard.max_distinct_resources, 1):
            error = (
                f"本轮已经尝试资源 ID {sorted(guard.attempted_resource_ids)}，"
                f"为防止探针异常导致批量换号，已拦截资源 {resource.name} (#{resource.id})；下轮会重新评估"
            )
            _report_auto_ip_change_warning(
                db,
                origin,
                event_type="azpanel.ip_change_suppressed",
                message=f"{resource.name} 自动换 IP 已被单轮熔断保护拦截",
                error=error,
                trigger_type="mass_change_guard",
                guard=guard,
                warning_key="mass-change-guard",
                resource=resource,
            )
            return None
    job = change_resource_ip(db, resource, trigger_type="auto_blocked", reason=reason)
    if guard is not None and job is not None:
        guard.attempted_resource_ids.add(resource.id)
    return job
