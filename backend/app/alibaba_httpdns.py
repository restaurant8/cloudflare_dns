from datetime import datetime
from typing import Any

import httpx
from sqlalchemy.orm import Session, selectinload

from .events import add_event
from .dns_utils import tcp_check
from .integrations import _azpanel_token, _raise_for_status_with_body, azpanel_settings
from .models import AlibabaHttpDnsGroup, AlibabaHttpDnsOrigin
from .notifier import send_webhooks
from .runtime_settings import get_runtime_settings

def _endpoint(db: Session) -> tuple[str, dict[str, str], int]:
    settings = azpanel_settings(db)
    if not settings["enabled"]:
        raise RuntimeError("请先在“自动换 IP”中启用 azpanel 集成")
    if not settings["base_url"]:
        raise RuntimeError("请先配置 azpanel 地址")
    token = _azpanel_token(db)
    if not token:
        raise RuntimeError("请先配置 azpanel 内部 API Token")
    return (
        f"{settings['base_url']}/api/internal/cloudflare-dns/alibaba-httpdns",
        {"Authorization": f"Bearer {token}", "X-Cloudflare-Dns-Token": token},
        settings["timeout_seconds"],
    )


def call_azpanel_httpdns(db: Session, method: str = "GET", **parameters: Any) -> dict[str, Any]:
    url, headers, timeout = _endpoint(db)
    response = httpx.request(
        method,
        url,
        headers=headers,
        params=parameters if method.upper() == "GET" else None,
        json=parameters if method.upper() != "GET" else None,
        timeout=timeout,
    )
    _raise_for_status_with_body(response, "azpanel Alibaba HTTPDNS")
    data = response.json()
    if data.get("status") != "success":
        raise RuntimeError(str(data.get("message") or "azpanel Alibaba HTTPDNS 请求失败"))
    payload = data.get("data")
    return payload if isinstance(payload, dict) else {}


def list_remote_accounts(db: Session) -> list[dict[str, Any]]:
    return list(call_azpanel_httpdns(db).get("accounts") or [])


def list_remote_zones(db: Session, account_id: int) -> list[dict[str, Any]]:
    return list(call_azpanel_httpdns(db, account_id=account_id).get("zones") or [])


def list_remote_records(db: Session, account_id: int, zone_id: str) -> list[dict[str, Any]]:
    return list(call_azpanel_httpdns(db, account_id=account_id, zone_id=zone_id).get("records") or [])


def _available(origin: AlibabaHttpDnsOrigin | None) -> bool:
    return bool(origin and origin.enabled and (origin.ignore_health_check or origin.status == "healthy"))


def _desired_origin(group: AlibabaHttpDnsGroup) -> AlibabaHttpDnsOrigin | None:
    healthy = [origin for origin in group.origins if _available(origin)]
    if not healthy:
        return None
    best_priority = min(origin.priority for origin in healthy)
    current = next((origin for origin in healthy if origin.id == group.current_origin_id), None)
    if current is not None and current.priority <= best_priority:
        return current
    return sorted((origin for origin in healthy if origin.priority == best_priority), key=lambda item: item.id)[0]


def probe_origin(db: Session, origin: AlibabaHttpDnsOrigin, check_cache: dict[tuple[str, int], object] | None = None) -> None:
    settings = get_runtime_settings(db)
    key = (origin.target.rstrip(".").lower(), int(origin.port))
    cache = check_cache if check_cache is not None else {}
    result = cache.get(key)
    if result is None:
        result = tcp_check(origin.target, origin.port, settings.check_timeout_seconds)
        cache[key] = result
    old_status = origin.status
    if result.success:
        origin.success_count += 1
        origin.fail_count = 0
        if origin.success_count >= settings.recovery_threshold:
            origin.status = "healthy"
    else:
        origin.fail_count += 1
        origin.success_count = 0
        if origin.fail_count >= settings.fail_threshold:
            origin.status = "unhealthy"
    origin.last_checked_at = datetime.utcnow()
    origin.last_error = None if result.success else result.error
    origin.last_rtt_ms = result.rtt_ms
    if old_status != origin.status and origin.status in {"healthy", "unhealthy"}:
        payload = {"provider": "alibaba_httpdns", "group_id": origin.group_id, "origin_id": origin.id, "target": origin.target, "status": origin.status}
        add_event(db, "alibaba_httpdns.origin_status_changed", "info" if origin.status == "healthy" else "warning", f"阿里云 HTTPDNS 源站 {origin.target}:{origin.port} 状态变为 {origin.status}", payload)
        send_webhooks(db, "alibaba_httpdns.origin_status_changed", payload)


def _remote_record(db: Session, group: AlibabaHttpDnsGroup) -> dict[str, Any]:
    payload = call_azpanel_httpdns(
        db,
        account_id=group.remote_account_id,
        zone_id=group.zone_id,
        record_id=group.record_id,
    )
    record = payload.get("record")
    if not isinstance(record, dict):
        raise RuntimeError("azpanel 未返回阿里云 HTTPDNS 记录")
    return record


def _record_matches(record: dict[str, Any], group: AlibabaHttpDnsGroup, origin: AlibabaHttpDnsOrigin) -> bool:
    return (
        str(record.get("RecordId") or "") == group.record_id
        and str(record.get("Type") or "").upper() == group.record_type.upper()
        and str(record.get("Value") or "").rstrip(".").lower() == origin.target.rstrip(".").lower()
        and int(record.get("Ttl") or 0) == group.ttl
    )


def publish_origin(db: Session, group: AlibabaHttpDnsGroup, origin: AlibabaHttpDnsOrigin) -> dict[str, Any]:
    result = call_azpanel_httpdns(
        db,
        method="PUT",
        account_id=group.remote_account_id,
        zone_id=group.zone_id,
        record_id=group.record_id,
        rr=group.rr,
        type=group.record_type,
        value=origin.target,
        ttl=group.ttl,
        line=group.request_source,
        weight=group.weight,
        priority=group.priority,
        remark=group.remark or "",
    )
    return dict(result.get("record") or {})


def evaluate_alibaba_httpdns_groups(
    db: Session,
    group_ids: list[int] | None = None,
    commit_per_group: bool = False,
    force_consistency: bool = False,
    check_cache: dict[tuple[str, int], object] | None = None,
) -> int:
    query = db.query(AlibabaHttpDnsGroup).options(selectinload(AlibabaHttpDnsGroup.origins)).filter(AlibabaHttpDnsGroup.enabled.is_(True))
    if group_ids is not None:
        if not group_ids:
            return 0
        query = query.filter(AlibabaHttpDnsGroup.id.in_(group_ids))
    settings = get_runtime_settings(db)
    now = datetime.utcnow()
    switched = 0
    cache = check_cache if check_cache is not None else {}
    for group in query.all():
        previous_error = group.last_error
        try:
            for origin in group.origins:
                if origin.enabled and not origin.ignore_health_check:
                    probe_origin(db, origin, cache)
            desired = _desired_origin(group)
            if desired is None:
                waiting_for_threshold = any(
                    origin.enabled and not origin.ignore_health_check and origin.status == "unknown"
                    for origin in group.origins
                )
                if waiting_for_threshold:
                    group.last_error = "等待源站探测达到判定阈值"
                    if commit_per_group:
                        db.commit()
                    continue
                group.last_error = "没有可用的健康源站"
                if group.no_healthy_notified_at is None or (now - group.no_healthy_notified_at).total_seconds() >= settings.no_healthy_notification_interval_seconds:
                    group.no_healthy_notified_at = now
                    payload = {"provider": "alibaba_httpdns", "group_id": group.id, "record": f"{group.rr}.{group.zone_name}", "origins": [{"id": item.id, "target": item.target, "status": item.status} for item in group.origins]}
                    add_event(db, "alibaba_httpdns.no_healthy_origin", "error", f"阿里云 HTTPDNS {group.rr}.{group.zone_name} 没有可用源站", payload)
                    send_webhooks(db, "alibaba_httpdns.no_healthy_origin", payload)
                if commit_per_group:
                    db.commit()
                continue
            group.no_healthy_notified_at = None
            current = next((item for item in group.origins if item.id == group.current_origin_id), None)
            needs_publish = desired.id != group.current_origin_id or group.last_error is not None
            consistency_due = force_consistency or group.last_consistency_check_at is None or (now - group.last_consistency_check_at).total_seconds() >= 300
            if not needs_publish and consistency_due:
                needs_publish = not _record_matches(_remote_record(db, group), group, desired)
                group.last_consistency_check_at = now
            if needs_publish and group.last_switch_at and desired.id != group.current_origin_id and _available(current):
                if (now - group.last_switch_at).total_seconds() < group.min_switch_interval_seconds:
                    needs_publish = False
            if needs_publish:
                old_origin_id = group.current_origin_id
                publish_origin(db, group, desired)
                group.current_origin_id = desired.id
                group.last_switch_at = now
                group.last_consistency_check_at = now
                group.last_error = None
                payload = {"provider": "alibaba_httpdns", "group_id": group.id, "hostname": f"{group.rr}.{group.zone_name}".replace("@.", ""), "old_origin_id": old_origin_id, "new_origin_id": desired.id, "record_id": group.record_id, "record_type": group.record_type, "content": desired.target}
                add_event(db, "alibaba_httpdns.switched", "info", f"阿里云 HTTPDNS {payload['hostname']} 已切换到 {group.record_type} {desired.target}", payload)
                send_webhooks(db, "alibaba_httpdns.switched", payload)
                switched += 1
            elif group.last_error == "没有可用的健康源站":
                group.last_error = None
            if commit_per_group:
                db.commit()
        except Exception as exc:
            group.last_error = str(exc)
            if previous_error != group.last_error:
                payload = {"provider": "alibaba_httpdns", "group_id": group.id, "error": str(exc)}
                add_event(db, "alibaba_httpdns.publish_failed", "error", f"阿里云 HTTPDNS {group.rr}.{group.zone_name} 发布失败：{exc}", payload)
                send_webhooks(db, "alibaba_httpdns.publish_failed", payload)
            if commit_per_group:
                db.commit()
    return switched
