import ipaddress
import json
from datetime import datetime, timedelta
from typing import Any

import httpx
from sqlalchemy.orm import Session, selectinload

from .doh import resolve_hostname_ips_bounded
from .dns_utils import tcp_check
from .events import add_event
from .integrations import _azpanel_token, _raise_for_status_with_body, azpanel_settings
from .models import AlibabaHttpDnsAccountState, AlibabaHttpDnsGroup, AlibabaHttpDnsOrigin
from .notifier import send_webhooks
from .origin_expansion import (
    healthy_ips,
    published_ips,
    resolved_ips,
    set_healthy_ips,
    set_published_ips,
    set_resolved_ips,
)
from .runtime_settings import get_runtime_settings


def _endpoint(db: Session) -> tuple[str, dict[str, str], int]:
    settings = azpanel_settings(db)
    if not settings["enabled"]:
        raise RuntimeError("请先在‘自动换 IP’中启用 azpanel 集成")
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


def _account_state(db: Session, account_id: int) -> AlibabaHttpDnsAccountState:
    state = db.query(AlibabaHttpDnsAccountState).filter_by(remote_account_id=account_id).one_or_none()
    if state is None:
        state = AlibabaHttpDnsAccountState(remote_account_id=account_id)
        db.add(state)
        db.flush()
    return state


def call_azpanel_httpdns(
    db: Session,
    method: str = "GET",
    *,
    respect_backoff: bool = False,
    **parameters: Any,
) -> dict[str, Any]:
    account_id = int(parameters.get("account_id") or 0)
    state = _account_state(db, account_id) if account_id else None
    now = datetime.utcnow()
    if respect_backoff and state and state.next_retry_at and state.next_retry_at > now:
        raise RuntimeError(state.last_error or f"Alibaba HTTPDNS retry deferred until {state.next_retry_at.isoformat()}Z")
    try:
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
    except Exception as exc:
        if state is not None:
            state.failure_count = int(state.failure_count or 0) + 1
            delay_seconds = min(600, 30 * (2 ** min(state.failure_count - 1, 5)))
            state.next_retry_at = now + timedelta(seconds=delay_seconds)
            state.last_error = str(exc)
        raise
    if state is not None:
        state.failure_count = 0
        state.next_retry_at = None
        state.last_error = None
        state.last_success_at = now
    payload = data.get("data")
    return payload if isinstance(payload, dict) else {}


def list_remote_accounts(db: Session) -> list[dict[str, Any]]:
    return list(call_azpanel_httpdns(db).get("accounts") or [])


def list_remote_zones(db: Session, account_id: int) -> list[dict[str, Any]]:
    return list(call_azpanel_httpdns(db, account_id=account_id).get("zones") or [])


def list_remote_records(db: Session, account_id: int, zone_id: str) -> list[dict[str, Any]]:
    return list(call_azpanel_httpdns(db, account_id=account_id, zone_id=zone_id).get("records") or [])


def _ip_probe_states(origin: AlibabaHttpDnsOrigin) -> dict[str, dict[str, Any]]:
    try:
        value = json.loads(origin.ip_probe_states_json or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _set_ip_probe_states(origin: AlibabaHttpDnsOrigin, value: dict[str, dict[str, Any]]) -> None:
    origin.ip_probe_states_json = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _candidate_ips(origin: AlibabaHttpDnsOrigin, timeout_seconds: float) -> list[str]:
    if origin.target_type == "hostname":
        addresses = resolve_hostname_ips_bounded(origin.target, timeout_seconds)
        if origin.group.record_type == "A":
            return [value for value in addresses if ipaddress.ip_address(value).version == 4]
        if origin.group.record_type == "AAAA":
            return [value for value in addresses if ipaddress.ip_address(value).version == 6]
        return addresses
    return [str(ipaddress.ip_address(origin.target))]


def _available(origin: AlibabaHttpDnsOrigin | None) -> bool:
    if not origin or not origin.enabled:
        return False
    if origin.ignore_health_check:
        return bool(resolved_ips(origin) or published_ips(origin) or origin.target)
    return origin.status == "healthy" and bool(healthy_ips(origin) or origin.target_type != "hostname")


def _desired_origin(group: AlibabaHttpDnsGroup) -> AlibabaHttpDnsOrigin | None:
    available = [origin for origin in group.origins if _available(origin)]
    if not available:
        return None
    best_priority = min(origin.priority for origin in available)
    current = next((origin for origin in available if origin.id == group.current_origin_id), None)
    if current is not None and current.priority <= best_priority:
        return current
    return sorted((origin for origin in available if origin.priority == best_priority), key=lambda item: item.id)[0]


def _emit_status_change(db: Session, origin: AlibabaHttpDnsOrigin, old_status: str) -> None:
    if old_status == origin.status or origin.status not in {"healthy", "unhealthy"}:
        return
    payload = {
        "provider": "alibaba_httpdns",
        "group_id": origin.group_id,
        "origin_id": origin.id,
        "target": origin.target,
        "status": origin.status,
        "healthy_ips": healthy_ips(origin),
    }
    add_event(
        db,
        "alibaba_httpdns.origin_status_changed",
        "info" if origin.status == "healthy" else "warning",
        f"阿里云 HTTPDNS 源站 {origin.target}:{origin.port} 状态变为 {origin.status}",
        payload,
    )
    send_webhooks(db, "alibaba_httpdns.origin_status_changed", payload)


def probe_origin(
    db: Session,
    origin: AlibabaHttpDnsOrigin,
    check_cache: dict[tuple[str, int], object] | None = None,
) -> None:
    settings = get_runtime_settings(db)
    cache = check_cache if check_cache is not None else {}
    old_status = origin.status
    now = datetime.utcnow()
    try:
        candidates = _candidate_ips(origin, settings.check_timeout_seconds)
        if not candidates:
            raise ValueError(f"Alibaba HTTPDNS target {origin.target} resolved to no addresses")
    except Exception as exc:
        origin.success_count = 0
        origin.fail_count += 1
        if origin.fail_count >= settings.fail_threshold:
            origin.status = "unhealthy"
            set_resolved_ips(origin, [])
            set_healthy_ips(origin, [])
        origin.last_checked_at = now
        origin.last_error = str(exc)
        origin.last_rtt_ms = None
        _emit_status_change(db, origin, old_status)
        return

    set_resolved_ips(origin, candidates)
    if origin.group.current_origin_id == origin.id and not published_ips(origin):
        if origin.group.last_published_value:
            try:
                set_published_ips(origin, [origin.group.last_published_value])
            except ValueError:
                pass
        elif origin.target_type != "hostname":
            set_published_ips(origin, [origin.target])
    if origin.ignore_health_check:
        set_healthy_ips(origin, candidates)
        origin.status = "healthy"
        origin.success_count = max(origin.success_count, settings.recovery_threshold)
        origin.fail_count = 0
        origin.last_checked_at = now
        origin.last_error = None
        origin.last_rtt_ms = None
        _emit_status_change(db, origin, old_status)
        return

    previous_states = _ip_probe_states(origin)
    states: dict[str, dict[str, Any]] = {}
    rtts: list[float] = []
    errors: list[str] = []
    for ip in candidates:
        state = previous_states.get(ip, {})
        key = (ip, int(origin.port))
        result = cache.get(key)
        if result is None:
            result = tcp_check(ip, origin.port, settings.check_timeout_seconds)
            cache[key] = result
        success_count = int(state.get("success_count", 0))
        fail_count = int(state.get("fail_count", 0))
        status = str(state.get("status", "unknown"))
        if result.success:
            success_count += 1
            fail_count = 0
            if success_count >= settings.recovery_threshold:
                status = "healthy"
            if result.rtt_ms is not None:
                rtts.append(float(result.rtt_ms))
        else:
            fail_count += 1
            success_count = 0
            if fail_count >= settings.fail_threshold:
                status = "unhealthy"
            errors.append(f"{ip}: {result.error or 'connect failed'}")
        states[ip] = {
            "status": status,
            "success_count": success_count,
            "fail_count": fail_count,
            "last_error": None if result.success else result.error,
            "last_rtt_ms": result.rtt_ms,
        }
    _set_ip_probe_states(origin, states)
    healthy = [ip for ip in candidates if states[ip]["status"] == "healthy"]
    set_healthy_ips(origin, healthy)
    origin.status = "healthy" if healthy else (
        "unknown" if any(states[ip]["status"] == "unknown" for ip in candidates) else "unhealthy"
    )
    origin.success_count = max((int(item["success_count"]) for item in states.values()), default=0)
    origin.fail_count = max((int(item["fail_count"]) for item in states.values()), default=0)
    origin.last_checked_at = now
    origin.last_error = "; ".join(errors) if errors and not healthy else None
    origin.last_rtt_ms = round(min(rtts), 2) if rtts else None
    _emit_status_change(db, origin, old_status)


def _desired_value(group: AlibabaHttpDnsGroup, origin: AlibabaHttpDnsOrigin) -> str | None:
    if group.record_type == "CNAME":
        return origin.target
    values = resolved_ips(origin) if origin.ignore_health_check else healthy_ips(origin)
    if not values and origin.target_type != "hostname":
        values = [origin.target]
    current = group.last_published_value or (published_ips(origin)[0] if published_ips(origin) else None)
    if current in values:
        return current
    return values[0] if values else None


def _remote_record(db: Session, group: AlibabaHttpDnsGroup) -> dict[str, Any]:
    payload = call_azpanel_httpdns(
        db,
        account_id=group.remote_account_id,
        zone_id=group.zone_id,
        record_id=group.record_id,
        respect_backoff=True,
    )
    record = payload.get("record")
    if not isinstance(record, dict):
        raise RuntimeError("azpanel 未返回阿里云 HTTPDNS 记录")
    return record


def _record_matches(record: dict[str, Any], group: AlibabaHttpDnsGroup, value: str) -> bool:
    return (
        str(record.get("RecordId") or "") == group.record_id
        and str(record.get("Type") or "").upper() == group.record_type.upper()
        and str(record.get("Value") or "").rstrip(".").lower() == value.rstrip(".").lower()
        and int(record.get("Ttl") or 0) == group.ttl
    )


def publish_origin(
    db: Session,
    group: AlibabaHttpDnsGroup,
    origin: AlibabaHttpDnsOrigin,
    value: str | None = None,
) -> dict[str, Any]:
    published_value = value or _desired_value(group, origin)
    if not published_value:
        raise RuntimeError(f"Alibaba HTTPDNS target {origin.target} has no healthy publishable address")
    result = call_azpanel_httpdns(
        db,
        method="PUT",
        account_id=group.remote_account_id,
        zone_id=group.zone_id,
        record_id=group.record_id,
        rr=group.rr,
        type=group.record_type,
        value=published_value,
        ttl=group.ttl,
        line=group.request_source,
        weight=group.weight,
        priority=group.priority,
        remark=group.remark or "",
        respect_backoff=True,
    )
    return dict(result.get("record") or {})


def evaluate_alibaba_httpdns_groups(
    db: Session,
    group_ids: list[int] | None = None,
    commit_per_group: bool = False,
    force_consistency: bool = False,
    check_cache: dict[tuple[str, int], object] | None = None,
) -> int:
    query = (
        db.query(AlibabaHttpDnsGroup)
        .options(selectinload(AlibabaHttpDnsGroup.origins))
        .filter(AlibabaHttpDnsGroup.enabled.is_(True))
    )
    if group_ids is not None:
        if not group_ids:
            return 0
        query = query.filter(AlibabaHttpDnsGroup.id.in_(group_ids))
    settings = get_runtime_settings(db)
    now = datetime.utcnow()
    switched = 0
    cache = check_cache if check_cache is not None else {}
    for group in query.order_by(AlibabaHttpDnsGroup.id).all():
        previous_error = group.last_error
        try:
            for origin in group.origins:
                if origin.enabled:
                    probe_origin(db, origin, cache)
            desired = _desired_origin(group)
            if desired is None:
                waiting = any(
                    origin.enabled and not origin.ignore_health_check and origin.status == "unknown"
                    for origin in group.origins
                )
                group.last_error = "等待源站探测达到判定阈值" if waiting else "没有可用的健康源站"
                if not waiting and (
                    group.no_healthy_notified_at is None
                    or (now - group.no_healthy_notified_at).total_seconds()
                    >= settings.no_healthy_notification_interval_seconds
                ):
                    group.no_healthy_notified_at = now
                    payload = {
                        "provider": "alibaba_httpdns",
                        "group_id": group.id,
                        "record": f"{group.rr}.{group.zone_name}",
                        "origins": [
                            {"id": item.id, "target": item.target, "status": item.status}
                            for item in group.origins
                        ],
                    }
                    add_event(
                        db,
                        "alibaba_httpdns.no_healthy_origin",
                        "error",
                        f"阿里云 HTTPDNS {group.rr}.{group.zone_name} 没有可用源站",
                        payload,
                    )
                    send_webhooks(db, "alibaba_httpdns.no_healthy_origin", payload)
                if commit_per_group:
                    db.commit()
                continue

            group.no_healthy_notified_at = None
            desired_value = _desired_value(group, desired)
            if not desired_value:
                group.last_error = f"目标 {desired.target} 尚无健康可发布地址"
                if commit_per_group:
                    db.commit()
                continue
            current = next((item for item in group.origins if item.id == group.current_origin_id), None)
            origin_changed = desired.id != group.current_origin_id
            value_changed = group.last_published_value not in {None, desired_value}
            needs_publish = origin_changed or value_changed or group.last_error is not None
            consistency_due = (
                force_consistency
                or group.last_consistency_check_at is None
                or (now - group.last_consistency_check_at).total_seconds() >= 300
            )
            if not needs_publish and consistency_due:
                needs_publish = not _record_matches(_remote_record(db, group), group, desired_value)
                group.last_consistency_check_at = now
            if needs_publish and origin_changed and group.last_switch_at and _available(current):
                if (now - group.last_switch_at).total_seconds() < group.min_switch_interval_seconds:
                    needs_publish = False
            if needs_publish:
                old_origin_id = group.current_origin_id
                publish_origin(db, group, desired)
                group.current_origin_id = desired.id
                group.last_published_value = desired_value
                if desired_value and desired.target_type != "hostname":
                    set_published_ips(desired, [desired_value])
                elif desired_value and group.record_type != "CNAME":
                    set_published_ips(desired, [desired_value])
                if origin_changed:
                    group.last_switch_at = now
                group.last_consistency_check_at = now
                group.last_error = None
                payload = {
                    "provider": "alibaba_httpdns",
                    "group_id": group.id,
                    "hostname": f"{group.rr}.{group.zone_name}".replace("@.", ""),
                    "old_origin_id": old_origin_id,
                    "new_origin_id": desired.id,
                    "record_id": group.record_id,
                    "record_type": group.record_type,
                    "content": desired_value,
                }
                event_type = "alibaba_httpdns.switched" if origin_changed else "alibaba_httpdns.records_updated"
                add_event(
                    db,
                    event_type,
                    "info",
                    f"阿里云 HTTPDNS {payload['hostname']} 已发布 {group.record_type} {desired_value}",
                    payload,
                )
                send_webhooks(db, event_type, payload)
                switched += int(origin_changed)
            elif group.last_error == "没有可用的健康源站":
                group.last_error = None
            if commit_per_group:
                db.commit()
        except Exception as exc:
            group.last_error = str(exc)
            if previous_error != group.last_error:
                payload = {"provider": "alibaba_httpdns", "group_id": group.id, "error": str(exc)}
                add_event(
                    db,
                    "alibaba_httpdns.publish_failed",
                    "error",
                    f"阿里云 HTTPDNS {group.rr}.{group.zone_name} 发布失败：{exc}",
                    payload,
                )
                send_webhooks(db, "alibaba_httpdns.publish_failed", payload)
            if commit_per_group:
                db.commit()
    return switched
