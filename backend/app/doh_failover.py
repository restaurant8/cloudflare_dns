import ipaddress
import json
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session, selectinload

from .dns_utils import tcp_check
from .dns_resolution import resolve_hostname_ips_bounded
from .doh import sync_doh_endpoint
from .events import add_event
from .models import DohFailoverGroup, DohFailoverOrigin
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


def _ip_probe_states(origin: DohFailoverOrigin) -> dict[str, dict[str, Any]]:
    try:
        value = json.loads(origin.ip_probe_states_json or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _set_ip_probe_states(origin: DohFailoverOrigin, value: dict[str, dict[str, Any]]) -> None:
    origin.ip_probe_states_json = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _candidate_ips(origin: DohFailoverOrigin, timeout_seconds: float) -> list[str]:
    if origin.target_type == "hostname":
        return resolve_hostname_ips_bounded(origin.target, timeout_seconds)
    return [str(ipaddress.ip_address(origin.target))]


def origin_is_available(origin: DohFailoverOrigin | None) -> bool:
    if not origin or not origin.enabled:
        return False
    candidates = resolved_ips(origin)
    if origin.ignore_health_check:
        return bool(candidates or published_ips(origin))
    return origin.status == "healthy" and bool(healthy_ips(origin))


def choose_desired_origin(group: DohFailoverGroup) -> DohFailoverOrigin | None:
    available = [origin for origin in group.origins if origin_is_available(origin)]
    if not available:
        return None
    best_priority = min(origin.priority for origin in available)
    current = next((origin for origin in available if origin.id == group.current_origin_id), None)
    if current is not None and current.priority <= best_priority:
        return current
    return sorted((origin for origin in available if origin.priority == best_priority), key=lambda item: item.id)[0]


def desired_publish_ips(origin: DohFailoverOrigin) -> list[str]:
    return resolved_ips(origin) if origin.ignore_health_check else healthy_ips(origin)


def origin_records(origin: DohFailoverOrigin) -> list[tuple[str, str]]:
    """Return only the last set that the control plane successfully published.

    Snapshot construction never resolves a hostname. This makes it deterministic,
    keeps a broken rule from blocking its endpoint, and preserves the last-known-
    good answer while an edited target is still passing its recovery threshold.
    """
    values = published_ips(origin)
    if not values and origin.target_type != "hostname":
        # Upgrade compatibility: a direct-IP current origin was necessarily the
        # value selected by older releases even though they did not persist the
        # published metadata. Hostnames never use this shortcut because their
        # resolved addresses may not have passed individual probes.
        values = [str(ipaddress.ip_address(origin.target))]
    return [("A" if ipaddress.ip_address(value).version == 4 else "AAAA", value) for value in values]


def _emit_status_change(db: Session, origin: DohFailoverOrigin, old_status: str) -> None:
    if old_status == origin.status or origin.status not in {"healthy", "unhealthy"}:
        return
    payload = {
        "provider": "private_doh",
        "group_id": origin.group_id,
        "origin_id": origin.id,
        "target": origin.target,
        "port": origin.port,
        "status": origin.status,
        "healthy_ips": healthy_ips(origin),
    }
    add_event(
        db,
        "doh_failover.origin_status_changed",
        "info" if origin.status == "healthy" else "warning",
        f"DoH target {origin.target}:{origin.port} is {origin.status}",
        payload,
    )
    send_webhooks(db, "doh_failover.origin_status_changed", payload)


def probe_origin(
    db: Session,
    origin: DohFailoverOrigin,
    check_cache: dict[tuple[str, int], object] | None = None,
) -> None:
    settings = get_runtime_settings(db)
    cache = check_cache if check_cache is not None else {}
    old_status = origin.status
    now = datetime.utcnow()
    try:
        candidates = _candidate_ips(origin, settings.check_timeout_seconds)
        if not candidates:
            raise ValueError(f"DoH failover target {origin.target} resolved to no addresses")
    except Exception as exc:
        # DNS failure belongs to this origin only. Do not erase published_ips: it
        # is the last-known-good remote state and may still be serving clients.
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
    if healthy:
        origin.status = "healthy"
    elif any(states[ip]["status"] == "unknown" for ip in candidates):
        origin.status = "unknown"
    else:
        origin.status = "unhealthy"
    origin.success_count = max((int(item["success_count"]) for item in states.values()), default=0)
    origin.fail_count = max((int(item["fail_count"]) for item in states.values()), default=0)
    origin.last_checked_at = now
    origin.last_error = "; ".join(errors) if errors and not healthy else None
    origin.last_rtt_ms = round(min(rtts), 2) if rtts else None
    _emit_status_change(db, origin, old_status)


def evaluate_doh_failover_groups(
    db: Session,
    group_ids: list[int] | None = None,
    *,
    commit_per_group: bool = False,
    check_cache: dict[tuple[str, int], object] | None = None,
) -> int:
    query = (
        db.query(DohFailoverGroup)
        .options(selectinload(DohFailoverGroup.origins), selectinload(DohFailoverGroup.endpoint))
        .filter(DohFailoverGroup.enabled.is_(True))
    )
    if group_ids is not None:
        if not group_ids:
            return 0
        query = query.filter(DohFailoverGroup.id.in_(group_ids))
    settings = get_runtime_settings(db)
    now = datetime.utcnow()
    cache = check_cache if check_cache is not None else {}
    switched = 0
    for group in query.order_by(DohFailoverGroup.id).all():
        previous_error = group.last_error
        try:
            for origin in group.origins:
                if origin.enabled:
                    probe_origin(db, origin, cache)
            desired = choose_desired_origin(group)
            if desired is None:
                waiting = any(
                    origin.enabled and not origin.ignore_health_check and origin.status == "unknown"
                    for origin in group.origins
                )
                group.last_error = "Waiting for health-check threshold" if waiting else "No healthy DoH target"
                if not waiting and (
                    group.no_healthy_notified_at is None
                    or (now - group.no_healthy_notified_at).total_seconds()
                    >= settings.no_healthy_notification_interval_seconds
                ):
                    group.no_healthy_notified_at = now
                    payload = {
                        "provider": "private_doh",
                        "group_id": group.id,
                        "hostname": group.hostname,
                        "origins": [
                            {"id": item.id, "target": item.target, "port": item.port, "status": item.status}
                            for item in group.origins
                        ],
                    }
                    add_event(
                        db,
                        "doh_failover.no_healthy_origin",
                        "error",
                        f"{group.hostname} has no healthy private DoH target",
                        payload,
                    )
                    send_webhooks(db, "doh_failover.no_healthy_origin", payload)
                if commit_per_group:
                    db.commit()
                continue

            group.no_healthy_notified_at = None
            proposed_ips = desired_publish_ips(desired)
            if not proposed_ips:
                group.last_error = f"DoH target {desired.target} has no publishable address"
                if commit_per_group:
                    db.commit()
                continue
            current = next((item for item in group.origins if item.id == group.current_origin_id), None)
            origin_changed = desired.id != group.current_origin_id
            records_changed = published_ips(desired) != proposed_ips
            if not origin_changed and not records_changed:
                group.last_error = None
                if commit_per_group:
                    db.commit()
                continue
            if origin_changed and group.last_switch_at and origin_is_available(current):
                if (now - group.last_switch_at).total_seconds() < group.min_switch_interval_seconds:
                    if commit_per_group:
                        db.commit()
                    continue

            old_origin_id = group.current_origin_id
            old_published_ips = published_ips(desired)
            group.current_origin_id = desired.id
            set_published_ips(desired, proposed_ips)
            db.flush()
            if not sync_doh_endpoint(db, group.endpoint, force=True, ignore_backoff=True):
                group.current_origin_id = old_origin_id
                set_published_ips(desired, old_published_ips)
                group.last_error = group.endpoint.last_error or "DoH endpoint is disabled or retry is deferred"
                if commit_per_group:
                    db.commit()
                continue

            if origin_changed:
                group.last_switch_at = now
            group.last_error = None
            event_type = "doh_failover.switched" if origin_changed else "doh_failover.records_updated"
            payload = {
                "provider": "private_doh",
                "group_id": group.id,
                "hostname": group.hostname,
                "old_origin_id": old_origin_id,
                "new_origin_id": desired.id,
                "content": proposed_ips,
            }
            message = (
                f"{group.hostname} switched to {desired.target}"
                if origin_changed
                else f"{group.hostname} updated healthy addresses for {desired.target}"
            )
            add_event(db, event_type, "info", message, payload)
            send_webhooks(db, event_type, payload)
            switched += int(origin_changed)
            if commit_per_group:
                db.commit()
        except Exception as exc:
            group.last_error = str(exc)
            if previous_error != group.last_error:
                payload = {
                    "provider": "private_doh",
                    "group_id": group.id,
                    "hostname": group.hostname,
                    "error": str(exc),
                }
                add_event(db, "doh_failover.failed", "error", f"{group.hostname} DoH failover failed: {exc}", payload)
                send_webhooks(db, "doh_failover.failed", payload)
            if commit_per_group:
                db.commit()
    return switched
