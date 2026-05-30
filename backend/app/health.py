from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from .config import get_settings
from .dns_utils import tcp_check
from .events import add_event
from .models import Agent, Origin, ProbeResult, ProbeState
from .notifier import send_webhooks


LOCAL_SOURCE = "local"


def _probe_state(db: Session, origin: Origin, source_key: str, agent: Agent | None) -> ProbeState:
    state = (
        db.query(ProbeState)
        .filter(ProbeState.origin_id == origin.id, ProbeState.source_key == source_key)
        .one_or_none()
    )
    if state is None:
        state = ProbeState(origin_id=origin.id, source_key=source_key, agent_id=agent.id if agent else None)
        db.add(state)
        db.flush()
    return state


def apply_probe_result(
    db: Session,
    origin: Origin,
    success: bool,
    rtt_ms: float | None,
    error: str | None,
    source_key: str = LOCAL_SOURCE,
    agent: Agent | None = None,
    target: str | None = None,
    port: int | None = None,
) -> None:
    settings = get_settings()
    now = datetime.utcnow()
    state = _probe_state(db, origin, source_key, agent)
    old_state_status = state.status

    if success:
        state.success_count += 1
        state.fail_count = 0
        if state.success_count >= settings.recovery_threshold:
            state.status = "healthy"
    else:
        state.fail_count += 1
        state.success_count = 0
        if state.fail_count >= settings.fail_threshold:
            state.status = "unhealthy"

    state.last_checked_at = now
    state.last_error = None if success else error
    state.last_rtt_ms = rtt_ms

    db.add(
        ProbeResult(
            origin_id=origin.id,
            agent_id=agent.id if agent else None,
            target=target or origin.target,
            port=port or origin.port,
            success=success,
            rtt_ms=rtt_ms,
            error=error,
        )
    )

    if old_state_status != state.status and state.status in {"healthy", "unhealthy"}:
        add_event(
            db,
            "probe.status_changed",
            "info" if state.status == "healthy" else "warning",
            f"{source_key} 将 {origin.target}:{origin.port} 标记为 {state.status}",
            {"origin_id": origin.id, "source": source_key, "status": state.status},
        )

    recalculate_origin_status(db, origin)


def recalculate_origin_status(db: Session, origin: Origin) -> None:
    settings = get_settings()
    old_status = origin.status
    if not origin.enabled:
        origin.status = "disabled"
        return

    enabled_agents = db.query(Agent).filter(Agent.enabled.is_(True)).all()
    required_sources = {LOCAL_SOURCE}
    required_sources.update(f"agent:{agent.id}" for agent in enabled_agents)
    states = {state.source_key: state for state in origin.probe_states}
    stale_before = datetime.utcnow() - timedelta(seconds=max(settings.check_interval_seconds * 3, 90))

    has_unknown = False
    for source_key in required_sources:
        state = states.get(source_key)
        if state is None or state.last_checked_at is None:
            has_unknown = True
            continue
        if state.last_checked_at < stale_before:
            origin.status = "unhealthy"
            origin.last_error = f"{source_key} 探测结果过期"
            break
        if state.status == "unhealthy":
            origin.status = "unhealthy"
            origin.last_error = state.last_error
            break
        if state.status != "healthy":
            has_unknown = True
    else:
        origin.status = "unknown" if has_unknown else "healthy"
        origin.last_error = None if origin.status == "healthy" else "等待探测结果"

    newest = max((state for state in origin.probe_states if state.last_checked_at), key=lambda item: item.last_checked_at, default=None)
    if newest:
        origin.last_checked_at = newest.last_checked_at
        origin.last_rtt_ms = newest.last_rtt_ms
        if origin.status == "healthy":
            origin.last_error = None

    if old_status != origin.status and origin.status in {"healthy", "unhealthy"}:
        payload = {"origin_id": origin.id, "target": origin.target, "port": origin.port, "status": origin.status}
        add_event(
            db,
            "origin.status_changed",
            "info" if origin.status == "healthy" else "warning",
            f"源站 {origin.target}:{origin.port} 状态变为 {origin.status}",
            payload,
        )
        send_webhooks(db, "origin.status_changed", payload)


def run_local_checks(db: Session) -> int:
    settings = get_settings()
    origins = (
        db.query(Origin)
        .join(Origin.group)
        .filter(Origin.enabled.is_(True))
        .all()
    )
    checked = 0
    for origin in origins:
        if not origin.group.enabled:
            continue
        result = tcp_check(origin.target, origin.port, settings.check_timeout_seconds)
        apply_probe_result(
            db,
            origin,
            result.success,
            result.rtt_ms,
            result.error,
            source_key=LOCAL_SOURCE,
            target=origin.target,
            port=origin.port,
        )
        checked += 1
    return checked
