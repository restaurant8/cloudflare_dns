from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from .config import get_settings
from .dns_utils import tcp_check
from .events import add_event
from .models import Agent, Origin, ProbeResult, ProbeState
from .notifier import send_webhooks


LOCAL_SOURCE = "local"
ORIGIN_AVAILABLE_STATUS = "healthy"
ORIGIN_UNAVAILABLE_STATUSES = {"unhealthy", "blocked", "machine_down", "regional_issue"}
FINAL_ORIGIN_STATUSES = {ORIGIN_AVAILABLE_STATUS, *ORIGIN_UNAVAILABLE_STATUSES}


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
    agent_source_keys = [f"agent:{agent.id}" for agent in enabled_agents]
    required_sources = [LOCAL_SOURCE, *agent_source_keys]
    probe_states = db.query(ProbeState).filter(ProbeState.origin_id == origin.id).all()
    states = {state.source_key: state for state in probe_states}
    stale_before = datetime.utcnow() - timedelta(seconds=max(settings.check_interval_seconds * 3, 90))

    source_health: dict[str, str] = {}
    source_errors: dict[str, str | None] = {}
    for source_key in required_sources:
        state = states.get(source_key)
        if state is None or state.last_checked_at is None:
            source_health[source_key] = "unknown"
            source_errors[source_key] = None
            continue
        if state.last_checked_at < stale_before:
            source_health[source_key] = "unhealthy"
            source_errors[source_key] = f"{source_key} 探测结果过期"
            continue
        if state.status in {"healthy", "unhealthy"}:
            source_health[source_key] = state.status
            source_errors[source_key] = state.last_error
            continue
        source_health[source_key] = "unknown"
        source_errors[source_key] = None

    if any(status == "unknown" for status in source_health.values()):
        origin.status = "unknown"
        origin.last_error = "等待本地和探针探测结果"
    else:
        local_status = source_health[LOCAL_SOURCE]
        agent_statuses = [source_health[source_key] for source_key in agent_source_keys]
        failed_agent_keys = [source_key for source_key in agent_source_keys if source_health[source_key] == "unhealthy"]

        if not agent_statuses:
            origin.status = "healthy" if local_status == "healthy" else "unhealthy"
            origin.last_error = None if origin.status == "healthy" else source_errors.get(LOCAL_SOURCE) or "本地探测不可达"
        elif local_status == "healthy" and all(status == "healthy" for status in agent_statuses):
            origin.status = "healthy"
            origin.last_error = None
        elif local_status == "healthy" and failed_agent_keys:
            origin.status = "blocked"
            origin.last_error = f"本地探测正常，但国内探针不可达，疑似被墙：{', '.join(failed_agent_keys)}"
        elif local_status == "unhealthy" and any(status == "healthy" for status in agent_statuses):
            origin.status = "regional_issue"
            origin.last_error = "国内探针正常，但本地探测不可达，可能是本地或海外线路异常"
        else:
            origin.status = "machine_down"
            origin.last_error = "本地和国内探针均不可达，疑似机器挂了"

    newest = max((state for state in probe_states if state.last_checked_at), key=lambda item: item.last_checked_at, default=None)
    if newest:
        origin.last_checked_at = newest.last_checked_at
        origin.last_rtt_ms = newest.last_rtt_ms
        if origin.status == "healthy":
            origin.last_error = None

    if old_status != origin.status and origin.status in FINAL_ORIGIN_STATUSES:
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


def mark_agent_online(db: Session, agent: Agent, last_ip: str | None) -> None:
    old_status = agent.status
    agent.last_seen_at = datetime.utcnow()
    agent.last_ip = last_ip
    agent.status = "online"
    if old_status != "online":
        payload = {"agent_id": agent.id, "name": agent.name, "status": "online", "last_ip": agent.last_ip}
        add_event(db, "agent.status_changed", "info", f"探针 {agent.name} 已上线", payload)
        send_webhooks(db, "agent.status_changed", payload)


def mark_stale_agents(db: Session) -> int:
    settings = get_settings()
    stale_before = datetime.utcnow() - timedelta(seconds=max(settings.check_interval_seconds * 3, 90))
    stale_agents = (
        db.query(Agent)
        .filter(Agent.enabled.is_(True), Agent.status == "online")
        .filter((Agent.last_seen_at.is_(None)) | (Agent.last_seen_at < stale_before))
        .all()
    )
    for agent in stale_agents:
        agent.status = "offline"
        payload = {"agent_id": agent.id, "name": agent.name, "status": "offline", "last_seen_at": agent.last_seen_at.isoformat() if agent.last_seen_at else None}
        add_event(db, "agent.status_changed", "warning", f"探针 {agent.name} 已离线", payload)
        send_webhooks(db, "agent.status_changed", payload)
    return len(stale_agents)
