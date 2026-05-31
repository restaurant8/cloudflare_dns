from datetime import datetime, timedelta

from sqlalchemy.orm import Session, selectinload

from .config import get_settings
from .dns_utils import tcp_check
from .events import add_event
from .models import Agent, FailoverGroup, Origin, ProbeResult, ProbeState
from .notifier import send_webhooks
from .origin_expansion import (
    EXPANDED_PUBLISH_MODE,
    expanded_source_key,
    healthy_ips,
    is_expanded_origin,
    resolve_hostname_ips,
    resolved_ips,
    set_healthy_ips,
    set_resolved_ips,
    split_expanded_source_key,
)


LOCAL_SOURCE = "local"
CHINA_AGENT_REGION = "china"
FOREIGN_AGENT_REGION = "foreign"
ORIGIN_AVAILABLE_STATUS = "healthy"
ORIGIN_UNAVAILABLE_STATUSES = {"unhealthy", "blocked", "machine_down", "regional_issue"}
FINAL_ORIGIN_STATUSES = {ORIGIN_AVAILABLE_STATUS, *ORIGIN_UNAVAILABLE_STATUSES}


def origin_needs_probe(origin: Origin, include_all: bool = False) -> bool:
    if include_all:
        return True
    group = origin.group
    if not group or not group.enabled or not origin.enabled:
        return False
    return True


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


def active_agents(db: Session, stale_before: datetime | None = None) -> list[Agent]:
    settings = get_settings()
    cutoff = stale_before or datetime.utcnow() - timedelta(seconds=max(settings.check_interval_seconds * 3, 90))
    return (
        db.query(Agent)
        .filter(Agent.enabled.is_(True), Agent.status == "online")
        .filter(Agent.last_seen_at.is_not(None), Agent.last_seen_at >= cutoff)
        .all()
    )


def agent_region(agent: Agent) -> str:
    return FOREIGN_AGENT_REGION if getattr(agent, "region", None) == FOREIGN_AGENT_REGION else CHINA_AGENT_REGION


def active_agents_by_region(db: Session, stale_before: datetime | None = None) -> tuple[list[Agent], list[Agent]]:
    china_agents: list[Agent] = []
    foreign_agents: list[Agent] = []
    for agent in active_agents(db, stale_before):
        if agent_region(agent) == FOREIGN_AGENT_REGION:
            foreign_agents.append(agent)
        else:
            china_agents.append(agent)
    return china_agents, foreign_agents


def _agent_source_key(agent: Agent) -> str:
    return f"agent:{agent.id}"


def _aggregate_source_health(source_health: dict[str, str], source_keys: list[str]) -> str:
    if not source_keys:
        return "not_configured"
    statuses = [source_health.get(source_key, "unknown") for source_key in source_keys]
    if any(status == "healthy" for status in statuses):
        return "healthy"
    if any(status == "unknown" for status in statuses):
        return "unknown"
    return "unhealthy"


def _source_errors(source_errors: dict[str, str | None], source_keys: list[str]) -> str | None:
    for source_key in source_keys:
        error = source_errors.get(source_key)
        if error:
            return error
    return None


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
    if is_expanded_origin(origin):
        recalculate_expanded_origin_status(db, origin)
        return

    settings = get_settings()
    old_status = origin.status
    if not origin.enabled:
        origin.status = "disabled"
        return

    stale_before = datetime.utcnow() - timedelta(seconds=max(settings.check_interval_seconds * 3, 90))
    china_agents, foreign_agents = active_agents_by_region(db, stale_before)
    china_source_keys = [_agent_source_key(agent) for agent in china_agents]
    foreign_source_keys = [LOCAL_SOURCE, *[_agent_source_key(agent) for agent in foreign_agents]]
    required_sources = [*foreign_source_keys, *china_source_keys]
    probe_states = db.query(ProbeState).filter(ProbeState.origin_id == origin.id).all()
    states = {state.source_key: state for state in probe_states}

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

    foreign_status = _aggregate_source_health(source_health, foreign_source_keys)
    china_status = _aggregate_source_health(source_health, china_source_keys)

    if foreign_status == "healthy":
        if china_status in {"healthy", "not_configured"}:
            origin.status = "healthy"
            origin.last_error = None
        elif china_status == "unknown":
            origin.status = "unknown"
            origin.last_error = "等待国内探针探测结果"
        else:
            failed_keys = [source_key for source_key in china_source_keys if source_health.get(source_key) == "unhealthy"]
            origin.status = "blocked"
            origin.last_error = f"国外探测正常，但国内探针均不可达，疑似被墙：{', '.join(failed_keys)}"
    elif foreign_status == "unknown":
        origin.status = "unknown"
        origin.last_error = "等待本地或国外探针探测结果"
    else:
        if china_status == "healthy":
            origin.status = "regional_issue"
            origin.last_error = "国内探针正常，但本地和国外探针不可达，可能是海外线路或本地探测异常"
        elif china_status == "unknown":
            origin.status = "unknown"
            origin.last_error = "国外探测不可达，等待国内探针确认"
        elif china_status == "not_configured":
            origin.status = "unhealthy"
            origin.last_error = _source_errors(source_errors, foreign_source_keys) or "本地和国外探针均不可达"
        else:
            origin.status = "machine_down"
            origin.last_error = "国内、国外探针均不可达，疑似机器挂了"

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


def _probe_health_for_state(
    states: dict[str, ProbeState],
    source_key: str,
    stale_before: datetime,
) -> tuple[str, str | None]:
    state = states.get(source_key)
    if state is None or state.last_checked_at is None:
        return "unknown", None
    if state.last_checked_at < stale_before:
        return "unhealthy", f"{source_key} 探测结果过期"
    if state.status in {"healthy", "unhealthy"}:
        return state.status, state.last_error
    return "unknown", None


def recalculate_expanded_origin_status(db: Session, origin: Origin) -> None:
    settings = get_settings()
    old_status = origin.status
    if not origin.enabled:
        origin.status = "disabled"
        set_healthy_ips(origin, [])
        return

    ips = resolved_ips(origin)
    if not ips:
        origin.status = "unhealthy"
        origin.last_error = "展开域名未解析到 A/AAAA IP"
        set_healthy_ips(origin, [])
        return

    stale_before = datetime.utcnow() - timedelta(seconds=max(settings.check_interval_seconds * 3, 90))
    china_agents, foreign_agents = active_agents_by_region(db, stale_before)
    china_source_keys = [_agent_source_key(agent) for agent in china_agents]
    foreign_source_keys = [LOCAL_SOURCE, *[_agent_source_key(agent) for agent in foreign_agents]]
    required_sources = [*foreign_source_keys, *china_source_keys]
    probe_states = db.query(ProbeState).filter(ProbeState.origin_id == origin.id).all()
    states = {state.source_key: state for state in probe_states}

    source_healthy_ips: dict[str, set[str]] = {}
    source_unknown: dict[str, bool] = {}
    source_errors: dict[str, str | None] = {}
    for source_key in required_sources:
        healthy_for_source: set[str] = set()
        unknown_for_source = False
        for ip in ips:
            status, error = _probe_health_for_state(states, expanded_source_key(source_key, ip), stale_before)
            if status == "healthy":
                healthy_for_source.add(ip)
            elif status == "unknown":
                unknown_for_source = True
            if error and source_key not in source_errors:
                source_errors[source_key] = error
        source_healthy_ips[source_key] = healthy_for_source
        source_unknown[source_key] = unknown_for_source

    foreign_healthy = set().union(*(source_healthy_ips.get(source_key, set()) for source_key in foreign_source_keys))
    china_healthy = set().union(*(source_healthy_ips.get(source_key, set()) for source_key in china_source_keys)) if china_source_keys else set(ips)
    final_healthy = foreign_healthy & china_healthy
    set_healthy_ips(origin, sorted(final_healthy))

    foreign_status = "healthy" if foreign_healthy else ("unknown" if any(source_unknown.get(source_key) for source_key in foreign_source_keys) else "unhealthy")
    if not china_source_keys:
        china_status = "not_configured"
    else:
        china_status = "healthy" if china_healthy else ("unknown" if any(source_unknown.get(source_key) for source_key in china_source_keys) else "unhealthy")

    if final_healthy:
        origin.status = "healthy"
        origin.last_error = None
    elif foreign_status == "unknown" or china_status == "unknown":
        origin.status = "unknown"
        origin.last_error = "等待展开 IP 池的本地和探针探测结果"
    elif china_status == "not_configured":
        origin.status = "unhealthy"
        origin.last_error = _source_errors(source_errors, foreign_source_keys) or "展开 IP 池本地和国外探针均不可达"
    elif foreign_healthy and not china_healthy:
        origin.status = "blocked"
        origin.last_error = "展开 IP 池国外有可用 IP，但国内探针均不可达，疑似被墙"
    elif not foreign_healthy and china_healthy:
        origin.status = "regional_issue"
        origin.last_error = "展开 IP 池国内探针有可用 IP，但本地和国外探针不可达"
    elif foreign_healthy and china_healthy:
        origin.status = "unhealthy"
        origin.last_error = "展开 IP 池没有国内和国外同时可达的 IP"
    else:
        origin.status = "machine_down"
        origin.last_error = "展开 IP 池国内、国外探针均不可达"

    expanded_states = [
        state
        for state in probe_states
        if state.last_checked_at and split_expanded_source_key(state.source_key)[1] in set(ips)
    ]
    newest = max(expanded_states, key=lambda item: item.last_checked_at, default=None)
    if newest:
        origin.last_checked_at = newest.last_checked_at
        origin.last_rtt_ms = newest.last_rtt_ms

    if old_status != origin.status and origin.status in FINAL_ORIGIN_STATUSES:
        payload = {"origin_id": origin.id, "target": origin.target, "port": origin.port, "status": origin.status}
        add_event(
            db,
            "origin.status_changed",
            "info" if origin.status == "healthy" else "warning",
            f"展开源站 {origin.target}:{origin.port} 状态变为 {origin.status}",
            payload,
        )
        send_webhooks(db, "origin.status_changed", payload)


def refresh_expanded_origin_ips(origin: Origin) -> list[str]:
    if origin.target_type != "hostname" or getattr(origin, "publish_mode", None) != EXPANDED_PUBLISH_MODE:
        return []
    ips = resolve_hostname_ips(origin.target)
    set_resolved_ips(origin, ips)
    return ips


def run_local_checks(
    db: Session,
    group_id: int | None = None,
    origin_id: int | None = None,
    include_all: bool = False,
) -> int:
    settings = get_settings()
    query = (
        db.query(Origin)
        .options(selectinload(Origin.group).selectinload(FailoverGroup.origins))
        .join(Origin.group)
        .filter(Origin.enabled.is_(True))
    )
    if group_id is not None:
        query = query.filter(Origin.group_id == group_id)
    if origin_id is not None:
        query = query.filter(Origin.id == origin_id)
    origins = query.all()
    origins_to_check = [
        origin
        for origin in origins
        if origin.group.enabled and origin_needs_probe(origin, include_all=include_all)
    ]
    checked = 0
    check_cache = {}

    def check_once(target: str, port: int):
        nonlocal checked
        key = (target.strip().rstrip(".").lower(), int(port))
        if key not in check_cache:
            check_cache[key] = tcp_check(target, port, settings.check_timeout_seconds)
            checked += 1
        return check_cache[key]

    for origin in origins_to_check:
        if is_expanded_origin(origin):
            try:
                ips = refresh_expanded_origin_ips(origin)
            except OSError as exc:
                set_resolved_ips(origin, [])
                set_healthy_ips(origin, [])
                origin.status = "unhealthy"
                origin.last_error = f"展开域名解析失败: {exc}"
                continue
            for ip in ips:
                result = check_once(ip, origin.port)
                apply_probe_result(
                    db,
                    origin,
                    result.success,
                    result.rtt_ms,
                    result.error,
                    source_key=expanded_source_key(LOCAL_SOURCE, ip),
                    target=ip,
                    port=origin.port,
                )
            if not ips:
                recalculate_origin_status(db, origin)
            continue
        result = check_once(origin.target, origin.port)
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
    return checked


def mark_agent_online(db: Session, agent: Agent, last_ip: str | None) -> None:
    old_status = agent.status
    agent.last_seen_at = datetime.utcnow()
    agent.last_ip = last_ip
    agent.status = "online"
    if old_status != "online":
        payload = {"agent_id": agent.id, "name": agent.name, "region": agent_region(agent), "status": "online", "last_ip": agent.last_ip}
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
        payload = {
            "agent_id": agent.id,
            "name": agent.name,
            "region": agent_region(agent),
            "status": "offline",
            "last_seen_at": agent.last_seen_at.isoformat() if agent.last_seen_at else None,
        }
        add_event(db, "agent.status_changed", "warning", f"探针 {agent.name} 已离线", payload)
        send_webhooks(db, "agent.status_changed", payload)
    return len(stale_agents)
