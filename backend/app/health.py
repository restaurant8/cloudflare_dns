from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from sqlalchemy.orm import Session, selectinload

from .dns_utils import tcp_check
from .events import add_event
from .models import Agent, FailoverGroup, Origin, ProbeResult, ProbeState, TargetPoolItem, TargetPoolProbeState
from .notifier import send_webhooks
from .origin_expansion import (
    EXPANDED_PUBLISH_MODE,
    expanded_source_key,
    healthy_ips,
    is_expanded_origin,
    published_ips,
    resolve_hostname_ips,
    resolved_ips,
    set_healthy_ips,
    set_resolved_ips,
    split_expanded_source_key,
)
from .runtime_settings import get_runtime_settings


LOCAL_SOURCE = "local"
CHINA_AGENT_REGION = "china"
FOREIGN_AGENT_REGION = "foreign"
PROBE_MODE_DEFAULT = "default"
PROBE_MODE_LOCAL_ONLY = "local_only"
PROBE_MODE_CHINA_ONLY = "china_only"
PROBE_MODE_ANY = "any"
PROBE_MODES = {PROBE_MODE_DEFAULT, PROBE_MODE_LOCAL_ONLY, PROBE_MODE_CHINA_ONLY, PROBE_MODE_ANY}
ORIGIN_AVAILABLE_STATUS = "healthy"
ORIGIN_UNAVAILABLE_STATUSES = {"unhealthy", "blocked", "machine_down", "regional_issue"}
FINAL_ORIGIN_STATUSES = {ORIGIN_AVAILABLE_STATUS, *ORIGIN_UNAVAILABLE_STATUSES}


def origin_probe_mode(origin: Origin) -> str:
    mode = getattr(origin, "probe_mode", None) or PROBE_MODE_DEFAULT
    return mode if mode in PROBE_MODES else PROBE_MODE_DEFAULT


def origin_needs_probe(origin: Origin, include_all: bool = False) -> bool:
    if include_all:
        return True
    group = origin.group
    if not group or not group.enabled or not origin.enabled:
        return False
    return True


def origin_needs_local_probe(origin: Origin, include_all: bool = False) -> bool:
    if not origin_needs_probe(origin, include_all=include_all):
        return False
    return origin_probe_mode(origin) != PROBE_MODE_CHINA_ONLY


def _normalized_probe_target(target: str) -> str:
    return target.strip().rstrip(".").lower()


def origin_probe_key(origin: Origin) -> tuple[str, str, int]:
    mode = EXPANDED_PUBLISH_MODE if is_expanded_origin(origin) else "direct"
    return mode, _normalized_probe_target(origin.target), int(origin.port)


def prioritize_global_origin_checks(origins: list[Origin]) -> tuple[list[Origin], set[int]]:
    global_by_key: dict[tuple[str, str, int], Origin] = {}
    for origin in origins:
        if not origin.global_origin_id:
            continue
        key = origin_probe_key(origin)
        current = global_by_key.get(key)
        if current is None or (origin.priority, origin.id) < (current.priority, current.id):
            global_by_key[key] = origin

    global_origin_ids = {origin.id for origin in global_by_key.values()}
    covered_keys = set(global_by_key)
    global_origins = sorted(global_by_key.values(), key=lambda item: (item.priority, item.id))
    standalone_origins = [
        origin
        for origin in origins
        if origin.id not in global_origin_ids and origin_probe_key(origin) not in covered_keys
    ]
    return [*global_origins, *standalone_origins], global_origin_ids


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


def sync_probe_states_from_origin(db: Session, source: Origin, origins: list[Origin]) -> int:
    source_key = origin_probe_key(source)
    targets = [
        origin
        for origin in origins
        if origin.id != source.id
        and origin.enabled
        and origin.group
        and origin.group.enabled
        and origin_probe_key(origin) == source_key
    ]
    if not targets:
        return 0

    source_states = db.query(ProbeState).filter(ProbeState.origin_id == source.id).all()
    source_state_keys = {state.source_key for state in source_states}
    synced = 0
    for target in targets:
        if is_expanded_origin(source):
            set_resolved_ips(target, resolved_ips(source))
            set_healthy_ips(target, healthy_ips(source))
        target.status = source.status
        target.last_checked_at = source.last_checked_at
        target.last_error = source.last_error
        target.last_rtt_ms = source.last_rtt_ms

        target_states = db.query(ProbeState).filter(ProbeState.origin_id == target.id).all()
        target_states_by_key = {state.source_key: state for state in target_states}
        for stale_state in target_states:
            if stale_state.source_key not in source_state_keys:
                db.delete(stale_state)
        for source_state in source_states:
            target_state = target_states_by_key.get(source_state.source_key)
            if target_state is None:
                target_state = ProbeState(origin_id=target.id, source_key=source_state.source_key)
                db.add(target_state)
            target_state.agent_id = source_state.agent_id
            target_state.status = source_state.status
            target_state.success_count = source_state.success_count
            target_state.fail_count = source_state.fail_count
            target_state.last_checked_at = source_state.last_checked_at
            target_state.last_error = source_state.last_error
            target_state.last_rtt_ms = source_state.last_rtt_ms
        db.flush()
        recalculate_origin_status(db, target)
        synced += 1
    return synced


def _target_pool_probe_state(db: Session, item: TargetPoolItem, source_key: str, agent: Agent | None) -> TargetPoolProbeState:
    state = (
        db.query(TargetPoolProbeState)
        .filter(TargetPoolProbeState.item_id == item.id, TargetPoolProbeState.source_key == source_key)
        .one_or_none()
    )
    if state is None:
        state = TargetPoolProbeState(item_id=item.id, source_key=source_key, agent_id=agent.id if agent else None)
        db.add(state)
        db.flush()
    return state


def target_pool_stale_before(item: TargetPoolItem) -> datetime:
    interval = max(getattr(item, "check_interval_seconds", None) or 600, 60)
    return datetime.utcnow() - timedelta(seconds=max(interval * 3, 90))


def target_pool_check_due(item: TargetPoolItem, now: datetime | None = None, source_key: str = LOCAL_SOURCE) -> bool:
    if not item.enabled:
        return False
    state = next((probe_state for probe_state in item.probe_states if probe_state.source_key == source_key), None)
    if state is None or state.last_checked_at is None:
        return True
    current_time = now or datetime.utcnow()
    interval = max(getattr(item, "check_interval_seconds", None) or 600, 60)
    return state.last_checked_at <= current_time - timedelta(seconds=interval)


def active_agents(db: Session, stale_before: datetime | None = None) -> list[Agent]:
    settings = get_runtime_settings(db)
    cutoff = stale_before or datetime.utcnow() - timedelta(seconds=max(settings.check_interval_seconds * 3, 90))
    return (
        db.query(Agent)
        .filter(Agent.enabled.is_(True), Agent.status == "online")
        .filter(Agent.last_seen_at.is_not(None), Agent.last_seen_at >= cutoff)
        .order_by(Agent.created_at.asc(), Agent.id.asc())
        .all()
    )


def default_agent_chain(
    db: Session,
    stale_before: datetime | None = None,
    include_inactive_default: bool = False,
) -> list[Agent] | None:
    configured_default = (
        db.query(Agent)
        .filter(Agent.enabled.is_(True), Agent.is_default.is_(True))
        .order_by(Agent.created_at.asc(), Agent.id.asc())
        .first()
    )
    if configured_default is None:
        return None

    agents = active_agents(db, stale_before)
    active_default = next((agent for agent in agents if agent.id == configured_default.id), None)
    if active_default is not None:
        return [active_default, *[agent for agent in agents if agent.id != active_default.id]]
    if agents:
        return agents
    return [configured_default] if include_inactive_default else []


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


def _probe_health_for_state(
    states: dict[str, ProbeState],
    source_key: str,
    stale_before: datetime,
) -> tuple[str, str | None]:
    state = states.get(source_key)
    if state is None or state.last_checked_at is None:
        return "unknown", None
    if state.last_checked_at < stale_before:
        return "unknown", f"{source_key} 探测结果过期，等待新结果"
    if state.status in {"healthy", "unhealthy"}:
        return state.status, state.last_error
    return "unknown", None


def _selected_agent_source_keys(
    agents: list[Agent],
    states: dict[str, ProbeState],
    stale_before: datetime,
    target: str | None = None,
) -> list[str]:
    selected: list[str] = []
    for agent in agents:
        source_key = _agent_source_key(agent)
        selected.append(source_key)
        state_key = expanded_source_key(source_key, target) if target else source_key
        status, _ = _probe_health_for_state(states, state_key, stale_before)
        if status != "unhealthy":
            break
    return selected


def _origin_remote_agent_source_keys(
    db: Session,
    origin: Origin,
    states: dict[str, ProbeState],
    stale_before: datetime,
    target: str | None = None,
) -> list[str] | None:
    if origin.preferred_agent_id:
        agent = db.get(Agent, origin.preferred_agent_id)
        if agent is None or not agent.enabled:
            return []
        return _selected_agent_source_keys([agent], states, stale_before, target)

    chain = default_agent_chain(db, stale_before, include_inactive_default=True)
    if chain is None:
        return None
    return _selected_agent_source_keys(chain, states, stale_before, target)


def _origin_china_agent_source_keys(
    db: Session,
    origin: Origin,
    states: dict[str, ProbeState],
    stale_before: datetime,
    target: str | None = None,
) -> list[str]:
    if origin.preferred_agent_id:
        return _origin_remote_agent_source_keys(db, origin, states, stale_before, target) or []
    china_agents, _ = active_agents_by_region(db, stale_before)
    return _selected_agent_source_keys(china_agents, states, stale_before, target)


def _probe_mode_source_keys(
    db: Session,
    origin: Origin,
    states: dict[str, ProbeState],
    stale_before: datetime,
    target: str | None = None,
) -> list[str] | None:
    mode = origin_probe_mode(origin)
    if mode == PROBE_MODE_DEFAULT:
        return None
    if mode == PROBE_MODE_LOCAL_ONLY:
        return [LOCAL_SOURCE]
    china_source_keys = _origin_china_agent_source_keys(db, origin, states, stale_before, target)
    if mode == PROBE_MODE_CHINA_ONLY:
        return china_source_keys
    if mode == PROBE_MODE_ANY:
        return [LOCAL_SOURCE, *china_source_keys]
    return None


def _aggregate_probe_state_keys(
    states: dict[str, ProbeState],
    source_keys: list[str],
    stale_before: datetime,
) -> tuple[str, str | None]:
    if not source_keys:
        return "not_configured", None
    has_unknown = False
    first_error: str | None = None
    for source_key in source_keys:
        status, error = _probe_health_for_state(states, source_key, stale_before)
        if status == "healthy":
            return "healthy", None
        if status == "unknown":
            has_unknown = True
        if error and first_error is None:
            first_error = error
    if has_unknown:
        return "unknown", first_error
    return "unhealthy", first_error


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
    settings = get_runtime_settings(db)
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


def apply_target_pool_probe_result(
    db: Session,
    item: TargetPoolItem,
    success: bool,
    rtt_ms: float | None,
    error: str | None,
    source_key: str = LOCAL_SOURCE,
    agent: Agent | None = None,
) -> None:
    settings = get_runtime_settings(db)
    now = datetime.utcnow()
    state = _target_pool_probe_state(db, item, source_key, agent)
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
    recalculate_target_pool_status(db, item)


def recalculate_origin_status(db: Session, origin: Origin) -> None:
    if is_expanded_origin(origin):
        recalculate_expanded_origin_status(db, origin)
        return

    settings = get_runtime_settings(db)
    old_status = origin.status
    if not origin.enabled:
        origin.status = "disabled"
        return

    stale_before = datetime.utcnow() - timedelta(seconds=max(settings.check_interval_seconds * 3, 90))
    probe_states = db.query(ProbeState).filter(ProbeState.origin_id == origin.id).all()
    states = {state.source_key: state for state in probe_states}
    probe_mode_source_keys = _probe_mode_source_keys(db, origin, states, stale_before)
    if probe_mode_source_keys is not None:
        mode_status, mode_error = _aggregate_probe_state_keys(states, probe_mode_source_keys, stale_before)
        if not probe_mode_source_keys:
            origin.status = "unknown"
            origin.last_error = "没有可用的国内探针"
        elif mode_status == "healthy":
            origin.status = "healthy"
            origin.last_error = None
        elif mode_status == "unknown":
            origin.status = "unknown"
            origin.last_error = mode_error or "等待所选探针策略的检测结果"
        else:
            origin.status = "machine_down" if origin_probe_mode(origin) == PROBE_MODE_ANY and len(probe_mode_source_keys) > 1 else "unhealthy"
            origin.last_error = mode_error or "所选探针策略下目标不可达"

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
        return

    remote_source_keys = _origin_remote_agent_source_keys(db, origin, states, stale_before)
    if remote_source_keys is None:
        china_agents, foreign_agents = active_agents_by_region(db, stale_before)
        china_source_keys = _selected_agent_source_keys(china_agents, states, stale_before)
        foreign_source_keys = [LOCAL_SOURCE, *_selected_agent_source_keys(foreign_agents, states, stale_before)]
    else:
        china_source_keys = remote_source_keys
        foreign_source_keys = [LOCAL_SOURCE]
    required_sources = [*foreign_source_keys, *china_source_keys]

    source_health: dict[str, str] = {}
    source_errors: dict[str, str | None] = {}
    for source_key in required_sources:
        status, error = _probe_health_for_state(states, source_key, stale_before)
        source_health[source_key] = status
        source_errors[source_key] = error

    foreign_status = _aggregate_source_health(source_health, foreign_source_keys)
    china_status = _aggregate_source_health(source_health, china_source_keys)

    # China-first semantics: an origin serves China traffic, so it counts as
    # healthy as soon as the China probes reach it — even if local/foreign probes
    # fail. This deliberately differs from target-pool items, which keep a
    # foreign-first view (they are candidate IPs being scouted, and the panel
    # itself cannot verify them when only China can connect).
    if china_status == "healthy":
        origin.status = "healthy"
        origin.last_error = None
    elif foreign_status == "healthy":
        if china_status == "not_configured":
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
        # china_status == "healthy" is impossible here (handled at the top), so the
        # remaining cases are: waiting for China probes, no China probes configured,
        # or everything down.
        if china_status == "unknown":
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


def copy_target_pool_status_from_matching_origin(db: Session, item: TargetPoolItem) -> bool:
    interval = max(getattr(item, "check_interval_seconds", None) or 600, 60)
    fresh_after = datetime.utcnow() - timedelta(seconds=interval)
    newest = (
        db.query(Origin)
        .join(Origin.group)
        .filter(Origin.enabled.is_(True), FailoverGroup.enabled.is_(True), Origin.last_checked_at.is_not(None), Origin.port == item.port, Origin.target == item.target)
        .order_by(Origin.last_checked_at.desc(), Origin.id.desc())
        .first()
    )
    if newest is None or newest.last_checked_at is None:
        return False
    if newest.last_checked_at < fresh_after:
        return False
    item.status = newest.status
    item.last_checked_at = newest.last_checked_at
    item.last_error = newest.last_error
    item.last_rtt_ms = newest.last_rtt_ms
    copied_states = False
    for origin_state in newest.probe_states:
        if origin_state.last_checked_at is None:
            continue
        state = _target_pool_probe_state(db, item, origin_state.source_key, origin_state.agent)
        state.agent_id = origin_state.agent_id
        state.status = origin_state.status
        state.success_count = origin_state.success_count
        state.fail_count = origin_state.fail_count
        state.last_checked_at = origin_state.last_checked_at
        state.last_error = origin_state.last_error
        state.last_rtt_ms = origin_state.last_rtt_ms
        copied_states = True
    if copied_states:
        recalculate_target_pool_status(db, item)
    return True


def recalculate_target_pool_status(db: Session, item: TargetPoolItem) -> None:
    if not item.enabled:
        item.status = "disabled"
        return

    stale_before = target_pool_stale_before(item)
    china_agents, foreign_agents = active_agents_by_region(db, stale_before)
    probe_states = db.query(TargetPoolProbeState).filter(TargetPoolProbeState.item_id == item.id).all()
    states = {state.source_key: state for state in probe_states}
    china_source_keys = _selected_agent_source_keys(china_agents, states, stale_before)
    foreign_source_keys = [LOCAL_SOURCE, *_selected_agent_source_keys(foreign_agents, states, stale_before)]

    source_health: dict[str, str] = {}
    source_errors: dict[str, str | None] = {}
    for source_key in [*foreign_source_keys, *china_source_keys]:
        status, error = _probe_health_for_state(states, source_key, stale_before)
        source_health[source_key] = status
        source_errors[source_key] = error

    foreign_status = _aggregate_source_health(source_health, foreign_source_keys)
    china_status = _aggregate_source_health(source_health, china_source_keys)

    if foreign_status == "healthy":
        if china_status in {"healthy", "not_configured"}:
            item.status = "healthy"
            item.last_error = None
        elif china_status == "unknown":
            item.status = "unknown"
            item.last_error = "等待国内探针探测结果"
        else:
            item.status = "blocked"
            item.last_error = "国外探测正常，但国内探针不可达，疑似被墙"
    elif foreign_status == "unknown":
        item.status = "unknown"
        item.last_error = "等待本地或国外探针探测结果"
    else:
        if china_status == "healthy":
            item.status = "regional_issue"
            item.last_error = "国内探针正常，但本地和国外探针不可达"
        elif china_status == "unknown":
            item.status = "unknown"
            item.last_error = "国外探测不可达，等待国内探针确认"
        elif china_status == "not_configured":
            item.status = "unhealthy"
            item.last_error = _source_errors(source_errors, foreign_source_keys) or "本地和国外探针均不可达"
        else:
            item.status = "machine_down"
            item.last_error = "国内、国外探针均不可达"

    newest = max((state for state in probe_states if state.last_checked_at), key=lambda state: state.last_checked_at, default=None)
    if newest:
        item.last_checked_at = newest.last_checked_at
        item.last_rtt_ms = newest.last_rtt_ms
        if item.status == "healthy":
            item.last_error = None


def recalculate_expanded_origin_status(db: Session, origin: Origin) -> None:
    settings = get_runtime_settings(db)
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
    probe_states = db.query(ProbeState).filter(ProbeState.origin_id == origin.id).all()
    states = {state.source_key: state for state in probe_states}
    if origin_probe_mode(origin) != PROBE_MODE_DEFAULT:
        healthy: set[str] = set()
        has_unknown = False
        source_configured = False
        first_error: str | None = None
        for ip in ips:
            source_keys = _probe_mode_source_keys(db, origin, states, stale_before, ip) or []
            if source_keys:
                source_configured = True
            state_keys = [expanded_source_key(source_key, ip) for source_key in source_keys]
            ip_status, ip_error = _aggregate_probe_state_keys(states, state_keys, stale_before)
            if ip_status == "healthy":
                healthy.add(ip)
            elif ip_status == "unknown":
                has_unknown = True
            if ip_error and first_error is None:
                first_error = ip_error

        set_healthy_ips(origin, sorted(healthy))
        if healthy:
            origin.status = "healthy"
            origin.last_error = None
        elif not source_configured:
            origin.status = "unknown"
            origin.last_error = "没有可用的国内探针"
        elif has_unknown:
            origin.status = "unknown"
            origin.last_error = first_error or "等待展开 IP 池的所选探针策略检测结果"
        else:
            origin.status = "machine_down" if origin_probe_mode(origin) == PROBE_MODE_ANY else "unhealthy"
            origin.last_error = first_error or "展开 IP 池在所选探针策略下均不可达"

        ips_set = set(ips)
        expanded_states = [
            state
            for state in probe_states
            if state.last_checked_at and split_expanded_source_key(state.source_key)[1] in ips_set
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
        return

    remote_mode = _origin_remote_agent_source_keys(db, origin, states, stale_before) is not None
    if remote_mode:
        china_agents: list[Agent] = []
        foreign_agents: list[Agent] = []
    else:
        china_agents, foreign_agents = active_agents_by_region(db, stale_before)

    source_errors: dict[str, str | None] = {}
    foreign_healthy: set[str] = set()
    china_healthy: set[str] = set(ips) if not remote_mode and not china_agents else set()
    foreign_unknown = False
    china_unknown = False
    remote_probe_configured = False
    for ip in ips:
        foreign_source_keys = [LOCAL_SOURCE] if remote_mode else [LOCAL_SOURCE, *_selected_agent_source_keys(foreign_agents, states, stale_before, ip)]
        foreign_state_keys = [expanded_source_key(source_key, ip) for source_key in foreign_source_keys]
        foreign_ip_status, foreign_error = _aggregate_probe_state_keys(states, foreign_state_keys, stale_before)
        if foreign_ip_status == "healthy":
            foreign_healthy.add(ip)
        elif foreign_ip_status == "unknown":
            foreign_unknown = True
        if foreign_error and "foreign" not in source_errors:
            source_errors["foreign"] = foreign_error

        if remote_mode:
            china_source_keys = _origin_remote_agent_source_keys(db, origin, states, stale_before, ip) or []
        else:
            china_source_keys = _selected_agent_source_keys(china_agents, states, stale_before, ip)
        if china_source_keys:
            remote_probe_configured = True
            china_state_keys = [expanded_source_key(source_key, ip) for source_key in china_source_keys]
            china_ip_status, china_error = _aggregate_probe_state_keys(states, china_state_keys, stale_before)
            if china_ip_status == "healthy":
                china_healthy.add(ip)
            elif china_ip_status == "unknown":
                china_unknown = True
            if china_error and "china" not in source_errors:
                source_errors["china"] = china_error

    final_healthy = china_healthy if remote_mode or china_agents else foreign_healthy
    set_healthy_ips(origin, sorted(final_healthy))

    foreign_status = "healthy" if foreign_healthy else ("unknown" if foreign_unknown else "unhealthy")
    if remote_mode:
        china_status = "healthy" if china_healthy else ("unknown" if china_unknown else ("unhealthy" if remote_probe_configured else "not_configured"))
    elif not china_agents:
        china_status = "not_configured"
    else:
        china_status = "healthy" if china_healthy else ("unknown" if china_unknown else "unhealthy")

    if final_healthy:
        origin.status = "healthy"
        origin.last_error = None
    elif foreign_status == "unknown" or china_status == "unknown":
        origin.status = "unknown"
        origin.last_error = "等待展开 IP 池的本地和探针探测结果"
    elif china_status == "not_configured":
        origin.status = "unhealthy"
        origin.last_error = source_errors.get("foreign") or "展开 IP 池本地和国外探针均不可达"
    elif foreign_healthy:
        # China probes are configured but reach no IP while foreign probes do —
        # the pool is effectively blocked. (china_healthy is always empty here:
        # with China probes configured, final_healthy == china_healthy.)
        origin.status = "blocked"
        origin.last_error = "展开 IP 池国外有可用 IP，但国内探针均不可达，疑似被墙"
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
    ips = sorted(set(ips + published_ips(origin)))
    set_resolved_ips(origin, ips)
    return ips


def run_local_checks(
    db: Session,
    group_id: int | None = None,
    origin_id: int | None = None,
    include_all: bool = False,
    check_cache: dict[tuple[str, int], object] | None = None,
) -> int:
    settings = get_runtime_settings(db)
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
        if origin.group.enabled and origin_needs_local_probe(origin, include_all=include_all)
    ]
    origins_to_probe, global_origin_ids = prioritize_global_origin_checks(origins_to_check)
    checked = 0
    if check_cache is None:
        check_cache = {}

    def check_once(target: str, port: int):
        nonlocal checked
        key = (target.strip().rstrip(".").lower(), int(port))
        if key not in check_cache:
            check_cache[key] = tcp_check(target, port, settings.check_timeout_seconds)
            checked += 1
        return check_cache[key]

    def sync_if_global(origin: Origin) -> None:
        if origin.id in global_origin_ids:
            sync_probe_states_from_origin(db, origin, origins_to_check)

    # Pre-probe every direct (non-expanded) target concurrently so the sequential
    # evaluation below never blocks on TCP I/O. These results are keyed by
    # (target, port) exactly like check_once, so the loop reuses them verbatim and
    # the outcome — probe results, `checked` count, and apply_probe_result order —
    # is identical to probing inline. Expanded origins still resolve+probe inside
    # the loop to avoid resolving DNS twice.
    prefetch_keys: dict[tuple[str, int], tuple[str, int]] = {}
    for origin in origins_to_probe:
        if is_expanded_origin(origin):
            continue
        key = (origin.target.strip().rstrip(".").lower(), int(origin.port))
        if key not in check_cache and key not in prefetch_keys:
            prefetch_keys[key] = (origin.target, origin.port)
    if prefetch_keys:
        with ThreadPoolExecutor(max_workers=min(len(prefetch_keys), 16)) as executor:
            futures = {
                key: executor.submit(tcp_check, target, port, settings.check_timeout_seconds)
                for key, (target, port) in prefetch_keys.items()
            }
            for key, future in futures.items():
                check_cache[key] = future.result()
                checked += 1

    for origin in origins_to_probe:
        if is_expanded_origin(origin):
            try:
                ips = refresh_expanded_origin_ips(origin)
            except OSError as exc:
                set_resolved_ips(origin, [])
                set_healthy_ips(origin, [])
                origin.status = "unhealthy"
                origin.last_error = f"展开域名解析失败: {exc}"
                sync_if_global(origin)
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
            sync_if_global(origin)
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
        sync_if_global(origin)
    return checked


def run_target_pool_checks(
    db: Session,
    item_id: int | None = None,
    include_all: bool = False,
    check_cache: dict[tuple[str, int], object] | None = None,
) -> int:
    settings = get_runtime_settings(db)
    query = db.query(TargetPoolItem).filter(TargetPoolItem.enabled.is_(True))
    if item_id is not None:
        query = query.filter(TargetPoolItem.id == item_id)
    items = query.all()
    checked = 0
    now = datetime.utcnow()
    if check_cache is None:
        check_cache = {}

    def check_once(target: str, port: int):
        nonlocal checked
        key = (target.strip().rstrip(".").lower(), int(port))
        if key not in check_cache:
            check_cache[key] = tcp_check(target, port, settings.check_timeout_seconds)
            checked += 1
        return check_cache[key]

    for item in items:
        if not include_all and copy_target_pool_status_from_matching_origin(db, item):
            continue
        if not include_all and not target_pool_check_due(item, now):
            continue
        result = check_once(item.target, item.port)
        apply_target_pool_probe_result(db, item, result.success, result.rtt_ms, result.error, source_key=LOCAL_SOURCE)
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
    settings = get_runtime_settings(db)
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
