import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session, selectinload

from ..agent_installer import build_install_script
from ..database import get_db
from ..deps import get_agent, get_current_user
from ..health import (
    active_agents,
    agent_region,
    apply_probe_result,
    mark_agent_online,
    origin_needs_probe,
    prioritize_global_origin_checks,
    refresh_expanded_origin_ips,
    sync_probe_states_from_origin,
)
from ..models import Agent, FailoverGroup, Origin, User
from ..origin_expansion import expanded_source_key, is_expanded_origin, resolved_ips
from ..request_utils import client_ip_from_request
from ..runtime_settings import get_runtime_settings
from ..schemas import AgentCreate, AgentCreated, AgentOut, AgentResultsIn, AgentTasksResponse, AgentTask, AgentUpdate, Message
from ..security import hash_token


router = APIRouter(tags=["agents"])


def _normalized_probe_target(target: str) -> str:
    return target.strip().rstrip(".").lower()


def _probe_key(target: str, port: int) -> tuple[str, int]:
    return _normalized_probe_target(target), int(port)


def _agent_source_key(agent: Agent) -> str:
    return f"agent:{agent.id}"


def _probe_status_for_agent(origin: Origin, agent: Agent, stale_before: datetime, target: str | None = None) -> str:
    source_key = _agent_source_key(agent)
    if target is not None:
        source_key = expanded_source_key(source_key, target)
    state = next((probe_state for probe_state in origin.probe_states if probe_state.source_key == source_key), None)
    if state is None or state.last_checked_at is None:
        return "unknown"
    if state.last_checked_at < stale_before:
        return "unhealthy"
    return state.status if state.status in {"healthy", "unhealthy"} else "unknown"


def _same_region_agents_by_region(agents: list[Agent]) -> dict[str, list[Agent]]:
    grouped: dict[str, list[Agent]] = {}
    for item in agents:
        grouped.setdefault(agent_region(item), []).append(item)
    return grouped


def _should_agent_probe_target(agent: Agent, same_region_agents: list[Agent], origin: Origin, stale_before: datetime, target: str | None = None) -> bool:
    try:
        agent_index = next(index for index, item in enumerate(same_region_agents) if item.id == agent.id)
    except StopIteration:
        return False
    for previous_agent in same_region_agents[:agent_index]:
        if _probe_status_for_agent(origin, previous_agent, stale_before, target) != "unhealthy":
            return False
    return True


def _matching_origins_for_probe(origins: list[Origin], target: str, port: int) -> list[Origin]:
    matches: list[Origin] = []
    normalized_target = _normalized_probe_target(target)
    for origin in origins:
        if not origin.group.enabled:
            continue
        if origin.port != port:
            continue
        if is_expanded_origin(origin):
            if any(_normalized_probe_target(ip) == normalized_target for ip in resolved_ips(origin)):
                matches.append(origin)
            continue
        if _normalized_probe_target(origin.target) == normalized_target:
            matches.append(origin)
    return matches


@router.get("/agent/install.sh", response_class=PlainTextResponse)
def agent_install_script():
    return PlainTextResponse(build_install_script(), media_type="text/x-shellscript; charset=utf-8")


@router.get("/agents", response_model=list[AgentOut])
def list_agents(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Agent).order_by(Agent.region.asc(), Agent.created_at.asc(), Agent.id.asc()).all()


@router.post("/agents", response_model=AgentCreated)
def create_agent(payload: AgentCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    token = secrets.token_urlsafe(32)
    agent = Agent(name=payload.name, region=payload.region, token_hash=hash_token(token), status="unknown")
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return AgentCreated(agent=agent, token=token)


@router.patch("/agents/{agent_id}", response_model=AgentOut)
def update_agent(agent_id: int, payload: AgentUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="探针不存在")
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="探针名称不能为空")
    agent.name = name
    db.commit()
    db.refresh(agent)
    return agent


@router.patch("/agents/{agent_id}/disable", response_model=AgentOut)
def disable_agent(agent_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="探针不存在")
    agent.enabled = False
    agent.status = "disabled"
    db.commit()
    db.refresh(agent)
    return agent


@router.patch("/agents/{agent_id}/enable", response_model=AgentOut)
def enable_agent(agent_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="探针不存在")
    agent.enabled = True
    if agent.status == "disabled":
        agent.status = "unknown"
    db.commit()
    db.refresh(agent)
    return agent


@router.delete("/agents/{agent_id}", response_model=Message)
def delete_agent(agent_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="探针不存在")
    db.delete(agent)
    db.commit()
    return Message(message="探针已删除")


@router.get("/agent/tasks", response_model=AgentTasksResponse)
def agent_tasks(request: Request, agent: Agent = Depends(get_agent), db: Session = Depends(get_db)):
    settings = get_runtime_settings(db)
    mark_agent_online(db, agent, client_ip_from_request(request))
    origins = (
        db.query(Origin)
        .options(selectinload(Origin.group).selectinload(FailoverGroup.origins), selectinload(Origin.probe_states))
        .join(Origin.group)
        .filter(Origin.enabled.is_(True))
        .all()
    )
    stale_before = datetime.utcnow() - timedelta(seconds=max(settings.check_interval_seconds * 3, 90))
    agents_by_region = _same_region_agents_by_region(active_agents(db, stale_before))
    same_region_agents = agents_by_region.get(agent_region(agent), [])
    tasks = []
    task_keys: set[tuple[str, int]] = set()

    def add_task(origin_id: int, target: str, port: int) -> None:
        key = _probe_key(target, port)
        if key in task_keys:
            return
        task_keys.add(key)
        tasks.append(AgentTask(origin_id=origin_id, target=target, port=port, timeout_seconds=settings.check_timeout_seconds))

    origin_candidates = [
        origin
        for origin in origins
        if origin.group.enabled and origin_needs_probe(origin)
    ]
    origins_to_probe, _ = prioritize_global_origin_checks(origin_candidates)

    for origin in origins_to_probe:
        if is_expanded_origin(origin):
            try:
                ips = refresh_expanded_origin_ips(origin)
            except OSError:
                ips = resolved_ips(origin)
            for ip in ips:
                if _should_agent_probe_target(agent, same_region_agents, origin, stale_before, ip):
                    add_task(origin.id, ip, origin.port)
            continue
        if _should_agent_probe_target(agent, same_region_agents, origin, stale_before):
            add_task(origin.id, origin.target, origin.port)
    db.commit()
    return AgentTasksResponse(interval_seconds=settings.check_interval_seconds, tasks=tasks)


@router.post("/agent/results", response_model=Message)
def agent_results(payload: AgentResultsIn, request: Request, agent: Agent = Depends(get_agent), db: Session = Depends(get_db)):
    mark_agent_online(db, agent, client_ip_from_request(request))
    origins = (
        db.query(Origin)
        .options(selectinload(Origin.group).selectinload(FailoverGroup.origins))
        .join(Origin.group)
        .filter(Origin.enabled.is_(True))
        .all()
    )
    processed_keys: set[tuple[str, int]] = set()
    for item in payload.results:
        key = _probe_key(item.target, item.port)
        if key in processed_keys:
            continue
        processed_keys.add(key)
        matched_origins = _matching_origins_for_probe(origins, item.target, item.port)
        for origin in matched_origins:
            source_key = f"agent:{agent.id}"
            if is_expanded_origin(origin):
                source_key = expanded_source_key(source_key, item.target)
            apply_probe_result(
                db,
                origin,
                item.success,
                item.rtt_ms,
                item.error,
                source_key=source_key,
                agent=agent,
                target=item.target,
                port=item.port,
            )
        for origin in matched_origins:
            if origin.global_origin_id:
                sync_probe_states_from_origin(db, origin, origins)
    db.commit()
    return Message(message="探测结果已接收")
