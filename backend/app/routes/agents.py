import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session, selectinload

from ..agent_installer import build_install_script
from ..config import get_settings
from ..database import get_db
from ..deps import get_agent, get_current_user
from ..health import apply_probe_result, mark_agent_online, origin_needs_probe, refresh_expanded_origin_ips
from ..models import Agent, FailoverGroup, Origin, User
from ..origin_expansion import expanded_source_key, is_expanded_origin, resolved_ips
from ..request_utils import client_ip_from_request
from ..schemas import AgentCreate, AgentCreated, AgentOut, AgentResultsIn, AgentTasksResponse, AgentTask, Message
from ..security import hash_token


router = APIRouter(tags=["agents"])


@router.get("/agent/install.sh", response_class=PlainTextResponse)
def agent_install_script():
    return PlainTextResponse(build_install_script(), media_type="text/x-shellscript; charset=utf-8")


@router.get("/agents", response_model=list[AgentOut])
def list_agents(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Agent).order_by(Agent.created_at.desc()).all()


@router.post("/agents", response_model=AgentCreated)
def create_agent(payload: AgentCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    token = secrets.token_urlsafe(32)
    agent = Agent(name=payload.name, region=payload.region, token_hash=hash_token(token), status="unknown")
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return AgentCreated(agent=agent, token=token)


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
    settings = get_settings()
    mark_agent_online(db, agent, client_ip_from_request(request))
    origins = (
        db.query(Origin)
        .options(selectinload(Origin.group).selectinload(FailoverGroup.origins))
        .join(Origin.group)
        .filter(Origin.enabled.is_(True))
        .all()
    )
    tasks = []
    for origin in origins:
        if not origin.group.enabled or not origin_needs_probe(origin):
            continue
        if is_expanded_origin(origin):
            try:
                ips = refresh_expanded_origin_ips(origin)
            except OSError:
                ips = resolved_ips(origin)
            tasks.extend(
                AgentTask(origin_id=origin.id, target=ip, port=origin.port, timeout_seconds=settings.check_timeout_seconds)
                for ip in ips
            )
            continue
        tasks.append(AgentTask(origin_id=origin.id, target=origin.target, port=origin.port, timeout_seconds=settings.check_timeout_seconds))
    db.commit()
    return AgentTasksResponse(interval_seconds=settings.check_interval_seconds, tasks=tasks)


@router.post("/agent/results", response_model=Message)
def agent_results(payload: AgentResultsIn, request: Request, agent: Agent = Depends(get_agent), db: Session = Depends(get_db)):
    mark_agent_online(db, agent, client_ip_from_request(request))
    for item in payload.results:
        origin = db.get(Origin, item.origin_id)
        if origin is None:
            continue
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
    db.commit()
    return Message(message="探测结果已接收")
