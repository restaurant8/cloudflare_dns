from datetime import datetime
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import Agent, CloudflareCredential, FailoverGroup, Origin, ProbeResult, ProbeState, Zone
from app.routes.agents import agent_results, agent_tasks
from app.schemas import AgentResultIn, AgentResultsIn
from app.security import encrypt_secret


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def request(headers=None, client_host="127.0.0.1"):
    return SimpleNamespace(headers=headers or {}, client=SimpleNamespace(host=client_host))


def make_group_with_duplicate_origins(db):
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.flush()
    current = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=443, priority=1)
    backup = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=443, priority=2)
    agent = Agent(name="china", region="china", token_hash="hash", status="online", last_seen_at=datetime.utcnow())
    db.add_all([current, backup, agent])
    db.commit()
    db.refresh(current)
    db.refresh(backup)
    db.refresh(agent)
    return current, backup, agent


def test_agent_tasks_reuses_duplicate_targets():
    db = make_session()
    current, backup, agent = make_group_with_duplicate_origins(db)

    response = agent_tasks(request(), agent=agent, db=db)

    assert len(response.tasks) == 1
    assert response.tasks[0].origin_id == current.id
    assert response.tasks[0].target == current.target
    assert response.tasks[0].port == current.port == backup.port


def test_agent_results_apply_duplicate_target_to_all_matching_origins():
    db = make_session()
    current, backup, agent = make_group_with_duplicate_origins(db)

    payload = AgentResultsIn(
        results=[
            AgentResultIn(
                origin_id=current.id,
                target=current.target,
                port=current.port,
                success=True,
                rtt_ms=8.5,
            )
        ]
    )

    agent_results(payload, request(), agent=agent, db=db)

    states = db.query(ProbeState).filter(ProbeState.origin_id.in_([current.id, backup.id])).all()
    results = db.query(ProbeResult).filter(ProbeResult.origin_id.in_([current.id, backup.id])).all()

    assert {state.origin_id for state in states} == {current.id, backup.id}
    assert {result.origin_id for result in results} == {current.id, backup.id}
