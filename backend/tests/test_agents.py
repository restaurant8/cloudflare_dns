from datetime import datetime
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import Agent, CloudflareCredential, FailoverGroup, Origin, ProbeResult, ProbeState, TargetPoolItem, Zone
from app.routes.agents import agent_results, agent_tasks, update_agent
from app.schemas import AgentResultIn, AgentResultsIn, AgentUpdate
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


def test_update_agent_renames_probe():
    db = make_session()
    _, _, agent = make_group_with_duplicate_origins(db)

    response = update_agent(agent.id, AgentUpdate(name="  mainland probe  "), _=SimpleNamespace(), db=db)

    assert response.name == "mainland probe"
    assert db.get(Agent, agent.id).name == "mainland probe"


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


def test_agent_tasks_only_use_first_same_region_probe_until_it_fails():
    db = make_session()
    current, _, primary_agent = make_group_with_duplicate_origins(db)
    secondary_agent = Agent(name="china-2", region="china", token_hash="hash-2", status="online", last_seen_at=datetime.utcnow())
    db.add(secondary_agent)
    db.commit()
    db.refresh(secondary_agent)

    primary_response = agent_tasks(request(), agent=primary_agent, db=db)
    secondary_response = agent_tasks(request(), agent=secondary_agent, db=db)

    assert len(primary_response.tasks) == 1
    assert primary_response.tasks[0].target == current.target
    assert secondary_response.tasks == []


def test_agent_tasks_use_second_same_region_probe_after_first_fails():
    db = make_session()
    current, _, primary_agent = make_group_with_duplicate_origins(db)
    secondary_agent = Agent(name="china-2", region="china", token_hash="hash-2", status="online", last_seen_at=datetime.utcnow())
    db.add(secondary_agent)
    db.commit()
    db.refresh(secondary_agent)
    db.add(
        ProbeState(
            origin_id=current.id,
            source_key=f"agent:{primary_agent.id}",
            status="unhealthy",
            last_checked_at=datetime.utcnow(),
            last_error="connect failed",
        )
    )
    db.commit()

    response = agent_tasks(request(), agent=secondary_agent, db=db)

    assert len(response.tasks) == 1
    assert response.tasks[0].target == current.target


def test_china_agent_tasks_include_all_enabled_origins_when_current_is_lower_priority():
    db = make_session()
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.flush()
    primary = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=443, priority=1)
    current = Origin(group_id=group.id, target="192.0.2.20", target_type="ipv4", port=443, priority=5, status="healthy")
    later_backup = Origin(group_id=group.id, target="192.0.2.30", target_type="ipv4", port=443, priority=10)
    agent = Agent(name="china", region="china", token_hash="hash", status="online", last_seen_at=datetime.utcnow())
    db.add_all([primary, current, later_backup, agent])
    db.flush()
    group.current_origin_id = current.id
    db.commit()

    response = agent_tasks(request(), agent=agent, db=db)

    assert {(task.target, task.port) for task in response.tasks} == {
        ("192.0.2.10", 443),
        ("192.0.2.20", 443),
        ("192.0.2.30", 443),
    }


def test_china_agent_tasks_include_backup_when_current_is_best_priority():
    db = make_session()
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.flush()
    current = Origin(group_id=group.id, target="192.0.2.20", target_type="ipv4", port=443, priority=1)
    backup = Origin(group_id=group.id, target="192.0.2.30", target_type="ipv4", port=443, priority=10)
    agent = Agent(name="china", region="china", token_hash="hash", status="online", last_seen_at=datetime.utcnow())
    db.add_all([current, backup, agent])
    db.flush()
    group.current_origin_id = current.id
    db.commit()

    response = agent_tasks(request(), agent=agent, db=db)

    assert {(task.target, task.port) for task in response.tasks} == {
        ("192.0.2.20", 443),
        ("192.0.2.30", 443),
    }


def test_china_agent_tasks_include_all_enabled_origins_when_current_is_unhealthy():
    db = make_session()
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.flush()
    primary = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=443, priority=1)
    current = Origin(group_id=group.id, target="192.0.2.20", target_type="ipv4", port=443, priority=5, status="machine_down")
    later_backup = Origin(group_id=group.id, target="192.0.2.30", target_type="ipv4", port=443, priority=10)
    agent = Agent(name="china", region="china", token_hash="hash", status="online", last_seen_at=datetime.utcnow())
    db.add_all([primary, current, later_backup, agent])
    db.flush()
    group.current_origin_id = current.id
    db.commit()

    response = agent_tasks(request(), agent=agent, db=db)

    assert {(task.target, task.port) for task in response.tasks} == {
        ("192.0.2.10", 443),
        ("192.0.2.20", 443),
        ("192.0.2.30", 443),
    }


def test_agent_tasks_skip_target_pool_items():
    db = make_session()
    china_agent = Agent(name="china", region="china", token_hash="hash", status="online", last_seen_at=datetime.utcnow())
    foreign_agent = Agent(name="foreign", region="foreign", token_hash="hash-2", status="online", last_seen_at=datetime.utcnow())
    pool_item = TargetPoolItem(target="198.51.100.10", target_type="ipv4", port=22, enabled=True)
    db.add_all([china_agent, foreign_agent, pool_item])
    db.commit()

    china_response = agent_tasks(request(), agent=china_agent, db=db)
    foreign_response = agent_tasks(request(), agent=foreign_agent, db=db)

    assert china_response.tasks == []
    assert foreign_response.tasks == []
