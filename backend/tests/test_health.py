from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.health import LOCAL_SOURCE, mark_stale_agents, recalculate_origin_status
from app.models import Agent, CloudflareCredential, FailoverGroup, Origin, ProbeState, Zone
from app.security import encrypt_secret


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def make_origin_with_agent(db):
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.flush()
    origin = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=443, priority=10, weight=1)
    agent = Agent(name="china", token_hash="hash", status="online", last_seen_at=datetime.utcnow())
    db.add_all([origin, agent])
    db.commit()
    db.refresh(origin)
    db.refresh(agent)
    return origin, agent


def set_probe(db, origin, source_key: str, status: str):
    state = ProbeState(
        origin_id=origin.id,
        source_key=source_key,
        status=status,
        last_checked_at=datetime.utcnow(),
        last_error=None if status == "healthy" else "connect failed",
    )
    db.add(state)
    db.commit()


def test_origin_healthy_when_local_and_agent_are_healthy():
    db = make_session()
    origin, agent = make_origin_with_agent(db)
    set_probe(db, origin, LOCAL_SOURCE, "healthy")
    set_probe(db, origin, f"agent:{agent.id}", "healthy")

    recalculate_origin_status(db, origin)

    assert origin.status == "healthy"
    assert origin.last_error is None


def test_origin_blocked_when_local_healthy_but_china_agent_fails():
    db = make_session()
    origin, agent = make_origin_with_agent(db)
    set_probe(db, origin, LOCAL_SOURCE, "healthy")
    set_probe(db, origin, f"agent:{agent.id}", "unhealthy")

    recalculate_origin_status(db, origin)

    assert origin.status == "blocked"
    assert "疑似被墙" in origin.last_error


def test_origin_machine_down_when_local_and_china_agent_fail():
    db = make_session()
    origin, agent = make_origin_with_agent(db)
    set_probe(db, origin, LOCAL_SOURCE, "unhealthy")
    set_probe(db, origin, f"agent:{agent.id}", "unhealthy")

    recalculate_origin_status(db, origin)

    assert origin.status == "machine_down"
    assert "机器挂了" in origin.last_error


def test_origin_regional_issue_when_local_fails_but_china_agent_is_healthy():
    db = make_session()
    origin, agent = make_origin_with_agent(db)
    set_probe(db, origin, LOCAL_SOURCE, "unhealthy")
    set_probe(db, origin, f"agent:{agent.id}", "healthy")

    recalculate_origin_status(db, origin)

    assert origin.status == "regional_issue"


def test_mark_stale_agents_sends_offline_status(monkeypatch):
    db = make_session()
    agent = Agent(name="china", token_hash="hash", status="online", last_seen_at=None)
    db.add(agent)
    db.commit()
    monkeypatch.setattr("app.health.send_webhooks", lambda *args, **kwargs: None)

    changed = mark_stale_agents(db)

    assert changed == 1
    assert agent.status == "offline"
