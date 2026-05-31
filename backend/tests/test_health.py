from datetime import datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.health import LOCAL_SOURCE, mark_stale_agents, recalculate_origin_status, run_local_checks
from app.models import Agent, CloudflareCredential, FailoverGroup, Origin, ProbeState, Zone
from app.origin_expansion import EXPANDED_PUBLISH_MODE, healthy_ips
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
    origin = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=443, priority=10)
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


def test_offline_agent_does_not_mark_origin_unhealthy():
    db = make_session()
    origin, agent = make_origin_with_agent(db)
    agent.status = "offline"
    agent.last_seen_at = datetime.utcnow() - timedelta(minutes=10)
    db.commit()
    set_probe(db, origin, LOCAL_SOURCE, "healthy")
    set_probe(db, origin, f"agent:{agent.id}", "unhealthy")

    recalculate_origin_status(db, origin)

    assert origin.status == "healthy"
    assert origin.last_error is None


def test_one_healthy_online_agent_prevents_blocked_false_positive():
    db = make_session()
    origin, failed_agent = make_origin_with_agent(db)
    healthy_agent = Agent(name="china-2", token_hash="hash", status="online", last_seen_at=datetime.utcnow())
    db.add(healthy_agent)
    db.commit()
    db.refresh(healthy_agent)
    set_probe(db, origin, LOCAL_SOURCE, "healthy")
    set_probe(db, origin, f"agent:{failed_agent.id}", "unhealthy")
    set_probe(db, origin, f"agent:{healthy_agent.id}", "healthy")

    recalculate_origin_status(db, origin)

    assert origin.status == "healthy"
    assert origin.last_error is None


def test_foreign_agent_can_keep_origin_healthy_when_local_fails():
    db = make_session()
    origin, foreign_agent = make_origin_with_agent(db)
    foreign_agent.region = "foreign"
    db.commit()
    set_probe(db, origin, LOCAL_SOURCE, "unhealthy")
    set_probe(db, origin, f"agent:{foreign_agent.id}", "healthy")

    recalculate_origin_status(db, origin)

    assert origin.status == "healthy"
    assert origin.last_error is None


def test_multiple_foreign_agents_only_need_one_healthy():
    db = make_session()
    origin, china_agent = make_origin_with_agent(db)
    failed_foreign = Agent(name="foreign-1", region="foreign", token_hash="hash", status="online", last_seen_at=datetime.utcnow())
    healthy_foreign = Agent(name="foreign-2", region="foreign", token_hash="hash", status="online", last_seen_at=datetime.utcnow())
    db.add_all([failed_foreign, healthy_foreign])
    db.commit()
    db.refresh(failed_foreign)
    db.refresh(healthy_foreign)
    set_probe(db, origin, LOCAL_SOURCE, "unhealthy")
    set_probe(db, origin, f"agent:{failed_foreign.id}", "unhealthy")
    set_probe(db, origin, f"agent:{healthy_foreign.id}", "healthy")
    set_probe(db, origin, f"agent:{china_agent.id}", "healthy")

    recalculate_origin_status(db, origin)

    assert origin.status == "healthy"
    assert origin.last_error is None


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


def make_group_with_current_and_backup(db, current_status: str = "healthy"):
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.flush()
    current = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=443, priority=0, status=current_status)
    backup = Origin(group_id=group.id, target="192.0.2.20", target_type="ipv4", port=443, priority=10, status="unknown")
    db.add_all([current, backup])
    db.flush()
    group.current_origin_id = current.id
    db.commit()
    return group, current, backup


def test_run_local_checks_checks_all_enabled_origins(monkeypatch):
    db = make_session()
    _, current, backup = make_group_with_current_and_backup(db, "healthy")
    checked_targets = []

    def fake_tcp_check(target, port, timeout):
        checked_targets.append(target)
        return SimpleNamespace(success=True, rtt_ms=1.0, error=None)

    monkeypatch.setattr("app.health.tcp_check", fake_tcp_check)

    checked = run_local_checks(db)

    assert checked == 2
    assert checked_targets == [current.target, backup.target]


def test_run_local_checks_checks_backup_when_current_is_unavailable(monkeypatch):
    db = make_session()
    _, current, backup = make_group_with_current_and_backup(db, "machine_down")
    checked_targets = []

    def fake_tcp_check(target, port, timeout):
        checked_targets.append(target)
        return SimpleNamespace(success=True, rtt_ms=1.0, error=None)

    monkeypatch.setattr("app.health.tcp_check", fake_tcp_check)

    checked = run_local_checks(db)

    assert checked == 2
    assert checked_targets == [current.target, backup.target]


def test_expanded_hostname_checks_each_resolved_ip_and_keeps_healthy_pool(monkeypatch):
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
    origin = Origin(
        group_id=group.id,
        target="backup.example.net",
        target_type="hostname",
        publish_mode=EXPANDED_PUBLISH_MODE,
        port=443,
        priority=10,
    )
    db.add(origin)
    db.commit()

    monkeypatch.setattr("app.health.resolve_hostname_ips", lambda hostname: ["192.0.2.10", "192.0.2.20"])

    def fake_tcp_check(target, port, timeout):
        return SimpleNamespace(success=target == "192.0.2.10", rtt_ms=1.0, error=None if target == "192.0.2.10" else "connect failed")

    monkeypatch.setattr("app.health.tcp_check", fake_tcp_check)

    run_local_checks(db, origin_id=origin.id, include_all=True)
    run_local_checks(db, origin_id=origin.id, include_all=True)

    assert origin.status == "healthy"
    assert healthy_ips(origin) == ["192.0.2.10"]
