from datetime import datetime
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.health import LOCAL_SOURCE, run_target_pool_checks
from app.models import Agent, CloudflareCredential, FailoverGroup, Origin, ProbeState, TargetPoolItem, TargetPoolProbeState, User, Zone
from app.routes.target_pool import bulk_create_target_pool_items, create_target_pool_item
from app.schemas import TargetPoolBulkCreate, TargetPoolCreate, TargetPoolOut
from app.security import encrypt_secret


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def test_create_target_pool_item_detects_ipv6_and_keeps_remark():
    db = make_session()
    user = User(username="admin", password_hash="hash")
    db.add(user)
    db.commit()

    item = create_target_pool_item(
        TargetPoolCreate(target="2001:db8::5", port=22, remark="大陆备用"),
        user,
        db,
    )

    assert item.target == "2001:db8::5"
    assert item.target_type == "ipv6"
    assert item.port == 22
    assert item.remark == "大陆备用"
    assert item.check_interval_seconds == 600


def test_target_pool_check_records_local_status(monkeypatch):
    db = make_session()
    pool_item = TargetPoolItem(target="192.0.2.10", target_type="ipv4", port=22)
    db.add(pool_item)
    db.commit()

    calls = []

    def fake_tcp_check(target, port, timeout):
        calls.append((target, port, timeout))
        return SimpleNamespace(success=True, rtt_ms=12.5, error=None)

    monkeypatch.setattr("app.health.tcp_check", fake_tcp_check)

    checked = run_target_pool_checks(db, item_id=pool_item.id, include_all=True)

    db.flush()
    db.refresh(pool_item)
    assert checked == 1
    assert calls[0][0:2] == ("192.0.2.10", 22)
    assert pool_item.last_checked_at is not None
    assert pool_item.probe_states[0].source_key == LOCAL_SOURCE
    assert pool_item.probe_states[0].last_rtt_ms == 12.5


def test_target_pool_reuses_fresh_matching_origin_status():
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
    checked_at = datetime.utcnow()
    origin = Origin(
        group_id=group.id,
        target="192.0.2.10",
        target_type="ipv4",
        port=22,
        priority=10,
        status="healthy",
        last_checked_at=checked_at,
    )
    db.add(origin)
    db.flush()
    db.add(ProbeState(origin_id=origin.id, source_key=LOCAL_SOURCE, status="healthy", success_count=2, last_checked_at=checked_at, last_rtt_ms=9.1))
    pool_item = TargetPoolItem(target="192.0.2.10", target_type="ipv4", port=22)
    db.add(pool_item)
    db.commit()

    checked = run_target_pool_checks(db, item_id=pool_item.id)

    db.flush()
    db.refresh(pool_item)
    assert checked == 0
    assert pool_item.status == "healthy"
    assert pool_item.last_checked_at == checked_at
    assert pool_item.probe_states[0].source_key == LOCAL_SOURCE
    assert pool_item.probe_states[0].last_rtt_ms == 9.1


def test_target_pool_output_hides_disabled_agent_probe_state():
    db = make_session()
    pool_item = TargetPoolItem(target="192.0.2.10", target_type="ipv4", port=22)
    enabled_agent = Agent(name="上海", region="china", token_hash="hash-1", enabled=True, status="online")
    disabled_agent = Agent(name="杭州", region="china", token_hash="hash-2", enabled=False, status="offline")
    db.add_all([pool_item, enabled_agent, disabled_agent])
    db.flush()
    db.add_all(
        [
            TargetPoolProbeState(item_id=pool_item.id, source_key=LOCAL_SOURCE, status="healthy"),
            TargetPoolProbeState(item_id=pool_item.id, agent_id=enabled_agent.id, source_key=f"agent:{enabled_agent.id}", status="healthy"),
            TargetPoolProbeState(item_id=pool_item.id, agent_id=disabled_agent.id, source_key=f"agent:{disabled_agent.id}", status="healthy"),
        ]
    )
    db.commit()

    output = TargetPoolOut.model_validate(pool_item)

    assert {state.agent_name for state in output.probe_states} == {None, "上海"}
    assert "杭州" not in {state.agent_name for state in output.probe_states}


def test_bulk_create_target_pool_items_skips_duplicates_and_reports_invalid():
    db = make_session()
    user = User(username="admin", password_hash="hash")
    db.add(user)
    db.add(TargetPoolItem(target="8.8.8.8", target_type="ipv4", port=22))
    db.commit()

    result = bulk_create_target_pool_items(
        TargetPoolBulkCreate(
            items=[
                TargetPoolCreate(target="8.8.8.8", port=22),
                TargetPoolCreate(target="1.1.1.1", port=443, remark="cf"),
                TargetPoolCreate(target="bad host", port=22),
            ]
        ),
        user,
        db,
    )

    assert result.created == 1
    assert result.skipped == 1
    assert result.failed == 1
    assert db.query(TargetPoolItem).filter(TargetPoolItem.target == "1.1.1.1").one().remark == "cf"
