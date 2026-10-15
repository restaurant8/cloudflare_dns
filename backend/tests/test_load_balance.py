import json
from collections import Counter
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.failover import evaluate_failover_groups
from app.load_balance import choose_node_member
from app.models import CloudflareCredential, Event, FailoverGroup, FailoverTimeRule, Origin, Zone
from app.routes.groups import create_origin, delete_origin, update_origin, upsert_time_rule
from app.schemas import FailoverTimeRuleUpsert, OriginCreate, OriginUpdate
from app.security import encrypt_secret


T0 = datetime(2026, 10, 15, 12, 0, 0)


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def add_origin(db, group, target, priority, parent=None, weight=1):
    origin = Origin(
        group_id=group.id,
        target=target,
        target_type="ipv4" if target[0].isdigit() else "hostname",
        port=443,
        priority=parent.priority if parent is not None else priority,
        load_parent_id=parent.id if parent is not None else None,
        weight=weight,
        status="healthy",
    )
    db.add(origin)
    db.flush()
    return origin


def setup(db, monkeypatch, *, a_targets=("192.0.2.11", "192.0.2.12"), with_members=True):
    """Node A (a1 + load address a2), node B (b), node C (c1 + load address c2)."""
    published = []
    notified = []
    monkeypatch.setattr(
        "app.failover.publish_origin",
        lambda _db, _group, origin: published.append(origin.target)
        or {"id": "record-1", "type": "A", "content": origin.target},
    )
    monkeypatch.setattr("app.failover.run_local_checks", lambda *args, **kwargs: 0)
    monkeypatch.setattr("app.notifier.send_telegram_notifications", lambda _db, event_type, _payload: notified.append(event_type))
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    group = FailoverGroup(
        zone_id=zone.id,
        hostname="www.example.com",
        ttl=60,
        load_balance_interval_seconds=120,
        min_switch_interval_seconds=600,
    )
    db.add(group)
    db.flush()
    a1 = add_origin(db, group, a_targets[0], 10)
    a2 = add_origin(db, group, a_targets[1], 10, parent=a1 if with_members else None)
    b = add_origin(db, group, "192.0.2.20", 20)
    c1 = add_origin(db, group, "192.0.2.31", 30)
    c2 = add_origin(db, group, "192.0.2.32", 30, parent=c1)
    group.current_origin_id = a1.id
    group.last_switch_at = T0
    db.commit()
    db.refresh(group)
    return group, (a1, a2, b, c1, c2), published, notified


def tick(db, seconds):
    evaluate_failover_groups(db, now=T0 + timedelta(seconds=seconds), check_dns_consistency=False)
    db.commit()


def test_weighted_round_robin_inside_a_node():
    group = FailoverGroup(hostname="www.example.com", load_balance_interval_seconds=30)
    a = Origin(id=1, target="192.0.2.1", target_type="ipv4", priority=10, weight=1, status="healthy", enabled=True)
    b = Origin(id=2, target="192.0.2.2", target_type="ipv4", priority=10, weight=1, status="healthy", enabled=True, load_parent_id=1)
    c = Origin(id=3, target="192.0.2.3", target_type="ipv4", priority=10, weight=3, status="healthy", enabled=True, load_parent_id=1)
    group.origins = [a, b, c]
    group.current_origin_id = a.id

    picks = []
    for index in range(50):
        chosen, _ = choose_node_member(group, a, T0 + timedelta(seconds=30 * index))
        group.current_origin_id = chosen.id
        picks.append(chosen.target)

    assert Counter(picks) == {"192.0.2.1": 10, "192.0.2.2": 10, "192.0.2.3": 30}
    assert picks[:5] == ["192.0.2.3", "192.0.2.1", "192.0.2.3", "192.0.2.2", "192.0.2.3"]


def test_node_addresses_take_turns_and_other_nodes_stay_backups(monkeypatch):
    db = make_session()
    group, (a1, a2, b, c1, c2), published, notified = setup(db, monkeypatch)

    tick(db, 0)  # equal weights start with the current address
    tick(db, 60)  # inside the interval
    assert published == []
    tick(db, 130)
    assert group.current_origin_id == a2.id
    tick(db, 260)
    assert group.current_origin_id == a1.id
    assert published == ["192.0.2.12", "192.0.2.11"]

    # Rotation ignores the 600s failover cooldown, is logged, but not pushed.
    switches = [json.loads(event.payload_json) for event in db.query(Event).all() if event.type == "dns.switched"]
    assert [item["switch_reason"] for item in switches] == ["load_balance", "load_balance"]
    assert "dns.switched" not in notified
    assert group.load_balance_origin_ids == [a1.id, a2.id]


def test_failed_address_is_replaced_and_node_fails_over_only_when_empty(monkeypatch):
    db = make_session()
    group, (a1, a2, b, c1, c2), published, notified = setup(db, monkeypatch)
    tick(db, 0)

    a1.status = "unhealthy"  # the node's own address fails; a2 keeps node A alive
    db.commit()
    tick(db, 10)
    assert group.current_origin_id == a2.id
    assert "dns.switched" in notified  # a real failover is still notified

    tick(db, 300)  # only one healthy address left: no rotation
    assert group.current_origin_id == a2.id

    a2.status = "unhealthy"
    db.commit()
    tick(db, 310)
    assert group.current_origin_id == b.id
    assert published == ["192.0.2.12", "192.0.2.20"]


def test_time_rule_points_at_a_node_and_its_addresses_rotate(monkeypatch):
    db = make_session()
    group, (a1, a2, b, c1, c2), published, _ = setup(db, monkeypatch)
    db.add(
        FailoverTimeRule(
            group_id=group.id,
            origin_id=c1.id,
            name="peak",
            timezone="UTC",
            weekdays_mask=127,
            start_minute=0,
            end_minute=24 * 60 - 1,
            enabled=True,
        )
    )
    db.commit()
    db.refresh(group)

    tick(db, 0)
    assert group.current_origin_id == c1.id
    tick(db, 130)
    assert group.current_origin_id == c2.id
    tick(db, 260)
    assert group.current_origin_id == c1.id

    # The scheduled node keeps working while one of its addresses is down.
    c1.status = "unhealthy"
    db.commit()
    tick(db, 270)
    assert group.current_origin_id == c2.id
    assert published == ["192.0.2.31", "192.0.2.32", "192.0.2.31", "192.0.2.32"]


def test_hostname_addresses_rotate(monkeypatch):
    db = make_session()
    group, (a1, a2, *_), published, _ = setup(db, monkeypatch, a_targets=("a1.example.net", "a2.example.net"))

    tick(db, 0)
    tick(db, 130)

    assert group.current_origin_id == a2.id
    assert published == ["a2.example.net"]


def test_plain_origins_without_load_addresses_never_rotate(monkeypatch):
    db = make_session()
    # a2 is a separate node with the same priority: classic failover, no rotation.
    group, (a1, a2, *_), published, _ = setup(db, monkeypatch, with_members=False)

    for seconds in (0, 130, 260, 390):
        tick(db, seconds)

    assert group.current_origin_id == a1.id
    assert published == []
    assert group.load_balance_state_json is None


def test_api_load_address_follows_its_node(monkeypatch):
    db = make_session()
    group, (a1, a2, b, c1, c2), _, _ = setup(db, monkeypatch)

    added = create_origin(group.id, OriginCreate(target="192.0.2.13", port=443, priority=99, weight=3, load_parent_id=a1.id), None, db)
    assert added.load_parent_id == a1.id
    assert added.priority == a1.priority
    assert added.weight == 3

    with pytest.raises(HTTPException) as nested:
        create_origin(group.id, OriginCreate(target="192.0.2.14", port=443, load_parent_id=a2.id), None, db)
    assert nested.value.status_code == 400

    with pytest.raises(HTTPException) as rule_on_member:
        upsert_time_rule(
            group.id,
            FailoverTimeRuleUpsert(origin_id=a2.id, weekdays=[1], start_time="19:00", end_time="23:00"),
            None,
            db,
        )
    assert rule_on_member.value.status_code == 400

    update_origin(a1.id, OriginUpdate(priority=5), None, db)
    db.refresh(a2)
    assert a2.priority == 5
    update_origin(a2.id, OriginUpdate(priority=50), None, db)
    db.refresh(a2)
    assert a2.priority == 5

    delete_origin(a1.id, None, db)
    remaining = {origin.target for origin in db.query(Origin).filter(Origin.group_id == group.id)}
    assert remaining == {"192.0.2.20", "192.0.2.31", "192.0.2.32"}
