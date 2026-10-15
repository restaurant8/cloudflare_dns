import json
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.failover import evaluate_failover_groups
from app.load_balance import choose_load_balanced_origin
from app.models import CloudflareCredential, Event, FailoverGroup, FailoverTimeRule, Origin, Zone
from app.security import encrypt_secret


T0 = datetime(2026, 10, 15, 12, 0, 0)


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def setup(db, monkeypatch, *, targets=("192.0.2.10", "192.0.2.20"), backup="192.0.2.30", load_balance_enabled=True):
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
        load_balance_enabled=load_balance_enabled,
        load_balance_interval_seconds=120,
        min_switch_interval_seconds=600,
    )
    db.add(group)
    db.flush()
    origins = []
    for target in [*targets, backup]:
        target_type = "hostname" if not target[0].isdigit() else "ipv4"
        origin = Origin(
            group_id=group.id,
            target=target,
            target_type=target_type,
            port=443,
            priority=20 if target == backup else 10,
            status="healthy",
        )
        db.add(origin)
        db.flush()
        origins.append(origin)
    group.current_origin_id = origins[0].id
    group.last_switch_at = T0
    db.commit()
    return group, origins, published, notified


def tick(db, seconds):
    evaluate_failover_groups(db, now=T0 + timedelta(seconds=seconds), check_dns_consistency=False)
    db.commit()


def test_weighted_round_robin_follows_weights():
    group = FailoverGroup(hostname="www.example.com", load_balance_enabled=True, load_balance_interval_seconds=30)
    a = Origin(id=1, target="192.0.2.1", target_type="ipv4", priority=10, weight=1, status="healthy", enabled=True)
    b = Origin(id=2, target="192.0.2.2", target_type="ipv4", priority=10, weight=1, status="healthy", enabled=True)
    c = Origin(id=3, target="192.0.2.3", target_type="ipv4", priority=10, weight=3, status="healthy", enabled=True)
    backup = Origin(id=4, target="192.0.2.4", target_type="ipv4", priority=20, weight=50, status="healthy", enabled=True)
    group.origins = [a, b, c, backup]
    group.current_origin_id = a.id

    picks = []
    for index in range(50):
        chosen, _ = choose_load_balanced_origin(group, a, T0 + timedelta(seconds=30 * index))
        group.current_origin_id = chosen.id
        picks.append(chosen.target)

    assert Counter(picks) == {"192.0.2.1": 10, "192.0.2.2": 10, "192.0.2.3": 30}
    assert picks[:5] == ["192.0.2.3", "192.0.2.1", "192.0.2.3", "192.0.2.2", "192.0.2.3"]


def test_rotates_between_same_priority_origins_each_interval(monkeypatch):
    db = make_session()
    group, (a, b, c), published, notified = setup(db, monkeypatch)

    tick(db, 0)  # equal weights start with the current origin: nothing to publish
    assert group.current_origin_id == a.id and published == []
    tick(db, 60)  # inside the interval
    assert published == []
    tick(db, 130)
    assert group.current_origin_id == b.id
    tick(db, 260)
    assert group.current_origin_id == a.id
    assert published == ["192.0.2.20", "192.0.2.10"]
    # The lower priority stays a backup and is never rotated in.
    assert c.id not in {group.current_origin_id}

    # Rotation ignores the failover cooldown (600s) and is logged but not pushed.
    switch_events = [event for event in db.query(Event).all() if event.type == "dns.switched"]
    assert len(switch_events) == 2
    assert all(json.loads(event.payload_json)["switch_reason"] == "load_balance" for event in switch_events)
    assert "dns.switched" not in notified
    assert group.load_balance_origin_ids == [a.id, b.id]


def test_failed_member_is_replaced_immediately_and_notified(monkeypatch):
    db = make_session()
    group, (a, b, c), published, notified = setup(db, monkeypatch)
    tick(db, 0)

    a.status = "unhealthy"
    db.commit()
    tick(db, 10)
    assert group.current_origin_id == b.id
    assert "dns.switched" in notified

    b.status = "unhealthy"
    db.commit()
    tick(db, 20)
    assert group.current_origin_id == c.id
    assert published == ["192.0.2.20", "192.0.2.30"]


def test_hostname_origins_rotate_too(monkeypatch):
    db = make_session()
    group, (a, b, _), published, _ = setup(db, monkeypatch, targets=("a.example.net", "b.example.net"), backup="c.example.net")

    tick(db, 0)
    tick(db, 130)

    assert group.current_origin_id == b.id
    assert published == ["b.example.net"]


def test_disabled_group_never_rotates(monkeypatch):
    db = make_session()
    group, (a, _, _), published, _ = setup(db, monkeypatch, load_balance_enabled=False)

    for seconds in (0, 130, 260, 390):
        tick(db, seconds)

    assert group.current_origin_id == a.id
    assert published == []
    assert group.load_balance_state_json is None
    assert group.load_balance_origin_ids == []


def test_active_time_rule_pins_its_origin(monkeypatch):
    db = make_session()
    group, (a, b, _), published, _ = setup(db, monkeypatch)
    db.add(
        FailoverTimeRule(
            group_id=group.id,
            origin_id=a.id,
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

    for seconds in (0, 130, 260):
        tick(db, seconds)

    assert group.current_origin_id == a.id
    assert published == []
