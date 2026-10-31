"""Relay backends via IP pools: A → B → C, the origin (A) only counts when one B works."""

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.dns_utils import TcpCheckResult
from app.failover import evaluate_failover_groups
from app.health import run_local_checks
from app.models import FailoverCollection, FailoverGlobalOrigin, FailoverGroup, Origin, TargetPool, TargetPoolItem
from app.relay import apply_relay_verdict, relay_overview, relay_verdict
from app.routes.groups import create_origin, sync_global_origins_to_group, update_origin
from app.schemas import OriginCreate, OriginUpdate


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


class Network:
    """Which (host, port) pairs answer a TCP connect."""

    def __init__(self, *up):
        self.up = set(up)

    def __call__(self, target, port, timeout):
        if (target, port) in self.up:
            return TcpCheckResult(True, 5.0, None, target)
        return TcpCheckResult(False, None, "connection refused", None)


def make_pool(db, name, *addresses):
    pool = TargetPool(name=name)
    db.add(pool)
    db.flush()
    for target, port in addresses:
        db.add(TargetPoolItem(pool_id=pool.id, target=target, target_type="ipv4", port=port))
    db.commit()
    return pool


def setup(db, monkeypatch, network):
    monkeypatch.setattr("app.health.tcp_check", network)
    monkeypatch.setattr("app.health.send_webhooks", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.routes.groups._evaluate_locally", lambda *args, **kwargs: None)
    group = FailoverGroup(hostname="www.example.com", cloudflare_publish_enabled=False)
    db.add(group)
    db.flush()
    # probe_mode local_only: only the panel decides, no agents needed in tests
    a = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=443, priority=10, probe_mode="local_only")
    backup = Origin(group_id=group.id, target="192.0.2.20", target_type="ipv4", port=443, priority=20, probe_mode="local_only")
    db.add_all([a, backup])
    db.commit()
    return group, a, backup


def checks(db, rounds):
    for _ in range(rounds):
        run_local_checks(db, include_all=True)
        db.commit()


def test_origin_is_relay_down_only_when_every_backend_fails(monkeypatch):
    db = make_session()
    network = Network(("192.0.2.10", 443), ("192.0.2.20", 443), ("198.51.100.1", 8443), ("198.51.100.2", 8443))
    group, a, _ = setup(db, monkeypatch, network)
    pool = make_pool(db, "HK exit", ("198.51.100.1", 8443), ("198.51.100.2", 8443))
    update_origin(a.id, OriginUpdate(relay_pool_ids=[pool.id]), None, db)

    checks(db, 2)
    assert a.status == "healthy"
    assert relay_verdict(a) == "up"

    # One B of the pool dies: the chain still works.
    network.up.discard(("198.51.100.1", 8443))
    checks(db, 5)
    assert a.status == "healthy"
    assert [item["status"] for item in relay_overview(a)] == ["unhealthy", "healthy"]

    # Both Bs down: A itself still answers, but the chain is broken.
    network.up.discard(("198.51.100.2", 8443))
    checks(db, 4)
    assert a.status == "healthy"  # below the fail threshold (5): no switch on a blip
    checks(db, 1)
    assert a.status == "relay_down"
    assert "中转后端全部不通" in a.last_error

    # One B back: A is usable again after the recovery threshold.
    network.up.add(("198.51.100.2", 8443))
    checks(db, 3)
    assert a.status == "healthy"


def test_several_pools_count_as_one_backend_set(monkeypatch):
    db = make_session()
    network = Network(("192.0.2.10", 443), ("203.0.113.5", 8443))
    group, a, _ = setup(db, monkeypatch, network)
    hk = make_pool(db, "HK exit", ("198.51.100.1", 8443))
    jp = make_pool(db, "JP exit", ("203.0.113.5", 8443))
    update_origin(a.id, OriginUpdate(relay_pool_ids=[hk.id, jp.id]), None, db)

    checks(db, 6)

    assert a.status == "healthy"  # HK is down but JP still carries the chain
    assert {item["pool_name"] for item in relay_overview(a)} == {"HK exit", "JP exit"}


def test_one_pool_edit_reaches_every_origin_using_it(monkeypatch):
    db = make_session()
    network = Network(("192.0.2.10", 443), ("192.0.2.20", 443), ("198.51.100.9", 8443))
    group, a, backup = setup(db, monkeypatch, network)
    pool = make_pool(db, "HK exit", ("198.51.100.1", 8443))
    for origin in (a, backup):
        update_origin(origin.id, OriginUpdate(relay_pool_ids=[pool.id]), None, db)
    checks(db, 6)
    assert (a.status, backup.status) == ("relay_down", "relay_down")

    # B changed: edit the single pool entry once.
    from app.routes.target_pool import update_pool_item
    from app.schemas import TargetPoolItemUpdate

    item = pool.items[0]
    update_pool_item(item.id, TargetPoolItemUpdate(target="198.51.100.9"), None, db)
    checks(db, 1)

    assert (a.status, backup.status) == ("healthy", "healthy")


def test_failover_moves_away_from_relay_down_origin_without_ip_change(monkeypatch):
    db = make_session()
    network = Network(("192.0.2.10", 443), ("192.0.2.20", 443))
    group, a, backup = setup(db, monkeypatch, network)
    pool = make_pool(db, "HK exit", ("198.51.100.1", 8443))
    update_origin(a.id, OriginUpdate(relay_pool_ids=[pool.id]), None, db)
    group.current_origin_id = a.id
    db.commit()
    published = []
    monkeypatch.setattr("app.failover.publish_origin", lambda _db, _group, origin: published.append(origin.target) or {"id": "r", "type": "A", "content": origin.target})
    monkeypatch.setattr("app.failover.trigger_ip_change_for_origin", lambda *args, **kwargs: pytest.fail("A is fine; its IP must not be changed"))
    group.cloudflare_publish_enabled = True
    db.commit()

    checks(db, 6)
    assert a.status == "relay_down"
    evaluate_failover_groups(db, check_dns_consistency=False)
    db.commit()

    assert group.current_origin_id == backup.id
    assert published == ["192.0.2.20"]


def test_blocked_origin_stays_blocked_so_ip_change_still_runs(monkeypatch):
    db = make_session()
    group, a, _ = setup(db, monkeypatch, Network())
    pool = make_pool(db, "HK exit", ("198.51.100.1", 8443))
    pool.items[0].status = "unhealthy"
    a.relay_pool_ids_json = f"[{pool.id}]"
    a.status = "blocked"
    db.commit()

    apply_relay_verdict(a, db)

    assert a.status == "blocked"


def test_origin_without_pools_is_unaffected(monkeypatch):
    db = make_session()
    group, a, _ = setup(db, monkeypatch, Network(("192.0.2.10", 443)))
    make_pool(db, "unused", ("198.51.100.1", 8443))

    checks(db, 6)

    assert a.status == "healthy"
    assert relay_verdict(a) == "none"


def test_api_validates_pools_and_deselecting_lifts_relay_down(monkeypatch):
    db = make_session()
    group, a, _ = setup(db, monkeypatch, Network(("192.0.2.10", 443)))
    pool = make_pool(db, "HK exit", ("198.51.100.9", 8443))

    with pytest.raises(HTTPException):
        update_origin(a.id, OriginUpdate(relay_pool_ids=[9999]), None, db)

    update_origin(a.id, OriginUpdate(relay_pool_ids=[pool.id]), None, db)
    checks(db, 6)
    assert a.status == "relay_down"

    update_origin(a.id, OriginUpdate(relay_pool_ids=[]), None, db)
    db.refresh(a)
    assert a.status == "healthy"


def test_load_ips_and_global_mirrors_inherit_pools(monkeypatch):
    db = make_session()
    group, a, _ = setup(db, monkeypatch, Network())
    hk = make_pool(db, "HK exit", ("198.51.100.1", 8443))
    jp = make_pool(db, "JP exit", ("198.51.100.2", 8443))
    update_origin(a.id, OriginUpdate(relay_pool_ids=[hk.id]), None, db)

    member = create_origin(group.id, OriginCreate(target="192.0.2.11", port=443, load_parent_id=a.id), None, db)
    assert member.relay_pool_ids == [hk.id]

    update_origin(a.id, OriginUpdate(relay_pool_ids=[jp.id]), None, db)
    db.refresh(member)
    assert member.relay_pool_ids == [jp.id]

    collection = FailoverCollection(name="hk")
    db.add(collection)
    db.flush()
    group.collection_id = collection.id
    global_origin = FailoverGlobalOrigin(
        collection_id=collection.id,
        target="192.0.2.50",
        target_type="ipv4",
        port=443,
        relay_pool_ids_json=f"[{hk.id}]",
    )
    db.add(global_origin)
    db.commit()
    db.refresh(group)
    sync_global_origins_to_group(db, group)
    mirror = next(origin for origin in group.origins if origin.global_origin_id == global_origin.id)
    assert mirror.relay_pool_ids == [hk.id]
