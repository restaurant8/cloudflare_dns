"""IP pools: named reusable address sets, referenced as relay backends."""

import json

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, _migrate_into_ip_pools
from app.external_ips import ImportedExternalIp, _sync_bound_pool_items
from app.models import ExternalIpItem, ExternalIpSource, FailoverGroup, Origin, TargetPool, TargetPoolItem
from app.routes.target_pool import (
    bulk_create_pool_items,
    create_pool,
    create_pool_item,
    delete_pool,
    list_pools,
    update_pool_item,
)
from app.schemas import TargetPoolBulkCreate, TargetPoolCreate, TargetPoolItemCreate, TargetPoolItemUpdate
from app.security import encrypt_secret


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)(), engine


def test_pools_hold_addresses_and_one_address_may_join_several_pools():
    db, _ = make_session()
    hk = create_pool(TargetPoolCreate(name="HK exit"), None, db)
    jp = create_pool(TargetPoolCreate(name="JP exit"), None, db)

    item = create_pool_item(hk.id, TargetPoolItemCreate(target="2001:db8::1", port=8443, remark=" B1 "), None, db)
    assert (item.target_type, item.remark, item.pool_id) == ("ipv6", "B1", hk.id)
    create_pool_item(jp.id, TargetPoolItemCreate(target="2001:db8::1", port=8443), None, db)

    with pytest.raises(HTTPException) as duplicate:
        create_pool_item(hk.id, TargetPoolItemCreate(target="2001:db8::1", port=8443), None, db)
    assert duplicate.value.status_code == 409
    with pytest.raises(HTTPException):
        create_pool(TargetPoolCreate(name="HK exit"), None, db)


def test_bulk_add_skips_duplicates_and_reports_invalid():
    db, _ = make_session()
    pool = create_pool(TargetPoolCreate(name="HK exit"), None, db)
    create_pool_item(pool.id, TargetPoolItemCreate(target="198.51.100.1", port=8443), None, db)

    result = bulk_create_pool_items(
        pool.id,
        TargetPoolBulkCreate(
            items=[
                TargetPoolItemCreate(target="198.51.100.1", port=8443),
                TargetPoolItemCreate(target="198.51.100.2", port=8443),
                TargetPoolItemCreate(target="not a host!", port=8443),
            ]
        ),
        None,
        db,
    )

    assert (result.created, result.skipped, result.failed) == (1, 1, 1)


def test_pool_listing_counts_users_and_used_pools_cannot_be_deleted():
    db, _ = make_session()
    pool = create_pool(TargetPoolCreate(name="HK exit"), None, db)
    group = FailoverGroup(hostname="www.example.com")
    db.add(group)
    db.flush()
    db.add(Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=443, relay_pool_ids_json=f"[{pool.id}]"))
    db.commit()

    listed = list_pools(None, db)
    assert listed[0].used_by_origins == 1

    with pytest.raises(HTTPException) as in_use:
        delete_pool(pool.id, None, db)
    assert in_use.value.status_code == 409


def test_address_follows_its_nyanpass_machine_but_keeps_its_relay_port():
    db, _ = make_session()
    source = ExternalIpSource(name="ny", base_url="https://ny.example.com", token_encrypted=encrypt_secret("t"))
    db.add(source)
    db.flush()
    machine = ExternalIpItem(source_id=source.id, name="HK-B", machine_key="hk-b", target="198.51.100.1", target_type="ipv4", port=22)
    db.add(machine)
    db.commit()
    pool = create_pool(TargetPoolCreate(name="HK exit"), None, db)

    item = create_pool_item(pool.id, TargetPoolItemCreate(target="0.0.0.0", port=8443, external_ip_item_id=machine.id), None, db)
    assert (item.target, item.port, item.external_machine_key) == ("198.51.100.1", 8443, "hk-b")

    updated = _sync_bound_pool_items(
        db,
        source,
        [ImportedExternalIp(name="HK-B", group_name=None, machine_key="hk-b", country=None, target="198.51.100.77", target_type="ipv4", port=22)],
    )
    db.commit()
    db.refresh(item)

    assert updated == 1
    assert (item.target, item.port, item.status) == ("198.51.100.77", 8443, "unknown")

    update_pool_item(item.id, TargetPoolItemUpdate(external_ip_item_id=None), None, db)
    db.refresh(item)
    assert item.external_machine_key is None


def test_migration_turns_typed_relays_and_loose_addresses_into_pools(monkeypatch):
    db, engine = make_session()
    group = FailoverGroup(hostname="www.example.com")
    db.add(group)
    db.flush()
    relays = json.dumps([{"target": "198.51.100.1", "port": 8443}, {"target": "198.51.100.2", "port": 8443}])
    first = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=443, relay_targets_json=relays)
    second = Origin(group_id=group.id, target="192.0.2.11", target_type="ipv4", port=443, relay_targets_json=relays)
    db.add_all([first, second, TargetPoolItem(target="203.0.113.9", target_type="ipv4", port=22)])
    db.commit()
    monkeypatch.setattr("app.database.engine", engine)

    _migrate_into_ip_pools()
    _migrate_into_ip_pools()  # idempotent
    db.expire_all()

    pools = {pool.name: pool for pool in db.query(TargetPool).all()}
    assert set(pools) == {"默认池子", "中转 198.51.100.1 等 2 个"}
    relay_pool = pools["中转 198.51.100.1 等 2 个"]
    assert sorted((item.target, item.port) for item in relay_pool.items) == [("198.51.100.1", 8443), ("198.51.100.2", 8443)]
    assert first.relay_pool_ids == second.relay_pool_ids == [relay_pool.id]
    assert first.relay_targets_json is None


def test_existing_install_drops_global_address_uniqueness(monkeypatch):
    """An old database had UNIQUE(target, port) on the pool; upgrading keeps the rows."""
    from sqlalchemy import inspect, text

    from app import database

    engine = create_engine("sqlite:///:memory:", future=True)
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE target_pool_items ("
                "id INTEGER PRIMARY KEY, target VARCHAR(255) NOT NULL, target_type VARCHAR(20) NOT NULL, "
                "port INTEGER NOT NULL DEFAULT 22, remark TEXT, check_interval_seconds INTEGER NOT NULL DEFAULT 600, "
                "enabled BOOLEAN NOT NULL DEFAULT 1, status VARCHAR(20) NOT NULL DEFAULT 'unknown', "
                "last_checked_at DATETIME, last_error TEXT, last_rtt_ms FLOAT, created_at DATETIME, updated_at DATETIME, "
                "CONSTRAINT uq_target_pool_target_port UNIQUE (target, port))"
            )
        )
        connection.execute(
            text("INSERT INTO target_pool_items (id, target, target_type, port) VALUES (1, '198.51.100.1', 'ipv4', 8443)")
        )
    monkeypatch.setattr(database, "engine", engine)
    Base.metadata.create_all(engine)  # init_db creates new tables (target_pools) first

    database._migrate_existing_schema()

    with sessionmaker(bind=engine, future=True)() as db:
        item = db.get(TargetPoolItem, 1)
        assert item.pool_name == "默认池子"
        other = TargetPool(name="JP exit")
        db.add(other)
        db.flush()
        db.add(TargetPoolItem(pool_id=other.id, target="198.51.100.1", target_type="ipv4", port=8443))
        db.commit()  # the same address in a second pool is now allowed
    uniques = {unique["name"] for unique in inspect(engine).get_unique_constraints("target_pool_items")}
    assert "uq_target_pool_target_port" not in uniques
