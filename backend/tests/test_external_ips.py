from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.external_ips import ImportedExternalIp, extract_nyanpass_ips, sync_external_ip_source
from app.models import ExternalIpItem, ExternalIpSource
from app.security import encrypt_secret


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def test_extract_nyanpass_ips_keeps_online_public_ips_only():
    payload = [
        {
            "name": "香港",
            "servers": [
                {"id": "node-a", "name": "a", "online": True, "ip4": "8.8.8.8", "ip6": "2001:4860:4860::8888", "country": "日本"},
                {"name": "b", "online": False, "ip4": "1.1.1.1"},
                {"name": "c", "online": True, "ip4": "192.168.1.10"},
            ],
        }
    ]

    items = extract_nyanpass_ips(payload, 443)

    assert [(item.target, item.port, item.target_type) for item in items] == [
        ("2001:4860:4860::8888", 443, "ipv6"),
        ("8.8.8.8", 443, "ipv4"),
    ]
    assert all(item.group_name == "香港" for item in items)
    assert all(item.machine_key == "香港:node-a" for item in items)
    assert all(item.country == "日本" for item in items)


def test_sync_external_ip_source_replaces_stale_items(monkeypatch):
    db = make_session()
    source = ExternalIpSource(
        name="nyanpass",
        base_url="https://ny.example.com",
        token_encrypted=encrypt_secret("token"),
        default_port=22,
        sync_interval_seconds=600,
    )
    db.add(source)
    db.flush()
    stale = ExternalIpItem(source_id=source.id, name="old", target="1.1.1.1", target_type="ipv4", port=22, status="healthy")
    db.add(stale)
    db.commit()
    db.refresh(source)

    monkeypatch.setattr(
        "app.external_ips.fetch_nyanpass_ips",
        lambda item: [
            ImportedExternalIp(name="new", group_name="hk", machine_key="hk:new", country="香港", target="8.8.8.8", target_type="ipv4", port=22),
        ],
    )

    count = sync_external_ip_source(db, source)
    db.commit()

    items = db.query(ExternalIpItem).all()
    assert count == 1
    assert [(item.name, item.target, item.machine_key, item.country) for item in items] == [("new", "8.8.8.8", "hk:new", "香港")]
    assert source.status == "ok"


def make_bound_origin(db, source, machine_key="hk:node-a", target="8.8.8.8"):
    from app.models import CloudflareCredential, FailoverGroup, Origin, Zone

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
        target=target,
        target_type="ipv4",
        port=443,
        priority=1,
        status="blocked",
        external_source_id=source.id,
        external_machine_key=machine_key,
    )
    db.add(origin)
    db.commit()
    db.refresh(origin)
    return origin


def test_sync_updates_bound_origin_when_machine_ip_changes(monkeypatch):
    db = make_session()
    source = ExternalIpSource(
        name="nyanpass",
        base_url="https://ny.example.com",
        token_encrypted=encrypt_secret("token"),
        default_port=443,
        sync_interval_seconds=10,
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    origin = make_bound_origin(db, source, machine_key="hk:node-a", target="8.8.8.8")

    # 机器换了 IP：老的 (target, port) 项会被删掉、新项建出来，绑定按 machine_key 跟随
    monkeypatch.setattr(
        "app.external_ips.fetch_nyanpass_ips",
        lambda item: [
            ImportedExternalIp(name="node-a", group_name="hk", machine_key="hk:node-a", country=None, target="9.9.9.9", target_type="ipv4", port=443),
        ],
    )
    sync_external_ip_source(db, source)
    db.commit()
    db.refresh(origin)

    assert origin.target == "9.9.9.9"
    assert origin.status == "unknown"
    # 源站端口是入口端口，不跟随外部项的端口
    assert origin.port == 443


def test_sync_keeps_binding_when_machine_temporarily_missing(monkeypatch):
    db = make_session()
    source = ExternalIpSource(
        name="nyanpass",
        base_url="https://ny.example.com",
        token_encrypted=encrypt_secret("token"),
        default_port=443,
        sync_interval_seconds=10,
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    origin = make_bound_origin(db, source, machine_key="hk:node-a", target="8.8.8.8")

    monkeypatch.setattr("app.external_ips.fetch_nyanpass_ips", lambda item: [])
    sync_external_ip_source(db, source)
    db.commit()
    db.refresh(origin)

    # 机器暂时不在线：目标保持原值，绑定保留
    assert origin.target == "8.8.8.8"
    assert origin.external_machine_key == "hk:node-a"


def test_mark_external_ip_sources_due_clears_last_synced(monkeypatch):
    from datetime import datetime

    from app.external_ips import mark_external_ip_sources_due

    db = make_session()
    enabled_source = ExternalIpSource(
        name="a",
        base_url="https://a.example.com",
        token_encrypted=encrypt_secret("token"),
        last_synced_at=datetime.utcnow(),
    )
    disabled_source = ExternalIpSource(
        name="b",
        base_url="https://b.example.com",
        token_encrypted=encrypt_secret("token"),
        enabled=False,
        last_synced_at=datetime.utcnow(),
    )
    db.add_all([enabled_source, disabled_source])
    db.commit()

    assert mark_external_ip_sources_due(db) == 1
    assert enabled_source.last_synced_at is None
    assert disabled_source.last_synced_at is not None


def make_collection_with_bound_global(db, source, machine_key="hk:node-a", target="8.8.8.8", group_count=3):
    """A collection whose global backup is bound to a machine, mirrored into N groups."""
    from app.models import CloudflareCredential, FailoverCollection, FailoverGlobalOrigin, FailoverGroup, Origin, Zone

    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    collection = FailoverCollection(name="出海业务")
    db.add(collection)
    db.flush()
    global_origin = FailoverGlobalOrigin(
        collection_id=collection.id,
        target=target,
        target_type="ipv4",
        port=443,
        priority=10,
        external_source_id=source.id,
        external_machine_key=machine_key,
    )
    db.add(global_origin)
    db.flush()
    mirrors = []
    for index in range(group_count):
        group = FailoverGroup(zone_id=zone.id, hostname=f"h{index}.example.com", collection_id=collection.id)
        db.add(group)
        db.flush()
        mirror = Origin(
            group_id=group.id,
            global_origin_id=global_origin.id,
            target=target,
            target_type="ipv4",
            port=443,
            priority=10,
            status="healthy",
            external_source_id=source.id,
            external_machine_key=machine_key,
        )
        db.add(mirror)
        mirrors.append(mirror)
    db.commit()
    return global_origin, mirrors


def make_source(db):
    source = ExternalIpSource(
        name="nyanpass",
        base_url="https://ny.example.com",
        token_encrypted=encrypt_secret("token"),
        default_port=443,
        sync_interval_seconds=10,
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


def test_sync_updates_machine_bound_global_origin_and_all_its_mirrors(monkeypatch):
    db = make_session()
    source = make_source(db)
    global_origin, mirrors = make_collection_with_bound_global(db, source)

    monkeypatch.setattr(
        "app.external_ips.fetch_nyanpass_ips",
        lambda item: [
            ImportedExternalIp(name="node-a", group_name="hk", machine_key="hk:node-a", country=None, target="9.9.9.9", target_type="ipv4", port=443),
        ],
    )
    sync_external_ip_source(db, source)
    db.commit()

    db.refresh(global_origin)
    assert global_origin.target == "9.9.9.9"
    # One machine, one global backup, N domains — no new backup row was needed.
    for mirror in mirrors:
        db.refresh(mirror)
        assert mirror.target == "9.9.9.9"
        assert mirror.status == "unknown"


def test_sync_keeps_machine_bound_global_origin_when_machine_missing(monkeypatch):
    db = make_session()
    source = make_source(db)
    global_origin, mirrors = make_collection_with_bound_global(db, source)

    monkeypatch.setattr("app.external_ips.fetch_nyanpass_ips", lambda item: [])
    sync_external_ip_source(db, source)
    db.commit()

    db.refresh(global_origin)
    assert global_origin.target == "8.8.8.8"
    assert global_origin.external_machine_key == "hk:node-a"
    for mirror in mirrors:
        db.refresh(mirror)
        assert mirror.target == "8.8.8.8"
        assert mirror.status == "healthy"


def test_sync_emits_one_global_event_not_one_per_mirror(monkeypatch):
    from app.models import Event

    db = make_session()
    source = make_source(db)
    make_collection_with_bound_global(db, source, group_count=4)

    monkeypatch.setattr(
        "app.external_ips.fetch_nyanpass_ips",
        lambda item: [
            ImportedExternalIp(name="node-a", group_name="hk", machine_key="hk:node-a", country=None, target="9.9.9.9", target_type="ipv4", port=443),
        ],
    )
    sync_external_ip_source(db, source)
    db.commit()

    events = db.query(Event).filter(Event.type == "external_ip.global_origin_synced").all()
    assert len(events) == 1
    # Mirrors are driven by the global backup, so they must not also be synced directly.
    assert db.query(Event).filter(Event.type == "external_ip.origin_synced").count() == 0
