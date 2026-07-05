from datetime import datetime
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import pytest
from fastapi import HTTPException

from app.database import Base
from app.models import Agent, AzPanelRemoteResource, AzPanelResource, CloudflareCredential, FailoverCollection, FailoverGlobalOrigin, FailoverGroup, FailoverHostname, Origin, ProbeState, User, Zone
from app.origin_expansion import EXPANDED_PUBLISH_MODE, resolved_ips
from app.routes.groups import add_group_hostname, create_collection, create_global_origin, create_group, create_origin, delete_global_origin, delete_group_hostname, update_global_origin, update_group, update_origin
from app.schemas import FailoverCollectionCreate, FailoverGlobalOriginCreate, FailoverGlobalOriginUpdate, FailoverGroupCreate, FailoverGroupUpdate, FailoverHostnameCreate, OriginCreate, OriginOut, OriginUpdate
from app.security import encrypt_secret


class FakeCloudflareClient:
    records = [
        {
            "id": "record-1",
            "name": "www.example.com",
            "type": "A",
            "content": "192.0.2.10",
            "proxied": False,
        }
    ]

    def __init__(self, token: str):
        self.token = token

    def list_dns_records(self, zone_id: str, name: str | None = None):
        return [record for record in self.records if name is None or record["name"] == name]

    def update_dns_record(self, zone_id: str, record_id: str, record: dict):
        existing = next(item for item in self.records if item["id"] == record_id)
        existing.update(record)
        return {**existing}

    def create_dns_record(self, zone_id: str, record: dict):
        created = {"id": "new-record", **record}
        self.records.append(created)
        return created

    def delete_dns_record(self, zone_id: str, record_id: str):
        self.records = [record for record in self.records if record["id"] != record_id]


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def setup_zone(db):
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    user = User(username="admin", password_hash="hash")
    db.add(user)
    db.commit()
    db.refresh(zone)
    db.refresh(user)
    return zone, user


def test_create_group_adopts_current_dns_record_as_primary_origin(monkeypatch):
    monkeypatch.setattr("app.routes.groups.CloudflareClient", FakeCloudflareClient)
    db = make_session()
    zone, user = setup_zone(db)

    group = create_group(
        FailoverGroupCreate(
            zone_id=zone.id,
            hostname="www.example.com",
            adopt_record_id="record-1",
            primary_port=22,
        ),
        user,
        db,
    )

    assert group.current_record_id == "record-1"
    assert len(group.origins) == 1
    assert group.origins[0].target == "192.0.2.10"
    assert group.origins[0].port == 22
    assert group.origins[0].priority == 0
    assert group.current_origin_id == group.origins[0].id


def test_create_group_adopts_record_by_id_when_name_filter_misses(monkeypatch):
    class NameFilterMissClient(FakeCloudflareClient):
        records = [
            {
                "id": "record-1",
                "name": "www.example.com",
                "type": "A",
                "content": "192.0.2.10",
                "proxied": False,
            }
        ]

        def list_dns_records(self, zone_id: str, name: str | None = None):
            if name is not None:
                return []
            return self.records

    monkeypatch.setattr("app.routes.groups.CloudflareClient", NameFilterMissClient)
    db = make_session()
    zone, user = setup_zone(db)

    group = create_group(
        FailoverGroupCreate(
            zone_id=zone.id,
            hostname="www.example.com",
            adopt_record_id="record-1",
            primary_port=22,
        ),
        user,
        db,
    )

    assert group.current_record_id == "record-1"
    assert group.origins[0].target == "192.0.2.10"


def test_add_group_hostname_publishes_current_origin(monkeypatch):
    class MultiHostnameClient(FakeCloudflareClient):
        records = [
            {
                "id": "record-1",
                "name": "www.example.com",
                "type": "A",
                "content": "192.0.2.10",
                "ttl": 60,
                "proxied": False,
            },
            {
                "id": "record-2",
                "name": "api.example.com",
                "type": "A",
                "content": "192.0.2.99",
                "ttl": 60,
                "proxied": False,
            },
        ]

    monkeypatch.setattr("app.routes.groups.CloudflareClient", MultiHostnameClient)
    monkeypatch.setattr("app.failover.CloudflareClient", MultiHostnameClient)
    db = make_session()
    zone, user = setup_zone(db)
    group = create_group(
        FailoverGroupCreate(
            zone_id=zone.id,
            hostname="www.example.com",
            adopt_record_id="record-1",
            primary_port=22,
        ),
        user,
        db,
    )

    updated = add_group_hostname(group.id, FailoverHostnameCreate(hostname="api.example.com", adopt_record_id="record-2"), user, db)

    assert {item.hostname for item in updated.hostnames} == {"www.example.com", "api.example.com"}
    assert {(item["name"], item["content"]) for item in MultiHostnameClient.records} == {
        ("www.example.com", "192.0.2.10"),
        ("api.example.com", "192.0.2.10"),
    }


def test_add_group_hostname_only_publishes_new_hostname(monkeypatch):
    class OnlyNewHostnameClient(FakeCloudflareClient):
        records = [
            {
                "id": "record-1",
                "name": "www.example.com",
                "type": "A",
                "content": "192.0.2.10",
                "ttl": 60,
                "proxied": False,
            },
            {
                "id": "record-2",
                "name": "api.example.com",
                "type": "A",
                "content": "192.0.2.99",
                "ttl": 60,
                "proxied": False,
            },
        ]
        updated_names: list[str] = []

        def update_dns_record(self, zone_id: str, record_id: str, record: dict):
            existing = next(item for item in self.records if item["id"] == record_id)
            if existing["name"] == "www.example.com":
                raise AssertionError("primary hostname should not be republished while adding another hostname")
            self.updated_names.append(existing["name"])
            return super().update_dns_record(zone_id, record_id, record)

    monkeypatch.setattr("app.routes.groups.CloudflareClient", OnlyNewHostnameClient)
    monkeypatch.setattr("app.failover.CloudflareClient", OnlyNewHostnameClient)
    db = make_session()
    zone, user = setup_zone(db)
    group = create_group(
        FailoverGroupCreate(
            zone_id=zone.id,
            hostname="www.example.com",
            adopt_record_id="record-1",
            primary_port=22,
        ),
        user,
        db,
    )

    updated = add_group_hostname(group.id, FailoverHostnameCreate(hostname="api.example.com", adopt_record_id="record-2"), user, db)

    assert {item.hostname for item in updated.hostnames} == {"www.example.com", "api.example.com"}
    assert OnlyNewHostnameClient.updated_names == ["api.example.com"]
    assert {(item["name"], item["content"]) for item in OnlyNewHostnameClient.records} == {
        ("www.example.com", "192.0.2.10"),
        ("api.example.com", "192.0.2.10"),
    }


def test_add_group_hostname_keeps_hostname_when_publish_fails(monkeypatch):
    class PublishFailClient(FakeCloudflareClient):
        records = [
            {
                "id": "record-1",
                "name": "www.example.com",
                "type": "A",
                "content": "192.0.2.10",
                "ttl": 60,
                "proxied": False,
            }
        ]

        def create_dns_record(self, zone_id: str, record: dict):
            if record["name"] == "api.example.com":
                raise RuntimeError("cloudflare temporary failure")
            return super().create_dns_record(zone_id, record)

    monkeypatch.setattr("app.routes.groups.CloudflareClient", PublishFailClient)
    monkeypatch.setattr("app.failover.CloudflareClient", PublishFailClient)
    db = make_session()
    zone, user = setup_zone(db)
    group = create_group(
        FailoverGroupCreate(
            zone_id=zone.id,
            hostname="www.example.com",
            adopt_record_id="record-1",
            primary_port=22,
        ),
        user,
        db,
    )

    updated = add_group_hostname(group.id, FailoverHostnameCreate(hostname="api.example.com"), user, db)

    assert {item.hostname for item in updated.hostnames} == {"www.example.com", "api.example.com"}
    assert "DNS 发布失败" in (updated.last_error or "")


def test_delete_group_hostname_keeps_at_least_one_hostname(monkeypatch):
    monkeypatch.setattr("app.routes.groups.CloudflareClient", FakeCloudflareClient)
    db = make_session()
    zone, user = setup_zone(db)
    group = create_group(
        FailoverGroupCreate(
            zone_id=zone.id,
            hostname="www.example.com",
            adopt_record_id="record-1",
            primary_port=22,
        ),
        user,
        db,
    )

    try:
        delete_group_hostname(group.hostnames[0].id, user, db)
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 400
    else:
        raise AssertionError("Expected last hostname deletion to fail")


def test_delete_group_hostname_deletes_managed_dns_record(monkeypatch):
    class DeleteTrackingClient(FakeCloudflareClient):
        deleted_ids: list[str] = []

        def delete_dns_record(self, zone_id: str, record_id: str):
            self.__class__.deleted_ids.append(record_id)

    monkeypatch.setattr("app.routes.groups.CloudflareClient", DeleteTrackingClient)
    db = make_session()
    zone, user = setup_zone(db)
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com", ttl=60, current_record_id="record-1")
    db.add(group)
    db.flush()
    db.add(FailoverHostname(group_id=group.id, hostname="www.example.com", current_record_id="record-1"))
    api_hostname = FailoverHostname(group_id=group.id, hostname="api.example.com", current_record_id="record-2")
    db.add(api_hostname)
    db.commit()

    updated = delete_group_hostname(api_hostname.id, user, db)

    assert DeleteTrackingClient.deleted_ids == ["record-2"]
    assert [item.hostname for item in updated.hostnames] == ["www.example.com"]


def test_create_global_origin_syncs_to_all_collection_groups():
    db = make_session()
    zone, user = setup_zone(db)
    agent = Agent(name="杭州", region="china", token_hash="hash", status="online")
    db.add(agent)
    db.flush()
    collection = create_collection(FailoverCollectionCreate(name="业务 A"), user, db)
    groups = [
        FailoverGroup(zone_id=zone.id, collection_id=collection.id, hostname="a.example.com"),
        FailoverGroup(zone_id=zone.id, collection_id=collection.id, hostname="b.example.com"),
    ]
    db.add_all(groups)
    db.commit()

    updated = create_global_origin(
        collection.id,
        FailoverGlobalOriginCreate(target="192.0.2.20", port=22, priority=30, remark="通用备用", preferred_agent_id=agent.id, probe_mode="any"),
        user,
        db,
    )

    assert len(updated.global_origins) == 1
    assert updated.global_origins[0].preferred_agent_id == agent.id
    assert updated.global_origins[0].probe_mode == "any"
    for group in db.query(FailoverGroup).filter(FailoverGroup.collection_id == collection.id).all():
        mirrors = [origin for origin in group.origins if origin.global_origin_id == updated.global_origins[0].id]
        assert len(mirrors) == 1
        assert mirrors[0].target == "192.0.2.20"
        assert mirrors[0].priority == 30
        assert mirrors[0].remark == "通用备用"
        assert mirrors[0].preferred_agent_id == agent.id
        assert mirrors[0].probe_mode == "any"


def test_update_global_origin_updates_all_mirrored_origins():
    db = make_session()
    zone, user = setup_zone(db)
    first_agent = Agent(name="杭州", region="china", token_hash="hash-1", status="online")
    second_agent = Agent(name="上海", region="china", token_hash="hash-2", status="online")
    db.add_all([first_agent, second_agent])
    db.flush()
    collection = create_collection(FailoverCollectionCreate(name="业务 B"), user, db)
    group = FailoverGroup(zone_id=zone.id, collection_id=collection.id, hostname="a.example.com")
    db.add(group)
    db.commit()
    updated = create_global_origin(
        collection.id,
        FailoverGlobalOriginCreate(target="192.0.2.20", port=22, priority=30, remark="旧备用", preferred_agent_id=first_agent.id),
        user,
        db,
    )
    global_origin = updated.global_origins[0]
    mirror = db.query(Origin).filter(Origin.global_origin_id == global_origin.id).one()
    db.add(
        ProbeState(
            origin_id=mirror.id,
            source_key=f"agent:{first_agent.id}",
            agent_id=first_agent.id,
            status="healthy",
            last_checked_at=datetime.utcnow(),
        )
    )
    db.commit()

    update_global_origin(
        global_origin.id,
        FailoverGlobalOriginUpdate(target="2001:db8::20", port=443, priority=5, remark="新备用", preferred_agent_id=second_agent.id, probe_mode="local_only", enabled=False),
        user,
        db,
    )

    mirror = db.query(Origin).filter(Origin.global_origin_id == global_origin.id).one()
    assert mirror.target == "2001:db8::20"
    assert mirror.target_type == "ipv6"
    assert mirror.port == 443
    assert mirror.priority == 5
    assert mirror.remark == "新备用"
    assert mirror.preferred_agent_id == second_agent.id
    assert mirror.probe_mode == "local_only"
    assert mirror.enabled is False
    assert mirror.probe_states == []


def test_update_current_global_origin_republishes_dns(monkeypatch):
    FakeCloudflareClient.records = [{"id": "record-1", "name": "www.example.com", "type": "A", "content": "192.0.2.20", "ttl": 60, "proxied": False}]
    monkeypatch.setattr("app.failover.CloudflareClient", FakeCloudflareClient)
    db = make_session()
    zone, user = setup_zone(db)
    collection = FailoverCollection(name="业务 当前全局")
    db.add(collection)
    db.flush()
    group = FailoverGroup(zone_id=zone.id, collection_id=collection.id, hostname="www.example.com", current_record_id="record-1")
    global_origin = FailoverGlobalOrigin(collection_id=collection.id, target="192.0.2.20", target_type="ipv4", port=22, priority=5, enabled=True)
    db.add_all([group, global_origin])
    db.flush()
    mirror = Origin(
        group_id=group.id,
        global_origin_id=global_origin.id,
        target="192.0.2.20",
        target_type="ipv4",
        port=22,
        priority=5,
        status="healthy",
        enabled=True,
    )
    db.add(mirror)
    db.flush()
    group.current_origin_id = mirror.id
    db.commit()

    update_global_origin(global_origin.id, FailoverGlobalOriginUpdate(target="192.0.2.55"), user, db)

    assert FakeCloudflareClient.records[0]["content"] == "192.0.2.55"
    assert FakeCloudflareClient.records[0]["type"] == "A"


def test_delete_current_global_origin_republishes_next_backup(monkeypatch):
    FakeCloudflareClient.records = [{"id": "record-1", "name": "www.example.com", "type": "A", "content": "192.0.2.20", "ttl": 60, "proxied": False}]
    monkeypatch.setattr("app.failover.CloudflareClient", FakeCloudflareClient)
    monkeypatch.setattr("app.failover.run_local_checks", lambda *args, **kwargs: None)
    db = make_session()
    zone, user = setup_zone(db)
    collection = FailoverCollection(name="业务 删除全局")
    db.add(collection)
    db.flush()
    group = FailoverGroup(
        zone_id=zone.id,
        collection_id=collection.id,
        hostname="www.example.com",
        current_record_id="record-1",
        min_switch_interval_seconds=120,
        last_switch_at=datetime.utcnow(),
    )
    global_origin = FailoverGlobalOrigin(collection_id=collection.id, target="192.0.2.20", target_type="ipv4", port=22, priority=5, enabled=True)
    db.add_all([group, global_origin])
    db.flush()
    current = Origin(
        group_id=group.id,
        global_origin_id=global_origin.id,
        target="192.0.2.20",
        target_type="ipv4",
        port=22,
        priority=5,
        status="healthy",
        enabled=True,
    )
    backup = Origin(group_id=group.id, target="192.0.2.30", target_type="ipv4", port=22, priority=10, status="healthy", enabled=True)
    db.add_all([current, backup])
    db.flush()
    group.current_origin_id = current.id
    db.commit()

    delete_global_origin(global_origin.id, user, db)

    db.refresh(group)
    assert group.current_origin_id == backup.id
    assert FakeCloudflareClient.records[0]["content"] == "192.0.2.30"


def test_update_group_collection_adds_and_removes_global_origin_mirrors():
    db = make_session()
    zone, user = setup_zone(db)
    collection = create_collection(FailoverCollectionCreate(name="业务 C"), user, db)
    create_global_origin(
        collection.id,
        FailoverGlobalOriginCreate(target="backup.example.net", port=22, priority=50),
        user,
        db,
    )
    group = FailoverGroup(zone_id=zone.id, hostname="a.example.com")
    db.add(group)
    db.commit()

    update_group(group.id, FailoverGroupUpdate(collection_id=collection.id), user, db)

    group = db.get(FailoverGroup, group.id)
    assert group is not None
    assert group.collection_id == collection.id
    assert [origin.target for origin in group.origins if origin.global_origin_id] == ["backup.example.net"]

    update_group(group.id, FailoverGroupUpdate(collection_id=None), user, db)

    group = db.get(FailoverGroup, group.id)
    assert group is not None
    assert group.collection_id is None
    assert [origin for origin in group.origins if origin.global_origin_id] == []


def test_update_current_origin_publishes_new_dns_target(monkeypatch):
    FakeCloudflareClient.records = [
        {
            "id": "record-1",
            "name": "www.example.com",
            "type": "A",
            "content": "192.0.2.10",
            "ttl": 60,
            "proxied": False,
        }
    ]
    monkeypatch.setattr("app.failover.CloudflareClient", FakeCloudflareClient)
    db = make_session()
    zone, user = setup_zone(db)
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com", ttl=60, current_record_id="record-1")
    db.add(group)
    db.flush()
    origin = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=443, status="healthy", priority=0)
    db.add(origin)
    db.flush()
    group.current_origin_id = origin.id
    db.commit()

    updated = update_origin(origin.id, OriginUpdate(target="2001:db8::5"), user, db)

    assert updated.target == "2001:db8::5"
    assert updated.target_type == "ipv6"
    assert FakeCloudflareClient.records[0]["type"] == "AAAA"
    assert FakeCloudflareClient.records[0]["content"] == "2001:db8::5"


def test_update_hostname_origin_to_expanded_resolves_ips_immediately(monkeypatch):
    db = make_session()
    zone, user = setup_zone(db)
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com", ttl=60)
    db.add(group)
    db.flush()
    origin = Origin(group_id=group.id, target="backup.example.net", target_type="hostname", port=443, status="unknown", priority=10)
    db.add(origin)
    db.commit()

    monkeypatch.setattr("app.health.resolve_hostname_ips", lambda hostname: ["192.0.2.10", "2001:db8::10"])
    monkeypatch.setattr("app.health.tcp_check", lambda target, port, timeout: SimpleNamespace(success=True, rtt_ms=1.0, error=None))

    updated = update_origin(origin.id, OriginUpdate(publish_mode=EXPANDED_PUBLISH_MODE), user, db)

    assert updated.publish_mode == EXPANDED_PUBLISH_MODE
    assert resolved_ips(updated) == ["192.0.2.10", "2001:db8::10"]


def test_update_current_origin_to_expanded_saves_when_no_healthy_ip_yet(monkeypatch):
    db = make_session()
    zone, user = setup_zone(db)
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com", ttl=60, current_record_id="record-1")
    db.add(group)
    db.flush()
    origin = Origin(
        group_id=group.id,
        target="backup.example.net",
        target_type="hostname",
        port=443,
        status="healthy",
        priority=0,
    )
    db.add(origin)
    db.flush()
    group.current_origin_id = origin.id
    db.commit()

    monkeypatch.setattr("app.health.resolve_hostname_ips", lambda hostname: ["192.0.2.10"])
    monkeypatch.setattr("app.health.tcp_check", lambda target, port, timeout: SimpleNamespace(success=True, rtt_ms=1.0, error=None))

    updated = update_origin(origin.id, OriginUpdate(publish_mode=EXPANDED_PUBLISH_MODE), user, db)

    assert updated.publish_mode == EXPANDED_PUBLISH_MODE
    assert resolved_ips(updated) == ["192.0.2.10"]
    assert "暂不发布" in group.last_error


def test_origin_output_hides_disabled_agent_probe_state():
    db = make_session()
    zone, _ = setup_zone(db)
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.flush()
    origin = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=22, status="healthy")
    enabled_agent = Agent(name="上海", region="china", token_hash="hash-1", enabled=True, status="online")
    disabled_agent = Agent(name="杭州", region="china", token_hash="hash-2", enabled=False, status="offline")
    db.add_all([origin, enabled_agent, disabled_agent])
    db.flush()
    db.add_all(
        [
            ProbeState(origin_id=origin.id, source_key="local", status="healthy"),
            ProbeState(origin_id=origin.id, agent_id=enabled_agent.id, source_key=f"agent:{enabled_agent.id}", status="healthy"),
            ProbeState(origin_id=origin.id, agent_id=disabled_agent.id, source_key=f"agent:{disabled_agent.id}", status="healthy"),
        ]
    )
    db.commit()

    output = OriginOut.model_validate(origin)

    assert {state.agent_name for state in output.probe_states} == {None, "上海"}
    assert "杭州" not in {state.agent_name for state in output.probe_states}


def test_create_origin_binds_azpanel_resource_and_syncs_ip():
    db = make_session()
    zone, user = setup_zone(db)
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.flush()
    resource = AzPanelResource(
        name="az-node",
        provider="azure",
        resource_id="vm-1",
        current_ip="203.0.113.5",
        port=443,
        auto_update_origin=True,
    )
    db.add(resource)
    db.commit()

    origin = create_origin(
        group.id,
        OriginCreate(target="192.0.2.99", port=443, priority=10, azpanel_resource_id=resource.id),
        user,
        db,
    )

    assert resource.origin_id == origin.id
    # 绑定后云资源的当前 IP 立即同步到新源站，保持一致
    assert origin.target == "203.0.113.5"
    assert origin.port == 443


def test_create_origin_rejects_missing_azpanel_resource():
    db = make_session()
    zone, user = setup_zone(db)
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.commit()

    with pytest.raises(HTTPException) as exc_info:
        create_origin(
            group.id,
            OriginCreate(target="192.0.2.99", port=22, priority=10, azpanel_resource_id=999),
            user,
            db,
        )

    assert exc_info.value.status_code == 404


def test_create_origin_from_remote_key_creates_and_binds_resource():
    db = make_session()
    zone, user = setup_zone(db)
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.flush()
    remote = AzPanelRemoteResource(
        key="aws|acct|ap-northeast-1|i-9|ipv4",
        name="jp-node",
        provider="aws",
        resource_id="i-9",
        account_id="acct",
        region="ap-northeast-1",
        ip_version="ipv4",
        current_ip="203.0.113.50",
        port=31111,
    )
    db.add(remote)
    db.commit()

    origin = create_origin(
        group.id,
        OriginCreate(target="203.0.113.50", port=31111, priority=10, azpanel_remote_key=remote.key),
        user,
        db,
    )

    resource = db.query(AzPanelResource).one()
    assert resource.origin_id == origin.id
    assert resource.provider == "aws"
    assert resource.resource_id == "i-9"
    assert resource.current_ip == "203.0.113.50"
    assert resource.port == 31111
    assert resource.enabled is True
    assert resource.auto_change_on_blocked is True
    assert resource.auto_update_origin is True


def test_create_origin_from_remote_key_reuses_existing_local_resource():
    db = make_session()
    zone, user = setup_zone(db)
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.flush()
    existing = AzPanelResource(
        name="jp-node",
        provider="aws",
        resource_id="i-9",
        account_id="acct",
        region="ap-northeast-1",
        ip_version="ipv4",
        current_ip="203.0.113.50",
        port=31111,
    )
    remote = AzPanelRemoteResource(
        key="aws|acct|ap-northeast-1|i-9|ipv4",
        name="jp-node",
        provider="aws",
        resource_id="i-9",
        account_id="acct",
        region="ap-northeast-1",
        ip_version="ipv4",
        current_ip="203.0.113.50",
        port=31111,
    )
    db.add_all([existing, remote])
    db.commit()

    origin = create_origin(
        group.id,
        OriginCreate(target="203.0.113.50", port=31111, priority=10, azpanel_remote_key=remote.key),
        user,
        db,
    )

    assert db.query(AzPanelResource).count() == 1
    assert existing.origin_id == origin.id


def test_create_origin_rejects_unknown_remote_key():
    db = make_session()
    zone, user = setup_zone(db)
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.commit()

    with pytest.raises(HTTPException) as exc_info:
        create_origin(
            group.id,
            OriginCreate(target="192.0.2.99", port=22, priority=10, azpanel_remote_key="missing-key"),
            user,
            db,
        )

    assert exc_info.value.status_code == 404
