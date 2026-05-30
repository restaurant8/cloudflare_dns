from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.dns_utils import parse_target
from app.failover import choose_desired_origin, publish_origin, validate_group_hostname_records
from app.models import CloudflareCredential, FailoverGroup, Origin, Zone
from app.security import encrypt_secret


def origin(id_: int, status: str, priority: int, weight: int = 1) -> Origin:
    return Origin(id=id_, target=f"192.0.2.{id_}", target_type="ipv4", port=443, status=status, priority=priority, weight=weight, enabled=True)


def test_choose_desired_origin_prefers_priority_then_oldest_origin():
    origins = [
        origin(1, "healthy", 20, 100),
        origin(2, "unhealthy", 5, 100),
        origin(3, "healthy", 10, 1),
        origin(4, "healthy", 10, 5),
    ]
    assert choose_desired_origin(origins).id == 3


def test_choose_desired_origin_ignores_unavailable_regional_statuses():
    origins = [
        origin(1, "blocked", 1, 100),
        origin(2, "machine_down", 2, 100),
        origin(3, "regional_issue", 3, 100),
        origin(4, "healthy", 10, 1),
    ]
    assert choose_desired_origin(origins).id == 4


def test_choose_desired_origin_keeps_current_when_same_best_priority():
    origins = [origin(1, "healthy", 10, 1), origin(2, "healthy", 10, 100)]
    assert choose_desired_origin(origins, current_origin_id=1).id == 1


class FakeCloudflareClient:
    records: list[dict] = []

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


def setup_group(db, target: str, current_record_id: str | None = "record-1"):
    target_info = parse_target(target)
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com", ttl=60, current_record_id=current_record_id)
    origin_model = Origin(group_id=group.id, target=target_info.value, target_type=target_info.target_type, port=443, status="healthy", priority=10, weight=1)
    db.add(group)
    db.flush()
    origin_model.group_id = group.id
    db.add(origin_model)
    db.commit()
    db.refresh(group)
    db.refresh(origin_model)
    return group, origin_model


def test_publish_origin_updates_record_type_for_ipv6(monkeypatch):
    FakeCloudflareClient.records = [{"id": "record-1", "name": "www.example.com", "type": "A", "content": "192.0.2.1", "ttl": 60, "proxied": False}]
    monkeypatch.setattr("app.failover.CloudflareClient", FakeCloudflareClient)
    db = make_session()
    group, origin_model = setup_group(db, "2001:db8::5")

    record = publish_origin(db, group, origin_model)

    assert record["type"] == "AAAA"
    assert record["content"] == "2001:db8::5"


def test_publish_origin_creates_cname_for_hostname(monkeypatch):
    FakeCloudflareClient.records = []
    monkeypatch.setattr("app.failover.CloudflareClient", FakeCloudflareClient)
    db = make_session()
    group, origin_model = setup_group(db, "backup.example.net", current_record_id=None)

    record = publish_origin(db, group, origin_model)

    assert record["type"] == "CNAME"
    assert record["content"] == "backup.example.net"
    assert group.current_record_id == "new-record"


def test_validate_group_hostname_records_rejects_cname_conflict():
    class Client:
        def list_dns_records(self, zone_id: str, name: str | None = None):
            return [
                {"id": "a", "name": name, "type": "A", "proxied": False},
                {"id": "cname", "name": name, "type": "CNAME", "proxied": False},
            ]

    try:
        validate_group_hostname_records(Client(), "zone-1", "www.example.com")
    except ValueError as exc:
        assert "多个 A/AAAA/CNAME" in str(exc)
    else:
        raise AssertionError("Expected conflict")
