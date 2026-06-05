import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import CloudflareCredential, DnsRecord, FailoverGroup, FailoverHostname, User, Zone
from app.routes.zones import create_record, update_record
from app.schemas import DnsRecordCreate, DnsRecordUpdate
from app.security import encrypt_secret


class FakeCloudflareClient:
    creates: list[dict] = []
    updates: list[dict] = []

    def __init__(self, token: str):
        self.token = token

    def create_dns_record(self, zone_id: str, record: dict):
        self.creates.append({"zone_id": zone_id, "record": record})
        return {"id": f"record-new-{len(self.creates)}", **record}

    def update_dns_record(self, zone_id: str, record_id: str, record: dict):
        self.updates.append({"zone_id": zone_id, "record_id": record_id, "record": record})
        return {"id": record_id, **record}


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def setup_record(db):
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    record = DnsRecord(
        zone_id=zone.id,
        cf_record_id="record-1",
        name="www.example.com",
        type="A",
        content="192.0.2.10",
        ttl=60,
        proxied=False,
    )
    user = User(username="admin", password_hash="hash")
    db.add_all([record, user])
    db.commit()
    db.refresh(record)
    db.refresh(user)
    return zone, record, user


def test_update_record_updates_cloudflare_and_local_cache(monkeypatch):
    FakeCloudflareClient.creates = []
    FakeCloudflareClient.updates = []
    monkeypatch.setattr("app.routes.zones.CloudflareClient", FakeCloudflareClient)
    db = make_session()
    _, record, user = setup_record(db)

    updated = update_record(
        record.id,
        DnsRecordUpdate(name="www.example.com", type="CNAME", content="backup.example.net", ttl=120),
        user,
        db,
    )

    assert updated.type == "CNAME"
    assert updated.content == "backup.example.net"
    assert updated.ttl == 120
    assert FakeCloudflareClient.updates == [
        {
            "zone_id": "zone-1",
            "record_id": "record-1",
            "record": {
                "type": "CNAME",
                "name": "www.example.com",
                "content": "backup.example.net",
                "ttl": 120,
                "proxied": False,
            },
        }
    ]


def test_create_record_creates_cloudflare_record_and_local_cache(monkeypatch):
    FakeCloudflareClient.creates = []
    FakeCloudflareClient.updates = []
    monkeypatch.setattr("app.routes.zones.CloudflareClient", FakeCloudflareClient)
    db = make_session()
    zone, _, user = setup_record(db)

    created = create_record(
        zone.id,
        DnsRecordCreate(name="api", type="AAAA", content="2001:db8::10", ttl=60),
        user,
        db,
    )

    assert created.cf_record_id == "record-new-1"
    assert created.name == "api.example.com"
    assert created.type == "AAAA"
    assert created.content == "2001:db8::10"
    assert FakeCloudflareClient.creates == [
        {
            "zone_id": "zone-1",
            "record": {
                "type": "AAAA",
                "name": "api.example.com",
                "content": "2001:db8::10",
                "ttl": 60,
                "proxied": False,
            },
        }
    ]


def test_update_record_rejects_content_that_does_not_match_type(monkeypatch):
    FakeCloudflareClient.creates = []
    FakeCloudflareClient.updates = []
    monkeypatch.setattr("app.routes.zones.CloudflareClient", FakeCloudflareClient)
    db = make_session()
    _, record, user = setup_record(db)

    with pytest.raises(HTTPException) as exc_info:
        update_record(
            record.id,
            DnsRecordUpdate(name="www.example.com", type="A", content="backup.example.net", ttl=60),
            user,
            db,
        )

    assert exc_info.value.status_code == 400
    assert not FakeCloudflareClient.updates


def test_create_record_rejects_failover_managed_hostname(monkeypatch):
    FakeCloudflareClient.creates = []
    FakeCloudflareClient.updates = []
    monkeypatch.setattr("app.routes.zones.CloudflareClient", FakeCloudflareClient)
    db = make_session()
    zone, record, user = setup_record(db)
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com", current_record_id=record.cf_record_id)
    db.add(group)
    db.flush()
    db.add(FailoverHostname(group_id=group.id, hostname="www.example.com", current_record_id=record.cf_record_id))
    db.commit()

    with pytest.raises(HTTPException) as exc_info:
        create_record(
            zone.id,
            DnsRecordCreate(name="www", type="A", content="192.0.2.30", ttl=60),
            user,
            db,
        )

    assert exc_info.value.status_code == 409
    assert not FakeCloudflareClient.creates


def test_update_record_rejects_failover_managed_record(monkeypatch):
    FakeCloudflareClient.creates = []
    FakeCloudflareClient.updates = []
    monkeypatch.setattr("app.routes.zones.CloudflareClient", FakeCloudflareClient)
    db = make_session()
    zone, record, user = setup_record(db)
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com", current_record_id=record.cf_record_id)
    db.add(group)
    db.flush()
    db.add(FailoverHostname(group_id=group.id, hostname="www.example.com", current_record_id=record.cf_record_id))
    db.commit()

    with pytest.raises(HTTPException) as exc_info:
        update_record(
            record.id,
            DnsRecordUpdate(name="www.example.com", type="A", content="192.0.2.20", ttl=60),
            user,
            db,
        )

    assert exc_info.value.status_code == 409
    assert not FakeCloudflareClient.updates
