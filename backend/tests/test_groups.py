from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import CloudflareCredential, User, Zone
from app.routes.groups import create_group
from app.schemas import FailoverGroupCreate
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
