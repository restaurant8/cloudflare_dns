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
                {"name": "a", "online": True, "ip4": "8.8.8.8", "ip6": "2001:4860:4860::8888"},
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
            ImportedExternalIp(name="new", group_name="hk", target="8.8.8.8", target_type="ipv4", port=22),
        ],
    )

    count = sync_external_ip_source(db, source)
    db.commit()

    items = db.query(ExternalIpItem).all()
    assert count == 1
    assert [(item.name, item.target) for item in items] == [("new", "8.8.8.8")]
    assert source.status == "ok"
