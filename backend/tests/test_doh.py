import hashlib
import hmac
import json
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.doh import build_doh_snapshot, sync_doh_endpoint, sync_due_doh_endpoints, validate_doh_hostname_conflicts
from app.models import DohEndpoint, FailoverGroup, FailoverHostname, Origin
from app.security import encrypt_secret


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def setup_endpoint_group(db):
    endpoint = DohEndpoint(
        name="aws-hk",
        base_url="https://example.cloudfront.net",
        sync_path="/_admin/doh-sync",
        query_path="/dns-query",
        hmac_secret_encrypted=encrypt_secret("x" * 40),
    )
    db.add(endpoint)
    db.flush()
    group = FailoverGroup(
        zone_id=1,
        hostname="snejsat.baidu.com",
        ttl=60,
        enabled=True,
        doh_enabled=True,
        doh_endpoint_id=endpoint.id,
        doh_hostnames_json='["snejsat.baidu.com"]',
        cloudflare_publish_enabled=False,
    )
    db.add(group)
    db.flush()
    origin = Origin(group_id=group.id, target="203.0.113.10", target_type="ipv4", port=443, priority=10, status="healthy")
    db.add(origin)
    db.flush()
    group.current_origin_id = origin.id
    db.commit()
    return endpoint, group, origin


def test_snapshot_uses_real_current_origin_not_cloudflare_decoy():
    db = make_session()
    endpoint, _, _ = setup_endpoint_group(db)

    snapshot = build_doh_snapshot(db, endpoint)

    assert snapshot["records"] == [
        {"name": "snejsat.baidu.com", "type": "A", "value": "203.0.113.10", "ttl": 60, "group_id": 1}
    ]


def test_sync_signs_exact_body(monkeypatch):
    db = make_session()
    endpoint, _, _ = setup_endpoint_group(db)
    captured = {}

    class Response:
        def raise_for_status(self):
            return None

    def fake_post(url, *, content, headers, timeout, verify):
        captured.update(url=url, content=content, headers=headers, timeout=timeout, verify=verify)
        return Response()

    monkeypatch.setattr("app.doh.httpx.post", fake_post)
    assert sync_doh_endpoint(db, endpoint, force=True) is True
    signed = (
        captured["headers"]["x-doh-timestamp"].encode("ascii")
        + b"\n"
        + captured["headers"]["x-doh-nonce"].encode("ascii")
        + b"\n"
        + captured["content"]
    )
    expected = hmac.new(("x" * 40).encode(), signed, hashlib.sha256).hexdigest()
    assert captured["headers"]["x-doh-signature"] == expected
    assert captured["url"] == "https://example.cloudfront.net/_admin/doh-sync"


def test_scheduler_pushes_immediately_when_current_origin_ip_changes(monkeypatch):
    db = make_session()
    endpoint, _, origin = setup_endpoint_group(db)
    calls = []

    class Response:
        def raise_for_status(self):
            return None

    monkeypatch.setattr("app.doh.httpx.post", lambda *args, **kwargs: calls.append(kwargs["content"]) or Response())
    assert sync_doh_endpoint(db, endpoint, force=True) is True
    endpoint.last_synced_at = datetime.utcnow()
    origin.target = "203.0.113.20"
    db.commit()

    assert sync_due_doh_endpoints(db) == 1
    assert len(calls) == 2
    assert json.loads(calls[-1])["records"][0]["value"] == "203.0.113.20"


def test_identical_ticks_do_not_postpone_periodic_forced_reconciliation(monkeypatch):
    db = make_session()
    endpoint, _, _ = setup_endpoint_group(db)
    endpoint.sync_interval_seconds = 3600
    calls = []

    class Response:
        def raise_for_status(self):
            return None

    monkeypatch.setattr("app.doh.httpx.post", lambda *args, **kwargs: calls.append(kwargs["content"]) or Response())
    assert sync_doh_endpoint(db, endpoint, force=True) is True
    first_success = endpoint.last_synced_at

    for _ in range(240):
        assert sync_doh_endpoint(db, endpoint) is False
    assert len(calls) == 1
    assert endpoint.last_synced_at == first_success

    endpoint.last_synced_at = datetime.utcnow() - timedelta(hours=2)
    assert sync_due_doh_endpoints(db) == 1
    assert len(calls) == 2


def test_old_group_without_explicit_doh_names_uses_all_managed_hostnames():
    db = make_session()
    endpoint, group, _ = setup_endpoint_group(db)
    group.doh_hostnames_json = "[]"
    db.add_all(
        [
            FailoverHostname(group_id=group.id, hostname="snejsat.baidu.com"),
            FailoverHostname(group_id=group.id, hostname="alt.baidu.com"),
        ]
    )
    db.commit()

    names = [record["name"] for record in build_doh_snapshot(db, endpoint)["records"]]
    assert names == ["alt.baidu.com", "snejsat.baidu.com"]


def test_hostname_origin_is_resolved_to_address_records_not_cname(monkeypatch):
    db = make_session()
    endpoint, group, origin = setup_endpoint_group(db)
    origin.target = "real-origin.example.net"
    origin.target_type = "hostname"
    db.commit()
    monkeypatch.setattr("app.doh.resolve_hostname_ips", lambda _hostname: ["203.0.113.20", "2001:db8::20"])

    records = build_doh_snapshot(db, endpoint)["records"]

    assert [(item["type"], item["value"]) for item in records] == [
        ("A", "203.0.113.20"),
        ("AAAA", "2001:db8::20"),
    ]


def test_hostname_conflict_is_rejected_before_endpoint_sync():
    db = make_session()
    endpoint, group, _ = setup_endpoint_group(db)

    try:
        validate_doh_hostname_conflicts(
            db,
            endpoint_id=endpoint.id,
            hostnames=["snejsat.baidu.com"],
            exclude_group_id=group.id + 1,
        )
    except ValueError as exc:
        assert "already assigned" in str(exc)
    else:
        raise AssertionError("expected hostname conflict")
