import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.doh import build_doh_snapshot
from app.doh_failover import evaluate_doh_failover_groups
from app.models import DohEndpoint, DohFailoverGroup, DohFailoverOrigin
from app.routes.doh import delete_endpoint
from app.routes.doh_failover import create_group, create_origin, delete_group, update_group, update_origin
from app.schemas import (
    DohFailoverGroupCreate,
    DohFailoverGroupUpdate,
    DohFailoverOriginCreate,
    DohFailoverOriginUpdate,
)
from app.security import encrypt_secret


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def setup_group(db):
    endpoint = DohEndpoint(
        name="aws-hk",
        base_url="https://example.cloudfront.net",
        sync_path="/_admin/doh-sync",
        query_path="/dns-query",
        hmac_secret_encrypted=encrypt_secret("x" * 40),
    )
    db.add(endpoint)
    db.flush()
    group = DohFailoverGroup(
        doh_endpoint_id=endpoint.id,
        hostname="snejsat.baidu.com",
        ttl=60,
        enabled=True,
        min_switch_interval_seconds=0,
    )
    db.add(group)
    db.flush()
    primary = DohFailoverOrigin(
        group_id=group.id,
        target="203.0.113.10",
        target_type="ipv4",
        port=443,
        priority=10,
        enabled=True,
        status="healthy",
        ignore_health_check=True,
    )
    backup = DohFailoverOrigin(
        group_id=group.id,
        target="203.0.113.20",
        target_type="ipv4",
        port=443,
        priority=20,
        enabled=True,
        status="healthy",
        ignore_health_check=True,
    )
    db.add_all([primary, backup])
    db.flush()
    return endpoint, group, primary, backup


def test_independent_group_publishes_its_own_selected_ip(monkeypatch):
    db = make_session()
    endpoint, group, primary, _ = setup_group(db)
    posted = []

    class Response:
        def raise_for_status(self):
            return None

    monkeypatch.setattr("app.doh.httpx.post", lambda *args, **kwargs: posted.append(kwargs["content"]) or Response())

    assert evaluate_doh_failover_groups(db, [group.id]) == 1
    assert group.current_origin_id == primary.id
    snapshot = build_doh_snapshot(db, endpoint)
    assert snapshot["records"] == [
        {
            "name": "snejsat.baidu.com",
            "type": "A",
            "value": "203.0.113.10",
            "ttl": 60,
            "doh_failover_group_id": group.id,
        }
    ]
    assert json.loads(posted[-1])["records"][0]["value"] == "203.0.113.10"


def test_independent_group_fails_over_to_backup(monkeypatch):
    db = make_session()
    _, group, primary, backup = setup_group(db)

    class Response:
        def raise_for_status(self):
            return None

    monkeypatch.setattr("app.doh.httpx.post", lambda *args, **kwargs: Response())
    group.current_origin_id = primary.id
    primary.enabled = False

    assert evaluate_doh_failover_groups(db, [group.id]) == 1
    assert group.current_origin_id == backup.id


def test_failed_endpoint_sync_does_not_advance_current_origin(monkeypatch):
    db = make_session()
    _, group, primary, _ = setup_group(db)

    def fail(*args, **kwargs):
        raise RuntimeError("CloudFront unavailable")

    monkeypatch.setattr("app.doh.httpx.post", fail)

    assert evaluate_doh_failover_groups(db, [group.id]) == 0
    assert group.current_origin_id is None
    assert "CloudFront unavailable" in (group.last_error or "")


def test_api_create_rule_then_fixed_candidate_publishes_immediately(monkeypatch):
    db = make_session()
    endpoint = DohEndpoint(
        name="aws-hk",
        base_url="https://example.cloudfront.net",
        sync_path="/_admin/doh-sync",
        query_path="/dns-query",
        hmac_secret_encrypted=encrypt_secret("x" * 40),
    )
    db.add(endpoint)
    db.commit()

    class Response:
        def raise_for_status(self):
            return None

    monkeypatch.setattr("app.doh.httpx.post", lambda *args, **kwargs: Response())
    group = create_group(
        DohFailoverGroupCreate(doh_endpoint_id=endpoint.id, hostname="snejsat.baidu.com"),
        None,
        db,
    )
    origin = create_origin(
        group.id,
        DohFailoverOriginCreate(target="136.110.30.173", port=22, ignore_health_check=True),
        None,
        db,
    )

    refreshed = db.get(DohFailoverGroup, group.id)
    assert refreshed.current_origin_id == origin.id
    assert build_doh_snapshot(db, endpoint)["records"][0]["value"] == "136.110.30.173"


def test_remote_outage_does_not_lock_disable_or_delete(monkeypatch):
    db = make_session()
    endpoint, group, _, _ = setup_group(db)
    db.commit()

    def fail(*args, **kwargs):
        raise RuntimeError("CloudFront unavailable")

    monkeypatch.setattr("app.doh.httpx.post", fail)
    updated = update_group(group.id, DohFailoverGroupUpdate(enabled=False), None, db)
    assert updated.enabled is False

    result = delete_group(group.id, None, db)
    assert result.message == "DoH failover group deleted"
    assert db.get(DohFailoverGroup, group.id) is None
    assert db.query(DohFailoverGroup).filter(DohFailoverGroup.doh_endpoint_id == endpoint.id).count() == 0
    assert delete_endpoint(endpoint.id, None, db).message == "DoH endpoint deleted"


def test_one_unresolvable_rule_does_not_block_healthy_group_switch(monkeypatch):
    db = make_session()
    endpoint, healthy_group, primary, backup = setup_group(db)
    healthy_group.current_origin_id = primary.id
    primary.published_ips_json = '["203.0.113.10"]'
    primary.enabled = False
    broken_group = DohFailoverGroup(
        doh_endpoint_id=endpoint.id,
        hostname="broken.example.com",
        enabled=True,
        min_switch_interval_seconds=0,
    )
    db.add(broken_group)
    db.flush()
    broken_origin = DohFailoverOrigin(
        group_id=broken_group.id,
        target="gone.example.net",
        target_type="hostname",
        port=443,
        priority=10,
        enabled=True,
        ignore_health_check=False,
    )
    db.add(broken_origin)
    db.commit()

    class Response:
        def raise_for_status(self):
            return None

    monkeypatch.setattr("app.doh.httpx.post", lambda *args, **kwargs: Response())
    monkeypatch.setattr(
        "app.doh_failover.resolve_hostname_ips_bounded",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("resolved to no addresses")),
    )

    assert evaluate_doh_failover_groups(db) == 1
    assert healthy_group.current_origin_id == backup.id
    assert "resolved to no addresses" in (broken_origin.last_error or "")


def test_editing_active_ip_keeps_last_published_answer_until_recovered(monkeypatch):
    db = make_session()
    endpoint, group, primary, backup = setup_group(db)
    group.current_origin_id = primary.id
    primary.ignore_health_check = False
    primary.status = "healthy"
    primary.published_ips_json = '["203.0.113.10"]'
    backup.enabled = False
    db.commit()

    class Result:
        success = True
        rtt_ms = 1.0
        error = None

    monkeypatch.setattr("app.doh_failover.tcp_check", lambda *args, **kwargs: Result())
    monkeypatch.setattr("app.doh.httpx.post", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("must not post")))

    update_origin(primary.id, DohFailoverOriginUpdate(target="203.0.113.99"), None, db)

    assert group.current_origin_id == primary.id
    assert build_doh_snapshot(db, endpoint)["records"][0]["value"] == "203.0.113.10"
    assert primary.status == "unknown"
    assert primary.success_count == 1


def test_hostname_candidate_publishes_only_individually_healthy_ips(monkeypatch):
    db = make_session()
    endpoint, group, primary, backup = setup_group(db)
    primary.target = "multi.example.net"
    primary.target_type = "hostname"
    primary.ignore_health_check = False
    primary.status = "unknown"
    backup.enabled = False
    db.commit()

    class Result:
        def __init__(self, success):
            self.success = success
            self.rtt_ms = 1.0
            self.error = None if success else "blocked"

    monkeypatch.setattr(
        "app.doh_failover.resolve_hostname_ips_bounded",
        lambda *args, **kwargs: ["203.0.113.10", "203.0.113.11", "203.0.113.12"],
    )
    monkeypatch.setattr("app.doh_failover.tcp_check", lambda ip, *args: Result(ip == "203.0.113.10"))

    class Response:
        def raise_for_status(self):
            return None

    monkeypatch.setattr("app.doh.httpx.post", lambda *args, **kwargs: Response())
    evaluate_doh_failover_groups(db, [group.id])
    evaluate_doh_failover_groups(db, [group.id])

    assert primary.healthy_ips == ["203.0.113.10"]
    assert [record["value"] for record in build_doh_snapshot(db, endpoint)["records"]] == ["203.0.113.10"]


def test_endpoint_failure_backoff_suppresses_repeated_posts(monkeypatch):
    db = make_session()
    endpoint, group, _, _ = setup_group(db)
    calls = []

    def fail(*args, **kwargs):
        calls.append(1)
        raise RuntimeError("CloudFront unavailable")

    monkeypatch.setattr("app.doh.httpx.post", fail)
    for _ in range(5):
        evaluate_doh_failover_groups(db, [group.id])

    assert len(calls) == 1
    assert endpoint.sync_failure_count == 1
    assert endpoint.next_sync_retry_at is not None
