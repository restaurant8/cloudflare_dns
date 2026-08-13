from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.alibaba_httpdns import _desired_origin, call_azpanel_httpdns, evaluate_alibaba_httpdns_groups
from app.database import Base
from app.dns_utils import TcpCheckResult
from app.integrations import update_azpanel_settings
from app.models import (
    AlibabaHttpDnsAccountState,
    AlibabaHttpDnsGroup,
    AlibabaHttpDnsOrigin,
    CloudflareCredential,
    DohEndpoint,
    DohFailoverGroup,
    DohFailoverOrigin,
    Event,
    FailoverGroup,
    Origin,
    User,
    Zone,
)
from app.routes.alibaba_httpdns import adopt_zone, delete_origin_action, release_zone_action, router, update_origin
from app.schemas import AlibabaHttpDnsOriginUpdate, AlibabaHttpDnsZoneAdopt, AlibabaHttpDnsZoneRelease


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def add_group(db, *, current_target="192.0.2.10", backup_target="192.0.2.20"):
    group = AlibabaHttpDnsGroup(
        remote_account_id=7,
        account_name="Alibaba International",
        zone_id="zone-1",
        zone_name="example.com",
        record_id="record-1",
        rr="www",
        record_type="A",
        ttl=60,
        request_source="default",
        enabled=True,
    )
    db.add(group)
    db.flush()
    primary = AlibabaHttpDnsOrigin(group_id=group.id, target=current_target, target_type="ipv4", port=443, priority=0, status="healthy")
    backup = AlibabaHttpDnsOrigin(group_id=group.id, target=backup_target, target_type="ipv4", port=443, priority=10, status="healthy")
    db.add_all([primary, backup])
    db.flush()
    group.current_origin_id = primary.id
    db.commit()
    db.refresh(group)
    return group, primary, backup


def test_desired_origin_keeps_current_at_best_priority():
    group = AlibabaHttpDnsGroup(current_origin_id=2)
    group.origins = [
        AlibabaHttpDnsOrigin(id=1, target="192.0.2.1", target_type="ipv4", port=443, priority=0, status="healthy", enabled=True),
        AlibabaHttpDnsOrigin(id=2, target="192.0.2.2", target_type="ipv4", port=443, priority=0, status="healthy", enabled=True),
    ]

    assert _desired_origin(group).id == 2


def test_call_azpanel_httpdns_uses_shared_proxy_account_gateway(monkeypatch):
    db = make_session()
    update_azpanel_settings(db, {"enabled": True, "base_url": "https://az.example.com/", "api_token": "secret-token", "timeout_seconds": 15})

    def handler(request):
        assert str(request.url.copy_with(query=None)) == "https://az.example.com/api/internal/cloudflare-dns/alibaba-httpdns"
        assert request.headers["Authorization"] == "Bearer secret-token"
        assert str(request.url.params) == "account_id=7&zone_id=zone-1"
        return __import__("httpx").Response(200, json={"status": "success", "data": {"records": [{"RecordId": "record-1"}]}})

    monkeypatch.setattr("app.alibaba_httpdns.httpx.request", lambda method, url, **kwargs: __import__("httpx").Client(transport=__import__("httpx").MockTransport(handler)).request(method, url, **kwargs))

    assert call_azpanel_httpdns(db, account_id=7, zone_id="zone-1")["records"][0]["RecordId"] == "record-1"


def test_unknown_origins_wait_for_recovery_threshold_without_false_alarm(monkeypatch):
    db = make_session()
    group, primary, backup = add_group(db)
    primary.status = "unknown"
    primary.success_count = 0
    backup.status = "unknown"
    backup.success_count = 0
    db.commit()
    monkeypatch.setattr("app.alibaba_httpdns.tcp_check", lambda *args: TcpCheckResult(True, 5.0, None))
    monkeypatch.setattr("app.alibaba_httpdns.send_webhooks", lambda *args, **kwargs: None)

    switched = evaluate_alibaba_httpdns_groups(db, [group.id])
    db.commit()

    db.refresh(group)
    assert switched == 0
    assert group.last_error == "等待源站探测达到判定阈值"
    assert db.query(Event).filter(Event.type == "alibaba_httpdns.no_healthy_origin").count() == 0


def test_unhealthy_primary_switches_to_healthy_backup(monkeypatch):
    db = make_session()
    group, primary, backup = add_group(db)
    published = []
    monkeypatch.setattr("app.alibaba_httpdns.tcp_check", lambda target, *args: TcpCheckResult(target == backup.target, 5.0, None if target == backup.target else "down"))
    monkeypatch.setattr("app.alibaba_httpdns._remote_record", lambda *_args: {"RecordId": "record-1", "Type": "A", "Value": primary.target, "Ttl": 60})
    monkeypatch.setattr("app.alibaba_httpdns.publish_origin", lambda _db, _group, origin: published.append(origin.target) or {"RecordId": "record-1"})
    monkeypatch.setattr("app.alibaba_httpdns.send_webhooks", lambda *args, **kwargs: None)

    for _ in range(5):
        evaluate_alibaba_httpdns_groups(db, [group.id])
        db.commit()

    db.refresh(group)
    assert group.current_origin_id == backup.id
    assert published == [backup.target]
    assert db.query(Event).filter(Event.type == "alibaba_httpdns.switched").count() == 1


def test_repeated_gateway_error_only_emits_one_event(monkeypatch):
    db = make_session()
    group, _primary, _backup = add_group(db)
    monkeypatch.setattr("app.alibaba_httpdns.tcp_check", lambda *args: TcpCheckResult(True, 5.0, None))
    monkeypatch.setattr("app.alibaba_httpdns._remote_record", lambda *_args: (_ for _ in ()).throw(RuntimeError("azpanel 未启用")))
    monkeypatch.setattr("app.alibaba_httpdns.publish_origin", lambda *_args: (_ for _ in ()).throw(RuntimeError("azpanel 未启用")))
    monkeypatch.setattr("app.alibaba_httpdns.send_webhooks", lambda *args, **kwargs: None)

    evaluate_alibaba_httpdns_groups(db, [group.id], force_consistency=True)
    db.commit()
    evaluate_alibaba_httpdns_groups(db, [group.id], force_consistency=True)
    db.commit()

    assert db.query(Event).filter(Event.type == "alibaba_httpdns.publish_failed").count() == 1


def test_adopt_zone_imports_all_enabled_address_records(monkeypatch):
    db = make_session()
    user = User(username="admin", password_hash="hash")
    db.add(user)
    db.commit()
    records = [
        {"RecordId": "a-1", "Rr": "www", "Type": "A", "Value": "192.0.2.10", "Ttl": 30, "EnableStatus": "enable"},
        {"RecordId": "aaaa-1", "Rr": "v6", "Type": "AAAA", "Value": "2001:db8::10", "Ttl": 60, "EnableStatus": "enable"},
        {"RecordId": "cname-1", "Rr": "api", "Type": "CNAME", "Value": "origin.example.net", "Ttl": 60, "EnableStatus": "enable"},
        {"RecordId": "txt-1", "Rr": "@", "Type": "TXT", "Value": "ignored", "Ttl": 60, "EnableStatus": "enable"},
        {"RecordId": "disabled", "Rr": "old", "Type": "A", "Value": "192.0.2.99", "Ttl": 60, "EnableStatus": "disable"},
    ]
    monkeypatch.setattr("app.routes.alibaba_httpdns.list_remote_records", lambda *_args: records)

    response = adopt_zone(
        AlibabaHttpDnsZoneAdopt(remote_account_id=7, account_name="intl", zone_id="zone-1", zone_name="example.com", primary_port=443),
        user,
        db,
    )

    assert response.detail["created"] == 3
    groups = db.query(AlibabaHttpDnsGroup).order_by(AlibabaHttpDnsGroup.record_id).all()
    assert {item.record_id for item in groups} == {"a-1", "aaaa-1", "cname-1"}
    assert {item.record_type for item in groups} == {"A", "AAAA", "CNAME"}
    assert all(len(item.origins) == 1 and item.origins[0].port == 443 for item in groups)


def test_adopt_zone_is_idempotent_and_only_adds_new_records(monkeypatch):
    db = make_session()
    user = User(username="admin", password_hash="hash")
    db.add(user)
    db.commit()
    records = [{"RecordId": "a-1", "Rr": "www", "Type": "A", "Value": "192.0.2.10", "Ttl": 30, "EnableStatus": "enable"}]
    monkeypatch.setattr("app.routes.alibaba_httpdns.list_remote_records", lambda *_args: records)
    payload = AlibabaHttpDnsZoneAdopt(remote_account_id=7, account_name="intl", zone_id="zone-1", zone_name="example.com", primary_port=443)

    first = adopt_zone(payload, user, db)
    second = adopt_zone(payload, user, db)
    records.append({"RecordId": "a-2", "Rr": "api", "Type": "A", "Value": "192.0.2.20", "Ttl": 30, "EnableStatus": "enable"})
    third = adopt_zone(payload, user, db)

    assert first.detail == {"created": 1, "existing": 0, "errors": []}
    assert second.detail == {"created": 0, "existing": 1, "errors": []}
    assert third.detail == {"created": 1, "existing": 1, "errors": []}
    assert db.query(AlibabaHttpDnsGroup).count() == 2


def test_post_delete_origin_compatibility_endpoint_removes_backup_without_cloud_call(monkeypatch):
    db = make_session()
    user = User(username="admin", password_hash="hash")
    db.add(user)
    db.commit()
    group, primary, backup = add_group(db)
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.evaluate_alibaba_httpdns_groups",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("backup deletion must not publish")),
    )

    response = delete_origin_action(backup.id, user, db)

    assert response.message == "源站已删除"
    assert db.get(AlibabaHttpDnsOrigin, backup.id) is None
    assert db.get(AlibabaHttpDnsGroup, group.id).current_origin_id == primary.id


def test_post_release_zone_compatibility_endpoint_removes_local_config_only():
    db = make_session()
    user = User(username="admin", password_hash="hash")
    db.add(user)
    db.commit()
    group, _primary, _backup = add_group(db)

    response = release_zone_action(AlibabaHttpDnsZoneRelease(remote_account_id=7, zone_id="zone-1"), user, db)

    assert response.message == "已取消管理 1 条记录，阿里云云端解析保持不变"
    assert db.get(AlibabaHttpDnsGroup, group.id) is None
    assert db.query(AlibabaHttpDnsOrigin).count() == 0


def test_post_compatibility_routes_are_registered():
    post_paths = {route.path for route in router.routes if "POST" in getattr(route, "methods", set())}

    assert "/alibaba-httpdns/zones/release" in post_paths
    assert "/alibaba-httpdns/origins/{origin_id}/delete" in post_paths


def test_editing_active_origin_keeps_last_remote_value_until_recovered(monkeypatch):
    db = make_session()
    group, primary, backup = add_group(db)
    group.last_published_value = primary.target
    primary.published_ips_json = '["192.0.2.10"]'
    primary.status = "healthy"
    backup.enabled = False
    db.commit()
    writes = []
    monkeypatch.setattr("app.alibaba_httpdns.tcp_check", lambda *args: TcpCheckResult(True, 2.0, None))
    monkeypatch.setattr("app.alibaba_httpdns.publish_origin", lambda *_args, **_kwargs: writes.append(1) or {})
    monkeypatch.setattr("app.alibaba_httpdns.send_webhooks", lambda *args, **kwargs: None)

    update_origin(primary.id, AlibabaHttpDnsOriginUpdate(target="192.0.2.99"), None, db)

    assert group.current_origin_id == primary.id
    assert group.last_published_value == "192.0.2.10"
    assert primary.status == "unknown"
    assert primary.success_count == 1
    assert writes == []


def test_hostname_origin_publishes_only_healthy_ip_of_record_family(monkeypatch):
    db = make_session()
    group, primary, backup = add_group(db)
    primary.target = "multi.example.net"
    primary.target_type = "hostname"
    primary.status = "unknown"
    primary.success_count = 0
    primary.published_ips_json = "[]"
    group.current_origin_id = None
    group.last_published_value = None
    backup.enabled = False
    db.commit()
    writes = []
    monkeypatch.setattr(
        "app.alibaba_httpdns.resolve_hostname_ips_bounded",
        lambda *args: ["192.0.2.10", "192.0.2.11", "2001:db8::10"],
    )
    monkeypatch.setattr(
        "app.alibaba_httpdns.tcp_check",
        lambda ip, *args: TcpCheckResult(ip == "192.0.2.10", 2.0, None if ip == "192.0.2.10" else "blocked"),
    )
    monkeypatch.setattr(
        "app.alibaba_httpdns.publish_origin",
        lambda _db, _group, origin: writes.append(__import__("app.alibaba_httpdns", fromlist=["_desired_value"])._desired_value(_group, origin)) or {},
    )
    monkeypatch.setattr("app.alibaba_httpdns.send_webhooks", lambda *args, **kwargs: None)

    evaluate_alibaba_httpdns_groups(db, [group.id])
    evaluate_alibaba_httpdns_groups(db, [group.id])

    assert primary.resolved_ips == ["192.0.2.10", "192.0.2.11"]
    assert primary.healthy_ips == ["192.0.2.10"]
    assert group.last_published_value == "192.0.2.10"
    assert writes == ["192.0.2.10"]


def test_broken_hostname_rule_does_not_block_other_group(monkeypatch):
    db = make_session()
    healthy_group, primary, backup = add_group(db)
    primary.enabled = False
    broken = AlibabaHttpDnsGroup(
        remote_account_id=8,
        account_name="Alibaba Second",
        zone_id="zone-2",
        zone_name="example.net",
        record_id="record-2",
        rr="www",
        record_type="A",
        ttl=60,
        enabled=True,
    )
    db.add(broken)
    db.flush()
    broken_origin = AlibabaHttpDnsOrigin(
        group_id=broken.id,
        target="gone.example.net",
        target_type="hostname",
        port=443,
        priority=0,
        enabled=True,
    )
    db.add(broken_origin)
    db.commit()
    published = []
    monkeypatch.setattr("app.alibaba_httpdns.tcp_check", lambda *args: TcpCheckResult(True, 2.0, None))
    monkeypatch.setattr(
        "app.alibaba_httpdns.resolve_hostname_ips_bounded",
        lambda *args: (_ for _ in ()).throw(ValueError("NXDOMAIN")),
    )
    monkeypatch.setattr("app.alibaba_httpdns.publish_origin", lambda _db, group, origin: published.append((group.id, origin.id)) or {})
    monkeypatch.setattr("app.alibaba_httpdns.send_webhooks", lambda *args, **kwargs: None)

    evaluate_alibaba_httpdns_groups(db)
    assert evaluate_alibaba_httpdns_groups(db) == 1
    assert healthy_group.current_origin_id == backup.id
    assert published == [(healthy_group.id, backup.id)]
    assert "NXDOMAIN" in (broken_origin.last_error or "")


def test_account_backoff_suppresses_repeated_gateway_requests(monkeypatch):
    db = make_session()
    group, _, _ = add_group(db)
    group.last_published_value = group.origins[0].target
    update_azpanel_settings(
        db,
        {"enabled": True, "base_url": "https://az.example.com", "api_token": "secret-token", "timeout_seconds": 15},
    )
    db.commit()
    calls = []

    def fail(*args, **kwargs):
        calls.append(1)
        raise RuntimeError("azpanel unavailable")

    monkeypatch.setattr("app.alibaba_httpdns.httpx.request", fail)
    monkeypatch.setattr("app.alibaba_httpdns.tcp_check", lambda *args: TcpCheckResult(True, 2.0, None))
    monkeypatch.setattr("app.alibaba_httpdns.send_webhooks", lambda *args, **kwargs: None)
    for _ in range(5):
        evaluate_alibaba_httpdns_groups(db, [group.id], force_consistency=True)
        db.commit()

    state = db.query(AlibabaHttpDnsAccountState).filter_by(remote_account_id=group.remote_account_id).one()
    assert calls == [1]
    assert state.failure_count == 1
    assert state.next_retry_at is not None


def test_same_hostname_can_have_independent_cloudflare_alibaba_and_aws_outputs():
    db = make_session()
    hostname = "shared.example.com"
    credential = CloudflareCredential(name="cf", token_encrypted="secret")
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-cf", name="example.com")
    db.add(zone)
    db.flush()
    cloudflare = FailoverGroup(zone_id=zone.id, hostname=hostname, ttl=60, enabled=True)
    db.add(cloudflare)
    db.flush()
    db.add(Origin(group_id=cloudflare.id, target="192.0.2.1", target_type="ipv4", port=443, priority=0))

    alibaba = AlibabaHttpDnsGroup(
        remote_account_id=7,
        account_name="Alibaba",
        zone_id="zone-ali",
        zone_name="example.com",
        record_id="record-ali",
        rr="shared",
        record_type="A",
        ttl=60,
        enabled=True,
        last_published_value="192.0.2.2",
    )
    db.add(alibaba)
    db.flush()
    db.add(AlibabaHttpDnsOrigin(group_id=alibaba.id, target="192.0.2.2", target_type="ipv4", port=443, priority=0))

    endpoint = DohEndpoint(
        name="aws",
        base_url="https://example.cloudfront.net",
        hmac_secret_encrypted="secret",
    )
    db.add(endpoint)
    db.flush()
    aws = DohFailoverGroup(doh_endpoint_id=endpoint.id, hostname=hostname, ttl=60, enabled=True)
    db.add(aws)
    db.flush()
    db.add(DohFailoverOrigin(group_id=aws.id, target="192.0.2.3", target_type="ipv4", port=443, priority=0))
    db.commit()

    assert cloudflare.hostname == hostname
    assert f"{alibaba.rr}.{alibaba.zone_name}" == hostname
    assert aws.hostname == hostname
    assert {cloudflare.origins[0].target, alibaba.origins[0].target, aws.origins[0].target} == {
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.3",
    }
