from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.alibaba_httpdns import _desired_origin, call_azpanel_httpdns, evaluate_alibaba_httpdns_groups
from app.database import Base
from app.dns_utils import TcpCheckResult
from app.integrations import update_azpanel_settings
from app.models import AlibabaHttpDnsGroup, AlibabaHttpDnsOrigin, Event, User
from app.routes.alibaba_httpdns import adopt_zone
from app.schemas import AlibabaHttpDnsZoneAdopt


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
