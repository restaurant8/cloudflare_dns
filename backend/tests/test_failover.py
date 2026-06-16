from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.dns_utils import parse_target
from app.cloudflare import CloudflareError
from app.failover import choose_desired_origin, evaluate_failover_groups, publish_origin, validate_group_hostname_records
from app.models import CloudflareCredential, FailoverGroup, FailoverHostname, Origin, Zone
from app.origin_expansion import EXPANDED_PUBLISH_MODE, selected_healthy_ip, set_expanded_ip_priorities, set_healthy_ips, set_published_ips
from app.security import encrypt_secret


def origin(id_: int, status: str, priority: int) -> Origin:
    return Origin(id=id_, target=f"192.0.2.{id_}", target_type="ipv4", port=443, status=status, priority=priority, enabled=True)


def test_choose_desired_origin_prefers_priority_then_oldest_origin():
    origins = [
        origin(1, "healthy", 20),
        origin(2, "unhealthy", 5),
        origin(3, "healthy", 10),
        origin(4, "healthy", 10),
    ]
    assert choose_desired_origin(origins).id == 3


def test_choose_desired_origin_ignores_unavailable_regional_statuses():
    origins = [
        origin(1, "blocked", 1),
        origin(2, "machine_down", 2),
        origin(3, "regional_issue", 3),
        origin(4, "healthy", 10),
    ]
    assert choose_desired_origin(origins).id == 4


def test_choose_desired_origin_keeps_current_when_same_best_priority():
    origins = [origin(1, "healthy", 10), origin(2, "healthy", 10)]
    assert choose_desired_origin(origins, current_origin_id=1).id == 1


def test_selected_expanded_ip_keeps_current_published_ip_while_healthy():
    origin_model = Origin(target="backup.example.net", target_type="hostname", publish_mode=EXPANDED_PUBLISH_MODE, port=443)
    set_healthy_ips(origin_model, ["192.0.2.10", "192.0.2.20"])
    set_published_ips(origin_model, ["192.0.2.20"])
    set_expanded_ip_priorities(origin_model, {"192.0.2.10": 1, "192.0.2.20": 50})

    assert selected_healthy_ip(origin_model) == "192.0.2.20"


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
    origin_model = Origin(group_id=group.id, target=target_info.value, target_type=target_info.target_type, port=443, status="healthy", priority=10)
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


def test_publish_origin_updates_all_group_hostnames(monkeypatch):
    FakeCloudflareClient.records = [
        {"id": "record-1", "name": "www.example.com", "type": "A", "content": "192.0.2.1", "ttl": 60, "proxied": False},
        {"id": "record-2", "name": "api.example.com", "type": "A", "content": "192.0.2.2", "ttl": 60, "proxied": False},
    ]
    monkeypatch.setattr("app.failover.CloudflareClient", FakeCloudflareClient)
    db = make_session()
    group, origin_model = setup_group(db, "192.0.2.20")
    db.add(FailoverHostname(group_id=group.id, hostname="www.example.com", current_record_id="record-1"))
    db.add(FailoverHostname(group_id=group.id, hostname="api.example.com", current_record_id="record-2"))
    db.commit()

    record = publish_origin(db, group, origin_model)

    assert record["id"] == "record-1,record-2"
    assert {(item["name"], item["content"]) for item in FakeCloudflareClient.records} == {
        ("www.example.com", "192.0.2.20"),
        ("api.example.com", "192.0.2.20"),
    }


def test_publish_origin_adopts_identical_record_created_outside_managed_ids(monkeypatch):
    class IdenticalCreateClient:
        records = [
            {"id": "record-1", "name": "www.example.com", "type": "A", "content": "192.0.2.1", "ttl": 60, "proxied": False}
        ]
        hidden_record = {
            "id": "api-existing",
            "name": "api.example.com",
            "type": "A",
            "content": "192.0.2.20",
            "ttl": 60,
            "proxied": False,
        }
        create_attempts = 0

        def __init__(self, token: str):
            self.token = token

        def list_dns_records(self, zone_id: str, name: str | None = None):
            records = list(self.__class__.records)
            if self.__class__.create_attempts:
                records.append(self.__class__.hidden_record)
            return [record for record in records if name is None or record["name"] == name]

        def update_dns_record(self, zone_id: str, record_id: str, record: dict):
            existing = next(item for item in self.__class__.records if item["id"] == record_id)
            existing.update(record)
            return {**existing}

        def create_dns_record(self, zone_id: str, record: dict):
            if record["name"] == "api.example.com" and record["content"] == "192.0.2.20":
                self.__class__.create_attempts += 1
                raise CloudflareError("An identical record already exists.", 400, {})
            created = {"id": "new-record", **record}
            self.__class__.records.append(created)
            return created

        def delete_dns_record(self, zone_id: str, record_id: str):
            self.__class__.records = [record for record in self.__class__.records if record["id"] != record_id]

    monkeypatch.setattr("app.failover.CloudflareClient", IdenticalCreateClient)
    db = make_session()
    group, origin_model = setup_group(db, "192.0.2.20")
    db.add(FailoverHostname(group_id=group.id, hostname="www.example.com", current_record_id="record-1"))
    api_hostname = FailoverHostname(group_id=group.id, hostname="api.example.com")
    db.add(api_hostname)
    db.commit()

    record = publish_origin(db, group, origin_model)

    assert record["id"] == "record-1,api-existing"
    assert group.current_record_id == "record-1"
    assert api_hostname.current_record_id == "api-existing"
    assert IdenticalCreateClient.create_attempts == 1


def test_publish_origin_converts_identical_proxied_record_to_dns_only(monkeypatch):
    class IdenticalProxiedClient:
        records = [
            {"id": "record-1", "name": "www.example.com", "type": "A", "content": "192.0.2.1", "ttl": 60, "proxied": False}
        ]
        hidden_record = {
            "id": "api-proxied",
            "name": "api.example.com",
            "type": "A",
            "content": "192.0.2.20",
            "ttl": 1,
            "proxied": True,
        }
        create_attempts = 0

        def __init__(self, token: str):
            self.token = token

        def list_dns_records(self, zone_id: str, name: str | None = None):
            records = list(self.__class__.records)
            if self.__class__.create_attempts:
                records.append(self.__class__.hidden_record)
            return [record for record in records if name is None or record["name"] == name]

        def update_dns_record(self, zone_id: str, record_id: str, record: dict):
            if record_id == self.__class__.hidden_record["id"]:
                self.__class__.hidden_record.update(record)
                return {**self.__class__.hidden_record}
            existing = next(item for item in self.__class__.records if item["id"] == record_id)
            existing.update(record)
            return {**existing}

        def create_dns_record(self, zone_id: str, record: dict):
            if record["name"] == "api.example.com" and record["content"] == "192.0.2.20":
                self.__class__.create_attempts += 1
                raise CloudflareError("An identical record already exists.", 400, {})
            created = {"id": "new-record", **record}
            self.__class__.records.append(created)
            return created

        def delete_dns_record(self, zone_id: str, record_id: str):
            self.__class__.records = [record for record in self.__class__.records if record["id"] != record_id]

    monkeypatch.setattr("app.failover.CloudflareClient", IdenticalProxiedClient)
    db = make_session()
    group, origin_model = setup_group(db, "192.0.2.20")
    db.add(FailoverHostname(group_id=group.id, hostname="www.example.com", current_record_id="record-1"))
    api_hostname = FailoverHostname(group_id=group.id, hostname="api.example.com")
    db.add(api_hostname)
    db.commit()

    record = publish_origin(db, group, origin_model)

    assert record["id"] == "record-1,api-proxied"
    assert api_hostname.current_record_id == "api-proxied"
    assert IdenticalProxiedClient.hidden_record["proxied"] is False
    assert IdenticalProxiedClient.hidden_record["ttl"] == 60


def test_publish_origin_creates_cname_for_hostname(monkeypatch):
    FakeCloudflareClient.records = []
    monkeypatch.setattr("app.failover.CloudflareClient", FakeCloudflareClient)
    db = make_session()
    group, origin_model = setup_group(db, "backup.example.net", current_record_id=None)

    record = publish_origin(db, group, origin_model)

    assert record["type"] == "CNAME"
    assert record["content"] == "backup.example.net"
    assert group.current_record_id == "new-record"


def test_publish_expanded_hostname_creates_selected_healthy_record_by_priority(monkeypatch):
    class ExpandedClient:
        records = [{"id": "record-1", "name": "www.example.com", "type": "CNAME", "content": "backup.example.net", "ttl": 60, "proxied": False}]
        created = 0

        def __init__(self, token: str):
            self.token = token

        def list_dns_records(self, zone_id: str, name: str | None = None):
            return [record for record in self.__class__.records if name is None or record["name"] == name]

        def create_dns_record(self, zone_id: str, record: dict):
            self.__class__.created += 1
            created = {"id": f"new-record-{self.created}", **record}
            self.__class__.records.append(created)
            return created

        def update_dns_record(self, zone_id: str, record_id: str, record: dict):
            raise AssertionError("expanded publishing should recreate the managed record set")

        def delete_dns_record(self, zone_id: str, record_id: str):
            self.__class__.records = [record for record in self.__class__.records if record["id"] != record_id]

    monkeypatch.setattr("app.failover.CloudflareClient", ExpandedClient)
    db = make_session()
    group, origin_model = setup_group(db, "backup.example.net")
    origin_model.publish_mode = EXPANDED_PUBLISH_MODE
    set_healthy_ips(origin_model, ["192.0.2.10", "2001:db8::10"])
    set_expanded_ip_priorities(origin_model, {"192.0.2.10": 50, "2001:db8::10": 5})

    record = publish_origin(db, group, origin_model)

    assert record["type"] == "AAAA"
    assert record["content"] == "2001:db8::10"
    assert group.current_record_id == "new-record-1"
    assert [(item["type"], item["content"]) for item in ExpandedClient.records] == [("AAAA", "2001:db8::10")]


def test_publish_origin_reclaims_orphaned_app_managed_records(monkeypatch):
    class ClientWithOrphanedRecord:
        records = [
            {"id": "record-1", "name": "www.example.com", "type": "A", "content": "192.0.2.1", "ttl": 60, "proxied": False},
            {
                "id": "record-2",
                "name": "www.example.com",
                "type": "AAAA",
                "content": "2001:db8::10",
                "ttl": 60,
                "proxied": False,
                "comment": "managed by cloudflare-dns-failover expanded from backup.example.net",
            },
        ]

        def __init__(self, token: str):
            self.token = token

        def list_dns_records(self, zone_id: str, name: str | None = None):
            return [record for record in self.__class__.records if name is None or record["name"] == name]

        def update_dns_record(self, zone_id: str, record_id: str, record: dict):
            existing = next(item for item in self.__class__.records if item["id"] == record_id)
            existing.update(record)
            return {**existing}

        def create_dns_record(self, zone_id: str, record: dict):
            created = {"id": "new-record", **record}
            self.__class__.records.append(created)
            return created

        def delete_dns_record(self, zone_id: str, record_id: str):
            self.__class__.records = [record for record in self.__class__.records if record["id"] != record_id]

    monkeypatch.setattr("app.failover.CloudflareClient", ClientWithOrphanedRecord)
    db = make_session()
    group, origin_model = setup_group(db, "192.0.2.20", current_record_id="record-1")

    record = publish_origin(db, group, origin_model)

    assert record["id"] == "record-1"
    assert group.current_record_id == "record-1"
    assert {item["id"] for item in ClientWithOrphanedRecord.records} == {"record-1"}


def test_evaluate_republishes_current_origin_when_dns_drifted(monkeypatch):
    FakeCloudflareClient.records = [{"id": "record-1", "name": "www.example.com", "type": "A", "content": "192.0.2.99", "ttl": 60, "proxied": False}]
    monkeypatch.setattr("app.failover.CloudflareClient", FakeCloudflareClient)
    db = make_session()
    group, origin_model = setup_group(db, "192.0.2.20", current_record_id="record-1")
    group.current_origin_id = origin_model.id
    group.last_switch_at = datetime.utcnow()
    db.commit()

    switches = evaluate_failover_groups(db)

    assert switches == 0
    assert FakeCloudflareClient.records[0]["content"] == "192.0.2.20"
    assert FakeCloudflareClient.records[0]["type"] == "A"


def test_publish_origin_rejects_unmanaged_same_name_conflict(monkeypatch):
    FakeCloudflareClient.records = [
        {"id": "record-1", "name": "www.example.com", "type": "A", "content": "192.0.2.1", "ttl": 60, "proxied": False},
        {"id": "manual-record", "name": "www.example.com", "type": "A", "content": "192.0.2.99", "ttl": 60, "proxied": False},
    ]
    monkeypatch.setattr("app.failover.CloudflareClient", FakeCloudflareClient)
    db = make_session()
    group, origin_model = setup_group(db, "192.0.2.20", current_record_id="record-1")

    try:
        publish_origin(db, group, origin_model)
    except ValueError as exc:
        message = str(exc)
        assert "未托管的 A/AAAA/CNAME 冲突记录" in message
        assert "manual-record" in message
        assert "192.0.2.99" in message
    else:
        raise AssertionError("Expected unmanaged conflict")


def test_evaluate_probes_group_before_switching_from_failed_current(monkeypatch):
    db = make_session()
    group, current = setup_group(db, "192.0.2.10")
    backup = Origin(group_id=group.id, target="192.0.2.20", target_type="ipv4", port=443, status="unknown", priority=10)
    current.status = "machine_down"
    current.priority = 0
    group.current_origin_id = current.id
    db.add(backup)
    db.commit()
    db.refresh(group)
    db.refresh(current)
    db.refresh(backup)
    calls = []

    def fake_run_local_checks(db, group_id=None, include_all=False, **_kwargs):
        calls.append((group_id, include_all))
        current.status = "machine_down"
        backup.status = "healthy"
        return 2

    def fake_publish_origin(db, group_arg, origin_arg):
        return {"id": "record-1", "type": "A", "content": origin_arg.target}

    monkeypatch.setattr("app.failover.run_local_checks", fake_run_local_checks)
    monkeypatch.setattr("app.failover.publish_origin", fake_publish_origin)

    switches = evaluate_failover_groups(db)

    assert switches == 1
    assert calls == [(group.id, False)]
    assert group.current_origin_id == backup.id


def test_evaluate_triggers_ip_change_when_current_machine_down(monkeypatch):
    db = make_session()
    group, current = setup_group(db, "192.0.2.10")
    current.status = "machine_down"
    group.current_origin_id = current.id
    db.commit()
    calls = []

    monkeypatch.setattr("app.failover.run_local_checks", lambda *args, **kwargs: 0)
    monkeypatch.setattr("app.failover.send_webhooks", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "app.failover.trigger_ip_change_for_origin",
        lambda db_arg, origin_arg, reason: calls.append((origin_arg.id, reason)),
    )

    evaluate_failover_groups(db)

    assert calls == [(current.id, f"{group.hostname} current origin is machine_down")]


def test_evaluate_switches_to_higher_priority_healthy_origin_by_status(monkeypatch):
    db = make_session()
    group, current = setup_group(db, "192.0.2.10")
    higher_priority_backup = Origin(group_id=group.id, target="192.0.2.20", target_type="ipv4", port=443, status="healthy", priority=1)
    current.priority = 10
    group.current_origin_id = current.id
    db.add(higher_priority_backup)
    db.commit()

    def fake_publish_origin(db, group_arg, origin_arg):
        return {"id": "record-1", "type": "A", "content": origin_arg.target}

    monkeypatch.setattr("app.failover.publish_origin", fake_publish_origin)

    switches = evaluate_failover_groups(db)

    assert switches == 1
    assert group.current_origin_id == higher_priority_backup.id


def test_evaluate_switches_to_fresh_healthy_higher_priority_origin(monkeypatch):
    db = make_session()
    group, current = setup_group(db, "192.0.2.10")
    higher_priority_backup = Origin(
        group_id=group.id,
        target="192.0.2.20",
        target_type="ipv4",
        port=443,
        status="healthy",
        priority=1,
        last_checked_at=datetime.utcnow(),
    )
    current.priority = 10
    group.current_origin_id = current.id
    db.add(higher_priority_backup)
    db.commit()
    db.refresh(higher_priority_backup)

    def fake_publish_origin(db, group_arg, origin_arg):
        return {"id": "record-1", "type": "A", "content": origin_arg.target}

    monkeypatch.setattr("app.failover.publish_origin", fake_publish_origin)

    switches = evaluate_failover_groups(db)

    assert switches == 1
    assert group.current_origin_id == higher_priority_backup.id


def test_evaluate_uses_later_healthy_backup_when_higher_priority_backup_is_unhealthy(monkeypatch):
    db = make_session()
    group, current = setup_group(db, "192.0.2.10")
    first_backup = Origin(group_id=group.id, target="192.0.2.20", target_type="ipv4", port=443, status="machine_down", priority=1)
    later_backup = Origin(group_id=group.id, target="192.0.2.30", target_type="ipv4", port=443, status="healthy", priority=2)
    current.status = "machine_down"
    current.priority = 0
    group.current_origin_id = current.id
    db.add_all([first_backup, later_backup])
    db.commit()

    monkeypatch.setattr("app.failover.run_local_checks", lambda *args, **kwargs: 0)
    monkeypatch.setattr("app.failover.send_webhooks", lambda *args, **kwargs: None)

    def fake_publish_origin(db, group_arg, origin_arg):
        return {"id": "record-1", "type": "A", "content": origin_arg.target}

    monkeypatch.setattr("app.failover.publish_origin", fake_publish_origin)

    switches = evaluate_failover_groups(db)

    assert switches == 1
    assert group.current_origin_id == later_backup.id


def test_no_healthy_origin_notification_is_throttled(monkeypatch):
    db = make_session()
    group, origin_model = setup_group(db, "192.0.2.10")
    origin_model.status = "machine_down"
    group.current_origin_id = origin_model.id
    db.commit()
    sent = []

    monkeypatch.setattr("app.failover.run_local_checks", lambda *args, **kwargs: 0)
    monkeypatch.setattr("app.failover.send_webhooks", lambda db, event_type, payload: sent.append((event_type, payload)))

    evaluate_failover_groups(db)
    group.last_error = None
    evaluate_failover_groups(db)

    assert [item[0] for item in sent] == ["failover.no_healthy_origin"]
    assert sent[0][1]["origins"][0]["status"] == "machine_down"

    group.no_healthy_notified_at = datetime.utcnow() - timedelta(minutes=31)
    group.last_error = None
    evaluate_failover_groups(db)

    assert [item[0] for item in sent] == ["failover.no_healthy_origin", "failover.no_healthy_origin"]


def test_pending_origin_checks_do_not_send_no_healthy_notification(monkeypatch):
    db = make_session()
    group, origin_model = setup_group(db, "192.0.2.10")
    origin_model.status = "unknown"
    group.current_origin_id = origin_model.id
    db.commit()
    sent = []

    monkeypatch.setattr("app.failover.run_local_checks", lambda *args, **kwargs: 0)
    monkeypatch.setattr("app.failover.send_webhooks", lambda db, event_type, payload: sent.append((event_type, payload)))

    switches = evaluate_failover_groups(db)

    assert switches == 0
    assert sent == []
    assert group.last_error == "等待源站探测结果"


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
