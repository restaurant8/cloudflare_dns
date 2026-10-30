"""通用换 IP 接口：每台机器一个换 IP 链接 + 一个查 IP 链接。"""

import json
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.integrations import (
    CUSTOM_IP_LATE_WATCH_INTERVAL_SECONDS,
    auto_sync_custom_statuses,
    call_custom_change_ip,
    change_resource_ip,
    custom_ip_settings,
    custom_url_hint,
    parse_custom_ip,
    reconcile_pending_custom_changes,
    sync_custom_resource_status,
    trigger_ip_change_for_origin,
    update_custom_ip_settings,
)
from app.models import AzPanelResource, CloudflareCredential, FailoverGroup, IpChangeJob, Origin, Zone
from app.routes.integrations import create_azpanel_resource, update_azpanel_resource
from app.schemas import AzPanelResourceCreate, AzPanelResourceUpdate
from app.security import encrypt_secret


CHANGE_URL = "https://ip.example.net/vdschangeip.php?utoken=SECRET1&htoken=SECRET2"
STATUS_URL = "https://ip.example.net/vdsgetip.php?utoken=SECRET1&htoken=SECRET2"


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


class FakeProvider:
    """Plays the provider: the query link returns the machine's IP as plain text."""

    def __init__(self, ip="192.0.2.10", change_body="ok"):
        self.ips = [ip]
        self.change_body = change_body
        self.calls = []
        self.status_code = 200

    def set_ips(self, *ips):
        self.ips = list(ips)

    def __call__(self, url, headers=None, timeout=None, follow_redirects=None, verify=None):
        kind = "change" if "changeip" in url else "status"
        self.calls.append((kind, url, verify))
        self.user_agents = getattr(self, "user_agents", []) + [(headers or {}).get("User-Agent")]
        provider = self

        class Response:
            status_code = provider.status_code
            is_success = 200 <= provider.status_code < 300
            text = provider.change_body if kind == "change" else (provider.ips.pop(0) if len(provider.ips) > 1 else provider.ips[0]) + "\n"

        return Response()


def setup(db, monkeypatch, *, current_ip="192.0.2.10", provider=None):
    provider = provider or FakeProvider(current_ip)
    monkeypatch.setattr("app.integrations.httpx.get", provider)
    monkeypatch.setattr("app.integrations.time.sleep", lambda *_: None)
    monkeypatch.setattr("app.integrations.send_webhooks", lambda *args, **kwargs: None)
    update_custom_ip_settings(db, {"enabled": True})
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.flush()
    origin = Origin(group_id=group.id, target=current_ip, target_type="ipv4", port=443, status="blocked")
    db.add(origin)
    db.flush()
    resource = AzPanelResource(
        name="hk-vds",
        provider="custom",
        resource_id="custom-test",
        current_ip=current_ip,
        port=443,
        change_ip_url=encrypt_secret(CHANGE_URL),
        status_url=encrypt_secret(STATUS_URL),
    )
    db.add(resource)
    db.flush()
    origin.azpanel_resource_id = resource.id
    db.commit()
    return provider, resource, origin


def test_parse_plain_text_and_json_responses():
    assert parse_custom_ip("1.162.145.139\n") == "1.162.145.139"
    assert parse_custom_ip('{"ip": "203.0.113.5"}') == "203.0.113.5"
    assert parse_custom_ip('{"success": true, "data": {"vm": {"ipv4": "203.0.113.6"}}}') == "203.0.113.6"
    assert parse_custom_ip("ipv4 203.0.113.7 ipv6 2001:db8::7", "ipv6") == "2001:db8::7"
    # Two candidates of the same family: refuse to guess old vs new.
    assert parse_custom_ip("changed from 203.0.113.1 to 203.0.113.2") is None
    assert parse_custom_ip("") is None
    with pytest.raises(RuntimeError):
        parse_custom_ip('{"success": false, "message": "频率限制"}')


def test_settings_default_wait_is_generous():
    db = make_session()
    assert custom_ip_settings(db)["wait_seconds"] == 600
    assert custom_ip_settings(db)["enabled"] is False
    assert update_custom_ip_settings(db, {"enabled": True, "wait_seconds": 900})["wait_seconds"] == 900


def test_link_hint_and_errors_never_reveal_tokens(monkeypatch):
    assert custom_url_hint(encrypt_secret(CHANGE_URL)) == "https://ip.example.net/vdschangeip.php?••••••"

    db = make_session()
    provider, resource, _ = setup(db, monkeypatch)
    provider.status_code = 500
    with pytest.raises(RuntimeError) as exc:
        sync_custom_resource_status(db, resource)
    assert "SECRET" not in str(exc.value)
    assert "ip.example.net" in str(exc.value)


def test_change_requests_the_link_and_waits_for_the_query(monkeypatch):
    db = make_session()
    provider, resource, _ = setup(db, monkeypatch, provider=FakeProvider(change_body="success 198.51.100.1"))
    resource.verify_tls = False
    db.commit()

    result = call_custom_change_ip(db, resource)

    assert result["pending"] is True
    assert "new_ip" not in result  # the change response is only a hint
    assert result["reported_new_ip"] == "198.51.100.1"
    assert [kind for kind, _, _ in provider.calls] == ["status", "change"]
    assert provider.calls[1][1] == CHANGE_URL
    assert all(verify is False for _, _, verify in provider.calls)
    # Some providers answer anything but a terminal client with "请在终端执行".
    assert set(provider.user_agents) == {"curl/8.7.1"}

    update_custom_ip_settings(db, {"user_agent": "Wget/1.21"})
    call_custom_change_ip(db, resource)
    assert provider.user_agents[-1] == "Wget/1.21"
    assert update_custom_ip_settings(db, {"user_agent": ""})["user_agent"] == "curl/8.7.1"


def test_auto_change_adopts_an_ip_that_already_changed(monkeypatch):
    """Old bug #3: a late new IP made the next block trigger another change."""
    db = make_session()
    provider, resource, origin = setup(db, monkeypatch)
    provider.set_ips("198.51.100.20")  # machine already moved; panel did not notice

    job = trigger_ip_change_for_origin(db, origin, "blocked")
    db.commit()

    assert job.status == "success"
    assert resource.current_ip == "198.51.100.20"
    assert origin.target == "198.51.100.20"
    assert "change" not in [kind for kind, _, _ in provider.calls]


def test_pending_change_is_confirmed_after_two_identical_reads(monkeypatch):
    db = make_session()
    provider, resource, origin = setup(db, monkeypatch)

    job = change_resource_ip(db, resource, trigger_type="auto_blocked", reason="blocked")
    db.commit()
    assert job.status == "pending"

    provider.set_ips("198.51.100.30")
    assert reconcile_pending_custom_changes(db) == 0  # first sighting: candidate only
    assert reconcile_pending_custom_changes(db) == 1
    db.commit()

    assert job.status == "success" and job.new_ip == "198.51.100.30"
    assert resource.current_ip == "198.51.100.30"
    assert origin.target == "198.51.100.30"
    assert resource.pending_change_at is None


def test_stale_stored_ip_does_not_confirm_the_old_ip(monkeypatch):
    """Old bug #2: with a stale stored IP, the machine's old IP was taken as "new"."""
    db = make_session()
    provider, resource, origin = setup(db, monkeypatch, current_ip="192.0.2.10")
    # The machine really sits on .11; the panel still remembers .10.
    provider.set_ips("192.0.2.11", "192.0.2.11")

    job = change_resource_ip(db, resource, trigger_type="manual", reason="test")
    db.commit()
    assert json.loads(job.response_json)["old_ip"] == "192.0.2.11"

    provider.set_ips("192.0.2.11")  # change not visible yet
    for _ in range(3):
        assert reconcile_pending_custom_changes(db) == 0
    assert resource.pending_change_at is not None  # still waiting, old IP not adopted

    provider.set_ips("198.51.100.40")
    reconcile_pending_custom_changes(db)
    assert reconcile_pending_custom_changes(db) == 1
    assert resource.current_ip == "198.51.100.40"


def test_late_ip_is_still_picked_up_after_the_wait_runs_out(monkeypatch):
    """Old bug #1: after the wait ran out nobody looked again."""
    db = make_session()
    provider, resource, origin = setup(db, monkeypatch)
    job = change_resource_ip(db, resource, trigger_type="auto_blocked", reason="blocked")
    db.commit()

    resource.pending_change_at = datetime.utcnow() - timedelta(seconds=601)
    db.commit()
    reconcile_pending_custom_changes(db)
    db.commit()
    assert job.status == "failed"
    assert "仍会每分钟查询" in resource.last_error

    provider.set_ips("198.51.100.50")
    assert auto_sync_custom_statuses(db) == 0  # candidate
    resource.last_status_sync_at -= timedelta(seconds=CUSTOM_IP_LATE_WATCH_INTERVAL_SECONDS)
    assert auto_sync_custom_statuses(db) == 1
    db.commit()

    assert resource.current_ip == "198.51.100.50"
    assert origin.target == "198.51.100.50"
    assert job.status == "success" and job.new_ip == "198.51.100.50"

    # Once confirmed, the late watch stops (no interval configured).
    provider.calls.clear()
    resource.last_status_sync_at -= timedelta(hours=1)
    auto_sync_custom_statuses(db)
    assert provider.calls == []


def test_manual_status_refresh_adopts_stable_ip_and_rejects_unstable(monkeypatch):
    db = make_session()
    provider, resource, origin = setup(db, monkeypatch)

    provider.set_ips("198.51.100.60", "198.51.100.61")
    with pytest.raises(RuntimeError):
        sync_custom_resource_status(db, resource)
    assert resource.current_ip == "192.0.2.10"

    provider.set_ips("198.51.100.62")
    assert sync_custom_resource_status(db, resource) == "198.51.100.62"
    assert origin.target == "198.51.100.62"


def test_api_requires_both_links_and_masks_them(monkeypatch):
    db = make_session()
    monkeypatch.setattr("app.routes.integrations.sync_resource_current_ip_to_origin", lambda *args, **kwargs: False)

    with pytest.raises(ValueError):
        AzPanelResourceCreate(name="hk", provider="custom", change_ip_url=CHANGE_URL)
    with pytest.raises(ValueError):
        AzPanelResourceCreate(name="hk", provider="custom", change_ip_url="ftp://x", status_url=STATUS_URL)

    out = create_azpanel_resource(
        AzPanelResourceCreate(name="hk", provider="custom", change_ip_url=CHANGE_URL, status_url=STATUS_URL, port=443),
        None,
        db,
    )
    assert out.resource_id.startswith("custom-")
    assert out.change_ip_url_hint == "https://ip.example.net/vdschangeip.php?••••••"
    assert out.status_url_hint == "https://ip.example.net/vdsgetip.php?••••••"
    assert "SECRET" not in out.model_dump_json()

    # Leaving the links empty keeps the saved ones.
    updated = update_azpanel_resource(out.id, AzPanelResourceUpdate(change_ip_url="", status_url="", cooldown_seconds=900), None, db)
    assert updated.status_url_hint == out.status_url_hint
    assert updated.cooldown_seconds == 900

    with pytest.raises(HTTPException):
        resource = db.get(AzPanelResource, out.id)
        resource.status_url = None
        update_azpanel_resource(out.id, AzPanelResourceUpdate(remark="x"), None, db)


def setup_unbound(db, monkeypatch, *, origin_port=443, resource_port=22, current_ip="192.0.2.10", external=False):
    """The user's case: the backup sits on the machine's IP but nothing is bound,
    and the resource keeps the form's default port 22 while the backup uses 443."""
    provider = FakeProvider(current_ip)
    monkeypatch.setattr("app.integrations.httpx.get", provider)
    monkeypatch.setattr("app.integrations.time.sleep", lambda *_: None)
    monkeypatch.setattr("app.integrations.send_webhooks", lambda *args, **kwargs: None)
    update_custom_ip_settings(db, {"enabled": True})
    group = FailoverGroup(hostname="www.example.com", cloudflare_publish_enabled=False)
    db.add(group)
    db.flush()
    origin = Origin(group_id=group.id, target=current_ip, target_type="ipv4", port=origin_port, status="blocked")
    if external:
        origin.external_source_id = None
        origin.external_machine_key = "nyanpass-machine-1"
    db.add(origin)
    resource = AzPanelResource(
        name="hk-vds",
        provider="custom",
        resource_id="custom-unbound",
        current_ip=current_ip,
        port=resource_port,
        change_ip_url=encrypt_secret(CHANGE_URL),
        status_url=encrypt_secret(STATUS_URL),
    )
    db.add(resource)
    db.commit()
    return provider, resource, origin


def test_ip_matched_backup_is_bound_and_follows_the_new_ip(monkeypatch):
    db = make_session()
    provider, resource, origin = setup_unbound(db, monkeypatch)

    job = trigger_ip_change_for_origin(db, origin, "blocked")
    db.commit()

    assert job is not None and job.status == "pending"
    assert origin.azpanel_resource_id == resource.id  # now shows as "drives 1"
    assert origin.port == 443  # a custom resource never rewrites the backup's port

    provider.set_ips("198.51.100.70")
    reconcile_pending_custom_changes(db)
    reconcile_pending_custom_changes(db)
    db.commit()

    assert (origin.target, origin.port) == ("198.51.100.70", 443)
    assert resource.current_ip == "198.51.100.70"


def test_manual_change_on_unbound_resource_updates_backup_on_old_ip(monkeypatch):
    db = make_session()
    provider, resource, origin = setup_unbound(db, monkeypatch)

    change_resource_ip(db, resource, trigger_type="manual", reason="test")
    provider.set_ips("198.51.100.71")
    reconcile_pending_custom_changes(db)
    reconcile_pending_custom_changes(db)
    db.commit()

    assert origin.azpanel_resource_id == resource.id
    assert (origin.target, origin.port) == ("198.51.100.71", 443)


def test_first_status_query_binds_backups_on_the_found_ip(monkeypatch):
    db = make_session()
    provider, resource, origin = setup_unbound(db, monkeypatch)
    resource.current_ip = None  # created without an IP, then "查询状态"
    db.commit()

    assert sync_custom_resource_status(db, resource) == "192.0.2.10"
    db.commit()

    assert origin.azpanel_resource_id == resource.id
    assert (origin.target, origin.port) == ("192.0.2.10", 443)


def test_backup_following_an_external_machine_is_not_taken_over(monkeypatch):
    db = make_session()
    provider, resource, origin = setup_unbound(db, monkeypatch, external=True)

    trigger_ip_change_for_origin(db, origin, "blocked")
    db.commit()

    assert origin.azpanel_resource_id is None


def test_explicit_binding_keeps_the_backup_port(monkeypatch):
    from app.routes.groups import update_origin
    from app.schemas import OriginUpdate

    db = make_session()
    provider, resource, origin = setup_unbound(db, monkeypatch)
    monkeypatch.setattr("app.routes.groups._evaluate_locally", lambda *args, **kwargs: None)

    update_origin(origin.id, OriginUpdate(azpanel_resource_id=resource.id), None, db)
    db.refresh(origin)

    assert origin.azpanel_resource_id == resource.id
    assert origin.port == 443


def test_status_query_repairs_backup_left_on_the_old_ip(monkeypatch):
    """A change done before anything was bound left the backup on the old IP."""
    db = make_session()
    provider, resource, origin = setup_unbound(db, monkeypatch, current_ip="198.51.100.80")
    origin.target = "192.0.2.10"  # still on the pre-change IP
    db.add(
        IpChangeJob(
            trigger_type="manual",
            status="success",
            provider="custom",
            azpanel_resource_id=resource.id,
            old_ip="192.0.2.10",
            new_ip="198.51.100.80",
            started_at=datetime.utcnow(),
        )
    )
    db.commit()
    provider.set_ips("198.51.100.80")

    sync_custom_resource_status(db, resource)
    db.commit()

    assert origin.azpanel_resource_id == resource.id
    assert (origin.target, origin.port) == ("198.51.100.80", 443)


def test_saving_a_custom_resource_binds_backups_on_its_ip(monkeypatch):
    db = make_session()
    group = FailoverGroup(hostname="www.example.com", cloudflare_publish_enabled=False)
    db.add(group)
    db.flush()
    origin = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=443)
    db.add(origin)
    db.commit()

    out = create_azpanel_resource(
        AzPanelResourceCreate(name="hk", provider="custom", current_ip="192.0.2.10", change_ip_url=CHANGE_URL, status_url=STATUS_URL),
        None,
        db,
    )

    assert out.bound_origin_ids == [origin.id]
    db.refresh(origin)
    assert origin.port == 443
