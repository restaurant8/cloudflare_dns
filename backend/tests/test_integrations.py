from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.integrations import (
    azpanel_settings,
    change_resource_ip,
    list_azpanel_remote_resources,
    sync_resource_current_ip_to_origin,
    trigger_ip_change_for_origin,
    update_azpanel_settings,
)
from app.models import AzPanelRemoteResource, AzPanelResource, CloudflareCredential, FailoverGroup, Origin, User, XboardNodeBinding, Zone
from app.security import encrypt_secret


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def make_user(db):
    user = User(username="admin", password_hash="hash")
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def make_origin(db):
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.flush()
    origin = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=22, priority=1, status="blocked")
    db.add(origin)
    db.commit()
    db.refresh(origin)
    return origin


def test_azpanel_settings_do_not_expose_token():
    db = make_session()

    settings = update_azpanel_settings(
        db,
        {
            "enabled": True,
            "base_url": "https://az.example.com/",
            "api_token": "secret-token",
            "timeout_seconds": 15,
            "default_cooldown_seconds": 900,
        },
    )

    assert settings["enabled"] is True
    assert settings["base_url"] == "https://az.example.com"
    assert settings["api_token_configured"] is True
    assert "api_token" not in settings
    assert azpanel_settings(db)["api_token_configured"] is True


def test_list_azpanel_remote_resources_caches_loaded_aws_instances(monkeypatch):
    db = make_session()
    update_azpanel_settings(db, {"base_url": "https://az.example.com", "api_token": "secret-token"})

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "resources": [
                    {
                        "provider": "aws",
                        "name": "tokyo-node",
                        "resource_id": "i-123",
                        "account_id": "aws-main",
                        "region": "ap-northeast-1",
                        "ip_version": "ipv4",
                        "current_ip": "203.0.113.10",
                        "status": "running",
                    }
                ]
            }

    def fake_get(url, params=None, headers=None, timeout=None):
        assert url == "https://az.example.com/api/internal/cloudflare-dns/resources"
        assert params == {"provider": "aws"}
        return Response()

    monkeypatch.setattr("app.integrations.httpx.get", fake_get)

    resources = list_azpanel_remote_resources(db, "aws")
    db.commit()

    assert resources[0]["resource_id"] == "i-123"
    assert resources[0]["cached"] is False
    cached_row = db.query(AzPanelRemoteResource).one()
    assert cached_row.provider == "aws"
    assert cached_row.current_ip == "203.0.113.10"

    def failing_get(*args, **kwargs):
        raise RuntimeError("azpanel unavailable")

    monkeypatch.setattr("app.integrations.httpx.get", failing_get)

    cached = list_azpanel_remote_resources(db, "aws")

    assert cached[0]["resource_id"] == "i-123"
    assert cached[0]["cached"] is True


def test_remote_resource_refresh_syncs_matching_bound_resource_and_origin(monkeypatch):
    db = make_session()
    update_azpanel_settings(db, {"base_url": "https://az.example.com", "api_token": "secret-token"})
    origin = make_origin(db)
    resource = AzPanelResource(
        name="tokyo-node",
        provider="aws",
        resource_id="i-123",
        account_id="aws-main",
        region="ap-northeast-1",
        ip_version="ipv4",
        origin_id=origin.id,
        current_ip="192.0.2.10",
        port=31111,
        auto_update_origin=True,
    )
    db.add(resource)
    db.commit()

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "resources": [
                    {
                        "provider": "aws",
                        "name": "tokyo-node",
                        "resource_id": "i-123",
                        "account_id": "aws-main",
                        "region": "ap-northeast-1",
                        "ip_version": "ipv4",
                        "current_ip": "203.0.113.88",
                    }
                ]
            }

    monkeypatch.setattr("app.integrations.httpx.get", lambda *args, **kwargs: Response())

    list_azpanel_remote_resources(db, "aws")

    assert resource.current_ip == "203.0.113.88"
    assert origin.target == "203.0.113.88"
    assert origin.port == 31111
    assert origin.status == "unknown"


def test_change_resource_ip_updates_resource_and_xboard_binding_without_xboard_api(monkeypatch):
    db = make_session()
    make_user(db)
    update_azpanel_settings(db, {"enabled": True, "base_url": "https://az.example.com", "api_token": "secret-token"})
    resource = AzPanelResource(name="node-1", provider="azure", resource_id="vm-1", current_ip="192.0.2.10", port=22)
    db.add(resource)
    db.flush()
    node = XboardNodeBinding(name="x-node", xboard_node_id=7, azpanel_resource_id=resource.id)
    db.add(node)
    db.commit()
    db.refresh(resource)

    def fake_change(db, resource, reason=None):
        return {"new_ip": "198.51.100.20", "message": "ok"}

    monkeypatch.setattr("app.integrations.call_azpanel_change_ip", fake_change)

    job = change_resource_ip(db, resource, reason="test")

    assert job.status == "success"
    assert job.new_ip == "198.51.100.20"
    assert resource.current_ip == "198.51.100.20"
    assert node.host == "198.51.100.20"
    assert node.last_error is None


def test_bound_resource_current_ip_syncs_to_origin():
    db = make_session()
    origin = make_origin(db)
    resource = AzPanelResource(
        name="aws-node",
        provider="aws",
        resource_id="i-123",
        origin_id=origin.id,
        current_ip="203.0.113.20",
        port=31111,
        auto_update_origin=True,
    )
    db.add(resource)
    db.commit()

    changed = sync_resource_current_ip_to_origin(db, resource)

    assert changed is True
    assert origin.target == "203.0.113.20"
    assert origin.target_type == "ipv4"
    assert origin.port == 31111
    assert origin.status == "unknown"
    assert "资源 IP 已同步" in origin.last_error


def test_trigger_ip_change_for_origin_uses_bound_resource(monkeypatch):
    db = make_session()
    update_azpanel_settings(db, {"enabled": True, "base_url": "https://az.example.com", "api_token": "secret-token"})
    origin = make_origin(db)
    resource = AzPanelResource(
        name="origin-resource",
        provider="azure",
        resource_id="vm-1",
        origin_id=origin.id,
        current_ip=origin.target,
        port=origin.port,
    )
    db.add(resource)
    db.commit()
    db.refresh(origin)

    def fake_change(db, resource, reason=None):
        return {"new_ip": "198.51.100.30"}

    monkeypatch.setattr("app.integrations.call_azpanel_change_ip", fake_change)

    job = trigger_ip_change_for_origin(db, origin, "blocked")

    assert job is not None
    assert job.status == "success"
    assert job.new_ip == "198.51.100.30"
    assert origin.target == "198.51.100.30"
    assert origin.status == "unknown"
