from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.integrations import (
    AutoIpChangeGuard,
    azpanel_settings,
    change_resource_ip,
    ip_change_event_payload,
    list_azpanel_remote_resources,
    resource_bound_origins,
    sync_resource_current_ip_to_origin,
    trigger_ip_change_for_origin,
    update_azpanel_settings,
    update_custom_ip_settings,
)
from app.models import AzPanelRemoteResource, AzPanelResource, CloudflareCredential, FailoverCollection, FailoverGlobalOrigin, FailoverGroup, Origin, ProbeState, User, XboardNodeBinding, Zone
from app.notifier import render_telegram_message
from app.routes.integrations import delete_azpanel_resource, list_azpanel_resources
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



def bind_resource_to_origin(db, resource):
    """Add a resource and bind it the way the app does — on the origin.

    The binding used to live on AzPanelResource.origin_id; it moved onto the origin
    so one machine can drive several backups. Tests still express intent with the
    ``origin_id=`` kwarg, and this translates it.
    """
    db.add(resource)
    db.flush()
    if resource.origin_id:
        origin = db.get(Origin, resource.origin_id)
        if origin is not None:
            origin.azpanel_resource_id = resource.id
    return resource


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
    bind_resource_to_origin(db, resource)
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
    bind_resource_to_origin(db, resource)
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
    bind_resource_to_origin(db, resource)
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
    bind_resource_to_origin(db, resource)
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


def test_trigger_ip_change_syncs_mismatched_resource_ip_before_changing(monkeypatch):
    db = make_session()
    update_azpanel_settings(db, {"enabled": True, "base_url": "https://az.example.com", "api_token": "secret-token"})
    origin = make_origin(db)
    origin.target = "1.1.1.1"
    origin.port = 31111
    origin.status = "machine_down"
    resource = AzPanelResource(
        name="aws-node",
        provider="aws",
        resource_id="i-123",
        origin_id=origin.id,
        current_ip="203.0.113.90",
        port=31111,
        auto_update_origin=True,
    )
    bind_resource_to_origin(db, resource)
    db.flush()
    db.add(ProbeState(origin_id=origin.id, source_key="local", status="unhealthy"))
    db.commit()
    db.refresh(origin)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("stale origin IP should be synced, not changed")

    monkeypatch.setattr("app.integrations.call_azpanel_change_ip", fail_if_called)

    job = trigger_ip_change_for_origin(db, origin, "machine_down")

    assert job is None
    assert origin.target == "203.0.113.90"
    assert origin.port == 31111
    assert origin.status == "unknown"
    assert origin.last_checked_at is None
    assert origin.probe_states == []

def test_remote_resource_refresh_prunes_resources_deleted_on_azpanel(monkeypatch):
    db = make_session()
    update_azpanel_settings(db, {"base_url": "https://az.example.com", "api_token": "secret-token"})

    def make_response(resources):
        class Response:
            def raise_for_status(self):
                return None

            def json(self):
                return {"resources": resources}

        return Response()

    first_batch = [
        {
            "provider": "aws",
            "name": "tokyo-node",
            "resource_id": "i-123",
            "account_id": "aws-main",
            "region": "ap-northeast-1",
            "current_ip": "203.0.113.10",
        },
        {
            "provider": "aws",
            "name": "osaka-node",
            "resource_id": "i-456",
            "account_id": "aws-main",
            "region": "ap-northeast-3",
            "current_ip": "203.0.113.11",
        },
    ]
    monkeypatch.setattr("app.integrations.httpx.get", lambda *args, **kwargs: make_response(first_batch))
    assert len(list_azpanel_remote_resources(db, "aws")) == 2
    db.commit()

    # osaka-node 在 azpanel 侧被删除，刷新后应从列表和缓存里消失
    second_batch = [first_batch[0]]
    monkeypatch.setattr("app.integrations.httpx.get", lambda *args, **kwargs: make_response(second_batch))
    resources = list_azpanel_remote_resources(db, "aws")
    db.commit()

    assert [item["resource_id"] for item in resources] == ["i-123"]
    cached_rows = db.query(AzPanelRemoteResource).all()
    assert [row.resource_id for row in cached_rows] == ["i-123"]

    # azpanel 挂掉时仍回退到（已清理过的）本地缓存
    def failing_get(*args, **kwargs):
        raise RuntimeError("azpanel unavailable")

    monkeypatch.setattr("app.integrations.httpx.get", failing_get)
    fallback = list_azpanel_remote_resources(db, "aws")

    assert [item["resource_id"] for item in fallback] == ["i-123"]
    assert fallback[0]["cached"] is True


def test_remote_resource_prune_keeps_other_provider_cache(monkeypatch):
    db = make_session()
    update_azpanel_settings(db, {"base_url": "https://az.example.com", "api_token": "secret-token"})

    def make_response(resources):
        class Response:
            def raise_for_status(self):
                return None

            def json(self):
                return {"resources": resources}

        return Response()

    azure_batch = [{"provider": "azure", "name": "az-node", "resource_id": "vm-1", "current_ip": "203.0.113.20"}]
    monkeypatch.setattr("app.integrations.httpx.get", lambda *args, **kwargs: make_response(azure_batch))
    list_azpanel_remote_resources(db, "azure")
    db.commit()

    # 只刷新 AWS 不应清掉 Azure 的缓存
    aws_batch = [{"provider": "aws", "name": "aws-node", "resource_id": "i-789", "current_ip": "203.0.113.30"}]
    monkeypatch.setattr("app.integrations.httpx.get", lambda *args, **kwargs: make_response(aws_batch))
    list_azpanel_remote_resources(db, "aws")
    db.commit()

    providers = sorted(row.provider for row in db.query(AzPanelRemoteResource).all())
    assert providers == ["aws", "azure"]

def test_remote_resource_refresh_with_empty_list_clears_cache(monkeypatch):
    db = make_session()
    update_azpanel_settings(db, {"base_url": "https://az.example.com", "api_token": "secret-token"})

    def make_response(resources):
        class Response:
            def raise_for_status(self):
                return None

            def json(self):
                # azpanel 实际返回的嵌套结构
                return {"status": "success", "data": {"resources": resources}}

        return Response()

    seeded = [{"provider": "aws", "name": "old-node", "resource_id": "i-1", "current_ip": "203.0.113.9"}]
    monkeypatch.setattr("app.integrations.httpx.get", lambda *args, **kwargs: make_response(seeded))
    assert len(list_azpanel_remote_resources(db, "aws")) == 1
    db.commit()

    # azpanel 侧机器全部删除：空列表是有效结果，必须清空而不是回退到缓存
    monkeypatch.setattr("app.integrations.httpx.get", lambda *args, **kwargs: make_response([]))
    resources = list_azpanel_remote_resources(db, "aws")
    db.commit()

    assert resources == []
    assert db.query(AzPanelRemoteResource).count() == 0


def test_change_resource_ip_dispatches_custom_and_updates_origin(monkeypatch):
    db = make_session()
    origin = make_origin(db)
    update_custom_ip_settings(db, {"enabled": True})
    resource = AzPanelResource(
        name="syn-861",
        provider="custom",
        resource_id="861",
        ip_version="ipv4",
        origin_id=origin.id,
        current_ip="192.0.2.10",
        port=22,
    )
    bind_resource_to_origin(db, resource)
    db.commit()
    db.refresh(resource)

    monkeypatch.setattr(
        "app.integrations.call_custom_change_ip", lambda db_, res, reason=None, **_: {"new_ip": "198.51.100.7"}
    )

    job = change_resource_ip(db, resource, trigger_type="manual", reason="test")
    db.commit()

    assert job.status == "success"
    assert job.provider == "custom"
    assert job.new_ip == "198.51.100.7"
    assert resource.current_ip == "198.51.100.7"
    db.refresh(origin)
    assert origin.target == "198.51.100.7"


def test_trigger_ip_change_uses_custom_resource_when_azpanel_disabled(monkeypatch):
    db = make_session()
    origin = make_origin(db)
    update_custom_ip_settings(db, {"enabled": True})
    resource = AzPanelResource(
        name="syn-861",
        provider="custom",
        resource_id="861",
        ip_version="ipv4",
        origin_id=origin.id,
        current_ip="192.0.2.10",
        port=22,
    )
    bind_resource_to_origin(db, resource)
    db.commit()
    db.refresh(resource)

    called = {}

    def fake_change(db_, res, reason=None, **_):
        called["id"] = res.id
        return {"new_ip": "198.51.100.8"}

    monkeypatch.setattr("app.integrations.call_custom_change_ip", fake_change)

    job = trigger_ip_change_for_origin(db, origin, "origin blocked")
    db.commit()

    assert job is not None
    assert job.status == "success"
    assert called["id"] == resource.id


def test_trigger_ip_change_skips_custom_resource_when_disabled(monkeypatch):
    db = make_session()
    origin = make_origin(db)
    # 通用接口未启用：绑定的资源不应触发换 IP
    resource = AzPanelResource(
        name="syn-861",
        provider="custom",
        resource_id="861",
        ip_version="ipv4",
        origin_id=origin.id,
        current_ip="192.0.2.10",
        port=22,
    )
    bind_resource_to_origin(db, resource)
    db.commit()

    def fail_if_called(*args, **kwargs):
        raise AssertionError("custom change ip should not be called when integration is disabled")

    monkeypatch.setattr("app.integrations.call_custom_change_ip", fail_if_called)

    assert trigger_ip_change_for_origin(db, origin, "origin blocked") is None


def test_trigger_ip_change_matches_resource_by_ip_when_port_differs(monkeypatch):
    db = make_session()
    origin = make_origin(db)  # target 192.0.2.10:22
    origin.port = 443  # 外部 IP 的入口端口，和云资源的检查端口不同
    update_azpanel_settings(db, {"enabled": True, "base_url": "https://az.example.com", "api_token": "tok"})
    resource = AzPanelResource(
        name="az-vm",
        provider="azure",
        resource_id="vm-1",
        ip_version="ipv4",
        current_ip="192.0.2.10",
        port=22,
    )
    bind_resource_to_origin(db, resource)
    db.commit()
    db.refresh(resource)

    called = {}

    def fake_change(db_, res, reason=None, **_):
        called["id"] = res.id
        return {"new_ip": "198.51.100.9"}

    monkeypatch.setattr("app.integrations.call_azpanel_change_ip", fake_change)

    job = trigger_ip_change_for_origin(db, origin, "origin blocked")
    db.commit()

    assert job is not None
    assert job.status == "success"
    assert called["id"] == resource.id
    # azpanel 资源的端口就是机器端口：端口不同的源站不自动绑定、不直接改，
    # 等外部来源同步新 IP 后按绑定跟随（通用接口只看 IP，见 test_custom_ip.py）
    assert origin.azpanel_resource_id is None
    assert origin.target == "192.0.2.10"


def test_trigger_ip_change_refuses_ambiguous_unbound_resources(monkeypatch):
    """An IP shared by several accounts must never select the first account."""
    db = make_session()
    origin = make_origin(db)
    origin.port = 443
    update_custom_ip_settings(db, {"enabled": True})
    db.add_all(
        [
            AzPanelResource(
                name=f"account-{index}",
                provider="custom",
                resource_id=str(index),
                current_ip=origin.target,
                port=22,
            )
            for index in range(3)
        ]
    )
    db.commit()
    events = []

    monkeypatch.setattr(
        "app.integrations.change_resource_ip",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("ambiguous resource must not be changed")),
    )
    monkeypatch.setattr(
        "app.integrations.add_event",
        lambda _db, event_type, _severity, message, payload: events.append((event_type, message, payload)),
    )
    monkeypatch.setattr("app.integrations.send_webhooks", lambda *args, **kwargs: None)

    guard = AutoIpChangeGuard()
    assert trigger_ip_change_for_origin(db, origin, "origin blocked", guard=guard) is None
    assert trigger_ip_change_for_origin(db, origin, "origin blocked", guard=guard) is None

    assert len(events) == 1
    assert events[0][0] == "azpanel.ip_change_ambiguous"
    assert "3 个未绑定云资源" in events[0][2]["error"]


def test_ip_fallback_does_not_use_resource_bound_to_another_origin(monkeypatch):
    """An unbound origin sharing an address cannot rotate another domain's machine."""
    db = make_session()
    unbound, bound = make_origins_in_two_groups(db)
    update_custom_ip_settings(db, {"enabled": True})
    resource = AzPanelResource(
        name="bound-account",
        provider="custom",
        resource_id="861",
        current_ip=unbound.target,
        port=unbound.port,
    )
    db.add(resource)
    db.flush()
    bound.azpanel_resource_id = resource.id
    db.commit()

    monkeypatch.setattr(
        "app.integrations.change_resource_ip",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("cross-bound resource must not be changed")),
    )

    assert trigger_ip_change_for_origin(db, unbound, "origin blocked") is None


def test_auto_ip_change_guard_allows_only_one_distinct_resource_per_pass(monkeypatch):
    db = make_session()
    first, second = make_origins_in_two_groups(db)
    update_custom_ip_settings(db, {"enabled": True})
    resources = [
        AzPanelResource(
            name=f"account-{index}",
            provider="custom",
            resource_id=str(index),
            current_ip=origin.target,
            port=origin.port,
        )
        for index, origin in enumerate((first, second), start=1)
    ]
    db.add_all(resources)
    db.flush()
    first.azpanel_resource_id = resources[0].id
    second.azpanel_resource_id = resources[1].id
    db.commit()
    attempted = []
    events = []

    def fake_change(_db, resource, **_kwargs):
        attempted.append(resource.id)
        return object()

    monkeypatch.setattr("app.integrations.change_resource_ip", fake_change)
    monkeypatch.setattr(
        "app.integrations.add_event",
        lambda _db, event_type, _severity, message, payload: events.append((event_type, message, payload)),
    )
    monkeypatch.setattr("app.integrations.send_webhooks", lambda *args, **kwargs: None)

    guard = AutoIpChangeGuard()
    assert trigger_ip_change_for_origin(db, first, "first blocked", guard=guard) is not None
    assert trigger_ip_change_for_origin(db, second, "second blocked", guard=guard) is None

    assert attempted == [resources[0].id]
    assert guard.attempted_resource_ids == {resources[0].id}
    assert [event[0] for event in events] == ["azpanel.ip_change_suppressed"]


def test_auto_ip_change_guard_deduplicates_shared_bound_resource(monkeypatch):
    db = make_session()
    first, second = make_origins_in_two_groups(db)
    update_custom_ip_settings(db, {"enabled": True})
    resource = AzPanelResource(
        name="shared-account",
        provider="custom",
        resource_id="861",
        current_ip=first.target,
        port=first.port,
    )
    db.add(resource)
    db.flush()
    first.azpanel_resource_id = resource.id
    second.azpanel_resource_id = resource.id
    db.commit()
    attempted = []

    def fake_change(_db, resource_arg, **_kwargs):
        attempted.append(resource_arg.id)
        return object()

    monkeypatch.setattr("app.integrations.change_resource_ip", fake_change)

    guard = AutoIpChangeGuard()
    assert trigger_ip_change_for_origin(db, first, "first blocked", guard=guard) is not None
    assert trigger_ip_change_for_origin(db, second, "second blocked", guard=guard) is None

    assert attempted == [resource.id]


def test_successful_ip_change_marks_external_sources_due(monkeypatch):
    from datetime import datetime as dt

    from app.models import ExternalIpSource

    db = make_session()
    update_custom_ip_settings(db, {"enabled": True})
    source = ExternalIpSource(
        name="nyanpass",
        base_url="https://ny.example.com",
        token_encrypted=encrypt_secret("token"),
        last_synced_at=dt.utcnow(),
    )
    resource = AzPanelResource(
        name="syn-861", provider="custom", resource_id="861", ip_version="ipv4", current_ip="192.0.2.10", port=22
    )
    db.add_all([source, resource])
    db.commit()
    db.refresh(resource)

    monkeypatch.setattr(
        "app.integrations.call_custom_change_ip", lambda db_, res, reason=None, **_: {"new_ip": "198.51.100.10"}
    )

    job = change_resource_ip(db, resource, trigger_type="manual", reason="test")
    db.commit()

    assert job.status == "success"
    # 换 IP 成功后外部来源被标记为到期，下个调度周期立即重新同步
    assert source.last_synced_at is None


def test_change_resource_ip_pending_marks_resource_and_external_due(monkeypatch):
    from app.models import ExternalIpSource
    from datetime import datetime as dt

    db = make_session()
    origin = make_origin(db)
    update_custom_ip_settings(db, {"enabled": True})
    source = ExternalIpSource(name="ny", base_url="https://ny.example.com", token_encrypted=encrypt_secret("t"), last_synced_at=dt.utcnow())
    resource = AzPanelResource(
        name="syn-861", provider="custom", resource_id="861", ip_version="ipv4", origin_id=origin.id, current_ip="192.0.2.10", port=22
    )
    db.add_all([source, resource])
    db.commit()
    db.refresh(resource)

    monkeypatch.setattr("app.integrations.call_custom_change_ip", lambda db_, res, reason=None, **_: {"pending": True, "old_ip": "192.0.2.10"})

    job = change_resource_ip(db, resource, trigger_type="auto_blocked", reason="blocked")
    db.commit()

    assert job.status == "pending"
    assert job.new_ip is None
    assert resource.pending_change_at is not None
    # 源站不立即改（等新 IP），但外部来源被催重新同步
    db.refresh(origin)
    assert origin.target == "192.0.2.10"
    assert source.last_synced_at is None


def make_origins_in_two_groups(db, count=2):
    """One machine used as a backup by several domains — the reported topology."""
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    origins = []
    for index in range(count):
        group = FailoverGroup(zone_id=zone.id, hostname=f"h{index}.example.com")
        db.add(group)
        db.flush()
        origin = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=22, priority=1, status="blocked")
        db.add(origin)
        db.flush()
        origins.append(origin)
    db.commit()
    return origins


def test_one_resource_syncs_its_ip_to_every_bound_backup():
    """The reported bug: binding a second backup left the first on the dead IP."""
    db = make_session()
    first, second = make_origins_in_two_groups(db)
    resource = AzPanelResource(
        name="aws-tokyo", provider="aws", resource_id="i-1", ip_version="ipv4", current_ip="198.51.100.7", port=22
    )
    db.add(resource)
    db.flush()
    first.azpanel_resource_id = resource.id
    second.azpanel_resource_id = resource.id
    first.group.current_origin_id = first.id
    second.group.current_origin_id = second.id
    db.commit()

    assert sync_resource_current_ip_to_origin(db, resource) is True
    db.commit()

    for origin in (first, second):
        db.refresh(origin)
        assert origin.target == "198.51.100.7"
        assert origin.status == "unknown"
        # DNS still points at the previous target, so this group must not remain in
        # the steady-state fast path where the consistency cache can skip a write.
        assert origin.group.current_origin_id is None


def test_one_resource_ip_change_republishes_every_domain_even_with_fresh_consistency_cache(monkeypatch):
    """Regression for “several domains bind one resource, only one DNS record updates”."""
    from datetime import datetime as dt

    from app import failover as failover_module

    db = make_session()
    first, second = make_origins_in_two_groups(db)
    resource = AzPanelResource(
        name="aws-tokyo", provider="aws", resource_id="i-1", ip_version="ipv4", current_ip="192.0.2.10", port=22
    )
    db.add(resource)
    db.flush()
    now = dt.utcnow()
    for origin in (first, second):
        origin.azpanel_resource_id = resource.id
        origin.status = "healthy"
        origin.group.current_origin_id = origin.id
        failover_module._consistency_checked_at[origin.group_id] = now
    db.commit()

    resource.current_ip = "198.51.100.22"
    assert sync_resource_current_ip_to_origin(db, resource) is True
    # Simulate the next probe pass accepting the new address.
    for origin in (first, second):
        origin.status = "healthy"

    published = []

    def fake_publish(_db, group, origin):
        published.append((group.hostname, origin.target))
        return {"id": f"record-{group.id}", "type": "A", "content": origin.target, "hostnames": [group.hostname]}

    monkeypatch.setattr("app.failover.run_local_checks", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.failover.publish_origin", fake_publish)
    monkeypatch.setattr("app.failover.add_event", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.failover.send_webhooks", lambda *args, **kwargs: None)

    switches = failover_module.evaluate_failover_groups(
        db,
        group_ids=[first.group_id, second.group_id],
        consistency_check_interval_seconds=300,
        now=now,
        trigger_ip_changes=False,
    )

    assert switches == 2
    assert set(published) == {
        ("h0.example.com", "198.51.100.22"),
        ("h1.example.com", "198.51.100.22"),
    }


def test_binding_a_second_backup_does_not_unbind_the_first():
    db = make_session()
    first, second = make_origins_in_two_groups(db)
    resource = AzPanelResource(
        name="aws-tokyo", provider="aws", resource_id="i-1", ip_version="ipv4", current_ip="198.51.100.7", port=22
    )
    db.add(resource)
    db.flush()
    first.azpanel_resource_id = resource.id
    db.commit()

    second.azpanel_resource_id = resource.id
    db.commit()

    bound = {origin.id for origin in resource_bound_origins(db, resource)}
    assert bound == {first.id, second.id}


def test_resource_bound_to_a_global_backup_reaches_every_mirrored_origin():
    from app.models import FailoverCollection, FailoverGlobalOrigin

    db = make_session()
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    collection = FailoverCollection(name="出海业务")
    db.add(collection)
    db.flush()
    resource = AzPanelResource(
        name="aws-tokyo", provider="aws", resource_id="i-1", ip_version="ipv4", current_ip="198.51.100.7", port=22
    )
    db.add(resource)
    db.flush()
    global_origin = FailoverGlobalOrigin(
        collection_id=collection.id, target="192.0.2.10", target_type="ipv4", port=22, priority=10,
        azpanel_resource_id=resource.id,
    )
    db.add(global_origin)
    db.flush()
    mirrors = []
    for index in range(4):
        group = FailoverGroup(zone_id=zone.id, hostname=f"h{index}.example.com", collection_id=collection.id)
        db.add(group)
        db.flush()
        mirror = Origin(
            group_id=group.id, global_origin_id=global_origin.id, target="192.0.2.10",
            target_type="ipv4", port=22, priority=10, status="healthy",
        )
        db.add(mirror)
        mirrors.append(mirror)
    db.commit()

    assert sync_resource_current_ip_to_origin(db, resource) is True
    db.commit()

    # One binding covers every domain in the collection.
    db.refresh(global_origin)
    assert global_origin.target == "198.51.100.7"
    for mirror in mirrors:
        db.refresh(mirror)
        assert mirror.target == "198.51.100.7"


def test_ip_change_event_payload_names_the_resource_and_every_affected_backup():
    db = make_session()
    first, second = make_origins_in_two_groups(db)
    first.remark = "台北 tw01"
    resource = AzPanelResource(
        name="aws-tokyo", provider="aws", resource_id="i-1", ip_version="ipv4", current_ip="198.51.100.7", port=22
    )
    db.add(resource)
    db.flush()
    first.azpanel_resource_id = resource.id
    second.azpanel_resource_id = resource.id
    db.commit()

    payload = ip_change_event_payload(db, resource, old_ip="192.0.2.10", new_ip="198.51.100.7", trigger_type="auto_blocked")

    assert payload["resource_name"] == "aws-tokyo"
    assert {target["hostname"] for target in payload["targets"]} == {"h0.example.com", "h1.example.com"}
    assert "台北 tw01" in {target["remark"] for target in payload["targets"]}

    text = render_telegram_message("azpanel.ip_changed", payload)
    assert "aws-tokyo" in text
    assert "h0.example.com" in text
    assert "h1.example.com" in text
    assert "台北 tw01" in text
    # The old generic renderer printed bare ids and nothing else.
    assert "origin_id" not in text


def test_resource_output_lists_all_bindings_and_delete_clears_them():
    db = make_session()
    user = make_user(db)
    direct, mirror = make_origins_in_two_groups(db)
    collection = FailoverCollection(name="出海业务")
    resource = AzPanelResource(
        name="aws-tokyo", provider="aws", resource_id="i-1", ip_version="ipv4", current_ip="198.51.100.7", port=22
    )
    db.add_all([collection, resource])
    db.flush()
    global_origin = FailoverGlobalOrigin(
        collection_id=collection.id,
        target="198.51.100.7",
        target_type="ipv4",
        port=22,
        priority=10,
        azpanel_resource_id=resource.id,
    )
    db.add(global_origin)
    db.flush()
    direct.azpanel_resource_id = resource.id
    mirror.global_origin_id = global_origin.id
    mirror.azpanel_resource_id = resource.id
    resource.origin_id = direct.id
    db.commit()

    output = list_azpanel_resources(user, db)[0]
    assert set(output.bound_origin_ids) == {direct.id, mirror.id}
    assert output.bound_global_origin_ids == [global_origin.id]

    delete_azpanel_resource(resource.id, user, db)

    db.refresh(direct)
    db.refresh(mirror)
    db.refresh(global_origin)
    assert db.get(AzPanelResource, resource.id) is None
    assert direct.azpanel_resource_id is None
    assert mirror.azpanel_resource_id is None
    assert global_origin.azpanel_resource_id is None
