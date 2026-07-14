from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.integrations import (
    azpanel_settings,
    call_synexvm_change_ip,
    change_resource_ip,
    list_azpanel_remote_resources,
    sync_resource_current_ip_to_origin,
    sync_synexvm_resource_status,
    synexvm_settings,
    trigger_ip_change_for_origin,
    update_azpanel_settings,
    update_synexvm_settings,
)
from app.models import AzPanelRemoteResource, AzPanelResource, CloudflareCredential, FailoverGroup, Origin, ProbeState, User, XboardNodeBinding, Zone
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
    db.add(resource)
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


def test_synexvm_settings_do_not_expose_token():
    db = make_session()

    settings = update_synexvm_settings(
        db,
        {
            "enabled": True,
            "api_url": "https://panel.example.com/modules/servers/pvewhmcs/api.php",
            "api_token": "secret-token",
            "timeout_seconds": 20,
            "wait_seconds": 60,
            "default_cooldown_seconds": 900,
        },
    )

    assert settings["enabled"] is True
    assert settings["api_url"] == "https://panel.example.com/modules/servers/pvewhmcs/api.php"
    assert settings["api_token_configured"] is True
    assert "api_token" not in settings
    assert synexvm_settings(db)["wait_seconds"] == 60


def test_synexvm_settings_fall_back_to_default_api_url():
    db = make_session()

    assert synexvm_settings(db)["api_url"] == "https://www.synexvm.com/modules/servers/pvewhmcs/api.php"

    # 清空表示回退到内置默认地址，而不是留下无法请求的空串
    update_synexvm_settings(db, {"api_url": ""})
    assert synexvm_settings(db)["api_url"] == "https://www.synexvm.com/modules/servers/pvewhmcs/api.php"


def test_call_synexvm_change_ip_never_trusts_immediate_ip(monkeypatch):
    """换 IP 刚下发时 status 可能返回过渡 IP，一律不采纳，统一 pending 由调度器双读确认。"""
    db = make_session()
    update_synexvm_settings(db, {"enabled": True, "api_token": "tok", "wait_seconds": 60})
    resource = AzPanelResource(
        name="syn-861", provider="synexvm", resource_id="861", ip_version="ipv4", current_ip="42.200.231.85", port=22
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)

    class Response:
        is_success = True

        def __init__(self, payload):
            self._payload = payload

        def json(self):
            return self._payload

    calls = []

    def fake_get(url, params=None, timeout=None, follow_redirects=None):
        assert url == "https://www.synexvm.com/modules/servers/pvewhmcs/api.php"
        assert params["service_id"] == "861"
        assert params["token"] == "tok"
        calls.append(params["action"])
        if params["action"] == "change_ip":
            return Response({"success": True, "message": "IP change scheduled"})
        # 下发后 status 立刻给出一个"看似新"的过渡 IP —— 不能信
        return Response({"success": True, "vm": {"ipv4": "42.200.240.9", "status": "running"}})

    monkeypatch.setattr("app.integrations.httpx.get", fake_get)
    monkeypatch.setattr("app.integrations.time.sleep", lambda *_: None)

    result = call_synexvm_change_ip(db, resource)

    assert result.get("pending") is True
    assert "new_ip" not in result
    assert calls == ["status", "change_ip"]


def test_call_synexvm_change_ip_prefers_resource_override(monkeypatch):
    db = make_session()
    update_synexvm_settings(db, {"enabled": True, "api_token": "global-tok"})
    resource = AzPanelResource(
        name="syn-999",
        provider="synexvm",
        resource_id="999",
        ip_version="ipv4",
        current_ip="203.0.113.5",
        port=22,
        api_url="https://other-panel.example.com/api.php",
        api_token=encrypt_secret("per-service-tok"),
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)

    class Response:
        is_success = True

        def __init__(self, payload):
            self._payload = payload

        def json(self):
            return self._payload

    seen = []

    def fake_get(url, params=None, timeout=None, follow_redirects=None):
        seen.append((url, params["token"], params["action"]))
        if params["action"] == "change_ip":
            return Response({"success": True, "new_ip": "203.0.113.99"})
        return Response({"success": True, "vm": {"ipv4": "203.0.113.5"}})

    monkeypatch.setattr("app.integrations.httpx.get", fake_get)
    monkeypatch.setattr("app.integrations.time.sleep", lambda *_: None)

    result = call_synexvm_change_ip(db, resource)

    # change_ip 响应里的 IP 只留作提示，实际以 status 双读确认为准（pending）
    assert result.get("pending") is True
    assert result.get("reported_new_ip") == "203.0.113.99"
    assert all(url == "https://other-panel.example.com/api.php" for url, _, _ in seen)
    assert all(token == "per-service-tok" for _, token, _ in seen)


def test_call_synexvm_change_ip_keeps_reported_ip_as_hint_only(monkeypatch):
    db = make_session()
    update_synexvm_settings(db, {"enabled": True, "api_token": "tok", "wait_seconds": 15})
    resource = AzPanelResource(
        name="syn-861",
        provider="synexvm",
        resource_id="861",
        ip_version="ipv4",
        current_ip="209.9.202.194",
        port=22,
    )
    db.add(resource)
    db.commit()

    calls = []

    def fake_get(url, params=None, timeout=None, follow_redirects=None):
        calls.append(params["action"])
        if params["action"] == "change_ip":
            return _synex_resp({"success": True, "new_ip": "42.200.177.53"})
        return _synex_resp({"success": True, "vm": {"ipv4": "209.9.202.194"}})

    monkeypatch.setattr("app.integrations.httpx.get", fake_get)
    monkeypatch.setattr("app.integrations.time.sleep", lambda *_: None)

    result = call_synexvm_change_ip(db, resource)

    # change_ip 报的 IP 可能不是最终地址：只保留提示，不当 new_ip，等 status 双读确认
    assert result["reported_new_ip"] == "42.200.177.53"
    assert "new_ip" not in result
    assert result.get("pending") is True
    assert calls == ["status", "change_ip"]


def test_change_resource_ip_dispatches_synexvm_and_updates_origin(monkeypatch):
    db = make_session()
    origin = make_origin(db)
    update_synexvm_settings(db, {"enabled": True, "api_token": "tok"})
    resource = AzPanelResource(
        name="syn-861",
        provider="synexvm",
        resource_id="861",
        ip_version="ipv4",
        origin_id=origin.id,
        current_ip="192.0.2.10",
        port=22,
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)

    monkeypatch.setattr(
        "app.integrations.call_synexvm_change_ip", lambda db_, res, reason=None: {"new_ip": "198.51.100.7"}
    )

    job = change_resource_ip(db, resource, trigger_type="manual", reason="test")
    db.commit()

    assert job.status == "success"
    assert job.provider == "synexvm"
    assert job.new_ip == "198.51.100.7"
    assert resource.current_ip == "198.51.100.7"
    db.refresh(origin)
    assert origin.target == "198.51.100.7"


def test_trigger_ip_change_uses_synexvm_resource_when_azpanel_disabled(monkeypatch):
    db = make_session()
    origin = make_origin(db)
    update_synexvm_settings(db, {"enabled": True, "api_token": "tok"})
    resource = AzPanelResource(
        name="syn-861",
        provider="synexvm",
        resource_id="861",
        ip_version="ipv4",
        origin_id=origin.id,
        current_ip="192.0.2.10",
        port=22,
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)

    called = {}

    def fake_change(db_, res, reason=None):
        called["id"] = res.id
        return {"new_ip": "198.51.100.8"}

    monkeypatch.setattr("app.integrations.call_synexvm_change_ip", fake_change)

    job = trigger_ip_change_for_origin(db, origin, "origin blocked")
    db.commit()

    assert job is not None
    assert job.status == "success"
    assert called["id"] == resource.id


def test_trigger_ip_change_skips_synexvm_resource_when_disabled(monkeypatch):
    db = make_session()
    origin = make_origin(db)
    # synexvm 未启用：绑定的 synexvm 资源不应触发换 IP
    resource = AzPanelResource(
        name="syn-861",
        provider="synexvm",
        resource_id="861",
        ip_version="ipv4",
        origin_id=origin.id,
        current_ip="192.0.2.10",
        port=22,
    )
    db.add(resource)
    db.commit()

    def fail_if_called(*args, **kwargs):
        raise AssertionError("synexvm change ip should not be called when integration is disabled")

    monkeypatch.setattr("app.integrations.call_synexvm_change_ip", fail_if_called)

    assert trigger_ip_change_for_origin(db, origin, "origin blocked") is None


def test_trigger_ip_change_matches_resource_by_ip_when_port_differs(monkeypatch):
    db = make_session()
    origin = make_origin(db)  # target 192.0.2.10:22
    origin.port = 443  # 外部 IP 的入口端口，和云资源的检查端口不同
    update_synexvm_settings(db, {"enabled": True, "api_token": "tok"})
    resource = AzPanelResource(
        name="syn-861",
        provider="synexvm",
        resource_id="861",
        ip_version="ipv4",
        current_ip="192.0.2.10",
        port=22,
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)

    called = {}

    def fake_change(db_, res, reason=None):
        called["id"] = res.id
        return {"new_ip": "198.51.100.9"}

    monkeypatch.setattr("app.integrations.call_synexvm_change_ip", fake_change)

    job = trigger_ip_change_for_origin(db, origin, "origin blocked")
    db.commit()

    assert job is not None
    assert job.status == "success"
    assert called["id"] == resource.id
    # 资源没绑定源站：源站目标不直接改，等外部来源同步新 IP 后按绑定跟随
    assert origin.target == "192.0.2.10"


def test_successful_ip_change_marks_external_sources_due(monkeypatch):
    from datetime import datetime as dt

    from app.models import ExternalIpSource

    db = make_session()
    update_synexvm_settings(db, {"enabled": True, "api_token": "tok"})
    source = ExternalIpSource(
        name="nyanpass",
        base_url="https://ny.example.com",
        token_encrypted=encrypt_secret("token"),
        last_synced_at=dt.utcnow(),
    )
    resource = AzPanelResource(
        name="syn-861", provider="synexvm", resource_id="861", ip_version="ipv4", current_ip="192.0.2.10", port=22
    )
    db.add_all([source, resource])
    db.commit()
    db.refresh(resource)

    monkeypatch.setattr(
        "app.integrations.call_synexvm_change_ip", lambda db_, res, reason=None: {"new_ip": "198.51.100.10"}
    )

    job = change_resource_ip(db, resource, trigger_type="manual", reason="test")
    db.commit()

    assert job.status == "success"
    # 换 IP 成功后外部来源被标记为到期，下个调度周期立即重新同步
    assert source.last_synced_at is None


def _synex_resp(payload):
    class Response:
        is_success = True

        def json(self):
            return payload

    return Response()


def test_synexvm_change_ip_returns_pending_when_status_lags(monkeypatch):
    db = make_session()
    update_synexvm_settings(db, {"enabled": True, "api_token": "tok", "wait_seconds": 10})
    resource = AzPanelResource(
        name="syn-861", provider="synexvm", resource_id="861", ip_version="ipv4", current_ip="42.200.231.85", port=22
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)

    # status 一直返回旧 IP（换 IP 生效慢），change_ip 不带新 IP
    def fake_get(url, params=None, timeout=None, follow_redirects=None):
        if params["action"] == "change_ip":
            return _synex_resp({"success": True, "message": "scheduled"})
        return _synex_resp({"success": True, "vm": {"ipv4": "42.200.231.85"}})

    monkeypatch.setattr("app.integrations.httpx.get", fake_get)
    monkeypatch.setattr("app.integrations.time.sleep", lambda *_: None)

    result = call_synexvm_change_ip(db, resource)

    assert result.get("pending") is True
    assert "new_ip" not in result


def test_change_resource_ip_pending_marks_resource_and_external_due(monkeypatch):
    from app.models import ExternalIpSource
    from datetime import datetime as dt

    db = make_session()
    origin = make_origin(db)
    update_synexvm_settings(db, {"enabled": True, "api_token": "tok"})
    source = ExternalIpSource(name="ny", base_url="https://ny.example.com", token_encrypted=encrypt_secret("t"), last_synced_at=dt.utcnow())
    resource = AzPanelResource(
        name="syn-861", provider="synexvm", resource_id="861", ip_version="ipv4", origin_id=origin.id, current_ip="192.0.2.10", port=22
    )
    db.add_all([source, resource])
    db.commit()
    db.refresh(resource)

    monkeypatch.setattr("app.integrations.call_synexvm_change_ip", lambda db_, res, reason=None: {"pending": True, "old_ip": "192.0.2.10"})

    job = change_resource_ip(db, resource, trigger_type="auto_blocked", reason="blocked")
    db.commit()

    assert job.status == "pending"
    assert job.new_ip is None
    assert resource.pending_change_at is not None
    # 源站不立即改（等新 IP），但外部来源被催重新同步
    db.refresh(origin)
    assert origin.target == "192.0.2.10"
    assert source.last_synced_at is None


def test_synexvm_status_refresh_finishes_pending_job_with_actual_ip(monkeypatch):
    from app.models import IpChangeJob
    from datetime import datetime as dt

    db = make_session()
    origin = make_origin(db)
    update_synexvm_settings(db, {"enabled": True, "api_token": "tok"})
    resource = AzPanelResource(
        name="syn-861",
        provider="synexvm",
        resource_id="861",
        ip_version="ipv4",
        origin_id=origin.id,
        current_ip="209.9.202.194",
        port=22,
        pending_change_at=dt.utcnow(),
        auto_update_origin=True,
    )
    db.add(resource)
    db.flush()
    job = IpChangeJob(
        trigger_type="manual",
        status="pending",
        provider="synexvm",
        azpanel_resource_id=resource.id,
        origin_id=origin.id,
        old_ip="209.9.202.194",
        started_at=dt.utcnow(),
    )
    db.add(job)
    db.commit()
    monkeypatch.setattr(
        "app.integrations.httpx.get",
        lambda *args, **kwargs: _synex_resp({"success": True, "vm": {"ipv4": "42.200.177.61"}}),
    )
    monkeypatch.setattr("app.integrations.time.sleep", lambda *_: None)

    sync_synexvm_resource_status(db, resource)
    db.commit()

    assert resource.current_ip == "42.200.177.61"
    assert resource.pending_change_at is None
    assert resource.last_change_at is not None
    assert job.status == "success"
    assert job.new_ip == "42.200.177.61"
    assert origin.target == "42.200.177.61"


def test_reconcile_applies_new_ip_and_finishes_job(monkeypatch):
    from app.integrations import reconcile_pending_synexvm_changes
    from app.models import IpChangeJob
    from datetime import datetime as dt

    db = make_session()
    origin = make_origin(db)
    update_synexvm_settings(db, {"enabled": True, "api_token": "tok"})
    resource = AzPanelResource(
        name="syn-861", provider="synexvm", resource_id="861", ip_version="ipv4", origin_id=origin.id,
        current_ip="192.0.2.10", port=22, pending_change_at=dt.utcnow(), auto_update_origin=True,
    )
    db.add(resource)
    db.flush()
    pending_job = IpChangeJob(
        trigger_type="auto_blocked", status="pending", provider="synexvm",
        azpanel_resource_id=resource.id, origin_id=origin.id, old_ip="192.0.2.10", started_at=dt.utcnow(),
    )
    db.add(pending_job)
    db.commit()

    # status 现在返回新 IP
    monkeypatch.setattr("app.integrations.httpx.get", lambda *a, **k: _synex_resp({"success": True, "vm": {"ipv4": "198.51.100.7"}}))

    # 第一个周期：只见过一次的新 IP 先记为候选，不落地（防过渡 IP）
    assert reconcile_pending_synexvm_changes(db) == 0
    db.commit()
    db.refresh(resource)
    assert resource.current_ip == "192.0.2.10"
    assert resource.pending_candidate_ip == "198.51.100.7"

    # 第二个周期：同一个新 IP 再次出现，确认稳定，落地
    resolved = reconcile_pending_synexvm_changes(db)
    db.commit()

    assert resolved == 1
    db.refresh(resource)
    db.refresh(pending_job)
    assert resource.current_ip == "198.51.100.7"
    assert resource.pending_change_at is None
    assert resource.pending_candidate_ip is None
    assert pending_job.status == "success"
    assert pending_job.new_ip == "198.51.100.7"
    db.refresh(origin)
    assert origin.target == "198.51.100.7"


def test_reconcile_gives_up_after_budget(monkeypatch):
    from app.integrations import reconcile_pending_synexvm_changes
    from datetime import datetime as dt, timedelta

    db = make_session()
    update_synexvm_settings(db, {"enabled": True, "api_token": "tok", "wait_seconds": 60})
    resource = AzPanelResource(
        name="syn-861", provider="synexvm", resource_id="861", ip_version="ipv4",
        current_ip="192.0.2.10", port=22, pending_change_at=dt.utcnow() - timedelta(seconds=200),
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)

    # status 一直是旧 IP，超过预算应放弃
    monkeypatch.setattr("app.integrations.httpx.get", lambda *a, **k: _synex_resp({"success": True, "vm": {"ipv4": "192.0.2.10"}}))

    reconcile_pending_synexvm_changes(db)
    db.commit()
    db.refresh(resource)

    assert resource.pending_change_at is None
    assert "未返回新 IP" in (resource.last_error or "")


def test_reconcile_discards_transient_ip_and_applies_stable_one(monkeypatch):
    """换 IP 过程中 status 短暂返回过渡 IP：不能落地，最终以连续两次一致的地址为准。"""
    from app.integrations import reconcile_pending_synexvm_changes
    from datetime import datetime as dt

    db = make_session()
    origin = make_origin(db)
    update_synexvm_settings(db, {"enabled": True, "api_token": "tok"})
    resource = AzPanelResource(
        name="syn-861", provider="synexvm", resource_id="861", ip_version="ipv4", origin_id=origin.id,
        current_ip="192.0.2.10", port=22, pending_change_at=dt.utcnow(), auto_update_origin=True,
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)

    reported = {"ip": "203.0.113.250"}  # 过渡 IP

    monkeypatch.setattr(
        "app.integrations.httpx.get",
        lambda *a, **k: _synex_resp({"success": True, "vm": {"ipv4": reported["ip"]}}),
    )

    # 周期 1：过渡 IP 只记候选
    assert reconcile_pending_synexvm_changes(db) == 0
    assert resource.pending_candidate_ip == "203.0.113.250"
    assert resource.current_ip == "192.0.2.10"

    # 周期 2：面板换成了真正的新 IP，候选被替换，仍不落地
    reported["ip"] = "198.51.100.7"
    assert reconcile_pending_synexvm_changes(db) == 0
    assert resource.pending_candidate_ip == "198.51.100.7"
    assert resource.current_ip == "192.0.2.10"

    # 周期 3：真新 IP 连续第二次出现，落地；过渡 IP 从未被采纳
    assert reconcile_pending_synexvm_changes(db) == 1
    db.commit()
    db.refresh(resource)
    assert resource.current_ip == "198.51.100.7"
    db.refresh(origin)
    assert origin.target == "198.51.100.7"


def test_manual_status_refresh_rejects_unstable_ip(monkeypatch):
    import pytest

    db = make_session()
    update_synexvm_settings(db, {"enabled": True, "api_token": "tok"})
    resource = AzPanelResource(
        name="syn-861", provider="synexvm", resource_id="861", ip_version="ipv4", current_ip="192.0.2.10", port=22
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)

    ips = iter(["203.0.113.250", "198.51.100.7"])  # 两次读取不一致 → 尚未稳定

    monkeypatch.setattr(
        "app.integrations.httpx.get",
        lambda *a, **k: _synex_resp({"success": True, "vm": {"ipv4": next(ips)}}),
    )
    monkeypatch.setattr("app.integrations.time.sleep", lambda *_: None)

    with pytest.raises(RuntimeError, match="尚未稳定"):
        sync_synexvm_resource_status(db, resource)
    assert resource.current_ip == "192.0.2.10"


def test_auto_sync_synexvm_statuses_applies_ip_after_two_reads(monkeypatch):
    from app.integrations import auto_sync_synexvm_statuses
    from datetime import datetime as dt, timedelta

    db = make_session()
    origin = make_origin(db)
    update_synexvm_settings(db, {"enabled": True, "api_token": "tok"})
    resource = AzPanelResource(
        name="syn-861", provider="synexvm", resource_id="861", ip_version="ipv4", origin_id=origin.id,
        current_ip="192.0.2.10", port=22, status_sync_interval_seconds=30, auto_update_origin=True,
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)

    monkeypatch.setattr(
        "app.integrations.httpx.get",
        lambda *a, **k: _synex_resp({"success": True, "vm": {"ipv4": "198.51.100.7"}}),
    )

    # 第一次到期查询：新 IP 记候选
    assert auto_sync_synexvm_statuses(db) == 0
    assert resource.pending_candidate_ip == "198.51.100.7"
    assert resource.last_status_sync_at is not None

    # 间隔未到：不重复查询
    assert auto_sync_synexvm_statuses(db) == 0
    assert resource.pending_candidate_ip == "198.51.100.7"

    # 间隔已到：同一 IP 第二次出现，落地并同步源站
    resource.last_status_sync_at = dt.utcnow() - timedelta(seconds=60)
    db.flush()
    assert auto_sync_synexvm_statuses(db) == 1
    db.commit()
    db.refresh(resource)
    assert resource.current_ip == "198.51.100.7"
    assert resource.pending_candidate_ip is None
    db.refresh(origin)
    assert origin.target == "198.51.100.7"


def test_auto_sync_skips_disabled_zero_interval_and_pending(monkeypatch):
    from app.integrations import auto_sync_synexvm_statuses
    from datetime import datetime as dt

    db = make_session()
    update_synexvm_settings(db, {"enabled": True, "api_token": "tok"})
    db.add_all([
        AzPanelResource(name="off", provider="synexvm", resource_id="1", ip_version="ipv4", current_ip="192.0.2.1", port=22, status_sync_interval_seconds=0),
        AzPanelResource(name="disabled", provider="synexvm", resource_id="2", ip_version="ipv4", current_ip="192.0.2.2", port=22, status_sync_interval_seconds=30, enabled=False),
        AzPanelResource(name="pending", provider="synexvm", resource_id="3", ip_version="ipv4", current_ip="192.0.2.3", port=22, status_sync_interval_seconds=30, pending_change_at=dt.utcnow()),
    ])
    db.commit()

    def fail_get(*a, **k):
        raise AssertionError("should not query status for skipped resources")

    monkeypatch.setattr("app.integrations.httpx.get", fail_get)

    assert auto_sync_synexvm_statuses(db) == 0
