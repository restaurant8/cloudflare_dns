import base64
import hashlib
import hmac
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from urllib.parse import quote

import pytest
import app.routes.alibaba_httpdns as alibaba_httpdns_routes
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.alibaba_httpdns import (
    AlibabaEffectiveScopeVerificationError,
    _desired_origin,
    call_azpanel_httpdns,
    create_credential_zone,
    delete_credential_record,
    evaluate_alibaba_httpdns_groups,
    list_credential_zones,
    sync_group_alibaba_outputs,
    update_credential_zone_effective_scope,
)
from app.database import Base
from app.dns_utils import TcpCheckResult
from app.failover import evaluate_failover_groups
from app.integrations import update_azpanel_settings
from app.models import (
    AlibabaHttpDnsAccountState,
    AlibabaHttpDnsCredential,
    AlibabaHttpDnsGroup,
    AlibabaHttpDnsOrigin,
    AwsRoute53Credential,
    AwsRoute53Output,
    CloudflareCredential,
    DohEndpoint,
    Event,
    FailoverGroup,
    Origin,
    User,
    Zone,
)
from app.routes.alibaba_httpdns import (
    adopt_zone,
    create_credential,
    create_group,
    create_managed_group,
    create_zone,
    credential_records,
    delete_credential_record_action,
    delete_zone,
    delete_origin_action,
    release_zone_action,
    router,
    update_group as update_alibaba_group,
    update_origin,
    update_zone_effective_scope,
)
from app.routes.groups import create_origin as create_failover_origin, update_origin as update_failover_origin
from app.schemas import (
    AlibabaHttpDnsCredentialCreate,
    AlibabaHttpDnsEffectiveScopeUpdate,
    AlibabaHttpDnsGroupCreate,
    AlibabaHttpDnsGroupUpdate,
    AlibabaHttpDnsOriginUpdate,
    AlibabaHttpDnsRecordDelete,
    AlibabaHttpDnsStandaloneGroupCreate,
    AlibabaHttpDnsZoneAdopt,
    AlibabaHttpDnsZoneCreate,
    AlibabaHttpDnsZoneDelete,
    AlibabaHttpDnsZoneRelease,
    OriginCreate,
    OriginUpdate,
)
from app.security import encrypt_secret


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def add_direct_credential(db, *, name="direct-record-delete"):
    credential = AlibabaHttpDnsCredential(
        name=name,
        access_key_id_encrypted=encrypt_secret("ak"),
        access_key_secret_encrypted=encrypt_secret("secret"),
        endpoint="alidns.aliyuncs.com",
        enabled=True,
    )
    db.add(credential)
    db.commit()
    return credential


def remote_alibaba_record(record_id="record-1", record_type="TXT"):
    return {
        "RecordId": record_id,
        "Rr": "www",
        "Type": record_type,
        "Value": "record-value",
        "Ttl": 60,
        "RequestSource": "default",
        "Weight": 1,
        "Priority": 1,
        "Remark": "",
        "EnableStatus": "enable",
    }


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


def test_direct_credential_calls_alibaba_rpc_without_azpanel(monkeypatch):
    credential = AlibabaHttpDnsCredential(
        name="direct",
        access_key_id_encrypted=encrypt_secret("test-ak"),
        access_key_secret_encrypted=encrypt_secret("  test-secret\r\n"),
        endpoint="alidns.aliyuncs.com",
        enabled=True,
    )
    captured = {}

    class Response:
        is_error = False
        status_code = 200
        text = ""

        def json(self):
            return {
                "TotalPages": 1,
                "RecursionZones": {"RecursionZone": [{"ZoneId": "z-1", "ZoneName": "example.com"}]},
            }

    def post(url, *, params, timeout):
        captured.update({"url": url, "params": params, "timeout": timeout})
        return Response()

    monkeypatch.setattr("app.alibaba_httpdns.httpx.post", post)

    assert list_credential_zones(credential)[0]["ZoneId"] == "z-1"
    assert captured["url"] == "https://alidns.aliyuncs.com"
    assert captured["params"]["Action"] == "ListRecursionZones"
    assert captured["params"]["AccessKeyId"] == "test-ak"
    assert captured["params"]["Version"] == "2015-01-09"
    assert isinstance(captured["params"]["Signature"], str) and captured["params"]["Signature"]
    unsigned = {key: value for key, value in captured["params"].items() if key != "Signature"}
    encode = lambda value: quote(str(value), safe="~-._")
    canonical = "&".join(f"{encode(key)}={encode(unsigned[key])}" for key in sorted(unsigned))
    string_to_sign = f"POST&%2F&{encode(canonical)}"
    expected = base64.b64encode(
        hmac.new(b"test-secret&", string_to_sign.encode("utf-8"), hashlib.sha1).digest()
    ).decode("ascii")
    assert captured["params"]["Signature"] == expected


def test_zone_creation_uses_fresh_token_and_effective_scope_is_verified(monkeypatch):
    credential = AlibabaHttpDnsCredential(id=9, name="direct", enabled=True)
    calls = []
    current_scopes = []

    def call(_credential, action, **parameters):
        calls.append((action, parameters))
        if action == "AddRecursionZone":
            return {"ZoneId": "zone-new"}
        if action == "UpdateRecursionZoneEffectiveScope":
            current_scopes[:] = [
                value
                for key, value in parameters.items()
                if key.startswith("EffectiveScopes.1.Scope.")
            ]
            return {}
        if action == "ListRecursionZones":
            return {
                "TotalPages": 1,
                "Zones": {
                    "Zone": [
                        {
                            "ZoneId": "zone-new",
                            "ZoneName": "private.example.com",
                            "EffectiveScopes": {
                                "EffectiveScope": [
                                    {
                                        "EffectiveType": "account",
                                        "Scopes": {"Scope": list(reversed(current_scopes))},
                                    }
                                ]
                            },
                        }
                    ]
                },
            }
        return {}

    monkeypatch.setattr("app.alibaba_httpdns.call_alibaba_api", call)

    first = create_credential_zone(credential, zone_name="private.example.com", proxy_pattern="zone")
    second = create_credential_zone(credential, zone_name="private.example.com", proxy_pattern="zone")
    verified = update_credential_zone_effective_scope(
        credential,
        "zone-new",
        ["20004", "20003", "20003"],
    )

    assert first["ZoneId"] == second["ZoneId"] == "zone-new"
    assert calls[0][1]["ClientToken"] != calls[1][1]["ClientToken"]
    scope_params = calls[2][1]
    assert scope_params["EffectiveScopes.1.EffectiveType"] == "account"
    assert scope_params["EffectiveScopes.1.Scope.1"] == "20003"
    assert scope_params["EffectiveScopes.1.Scope.2"] == "20004"
    assert calls[3][0] == "ListRecursionZones"
    assert verified == ["20003", "20004"]


def test_list_zones_normalizes_alibaba_effective_scope_shape(monkeypatch):
    credential = AlibabaHttpDnsCredential(id=9, name="direct", enabled=True)
    monkeypatch.setattr(
        "app.alibaba_httpdns.call_alibaba_api",
        lambda *_args, **_kwargs: {
            "TotalPages": 1,
            "RecursionZones": {
                "RecursionZone": [
                    {
                        "ZoneId": "zone-1",
                        "ZoneName": "private.example.com",
                        "EffectiveScopes": {
                            "EffectiveScope": [
                                {
                                    "EffectiveType": "account",
                                    "Scopes": {"Scope": [20004, "20003", "20003"]},
                                },
                                {
                                    "EffectiveType": "unsupported",
                                    "Scopes": {"Scope": ["ignored"]},
                                },
                            ]
                        },
                    }
                ]
            },
        },
    )

    zone = list_credential_zones(credential)[0]

    assert zone["EffectiveScopeIds"] == ["20003", "20004"]
    assert "EffectiveScopes" in zone


def test_effective_scope_update_fails_when_alibaba_does_not_write_requested_ids(monkeypatch):
    credential = AlibabaHttpDnsCredential(id=9, name="direct", enabled=True)
    sleeps = []

    def call(_credential, action, **_parameters):
        if action == "ListRecursionZones":
            return {
                "TotalPages": 1,
                "Zones": {
                    "Zone": [
                        {
                            "ZoneId": "zone-1",
                            "ZoneName": "private.example.com",
                            "EffectiveScopes": {"EffectiveScope": []},
                        }
                    ]
                },
            }
        return {}

    monkeypatch.setattr("app.alibaba_httpdns.call_alibaba_api", call)
    monkeypatch.setattr("app.alibaba_httpdns.time.sleep", lambda seconds: sleeps.append(seconds))

    with pytest.raises(AlibabaEffectiveScopeVerificationError) as exc_info:
        update_credential_zone_effective_scope(credential, "zone-1", ["20003"])

    assert "20003" in str(exc_info.value)
    assert "实际: 空" in str(exc_info.value)
    assert sleeps == [0.2, 0.4]


def test_effective_scope_readback_retries_missing_zone_then_old_scope(monkeypatch):
    credential = AlibabaHttpDnsCredential(id=9, name="direct", enabled=True)
    reads = []
    sleeps = []

    def call(_credential, action, **_parameters):
        if action != "ListRecursionZones":
            return {}
        reads.append(1)
        if len(reads) == 1:
            zones = []
        else:
            scopes = ["old-account"] if len(reads) == 2 else ["20003"]
            zones = [
                {
                    "ZoneId": "zone-1",
                    "ZoneName": "private.example.com",
                    "EffectiveScopes": {
                        "EffectiveScope": [
                            {
                                "EffectiveType": "account",
                                "Scopes": {"Scope": scopes},
                            }
                        ]
                    },
                }
            ]
        return {"TotalPages": 1, "Zones": {"Zone": zones}}

    monkeypatch.setattr("app.alibaba_httpdns.call_alibaba_api", call)
    monkeypatch.setattr("app.alibaba_httpdns.time.sleep", lambda seconds: sleeps.append(seconds))

    assert update_credential_zone_effective_scope(credential, "zone-1", ["20003"]) == ["20003"]
    assert len(reads) == 3
    assert sleeps == [0.2, 0.4]


def test_create_zone_sets_effective_scope_before_reporting_success(monkeypatch):
    db = make_session()
    credential = AlibabaHttpDnsCredential(
        name="direct-create",
        access_key_id_encrypted=encrypt_secret("ak"),
        access_key_secret_encrypted=encrypt_secret("secret"),
        endpoint="alidns.aliyuncs.com",
        enabled=True,
    )
    db.add(credential)
    db.commit()
    calls = []
    monkeypatch.setattr("app.routes.alibaba_httpdns.list_credential_zones", lambda *_args: [])
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.create_credential_zone",
        lambda _credential, **kwargs: {
            "ZoneId": "zone-new",
            "ZoneName": kwargs["zone_name"],
            "RecordCount": 0,
            "ProxyPattern": kwargs["proxy_pattern"],
            "Remark": "",
        },
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.update_credential_zone_effective_scope",
        lambda _credential, zone_id, scopes: calls.append((zone_id, scopes)) or ["20003"],
    )

    result = create_zone(
        credential.id,
        AlibabaHttpDnsZoneCreate(
            zone_name="Private.Example.com.",
            proxy_pattern="zone",
            effective_scope_ids=["20003"],
        ),
        None,
        db,
    )

    assert calls == [("zone-new", ["20003"])]
    assert result["ZoneName"] == "private.example.com"
    assert result["EffectiveScopeIds"] == ["20003"]


def test_create_zone_without_scope_ids_loads_pdns_id_before_add(monkeypatch):
    db = make_session()
    credential = AlibabaHttpDnsCredential(
        name="legacy-client",
        access_key_id_encrypted=encrypt_secret("ak"),
        access_key_secret_encrypted=encrypt_secret("secret"),
        endpoint="alidns.aliyuncs.com",
        enabled=True,
    )
    db.add(credential)
    db.commit()
    calls = []
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.list_credential_effective_scopes",
        lambda *_args: calls.append("describe") or [{"id": "20003"}],
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.list_credential_zones",
        lambda *_args: calls.append("list-zones") or [],
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.create_credential_zone",
        lambda *_args, **_kwargs: calls.append("add-zone")
        or {"ZoneId": "zone-new", "ZoneName": "private.example.com"},
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.update_credential_zone_effective_scope",
        lambda _credential, _zone_id, scopes: calls.append(("scope", scopes)) or scopes,
    )

    result = create_zone(
        credential.id,
        AlibabaHttpDnsZoneCreate(zone_name="private.example.com"),
        None,
        db,
    )

    assert calls == ["describe", "list-zones", "add-zone", ("scope", ["20003"])]
    assert result["EffectiveScopeIds"] == ["20003"]


def test_create_zone_without_scope_ids_fails_before_add_when_pdns_id_is_unavailable(monkeypatch):
    db = make_session()
    credential = AlibabaHttpDnsCredential(
        name="legacy-client",
        access_key_id_encrypted=encrypt_secret("ak"),
        access_key_secret_encrypted=encrypt_secret("secret"),
        endpoint="alidns.aliyuncs.com",
        enabled=True,
    )
    db.add(credential)
    db.commit()
    monkeypatch.setattr("app.routes.alibaba_httpdns.list_credential_effective_scopes", lambda *_args: [])
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.create_credential_zone",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("PdnsId 缺失时不应创建 Zone")),
    )

    with pytest.raises(HTTPException) as exc_info:
        create_zone(
            credential.id,
            AlibabaHttpDnsZoneCreate(zone_name="private.example.com"),
            None,
            db,
        )

    assert exc_info.value.status_code == 400
    assert "PdnsId" in str(exc_info.value.detail)


def test_create_zone_keeps_zone_when_scope_update_is_denied(monkeypatch):
    db = make_session()
    credential = AlibabaHttpDnsCredential(
        name="direct-create",
        access_key_id_encrypted=encrypt_secret("ak"),
        access_key_secret_encrypted=encrypt_secret("secret"),
        endpoint="alidns.aliyuncs.com",
        enabled=True,
    )
    db.add(credential)
    db.commit()
    monkeypatch.setattr("app.routes.alibaba_httpdns.list_credential_zones", lambda *_args: [])
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.create_credential_zone",
        lambda *_args, **_kwargs: {"ZoneId": "zone-new", "ZoneName": "private.example.com"},
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.update_credential_zone_effective_scope",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("Forbidden.RAM AccessDenied")),
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.delete_empty_credential_zone",
        lambda *_args: (_ for _ in ()).throw(AssertionError("生效范围失败时不应自动删除 Zone")),
    )

    with pytest.raises(HTTPException) as exc_info:
        create_zone(
            credential.id,
            AlibabaHttpDnsZoneCreate(
                zone_name="private.example.com",
                effective_scope_ids=["20003"],
            ),
            None,
            db,
        )

    assert exc_info.value.status_code == 502
    assert "Forbidden.RAM AccessDenied" in str(exc_info.value.detail)
    assert "已保留" in str(exc_info.value.detail)
    assert "刷新后修复" in str(exc_info.value.detail)


def test_create_zone_keeps_zone_when_scope_update_readback_is_inconsistent(monkeypatch):
    db = make_session()
    credential = AlibabaHttpDnsCredential(
        name="direct-create",
        access_key_id_encrypted=encrypt_secret("ak"),
        access_key_secret_encrypted=encrypt_secret("secret"),
        endpoint="alidns.aliyuncs.com",
        enabled=True,
    )
    db.add(credential)
    db.commit()
    monkeypatch.setattr("app.routes.alibaba_httpdns.list_credential_zones", lambda *_args: [])
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.create_credential_zone",
        lambda *_args, **_kwargs: {"ZoneId": "zone-new", "ZoneName": "private.example.com"},
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.update_credential_zone_effective_scope",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AlibabaEffectiveScopeVerificationError("期望 20003，实际为空")
        ),
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.delete_empty_credential_zone",
        lambda *_args: (_ for _ in ()).throw(AssertionError("读回延迟时不应删除 Zone")),
    )

    with pytest.raises(HTTPException) as exc_info:
        create_zone(
            credential.id,
            AlibabaHttpDnsZoneCreate(
                zone_name="private.example.com",
                effective_scope_ids=["20003"],
            ),
            None,
            db,
        )

    assert exc_info.value.status_code == 502
    assert "未自动删除" in str(exc_info.value.detail)
    assert "生效范围修复" in str(exc_info.value.detail)


def test_credential_validation_requires_pdns_user_info(monkeypatch):
    db = make_session()
    monkeypatch.setattr("app.routes.alibaba_httpdns.list_credential_zones", lambda *_args: [])
    monkeypatch.setattr("app.routes.alibaba_httpdns.list_credential_effective_scopes", lambda *_args: [])

    with pytest.raises(HTTPException) as exc_info:
        create_credential(
            AlibabaHttpDnsCredentialCreate(
                name="missing-pdns",
                access_key_id="ak",
                access_key_secret="secret",
            ),
            None,
            db,
        )

    assert exc_info.value.status_code == 400
    assert "DescribePdnsUserInfo" in str(exc_info.value.detail)
    assert "PdnsId" in str(exc_info.value.detail)
    assert db.query(AlibabaHttpDnsCredential).count() == 0


def test_patch_effective_scope_surfaces_readback_mismatch(monkeypatch):
    db = make_session()
    credential = AlibabaHttpDnsCredential(
        name="direct-patch",
        access_key_id_encrypted=encrypt_secret("ak"),
        access_key_secret_encrypted=encrypt_secret("secret"),
        endpoint="alidns.aliyuncs.com",
        enabled=True,
    )
    db.add(credential)
    db.commit()
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns._credential_zone",
        lambda *_args: {"ZoneId": "zone-1", "ZoneName": "private.example.com"},
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.update_credential_zone_effective_scope",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AlibabaEffectiveScopeVerificationError("期望 20003，实际为空")
        ),
    )

    with pytest.raises(HTTPException) as exc_info:
        update_zone_effective_scope(
            credential.id,
            "zone-1",
            AlibabaHttpDnsEffectiveScopeUpdate(scope_ids=["20003"]),
            None,
            db,
    )

    assert exc_info.value.status_code == 502
    assert "实际为空" in str(exc_info.value.detail)


def test_patch_effective_scope_preserves_existing_account_ids(monkeypatch):
    db = make_session()
    credential = AlibabaHttpDnsCredential(
        name="direct-patch",
        access_key_id_encrypted=encrypt_secret("ak"),
        access_key_secret_encrypted=encrypt_secret("secret"),
        endpoint="alidns.aliyuncs.com",
        enabled=True,
    )
    db.add(credential)
    db.commit()
    calls = []
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns._credential_zone",
        lambda *_args: {
            "ZoneId": "zone-1",
            "ZoneName": "private.example.com",
            "EffectiveScopeIds": ["20004", "20003"],
        },
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.update_credential_zone_effective_scope",
        lambda _credential, zone_id, scopes: calls.append((zone_id, scopes)) or scopes,
    )

    response = update_zone_effective_scope(
        credential.id,
        "zone-1",
        AlibabaHttpDnsEffectiveScopeUpdate(scope_ids=["20005", "20003"]),
        None,
        db,
    )

    assert response.message == "阿里云 HTTPDNS 生效范围已更新"
    assert calls == [("zone-1", ["20003", "20004", "20005"])]


def test_delete_credential_record_uses_idempotent_rpc_parameters(monkeypatch):
    credential = AlibabaHttpDnsCredential(id=9, name="direct", enabled=True)
    calls = []
    monkeypatch.setattr(
        "app.alibaba_httpdns.call_alibaba_api",
        lambda _credential, action, **parameters: calls.append((action, parameters)) or {},
    )

    delete_credential_record(credential, "record-1")
    delete_credential_record(credential, "record-1")

    assert [item[0] for item in calls] == ["DeleteRecursionRecord", "DeleteRecursionRecord"]
    assert calls[0][1]["RecordId"] == "record-1"
    assert calls[0][1]["ClientToken"] == calls[1][1]["ClientToken"]
    assert calls[0][1]["ClientToken"].startswith("cfdns-delete-record-")


def test_delete_credential_record_action_deletes_unbound_record_and_adds_event(monkeypatch):
    db = make_session()
    credential = add_direct_credential(db)
    deleted = []
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns._credential_zone",
        lambda *_args: {"ZoneId": "zone-1", "ZoneName": "example.com"},
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.list_credential_records",
        lambda *_args: [remote_alibaba_record()],
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.delete_credential_record",
        lambda _credential, record_id: deleted.append(record_id),
    )

    response = delete_credential_record_action(
        credential.id,
        "zone-1",
        "record-1",
        AlibabaHttpDnsRecordDelete(confirm_record_id="record-1"),
        None,
        db,
    )

    event = db.query(Event).filter(Event.type == "alibaba_httpdns.record_deleted").one()
    assert response.message == "阿里云 HTTPDNS 解析记录已删除"
    assert deleted == ["record-1"]
    assert "www.example.com" in event.message
    assert "TXT" in event.message
    assert "RecordId: record-1" in event.message
    assert '"record_id":"record-1"' in event.payload_json


def test_delete_credential_record_action_rejects_wrong_confirmation(monkeypatch):
    db = make_session()
    credential = add_direct_credential(db)
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns._credential_zone",
        lambda *_args: {"ZoneId": "zone-1", "ZoneName": "example.com"},
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.list_credential_records",
        lambda *_args: [remote_alibaba_record()],
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.delete_credential_record",
        lambda *_args: (_ for _ in ()).throw(AssertionError("确认值错误时不应删除")),
    )

    with pytest.raises(HTTPException) as exc_info:
        delete_credential_record_action(
            credential.id,
            "zone-1",
            "record-1",
            AlibabaHttpDnsRecordDelete(confirm_record_id="wrong-record"),
            None,
            db,
        )

    assert exc_info.value.status_code == 400
    assert "RecordId 不匹配" in str(exc_info.value.detail)


def test_delete_credential_record_action_rejects_record_from_another_zone(monkeypatch):
    db = make_session()
    credential = add_direct_credential(db)
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns._credential_zone",
        lambda *_args: {"ZoneId": "zone-1", "ZoneName": "example.com"},
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.list_credential_records",
        lambda *_args: [remote_alibaba_record(record_id="record-in-another-zone")],
    )

    with pytest.raises(HTTPException) as exc_info:
        delete_credential_record_action(
            credential.id,
            "zone-1",
            "record-1",
            AlibabaHttpDnsRecordDelete(confirm_record_id="record-1"),
            None,
            db,
        )

    assert exc_info.value.status_code == 404
    assert "不属于" in str(exc_info.value.detail)


def test_delete_credential_record_action_blocks_any_local_group_binding(monkeypatch):
    db = make_session()
    credential = add_direct_credential(db)
    legacy_binding = AlibabaHttpDnsGroup(
        remote_account_id=7,
        account_name="legacy",
        credential_id=None,
        zone_id="zone-1",
        zone_name="example.com",
        record_id="record-1",
        rr="www",
        record_type="TXT",
        enabled=True,
    )
    db.add(legacy_binding)
    db.commit()
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns._credential_zone",
        lambda *_args: {"ZoneId": "zone-1", "ZoneName": "example.com"},
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.list_credential_records",
        lambda *_args: [remote_alibaba_record()],
    )

    with pytest.raises(HTTPException) as exc_info:
        delete_credential_record_action(
            credential.id,
            "zone-1",
            "record-1",
            AlibabaHttpDnsRecordDelete(confirm_record_id="record-1"),
            None,
            db,
        )

    assert exc_info.value.status_code == 409
    assert f"组 ID: {legacy_binding.id}" in str(exc_info.value.detail)


def test_delete_credential_record_action_preserves_alibaba_api_error(monkeypatch):
    db = make_session()
    credential = add_direct_credential(db)
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns._credential_zone",
        lambda *_args: {"ZoneId": "zone-1", "ZoneName": "example.com"},
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.list_credential_records",
        lambda *_args: [remote_alibaba_record()],
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.delete_credential_record",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("Forbidden.RAM AccessDenied")),
    )

    with pytest.raises(HTTPException) as exc_info:
        delete_credential_record_action(
            credential.id,
            "zone-1",
            "record-1",
            AlibabaHttpDnsRecordDelete(confirm_record_id="record-1"),
            None,
            db,
        )

    db.refresh(credential)
    assert exc_info.value.status_code == 502
    assert "Forbidden.RAM AccessDenied" in str(exc_info.value.detail)
    assert credential.last_error == "Forbidden.RAM AccessDenied"


def test_credential_records_returns_every_alibaba_record_type(monkeypatch):
    db = make_session()
    credential = add_direct_credential(db)
    records = [
        remote_alibaba_record(record_id="a", record_type="A"),
        remote_alibaba_record(record_id="txt", record_type="TXT"),
        remote_alibaba_record(record_id="mx", record_type="MX"),
        remote_alibaba_record(record_id="srv", record_type="SRV"),
    ]
    monkeypatch.setattr("app.routes.alibaba_httpdns.list_credential_records", lambda *_args: records)

    output = credential_records(credential.id, "zone-1", None, db)

    assert [item["Type"] for item in output] == ["A", "TXT", "MX", "SRV"]


def test_all_binding_entrypoints_and_remote_deletes_use_shared_zone_lock(monkeypatch):
    locked_zone_ids = []

    class SpyLock:
        def __init__(self, zone_id):
            self.zone_id = zone_id

        def __enter__(self):
            locked_zone_ids.append(self.zone_id)

        def __exit__(self, *_args):
            return False

    credential = AlibabaHttpDnsCredential(id=1, name="direct", enabled=True)
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns._alibaba_zone_mutation_lock",
        lambda zone_id: SpyLock(zone_id),
    )
    monkeypatch.setattr("app.routes.alibaba_httpdns._refresh_zone_mutation_session", lambda *_args: None)
    monkeypatch.setattr("app.routes.alibaba_httpdns._credential", lambda *_args: credential)
    monkeypatch.setattr("app.routes.alibaba_httpdns._create_managed_group_locked", lambda *_args: "managed")
    monkeypatch.setattr("app.routes.alibaba_httpdns._adopt_zone_locked", lambda *_args: "adopt")
    monkeypatch.setattr("app.routes.alibaba_httpdns._create_group_locked", lambda *_args: "group")
    monkeypatch.setattr("app.routes.alibaba_httpdns._delete_credential_record_locked", lambda *_args: "record-delete")
    monkeypatch.setattr("app.routes.alibaba_httpdns._delete_zone_locked", lambda *_args: "zone-delete")

    create_managed_group(
        AlibabaHttpDnsStandaloneGroupCreate(
            credential_id=1,
            zone_id="zone-1",
            primary_target="192.0.2.10",
            effective_scope_ids=["20003"],
        ),
        None,
        object(),
    )
    adopt_zone(
        AlibabaHttpDnsZoneAdopt(
            credential_id=1,
            account_name="direct",
            zone_id="zone-1",
            zone_name="example.com",
        ),
        None,
        object(),
    )
    create_group(
        AlibabaHttpDnsGroupCreate(
            credential_id=1,
            account_name="direct",
            zone_id="zone-1",
            zone_name="example.com",
            record_id="record-1",
        ),
        None,
        object(),
    )
    delete_credential_record_action(
        1,
        "zone-1",
        "record-1",
        AlibabaHttpDnsRecordDelete(confirm_record_id="record-1"),
        None,
        object(),
    )
    delete_zone(
        1,
        "zone-1",
        AlibabaHttpDnsZoneDelete(confirm_name="example.com"),
        None,
        object(),
    )

    assert locked_zone_ids == ["zone-1"] * 5


def test_zone_lock_serializes_legacy_adopt_and_direct_delete(tmp_path, monkeypatch):
    engine = create_engine(
        f"sqlite:///{(tmp_path / 'alibaba-zone-race.sqlite').as_posix()}",
        connect_args={"check_same_thread": False},
        future=True,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, future=True)
    setup_db = session_factory()
    credential = add_direct_credential(setup_db, name="delete-race")
    credential_id = credential.id
    setup_db.close()

    record = remote_alibaba_record(record_type="A")
    record["Value"] = "192.0.2.10"
    adopt_inside_lock = threading.Event()
    allow_adopt_to_commit = threading.Event()
    delete_started = threading.Event()
    delete_remote_read = threading.Event()
    delete_rpc_calls = []
    original_adopt_record = alibaba_httpdns_routes._adopt_record

    def blocking_adopt_record(*args, **kwargs):
        adopt_inside_lock.set()
        assert allow_adopt_to_commit.wait(timeout=5)
        return original_adopt_record(*args, **kwargs)

    def credential_zone(*_args):
        delete_remote_read.set()
        return {"ZoneId": "zone-race", "ZoneName": "example.com"}

    monkeypatch.setattr("app.routes.alibaba_httpdns._adopt_record", blocking_adopt_record)
    monkeypatch.setattr("app.routes.alibaba_httpdns.list_remote_records", lambda *_args: [record])
    monkeypatch.setattr("app.routes.alibaba_httpdns._credential_zone", credential_zone)
    monkeypatch.setattr("app.routes.alibaba_httpdns.list_credential_records", lambda *_args: [record])
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.delete_credential_record",
        lambda *_args: delete_rpc_calls.append(1),
    )

    def run_adopt():
        db = session_factory()
        try:
            return adopt_zone(
                AlibabaHttpDnsZoneAdopt(
                    remote_account_id=7,
                    account_name="legacy",
                    zone_id="zone-race",
                    zone_name="example.com",
                ),
                None,
                db,
            )
        finally:
            db.close()

    def run_delete():
        # Constructing a Session does not issue a query. The first DB read must
        # remain inside the Zone lock so it can observe the adopter's commit.
        db = session_factory()
        delete_started.set()
        try:
            return delete_credential_record_action(
                credential_id,
                "zone-race",
                "record-1",
                AlibabaHttpDnsRecordDelete(confirm_record_id="record-1"),
                None,
                db,
            )
        except HTTPException as exc:
            return exc
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        adopt_future = executor.submit(run_adopt)
        assert adopt_inside_lock.wait(timeout=5)
        delete_future = executor.submit(run_delete)
        assert delete_started.wait(timeout=5)
        try:
            assert not delete_remote_read.wait(timeout=0.2)
        finally:
            allow_adopt_to_commit.set()
        adopt_response = adopt_future.result(timeout=5)
        delete_response = delete_future.result(timeout=5)

    verify_db = session_factory()
    try:
        binding = verify_db.query(AlibabaHttpDnsGroup).filter_by(
            zone_id="zone-race",
            record_id="record-1",
        ).one()
        assert binding.credential_id is None
    finally:
        verify_db.close()
        engine.dispose()

    assert adopt_response.detail["created"] == 1
    assert isinstance(delete_response, HTTPException)
    assert delete_response.status_code == 409
    assert "组 ID" in str(delete_response.detail)
    assert delete_remote_read.is_set()
    assert delete_rpc_calls == []
    assert alibaba_httpdns_routes._zone_mutation_locks == {}


def test_managed_group_creates_apex_record_then_scope_and_unified_group(monkeypatch):
    db = make_session()
    credential = AlibabaHttpDnsCredential(
        name="direct-managed",
        access_key_id_encrypted=encrypt_secret("ak"),
        access_key_secret_encrypted=encrypt_secret("secret"),
        endpoint="alidns.aliyuncs.com",
        enabled=True,
    )
    db.add(credential)
    db.commit()
    calls = []
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns._credential_zone",
        lambda *_args: {
            "ZoneId": "zone-1",
            "ZoneName": "private.example.com",
            "RecordCount": 0,
            "EffectiveScopeIds": ["20004"],
        },
    )
    monkeypatch.setattr("app.routes.alibaba_httpdns.list_credential_records", lambda *_args: [])

    def add_record(_credential, **kwargs):
        calls.append(("record", kwargs))
        return {
            "RecordId": "record-1",
            "Rr": "@",
            "Type": kwargs["record_type"],
            "Value": kwargs["value"],
            "Ttl": kwargs["ttl"],
            "RequestSource": "default",
            "Weight": 1,
            "Priority": 1,
            "EnableStatus": "enable",
        }

    monkeypatch.setattr("app.routes.alibaba_httpdns.add_credential_record", add_record)
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.update_credential_zone_effective_scope",
        lambda _credential, zone_id, scopes: calls.append(("scope", {"zone_id": zone_id, "scopes": scopes})),
    )
    monkeypatch.setattr(
        "app.routes.alibaba_httpdns.resolve_hostname_ips_bounded",
        lambda *_args: ["203.0.113.10"],
    )

    output = create_managed_group(
        AlibabaHttpDnsStandaloneGroupCreate(
            credential_id=credential.id,
            zone_id="zone-1",
            primary_target="origin.example.net",
            primary_port=443,
            ttl=60,
            effective_scope_ids=["20003"],
        ),
        None,
        db,
    )

    source = db.get(FailoverGroup, output.source_group_id)
    assert [item[0] for item in calls] == ["record", "scope"]
    assert calls[0][1]["record_type"] == "A"
    assert calls[0][1]["value"] == "203.0.113.10"
    assert calls[1][1]["scopes"] == ["20003", "20004"]
    assert source.provider_type == "alibaba_httpdns"
    assert source.origins[0].target == "origin.example.net"
    assert source.origins[0].publish_mode == "expanded"


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


def test_direct_credential_zone_creates_full_provider_groups(monkeypatch):
    db = make_session()
    user = User(username="admin", password_hash="hash")
    credential = AlibabaHttpDnsCredential(
        name="direct",
        access_key_id_encrypted=encrypt_secret("ak"),
        access_key_secret_encrypted=encrypt_secret("secret"),
    )
    db.add_all([user, credential])
    db.commit()
    records = [
        {"RecordId": "a-1", "Rr": "www", "Type": "A", "Value": "192.0.2.10", "Ttl": 30, "EnableStatus": "enable"},
        {"RecordId": "c-1", "Rr": "api", "Type": "CNAME", "Value": "origin.example.net", "Ttl": 60, "EnableStatus": "enable"},
    ]
    monkeypatch.setattr("app.routes.alibaba_httpdns.list_credential_records", lambda *_args: records)

    response = adopt_zone(
        AlibabaHttpDnsZoneAdopt(
            credential_id=credential.id,
            remote_account_id=0,
            account_name="ignored",
            zone_id="zone-1",
            zone_name="example.com",
            primary_port=443,
        ),
        user,
        db,
    )

    assert response.detail["created"] == 2
    outputs = db.query(AlibabaHttpDnsGroup).order_by(AlibabaHttpDnsGroup.record_id).all()
    sources = db.query(FailoverGroup).order_by(FailoverGroup.hostname).all()
    assert all(item.credential_id == credential.id and item.source_group_id for item in outputs)
    assert all(item.origins == [] for item in outputs)
    assert {item.provider_type for item in sources} == {"alibaba_httpdns"}
    assert {item.hostname for item in sources} == {"www.example.com", "api.example.com"}
    assert all(len(item.origins) == 1 and item.origins[0].port == 443 for item in sources)


def test_unified_alibaba_only_group_switches_and_publishes_directly(monkeypatch):
    db = make_session()
    credential = AlibabaHttpDnsCredential(
        name="direct",
        access_key_id_encrypted=encrypt_secret("ak"),
        access_key_secret_encrypted=encrypt_secret("secret"),
    )
    source = FailoverGroup(
        provider_type="alibaba_httpdns",
        hostname="www.example.com",
        cloudflare_publish_enabled=False,
        doh_enabled=False,
        enabled=True,
    )
    db.add_all([credential, source])
    db.flush()
    primary = Origin(group_id=source.id, target="192.0.2.10", target_type="ipv4", port=443, priority=0, status="unhealthy")
    backup = Origin(group_id=source.id, target="192.0.2.20", target_type="ipv4", port=443, priority=10, status="healthy")
    db.add_all([primary, backup])
    db.flush()
    source.current_origin_id = primary.id
    output = AlibabaHttpDnsGroup(
        credential_id=credential.id,
        source_group_id=source.id,
        remote_account_id=-credential.id,
        account_name=credential.name,
        zone_id="zone-1",
        zone_name="example.com",
        record_id="record-1",
        rr="www",
        record_type="A",
        ttl=60,
        source_current_origin_id=primary.id,
        last_published_value=primary.target,
        enabled=True,
    )
    db.add(output)
    db.flush()
    legacy_candidate = AlibabaHttpDnsOrigin(
        group_id=output.id,
        target="198.51.100.99",
        target_type="ipv4",
        port=443,
        priority=0,
        status="healthy",
    )
    db.add(legacy_candidate)
    db.flush()
    output.current_origin_id = legacy_candidate.id
    db.commit()
    writes = []
    monkeypatch.setattr("app.failover.run_local_checks", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("app.alibaba_httpdns.publish_value", lambda _db, _output, value: writes.append(value) or {})
    monkeypatch.setattr("app.alibaba_httpdns.send_webhooks", lambda *_args, **_kwargs: None)

    assert evaluate_failover_groups(db, group_ids=[source.id], check_dns_consistency=False) == 1

    db.refresh(source)
    db.refresh(output)
    assert source.current_origin_id == backup.id
    assert output.current_origin_id == legacy_candidate.id
    assert output.source_current_origin_id == backup.id
    assert output.last_published_value == backup.target
    assert writes == [backup.target]


def test_alibaba_a_group_auto_repairs_direct_hostname_to_expanded_ip(monkeypatch):
    db = make_session()
    source = FailoverGroup(
        provider_type="alibaba_httpdns",
        hostname="www.example.com",
        cloudflare_publish_enabled=False,
        doh_enabled=False,
        enabled=True,
    )
    db.add(source)
    db.flush()
    origin = Origin(
        group_id=source.id,
        target="origin.example.net",
        target_type="hostname",
        publish_mode="direct",
        port=443,
        priority=0,
        status="healthy",
    )
    db.add(origin)
    db.flush()
    source.current_origin_id = origin.id
    output = AlibabaHttpDnsGroup(
        source_group_id=source.id,
        remote_account_id=7,
        account_name="Alibaba",
        zone_id="zone-1",
        zone_name="example.com",
        record_id="record-1",
        rr="www",
        record_type="A",
        enabled=True,
        source_current_origin_id=origin.id,
        last_published_value="192.0.2.9",
    )
    db.add(output)
    db.commit()
    writes = []

    def probe_expanded(_db, *, group_id=None, **_kwargs):
        assert group_id == source.id
        assert origin.publish_mode == "expanded"
        origin.resolved_ips_json = '["192.0.2.10"]'
        origin.healthy_ips_json = '["192.0.2.10"]'
        origin.status = "healthy"
        origin.last_error = None
        return 1

    monkeypatch.setattr("app.failover.run_local_checks", probe_expanded)
    monkeypatch.setattr("app.alibaba_httpdns.publish_value", lambda _db, _output, value: writes.append(value) or {})
    monkeypatch.setattr("app.alibaba_httpdns.send_webhooks", lambda *_args, **_kwargs: None)

    assert evaluate_failover_groups(db, group_ids=[source.id], check_dns_consistency=False) == 0

    assert origin.publish_mode == "expanded"
    assert output.last_published_value == "192.0.2.10"
    assert output.last_error is None
    assert writes == ["192.0.2.10"]


def test_alibaba_output_reconcile_also_repairs_direct_hostname(monkeypatch):
    db = make_session()
    source = FailoverGroup(
        provider_type="alibaba_httpdns",
        hostname="www.example.com",
        cloudflare_publish_enabled=False,
        enabled=True,
    )
    db.add(source)
    db.flush()
    origin = Origin(
        group_id=source.id,
        target="origin.example.net",
        target_type="hostname",
        publish_mode="direct",
        port=443,
        priority=0,
        status="healthy",
    )
    db.add(origin)
    db.flush()
    source.current_origin_id = origin.id
    output = AlibabaHttpDnsGroup(
        source_group_id=source.id,
        remote_account_id=7,
        account_name="Alibaba",
        zone_id="zone-1",
        zone_name="example.com",
        record_id="record-1",
        rr="www",
        record_type="A",
        enabled=True,
        source_current_origin_id=origin.id,
        last_published_value="192.0.2.9",
    )
    db.add(output)
    db.commit()
    writes = []

    def probe_expanded(_db, *, group_id=None, **_kwargs):
        assert group_id == source.id
        assert origin.publish_mode == "expanded"
        origin.resolved_ips_json = '["192.0.2.11"]'
        origin.healthy_ips_json = '["192.0.2.11"]'
        origin.status = "healthy"
        return 1

    monkeypatch.setattr("app.health.run_local_checks", probe_expanded)
    monkeypatch.setattr("app.alibaba_httpdns.publish_value", lambda _db, _output, value: writes.append(value) or {})
    monkeypatch.setattr("app.alibaba_httpdns.send_webhooks", lambda *_args, **_kwargs: None)

    assert evaluate_alibaba_httpdns_groups(db, [output.id]) == 0
    assert origin.publish_mode == "expanded"
    assert output.last_published_value == "192.0.2.11"
    assert output.last_error is None
    assert writes == ["192.0.2.11"]


def test_alibaba_cname_group_keeps_direct_hostname_mode(monkeypatch):
    db = make_session()
    source = FailoverGroup(
        provider_type="alibaba_httpdns",
        hostname="alias.example.com",
        cloudflare_publish_enabled=False,
        enabled=True,
    )
    db.add(source)
    db.flush()
    origin = Origin(
        group_id=source.id,
        target="origin.example.net",
        target_type="hostname",
        publish_mode="direct",
        port=443,
        priority=0,
        status="healthy",
    )
    db.add(origin)
    db.flush()
    source.current_origin_id = origin.id
    output = AlibabaHttpDnsGroup(
        source_group_id=source.id,
        remote_account_id=7,
        account_name="Alibaba",
        zone_id="zone-1",
        zone_name="example.com",
        record_id="record-cname",
        rr="alias",
        record_type="CNAME",
        enabled=True,
        source_current_origin_id=origin.id,
        last_published_value=origin.target,
    )
    db.add(output)
    db.commit()
    probes = []
    monkeypatch.setattr("app.failover.run_local_checks", lambda *_args, **_kwargs: probes.append(1))

    assert evaluate_failover_groups(db, group_ids=[source.id], check_dns_consistency=False) == 0
    assert origin.publish_mode == "direct"
    assert probes == []


def test_mixed_alibaba_output_types_are_visible_and_do_not_abort_scheduler(monkeypatch):
    db = make_session()
    source = FailoverGroup(
        provider_type="alibaba_httpdns",
        hostname="mixed.example.com",
        cloudflare_publish_enabled=False,
        enabled=True,
    )
    db.add(source)
    db.flush()
    origin = Origin(
        group_id=source.id,
        target="origin.example.net",
        target_type="hostname",
        publish_mode="direct",
        port=443,
        priority=0,
        status="healthy",
    )
    db.add(origin)
    db.flush()
    source.current_origin_id = origin.id
    for record_id, record_type in (("record-a", "A"), ("record-cname", "CNAME")):
        db.add(
            AlibabaHttpDnsGroup(
                source_group_id=source.id,
                remote_account_id=7,
                account_name="Alibaba",
                zone_id="zone-1",
                zone_name="example.com",
                record_id=record_id,
                rr="mixed",
                record_type=record_type,
                enabled=True,
            )
        )
    db.commit()
    webhooks = []
    monkeypatch.setattr("app.failover.send_webhooks", lambda _db, event_type, payload: webhooks.append((event_type, payload)))

    assert evaluate_failover_groups(db, group_ids=[source.id], check_dns_consistency=False) == 0
    assert source.last_error == "阿里云输出配置冲突：同一故障切换组不能同时绑定不同类型的阿里云输出（当前：A/CNAME）"
    assert source.provider_record_type is None
    assert source.provider_record_type_conflict is True
    assert db.query(Event).filter(Event.type == "alibaba_httpdns.configuration_error").count() == 1
    assert [item[0] for item in webhooks] == ["alibaba_httpdns.configuration_error"]

    # A steady scheduler tick keeps the visible error but does not spam events.
    assert evaluate_failover_groups(db, group_ids=[source.id], check_dns_consistency=False) == 0
    assert db.query(Event).filter(Event.type == "alibaba_httpdns.configuration_error").count() == 1


def test_mixed_alibaba_output_types_return_400_when_adding_or_editing_origin():
    db = make_session()
    user = User(username="admin", password_hash="hash")
    source = FailoverGroup(
        provider_type="alibaba_httpdns",
        hostname="mixed.example.com",
        cloudflare_publish_enabled=False,
        enabled=True,
    )
    db.add_all([user, source])
    db.flush()
    origin = Origin(
        group_id=source.id,
        target="origin.example.net",
        target_type="hostname",
        publish_mode="direct",
        port=443,
        priority=0,
        status="healthy",
    )
    db.add(origin)
    db.flush()
    for record_id, record_type in (("record-a", "A"), ("record-cname", "CNAME")):
        db.add(
            AlibabaHttpDnsGroup(
                source_group_id=source.id,
                remote_account_id=7,
                account_name="Alibaba",
                zone_id="zone-1",
                zone_name="example.com",
                record_id=record_id,
                rr="mixed",
                record_type=record_type,
                enabled=True,
            )
        )
    db.commit()

    with pytest.raises(HTTPException) as create_error:
        create_failover_origin(source.id, OriginCreate(target="backup.example.net", port=443), user, db)
    assert create_error.value.status_code == 400
    assert "不能同时绑定不同类型" in str(create_error.value.detail)

    with pytest.raises(HTTPException) as update_error:
        update_failover_origin(origin.id, OriginUpdate(remark="still invalid"), user, db)
    assert update_error.value.status_code == 400
    assert "不能同时绑定不同类型" in str(update_error.value.detail)


def test_legacy_cname_cannot_bind_to_direct_alibaba_a_group():
    db = make_session()
    user = User(username="admin", password_hash="hash")
    source = FailoverGroup(
        provider_type="alibaba_httpdns",
        hostname="a.example.com",
        cloudflare_publish_enabled=False,
        enabled=True,
    )
    db.add_all([user, source])
    db.flush()
    origin = Origin(group_id=source.id, target="192.0.2.10", target_type="ipv4", port=443, status="healthy")
    db.add(origin)
    db.flush()
    source.current_origin_id = origin.id
    direct_a = AlibabaHttpDnsGroup(
        source_group_id=source.id,
        remote_account_id=7,
        account_name="Alibaba",
        zone_id="zone-1",
        zone_name="example.com",
        record_id="record-a",
        rr="a",
        record_type="A",
        enabled=True,
    )
    legacy_cname = AlibabaHttpDnsGroup(
        remote_account_id=8,
        account_name="Legacy",
        zone_id="zone-2",
        zone_name="example.net",
        record_id="record-cname",
        rr="alias",
        record_type="CNAME",
        enabled=True,
    )
    db.add_all([direct_a, legacy_cname])
    db.commit()

    with pytest.raises(HTTPException) as exc_info:
        update_alibaba_group(
            legacy_cname.id,
            AlibabaHttpDnsGroupUpdate(source_group_id=source.id),
            user,
            db,
        )
    assert exc_info.value.status_code == 400
    assert "不能同时绑定不同类型" in str(exc_info.value.detail)
    assert legacy_cname.source_group_id is None


def test_sync_group_can_skip_already_completed_mode_guard(monkeypatch):
    db = make_session()
    source = FailoverGroup(provider_type="alibaba_httpdns", hostname="www.example.com", enabled=True)
    db.add(source)
    db.flush()
    origin = Origin(group_id=source.id, target="192.0.2.10", target_type="ipv4", port=443, status="healthy")
    db.add(origin)
    db.commit()
    monkeypatch.setattr(
        "app.alibaba_httpdns.normalize_alibaba_provider_origin_modes",
        lambda *_args: (_ for _ in ()).throw(AssertionError("mode guard ran twice")),
    )

    assert sync_group_alibaba_outputs(db, source, origin, origin_modes_normalized=True) is False


def test_shared_output_without_selected_source_is_a_quiet_noop(monkeypatch):
    db = make_session()
    source = FailoverGroup(
        provider_type="alibaba_httpdns",
        hostname="waiting.example.com",
        cloudflare_publish_enabled=False,
        enabled=True,
    )
    db.add(source)
    db.flush()
    output = AlibabaHttpDnsGroup(
        source_group_id=source.id,
        remote_account_id=7,
        account_name="Alibaba",
        zone_id="zone-1",
        zone_name="example.com",
        record_id="record-waiting",
        rr="waiting",
        record_type="A",
        enabled=True,
        last_error="The linked failover group has no current healthy origin",
    )
    db.add(output)
    db.commit()
    events = []
    monkeypatch.setattr("app.alibaba_httpdns.add_event", lambda _db, event_type, *_args: events.append(event_type))
    monkeypatch.setattr("app.alibaba_httpdns.send_webhooks", lambda *args, **kwargs: events.append("webhook"))

    assert evaluate_alibaba_httpdns_groups(db, [output.id]) == 0
    assert output.last_error is None
    assert events == []


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


def test_account_backoff_does_not_block_real_failover_publish(monkeypatch):
    db = make_session()
    group, primary, backup = add_group(db)
    group.current_origin_id = primary.id
    group.last_published_value = primary.target
    primary.published_ips_json = f'["{primary.target}"]'
    update_azpanel_settings(
        db,
        {"enabled": True, "base_url": "https://az.example.com", "api_token": "secret-token", "timeout_seconds": 15},
    )
    state = AlibabaHttpDnsAccountState(
        remote_account_id=group.remote_account_id,
        failure_count=1,
        next_retry_at=datetime.utcnow() + timedelta(minutes=5),
        last_error="temporary 503",
    )
    db.add(state)
    primary.enabled = False
    backup.ignore_health_check = True
    db.commit()
    calls = []

    class Response:
        is_success = True

        def raise_for_status(self):
            return None

        def json(self):
            return {"status": "success", "data": {"record": {}}}

    monkeypatch.setattr("app.alibaba_httpdns.httpx.request", lambda *args, **kwargs: calls.append(1) or Response())
    monkeypatch.setattr("app.alibaba_httpdns.tcp_check", lambda *args: TcpCheckResult(True, 2.0, None))
    monkeypatch.setattr("app.alibaba_httpdns.send_webhooks", lambda *args, **kwargs: None)

    assert evaluate_alibaba_httpdns_groups(db, [group.id]) == 1
    assert calls == [1]
    assert group.current_origin_id == backup.id
    assert group.last_published_value == backup.target
    assert state.failure_count == 0
    assert state.next_retry_at is None


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
    aws_credential = AwsRoute53Credential(
        name="aws",
        access_key_id_encrypted="key",
        secret_access_key_encrypted="secret",
        region="ap-east-1",
    )
    aws = FailoverGroup(
        provider_type="route53",
        zone_id=None,
        hostname=hostname,
        ttl=60,
        enabled=True,
        cloudflare_publish_enabled=False,
        doh_enabled=False,
    )
    db.add(aws_credential)
    db.add(aws)
    db.flush()
    db.add(Origin(group_id=aws.id, target="192.0.2.3", target_type="ipv4", port=443, priority=0))
    db.add(
        AwsRoute53Output(
            group_id=aws.id,
            credential_id=aws_credential.id,
            doh_endpoint_id=endpoint.id,
            hosted_zone_id="ZAWS",
            hosted_zone_name="example.com",
            hostname=hostname,
            ttl=60,
        )
    )
    db.commit()

    assert cloudflare.hostname == hostname
    assert f"{alibaba.rr}.{alibaba.zone_name}" == hostname
    assert aws.hostname == hostname
    assert {cloudflare.origins[0].target, alibaba.origins[0].target, aws.origins[0].target} == {
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.3",
    }
