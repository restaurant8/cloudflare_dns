import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.doh import build_doh_snapshot
from app.models import AwsRoute53Credential, AwsRoute53Output, DohEndpoint, FailoverGroup, Origin
from app.route53 import create_private_hosted_zone, delete_empty_private_hosted_zone, desired_origin_records, publish_route53_output, route53_output_matches, sync_group_route53_outputs
from app.routes.groups import create_origin as create_failover_origin
from app.routes.route53 import create_hosted_zone, create_output, create_standalone_group, delete_hosted_zone
from app.schemas import AwsRoute53OutputCreate, AwsRoute53PrivateHostedZoneCreate, AwsRoute53PrivateHostedZoneDelete, AwsRoute53StandaloneGroupCreate, OriginCreate
from app.security import encrypt_secret


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def setup_output(db):
    endpoint = DohEndpoint(
        name="aws-hk",
        base_url="https://example.cloudfront.net",
        hmac_secret_encrypted=encrypt_secret("x" * 40),
    )
    credential = AwsRoute53Credential(
        name="aws",
        access_key_id_encrypted=encrypt_secret("AKIAEXAMPLE"),
        secret_access_key_encrypted=encrypt_secret("secret"),
        region="ap-east-1",
    )
    group = FailoverGroup(
        provider_type="route53",
        zone_id=None,
        hostname="snejsat.baidu.com",
        cloudflare_publish_enabled=False,
        doh_enabled=False,
    )
    db.add_all([endpoint, credential, group])
    db.flush()
    origin = Origin(
        group_id=group.id,
        target="203.0.113.10",
        target_type="ipv4",
        port=443,
        priority=0,
        status="healthy",
    )
    db.add(origin)
    db.flush()
    group.current_origin_id = origin.id
    output = AwsRoute53Output(
        group_id=group.id,
        credential_id=credential.id,
        doh_endpoint_id=endpoint.id,
        hosted_zone_id="ZPRIVATE",
        hosted_zone_name="baidu.com",
        hostname="snejsat.baidu.com",
        ttl=60,
    )
    db.add(output)
    db.commit()
    return endpoint, group, origin, output


class FakeRoute53:
    def __init__(self, remote_records=None):
        self.changes = []
        self.remote_records = list(remote_records or [])

    def list_resource_record_sets(self, **_kwargs):
        return {"ResourceRecordSets": self.remote_records, "IsTruncated": False}

    def change_resource_record_sets(self, **kwargs):
        self.changes.append(kwargs)
        return {"ChangeInfo": {"Id": "change-1", "Status": "PENDING"}}


def test_publish_route53_output_upserts_selected_origin(monkeypatch):
    db = make_session()
    _, _, origin, output = setup_output(db)
    client = FakeRoute53()
    monkeypatch.setattr("app.route53.route53_client", lambda credential: client)

    publish_route53_output(output, origin)

    assert client.changes[0]["HostedZoneId"] == "ZPRIVATE"
    record = client.changes[0]["ChangeBatch"]["Changes"][0]["ResourceRecordSet"]
    assert record == {
        "Name": "snejsat.baidu.com.",
        "Type": "A",
        "TTL": 60,
        "ResourceRecords": [{"Value": "203.0.113.10"}],
    }
    assert output.current_origin_id == origin.id
    assert output.last_values == ["203.0.113.10"]


def test_selected_origin_ip_change_publishes_without_reselecting(monkeypatch):
    db = make_session()
    _, group, origin, output = setup_output(db)
    output.current_origin_id = origin.id
    output.last_record_type = "A"
    output.last_values_json = '["203.0.113.10"]'
    origin.target = "203.0.113.20"
    client = FakeRoute53()
    monkeypatch.setattr("app.route53.route53_client", lambda credential: client)

    assert sync_group_route53_outputs(db, group, origin) is True
    assert output.last_values == ["203.0.113.20"]


def test_route53_output_is_synced_to_ec2_as_resolver_allowlist_marker():
    db = make_session()
    endpoint, _, _, output = setup_output(db)

    snapshot = build_doh_snapshot(db, endpoint)

    assert snapshot["version"] == 2
    assert snapshot["records"] == [
        {
            "name": "snejsat.baidu.com",
            "type": "A",
            "value": "0.0.0.0",
            "ttl": 60,
            "route53_output_id": output.id,
            "source": "vpc_resolver",
        }
    ]


def test_direct_hostname_publishes_cname_for_vpc_resolver_to_follow():
    origin = Origin(target="real.example.net", target_type="hostname", publish_mode="direct", port=443)

    assert desired_origin_records(origin) == {"CNAME": ["real.example.net."]}


def test_route53_group_forces_hostname_backup_to_expanded_mode():
    db = make_session()
    _, group, _, _ = setup_output(db)

    backup = create_failover_origin(
        group.id,
        OriginCreate(target="backup.example.net", port=443, priority=10, publish_mode="direct"),
        None,
        db,
    )

    assert backup.publish_mode == "expanded"


def test_route53_apex_never_sends_direct_cname_to_aws(monkeypatch):
    db = make_session()
    _, _, origin, output = setup_output(db)
    output.hostname = "baidu.com"
    origin.target = "backup.example.net"
    origin.target_type = "hostname"
    origin.publish_mode = "direct"
    client = FakeRoute53()
    monkeypatch.setattr("app.route53.route53_client", lambda _credential: client)

    with pytest.raises(RuntimeError, match="cannot publish CNAME"):
        publish_route53_output(output, origin)

    assert client.changes == []


def test_record_type_change_deletes_exact_live_rrset_not_stale_local_metadata(monkeypatch):
    db = make_session()
    _, _, origin, output = setup_output(db)
    output.last_record_type = "A"
    output.last_values_json = '["203.0.113.10"]'
    output.last_ttl = 60
    origin.target = "real.example.net"
    origin.target_type = "hostname"
    origin.publish_mode = "direct"
    live = {
        "Name": "snejsat.baidu.com.",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [{"Value": "198.51.100.77"}],
    }
    client = FakeRoute53([live])
    monkeypatch.setattr("app.route53.route53_client", lambda credential: client)

    publish_route53_output(output, origin)

    changes = client.changes[0]["ChangeBatch"]["Changes"]
    assert changes[0] == {"Action": "DELETE", "ResourceRecordSet": live}
    assert changes[1]["Action"] == "UPSERT"
    assert changes[1]["ResourceRecordSet"]["Type"] == "CNAME"


def test_consistency_check_detects_stale_managed_record_type(monkeypatch):
    db = make_session()
    _, _, origin, output = setup_output(db)
    live_a = {
        "Name": "snejsat.baidu.com.",
        "Type": "A",
        "TTL": 60,
        "ResourceRecords": [{"Value": "203.0.113.10"}],
    }
    stale_aaaa = {
        "Name": "snejsat.baidu.com.",
        "Type": "AAAA",
        "TTL": 60,
        "ResourceRecords": [{"Value": "2001:db8::10"}],
    }
    client = FakeRoute53([live_a, stale_aaaa])
    monkeypatch.setattr("app.route53.route53_client", lambda credential: client)

    assert route53_output_matches(output, origin) is False


def test_alias_same_type_uses_delete_then_create(monkeypatch):
    db = make_session()
    _, _, origin, output = setup_output(db)
    alias = {
        "Name": "snejsat.baidu.com.",
        "Type": "A",
        "AliasTarget": {
            "HostedZoneId": "ZELB",
            "DNSName": "internal-elb.example.net.",
            "EvaluateTargetHealth": False,
        },
    }
    client = FakeRoute53([alias])
    monkeypatch.setattr("app.route53.route53_client", lambda credential: client)

    publish_route53_output(output, origin)

    changes = client.changes[0]["ChangeBatch"]["Changes"]
    assert [item["Action"] for item in changes] == ["DELETE", "CREATE"]
    assert changes[0]["ResourceRecordSet"] == alias


def _setup_unbound_output(db):
    endpoint, group, origin, output = setup_output(db)
    db.delete(output)
    db.commit()
    return endpoint, group, origin


def test_create_output_requires_explicit_adoption_of_existing_record(monkeypatch):
    db = make_session()
    endpoint, group, _ = _setup_unbound_output(db)
    alias = {
        "Name": "snejsat.baidu.com.",
        "Type": "A",
        "AliasTarget": {
            "HostedZoneId": "ZELB",
            "DNSName": "internal-elb.example.net.",
            "EvaluateTargetHealth": False,
        },
    }
    client = FakeRoute53([alias])
    monkeypatch.setattr("app.route53.route53_client", lambda credential: client)
    monkeypatch.setattr("app.routes.route53._best_effort_allowlist_sync", lambda *_args: None)
    payload = AwsRoute53OutputCreate(
        group_id=group.id,
        credential_id=db.query(AwsRoute53Credential).one().id,
        doh_endpoint_id=endpoint.id,
        hosted_zone_id="ZPRIVATE",
        hosted_zone_name="baidu.com",
        hostname="snejsat.baidu.com",
        ttl=60,
    )

    with pytest.raises(HTTPException) as exc_info:
        create_output(payload, None, db)

    assert exc_info.value.status_code == 409
    assert "Explicitly confirm adoption" in str(exc_info.value.detail)
    assert db.query(AwsRoute53Output).count() == 0
    assert client.changes == []


def test_confirmed_adoption_replaces_alias_and_traffic_policy_is_never_adopted(monkeypatch):
    db = make_session()
    endpoint, group, _ = _setup_unbound_output(db)
    credential_id = db.query(AwsRoute53Credential).one().id
    alias = {
        "Name": "snejsat.baidu.com.",
        "Type": "A",
        "AliasTarget": {
            "HostedZoneId": "ZELB",
            "DNSName": "internal-elb.example.net.",
            "EvaluateTargetHealth": False,
        },
    }
    client = FakeRoute53([alias])
    monkeypatch.setattr("app.route53.route53_client", lambda credential: client)
    monkeypatch.setattr("app.routes.route53._best_effort_allowlist_sync", lambda *_args: None)
    payload = AwsRoute53OutputCreate(
        group_id=group.id,
        credential_id=credential_id,
        doh_endpoint_id=endpoint.id,
        hosted_zone_id="ZPRIVATE",
        hosted_zone_name="baidu.com",
        hostname="snejsat.baidu.com",
        ttl=60,
        adopt_existing=True,
    )

    created = create_output(payload, None, db)
    assert created.id is not None
    assert [item["Action"] for item in client.changes[0]["ChangeBatch"]["Changes"]] == ["DELETE", "CREATE"]

    db.delete(db.get(AwsRoute53Output, created.id))
    db.commit()
    client.remote_records = [
        {
            "Name": "snejsat.baidu.com.",
            "Type": "A",
            "TTL": 60,
            "ResourceRecords": [{"Value": "203.0.113.10"}],
            "TrafficPolicyInstanceId": "12345678-abcd",
        }
    ]
    with pytest.raises(HTTPException) as exc_info:
        create_output(payload, None, db)
    assert exc_info.value.status_code == 409
    assert "Traffic Policy" in str(exc_info.value.detail)


def test_create_private_hosted_zone_uses_selected_vpc(monkeypatch):
    db = make_session()
    credential = AwsRoute53Credential(
        name="aws-create-zone",
        access_key_id_encrypted=encrypt_secret("AKIAEXAMPLE"),
        secret_access_key_encrypted=encrypt_secret("secret"),
        region="ap-east-1",
    )
    db.add(credential)
    db.commit()
    captured = {}
    monkeypatch.setattr(
        "app.routes.route53.list_vpcs",
        lambda _credential: [{"id": "vpc-123", "region": "ap-east-1"}],
    )

    def create(_credential, **kwargs):
        captured.update(kwargs)
        return {
            "id": "ZNEW",
            "name": kwargs["name"],
            "record_count": 2,
            "vpcs": [{"id": kwargs["vpc_id"], "region": kwargs["vpc_region"]}],
        }

    monkeypatch.setattr("app.routes.route53.create_private_hosted_zone", create)
    result = create_hosted_zone(
        credential.id,
        AwsRoute53PrivateHostedZoneCreate(
            name="snejsat.baidu.com",
            vpc_id="vpc-123",
            vpc_region="ap-east-1",
        ),
        None,
        db,
    )

    assert result["id"] == "ZNEW"
    assert captured["name"] == "snejsat.baidu.com"
    assert captured["vpc_id"] == "vpc-123"


def test_private_hosted_zone_caller_reference_is_retry_stable(monkeypatch):
    credential = AwsRoute53Credential(id=17, name="aws", region="ap-east-1", enabled=True)
    references = []

    class Client:
        def create_hosted_zone(self, **kwargs):
            references.append(kwargs["CallerReference"])
            return {"HostedZone": {"Id": "/hostedzone/ZNEW", "Name": kwargs["Name"]}}

    monkeypatch.setattr("app.route53.route53_client", lambda _credential: Client())

    for _ in range(2):
        create_private_hosted_zone(
            credential,
            name="private.example.com",
            vpc_id="vpc-123",
            vpc_region="ap-east-1",
        )

    assert references[0] == references[1]
    assert references[0].startswith("cloudflare-dns-")


def test_combined_group_creation_uses_hosted_zone_name_and_binds_output(monkeypatch):
    db = make_session()
    endpoint = DohEndpoint(
        name="aws-combined",
        base_url="https://example.cloudfront.net",
        hmac_secret_encrypted=encrypt_secret("x" * 40),
    )
    credential = AwsRoute53Credential(
        name="aws-combined",
        access_key_id_encrypted=encrypt_secret("AKIAEXAMPLE"),
        secret_access_key_encrypted=encrypt_secret("secret"),
        region="ap-east-1",
    )
    db.add_all([endpoint, credential])
    db.commit()
    monkeypatch.setattr(
        "app.routes.route53.get_private_hosted_zone",
        lambda *_args: {
            "id": "ZPRIVATE",
            "name": "snejsat.baidu.com",
            "record_count": 2,
            "vpcs": [{"id": "vpc-123", "region": "ap-east-1"}],
        },
    )
    monkeypatch.setattr("app.routes.route53.validate_route53_adoption", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("app.routes.route53._best_effort_allowlist_sync", lambda *_args: None)

    group = create_standalone_group(
        AwsRoute53StandaloneGroupCreate(
            credential_id=credential.id,
            doh_endpoint_id=endpoint.id,
            hosted_zone_id="ZPRIVATE",
            primary_target="203.0.113.10",
            primary_port=443,
            ttl=60,
        ),
        None,
        db,
    )

    output = db.query(AwsRoute53Output).one()
    assert group.hostname == "snejsat.baidu.com"
    assert group.provider_type == "route53"
    assert group.origins[0].target == "203.0.113.10"
    assert output.group_id == group.id
    assert output.hostname == "snejsat.baidu.com"
    assert output.hosted_zone_id == "ZPRIVATE"


def test_migrated_static_group_is_published_before_direct_doh_is_disabled(monkeypatch):
    db = make_session()
    endpoint = DohEndpoint(
        name="aws-migrated",
        base_url="https://example.cloudfront.net",
        hmac_secret_encrypted=encrypt_secret("x" * 40),
    )
    credential = AwsRoute53Credential(
        name="aws-migrated",
        access_key_id_encrypted=encrypt_secret("AKIAEXAMPLE"),
        secret_access_key_encrypted=encrypt_secret("secret"),
        region="ap-east-1",
    )
    group = FailoverGroup(
        provider_type="route53",
        zone_id=None,
        hostname="private.example.com",
        cloudflare_publish_enabled=False,
        doh_enabled=True,
        doh_endpoint=endpoint,
        doh_hostnames_json='["private.example.com"]',
    )
    db.add_all([endpoint, credential, group])
    db.flush()
    origin = Origin(group_id=group.id, target="203.0.113.10", target_type="ipv4", port=443, status="healthy")
    db.add(origin)
    db.flush()
    group.current_origin_id = origin.id
    db.commit()
    monkeypatch.setattr(
        "app.routes.route53.get_private_hosted_zone",
        lambda *_args: {"id": "ZPRIVATE", "name": "private.example.com", "record_count": 2, "vpcs": []},
    )
    monkeypatch.setattr("app.routes.route53.validate_route53_adoption", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("app.routes.route53._best_effort_allowlist_sync", lambda *_args: None)
    published = []
    monkeypatch.setattr(
        "app.routes.route53.publish_route53_output",
        lambda output, selected, **_kwargs: published.append((output.hostname, selected.target)) or {},
    )

    result = create_standalone_group(
        AwsRoute53StandaloneGroupCreate(
            credential_id=credential.id,
            doh_endpoint_id=endpoint.id,
            hosted_zone_id="ZPRIVATE",
            primary_target="203.0.113.10",
            primary_port=443,
        ),
        None,
        db,
    )

    assert result.id == group.id
    assert published == [("private.example.com", "203.0.113.10")]
    assert result.doh_enabled is False
    assert len(result.origins) == 1


def test_hosted_zone_delete_refuses_local_binding(monkeypatch):
    db = make_session()
    _, _, _, output = setup_output(db)
    monkeypatch.setattr(
        "app.routes.route53.get_private_hosted_zone",
        lambda *_args: {"id": "ZPRIVATE", "name": "baidu.com", "record_count": 2, "vpcs": []},
    )

    with pytest.raises(HTTPException) as exc_info:
        delete_hosted_zone(
            output.credential_id,
            "ZPRIVATE",
            AwsRoute53PrivateHostedZoneDelete(confirm_name="baidu.com"),
            None,
            db,
        )

    assert exc_info.value.status_code == 409
    assert "still used" in str(exc_info.value.detail)


def test_delete_empty_private_zone_never_removes_business_records(monkeypatch):
    db = make_session()
    credential = AwsRoute53Credential(
        name="aws-safe-delete",
        access_key_id_encrypted=encrypt_secret("AKIAEXAMPLE"),
        secret_access_key_encrypted=encrypt_secret("secret"),
        region="ap-east-1",
    )
    db.add(credential)
    db.commit()

    class Client:
        deleted = False

        def get_hosted_zone(self, **_kwargs):
            return {
                "HostedZone": {"Id": "/hostedzone/ZSAFE", "Name": "private.example.", "Config": {"PrivateZone": True}},
                "VPCs": [],
            }

        def list_resource_record_sets(self, **_kwargs):
            return {
                "ResourceRecordSets": [
                    {"Name": "private.example.", "Type": "SOA"},
                    {"Name": "private.example.", "Type": "NS"},
                    {"Name": "private.example.", "Type": "A", "TTL": 60, "ResourceRecords": [{"Value": "203.0.113.10"}]},
                ],
                "IsTruncated": False,
            }

        def delete_hosted_zone(self, **_kwargs):
            self.deleted = True
            return {"ChangeInfo": {"Id": "change-delete"}}

    client = Client()
    monkeypatch.setattr("app.route53.route53_client", lambda _credential: client)

    with pytest.raises(RuntimeError, match="not empty"):
        delete_empty_private_hosted_zone(credential, "ZSAFE")
    assert client.deleted is False
