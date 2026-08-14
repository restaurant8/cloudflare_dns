import hashlib
import ipaddress
import json
from collections.abc import Iterable
from datetime import datetime
from typing import Any

import boto3
from sqlalchemy.orm import Session, selectinload

from .events import add_event
from .models import AwsRoute53Credential, AwsRoute53Output, FailoverGroup, Origin
from .notifier import send_webhooks
from .origin_expansion import is_expanded_origin, selected_publish_ip
from .security import decrypt_secret


class Route53AdoptionRequired(RuntimeError):
    """Raised when an unmanaged owner name already has DNS data."""


class Route53TrafficPolicyManaged(RuntimeError):
    """Raised when Route 53 Traffic Flow owns an RRset we cannot safely replace."""


def route53_client(credential: AwsRoute53Credential):
    if not credential.enabled:
        raise RuntimeError(f"AWS Route 53 credential {credential.name} is disabled")
    kwargs: dict[str, Any] = {"region_name": credential.region or "ap-east-1"}
    if not credential.use_instance_role:
        if not credential.access_key_id_encrypted or not credential.secret_access_key_encrypted:
            raise RuntimeError(f"AWS Route 53 credential {credential.name} has no access key")
        kwargs["aws_access_key_id"] = decrypt_secret(credential.access_key_id_encrypted)
        kwargs["aws_secret_access_key"] = decrypt_secret(credential.secret_access_key_encrypted)
        if credential.session_token_encrypted:
            kwargs["aws_session_token"] = decrypt_secret(credential.session_token_encrypted)
    return boto3.client("route53", **kwargs)


def ec2_client(credential: AwsRoute53Credential):
    if not credential.enabled:
        raise RuntimeError(f"AWS Route 53 credential {credential.name} is disabled")
    kwargs: dict[str, Any] = {"region_name": credential.region or "ap-east-1"}
    if not credential.use_instance_role:
        if not credential.access_key_id_encrypted or not credential.secret_access_key_encrypted:
            raise RuntimeError(f"AWS Route 53 credential {credential.name} has no access key")
        kwargs["aws_access_key_id"] = decrypt_secret(credential.access_key_id_encrypted)
        kwargs["aws_secret_access_key"] = decrypt_secret(credential.secret_access_key_encrypted)
        if credential.session_token_encrypted:
            kwargs["aws_session_token"] = decrypt_secret(credential.session_token_encrypted)
    return boto3.client("ec2", **kwargs)


def normalize_hosted_zone_id(value: str) -> str:
    return str(value or "").strip().removeprefix("/hostedzone/")


def list_private_hosted_zones(credential: AwsRoute53Credential) -> list[dict[str, Any]]:
    client = route53_client(credential)
    paginator = client.get_paginator("list_hosted_zones")
    zones: list[dict[str, Any]] = []
    for page in paginator.paginate():
        for zone in page.get("HostedZones", []):
            if not bool((zone.get("Config") or {}).get("PrivateZone")):
                continue
            zone_id = normalize_hosted_zone_id(str(zone.get("Id") or ""))
            details = client.get_hosted_zone(Id=zone_id)
            zones.append(
                {
                    "id": zone_id,
                    "name": str(zone.get("Name") or "").rstrip("."),
                    "record_count": int(zone.get("ResourceRecordSetCount") or 0),
                    "vpcs": [
                        {"id": str(item.get("VPCId") or ""), "region": str(item.get("VPCRegion") or "")}
                        for item in details.get("VPCs", [])
                    ],
                }
            )
    return sorted(zones, key=lambda item: (item["name"], item["id"]))


def list_vpcs(credential: AwsRoute53Credential) -> list[dict[str, Any]]:
    response = ec2_client(credential).describe_vpcs()
    vpcs: list[dict[str, Any]] = []
    for item in response.get("Vpcs", []):
        tags = {str(tag.get("Key") or ""): str(tag.get("Value") or "") for tag in item.get("Tags", [])}
        vpcs.append(
            {
                "id": str(item.get("VpcId") or ""),
                "region": credential.region or "ap-east-1",
                "name": tags.get("Name") or None,
                "cidr_block": str(item.get("CidrBlock") or "") or None,
                "is_default": bool(item.get("IsDefault")),
            }
        )
    return sorted(vpcs, key=lambda item: (not item["is_default"], item["name"] or "", item["id"]))


def get_private_hosted_zone(credential: AwsRoute53Credential, hosted_zone_id: str) -> dict[str, Any]:
    zone_id = normalize_hosted_zone_id(hosted_zone_id)
    response = route53_client(credential).get_hosted_zone(Id=zone_id)
    zone = dict(response.get("HostedZone") or {})
    if not bool((zone.get("Config") or {}).get("PrivateZone")):
        raise ValueError(f"Route 53 hosted zone {zone_id} is not private")
    return {
        "id": zone_id,
        "name": str(zone.get("Name") or "").rstrip("."),
        "record_count": int(zone.get("ResourceRecordSetCount") or 0),
        "vpcs": [
            {"id": str(item.get("VPCId") or ""), "region": str(item.get("VPCRegion") or "")}
            for item in response.get("VPCs", [])
        ],
    }


def create_private_hosted_zone(
    credential: AwsRoute53Credential,
    *,
    name: str,
    vpc_id: str,
    vpc_region: str,
    comment: str | None = None,
) -> dict[str, Any]:
    client = route53_client(credential)
    canonical_request = ":".join(
        (
            str(credential.id or 0),
            name.rstrip(".").lower(),
            vpc_region.strip().lower(),
            vpc_id.strip().lower(),
        )
    )
    caller_reference = "cloudflare-dns-" + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    response = client.create_hosted_zone(
        Name=name.rstrip(".") + ".",
        CallerReference=caller_reference,
        VPC={"VPCRegion": vpc_region, "VPCId": vpc_id},
        HostedZoneConfig={
            "Comment": (comment or "Private DoH managed by cloudflare_dns")[:256],
            "PrivateZone": True,
        },
    )
    zone = dict(response.get("HostedZone") or {})
    return {
        "id": normalize_hosted_zone_id(str(zone.get("Id") or "")),
        "name": str(zone.get("Name") or name).rstrip("."),
        "record_count": int(zone.get("ResourceRecordSetCount") or 0),
        "vpcs": [{"id": vpc_id, "region": vpc_region}],
    }


def delete_empty_private_hosted_zone(
    credential: AwsRoute53Credential,
    hosted_zone_id: str,
) -> dict[str, Any]:
    client = route53_client(credential)
    zone = get_private_hosted_zone(credential, hosted_zone_id)
    records: list[dict[str, Any]] = []
    request: dict[str, Any] = {"HostedZoneId": zone["id"], "MaxItems": "300"}
    while True:
        response = client.list_resource_record_sets(**request)
        records.extend(response.get("ResourceRecordSets", []))
        if not response.get("IsTruncated"):
            break
        request["StartRecordName"] = response["NextRecordName"]
        request["StartRecordType"] = response["NextRecordType"]
        if response.get("NextRecordIdentifier"):
            request["StartRecordIdentifier"] = response["NextRecordIdentifier"]
    non_default = [item for item in records if str(item.get("Type") or "").upper() not in {"NS", "SOA"}]
    if non_default:
        summary = ", ".join(
            f"{str(item.get('Name') or '').rstrip('.')} {item.get('Type') or '?'}" for item in non_default[:8]
        )
        if len(non_default) > 8:
            summary += f", and {len(non_default) - 8} more"
        raise RuntimeError(f"Private hosted zone is not empty: {summary}")
    return dict(client.delete_hosted_zone(Id=zone["id"]).get("ChangeInfo") or {})


def validate_hostname_in_zone(hostname: str, zone_name: str) -> None:
    hostname = hostname.rstrip(".").lower()
    zone_name = zone_name.rstrip(".").lower()
    if not zone_name or (hostname != zone_name and not hostname.endswith("." + zone_name)):
        raise ValueError(f"{hostname} is not inside Route 53 private hosted zone {zone_name}")


def _records_by_type(values: Iterable[str]) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {}
    for raw in values:
        value = str(ipaddress.ip_address(raw))
        record_type = "A" if ipaddress.ip_address(value).version == 4 else "AAAA"
        records.setdefault(record_type, []).append(value)
    return {key: sorted(set(items)) for key, items in records.items() if items}


def _record_set(hostname: str, record_type: str, values: list[str], ttl: int) -> dict[str, Any]:
    return {
        "Name": hostname.rstrip(".") + ".",
        "Type": record_type,
        "TTL": max(int(ttl), 0),
        "ResourceRecords": [{"Value": value} for value in values],
    }


def desired_origin_records(origin: Origin) -> dict[str, list[str]]:
    """Convert the shared failover decision to private Route 53 A/AAAA data.

    Direct hostname mode becomes a Route 53 CNAME. This is safe here because the
    EC2 DoH service forwards the complete query to the VPC Resolver, which follows
    the CNAME recursively; the client never falls back to its local resolver.
    """
    if is_expanded_origin(origin):
        selected = selected_publish_ip(origin)
        return _records_by_type([selected] if selected else [])
    if origin.target_type in {"ipv4", "ipv6"}:
        return _records_by_type([origin.target])
    if origin.target_type == "hostname":
        return {"CNAME": [origin.target.rstrip(".") + "."]}
    raise RuntimeError(f"Unsupported Route 53 origin type: {origin.target_type}")


_RRSET_CHANGE_KEYS = {
    "Name",
    "Type",
    "SetIdentifier",
    "Weight",
    "Region",
    "GeoLocation",
    "Failover",
    "MultiValueAnswer",
    "TTL",
    "ResourceRecords",
    "AliasTarget",
    "CidrRoutingConfig",
    "GeoProximityLocation",
    "HealthCheckId",
}
_RRSET_READ_KEYS = _RRSET_CHANGE_KEYS | {"TrafficPolicyInstanceId"}
_ROUTING_POLICY_KEYS = _RRSET_CHANGE_KEYS - {
    "Name",
    "Type",
    "TTL",
    "ResourceRecords",
    "MultiValueAnswer",
}


def _remote_record_requires_recreate(record: dict[str, Any]) -> bool:
    return bool(record.get("MultiValueAnswer")) or any(key in record for key in _ROUTING_POLICY_KEYS)


def _remote_managed_record_sets(
    client,
    hosted_zone_id: str,
    hostname: str,
) -> list[dict[str, Any]]:
    """Read the live A/AAAA/CNAME RRsets for one owner name.

    Route 53 DELETE requests must echo the live record exactly. Local publication
    metadata is only an observation and may be stale after a console edit, restore,
    or database loss, so it is never used to construct destructive changes.
    """
    owner = hostname.rstrip(".").lower()
    request: dict[str, Any] = {
        "HostedZoneId": normalize_hosted_zone_id(hosted_zone_id),
        "StartRecordName": owner + ".",
        "MaxItems": "100",
    }
    matches: list[dict[str, Any]] = []
    while True:
        response = client.list_resource_record_sets(**request)
        for raw in response.get("ResourceRecordSets", []):
            name = str(raw.get("Name") or "").rstrip(".").lower()
            if name != owner:
                return matches
            if str(raw.get("Type") or "").upper() in {"A", "AAAA", "CNAME"}:
                matches.append({key: value for key, value in raw.items() if key in _RRSET_READ_KEYS})
        if not response.get("IsTruncated"):
            return matches
        next_name = str(response.get("NextRecordName") or "")
        if next_name.rstrip(".").lower() != owner:
            return matches
        request["StartRecordName"] = next_name
        request["StartRecordType"] = response["NextRecordType"]
        if response.get("NextRecordIdentifier"):
            request["StartRecordIdentifier"] = response["NextRecordIdentifier"]


def _describe_remote_record(record: dict[str, Any]) -> str:
    record_type = str(record.get("Type") or "?").upper()
    if record.get("TrafficPolicyInstanceId"):
        return f"{record_type} TrafficPolicyInstance={record['TrafficPolicyInstanceId']}"
    if record.get("AliasTarget"):
        target = str((record.get("AliasTarget") or {}).get("DNSName") or "alias")
        return f"{record_type} ALIAS→{target}"
    if record.get("SetIdentifier"):
        return f"{record_type} routing-policy[{record['SetIdentifier']}]"
    values = ",".join(str(item.get("Value") or "") for item in record.get("ResourceRecords", []))
    return f"{record_type} {values or '(empty)'}"


def validate_route53_adoption(
    credential: AwsRoute53Credential,
    hosted_zone_id: str,
    hostname: str,
    *,
    adopt_existing: bool,
) -> list[dict[str, Any]]:
    """Require explicit ownership before an output may replace live RRsets."""
    records = _remote_managed_record_sets(
        route53_client(credential),
        hosted_zone_id,
        hostname,
    )
    traffic_policy = next((item for item in records if item.get("TrafficPolicyInstanceId")), None)
    if traffic_policy is not None:
        raise Route53TrafficPolicyManaged(
            f"{hostname} is managed by Route 53 Traffic Policy instance "
            f"{traffic_policy['TrafficPolicyInstanceId']}; delete or detach that Traffic Policy instance before binding"
        )
    if records and not adopt_existing:
        summary = "; ".join(_describe_remote_record(item) for item in records[:8])
        if len(records) > 8:
            summary += f"; and {len(records) - 8} more"
        raise Route53AdoptionRequired(
            f"Route 53 already has records for {hostname}: {summary}. "
            "Explicitly confirm adoption to replace these A/AAAA/CNAME records"
        )
    return records


def publish_route53_output(
    output: AwsRoute53Output,
    origin: Origin,
    *,
    require_adoption: bool = False,
    adopt_existing: bool = False,
) -> dict[str, Any]:
    validate_hostname_in_zone(output.hostname, output.hosted_zone_name)
    desired = desired_origin_records(origin)
    if (
        output.hostname.rstrip(".").lower() == output.hosted_zone_name.rstrip(".").lower()
        and "CNAME" in desired
    ):
        raise RuntimeError(
            f"Route 53 private hosted-zone apex {output.hostname} cannot publish CNAME; "
            "set the hostname origin to expanded mode"
        )
    if not desired:
        raise RuntimeError(f"Origin {origin.target} has no healthy publishable address")
    client = route53_client(output.credential)
    remote_records = _remote_managed_record_sets(client, output.hosted_zone_id, output.hostname)
    traffic_policy = next((item for item in remote_records if item.get("TrafficPolicyInstanceId")), None)
    if traffic_policy is not None:
        raise Route53TrafficPolicyManaged(
            f"{output.hostname} is managed by Route 53 Traffic Policy instance "
            f"{traffic_policy['TrafficPolicyInstanceId']}; it cannot be changed through ChangeResourceRecordSets"
        )
    if require_adoption and remote_records and not adopt_existing:
        summary = "; ".join(_describe_remote_record(item) for item in remote_records[:8])
        raise Route53AdoptionRequired(
            f"Route 53 records appeared for {output.hostname} before publication: {summary}. "
            "Confirm adoption and retry"
        )
    changes: list[dict[str, Any]] = []
    recreated_types: set[str] = set()
    for remote in remote_records:
        record_type = str(remote.get("Type") or "").upper()
        # A routing-policy or alias RRset cannot be converted to a simple record
        # by a plain UPSERT. Delete the exact live object first, even when its type
        # matches the desired record.
        complex_record = _remote_record_requires_recreate(remote)
        if record_type not in desired or complex_record:
            if record_type in desired:
                recreated_types.add(record_type)
            changes.append(
                {
                    "Action": "DELETE",
                    "ResourceRecordSet": {
                        key: value for key, value in remote.items() if key in _RRSET_CHANGE_KEYS
                    },
                }
            )
    for record_type, new_values in desired.items():
        changes.append(
            {
                # Route 53's documented delete/recreate transaction requires
                # CREATE when the batch already deletes the same RRset identity.
                "Action": "CREATE" if record_type in recreated_types else "UPSERT",
                "ResourceRecordSet": _record_set(output.hostname, record_type, new_values, output.ttl),
            }
        )
    response = client.change_resource_record_sets(
        HostedZoneId=normalize_hosted_zone_id(output.hosted_zone_id),
        ChangeBatch={"Comment": f"cloudflare_dns failover group {output.group_id}", "Changes": changes},
    )
    record_type, values = next(iter(desired.items()))
    output.current_origin_id = origin.id
    output.last_record_type = record_type
    output.last_ttl = output.ttl
    output.last_values_json = json.dumps(values, separators=(",", ":"))
    output.last_published_at = datetime.utcnow()
    output.last_error = None
    output.credential.last_error = None
    return dict(response.get("ChangeInfo") or {})


def route53_output_matches(output: AwsRoute53Output, origin: Origin) -> bool:
    expected = desired_origin_records(origin)
    if (
        output.hostname.rstrip(".").lower() == output.hosted_zone_name.rstrip(".").lower()
        and "CNAME" in expected
    ):
        return False
    if not expected:
        return False
    client = route53_client(output.credential)
    remote_records = _remote_managed_record_sets(client, output.hosted_zone_id, output.hostname)
    if {str(record.get("Type") or "").upper() for record in remote_records} != set(expected):
        return False
    for record_type, expected_values in expected.items():
        records = [record for record in remote_records if str(record.get("Type") or "").upper() == record_type]
        if len(records) != 1:
            return False
        record = records[0]
        if _remote_record_requires_recreate(record):
            return False
        actual = sorted(str(item.get("Value") or "") for item in record.get("ResourceRecords", []))
        if actual != expected_values or int(record.get("TTL") or 0) != output.ttl:
            return False
    return True


def sync_group_route53_outputs(
    db: Session,
    group: FailoverGroup,
    origin: Origin,
    *,
    force_consistency: bool = False,
) -> bool:
    """Publish every enabled binding independently; local selection always wins."""
    changed = False
    for output in group.route53_outputs:
        if not output.enabled:
            continue
        try:
            desired = desired_origin_records(origin)
            desired_type, desired_values = next(iter(desired.items())) if desired else (None, [])
            needs_publish = (
                output.current_origin_id != origin.id
                or output.last_record_type != desired_type
                or output.last_values != desired_values
            )
            if force_consistency and not needs_publish:
                output.last_consistency_check_at = datetime.utcnow()
                needs_publish = not route53_output_matches(output, origin)
            if not needs_publish:
                if force_consistency:
                    output.last_error = None
                    output.credential.last_error = None
                continue
            publish_route53_output(output, origin)
            changed = True
            payload = {
                "provider": "aws_route53",
                "group_id": group.id,
                "output_id": output.id,
                "hostname": output.hostname,
                "origin_id": origin.id,
                "record_type": output.last_record_type,
                "values": output.last_values,
            }
            add_event(db, "route53.published", "info", f"{output.hostname} Route 53 private DNS updated", payload)
            send_webhooks(db, "route53.published", payload)
        except Exception as exc:
            message = str(exc)
            output.last_error = message
            output.credential.last_error = message
            payload = {
                "provider": "aws_route53",
                "group_id": group.id,
                "output_id": output.id,
                "hostname": output.hostname,
                "error": message,
            }
            add_event(db, "route53.publish_failed", "error", f"{output.hostname} Route 53 publish failed: {message}", payload)
            send_webhooks(db, "route53.publish_failed", payload)
    return changed


def reconcile_route53_outputs(db: Session, interval_seconds: int = 300) -> int:
    now = datetime.utcnow()
    outputs = (
        db.query(AwsRoute53Output)
        .options(
            selectinload(AwsRoute53Output.credential),
            selectinload(AwsRoute53Output.group).selectinload(FailoverGroup.origins),
            selectinload(AwsRoute53Output.group).selectinload(FailoverGroup.route53_outputs),
        )
        .filter(AwsRoute53Output.enabled.is_(True))
        .all()
    )
    synced = 0
    for output in outputs:
        if not output.group.enabled or output.group.current_origin_id is None:
            continue
        due = output.last_consistency_check_at is None or (
            now - output.last_consistency_check_at
        ).total_seconds() >= max(interval_seconds, 30)
        if not due:
            continue
        origin = next((item for item in output.group.origins if item.id == output.group.current_origin_id), None)
        if origin is None or not origin.enabled:
            continue
        output.last_consistency_check_at = now
        try:
            if not route53_output_matches(output, origin):
                publish_route53_output(output, origin)
                synced += 1
            else:
                output.last_error = None
                output.credential.last_error = None
        except Exception as exc:
            output.last_error = str(exc)
            output.credential.last_error = str(exc)
    return synced
