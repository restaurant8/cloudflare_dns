import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urljoin

import httpx
from sqlalchemy.orm import Session, selectinload

from .dns_resolution import resolve_hostname_ips_bounded
from .events import add_event
from .models import AwsRoute53Output, DohEndpoint, FailoverGroup, Origin
from .notifier import send_webhooks
from .origin_expansion import (
    is_expanded_origin,
    published_ips,
    resolved_ips,
    selected_publish_ip,
    set_published_ips,
    set_resolved_ips,
)
from .security import decrypt_secret


def _origin_records(origin: Origin, *, resolved_override: list[str] | None = None) -> list[tuple[str, str]]:
    if is_expanded_origin(origin):
        value = selected_publish_ip(origin)
        if not value:
            return []
        return [("A" if ipaddress.ip_address(value).version == 4 else "AAAA", value)]
    if origin.target_type == "hostname":
        # Private DoH must be the final source of truth. Returning a CNAME would
        # make the client resolve the target through its (possibly polluted)
        # recursive resolver, so resolve it here and publish address records.
        # Snapshot construction is deliberately pure. Resolution belongs to the
        # preparation phase of an actual sync, never to GET /snapshot.
        addresses = resolved_override if resolved_override is not None else published_ips(origin)
        if not addresses:
            return []
        return [
            ("A" if ipaddress.ip_address(value).version == 4 else "AAAA", value)
            for value in addresses
        ]
    value = str(ipaddress.ip_address(origin.target))
    return [("A" if ipaddress.ip_address(value).version == 4 else "AAAA", value)]


def group_doh_hostnames(group: FailoverGroup) -> list[str]:
    configured = group.doh_hostnames
    if configured:
        return configured
    migrated = [entry.hostname for entry in group.hostnames]
    return migrated or [group.hostname]


def _endpoint_groups(db: Session, endpoint_id: int) -> list[FailoverGroup]:
    return (
        db.query(FailoverGroup)
        .options(selectinload(FailoverGroup.origins), selectinload(FailoverGroup.hostnames))
        .filter(
            FailoverGroup.enabled.is_(True),
            FailoverGroup.doh_enabled.is_(True),
            FailoverGroup.doh_endpoint_id == endpoint_id,
        )
        .order_by(FailoverGroup.id)
        .all()
    )


def build_doh_snapshot(
    db: Session,
    endpoint: DohEndpoint,
    *,
    legacy_hostname_values: dict[int, list[str]] | None = None,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    owners: dict[str, tuple[str, int]] = {}
    for group in _endpoint_groups(db, endpoint.id):
        origin = next((item for item in group.origins if item.id == group.current_origin_id), None)
        if origin is None or not origin.enabled:
            continue
        override = (legacy_hostname_values or {}).get(origin.id)
        desired_records = _origin_records(origin, resolved_override=override)
        if not desired_records:
            continue
        hostnames = group_doh_hostnames(group)
        for hostname in hostnames:
            normalized_hostname = hostname.rstrip(".").lower()
            previous_owner = owners.get(normalized_hostname)
            owner = ("cloudflare_group", group.id)
            if previous_owner is not None and previous_owner != owner:
                raise ValueError(
                    f"DoH hostname {normalized_hostname} is assigned by groups "
                    f"{previous_owner} and {owner}"
                )
            owners[normalized_hostname] = owner
            for record_type, value in desired_records:
                records.append(
                    {
                        "name": normalized_hostname,
                        "type": record_type,
                        "value": value,
                        "ttl": group.ttl,
                        "group_id": group.id,
                    }
                )
    route53_outputs = (
        db.query(AwsRoute53Output)
        .join(AwsRoute53Output.group)
        .filter(
            AwsRoute53Output.enabled.is_(True),
            AwsRoute53Output.doh_endpoint_id == endpoint.id,
            FailoverGroup.enabled.is_(True),
        )
        .order_by(AwsRoute53Output.id)
        .all()
    )
    for output in route53_outputs:
        normalized_hostname = output.hostname.rstrip(".").lower()
        previous_owner = owners.get(normalized_hostname)
        owner = ("route53_output", output.id)
        if previous_owner is not None and previous_owner != owner:
            raise ValueError(f"DoH hostname {normalized_hostname} is assigned by {previous_owner} and {owner}")
        owners[normalized_hostname] = owner
        # Resolver-backed records are allowlist entries, not authoritative data.
        # The EC2 service forwards matching questions to the VPC Resolver, where
        # the Route 53 private hosted zone is the source of truth.
        records.append(
            {
                "name": normalized_hostname,
                "type": "A",
                "value": "0.0.0.0",
                "ttl": output.ttl,
                "route53_output_id": output.id,
                "source": "vpc_resolver",
            }
        )
    records.sort(
        key=lambda item: (
            item["name"],
            item["type"],
            item.get("group_id", 0),
            item.get("route53_output_id", 0),
            item.get("source", ""),
        )
    )
    canonical_records = json.dumps(records, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    revision = hashlib.sha256(canonical_records.encode("utf-8")).hexdigest()
    # Version 1 servers treat every entry as authoritative data. A resolver-backed
    # marker would therefore become a successful 0.0.0.0 answer during a rolling
    # upgrade. Version 2 makes old EC2 services reject the snapshot and retain
    # their previous known-good configuration instead.
    version = 2 if route53_outputs else 1
    return {"version": version, "revision": revision, "generated_at": int(time.time()), "records": records}


def _sync_url(endpoint: DohEndpoint) -> str:
    return urljoin(endpoint.base_url.rstrip("/") + "/", endpoint.sync_path.lstrip("/"))


def _resolve_legacy_hostname_values(db: Session, endpoint: DohEndpoint) -> dict[int, list[str]]:
    values: dict[int, list[str]] = {}
    timeout = min(max(endpoint.timeout_seconds, 1), 5)
    for group in _endpoint_groups(db, endpoint.id):
        origin = next((item for item in group.origins if item.id == group.current_origin_id), None)
        if origin is None or not origin.enabled or origin.target_type != "hostname" or is_expanded_origin(origin):
            continue
        try:
            addresses = resolve_hostname_ips_bounded(origin.target, timeout)
        except Exception:
            # A broken legacy rule keeps its persisted last-known-good values and
            # cannot prevent unrelated records on the endpoint from syncing.
            continue
        if addresses:
            values[origin.id] = addresses
    return values


def _remember_successful_legacy_hostname_records(
    db: Session,
    payload: dict[str, Any],
    resolved_values: dict[int, list[str]],
) -> None:
    values_by_group: dict[int, list[str]] = {}
    for record in payload.get("records", []):
        group_id = record.get("group_id")
        if group_id is not None:
            values_by_group.setdefault(int(group_id), []).append(str(record["value"]))
    if not values_by_group:
        return
    groups = (
        db.query(FailoverGroup)
        .options(selectinload(FailoverGroup.origins))
        .filter(FailoverGroup.id.in_(values_by_group))
        .all()
    )
    for group in groups:
        origin = next((item for item in group.origins if item.id == group.current_origin_id), None)
        if origin is not None and origin.target_type == "hostname" and not is_expanded_origin(origin):
            if origin.id in resolved_values:
                set_resolved_ips(origin, resolved_values[origin.id])
            set_published_ips(origin, values_by_group[group.id])


def sync_doh_endpoint(
    db: Session,
    endpoint: DohEndpoint,
    *,
    force: bool = False,
    ignore_backoff: bool = False,
) -> bool:
    if not endpoint.enabled:
        return False
    now = datetime.utcnow()
    if not ignore_backoff and endpoint.next_sync_retry_at and endpoint.next_sync_retry_at > now:
        return False
    previous_revision = endpoint.last_revision
    previous_error = endpoint.last_error
    resolved_values: dict[int, list[str]] = {}
    try:
        resolved_values = _resolve_legacy_hostname_values(db, endpoint)
        payload = build_doh_snapshot(db, endpoint, legacy_hostname_values=resolved_values)
        if not force and endpoint.last_revision == payload["revision"] and endpoint.last_error is None:
            return False
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        signed = timestamp.encode("ascii") + b"\n" + nonce.encode("ascii") + b"\n" + body
        signature = hmac.new(
            decrypt_secret(endpoint.hmac_secret_encrypted).encode("utf-8"),
            signed,
            hashlib.sha256,
        ).hexdigest()
        response = httpx.post(
            _sync_url(endpoint),
            content=body,
            headers={
                "content-type": "application/json",
                "x-doh-timestamp": timestamp,
                "x-doh-nonce": nonce,
                "x-doh-signature": signature,
                "x-doh-revision": payload["revision"],
            },
            timeout=max(endpoint.timeout_seconds, 1),
            verify=endpoint.verify_tls,
        )
        response.raise_for_status()
    except Exception as exc:
        message = str(exc)
        changed = endpoint.last_error != message
        endpoint.last_error = message
        endpoint.sync_failure_count = int(endpoint.sync_failure_count or 0) + 1
        delay_seconds = min(600, 30 * (2 ** min(endpoint.sync_failure_count - 1, 5)))
        endpoint.next_sync_retry_at = now + timedelta(seconds=delay_seconds)
        if changed:
            data = {"endpoint_id": endpoint.id, "name": endpoint.name, "error": message}
            add_event(db, "doh.sync_failed", "error", f"DoH endpoint {endpoint.name} sync failed: {message}", data)
            send_webhooks(db, "doh.sync_failed", data)
        return False

    endpoint.last_revision = payload["revision"]
    endpoint.last_error = None
    endpoint.last_synced_at = now
    endpoint.sync_failure_count = 0
    endpoint.next_sync_retry_at = None
    _remember_successful_legacy_hostname_records(db, payload, resolved_values)
    if previous_revision != payload["revision"] or previous_error:
        data = {
            "endpoint_id": endpoint.id,
            "name": endpoint.name,
            "revision": payload["revision"],
            "record_count": len(payload["records"]),
        }
        add_event(db, "doh.synced", "info", f"DoH endpoint {endpoint.name} synced {len(payload['records'])} records", data)
    return True


def sync_due_doh_endpoints(db: Session) -> int:
    now = datetime.utcnow()
    synced = 0
    endpoints = db.query(DohEndpoint).filter(DohEndpoint.enabled.is_(True)).all()
    for endpoint in endpoints:
        interval = max(endpoint.sync_interval_seconds, 30)
        due = endpoint.last_synced_at is None or endpoint.last_synced_at <= now - timedelta(seconds=interval)
        # Snapshot construction uses persisted last-known-good values for independent
        # rules. Legacy hostname resolution is bounded and also retains its last
        # published addresses. Identical revisions cause no network request.
        synced += int(sync_doh_endpoint(db, endpoint, force=bool(endpoint.last_error) or due))
    return synced


def sync_group_doh_endpoint(db: Session, group: FailoverGroup) -> bool:
    if not group.doh_enabled or not group.doh_endpoint_id:
        return False
    endpoint = db.get(DohEndpoint, group.doh_endpoint_id)
    if endpoint is None or not endpoint.enabled:
        return False
    db.flush()
    return sync_doh_endpoint(db, endpoint, force=True, ignore_backoff=True)


def validate_doh_hostname_conflicts(
    db: Session,
    *,
    endpoint_id: int,
    hostnames: list[str],
    exclude_group_id: int | None = None,
    exclude_route53_output_id: int | None = None,
) -> None:
    query = (
        db.query(FailoverGroup)
        .options(selectinload(FailoverGroup.hostnames))
        .filter(FailoverGroup.doh_enabled.is_(True), FailoverGroup.doh_endpoint_id == endpoint_id)
    )
    if exclude_group_id is not None:
        query = query.filter(FailoverGroup.id != exclude_group_id)
    wanted = {item.rstrip(".").lower() for item in hostnames}
    for other in query.all():
        overlap = wanted.intersection(item.rstrip(".").lower() for item in group_doh_hostnames(other))
        if overlap:
            hostname = sorted(overlap)[0]
            raise ValueError(f"DoH hostname {hostname} is already assigned to group {other.id}")
    route53_query = db.query(AwsRoute53Output).filter(
        AwsRoute53Output.enabled.is_(True),
        AwsRoute53Output.doh_endpoint_id == endpoint_id,
        AwsRoute53Output.hostname.in_(wanted),
    )
    if exclude_route53_output_id is not None:
        route53_query = route53_query.filter(AwsRoute53Output.id != exclude_route53_output_id)
    route53 = route53_query.first()
    if route53 is not None:
        raise ValueError(f"DoH hostname {route53.hostname} is already assigned to Route 53 output {route53.id}")
