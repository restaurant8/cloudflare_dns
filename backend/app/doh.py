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

from .events import add_event
from .models import DohEndpoint, FailoverGroup, Origin
from .notifier import send_webhooks
from .origin_expansion import is_expanded_origin, resolve_hostname_ips, selected_publish_ip
from .security import decrypt_secret


def _origin_records(origin: Origin) -> list[tuple[str, str]]:
    if is_expanded_origin(origin):
        value = selected_publish_ip(origin)
        if not value:
            return []
        return [("A" if ipaddress.ip_address(value).version == 4 else "AAAA", value)]
    if origin.target_type == "hostname":
        # Private DoH must be the final source of truth. Returning a CNAME would
        # make the client resolve the target through its (possibly polluted)
        # recursive resolver, so resolve it here and publish address records.
        addresses = resolve_hostname_ips(origin.target)
        if not addresses:
            raise ValueError(f"DoH origin hostname {origin.target} resolved to no addresses")
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


def build_doh_snapshot(db: Session, endpoint: DohEndpoint) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    owners: dict[str, int] = {}
    for group in _endpoint_groups(db, endpoint.id):
        origin = next((item for item in group.origins if item.id == group.current_origin_id), None)
        if origin is None or not origin.enabled:
            continue
        desired_records = _origin_records(origin)
        if not desired_records:
            continue
        hostnames = group_doh_hostnames(group)
        for hostname in hostnames:
            normalized_hostname = hostname.rstrip(".").lower()
            previous_group_id = owners.get(normalized_hostname)
            if previous_group_id is not None and previous_group_id != group.id:
                raise ValueError(
                    f"DoH hostname {normalized_hostname} is assigned by groups "
                    f"{previous_group_id} and {group.id}"
                )
            owners[normalized_hostname] = group.id
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
    records.sort(key=lambda item: (item["name"], item["type"], item["group_id"]))
    canonical_records = json.dumps(records, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    revision = hashlib.sha256(canonical_records.encode("utf-8")).hexdigest()
    return {"version": 1, "revision": revision, "generated_at": int(time.time()), "records": records}


def _sync_url(endpoint: DohEndpoint) -> str:
    return urljoin(endpoint.base_url.rstrip("/") + "/", endpoint.sync_path.lstrip("/"))


def sync_doh_endpoint(db: Session, endpoint: DohEndpoint, *, force: bool = False) -> bool:
    if not endpoint.enabled:
        return False
    previous_revision = endpoint.last_revision
    previous_error = endpoint.last_error
    try:
        payload = build_doh_snapshot(db, endpoint)
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
        if changed:
            data = {"endpoint_id": endpoint.id, "name": endpoint.name, "error": message}
            add_event(db, "doh.sync_failed", "error", f"DoH endpoint {endpoint.name} sync failed: {message}", data)
            send_webhooks(db, "doh.sync_failed", data)
        return False

    endpoint.last_revision = payload["revision"]
    endpoint.last_error = None
    endpoint.last_synced_at = datetime.utcnow()
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
        # Snapshot construction is local and cheap. Run it every scheduler tick so
        # a resource whose IP changed without changing origin_id is pushed
        # immediately. Identical revisions cause no network request; ``force`` is
        # reserved for periodic reconciliation and retrying errors.
        synced += int(sync_doh_endpoint(db, endpoint, force=bool(endpoint.last_error) or due))
    return synced


def sync_group_doh_endpoint(db: Session, group: FailoverGroup) -> bool:
    if not group.doh_enabled or not group.doh_endpoint_id:
        return False
    endpoint = db.get(DohEndpoint, group.doh_endpoint_id)
    if endpoint is None or not endpoint.enabled:
        return False
    db.flush()
    return sync_doh_endpoint(db, endpoint, force=True)


def validate_doh_hostname_conflicts(
    db: Session,
    *,
    endpoint_id: int,
    hostnames: list[str],
    exclude_group_id: int | None = None,
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
