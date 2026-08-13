import hashlib
import hmac
import ipaddress
import json
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urljoin

import httpx
from sqlalchemy.orm import Session, selectinload

from .events import add_event
from .models import DohEndpoint, DohFailoverGroup, FailoverGroup, Origin
from .notifier import send_webhooks
from .origin_expansion import (
    is_expanded_origin,
    published_ips,
    resolve_hostname_ips,
    selected_publish_ip,
    set_published_ips,
    set_resolved_ips,
)
from .security import decrypt_secret


_RESOLVER_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="doh-resolver")
_RESOLUTION_CACHE: dict[tuple[str, int], tuple[float, list[str]]] = {}
_RESOLUTION_CACHE_LOCK = threading.Lock()
_RESOLUTION_CACHE_TTL_SECONDS = 30


def resolve_hostname_ips_bounded(hostname: str, timeout_seconds: float) -> list[str]:
    """Resolve without letting libc DNS block the scheduler indefinitely."""
    key = (hostname.rstrip(".").lower(), id(resolve_hostname_ips))
    now = time.monotonic()
    with _RESOLUTION_CACHE_LOCK:
        cached = _RESOLUTION_CACHE.get(key)
        if cached and now - cached[0] < _RESOLUTION_CACHE_TTL_SECONDS:
            return list(cached[1])
    future = _RESOLVER_EXECUTOR.submit(resolve_hostname_ips, hostname)
    try:
        addresses = future.result(timeout=max(float(timeout_seconds), 0.1))
    except FutureTimeoutError as exc:
        future.cancel()
        raise TimeoutError(f"DNS resolution timed out for {hostname}") from exc
    with _RESOLUTION_CACHE_LOCK:
        _RESOLUTION_CACHE[key] = (now, list(addresses))
    return addresses


def _origin_records(origin: Origin, *, resolve_timeout_seconds: float = 3) -> list[tuple[str, str]]:
    if is_expanded_origin(origin):
        value = selected_publish_ip(origin)
        if not value:
            return []
        return [("A" if ipaddress.ip_address(value).version == 4 else "AAAA", value)]
    if origin.target_type == "hostname":
        # Private DoH must be the final source of truth. Returning a CNAME would
        # make the client resolve the target through its (possibly polluted)
        # recursive resolver, so resolve it here and publish address records.
        try:
            addresses = resolve_hostname_ips_bounded(origin.target, resolve_timeout_seconds)
        except Exception:
            # Keep the last successfully published address set. One transient or
            # broken hostname must not blank this name or poison the endpoint.
            addresses = published_ips(origin)
        if not addresses:
            return []
        set_resolved_ips(origin, addresses)
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
    owners: dict[str, tuple[str, int]] = {}
    for group in _endpoint_groups(db, endpoint.id):
        origin = next((item for item in group.origins if item.id == group.current_origin_id), None)
        if origin is None or not origin.enabled:
            continue
        desired_records = _origin_records(origin, resolve_timeout_seconds=min(max(endpoint.timeout_seconds, 1), 5))
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
    independent_groups = (
        db.query(DohFailoverGroup)
        .options(selectinload(DohFailoverGroup.origins))
        .filter(
            DohFailoverGroup.enabled.is_(True),
            DohFailoverGroup.doh_endpoint_id == endpoint.id,
        )
        .order_by(DohFailoverGroup.id)
        .all()
    )
    # Imported lazily to keep the publishing/signing module independent from the
    # scheduler implementation that calls back into sync_doh_endpoint.
    from .doh_failover import origin_records as independent_origin_records

    for group in independent_groups:
        origin = next((item for item in group.origins if item.id == group.current_origin_id), None)
        if origin is None or not origin.enabled:
            continue
        normalized_hostname = group.hostname.rstrip(".").lower()
        previous_owner = owners.get(normalized_hostname)
        owner = ("doh_failover_group", group.id)
        if previous_owner is not None and previous_owner != owner:
            raise ValueError(f"DoH hostname {normalized_hostname} is assigned by {previous_owner} and {owner}")
        owners[normalized_hostname] = owner
        for record_type, value in independent_origin_records(origin):
            records.append(
                {
                    "name": normalized_hostname,
                    "type": record_type,
                    "value": value,
                    "ttl": group.ttl,
                    "doh_failover_group_id": group.id,
                }
            )
    records.sort(
        key=lambda item: (
            item["name"],
            item["type"],
            item.get("group_id", 0),
            item.get("doh_failover_group_id", 0),
        )
    )
    canonical_records = json.dumps(records, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    revision = hashlib.sha256(canonical_records.encode("utf-8")).hexdigest()
    return {"version": 1, "revision": revision, "generated_at": int(time.time()), "records": records}


def _sync_url(endpoint: DohEndpoint) -> str:
    return urljoin(endpoint.base_url.rstrip("/") + "/", endpoint.sync_path.lstrip("/"))


def _remember_successful_legacy_hostname_records(db: Session, payload: dict[str, Any]) -> None:
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
    _remember_successful_legacy_hostname_records(db, payload)
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
    independent = (
        db.query(DohFailoverGroup)
        .filter(
            DohFailoverGroup.enabled.is_(True),
            DohFailoverGroup.doh_endpoint_id == endpoint_id,
            DohFailoverGroup.hostname.in_(wanted),
        )
        .first()
    )
    if independent is not None:
        raise ValueError(f"DoH hostname {independent.hostname} is already assigned to independent DoH group {independent.id}")
