import logging
from datetime import datetime

from sqlalchemy.orm import Session, selectinload

from .cloudflare import CloudflareClient, CloudflareError
from .dns_utils import record_type_for_target_type
from .events import add_event
from .health import FINAL_ORIGIN_STATUSES, ORIGIN_AVAILABLE_STATUS, PROBE_MODE_CHINA_ONLY, origin_probe_mode, run_local_checks
from .integrations import trigger_ip_change_for_origin
from .models import DnsRecord, FailoverGroup, FailoverHostname, Origin, Zone
from .notifier import send_webhooks
from .origin_expansion import (
    DIRECT_PUBLISH_MODE,
    is_expanded_origin,
    published_ips,
    record_type_for_ip,
    selected_healthy_ip,
    set_published_ips,
)
from .runtime_settings import get_runtime_settings
from .security import decrypt_secret
from .sync import MANAGED_RECORD_TYPES, sync_zone_records


logger = logging.getLogger(__name__)

MANAGED_RECORD_COMMENT_PREFIX = "managed by cloudflare-dns-failover"
NO_HEALTHY_ORIGIN_MESSAGE = "没有可用的健康源站"
WAITING_FOR_PROBES_MESSAGE = "等待源站探测结果"
RECOVERABLE_GROUP_ERRORS = {NO_HEALTHY_ORIGIN_MESSAGE, WAITING_FOR_PROBES_MESSAGE}


class DnsPublishError(ValueError):
    def __init__(self, hostname: str, message: str):
        super().__init__(message)
        self.hostname = hostname


def choose_desired_origin(origins: list[Origin], current_origin_id: int | None = None) -> Origin | None:
    healthy = [origin for origin in origins if origin.enabled and origin.status == ORIGIN_AVAILABLE_STATUS]
    if not healthy:
        return None
    best_priority = min(origin.priority for origin in healthy)
    current = next((origin for origin in healthy if origin.id == current_origin_id), None)
    if current is not None and current.priority <= best_priority:
        return current
    candidates = [origin for origin in healthy if origin.priority == best_priority]
    return sorted(candidates, key=lambda item: item.id)[0]


def _current_origin(group: FailoverGroup) -> Origin | None:
    return next((origin for origin in group.origins if origin.id == group.current_origin_id), None)


def _should_probe_group_before_switch(group: FailoverGroup) -> bool:
    current = _current_origin(group)
    return current is None or not current.enabled or current.status != ORIGIN_AVAILABLE_STATUS


def _origin_status_summaries(group: FailoverGroup) -> list[dict]:
    return [
        {
            "origin_id": origin.id,
            "target": origin.target,
            "port": origin.port,
            "status": origin.status,
            "last_checked_at": origin.last_checked_at.isoformat() if origin.last_checked_at else None,
            "last_error": origin.last_error,
        }
        for origin in sorted(group.origins, key=lambda item: (item.priority, item.id))
    ]


def _has_pending_origin_checks(group: FailoverGroup) -> bool:
    return any(origin.enabled and origin.status not in FINAL_ORIGIN_STATUSES for origin in group.origins)


def _should_notify_no_healthy(group: FailoverGroup, now: datetime, interval_seconds: int) -> bool:
    interval = max(interval_seconds, 60)
    if group.no_healthy_notified_at is None:
        return True
    return (now - group.no_healthy_notified_at).total_seconds() >= interval


def _normalized_record_name(value: str | None) -> str:
    return str(value or "").rstrip(".").lower()


def _managed_dns_records(client: CloudflareClient, cf_zone_id: str, hostname: str | None = None) -> list[dict]:
    if hostname is None:
        return [
            record
            for record in client.list_dns_records(cf_zone_id)
            if record.get("type") in MANAGED_RECORD_TYPES
        ]
    # Query by name first: listing the whole zone on every consistency check is
    # 10x+ the API calls on large zones. Fall back to a full listing only when the
    # name filter finds nothing (e.g. trailing-dot/case mismatches).
    normalized_hostname = _normalized_record_name(hostname)
    named = [
        record
        for record in client.list_dns_records(cf_zone_id, name=hostname)
        if record.get("type") in MANAGED_RECORD_TYPES
    ]
    if named:
        return named
    return [
        record
        for record in client.list_dns_records(cf_zone_id)
        if record.get("type") in MANAGED_RECORD_TYPES
        and _normalized_record_name(record.get("name")) == normalized_hostname
    ]


def find_managed_dns_record_by_id(client: CloudflareClient, cf_zone_id: str, record_id: str) -> dict | None:
    return next(
        (record for record in _managed_dns_records(client, cf_zone_id) if record.get("id") == record_id),
        None,
    )


def validate_group_hostname_records(
    client: CloudflareClient,
    cf_zone_id: str,
    hostname: str,
    current_record_id: str | None = None,
) -> str | None:
    records = _managed_dns_records(client, cf_zone_id, hostname)
    if not records:
        if current_record_id:
            record = find_managed_dns_record_by_id(client, cf_zone_id, current_record_id)
            if record is None:
                raise ValueError("未找到要接管的 A/AAAA/CNAME 记录，请重新从解析记录点管理")
            record_name = _normalized_record_name(record.get("name"))
            if record_name != _normalized_record_name(hostname):
                raise ValueError(f"接管记录属于 {record.get('name') or '-'}，不是 {hostname}，请重新从解析记录点管理")
            if record.get("proxied"):
                raise ValueError("仅支持 DNS-only 记录，请先关闭 Cloudflare 代理")
            return record["id"]
        return None
    if len(records) > 1:
        raise ValueError("该主机名存在多个 A/AAAA/CNAME 记录，启用故障切换前必须先清理为唯一记录")
    record = records[0]
    if record.get("proxied"):
        raise ValueError("仅支持 DNS-only 记录，请先关闭 Cloudflare 代理")
    if current_record_id and record["id"] != current_record_id:
        adopted = find_managed_dns_record_by_id(client, cf_zone_id, current_record_id)
        if adopted is None:
            raise ValueError("未找到要接管的 A/AAAA/CNAME 记录，请重新从解析记录点管理")
        raise ValueError(f"接管记录属于 {adopted.get('name') or '-'}，不是 {hostname}，请重新从解析记录点管理")
    return record["id"]


def ensure_group_hostname_entries(db: Session, group: FailoverGroup) -> list[FailoverHostname]:
    if group.hostnames:
        return sorted(group.hostnames, key=lambda item: (item.hostname != group.hostname, item.id))
    entry = FailoverHostname(group_id=group.id, hostname=group.hostname, current_record_id=group.current_record_id)
    db.add(entry)
    db.flush()
    group.hostnames.append(entry)
    return [entry]


def _record_ids(hostname_entry: FailoverHostname) -> set[str]:
    if not hostname_entry.current_record_id:
        return set()
    return {item.strip() for item in hostname_entry.current_record_id.split(",") if item.strip()}


def _store_record_ids(group: FailoverGroup, hostname_entry: FailoverHostname, record_ids: list[str]) -> None:
    hostname_entry.current_record_id = ",".join(record_ids) if record_ids else None
    if hostname_entry.hostname == group.hostname:
        group.current_record_id = hostname_entry.current_record_id


def _record_is_owned_by_app(record: dict) -> bool:
    return str(record.get("comment") or "").startswith(MANAGED_RECORD_COMMENT_PREFIX)


def _record_label(record: dict) -> str:
    proxy_state = "已代理" if record.get("proxied") else "仅 DNS"
    return f"{record.get('type')} {record.get('content')}（{proxy_state}，ID {record.get('id')}）"


def _normalize_dns_content(record_type: str, value: str | None) -> str:
    content = str(value or "").strip()
    if record_type == "CNAME":
        return content.rstrip(".").lower()
    return content


def _desired_record_for_origin(origin: Origin) -> tuple[str, str] | None:
    if is_expanded_origin(origin):
        selected_ip = selected_healthy_ip(origin)
        if not selected_ip:
            return None
        return record_type_for_ip(selected_ip), selected_ip
    return record_type_for_target_type(origin.target_type), origin.target


def _record_matches(record: dict, record_type: str, content: str) -> bool:
    return (
        record.get("type") == record_type
        and not record.get("proxied")
        and _normalize_dns_content(record_type, record.get("content")) == _normalize_dns_content(record_type, content)
    )


def _record_has_same_identity(record: dict, record_type: str, content: str) -> bool:
    return record.get("type") == record_type and _normalize_dns_content(record_type, record.get("content")) == _normalize_dns_content(record_type, content)


def _is_identical_record_error(exc: CloudflareError) -> bool:
    return "identical record already exists" in str(exc).lower()


def zone_for_hostname(db: Session, group: FailoverGroup, hostname_entry: FailoverHostname) -> Zone:
    """Resolve the Cloudflare zone a hostname entry should be published into.

    A null ``zone_id`` keeps the legacy behaviour of using the group's own zone,
    so existing single-zone groups are unaffected.
    """
    if hostname_entry.zone_id:
        zone = db.get(Zone, hostname_entry.zone_id)
        if zone is not None:
            return zone
    return group.zone


def _client_for_zone(zone: Zone) -> CloudflareClient:
    return CloudflareClient(decrypt_secret(zone.credential.token_encrypted))


def _create_dns_record_or_adopt(
    client: CloudflareClient,
    cf_zone_id: str,
    hostname_entry: FailoverHostname,
    body: dict,
) -> dict:
    try:
        return client.create_dns_record(cf_zone_id, body)
    except CloudflareError as exc:
        if not _is_identical_record_error(exc):
            raise
        for record in _same_name_records(client, cf_zone_id, hostname_entry):
            if _record_has_same_identity(record, body["type"], body["content"]):
                if _record_matches(record, body["type"], body["content"]):
                    return record
                return client.update_dns_record(cf_zone_id, record["id"], body)
        raise


def _publish_one_hostname_record(
    client: CloudflareClient,
    cf_zone_id: str,
    hostname_entry: FailoverHostname,
    managed_records: list[dict],
    body: dict,
) -> dict:
    if body["type"] == "CNAME" and len(managed_records) > 1:
        for extra_record in managed_records[1:]:
            client.delete_dns_record(cf_zone_id, extra_record["id"])
        managed_records = managed_records[:1]

    same_record = next(
        (record for record in managed_records if _record_has_same_identity(record, body["type"], body["content"])),
        None,
    )
    target_record = same_record or (managed_records[0] if managed_records else None)
    if target_record:
        try:
            record = client.update_dns_record(cf_zone_id, target_record["id"], body)
        except CloudflareError as exc:
            if _is_identical_record_error(exc):
                record = _create_dns_record_or_adopt(client, cf_zone_id, hostname_entry, body)
            else:
                client.delete_dns_record(cf_zone_id, target_record["id"])
                record = _create_dns_record_or_adopt(client, cf_zone_id, hostname_entry, body)
    else:
        record = _create_dns_record_or_adopt(client, cf_zone_id, hostname_entry, body)

    for extra_record in managed_records:
        if extra_record["id"] != record["id"]:
            client.delete_dns_record(cf_zone_id, extra_record["id"])
    return record


def current_dns_matches_origin(db: Session, group: FailoverGroup, origin: Origin) -> bool:
    desired = _desired_record_for_origin(origin)
    if desired is None:
        return True
    record_type, content = desired
    for hostname_entry in ensure_group_hostname_entries(db, group):
        managed_ids = _record_ids(hostname_entry)
        if not managed_ids:
            return False
        zone = zone_for_hostname(db, group, hostname_entry)
        client = _client_for_zone(zone)
        records = _same_name_records(client, zone.cf_zone_id, hostname_entry)
        managed_records = [record for record in records if record.get("id") in managed_ids]
        if len(managed_records) != len(managed_ids):
            return False
        if len(managed_records) != 1:
            return False
        if not _record_matches(managed_records[0], record_type, content):
            return False
    return True


def _same_name_records(client: CloudflareClient, cf_zone_id: str, hostname_entry: FailoverHostname) -> list[dict]:
    return _managed_dns_records(client, cf_zone_id, hostname_entry.hostname)


def _validate_same_name_records(group: FailoverGroup, hostname_entry: FailoverHostname, records: list[dict]) -> list[dict]:
    managed_ids = _record_ids(hostname_entry)
    if managed_ids:
        managed_records = [record for record in records if record["id"] in managed_ids]
        orphaned_app_records = [record for record in records if record["id"] not in managed_ids and _record_is_owned_by_app(record)]
        conflicts = [record for record in records if record["id"] not in managed_ids and not _record_is_owned_by_app(record)]
        if conflicts:
            details = "；".join(_record_label(record) for record in conflicts)
            raise ValueError(f"{hostname_entry.hostname} 存在未托管的 A/AAAA/CNAME 冲突记录：{details}")
        if orphaned_app_records:
            managed_records.extend(orphaned_app_records)
            _store_record_ids(group, hostname_entry, [record["id"] for record in managed_records])
        return managed_records
    if len(records) > 1:
        raise ValueError(f"{hostname_entry.hostname} 存在多个 A/AAAA/CNAME 记录，启用故障切换前必须先清理为唯一记录")
    if records and records[0].get("proxied"):
        raise ValueError(f"{hostname_entry.hostname} 仅支持 DNS-only 记录，请先关闭 Cloudflare 代理")
    return records


def publish_origin(
    db: Session,
    group: FailoverGroup,
    origin: Origin,
    hostname_entries: list[FailoverHostname] | None = None,
) -> dict:
    if is_expanded_origin(origin):
        return publish_expanded_origin(db, group, origin, hostname_entries=hostname_entries)

    record_type = record_type_for_target_type(origin.target_type)

    target_hostnames = hostname_entries if hostname_entries is not None else ensure_group_hostname_entries(db, group)
    managed_by_hostname = []
    for hostname_entry in target_hostnames:
        try:
            if record_type == "CNAME" and origin.target.rstrip(".").lower() == hostname_entry.hostname.rstrip(".").lower():
                raise ValueError(f"CNAME 目标不能和当前主机名相同：{hostname_entry.hostname}")
            zone = zone_for_hostname(db, group, hostname_entry)
            client = _client_for_zone(zone)
            managed_records = _validate_same_name_records(
                group, hostname_entry, _same_name_records(client, zone.cf_zone_id, hostname_entry)
            )
            managed_by_hostname.append((hostname_entry, zone, client, managed_records))
        except Exception as exc:
            raise DnsPublishError(hostname_entry.hostname, str(exc)) from exc

    published_records = []
    touched_zones: dict[int, tuple[Zone, CloudflareClient]] = {}
    for hostname_entry, zone, client, managed_records in managed_by_hostname:
        body = {
            "type": record_type,
            "name": hostname_entry.hostname,
            "content": origin.target,
            "ttl": group.ttl,
            "proxied": False,
            "comment": MANAGED_RECORD_COMMENT_PREFIX,
        }

        try:
            record = _publish_one_hostname_record(client, zone.cf_zone_id, hostname_entry, managed_records, body)
        except Exception as exc:
            raise DnsPublishError(hostname_entry.hostname, str(exc)) from exc

        _store_record_ids(group, hostname_entry, [record["id"]])
        published_records.append(record)
        touched_zones[zone.id] = (zone, client)
        local_record = (
            db.query(DnsRecord)
            .filter(DnsRecord.zone_id == zone.id, DnsRecord.cf_record_id == record["id"])
            .one_or_none()
        )
        if local_record:
            local_record.type = record_type
            local_record.content = origin.target
            local_record.ttl = group.ttl
            local_record.proxied = False
    origin.publish_mode = DIRECT_PUBLISH_MODE
    set_published_ips(origin, [])
    for zone, client in touched_zones.values():
        sync_zone_records(db, zone.credential, zone, client=client)
    return {
        "id": ",".join(record["id"] for record in published_records),
        "type": record_type,
        "content": origin.target,
        "hostnames": [record.get("name") for record in published_records],
    }


def publish_expanded_origin(
    db: Session,
    group: FailoverGroup,
    origin: Origin,
    hostname_entries: list[FailoverHostname] | None = None,
) -> dict:
    if origin.target_type != "hostname":
        raise ValueError("只有域名目标可以展开发布为 IP 池")
    selected_ip = selected_healthy_ip(origin)
    if not selected_ip:
        raise ValueError("展开域名当前没有健康 IP，无法发布")

    target_hostnames = hostname_entries if hostname_entries is not None else ensure_group_hostname_entries(db, group)
    managed_by_hostname = []
    for hostname_entry in target_hostnames:
        try:
            zone = zone_for_hostname(db, group, hostname_entry)
            client = _client_for_zone(zone)
            managed_records = _validate_same_name_records(
                group, hostname_entry, _same_name_records(client, zone.cf_zone_id, hostname_entry)
            )
            managed_by_hostname.append((hostname_entry, zone, client, managed_records))
        except Exception as exc:
            raise DnsPublishError(hostname_entry.hostname, str(exc)) from exc

    created_records = []
    touched_zones: dict[int, tuple[Zone, CloudflareClient]] = {}
    for hostname_entry, zone, client, managed_records in managed_by_hostname:
        body = {
            "type": record_type_for_ip(selected_ip),
            "name": hostname_entry.hostname,
            "content": selected_ip,
            "ttl": group.ttl,
            "proxied": False,
            "comment": f"{MANAGED_RECORD_COMMENT_PREFIX} expanded from {origin.target}",
        }
        try:
            hostname_records = [_publish_one_hostname_record(client, zone.cf_zone_id, hostname_entry, managed_records, body)]
        except Exception as exc:
            raise DnsPublishError(hostname_entry.hostname, str(exc)) from exc
        created_records.extend(hostname_records)
        _store_record_ids(group, hostname_entry, [record["id"] for record in hostname_records])
        touched_zones[zone.id] = (zone, client)

    set_published_ips(origin, [selected_ip])
    for zone, client in touched_zones.values():
        sync_zone_records(db, zone.credential, zone, client=client)
    return {
        "id": ",".join(record["id"] for record in created_records),
        "type": record_type_for_ip(selected_ip),
        "content": selected_ip,
        "hostnames": sorted({str(record.get("name")) for record in created_records}),
    }


# In-memory timestamps of the last successful DNS consistency verification per
# group. Only used to throttle the steady-state Cloudflare API polling; losing it
# on restart just means one extra check.
_consistency_checked_at: dict[int, datetime] = {}


def evaluate_failover_groups(
    db: Session,
    commit_per_group: bool = False,
    consistency_check_interval_seconds: int = 0,
) -> int:
    """Evaluate all enabled groups and publish DNS changes where needed.

    ``commit_per_group`` commits after each group so external side effects
    (Cloudflare writes, azpanel IP changes) stay recorded even if a later group
    fails — used by the scheduler. ``consistency_check_interval_seconds`` throttles
    the steady-state Cloudflare drift check (0 = check every call).
    """
    groups = (
        db.query(FailoverGroup)
        .options(
            selectinload(FailoverGroup.origins),
            selectinload(FailoverGroup.hostnames).selectinload(FailoverHostname.zone),
            selectinload(FailoverGroup.zone),
        )
        .filter(FailoverGroup.enabled.is_(True))
        .all()
    )
    switches = 0
    now = datetime.utcnow()
    settings = get_runtime_settings(db)
    for group in groups:
        try:
            switched = _evaluate_single_group(db, group, now, settings, consistency_check_interval_seconds)
        except Exception:
            # One broken group (bad credential, unexpected API shape…) must not stop
            # failover for every other group in this tick.
            logger.exception("failover evaluation failed for group %s (%s)", group.id, group.hostname)
            db.rollback()
            continue
        if switched:
            switches += 1
        if commit_per_group:
            db.commit()
    return switches


def _evaluate_single_group(
    db: Session,
    group: FailoverGroup,
    now: datetime,
    settings,
    consistency_check_interval_seconds: int,
) -> bool:
    if _should_probe_group_before_switch(group):
        run_local_checks(db, group_id=group.id, include_all=False)

    # Trigger an automatic IP change for every blocked origin in the group, not
    # just the currently published one. Otherwise an origin that gets blocked and
    # then failed away from would never have its IP replaced, because it is no
    # longer the "current" origin on subsequent cycles. Each attempt is still gated
    # by the resource's auto_change_on_blocked flag and cooldown.
    # Only a GFW block is fixable by rotating the IP: a machine that is down stays
    # down on a new IP, so machine_down/unhealthy do NOT trigger a change. The one
    # exception is probe_mode=china_only, which has no foreign probes to tell the
    # two apart and reports a suspected block as "unhealthy".
    for group_origin in group.origins:
        if not group_origin.enabled:
            continue
        suspected_block = group_origin.status == "blocked" or (
            group_origin.status == "unhealthy" and origin_probe_mode(group_origin) == PROBE_MODE_CHINA_ONLY
        )
        if suspected_block:
            trigger_ip_change_for_origin(db, group_origin, f"{group.hostname} origin {group_origin.target} is {group_origin.status}")

    desired = choose_desired_origin(group.origins, group.current_origin_id)
    if desired is None:
        if _has_pending_origin_checks(group):
            group.last_error = WAITING_FOR_PROBES_MESSAGE
            return False
        group.last_error = NO_HEALTHY_ORIGIN_MESSAGE
        if _should_notify_no_healthy(group, now, settings.no_healthy_notification_interval_seconds):
            group.no_healthy_notified_at = now
            payload = {"group_id": group.id, "hostname": group.hostname, "origins": _origin_status_summaries(group)}
            add_event(db, "failover.no_healthy_origin", "error", f"{group.hostname} 没有可用的健康源站", payload)
            send_webhooks(db, "failover.no_healthy_origin", payload)
        return False
    group.no_healthy_notified_at = None
    if group.last_error in RECOVERABLE_GROUP_ERRORS:
        group.last_error = None
    if desired.id == group.current_origin_id and not group.last_error:
        desired_expanded_ip = selected_healthy_ip(desired)
        expanded_metadata_mismatch = is_expanded_origin(desired) and published_ips(desired) != ([desired_expanded_ip] if desired_expanded_ip else [])
        checked_at = _consistency_checked_at.get(group.id)
        consistency_due = (
            consistency_check_interval_seconds <= 0
            or checked_at is None
            or (now - checked_at).total_seconds() >= consistency_check_interval_seconds
        )
        # The local metadata mismatch is free to detect and always repaired; the
        # Cloudflare drift check costs API calls and is throttled in steady state.
        if not expanded_metadata_mismatch and not consistency_due:
            return False
        try:
            dns_matches = current_dns_matches_origin(db, group, desired)
        except Exception as exc:
            message = str(exc)
            group.last_error = message
            payload = {"group_id": group.id, "hostname": group.hostname, "error": message}
            add_event(db, "dns.consistency_check_failed", "error", f"{group.hostname} DNS 一致性检查失败: {message}", payload)
            send_webhooks(db, "dns.consistency_check_failed", payload)
            return False
        _consistency_checked_at[group.id] = now
        if expanded_metadata_mismatch or not dns_matches:
            try:
                record = publish_origin(db, group, desired)
            except Exception as exc:
                message = str(exc)
                failed_hostname = getattr(exc, "hostname", group.hostname)
                group.last_error = message
                payload = {"group_id": group.id, "hostname": failed_hostname, "error": message}
                add_event(db, "dns.publish_failed", "error", f"{group.hostname} 发布 DNS 失败: {message}", payload)
                send_webhooks(db, "dns.publish_failed", payload)
            else:
                published_hostnames = record.get("hostnames") or [group.hostname]
                hostname_label = ", ".join(str(item) for item in published_hostnames)
                payload = {
                    "group_id": group.id,
                    "hostname": hostname_label,
                    "hostnames": published_hostnames,
                    "old_origin_id": desired.id,
                    "new_origin_id": desired.id,
                    "record_id": record["id"],
                    "record_type": record["type"],
                    "content": record["content"],
                }
                message = f"{group.hostname} 已修正 DNS 记录为 {record['type']} {record['content']}"
                add_event(db, "dns.switched", "info", message, payload)
                send_webhooks(db, "dns.switched", payload)
        return False
    if group.last_switch_at:
        elapsed = (now - group.last_switch_at).total_seconds()
        if elapsed < group.min_switch_interval_seconds and desired.id != group.current_origin_id:
            return False
    old_origin_id = group.current_origin_id
    try:
        record = publish_origin(db, group, desired)
    except Exception as exc:
        message = str(exc)
        if group.last_error != message:
            failed_hostname = getattr(exc, "hostname", group.hostname)
            group.last_error = message
            payload = {"group_id": group.id, "hostname": failed_hostname, "error": message}
            add_event(db, "dns.publish_failed", "error", f"{group.hostname} 发布 DNS 失败: {message}", payload)
            send_webhooks(db, "dns.publish_failed", payload)
        return False

    group.current_origin_id = desired.id
    group.last_switch_at = now
    group.last_error = None
    _consistency_checked_at[group.id] = now
    published_hostnames = record.get("hostnames") or [group.hostname]
    hostname_label = ", ".join(str(item) for item in published_hostnames)
    payload = {
        "group_id": group.id,
        "hostname": hostname_label,
        "hostnames": published_hostnames,
        "old_origin_id": old_origin_id,
        "new_origin_id": desired.id,
        "record_id": record["id"],
        "record_type": record["type"],
        "content": record["content"],
    }
    add_event(
        db,
        "dns.switched",
        "info",
        f"{group.hostname} 已切换到 {record['type']} {record['content']}",
        payload,
    )
    send_webhooks(db, "dns.switched", payload)
    return True
