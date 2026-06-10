from datetime import datetime

from sqlalchemy.orm import Session, selectinload

from .cloudflare import CloudflareClient, CloudflareError
from .dns_utils import record_type_for_target_type
from .events import add_event
from .health import FINAL_ORIGIN_STATUSES, ORIGIN_AVAILABLE_STATUS, run_local_checks
from .integrations import trigger_ip_change_for_origin
from .models import DnsRecord, FailoverGroup, FailoverHostname, Origin
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


MANAGED_RECORD_COMMENT_PREFIX = "managed by cloudflare-dns-failover"
NO_HEALTHY_ORIGIN_MESSAGE = "没有可用的健康源站"
WAITING_FOR_PROBES_MESSAGE = "等待源站探测结果"
RECOVERABLE_GROUP_ERRORS = {NO_HEALTHY_ORIGIN_MESSAGE, WAITING_FOR_PROBES_MESSAGE}


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
    normalized_hostname = _normalized_record_name(hostname) if hostname else None
    records = [
        record
        for record in client.list_dns_records(cf_zone_id)
        if record.get("type") in MANAGED_RECORD_TYPES
    ]
    if normalized_hostname is None:
        return records
    filtered = [record for record in records if _normalized_record_name(record.get("name")) == normalized_hostname]
    if filtered:
        return filtered
    return [
        record
        for record in client.list_dns_records(cf_zone_id, name=hostname)
        if record.get("type") in MANAGED_RECORD_TYPES
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


def current_dns_matches_origin(db: Session, group: FailoverGroup, origin: Origin) -> bool:
    desired = _desired_record_for_origin(origin)
    if desired is None:
        return True
    record_type, content = desired
    credential = group.zone.credential
    client = CloudflareClient(decrypt_secret(credential.token_encrypted))
    for hostname_entry in ensure_group_hostname_entries(db, group):
        managed_ids = _record_ids(hostname_entry)
        if not managed_ids:
            return False
        records = _same_name_records(client, group, hostname_entry)
        managed_records = [record for record in records if record.get("id") in managed_ids]
        if len(managed_records) != len(managed_ids):
            return False
        if len(managed_records) != 1:
            return False
        if not _record_matches(managed_records[0], record_type, content):
            return False
    return True


def _same_name_records(client: CloudflareClient, group: FailoverGroup, hostname_entry: FailoverHostname) -> list[dict]:
    return _managed_dns_records(client, group.zone.cf_zone_id, hostname_entry.hostname)


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


def publish_origin(db: Session, group: FailoverGroup, origin: Origin) -> dict:
    if is_expanded_origin(origin):
        return publish_expanded_origin(db, group, origin)

    record_type = record_type_for_target_type(origin.target_type)

    credential = group.zone.credential
    token = decrypt_secret(credential.token_encrypted)
    client = CloudflareClient(token)
    hostname_entries = ensure_group_hostname_entries(db, group)
    managed_by_hostname = []
    for hostname_entry in hostname_entries:
        if record_type == "CNAME" and origin.target.rstrip(".").lower() == hostname_entry.hostname.rstrip(".").lower():
            raise ValueError(f"CNAME 目标不能和当前主机名相同：{hostname_entry.hostname}")
        managed_by_hostname.append(
            (hostname_entry, _validate_same_name_records(group, hostname_entry, _same_name_records(client, group, hostname_entry)))
        )

    published_records = []
    for hostname_entry, managed_records in managed_by_hostname:
        target_record_id = managed_records[0]["id"] if managed_records else None
        for extra_record in managed_records[1:]:
            client.delete_dns_record(group.zone.cf_zone_id, extra_record["id"])

        body = {
            "type": record_type,
            "name": hostname_entry.hostname,
            "content": origin.target,
            "ttl": group.ttl,
            "proxied": False,
            "comment": MANAGED_RECORD_COMMENT_PREFIX,
        }

        if target_record_id:
            try:
                record = client.update_dns_record(group.zone.cf_zone_id, target_record_id, body)
            except CloudflareError:
                client.delete_dns_record(group.zone.cf_zone_id, target_record_id)
                record = client.create_dns_record(group.zone.cf_zone_id, body)
        else:
            record = client.create_dns_record(group.zone.cf_zone_id, body)

        _store_record_ids(group, hostname_entry, [record["id"]])
        published_records.append(record)
        local_record = (
            db.query(DnsRecord)
            .filter(DnsRecord.zone_id == group.zone_id, DnsRecord.cf_record_id == record["id"])
            .one_or_none()
        )
        if local_record:
            local_record.type = record_type
            local_record.content = origin.target
            local_record.ttl = group.ttl
            local_record.proxied = False
    origin.publish_mode = DIRECT_PUBLISH_MODE
    set_published_ips(origin, [])
    sync_zone_records(db, credential, group.zone, client=client)
    return {
        "id": ",".join(record["id"] for record in published_records),
        "type": record_type,
        "content": origin.target,
        "hostnames": [record.get("name") for record in published_records],
    }


def publish_expanded_origin(db: Session, group: FailoverGroup, origin: Origin) -> dict:
    if origin.target_type != "hostname":
        raise ValueError("只有域名目标可以展开发布为 IP 池")
    selected_ip = selected_healthy_ip(origin)
    if not selected_ip:
        raise ValueError("展开域名当前没有健康 IP，无法发布")

    credential = group.zone.credential
    token = decrypt_secret(credential.token_encrypted)
    client = CloudflareClient(token)
    hostname_entries = ensure_group_hostname_entries(db, group)
    managed_by_hostname = [
        (hostname_entry, _validate_same_name_records(group, hostname_entry, _same_name_records(client, group, hostname_entry)))
        for hostname_entry in hostname_entries
    ]

    created_records = []
    for hostname_entry, managed_records in managed_by_hostname:
        for record in managed_records:
            client.delete_dns_record(group.zone.cf_zone_id, record["id"])
        hostname_records = [
            client.create_dns_record(
                group.zone.cf_zone_id,
                {
                    "type": record_type_for_ip(selected_ip),
                    "name": hostname_entry.hostname,
                    "content": selected_ip,
                    "ttl": group.ttl,
                    "proxied": False,
                    "comment": f"{MANAGED_RECORD_COMMENT_PREFIX} expanded from {origin.target}",
                },
            )
        ]
        created_records.extend(hostname_records)
        _store_record_ids(group, hostname_entry, [record["id"] for record in hostname_records])

    set_published_ips(origin, [selected_ip])
    sync_zone_records(db, credential, group.zone, client=client)
    return {
        "id": ",".join(record["id"] for record in created_records),
        "type": record_type_for_ip(selected_ip),
        "content": selected_ip,
        "hostnames": sorted({str(record.get("name")) for record in created_records}),
    }


def evaluate_failover_groups(db: Session) -> int:
    groups = (
        db.query(FailoverGroup)
        .options(
            selectinload(FailoverGroup.origins),
            selectinload(FailoverGroup.hostnames),
            selectinload(FailoverGroup.zone),
        )
        .filter(FailoverGroup.enabled.is_(True))
        .all()
    )
    switches = 0
    now = datetime.utcnow()
    settings = get_runtime_settings(db)
    for group in groups:
        if _should_probe_group_before_switch(group):
            run_local_checks(db, group_id=group.id, include_all=False)

        current = _current_origin(group)
        if current is not None and current.status == "blocked":
            trigger_ip_change_for_origin(db, current, f"{group.hostname} current origin is blocked")

        desired = choose_desired_origin(group.origins, group.current_origin_id)
        if desired is None:
            if _has_pending_origin_checks(group):
                group.last_error = WAITING_FOR_PROBES_MESSAGE
                continue
            group.last_error = NO_HEALTHY_ORIGIN_MESSAGE
            if _should_notify_no_healthy(group, now, settings.no_healthy_notification_interval_seconds):
                group.no_healthy_notified_at = now
                payload = {"group_id": group.id, "hostname": group.hostname, "origins": _origin_status_summaries(group)}
                add_event(db, "failover.no_healthy_origin", "error", f"{group.hostname} 没有可用的健康源站", payload)
                send_webhooks(db, "failover.no_healthy_origin", payload)
            continue
        group.no_healthy_notified_at = None
        if group.last_error in RECOVERABLE_GROUP_ERRORS:
            group.last_error = None
        if desired.id == group.current_origin_id and not group.last_error:
            desired_expanded_ip = selected_healthy_ip(desired)
            try:
                dns_matches = current_dns_matches_origin(db, group, desired)
            except Exception as exc:
                message = str(exc)
                group.last_error = message
                payload = {"group_id": group.id, "hostname": group.hostname, "error": message}
                add_event(db, "dns.consistency_check_failed", "error", f"{group.hostname} DNS 一致性检查失败: {message}", payload)
                send_webhooks(db, "dns.consistency_check_failed", payload)
                continue
            expanded_metadata_mismatch = is_expanded_origin(desired) and published_ips(desired) != ([desired_expanded_ip] if desired_expanded_ip else [])
            if expanded_metadata_mismatch or not dns_matches:
                try:
                    record = publish_origin(db, group, desired)
                except Exception as exc:
                    message = str(exc)
                    group.last_error = message
                    payload = {"group_id": group.id, "hostname": group.hostname, "error": message}
                    add_event(db, "dns.publish_failed", "error", f"{group.hostname} 发布 DNS 失败: {message}", payload)
                    send_webhooks(db, "dns.publish_failed", payload)
                else:
                    payload = {
                        "group_id": group.id,
                        "hostname": group.hostname,
                        "old_origin_id": desired.id,
                        "new_origin_id": desired.id,
                        "record_id": record["id"],
                        "record_type": record["type"],
                        "content": record["content"],
                    }
                    message = f"{group.hostname} 已修正 DNS 记录为 {record['type']} {record['content']}"
                    add_event(db, "dns.switched", "info", message, payload)
                    send_webhooks(db, "dns.switched", payload)
            continue
        if group.last_switch_at:
            elapsed = (now - group.last_switch_at).total_seconds()
            if elapsed < group.min_switch_interval_seconds and desired.id != group.current_origin_id:
                continue
        old_origin_id = group.current_origin_id
        try:
            record = publish_origin(db, group, desired)
        except Exception as exc:
            message = str(exc)
            if group.last_error != message:
                group.last_error = message
                payload = {"group_id": group.id, "hostname": group.hostname, "error": message}
                add_event(db, "dns.publish_failed", "error", f"{group.hostname} 发布 DNS 失败: {message}", payload)
                send_webhooks(db, "dns.publish_failed", payload)
            continue

        group.current_origin_id = desired.id
        group.last_switch_at = now
        group.last_error = None
        switches += 1
        payload = {
            "group_id": group.id,
            "hostname": group.hostname,
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
    return switches
