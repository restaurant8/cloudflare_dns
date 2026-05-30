from datetime import datetime

from sqlalchemy.orm import Session, selectinload

from .cloudflare import CloudflareClient, CloudflareError
from .dns_utils import record_type_for_target_type
from .events import add_event
from .models import DnsRecord, FailoverGroup, Origin
from .notifier import send_webhooks
from .security import decrypt_secret
from .sync import MANAGED_RECORD_TYPES, sync_zone_records


def choose_desired_origin(origins: list[Origin], current_origin_id: int | None = None) -> Origin | None:
    healthy = [origin for origin in origins if origin.enabled and origin.status == "healthy"]
    if not healthy:
        return None
    best_priority = min(origin.priority for origin in healthy)
    current = next((origin for origin in healthy if origin.id == current_origin_id), None)
    if current is not None and current.priority <= best_priority:
        return current
    candidates = [origin for origin in healthy if origin.priority == best_priority]
    return sorted(candidates, key=lambda item: item.id)[0]


def validate_group_hostname_records(
    client: CloudflareClient,
    cf_zone_id: str,
    hostname: str,
    current_record_id: str | None = None,
) -> str | None:
    records = [record for record in client.list_dns_records(cf_zone_id, name=hostname) if record.get("type") in MANAGED_RECORD_TYPES]
    if not records:
        return None
    if len(records) > 1:
        raise ValueError("该主机名存在多个 A/AAAA/CNAME 记录，启用故障切换前必须先清理为唯一记录")
    record = records[0]
    if record.get("proxied"):
        raise ValueError("仅支持 DNS-only 记录，请先关闭 Cloudflare 代理")
    if current_record_id and record["id"] != current_record_id:
        raise ValueError("该主机名已被其他 A/AAAA/CNAME 记录占用")
    return record["id"]


def publish_origin(db: Session, group: FailoverGroup, origin: Origin) -> dict:
    record_type = record_type_for_target_type(origin.target_type)
    if record_type == "CNAME" and origin.target.rstrip(".").lower() == group.hostname.rstrip(".").lower():
        raise ValueError("CNAME 目标不能和当前主机名相同")

    credential = group.zone.credential
    token = decrypt_secret(credential.token_encrypted)
    client = CloudflareClient(token)
    same_name_records = [
        record for record in client.list_dns_records(group.zone.cf_zone_id, name=group.hostname)
        if record.get("type") in MANAGED_RECORD_TYPES
    ]

    if group.current_record_id:
        conflicts = [record for record in same_name_records if record["id"] != group.current_record_id]
        if conflicts:
            raise ValueError("该主机名存在未托管的 A/AAAA/CNAME 冲突记录")
        target_record_id = group.current_record_id
    elif same_name_records:
        if len(same_name_records) > 1:
            raise ValueError("该主机名存在多个 A/AAAA/CNAME 记录，启用故障切换前必须先清理为唯一记录")
        if same_name_records[0].get("proxied"):
            raise ValueError("仅支持 DNS-only 记录，请先关闭 Cloudflare 代理")
        target_record_id = same_name_records[0]["id"]
    else:
        target_record_id = None

    body = {
        "type": record_type,
        "name": group.hostname,
        "content": origin.target,
        "ttl": group.ttl,
        "proxied": False,
        "comment": "managed by cloudflare-dns-failover",
    }

    if target_record_id:
        try:
            record = client.update_dns_record(group.zone.cf_zone_id, target_record_id, body)
        except CloudflareError:
            client.delete_dns_record(group.zone.cf_zone_id, target_record_id)
            record = client.create_dns_record(group.zone.cf_zone_id, body)
    else:
        record = client.create_dns_record(group.zone.cf_zone_id, body)

    group.current_record_id = record["id"]
    sync_zone_records(db, credential, group.zone, client=client)
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
    return record


def evaluate_failover_groups(db: Session) -> int:
    groups = (
        db.query(FailoverGroup)
        .options(
            selectinload(FailoverGroup.origins),
            selectinload(FailoverGroup.zone),
        )
        .filter(FailoverGroup.enabled.is_(True))
        .all()
    )
    switches = 0
    now = datetime.utcnow()
    for group in groups:
        desired = choose_desired_origin(group.origins, group.current_origin_id)
        if desired is None:
            if group.last_error != "没有可用的健康源站":
                group.last_error = "没有可用的健康源站"
                payload = {"group_id": group.id, "hostname": group.hostname}
                add_event(db, "failover.no_healthy_origin", "error", f"{group.hostname} 没有可用的健康源站", payload)
                send_webhooks(db, "failover.no_healthy_origin", payload)
            continue
        if desired.id == group.current_origin_id and not group.last_error:
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
