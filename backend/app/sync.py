from datetime import datetime

from sqlalchemy.orm import Session

from .cloudflare import CloudflareClient
from .models import CloudflareCredential, DnsRecord, Zone
from .security import decrypt_secret


MANAGED_RECORD_TYPES = {"A", "AAAA", "CNAME"}


def sync_credential(db: Session, credential: CloudflareCredential) -> None:
    token = decrypt_secret(credential.token_encrypted)
    client = CloudflareClient(token)
    now = datetime.utcnow()
    zones = client.list_zones()
    seen_zone_ids: set[str] = set()

    for item in zones:
        cf_zone_id = item["id"]
        seen_zone_ids.add(cf_zone_id)
        zone = (
            db.query(Zone)
            .filter(Zone.credential_id == credential.id, Zone.cf_zone_id == cf_zone_id)
            .one_or_none()
        )
        account = item.get("account") or {}
        if zone is None:
            zone = Zone(credential_id=credential.id, cf_zone_id=cf_zone_id, name=item["name"])
            db.add(zone)
        zone.name = item["name"]
        zone.account_id = account.get("id")
        zone.account_name = account.get("name")
        zone.status = item.get("status")
        zone.synced_at = now
        db.flush()
        sync_zone_records(db, credential, zone, client=client)

    credential.status = "ok"
    credential.last_error = None
    credential.synced_at = now


def sync_zone_records(
    db: Session,
    credential: CloudflareCredential,
    zone: Zone,
    client: CloudflareClient | None = None,
) -> None:
    if client is None:
        client = CloudflareClient(decrypt_secret(credential.token_encrypted))
    now = datetime.utcnow()
    records = client.list_dns_records(zone.cf_zone_id)
    seen_ids: set[str] = set()
    for item in records:
        if item.get("type") not in MANAGED_RECORD_TYPES:
            continue
        cf_record_id = item["id"]
        seen_ids.add(cf_record_id)
        record = (
            db.query(DnsRecord)
            .filter(DnsRecord.zone_id == zone.id, DnsRecord.cf_record_id == cf_record_id)
            .one_or_none()
        )
        if record is None:
            record = DnsRecord(zone_id=zone.id, cf_record_id=cf_record_id)
            db.add(record)
        record.name = item["name"]
        record.type = item["type"]
        record.content = item.get("content") or ""
        record.ttl = int(item.get("ttl") or 1)
        record.proxied = bool(item.get("proxied") or False)
        record.synced_at = now
    db.query(DnsRecord).filter(DnsRecord.zone_id == zone.id, DnsRecord.cf_record_id.notin_(seen_ids)).delete(synchronize_session=False)
    zone.synced_at = now

