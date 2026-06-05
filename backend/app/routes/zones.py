from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..cloudflare import CloudflareClient, CloudflareError
from ..database import get_db
from ..deps import get_current_user
from ..dns_utils import normalize_hostname, parse_target
from ..models import DnsRecord, FailoverGroup, User, Zone
from ..schemas import DnsRecordCreate, DnsRecordOut, DnsRecordUpdate, Message, ZoneOut
from ..security import decrypt_secret
from ..sync import sync_zone_records


router = APIRouter(prefix="/zones", tags=["zones"])


def _record_ids(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def _failover_owner_for_record(db: Session, record: DnsRecord) -> str | None:
    groups = db.query(FailoverGroup).filter(FailoverGroup.zone_id == record.zone_id).all()
    for group in groups:
        if record.cf_record_id in _record_ids(group.current_record_id):
            return group.hostname
        for hostname in group.hostnames:
            if record.cf_record_id in _record_ids(hostname.current_record_id):
                return hostname.hostname
    return None


def _failover_owner_for_name(db: Session, zone_id: int, record_name: str) -> str | None:
    normalized_name = record_name.rstrip(".").lower()
    groups = db.query(FailoverGroup).filter(FailoverGroup.zone_id == zone_id).all()
    for group in groups:
        if group.hostname.rstrip(".").lower() == normalized_name:
            return group.hostname
        for hostname in group.hostnames:
            if hostname.hostname.rstrip(".").lower() == normalized_name:
                return hostname.hostname
    return None


def _normalize_record_name(value: str, zone: Zone) -> str:
    cleaned = value.strip()
    if cleaned == "@":
        cleaned = zone.name
    elif "." not in cleaned.rstrip("."):
        cleaned = f"{cleaned}.{zone.name}"
    hostname = normalize_hostname(cleaned)
    zone_name = zone.name.rstrip(".").lower()
    if hostname != zone_name and not hostname.endswith(f".{zone_name}"):
        raise HTTPException(status_code=400, detail="记录名称必须属于当前域名区域")
    return hostname


def _normalize_record_content(record_type: str, value: str, record_name: str) -> str:
    try:
        target = parse_target(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if target.record_type != record_type:
        raise HTTPException(status_code=400, detail=f"内容会被识别为 {target.record_type}，请把类型改为 {target.record_type} 或修改内容")
    if record_type == "CNAME" and target.value.rstrip(".").lower() == record_name.rstrip(".").lower():
        raise HTTPException(status_code=400, detail="CNAME 目标不能和记录名称相同")
    return target.value


def _validate_record_ttl(ttl: int) -> None:
    if ttl != 1 and ttl < 60:
        raise HTTPException(status_code=400, detail="TTL 必须为 1（自动）或至少 60 秒")


def _apply_cloudflare_record(record: DnsRecord, payload: dict) -> None:
    record.name = payload.get("name") or record.name
    record.type = payload.get("type") or record.type
    record.content = payload.get("content") or record.content
    record.ttl = int(payload.get("ttl") or record.ttl)
    record.proxied = bool(payload.get("proxied", record.proxied))
    record.synced_at = datetime.utcnow()


def _store_cloudflare_record(db: Session, zone: Zone, payload: dict) -> DnsRecord:
    cf_record_id = payload.get("id")
    if not cf_record_id:
        raise HTTPException(status_code=502, detail="Cloudflare 返回中缺少记录 ID")
    record = (
        db.query(DnsRecord)
        .filter(DnsRecord.zone_id == zone.id, DnsRecord.cf_record_id == cf_record_id)
        .one_or_none()
    )
    if record is None:
        record = DnsRecord(zone_id=zone.id, cf_record_id=cf_record_id)
        db.add(record)
    _apply_cloudflare_record(record, payload)
    return record


@router.get("", response_model=list[ZoneOut])
def list_zones(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Zone).order_by(Zone.name.asc()).all()


@router.get("/records/search", response_model=list[DnsRecordOut])
def search_records(zone_id: int = Query(...), q: str = Query(default=""), _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(DnsRecord).filter(DnsRecord.zone_id == zone_id)
    if q:
        query = query.filter(DnsRecord.name.contains(q))
    return query.order_by(DnsRecord.name.asc()).limit(100).all()


@router.post("/{zone_id}/records", response_model=DnsRecordOut)
def create_record(zone_id: int, payload: DnsRecordCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    zone = db.get(Zone, zone_id)
    if zone is None:
        raise HTTPException(status_code=404, detail="域名区域不存在")

    record_name = _normalize_record_name(payload.name, zone)
    owner_hostname = _failover_owner_for_name(db, zone.id, record_name)
    if owner_hostname:
        raise HTTPException(status_code=409, detail=f"该主机名已由故障切换组托管（{owner_hostname}），请到故障切换里添加备用源站")

    content = _normalize_record_content(payload.type, payload.content, record_name)
    _validate_record_ttl(payload.ttl)

    client = CloudflareClient(decrypt_secret(zone.credential.token_encrypted))
    body = {
        "type": payload.type,
        "name": record_name,
        "content": content,
        "ttl": payload.ttl,
        "proxied": payload.proxied,
    }
    try:
        created = client.create_dns_record(zone.cf_zone_id, body)
    except CloudflareError as exc:
        raise HTTPException(status_code=502, detail=f"Cloudflare 创建失败：{exc}") from exc

    record = _store_cloudflare_record(db, zone, created)
    db.commit()
    db.refresh(record)
    return record


@router.patch("/records/{record_id}", response_model=DnsRecordOut)
def update_record(record_id: int, payload: DnsRecordUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    record = db.get(DnsRecord, record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="解析记录不存在")

    owner_hostname = _failover_owner_for_record(db, record)
    if owner_hostname:
        raise HTTPException(status_code=409, detail=f"该记录已由故障切换组托管（{owner_hostname}），请到故障切换里修改源站")

    zone = record.zone
    record_name = _normalize_record_name(payload.name, zone)
    content = _normalize_record_content(payload.type, payload.content, record_name)
    _validate_record_ttl(payload.ttl)

    client = CloudflareClient(decrypt_secret(zone.credential.token_encrypted))
    body = {
        "type": payload.type,
        "name": record_name,
        "content": content,
        "ttl": payload.ttl,
        "proxied": payload.proxied,
    }
    try:
        updated = client.update_dns_record(zone.cf_zone_id, record.cf_record_id, body)
    except CloudflareError as exc:
        raise HTTPException(status_code=502, detail=f"Cloudflare 更新失败：{exc}") from exc

    _apply_cloudflare_record(record, updated)
    db.commit()
    db.refresh(record)
    return record


@router.delete("/records/{record_id}", response_model=Message)
def delete_record(record_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    record = db.get(DnsRecord, record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="解析记录不存在")

    owner_hostname = _failover_owner_for_record(db, record)
    if owner_hostname:
        raise HTTPException(status_code=409, detail=f"该记录已由故障切换组托管（{owner_hostname}），请先到故障切换里删除或取消托管")

    zone = record.zone
    client = CloudflareClient(decrypt_secret(zone.credential.token_encrypted))
    try:
        client.delete_dns_record(zone.cf_zone_id, record.cf_record_id)
    except CloudflareError as exc:
        raise HTTPException(status_code=502, detail=f"Cloudflare 删除失败：{exc}") from exc

    db.delete(record)
    db.commit()
    return Message(message="解析记录已删除")


@router.get("/{zone_id}/records", response_model=list[DnsRecordOut])
def list_records(zone_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    zone = db.get(Zone, zone_id)
    if zone is None:
        raise HTTPException(status_code=404, detail="域名区域不存在")
    return db.query(DnsRecord).filter(DnsRecord.zone_id == zone_id).order_by(DnsRecord.name.asc(), DnsRecord.type.asc()).all()


@router.post("/{zone_id}/records/sync", response_model=Message)
def sync_records(zone_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    zone = db.get(Zone, zone_id)
    if zone is None:
        raise HTTPException(status_code=404, detail="域名区域不存在")
    sync_zone_records(db, zone.credential, zone)
    db.commit()
    return Message(message="解析记录已同步")
