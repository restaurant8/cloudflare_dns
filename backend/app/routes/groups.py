from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from ..cloudflare import CloudflareClient
from ..database import get_db
from ..deps import get_current_user
from ..dns_utils import normalize_hostname, parse_target
from ..events import add_event
from ..failover import evaluate_failover_groups, validate_group_hostname_records
from ..health import run_local_checks
from ..models import FailoverGroup, Origin, User, Zone
from ..schemas import FailoverGroupCreate, FailoverGroupOut, FailoverGroupUpdate, Message, OriginBulkCreate, OriginCreate, OriginOut, OriginUpdate
from ..security import decrypt_secret
from ..sync import MANAGED_RECORD_TYPES


router = APIRouter(prefix="/groups", tags=["groups"])


def _group_query(db: Session):
    return db.query(FailoverGroup).options(selectinload(FailoverGroup.origins).selectinload(Origin.probe_states))


def _origin_from_payload(group: FailoverGroup, payload: OriginCreate) -> Origin:
    target_info = parse_target(payload.target)
    if target_info.record_type == "CNAME" and target_info.value == group.hostname:
        raise HTTPException(status_code=400, detail="CNAME 目标不能和当前主机名相同")
    return Origin(
        group_id=group.id,
        target=target_info.value,
        target_type=target_info.target_type,
        port=payload.port,
        priority=payload.priority,
        weight=payload.weight,
        enabled=payload.enabled,
    )


def _origin_from_dns_record(group: FailoverGroup, record: dict, port: int) -> Origin:
    if record.get("type") not in MANAGED_RECORD_TYPES:
        raise HTTPException(status_code=400, detail="只支持接管 A/AAAA/CNAME 记录")
    target_info = parse_target(str(record.get("content") or ""))
    if target_info.record_type == "CNAME" and target_info.value == group.hostname:
        raise HTTPException(status_code=400, detail="CNAME 目标不能和当前主机名相同")
    return Origin(
        group_id=group.id,
        target=target_info.value,
        target_type=target_info.target_type,
        port=port,
        priority=0,
        weight=1,
        enabled=True,
    )


@router.get("", response_model=list[FailoverGroupOut])
def list_groups(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _group_query(db).order_by(FailoverGroup.created_at.desc()).all()


@router.post("", response_model=FailoverGroupOut)
def create_group(payload: FailoverGroupCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    zone = db.get(Zone, payload.zone_id)
    if zone is None:
        raise HTTPException(status_code=404, detail="域名区域不存在")
    hostname = normalize_hostname(payload.hostname)
    existing = db.query(FailoverGroup).filter(FailoverGroup.zone_id == zone.id, FailoverGroup.hostname == hostname).one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="该主机名已经存在故障切换组")
    client = CloudflareClient(decrypt_secret(zone.credential.token_encrypted))
    try:
        existing_record_id = validate_group_hostname_records(client, zone.cf_zone_id, hostname, payload.adopt_record_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    group = FailoverGroup(
        zone_id=zone.id,
        hostname=hostname,
        ttl=payload.ttl,
        enabled=payload.enabled,
        min_switch_interval_seconds=payload.min_switch_interval_seconds,
        current_record_id=payload.adopt_record_id or existing_record_id,
    )
    db.add(group)
    db.flush()
    managed_record_id = group.current_record_id
    if managed_record_id:
        current_record = next(
            (
                record
                for record in client.list_dns_records(zone.cf_zone_id, name=hostname)
                if record.get("id") == managed_record_id and record.get("type") in MANAGED_RECORD_TYPES
            ),
            None,
        )
        if current_record is None:
            raise HTTPException(status_code=404, detail="未找到要接管的当前解析记录")
        primary_origin = _origin_from_dns_record(group, current_record, payload.primary_port)
        db.add(primary_origin)
        db.flush()
        group.current_origin_id = primary_origin.id
    add_event(db, "group.created", "info", f"{hostname} 的故障切换组已创建", {"group_id": group.id})
    db.commit()
    return _group_query(db).filter(FailoverGroup.id == group.id).one()


@router.patch("/{group_id}", response_model=FailoverGroupOut)
def update_group(group_id: int, payload: FailoverGroupUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(FailoverGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    updates = payload.model_dump(exclude_unset=True)
    for key, value in updates.items():
        setattr(group, key, value)
    db.commit()
    return _group_query(db).filter(FailoverGroup.id == group_id).one()


@router.delete("/{group_id}", response_model=Message)
def delete_group(group_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(FailoverGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    db.delete(group)
    db.commit()
    return Message(message="切换组已删除")


@router.post("/{group_id}/origins", response_model=OriginOut)
def create_origin(group_id: int, payload: OriginCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(FailoverGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    origin = _origin_from_payload(group, payload)
    db.add(origin)
    db.commit()
    db.refresh(origin)
    return origin


@router.post("/{group_id}/origins/bulk", response_model=FailoverGroupOut)
def create_origins_bulk(group_id: int, payload: OriginBulkCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(FailoverGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    existing_keys = {(origin.target, origin.port) for origin in group.origins}
    new_origins: list[Origin] = []
    new_keys: set[tuple[str, int]] = set()
    for item in payload.origins:
        origin = _origin_from_payload(group, item)
        key = (origin.target, origin.port)
        if key in existing_keys or key in new_keys:
            raise HTTPException(status_code=409, detail=f"{origin.target}:{origin.port} 已经在备用目标池中")
        new_keys.add(key)
        new_origins.append(origin)
    db.add_all(new_origins)
    db.commit()
    return _group_query(db).filter(FailoverGroup.id == group_id).one()


@router.patch("/origins/{origin_id}", response_model=OriginOut)
def update_origin(origin_id: int, payload: OriginUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    origin = db.get(Origin, origin_id)
    if origin is None:
        raise HTTPException(status_code=404, detail="源站不存在")
    updates = payload.model_dump(exclude_unset=True)
    if "target" in updates and updates["target"] is not None:
        target_info = parse_target(updates.pop("target"))
        if target_info.record_type == "CNAME" and target_info.value == origin.group.hostname:
            raise HTTPException(status_code=400, detail="CNAME 目标不能和当前主机名相同")
        origin.target = target_info.value
        origin.target_type = target_info.target_type
        origin.status = "unknown"
        origin.probe_states.clear()
    for key, value in updates.items():
        setattr(origin, key, value)
    db.commit()
    db.refresh(origin)
    return origin


@router.delete("/origins/{origin_id}", response_model=Message)
def delete_origin(origin_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    origin = db.get(Origin, origin_id)
    if origin is None:
        raise HTTPException(status_code=404, detail="源站不存在")
    db.delete(origin)
    db.commit()
    return Message(message="源站已删除")


@router.post("/run", response_model=Message)
def run_now(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    checked = run_local_checks(db)
    switches = evaluate_failover_groups(db)
    db.commit()
    return Message(message="健康检查已完成", detail={"checked": checked, "switches": switches})
