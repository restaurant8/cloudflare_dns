from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, selectinload

from ..alibaba_httpdns import evaluate_alibaba_httpdns_groups, list_remote_accounts, list_remote_records, list_remote_zones
from ..database import get_db
from ..deps import get_current_user
from ..dns_utils import parse_target
from ..events import add_event
from ..models import AlibabaHttpDnsGroup, AlibabaHttpDnsOrigin, User
from ..schemas import (
    AlibabaHttpDnsGroupCreate,
    AlibabaHttpDnsGroupOut,
    AlibabaHttpDnsGroupUpdate,
    AlibabaHttpDnsOriginCreate,
    AlibabaHttpDnsOriginOut,
    AlibabaHttpDnsOriginUpdate,
    AlibabaHttpDnsRemoteAccountOut,
    AlibabaHttpDnsRemoteRecordOut,
    AlibabaHttpDnsRemoteZoneOut,
    Message,
)


router = APIRouter(prefix="/alibaba-httpdns", tags=["alibaba-httpdns"])


def _group_query(db: Session):
    return db.query(AlibabaHttpDnsGroup).options(selectinload(AlibabaHttpDnsGroup.origins))


def _find_remote_record(db: Session, account_id: int, zone_id: str, record_id: str) -> dict:
    record = next((item for item in list_remote_records(db, account_id, zone_id) if str(item.get("RecordId") or "") == record_id), None)
    if record is None:
        raise HTTPException(status_code=404, detail="阿里云 HTTPDNS 解析记录不存在")
    if str(record.get("Type") or "").upper() not in {"A", "AAAA", "CNAME"}:
        raise HTTPException(status_code=400, detail="故障切换仅支持 A、AAAA 和 CNAME 记录")
    return record


@router.get("/remote/accounts", response_model=list[AlibabaHttpDnsRemoteAccountOut])
def remote_accounts(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        return list_remote_accounts(db)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/remote/zones", response_model=list[AlibabaHttpDnsRemoteZoneOut])
def remote_zones(account_id: int = Query(..., ge=1), _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        return list_remote_zones(db, account_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/remote/records", response_model=list[AlibabaHttpDnsRemoteRecordOut])
def remote_records(account_id: int = Query(..., ge=1), zone_id: str = Query(...), _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        return [item for item in list_remote_records(db, account_id, zone_id) if str(item.get("Type") or "").upper() in {"A", "AAAA", "CNAME"}]
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/groups", response_model=list[AlibabaHttpDnsGroupOut])
def list_groups(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _group_query(db).order_by(AlibabaHttpDnsGroup.created_at.desc()).all()


@router.post("/groups", response_model=AlibabaHttpDnsGroupOut)
def create_group(payload: AlibabaHttpDnsGroupCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    duplicate = db.query(AlibabaHttpDnsGroup).filter(
        AlibabaHttpDnsGroup.remote_account_id == payload.remote_account_id,
        AlibabaHttpDnsGroup.zone_id == payload.zone_id,
        AlibabaHttpDnsGroup.record_id == payload.record_id,
    ).one_or_none()
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="这条阿里云 HTTPDNS 记录已经创建切换组")
    try:
        record = _find_remote_record(db, payload.remote_account_id, payload.zone_id, payload.record_id)
        target = parse_target(str(record.get("Value") or ""))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    group = AlibabaHttpDnsGroup(
        remote_account_id=payload.remote_account_id,
        account_name=payload.account_name.strip(),
        zone_id=payload.zone_id.strip(),
        zone_name=payload.zone_name.strip(),
        record_id=payload.record_id.strip(),
        rr=str(record.get("Rr") or "@").strip(),
        record_type=str(record.get("Type") or "").upper(),
        ttl=int(record.get("Ttl") or 60),
        request_source=str(record.get("RequestSource") or "default"),
        weight=int(record.get("Weight") or 1),
        priority=int(record.get("Priority") or 1),
        remark=str(record.get("Remark") or "").strip() or None,
        enabled=payload.enabled,
        min_switch_interval_seconds=payload.min_switch_interval_seconds,
    )
    db.add(group)
    db.flush()
    origin = AlibabaHttpDnsOrigin(
        group_id=group.id,
        target=target.value,
        target_type=target.target_type,
        port=payload.primary_port,
        priority=0,
        remark="从当前阿里云记录接管",
        enabled=True,
    )
    db.add(origin)
    db.flush()
    group.current_origin_id = origin.id
    add_event(db, "alibaba_httpdns.group_created", "info", f"阿里云 HTTPDNS {group.rr}.{group.zone_name} 切换组已创建", {"group_id": group.id, "record_id": group.record_id})
    db.commit()
    return _group_query(db).filter(AlibabaHttpDnsGroup.id == group.id).one()


@router.patch("/groups/{group_id}", response_model=AlibabaHttpDnsGroupOut)
def update_group(group_id: int, payload: AlibabaHttpDnsGroupUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(AlibabaHttpDnsGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="阿里云 HTTPDNS 切换组不存在")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(group, key, value)
    if group.enabled:
        evaluate_alibaba_httpdns_groups(db, [group.id])
    db.commit()
    return _group_query(db).filter(AlibabaHttpDnsGroup.id == group.id).one()


@router.delete("/groups/{group_id}", response_model=Message)
def delete_group(group_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(AlibabaHttpDnsGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="阿里云 HTTPDNS 切换组不存在")
    db.delete(group)
    db.commit()
    return Message(message="阿里云 HTTPDNS 切换组已删除，云端记录保持不变")


@router.post("/groups/{group_id}/origins", response_model=AlibabaHttpDnsOriginOut)
def create_origin(group_id: int, payload: AlibabaHttpDnsOriginCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(AlibabaHttpDnsGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="阿里云 HTTPDNS 切换组不存在")
    try:
        target = parse_target(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if target.record_type != group.record_type:
        raise HTTPException(status_code=400, detail=f"当前记录是 {group.record_type}，目标将被识别为 {target.record_type}")
    if target.record_type == "CNAME" and target.value.rstrip(".").lower() == f"{group.rr}.{group.zone_name}".replace("@.", "").rstrip(".").lower():
        raise HTTPException(status_code=400, detail="CNAME 目标不能和当前记录名称相同")
    duplicate = next(
        (item for item in group.origins if item.target.rstrip(".").lower() == target.value.rstrip(".").lower() and item.port == payload.port),
        None,
    )
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="相同目标和端口已经存在")
    origin = AlibabaHttpDnsOrigin(group_id=group.id, target=target.value, target_type=target.target_type, port=payload.port, priority=payload.priority, remark=payload.remark.strip() if payload.remark else None, enabled=payload.enabled, ignore_health_check=payload.ignore_health_check)
    db.add(origin)
    db.commit()
    db.refresh(origin)
    return origin


@router.patch("/origins/{origin_id}", response_model=AlibabaHttpDnsOriginOut)
def update_origin(origin_id: int, payload: AlibabaHttpDnsOriginUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    origin = db.get(AlibabaHttpDnsOrigin, origin_id)
    if origin is None:
        raise HTTPException(status_code=404, detail="阿里云 HTTPDNS 源站不存在")
    updates = payload.model_dump(exclude_unset=True)
    next_target_value = origin.target
    if "target" in updates:
        try:
            target = parse_target(updates["target"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if target.record_type != origin.group.record_type:
            raise HTTPException(status_code=400, detail=f"当前记录是 {origin.group.record_type}，目标将被识别为 {target.record_type}")
        if target.record_type == "CNAME" and target.value.rstrip(".").lower() == f"{origin.group.rr}.{origin.group.zone_name}".replace("@.", "").rstrip(".").lower():
            raise HTTPException(status_code=400, detail="CNAME 目标不能和当前记录名称相同")
        next_target_value = target.value
        updates["target"] = target.value
        origin.target_type = target.target_type
        origin.status = "unknown"
        origin.success_count = 0
        origin.fail_count = 0
    next_port = int(updates.get("port", origin.port))
    duplicate = next(
        (
            item
            for item in origin.group.origins
            if item.id != origin.id
            and item.target.rstrip(".").lower() == next_target_value.rstrip(".").lower()
            and item.port == next_port
        ),
        None,
    )
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="相同目标和端口已经存在")
    for key, value in updates.items():
        if key == "remark" and isinstance(value, str):
            value = value.strip() or None
        setattr(origin, key, value)
    evaluate_alibaba_httpdns_groups(db, [origin.group_id])
    db.commit()
    db.refresh(origin)
    return origin


@router.delete("/origins/{origin_id}", response_model=Message)
def delete_origin(origin_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    origin = db.get(AlibabaHttpDnsOrigin, origin_id)
    if origin is None:
        raise HTTPException(status_code=404, detail="阿里云 HTTPDNS 源站不存在")
    group = origin.group
    if len(group.origins) <= 1:
        raise HTTPException(status_code=400, detail="至少需要保留一个源站")
    if group.current_origin_id == origin.id:
        group.current_origin_id = None
        group.last_switch_at = None
    db.delete(origin)
    db.flush()
    db.expire(group, ["origins"])
    evaluate_alibaba_httpdns_groups(db, [group.id])
    db.commit()
    return Message(message="源站已删除")


@router.post("/run", response_model=Message)
def run_now(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    switched = evaluate_alibaba_httpdns_groups(db, force_consistency=True)
    db.commit()
    return Message(message=f"阿里云 HTTPDNS 检查完成，本次切换 {switched} 组")


@router.post("/groups/{group_id}/run", response_model=Message)
def run_group_now(group_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(AlibabaHttpDnsGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="阿里云 HTTPDNS 切换组不存在")
    if not group.enabled:
        raise HTTPException(status_code=400, detail="请先启用这个切换组")
    switched = evaluate_alibaba_httpdns_groups(db, [group_id], force_consistency=True)
    db.commit()
    return Message(message=f"检查完成，本次切换 {switched} 组")
