from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from ..database import get_db
from ..deps import get_current_user
from ..dns_utils import parse_target
from ..health import run_target_pool_checks
from ..models import TargetPoolItem, TargetPoolProbeState, User
from ..schemas import Message, TargetPoolBulkCreate, TargetPoolBulkItemResult, TargetPoolBulkOut, TargetPoolCreate, TargetPoolOut, TargetPoolUpdate


router = APIRouter(prefix="/target-pool", tags=["target-pool"])


def _normalize_remark(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _ensure_unique(db: Session, target: str, port: int, item_id: int | None = None) -> None:
    query = db.query(TargetPoolItem).filter(TargetPoolItem.target == target, TargetPoolItem.port == port)
    if item_id is not None:
        query = query.filter(TargetPoolItem.id != item_id)
    if query.one_or_none():
        raise HTTPException(status_code=409, detail=f"{target}:{port} 已经在目标池中")


@router.get("", response_model=list[TargetPoolOut])
def list_target_pool(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return (
        db.query(TargetPoolItem)
        .options(selectinload(TargetPoolItem.probe_states).selectinload(TargetPoolProbeState.agent))
        .order_by(TargetPoolItem.created_at.desc())
        .all()
    )


@router.post("", response_model=TargetPoolOut)
def create_target_pool_item(payload: TargetPoolCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    target_info = parse_target(payload.target)
    _ensure_unique(db, target_info.value, payload.port)
    item = TargetPoolItem(
        target=target_info.value,
        target_type=target_info.target_type,
        port=payload.port,
        remark=_normalize_remark(payload.remark),
        check_interval_seconds=payload.check_interval_seconds,
        enabled=payload.enabled,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@router.post("/bulk", response_model=TargetPoolBulkOut)
def bulk_create_target_pool_items(payload: TargetPoolBulkCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    results: list[TargetPoolBulkItemResult] = []
    created = skipped = failed = 0
    for item_payload in payload.items:
        raw_target = item_payload.target.strip()
        try:
            target_info = parse_target(raw_target)
        except ValueError as exc:
            failed += 1
            results.append(TargetPoolBulkItemResult(target=raw_target, port=item_payload.port, status="failed", message=str(exc)))
            continue

        existing = (
            db.query(TargetPoolItem)
            .filter(TargetPoolItem.target == target_info.value, TargetPoolItem.port == item_payload.port)
            .one_or_none()
        )
        if existing is not None:
            skipped += 1
            results.append(
                TargetPoolBulkItemResult(
                    target=target_info.value,
                    port=item_payload.port,
                    status="skipped",
                    message="已存在",
                    id=existing.id,
                )
            )
            continue

        item = TargetPoolItem(
            target=target_info.value,
            target_type=target_info.target_type,
            port=item_payload.port,
            remark=_normalize_remark(item_payload.remark),
            check_interval_seconds=item_payload.check_interval_seconds,
            enabled=item_payload.enabled,
        )
        db.add(item)
        db.flush()
        created += 1
        results.append(TargetPoolBulkItemResult(target=item.target, port=item.port, status="created", id=item.id))

    db.commit()
    return TargetPoolBulkOut(created=created, skipped=skipped, failed=failed, results=results)


@router.patch("/{item_id}", response_model=TargetPoolOut)
def update_target_pool_item(item_id: int, payload: TargetPoolUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.get(TargetPoolItem, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="目标不存在")
    updates = payload.model_dump(exclude_unset=True)
    target = item.target
    target_type = item.target_type
    port = item.port
    if "target" in updates and updates["target"] is not None:
        target_info = parse_target(updates.pop("target"))
        target = target_info.value
        target_type = target_info.target_type
    if "port" in updates and updates["port"] is not None:
        port = updates.pop("port")
    _ensure_unique(db, target, port, item.id)
    endpoint_changed = target != item.target or port != item.port
    item.target = target
    item.target_type = target_type
    item.port = port
    if "remark" in updates:
        item.remark = _normalize_remark(updates.pop("remark"))
    for key, value in updates.items():
        setattr(item, key, value)
    if endpoint_changed:
        item.status = "unknown"
        item.last_checked_at = None
        item.last_error = "等待下次池子健康检查"
        item.last_rtt_ms = None
        item.probe_states.clear()
    db.commit()
    db.refresh(item)
    return item


@router.post("/{item_id}/run", response_model=Message)
def run_target_pool_item_now(item_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.get(TargetPoolItem, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="目标不存在")
    checked = run_target_pool_checks(db, item_id=item_id, include_all=True)
    db.commit()
    return Message(message="目标池检测已完成", detail={"checked": checked})


@router.delete("/{item_id}", response_model=Message)
def delete_target_pool_item(item_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.get(TargetPoolItem, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="目标不存在")
    db.delete(item)
    db.commit()
    return Message(message="目标已删除")
