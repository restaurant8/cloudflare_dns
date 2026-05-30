from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..dns_utils import parse_target
from ..models import TargetPoolItem, User
from ..schemas import Message, TargetPoolCreate, TargetPoolOut, TargetPoolUpdate


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
    return db.query(TargetPoolItem).order_by(TargetPoolItem.created_at.desc()).all()


@router.post("", response_model=TargetPoolOut)
def create_target_pool_item(payload: TargetPoolCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    target_info = parse_target(payload.target)
    _ensure_unique(db, target_info.value, payload.port)
    item = TargetPoolItem(
        target=target_info.value,
        target_type=target_info.target_type,
        port=payload.port,
        remark=_normalize_remark(payload.remark),
        enabled=payload.enabled,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


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
    item.target = target
    item.target_type = target_type
    item.port = port
    if "remark" in updates:
        item.remark = _normalize_remark(updates.pop("remark"))
    for key, value in updates.items():
        setattr(item, key, value)
    db.commit()
    db.refresh(item)
    return item


@router.delete("/{item_id}", response_model=Message)
def delete_target_pool_item(item_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.get(TargetPoolItem, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="目标不存在")
    db.delete(item)
    db.commit()
    return Message(message="目标已删除")
