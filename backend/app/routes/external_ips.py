from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime
from sqlalchemy.orm import Session, selectinload

from ..database import get_db
from ..deps import get_current_user
from ..external_ips import sync_external_ip_source
from ..models import ExternalIpItem, ExternalIpSource, User
from ..schemas import ExternalIpItemOut, ExternalIpSourceCreate, ExternalIpSourceOut, ExternalIpSourceUpdate, Message
from ..security import encrypt_secret


router = APIRouter(prefix="/external-ips", tags=["external-ips"])


@router.get("/sources", response_model=list[ExternalIpSourceOut])
def list_external_ip_sources(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(ExternalIpSource).order_by(ExternalIpSource.created_at.desc()).all()


@router.post("/sources", response_model=ExternalIpSourceOut)
def create_external_ip_source(payload: ExternalIpSourceCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    source = ExternalIpSource(
        name=payload.name.strip(),
        source_type="nyanpass",
        base_url=str(payload.base_url).rstrip("/"),
        token_encrypted=encrypt_secret(payload.token),
        default_port=payload.default_port,
        sync_interval_seconds=payload.sync_interval_seconds,
        enabled=payload.enabled,
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


@router.patch("/sources/{source_id}", response_model=ExternalIpSourceOut)
def update_external_ip_source(source_id: int, payload: ExternalIpSourceUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    source = db.get(ExternalIpSource, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="外部 IP 来源不存在")
    updates = payload.model_dump(exclude_unset=True)
    if "name" in updates and updates["name"] is not None:
        source.name = updates.pop("name").strip()
    if "base_url" in updates and updates["base_url"] is not None:
        source.base_url = str(updates.pop("base_url")).rstrip("/")
    if "token" in updates and updates["token"] is not None:
        source.token_encrypted = encrypt_secret(updates.pop("token"))
    for key, value in updates.items():
        setattr(source, key, value)
    db.commit()
    db.refresh(source)
    return source


@router.delete("/sources/{source_id}", response_model=Message)
def delete_external_ip_source(source_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    source = db.get(ExternalIpSource, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="外部 IP 来源不存在")
    db.delete(source)
    db.commit()
    return Message(message="外部 IP 来源已删除")


@router.post("/sources/{source_id}/sync", response_model=Message)
def sync_external_ip_source_route(source_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    source = (
        db.query(ExternalIpSource)
        .options(selectinload(ExternalIpSource.items))
        .filter(ExternalIpSource.id == source_id)
        .one_or_none()
    )
    if source is None:
        raise HTTPException(status_code=404, detail="外部 IP 来源不存在")
    try:
        count = sync_external_ip_source(db, source)
    except Exception as exc:
        source.status = "error"
        source.last_error = str(exc)
        source.last_synced_at = datetime.utcnow()
        db.commit()
        raise HTTPException(status_code=400, detail=f"同步失败: {exc}") from exc
    db.commit()
    return Message(message="外部 IP 已同步", detail={"count": count})


@router.get("/items", response_model=list[ExternalIpItemOut])
def list_external_ip_items(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return (
        db.query(ExternalIpItem)
        .join(ExternalIpItem.source)
        .filter(ExternalIpSource.enabled.is_(True), ExternalIpItem.status == "healthy")
        .order_by(ExternalIpItem.updated_at.desc(), ExternalIpItem.id.desc())
        .all()
    )
