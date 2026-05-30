from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import User, Webhook
from ..schemas import Message, WebhookCreate, WebhookOut, WebhookUpdate
from ..security import encrypt_secret


router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.get("", response_model=list[WebhookOut])
def list_webhooks(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Webhook).order_by(Webhook.created_at.desc()).all()


@router.post("", response_model=WebhookOut)
def create_webhook(payload: WebhookCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    webhook = Webhook(
        name=payload.name,
        url=str(payload.url),
        secret=encrypt_secret(payload.secret) if payload.secret else None,
        enabled=payload.enabled,
    )
    db.add(webhook)
    db.commit()
    db.refresh(webhook)
    return webhook


@router.patch("/{webhook_id}", response_model=WebhookOut)
def update_webhook(webhook_id: int, payload: WebhookUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    webhook = db.get(Webhook, webhook_id)
    if webhook is None:
        raise HTTPException(status_code=404, detail="Webhook 不存在")
    updates = payload.model_dump(exclude_unset=True)
    if "url" in updates and updates["url"] is not None:
        updates["url"] = str(updates["url"])
    if "secret" in updates:
        secret = updates.pop("secret")
        webhook.secret = encrypt_secret(secret) if secret else None
    for key, value in updates.items():
        setattr(webhook, key, value)
    db.commit()
    db.refresh(webhook)
    return webhook


@router.delete("/{webhook_id}", response_model=Message)
def delete_webhook(webhook_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    webhook = db.get(Webhook, webhook_id)
    if webhook is None:
        raise HTTPException(status_code=404, detail="Webhook 不存在")
    db.delete(webhook)
    db.commit()
    return Message(message="Webhook 已删除")
