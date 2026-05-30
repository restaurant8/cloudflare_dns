from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..cloudflare import CloudflareError
from ..database import get_db
from ..deps import get_current_user
from ..events import add_event
from ..models import CloudflareCredential, User
from ..schemas import CloudflareCredentialCreate, CloudflareCredentialOut, Message
from ..security import encrypt_secret
from ..sync import sync_credential


router = APIRouter(prefix="/credentials", tags=["credentials"])


@router.get("", response_model=list[CloudflareCredentialOut])
def list_credentials(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(CloudflareCredential).order_by(CloudflareCredential.created_at.desc()).all()


@router.post("", response_model=CloudflareCredentialOut)
def create_credential(payload: CloudflareCredentialCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    credential = CloudflareCredential(name=payload.name, token_encrypted=encrypt_secret(payload.token))
    db.add(credential)
    db.flush()
    try:
        sync_credential(db, credential)
        add_event(db, "cloudflare.synced", "info", f"Cloudflare 凭据 {credential.name} 已同步", {"credential_id": credential.id})
    except CloudflareError as exc:
        credential.status = "error"
        credential.last_error = str(exc)
        credential.synced_at = datetime.utcnow()
        add_event(db, "cloudflare.sync_failed", "error", f"Cloudflare 凭据 {credential.name} 同步失败", {"credential_id": credential.id, "error": str(exc)})
    db.commit()
    db.refresh(credential)
    return credential


@router.post("/{credential_id}/sync", response_model=CloudflareCredentialOut)
def sync_one(credential_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    credential = db.get(CloudflareCredential, credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="Cloudflare 凭据不存在")
    try:
        sync_credential(db, credential)
        add_event(db, "cloudflare.synced", "info", f"Cloudflare 凭据 {credential.name} 已同步", {"credential_id": credential.id})
    except CloudflareError as exc:
        credential.status = "error"
        credential.last_error = str(exc)
        add_event(db, "cloudflare.sync_failed", "error", f"Cloudflare 凭据 {credential.name} 同步失败", {"credential_id": credential.id, "error": str(exc)})
    db.commit()
    db.refresh(credential)
    return credential


@router.delete("/{credential_id}", response_model=Message)
def delete_credential(credential_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    credential = db.get(CloudflareCredential, credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="Cloudflare 凭据不存在")
    db.delete(credential)
    db.commit()
    return Message(message="Cloudflare 凭据已删除")
