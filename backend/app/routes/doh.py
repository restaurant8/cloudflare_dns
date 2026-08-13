from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..doh import build_doh_snapshot, sync_doh_endpoint
from ..models import DohEndpoint, DohFailoverGroup, FailoverGroup, User
from ..schemas import DohEndpointCreate, DohEndpointOut, DohEndpointUpdate, DohSnapshotOut, Message
from ..security import encrypt_secret


router = APIRouter(prefix="/doh", tags=["doh"])


def _normalize_url(value: str) -> str:
    cleaned = value.strip().rstrip("/")
    parsed = urlparse(cleaned)
    if parsed.scheme != "https" or not parsed.hostname:
        raise HTTPException(status_code=400, detail="DoH endpoint must use an https:// URL")
    return cleaned


def _normalize_path(value: str, label: str) -> str:
    cleaned = value.strip()
    if not cleaned.startswith("/") or "?" in cleaned or "#" in cleaned:
        raise HTTPException(status_code=400, detail=f"{label} must be an absolute URL path")
    return cleaned


@router.get("/endpoints", response_model=list[DohEndpointOut])
def list_endpoints(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(DohEndpoint).order_by(DohEndpoint.created_at.desc()).all()


@router.post("/endpoints", response_model=DohEndpointOut)
def create_endpoint(payload: DohEndpointCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    endpoint = DohEndpoint(
        name=payload.name.strip(),
        base_url=_normalize_url(payload.base_url),
        sync_path=_normalize_path(payload.sync_path, "sync_path"),
        query_path=_normalize_path(payload.query_path, "query_path"),
        hmac_secret_encrypted=encrypt_secret(payload.hmac_secret),
        timeout_seconds=payload.timeout_seconds,
        sync_interval_seconds=payload.sync_interval_seconds,
        verify_tls=payload.verify_tls,
        enabled=payload.enabled,
    )
    db.add(endpoint)
    db.commit()
    db.refresh(endpoint)
    return endpoint


@router.patch("/endpoints/{endpoint_id}", response_model=DohEndpointOut)
def update_endpoint(endpoint_id: int, payload: DohEndpointUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    endpoint = db.get(DohEndpoint, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="DoH endpoint not found")
    updates = payload.model_dump(exclude_unset=True)
    if updates.get("enabled") is False:
        bound = (
            db.query(FailoverGroup)
            .filter(FailoverGroup.doh_endpoint_id == endpoint.id, FailoverGroup.doh_enabled.is_(True))
            .count()
        )
        independent_bound = db.query(DohFailoverGroup).filter(DohFailoverGroup.doh_endpoint_id == endpoint.id).count()
        if bound or independent_bound:
            raise HTTPException(
                status_code=409,
                detail=f"DoH endpoint is still enabled for {bound} Cloudflare group(s) and {independent_bound} independent group(s)",
            )
    if "base_url" in updates:
        updates["base_url"] = _normalize_url(updates["base_url"])
    if "sync_path" in updates:
        updates["sync_path"] = _normalize_path(updates["sync_path"], "sync_path")
    if "query_path" in updates:
        updates["query_path"] = _normalize_path(updates["query_path"], "query_path")
    secret = updates.pop("hmac_secret", None)
    if secret:
        endpoint.hmac_secret_encrypted = encrypt_secret(secret)
    for key, value in updates.items():
        setattr(endpoint, key, value)
    endpoint.last_revision = None
    endpoint.sync_failure_count = 0
    endpoint.next_sync_retry_at = None
    db.commit()
    db.refresh(endpoint)
    return endpoint


@router.delete("/endpoints/{endpoint_id}", response_model=Message)
def delete_endpoint(endpoint_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    endpoint = db.get(DohEndpoint, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="DoH endpoint not found")
    count = db.query(FailoverGroup).filter(FailoverGroup.doh_endpoint_id == endpoint.id).count()
    independent_count = db.query(DohFailoverGroup).filter(DohFailoverGroup.doh_endpoint_id == endpoint.id).count()
    if count or independent_count:
        raise HTTPException(
            status_code=409,
            detail=f"DoH endpoint is still used by {count} Cloudflare group(s) and {independent_count} independent group(s)",
        )
    db.delete(endpoint)
    db.commit()
    return Message(message="DoH endpoint deleted")


@router.post("/endpoints/{endpoint_id}/sync", response_model=Message)
def sync_endpoint(endpoint_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    endpoint = db.get(DohEndpoint, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="DoH endpoint not found")
    succeeded = sync_doh_endpoint(db, endpoint, force=True, ignore_backoff=True)
    db.commit()
    if not succeeded and endpoint.last_error:
        raise HTTPException(status_code=502, detail=endpoint.last_error)
    return Message(message="DoH endpoint synced")


@router.get("/endpoints/{endpoint_id}/snapshot", response_model=DohSnapshotOut)
def endpoint_snapshot(endpoint_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    endpoint = db.get(DohEndpoint, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="DoH endpoint not found")
    return build_doh_snapshot(db, endpoint)
