from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from ..database import get_db
from ..deps import get_current_user
from ..integrations import (
    azpanel_settings,
    change_resource_ip,
    list_azpanel_remote_resources,
    sync_resource_current_ip_to_origin,
    update_azpanel_settings,
    update_xboard_settings,
    xboard_settings,
)
from ..models import AzPanelResource, IpChangeJob, Origin, User, XboardNodeBinding
from ..schemas import (
    AzPanelResourceCreate,
    AzPanelResourceOut,
    AzPanelResourceUpdate,
    AzPanelRemoteResourceOut,
    AzPanelSettingsOut,
    AzPanelSettingsUpdate,
    IpChangeJobOut,
    IpChangeRequest,
    Message,
    XboardNodeBindingCreate,
    XboardNodeBindingOut,
    XboardNodeBindingUpdate,
    XboardSettingsOut,
    XboardSettingsUpdate,
)


router = APIRouter(prefix="/integrations", tags=["integrations"])


def _normalize_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _ensure_origin(db: Session, origin_id: int | None) -> None:
    if origin_id is None:
        return
    if db.get(Origin, origin_id) is None:
        raise HTTPException(status_code=404, detail="origin not found")


def _ensure_resource(db: Session, resource_id: int | None) -> None:
    if resource_id is None:
        return
    if db.get(AzPanelResource, resource_id) is None:
        raise HTTPException(status_code=404, detail="azpanel resource not found")


@router.get("/azpanel/settings", response_model=AzPanelSettingsOut)
def read_azpanel_settings(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return azpanel_settings(db)


@router.patch("/azpanel/settings", response_model=AzPanelSettingsOut)
def save_azpanel_settings(payload: AzPanelSettingsUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    settings = update_azpanel_settings(db, payload.model_dump(exclude_unset=True))
    db.commit()
    return settings


@router.get("/azpanel/resources", response_model=list[AzPanelResourceOut])
def list_azpanel_resources(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(AzPanelResource).order_by(AzPanelResource.created_at.desc()).all()


@router.get("/azpanel/remote-resources", response_model=list[AzPanelRemoteResourceOut])
def list_remote_azpanel_resources(provider: str | None = None, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if provider not in {None, "", "azure", "aws"}:
        raise HTTPException(status_code=400, detail="provider must be azure or aws")
    try:
        resources = list_azpanel_remote_resources(db, provider or None)
        db.commit()
        return resources
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/azpanel/resources", response_model=AzPanelResourceOut)
def create_azpanel_resource(payload: AzPanelResourceCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _ensure_origin(db, payload.origin_id)
    resource = AzPanelResource(
        name=payload.name.strip(),
        provider=payload.provider,
        resource_id=payload.resource_id.strip(),
        account_id=_normalize_text(payload.account_id),
        region=_normalize_text(payload.region),
        ip_version=payload.ip_version,
        origin_id=payload.origin_id,
        current_ip=_normalize_text(payload.current_ip),
        port=payload.port,
        enabled=payload.enabled,
        auto_change_on_blocked=payload.auto_change_on_blocked,
        auto_update_origin=payload.auto_update_origin,
        cooldown_seconds=payload.cooldown_seconds,
        remark=_normalize_text(payload.remark),
    )
    db.add(resource)
    try:
        sync_resource_current_ip_to_origin(db, resource)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    db.refresh(resource)
    return resource


@router.patch("/azpanel/resources/{resource_id}", response_model=AzPanelResourceOut)
def update_azpanel_resource(resource_id: int, payload: AzPanelResourceUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    resource = db.get(AzPanelResource, resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="azpanel resource not found")
    updates = payload.model_dump(exclude_unset=True)
    if "origin_id" in updates:
        _ensure_origin(db, updates["origin_id"])
    for key, value in updates.items():
        if key in {"name", "resource_id"} and isinstance(value, str):
            value = value.strip()
        if key in {"account_id", "region", "current_ip", "remark"}:
            value = _normalize_text(value)
        setattr(resource, key, value)
    try:
        sync_resource_current_ip_to_origin(db, resource)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    db.refresh(resource)
    return resource


@router.delete("/azpanel/resources/{resource_id}", response_model=Message)
def delete_azpanel_resource(resource_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    resource = db.get(AzPanelResource, resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="azpanel resource not found")
    db.delete(resource)
    db.commit()
    return Message(message="azpanel resource deleted")


@router.post("/azpanel/resources/{resource_id}/change-ip", response_model=IpChangeJobOut)
def manual_change_azpanel_resource_ip(
    resource_id: int,
    payload: IpChangeRequest | None = None,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resource = (
        db.query(AzPanelResource)
        .options(selectinload(AzPanelResource.xboard_nodes))
        .filter(AzPanelResource.id == resource_id)
        .one_or_none()
    )
    if resource is None:
        raise HTTPException(status_code=404, detail="azpanel resource not found")
    job = change_resource_ip(db, resource, trigger_type="manual", reason=payload.reason if payload else "manual")
    db.commit()
    db.refresh(job)
    return job


@router.get("/xboard/settings", response_model=XboardSettingsOut)
def read_xboard_settings(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return xboard_settings(db)


@router.patch("/xboard/settings", response_model=XboardSettingsOut)
def save_xboard_settings(payload: XboardSettingsUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    settings = update_xboard_settings(db, payload.model_dump(exclude_unset=True))
    db.commit()
    return settings


@router.get("/xboard/nodes", response_model=list[XboardNodeBindingOut])
def list_xboard_nodes(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(XboardNodeBinding).order_by(XboardNodeBinding.created_at.desc()).all()


@router.post("/xboard/nodes", response_model=XboardNodeBindingOut)
def create_xboard_node(payload: XboardNodeBindingCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _ensure_origin(db, payload.origin_id)
    _ensure_resource(db, payload.azpanel_resource_id)
    node = XboardNodeBinding(
        name=payload.name.strip(),
        xboard_node_id=payload.xboard_node_id,
        node_type=_normalize_text(payload.node_type),
        host=_normalize_text(payload.host),
        port=payload.port,
        origin_id=payload.origin_id,
        azpanel_resource_id=payload.azpanel_resource_id,
        enabled=payload.enabled,
        auto_update_after_change=payload.auto_update_after_change,
        remark=_normalize_text(payload.remark),
    )
    db.add(node)
    db.commit()
    db.refresh(node)
    return node


@router.patch("/xboard/nodes/{node_id}", response_model=XboardNodeBindingOut)
def update_xboard_node(node_id: int, payload: XboardNodeBindingUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    node = db.get(XboardNodeBinding, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Xboard node binding not found")
    updates = payload.model_dump(exclude_unset=True)
    if "origin_id" in updates:
        _ensure_origin(db, updates["origin_id"])
    if "azpanel_resource_id" in updates:
        _ensure_resource(db, updates["azpanel_resource_id"])
    for key, value in updates.items():
        if key == "name" and isinstance(value, str):
            value = value.strip()
        if key in {"node_type", "host", "remark"}:
            value = _normalize_text(value)
        setattr(node, key, value)
    db.commit()
    db.refresh(node)
    return node


@router.delete("/xboard/nodes/{node_id}", response_model=Message)
def delete_xboard_node(node_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    node = db.get(XboardNodeBinding, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Xboard node binding not found")
    db.delete(node)
    db.commit()
    return Message(message="Xboard node binding deleted")


@router.post("/xboard/nodes/{node_id}/change-ip", response_model=IpChangeJobOut)
def change_xboard_node_ip(
    node_id: int,
    payload: IpChangeRequest | None = None,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    node = db.get(XboardNodeBinding, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Xboard node binding not found")
    if not node.azpanel_resource_id:
        raise HTTPException(status_code=400, detail="Xboard node is not bound to an azpanel resource")
    resource = (
        db.query(AzPanelResource)
        .options(selectinload(AzPanelResource.xboard_nodes))
        .filter(AzPanelResource.id == node.azpanel_resource_id)
        .one_or_none()
    )
    if resource is None:
        raise HTTPException(status_code=404, detail="azpanel resource not found")
    job = change_resource_ip(db, resource, trigger_type="xboard_manual", reason=payload.reason if payload else f"Xboard node {node.xboard_node_id}")
    job.xboard_node_id = node.id
    db.commit()
    db.refresh(job)
    return job


@router.get("/ip-change-jobs", response_model=list[IpChangeJobOut])
def list_ip_change_jobs(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(IpChangeJob).order_by(IpChangeJob.created_at.desc()).limit(100).all()
