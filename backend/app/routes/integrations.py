import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from ..database import get_db
from ..deps import get_current_user
from ..integrations import (
    CUSTOM_IP_PROVIDER,
    azpanel_settings,
    bind_custom_resource_backups,
    change_resource_ip,
    custom_ip_settings,
    custom_url_hint,
    list_azpanel_remote_resources,
    refresh_legacy_origin_mirror,
    resource_bound_global_origins,
    resource_bound_origins,
    sync_custom_resource_status,
    sync_resource_current_ip_to_origin,
    update_azpanel_settings,
    update_custom_ip_settings,
    update_xboard_settings,
    xboard_settings,
)
from ..models import AzPanelResource, FailoverGlobalOrigin, IpChangeJob, Origin, User, XboardNodeBinding
from ..schemas import (
    AzPanelResourceCreate,
    AzPanelResourceOut,
    AzPanelResourceUpdate,
    AzPanelRemoteResourceOut,
    AzPanelSettingsOut,
    AzPanelSettingsUpdate,
    CustomIpSettingsOut,
    CustomIpSettingsUpdate,
    IpChangeJobOut,
    IpChangeRequest,
    Message,
    XboardNodeBindingCreate,
    XboardNodeBindingOut,
    XboardNodeBindingUpdate,
    XboardSettingsOut,
    XboardSettingsUpdate,
)
from ..security import encrypt_secret


router = APIRouter(prefix="/integrations", tags=["integrations"])


def _normalize_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _ensure_origin(db: Session, origin_id: int | None, *, reject_global_mirror: bool = False) -> Origin | None:
    if origin_id is None:
        return None
    origin = db.get(Origin, origin_id)
    if origin is None:
        raise HTTPException(status_code=404, detail="origin not found")
    if reject_global_mirror and origin.global_origin_id:
        raise HTTPException(
            status_code=400,
            detail="这是业务分组的全局备用镜像，请把云资源绑定到全局备用，业务分组下所有域名都会跟着换 IP",
        )
    return origin


def _bind_resource_to_origin(db: Session, resource: AzPanelResource, origin: Origin | None) -> None:
    """Bind additively.

    The binding used to live on AzPanelResource.origin_id, so pointing a resource at
    a second backup silently unbound the first and left it stuck on a dead IP. It now
    lives on the origin, and binding one never disturbs another.
    """
    if origin is None:
        return
    db.flush()
    origin.azpanel_resource_id = resource.id
    refresh_legacy_origin_mirror(db, resource)


def _resource_out(db: Session, resource: AzPanelResource) -> AzPanelResourceOut:
    """Return the compatibility field plus the complete one-to-many binding state."""
    db.flush()
    return AzPanelResourceOut.model_validate(resource).model_copy(
        update={
            "bound_origin_ids": [origin.id for origin in resource_bound_origins(db, resource)],
            "bound_global_origin_ids": [origin.id for origin in resource_bound_global_origins(db, resource)],
            "change_ip_url_hint": custom_url_hint(resource.change_ip_url),
            "status_url_hint": custom_url_hint(resource.status_url),
        }
    )


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


@router.get("/custom-ip/settings", response_model=CustomIpSettingsOut)
def read_custom_ip_settings(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return custom_ip_settings(db)


@router.patch("/custom-ip/settings", response_model=CustomIpSettingsOut)
def save_custom_ip_settings(payload: CustomIpSettingsUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    settings = update_custom_ip_settings(db, payload.model_dump(exclude_unset=True))
    db.commit()
    return settings


@router.get("/azpanel/resources", response_model=list[AzPanelResourceOut])
def list_azpanel_resources(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    resources = db.query(AzPanelResource).order_by(AzPanelResource.created_at.desc()).all()
    return [_resource_out(db, resource) for resource in resources]


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
    bind_origin = _ensure_origin(db, payload.origin_id, reject_global_mirror=True)
    custom = payload.provider == CUSTOM_IP_PROVIDER
    resource = AzPanelResource(
        name=payload.name.strip(),
        provider=payload.provider,
        # 通用接口没有云厂商的资源 ID，生成一个内部标识即可
        resource_id=payload.resource_id.strip() or f"custom-{uuid.uuid4().hex[:12]}",
        account_id=None if custom else _normalize_text(payload.account_id),
        region=None if custom else _normalize_text(payload.region),
        ip_version=payload.ip_version,
        ip_change_method=payload.ip_change_method,
        change_ip_url=encrypt_secret(payload.change_ip_url) if custom and payload.change_ip_url else None,
        status_url=encrypt_secret(payload.status_url) if custom and payload.status_url else None,
        verify_tls=payload.verify_tls,
        current_ip=_normalize_text(payload.current_ip),
        port=payload.port,
        enabled=payload.enabled,
        auto_change_on_blocked=payload.auto_change_on_blocked,
        auto_update_origin=payload.auto_update_origin,
        cooldown_seconds=payload.cooldown_seconds,
        status_sync_interval_seconds=payload.status_sync_interval_seconds,
        remark=_normalize_text(payload.remark),
    )
    db.add(resource)
    _bind_resource_to_origin(db, resource, bind_origin)
    if custom:
        db.flush()
        bind_custom_resource_backups(db, resource)
    try:
        sync_resource_current_ip_to_origin(db, resource)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    db.refresh(resource)
    return _resource_out(db, resource)


@router.patch("/azpanel/resources/{resource_id}", response_model=AzPanelResourceOut)
def update_azpanel_resource(resource_id: int, payload: AzPanelResourceUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    resource = db.get(AzPanelResource, resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="azpanel resource not found")
    updates = payload.model_dump(exclude_unset=True)
    bind_origin = None
    unbind_all = False
    if "origin_id" in updates:
        # origin_id is kept for API compatibility but is now an additive bind;
        # null clears every backup bound to this resource.
        requested_origin_id = updates.pop("origin_id")
        if requested_origin_id is None:
            unbind_all = True
        else:
            bind_origin = _ensure_origin(db, requested_origin_id, reject_global_mirror=True)
    # 链接留空表示不修改已保存的链接
    for key in ("change_ip_url", "status_url"):
        link = _normalize_text(updates.pop(key, None))
        if link:
            setattr(resource, key, encrypt_secret(link))
    if "resource_id" in updates and not (updates["resource_id"] or "").strip():
        updates.pop("resource_id")
    for key, value in updates.items():
        if key in {"name", "resource_id"} and isinstance(value, str):
            value = value.strip()
        if key in {"account_id", "region", "current_ip", "remark"}:
            value = _normalize_text(value)
        setattr(resource, key, value)
    if resource.provider == CUSTOM_IP_PROVIDER and (not resource.change_ip_url or not resource.status_url):
        raise HTTPException(status_code=400, detail="通用接口需要同时填写换 IP 链接和查 IP 链接")
    if unbind_all:
        for bound in resource_bound_origins(db, resource):
            bound.azpanel_resource_id = None
        for bound_global in resource_bound_global_origins(db, resource):
            bound_global.azpanel_resource_id = None
        db.flush()
        refresh_legacy_origin_mirror(db, resource)
    _bind_resource_to_origin(db, resource, bind_origin)
    if resource.provider == CUSTOM_IP_PROVIDER and not unbind_all:
        bind_custom_resource_backups(db, resource)
    try:
        sync_resource_current_ip_to_origin(db, resource)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    db.refresh(resource)
    return _resource_out(db, resource)


@router.delete("/azpanel/resources/{resource_id}", response_model=Message)
def delete_azpanel_resource(resource_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    resource = db.get(AzPanelResource, resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="azpanel resource not found")
    # These columns intentionally have no foreign key so SQLite/MySQL upgrades can
    # add them without rebuilding both sides. Clear them explicitly before delete.
    db.query(Origin).filter(Origin.azpanel_resource_id == resource.id).update(
        {Origin.azpanel_resource_id: None}, synchronize_session="fetch"
    )
    db.query(FailoverGlobalOrigin).filter(FailoverGlobalOrigin.azpanel_resource_id == resource.id).update(
        {FailoverGlobalOrigin.azpanel_resource_id: None}, synchronize_session="fetch"
    )
    resource.origin_id = None
    db.delete(resource)
    db.commit()
    return Message(message="azpanel resource deleted")


@router.post("/azpanel/resources/{resource_id}/refresh-status", response_model=AzPanelResourceOut)
def refresh_azpanel_resource_status(resource_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """调用查 IP 链接，把机器当前 IP 同步到资源和绑定源站。"""
    resource = db.get(AzPanelResource, resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="azpanel resource not found")
    if resource.provider != CUSTOM_IP_PROVIDER:
        raise HTTPException(status_code=400, detail="只有通用接口资源支持查询状态")
    try:
        sync_custom_resource_status(db, resource)
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.commit()
    db.refresh(resource)
    return _resource_out(db, resource)


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
