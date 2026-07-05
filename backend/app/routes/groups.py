from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session, selectinload

from ..cloudflare import CloudflareClient, CloudflareError
from ..database import get_db
from ..deps import get_current_user
from ..dns_utils import normalize_hostname, parse_target
from ..events import add_event
from ..failover import ensure_group_hostname_entries, evaluate_failover_groups, find_managed_dns_record_by_id, publish_origin, validate_group_hostname_records, zone_for_hostname
from ..health import run_local_checks
from ..integrations import azpanel_settings, sync_resource_current_ip_to_origin
from ..models import Agent, AzPanelRemoteResource, AzPanelResource, FailoverCollection, FailoverGlobalOrigin, FailoverGroup, FailoverHostname, Origin, ProbeState, User, Zone
from ..notifier import send_webhooks
from ..origin_expansion import (
    DIRECT_PUBLISH_MODE,
    EXPANDED_PUBLISH_MODE,
    expanded_ip_priorities,
    set_expanded_ip_priorities,
    set_healthy_ips,
    set_published_ips,
    set_resolved_ips,
)
from ..schemas import (
    FailoverCollectionCreate,
    FailoverCollectionOut,
    FailoverCollectionUpdate,
    FailoverGlobalOriginCreate,
    FailoverGlobalOriginOut,
    FailoverGlobalOriginUpdate,
    FailoverGroupCreate,
    FailoverGroupOut,
    FailoverGroupUpdate,
    FailoverHostnameCreate,
    Message,
    OriginBulkCreate,
    OriginCreate,
    OriginOut,
    OriginUpdate,
)
from ..security import decrypt_secret
from ..sync import MANAGED_RECORD_TYPES


router = APIRouter(prefix="/groups", tags=["groups"])


def _normalize_remark(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _apply_expanded_ip_priorities(target, values: dict[str, int] | None) -> None:
    try:
        set_expanded_ip_priorities(target, values or {})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _validate_preferred_agent_id(db: Session, agent_id: int | None) -> int | None:
    if agent_id is None:
        return None
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="指定探针不存在")
    return agent.id


def _normalize_probe_mode(value: str | None) -> str:
    return value if value in {"default", "local_only", "china_only", "any"} else "default"


def _group_query(db: Session):
    return db.query(FailoverGroup).options(
        selectinload(FailoverGroup.hostnames),
        selectinload(FailoverGroup.origins).selectinload(Origin.probe_states).selectinload(ProbeState.agent),
    )


def _group_hostname_values(group: FailoverGroup) -> set[str]:
    values = {group.hostname}
    values.update(hostname.hostname for hostname in group.hostnames)
    return values


def _zone_matches_hostname(zone_name: str, hostname: str) -> bool:
    zone_name = (zone_name or "").rstrip(".").lower()
    hostname = (hostname or "").rstrip(".").lower()
    return bool(zone_name) and (hostname == zone_name or hostname.endswith("." + zone_name))


def _resolve_hostname_zone(db: Session, group: FailoverGroup, hostname: str) -> Zone | None:
    """Find the registered Cloudflare zone a hostname belongs to.

    Prefers the longest matching zone name, then the group's own credential so a
    same-zone hostname always resolves to the group's zone.
    """
    candidates = [zone for zone in db.query(Zone).all() if _zone_matches_hostname(zone.name, hostname)]
    if not candidates:
        return None
    group_credential_id = group.zone.credential_id
    candidates.sort(
        key=lambda zone: (len(zone.name or ""), 1 if zone.credential_id == group_credential_id else 0),
        reverse=True,
    )
    return candidates[0]


def _origin_from_payload(db: Session, group: FailoverGroup, payload: OriginCreate) -> Origin:
    target_info = parse_target(payload.target)
    if target_info.record_type == "CNAME" and target_info.value in _group_hostname_values(group):
        raise HTTPException(status_code=400, detail="CNAME 目标不能和当前主机名相同")
    if payload.publish_mode == EXPANDED_PUBLISH_MODE and target_info.target_type != "hostname":
        raise HTTPException(status_code=400, detail="只有域名目标可以启用展开 IP 池")
    origin = Origin(
        group_id=group.id,
        target=target_info.value,
        target_type=target_info.target_type,
        publish_mode=payload.publish_mode if target_info.target_type == "hostname" else DIRECT_PUBLISH_MODE,
        port=payload.port,
        priority=payload.priority,
        preferred_agent_id=_validate_preferred_agent_id(db, payload.preferred_agent_id),
        probe_mode=_normalize_probe_mode(payload.probe_mode),
        remark=_normalize_remark(payload.remark),
        enabled=payload.enabled,
    )
    _apply_expanded_ip_priorities(origin, payload.expanded_ip_priorities if target_info.target_type == "hostname" else {})
    return origin


def _origin_from_dns_record(group: FailoverGroup, record: dict, port: int) -> Origin:
    if record.get("type") not in MANAGED_RECORD_TYPES:
        raise HTTPException(status_code=400, detail="只支持接管 A/AAAA/CNAME 记录")
    target_info = parse_target(str(record.get("content") or ""))
    if target_info.record_type == "CNAME" and target_info.value in _group_hostname_values(group):
        raise HTTPException(status_code=400, detail="CNAME 目标不能和当前主机名相同")
    return Origin(
        group_id=group.id,
        target=target_info.value,
        target_type=target_info.target_type,
        publish_mode=DIRECT_PUBLISH_MODE,
        port=port,
        priority=0,
        enabled=True,
    )


def _collection_query(db: Session):
    return db.query(FailoverCollection).options(selectinload(FailoverCollection.global_origins))


def _collection_hostname_values(collection: FailoverCollection) -> set[str]:
    values: set[str] = set()
    for group in collection.groups:
        values.update(_group_hostname_values(group))
    return values


def _global_origin_from_payload(db: Session, collection: FailoverCollection, payload: FailoverGlobalOriginCreate) -> FailoverGlobalOrigin:
    target_info = parse_target(payload.target)
    if target_info.record_type == "CNAME" and target_info.value in _collection_hostname_values(collection):
        raise HTTPException(status_code=400, detail="全局 CNAME 备用不能和当前业务分组内的主机名相同")
    if payload.publish_mode == EXPANDED_PUBLISH_MODE and target_info.target_type != "hostname":
        raise HTTPException(status_code=400, detail="只有域名目标可以启用展开 IP 池")
    global_origin = FailoverGlobalOrigin(
        collection_id=collection.id,
        target=target_info.value,
        target_type=target_info.target_type,
        publish_mode=payload.publish_mode if target_info.target_type == "hostname" else DIRECT_PUBLISH_MODE,
        port=payload.port,
        priority=payload.priority,
        preferred_agent_id=_validate_preferred_agent_id(db, payload.preferred_agent_id),
        probe_mode=_normalize_probe_mode(payload.probe_mode),
        remark=_normalize_remark(payload.remark),
        enabled=payload.enabled,
    )
    _apply_expanded_ip_priorities(global_origin, payload.expanded_ip_priorities if target_info.target_type == "hostname" else {})
    return global_origin


def _reset_origin_probe_state(origin: Origin) -> None:
    origin.status = "unknown"
    origin.last_error = "等待本地和探针探测结果"
    origin.last_checked_at = None
    origin.last_rtt_ms = None
    origin.probe_states.clear()
    set_resolved_ips(origin, [])
    set_healthy_ips(origin, [])
    set_published_ips(origin, [])


def _copy_global_origin_to_origin(origin: Origin, global_origin: FailoverGlobalOrigin) -> bool:
    endpoint_changed = (
        origin.target != global_origin.target
        or origin.target_type != global_origin.target_type
        or origin.port != global_origin.port
        or origin.publish_mode != global_origin.publish_mode
    )
    probe_source_changed = (
        origin.preferred_agent_id != global_origin.preferred_agent_id
        or origin.probe_mode != global_origin.probe_mode
    )
    origin.global_origin_id = global_origin.id
    origin.preferred_agent_id = global_origin.preferred_agent_id
    origin.probe_mode = global_origin.probe_mode
    origin.target = global_origin.target
    origin.target_type = global_origin.target_type
    origin.publish_mode = global_origin.publish_mode
    origin.port = global_origin.port
    origin.priority = global_origin.priority
    origin.remark = global_origin.remark
    origin.enabled = global_origin.enabled
    origin.expanded_ip_priorities_json = global_origin.expanded_ip_priorities_json
    if endpoint_changed or probe_source_changed:
        _reset_origin_probe_state(origin)
    return endpoint_changed


def _ensure_global_origin_unique(db: Session, collection_id: int, target: str, port: int, exclude_id: int | None = None) -> None:
    query = db.query(FailoverGlobalOrigin).filter(
        FailoverGlobalOrigin.collection_id == collection_id,
        FailoverGlobalOrigin.target == target,
        FailoverGlobalOrigin.port == port,
    )
    if exclude_id is not None:
        query = query.filter(FailoverGlobalOrigin.id != exclude_id)
    if query.one_or_none():
        raise HTTPException(status_code=409, detail=f"{target}:{port} 已经是这个业务分组的全局备用")


def _ensure_global_origin_update_has_no_group_conflicts(db: Session, global_origin: FailoverGlobalOrigin, target: str, port: int) -> None:
    if global_origin.target == target and global_origin.port == port:
        return
    conflicts = (
        db.query(Origin)
        .join(FailoverGroup)
        .filter(
            FailoverGroup.collection_id == global_origin.collection_id,
            or_(Origin.global_origin_id.is_(None), Origin.global_origin_id != global_origin.id),
            Origin.target == target,
            Origin.port == port,
        )
        .limit(3)
        .all()
    )
    if conflicts:
        names = ", ".join(origin.group.hostname for origin in conflicts)
        raise HTTPException(status_code=409, detail=f"这些切换组已存在相同目标，无法整体修改：{names}")


def sync_global_origins_to_group(db: Session, group: FailoverGroup) -> bool:
    collection = group.collection
    active_global_ids: set[int] = set()
    current_endpoint_changed = False
    if collection:
        global_origins = sorted(collection.global_origins, key=lambda item: (item.priority, item.id))
        for global_origin in global_origins:
            if global_origin.target_type == "hostname" and global_origin.target in _group_hostname_values(group):
                raise HTTPException(status_code=400, detail=f"{group.hostname} 的主机名和全局 CNAME 备用冲突")
            active_global_ids.add(global_origin.id)
            origin = next((item for item in group.origins if item.global_origin_id == global_origin.id), None)
            if origin is None:
                origin = next(
                    (
                        item
                        for item in group.origins
                        if item.global_origin_id is None and item.target == global_origin.target and item.port == global_origin.port
                    ),
                    None,
                )
            if origin is None:
                origin = Origin(
                    group_id=group.id,
                    preferred_agent_id=global_origin.preferred_agent_id,
                    target=global_origin.target,
                    target_type=global_origin.target_type,
                    port=global_origin.port,
                )
                db.add(origin)
                group.origins.append(origin)
            was_current = group.current_origin_id == origin.id
            previous_priority = origin.priority
            previous_enabled = origin.enabled
            endpoint_changed = _copy_global_origin_to_origin(origin, global_origin)
            if was_current and endpoint_changed:
                current_endpoint_changed = True
            if was_current and (endpoint_changed or previous_priority != origin.priority or previous_enabled != origin.enabled):
                group.last_switch_at = None

    stale_global_origins = [origin for origin in group.origins if origin.global_origin_id and origin.global_origin_id not in active_global_ids]
    for origin in stale_global_origins:
        if group.current_origin_id == origin.id:
            group.current_origin_id = None
            group.last_switch_at = None
        db.delete(origin)
    return current_endpoint_changed


def sync_global_origins_to_collection(db: Session, collection: FailoverCollection) -> list[FailoverGroup]:
    current_endpoint_changed_groups: list[FailoverGroup] = []
    for group in collection.groups:
        if sync_global_origins_to_group(db, group):
            current_endpoint_changed_groups.append(group)
    return current_endpoint_changed_groups


def _publish_current_group_origin(db: Session, group: FailoverGroup) -> None:
    if not group.enabled or not group.current_origin_id:
        return
    current_origin = next((origin for origin in group.origins if origin.id == group.current_origin_id), None)
    if current_origin is None:
        current_origin = db.get(Origin, group.current_origin_id)
    if current_origin is None or not current_origin.enabled:
        return
    try:
        publish_origin(db, group, current_origin)
    except Exception as exc:
        group.last_error = str(exc)
    else:
        group.last_error = None


def _validate_group_collection(group: FailoverGroup, collection: FailoverCollection | None) -> None:
    if collection is None:
        return
    group_hostnames = _group_hostname_values(group)
    conflict = next(
        (
            global_origin
            for global_origin in collection.global_origins
            if global_origin.target_type == "hostname" and global_origin.target in group_hostnames
        ),
        None,
    )
    if conflict:
        raise HTTPException(status_code=400, detail=f"业务分组里的全局 CNAME 备用 {conflict.target} 和该切换组主机名冲突")


@router.get("/collections", response_model=list[FailoverCollectionOut])
def list_collections(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _collection_query(db).order_by(FailoverCollection.created_at.asc()).all()


@router.post("/collections", response_model=FailoverCollectionOut)
def create_collection(payload: FailoverCollectionCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    name = payload.name.strip()
    existing = db.query(FailoverCollection).filter(FailoverCollection.name == name).one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="业务分组名称已经存在")
    collection = FailoverCollection(name=name)
    db.add(collection)
    db.commit()
    return _collection_query(db).filter(FailoverCollection.id == collection.id).one()


@router.patch("/collections/{collection_id}", response_model=FailoverCollectionOut)
def update_collection(collection_id: int, payload: FailoverCollectionUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    collection = db.get(FailoverCollection, collection_id)
    if collection is None:
        raise HTTPException(status_code=404, detail="业务分组不存在")
    updates = payload.model_dump(exclude_unset=True)
    if "name" in updates and updates["name"] is not None:
        name = updates["name"].strip()
        duplicate = (
            db.query(FailoverCollection)
            .filter(FailoverCollection.id != collection.id, FailoverCollection.name == name)
            .one_or_none()
        )
        if duplicate:
            raise HTTPException(status_code=409, detail="业务分组名称已经存在")
        collection.name = name
    db.commit()
    return _collection_query(db).filter(FailoverCollection.id == collection_id).one()


@router.delete("/collections/{collection_id}", response_model=Message)
def delete_collection(collection_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    collection = (
        db.query(FailoverCollection)
        .options(selectinload(FailoverCollection.groups).selectinload(FailoverGroup.origins), selectinload(FailoverCollection.global_origins))
        .filter(FailoverCollection.id == collection_id)
        .one_or_none()
    )
    if collection is None:
        raise HTTPException(status_code=404, detail="业务分组不存在")
    groups = list(collection.groups)
    affected_group_ids = [group.id for group in groups if group.enabled]
    for group in groups:
        group.collection = None
        group.collection_id = None
        sync_global_origins_to_group(db, group)
    db.delete(collection)
    if affected_group_ids:
        evaluate_failover_groups(db)
    db.commit()
    return Message(message="业务分组已删除")


@router.post("/collections/{collection_id}/global-origins", response_model=FailoverCollectionOut)
def create_global_origin(collection_id: int, payload: FailoverGlobalOriginCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    collection = (
        db.query(FailoverCollection)
        .options(
            selectinload(FailoverCollection.groups).selectinload(FailoverGroup.hostnames),
            selectinload(FailoverCollection.groups).selectinload(FailoverGroup.origins).selectinload(Origin.probe_states),
            selectinload(FailoverCollection.global_origins),
        )
        .filter(FailoverCollection.id == collection_id)
        .one_or_none()
    )
    if collection is None:
        raise HTTPException(status_code=404, detail="业务分组不存在")
    global_origin = _global_origin_from_payload(db, collection, payload)
    _ensure_global_origin_unique(db, collection.id, global_origin.target, global_origin.port)
    db.add(global_origin)
    db.flush()
    collection.global_origins.append(global_origin)
    current_endpoint_changed_groups = sync_global_origins_to_collection(db, collection)
    for group in current_endpoint_changed_groups:
        _publish_current_group_origin(db, group)
    evaluate_failover_groups(db)
    db.commit()
    return _collection_query(db).filter(FailoverCollection.id == collection_id).one()


@router.patch("/global-origins/{global_origin_id}", response_model=FailoverGlobalOriginOut)
def update_global_origin(global_origin_id: int, payload: FailoverGlobalOriginUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    global_origin = (
        db.query(FailoverGlobalOrigin)
        .options(
            selectinload(FailoverGlobalOrigin.collection).selectinload(FailoverCollection.groups).selectinload(FailoverGroup.hostnames),
            selectinload(FailoverGlobalOrigin.collection).selectinload(FailoverCollection.groups).selectinload(FailoverGroup.origins).selectinload(Origin.probe_states),
            selectinload(FailoverGlobalOrigin.collection).selectinload(FailoverCollection.global_origins),
        )
        .filter(FailoverGlobalOrigin.id == global_origin_id)
        .one_or_none()
    )
    if global_origin is None:
        raise HTTPException(status_code=404, detail="全局备用不存在")
    updates = payload.model_dump(exclude_unset=True)
    new_target = global_origin.target
    new_target_type = global_origin.target_type
    new_port = global_origin.port
    new_publish_mode = global_origin.publish_mode
    new_preferred_agent_id = global_origin.preferred_agent_id
    new_probe_mode = global_origin.probe_mode
    if "target" in updates and updates["target"] is not None:
        target_info = parse_target(updates.pop("target"))
        if target_info.record_type == "CNAME" and target_info.value in _collection_hostname_values(global_origin.collection):
            raise HTTPException(status_code=400, detail="全局 CNAME 备用不能和当前业务分组内的主机名相同")
        new_target = target_info.value
        new_target_type = target_info.target_type
    if "port" in updates and updates["port"] is not None:
        new_port = updates["port"]
    if "publish_mode" in updates and updates["publish_mode"] is not None:
        new_publish_mode = updates.pop("publish_mode")
    priority_updates_provided = "expanded_ip_priorities" in updates
    priority_updates = updates.pop("expanded_ip_priorities", None) if priority_updates_provided else None
    if new_target_type != "hostname" and new_publish_mode == EXPANDED_PUBLISH_MODE:
        raise HTTPException(status_code=400, detail="只有域名目标可以启用展开 IP 池")
    if "preferred_agent_id" in updates:
        new_preferred_agent_id = _validate_preferred_agent_id(db, updates.pop("preferred_agent_id"))
    if "probe_mode" in updates:
        new_probe_mode = _normalize_probe_mode(updates.pop("probe_mode"))
    _ensure_global_origin_unique(db, global_origin.collection_id, new_target, new_port, exclude_id=global_origin.id)
    _ensure_global_origin_update_has_no_group_conflicts(db, global_origin, new_target, new_port)

    global_origin.target = new_target
    global_origin.target_type = new_target_type
    global_origin.publish_mode = new_publish_mode if new_target_type == "hostname" else DIRECT_PUBLISH_MODE
    global_origin.port = new_port
    global_origin.preferred_agent_id = new_preferred_agent_id
    global_origin.probe_mode = new_probe_mode
    if priority_updates_provided:
        _apply_expanded_ip_priorities(global_origin, priority_updates if new_target_type == "hostname" else {})
    elif new_target_type != "hostname":
        _apply_expanded_ip_priorities(global_origin, {})
    if "remark" in updates:
        global_origin.remark = _normalize_remark(updates.pop("remark"))
    for key, value in updates.items():
        setattr(global_origin, key, value)
    current_endpoint_changed_groups = sync_global_origins_to_collection(db, global_origin.collection)
    for group in current_endpoint_changed_groups:
        _publish_current_group_origin(db, group)
    evaluate_failover_groups(db)
    db.commit()
    db.refresh(global_origin)
    return global_origin


@router.delete("/global-origins/{global_origin_id}", response_model=Message)
def delete_global_origin(global_origin_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    global_origin = (
        db.query(FailoverGlobalOrigin)
        .options(selectinload(FailoverGlobalOrigin.collection).selectinload(FailoverCollection.groups).selectinload(FailoverGroup.origins))
        .filter(FailoverGlobalOrigin.id == global_origin_id)
        .one_or_none()
    )
    if global_origin is None:
        raise HTTPException(status_code=404, detail="全局备用不存在")
    collection = global_origin.collection
    affected_group_ids = [group.id for group in collection.groups if group.enabled]
    mirrored_origins = db.query(Origin).filter(Origin.global_origin_id == global_origin.id).all()
    for origin in mirrored_origins:
        if origin.group.current_origin_id == origin.id:
            origin.group.current_origin_id = None
            origin.group.last_switch_at = None
        db.delete(origin)
    db.delete(global_origin)
    db.flush()
    db.expire_all()
    if affected_group_ids:
        evaluate_failover_groups(db)
    db.commit()
    return Message(message="全局备用已删除")


@router.get("", response_model=list[FailoverGroupOut])
def list_groups(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _group_query(db).order_by(FailoverGroup.created_at.desc()).all()


@router.post("", response_model=FailoverGroupOut)
def create_group(payload: FailoverGroupCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    zone = db.get(Zone, payload.zone_id)
    if zone is None:
        raise HTTPException(status_code=404, detail="域名区域不存在")
    collection = db.get(FailoverCollection, payload.collection_id) if payload.collection_id else None
    if payload.collection_id and collection is None:
        raise HTTPException(status_code=404, detail="业务分组不存在")
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
        collection_id=collection.id if collection else None,
        hostname=hostname,
        ttl=payload.ttl,
        enabled=payload.enabled,
        min_switch_interval_seconds=payload.min_switch_interval_seconds,
        current_record_id=payload.adopt_record_id or existing_record_id,
    )
    db.add(group)
    db.flush()
    db.add(FailoverHostname(group_id=group.id, hostname=hostname, current_record_id=group.current_record_id))
    db.flush()
    managed_record_id = group.current_record_id
    if managed_record_id:
        current_record = find_managed_dns_record_by_id(client, zone.cf_zone_id, managed_record_id)
        if current_record is None:
            raise HTTPException(status_code=404, detail="未找到要接管的当前解析记录")
        primary_origin = _origin_from_dns_record(group, current_record, payload.primary_port)
        db.add(primary_origin)
        db.flush()
        group.current_origin_id = primary_origin.id
    if collection:
        db.refresh(group)
        _validate_group_collection(group, collection)
        group.collection = collection
        sync_global_origins_to_group(db, group)
    add_event(db, "group.created", "info", f"{hostname} 的故障切换组已创建", {"group_id": group.id})
    db.commit()
    return _group_query(db).filter(FailoverGroup.id == group.id).one()


@router.patch("/{group_id}", response_model=FailoverGroupOut)
def update_group(group_id: int, payload: FailoverGroupUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = (
        db.query(FailoverGroup)
        .options(
            selectinload(FailoverGroup.hostnames),
            selectinload(FailoverGroup.origins).selectinload(Origin.probe_states),
            selectinload(FailoverGroup.collection).selectinload(FailoverCollection.global_origins),
        )
        .filter(FailoverGroup.id == group_id)
        .one_or_none()
    )
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    updates = payload.model_dump(exclude_unset=True)
    collection_changed = "collection_id" in updates and updates["collection_id"] != group.collection_id
    if "collection_id" in updates:
        collection_id = updates.pop("collection_id")
        collection = db.get(FailoverCollection, collection_id) if collection_id else None
        if collection_id and collection is None:
            raise HTTPException(status_code=404, detail="业务分组不存在")
        _validate_group_collection(group, collection)
        group.collection = collection
        group.collection_id = collection.id if collection else None
        sync_global_origins_to_group(db, group)
    ttl_changed = "ttl" in updates and updates["ttl"] != group.ttl
    for key, value in updates.items():
        setattr(group, key, value)
    if ttl_changed and group.enabled and group.current_origin_id:
        current_origin = db.get(Origin, group.current_origin_id)
        if current_origin and current_origin.enabled:
            try:
                publish_origin(db, group, current_origin)
            except Exception as exc:
                db.rollback()
                raise HTTPException(status_code=502, detail=f"DNS 发布失败，修改未保存：{exc}") from exc
    if group.enabled or collection_changed:
        evaluate_failover_groups(db)
    db.commit()
    return _group_query(db).filter(FailoverGroup.id == group_id).one()


@router.post("/{group_id}/hostnames", response_model=FailoverGroupOut)
def add_group_hostname(group_id: int, payload: FailoverHostnameCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(FailoverGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    ensure_group_hostname_entries(db, group)
    hostname = normalize_hostname(payload.hostname)
    duplicate_in_group = (
        db.query(FailoverHostname)
        .filter(FailoverHostname.group_id == group.id, FailoverHostname.hostname == hostname)
        .one_or_none()
    )
    if duplicate_in_group:
        raise HTTPException(status_code=409, detail="该主域名已经在这个切换组中")
    duplicate_in_zone = (
        db.query(FailoverHostname)
        .join(FailoverGroup)
        .filter(FailoverGroup.zone_id == group.zone_id, FailoverGroup.id != group.id, FailoverHostname.hostname == hostname)
        .one_or_none()
    )
    legacy_group = (
        db.query(FailoverGroup)
        .filter(FailoverGroup.zone_id == group.zone_id, FailoverGroup.id != group.id, FailoverGroup.hostname == hostname)
        .one_or_none()
    )
    if duplicate_in_zone or legacy_group:
        raise HTTPException(status_code=409, detail="该主域名已经被其他切换组接管")
    if group.collection:
        conflict = next(
            (
                global_origin
                for global_origin in group.collection.global_origins
                if global_origin.target_type == "hostname" and global_origin.target == hostname
            ),
            None,
        )
        if conflict:
            raise HTTPException(status_code=400, detail=f"该主域名和业务分组全局备用 {conflict.target} 冲突")

    target_zone = _resolve_hostname_zone(db, group, hostname)
    if target_zone is None:
        raise HTTPException(
            status_code=409,
            detail=f"域名 {hostname} 所属的 Cloudflare 区域尚未在系统中添加，请先在区域页面同步该区域后再试",
        )

    client = CloudflareClient(decrypt_secret(target_zone.credential.token_encrypted))
    try:
        existing_record_id = validate_group_hostname_records(client, target_zone.cf_zone_id, hostname, payload.adopt_record_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    hostname_entry = FailoverHostname(
        group=group,
        hostname=hostname,
        zone_id=target_zone.id if target_zone.id != group.zone_id else None,
        current_record_id=payload.adopt_record_id or existing_record_id,
    )
    db.add(hostname_entry)
    db.flush()

    current_origin = db.get(Origin, group.current_origin_id) if group.current_origin_id else None
    if group.enabled and current_origin and current_origin.enabled:
        try:
            publish_origin(db, group, current_origin, hostname_entries=[hostname_entry])
        except Exception as exc:
            message = f"DNS 发布失败，主域名已保存但暂未完全接管：{exc}"
            group.last_error = message
            add_event(
                db,
                "dns.publish_failed",
                "error",
                f"{group.hostname} 添加主域名 {hostname} 后发布 DNS 失败: {exc}",
                {"group_id": group.id, "hostname": hostname, "error": str(exc)},
            )
        else:
            group.last_error = None
    add_event(db, "group.hostname_added", "info", f"{group.hostname} 已添加主域名 {hostname}", {"group_id": group.id, "hostname": hostname})
    db.commit()
    return _group_query(db).filter(FailoverGroup.id == group_id).one()


@router.delete("/hostnames/{hostname_id}", response_model=FailoverGroupOut)
def delete_group_hostname(hostname_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    hostname_entry = db.get(FailoverHostname, hostname_id)
    if hostname_entry is None:
        raise HTTPException(status_code=404, detail="主域名不存在")
    group = hostname_entry.group
    ensure_group_hostname_entries(db, group)
    remaining = [item for item in group.hostnames if item.id != hostname_entry.id]
    if not remaining:
        raise HTTPException(status_code=400, detail="至少需要保留一个主域名")
    removed_hostname = hostname_entry.hostname
    was_primary = removed_hostname == group.hostname
    record_ids = [item.strip() for item in (hostname_entry.current_record_id or "").split(",") if item.strip()]
    if record_ids:
        zone = zone_for_hostname(db, group, hostname_entry)
        client = CloudflareClient(decrypt_secret(zone.credential.token_encrypted))
        for record_id in record_ids:
            try:
                client.delete_dns_record(zone.cf_zone_id, record_id)
            except CloudflareError as exc:
                if exc.status_code == 404:
                    continue
                raise HTTPException(status_code=502, detail=f"删除 Cloudflare DNS 记录失败：{exc}") from exc
    db.delete(hostname_entry)
    if was_primary:
        next_primary = sorted(remaining, key=lambda item: item.id)[0]
        group.hostname = next_primary.hostname
        group.current_record_id = next_primary.current_record_id
    add_event(db, "group.hostname_removed", "info", f"{group.hostname} 已取消接管主域名 {removed_hostname}", {"group_id": group.id, "hostname": removed_hostname})
    db.commit()
    return _group_query(db).filter(FailoverGroup.id == group.id).one()


@router.delete("/{group_id}", response_model=Message)
def delete_group(group_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(FailoverGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    db.delete(group)
    db.commit()
    return Message(message="切换组已删除")


def _resource_from_remote_key(db: Session, remote_key: str, port: int) -> AzPanelResource:
    """Resolve an azpanel remote-resource key into a local AzPanelResource.

    Reuses an existing local resource for the same machine (so picking an
    already-added machine rebinds instead of duplicating it); otherwise creates
    one with auto-change defaults from the cached remote listing.
    """
    remote = db.query(AzPanelRemoteResource).filter(AzPanelRemoteResource.key == remote_key).one_or_none()
    if remote is None:
        raise HTTPException(status_code=404, detail="azpanel 远端资源不存在，请重新刷新资源")
    candidates = (
        db.query(AzPanelResource)
        .filter(
            AzPanelResource.provider == remote.provider,
            AzPanelResource.resource_id == remote.resource_id,
            AzPanelResource.ip_version == remote.ip_version,
        )
        .all()
    )
    existing = next(
        (
            item
            for item in candidates
            if (item.account_id or "") == (remote.account_id or "") and (item.region or "") == (remote.region or "")
        ),
        None,
    )
    if existing is not None:
        return existing
    resource = AzPanelResource(
        name=remote.name,
        provider=remote.provider,
        resource_id=remote.resource_id,
        account_id=remote.account_id or None,
        region=remote.region or None,
        ip_version=remote.ip_version,
        current_ip=remote.current_ip,
        port=port,
        enabled=True,
        auto_change_on_blocked=True,
        auto_update_origin=True,
        cooldown_seconds=azpanel_settings(db)["default_cooldown_seconds"],
        remark=remote.remark,
    )
    db.add(resource)
    return resource


@router.post("/{group_id}/origins", response_model=OriginOut)
def create_origin(group_id: int, payload: OriginCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(FailoverGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    resource = None
    if payload.azpanel_resource_id is not None:
        resource = db.get(AzPanelResource, payload.azpanel_resource_id)
        if resource is None:
            raise HTTPException(status_code=404, detail="azpanel 云资源不存在")
    elif payload.azpanel_remote_key:
        resource = _resource_from_remote_key(db, payload.azpanel_remote_key, payload.port)
    origin = _origin_from_payload(db, group, payload)
    duplicate = (
        db.query(Origin)
        .filter(Origin.group_id == group.id, Origin.target == origin.target, Origin.port == origin.port)
        .one_or_none()
    )
    if duplicate:
        raise HTTPException(status_code=409, detail=f"{origin.target}:{origin.port} 已经在备用目标池中")
    db.add(origin)
    if resource is not None:
        db.flush()
        resource.origin_id = origin.id
        try:
            sync_resource_current_ip_to_origin(db, resource)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"云资源当前 IP 无法同步到源站: {exc}") from exc
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
        origin = _origin_from_payload(db, group, item)
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
    if origin.global_origin_id:
        raise HTTPException(status_code=400, detail="这是业务分组的全局备用，请在全局备用里修改")
    updates = payload.model_dump(exclude_unset=True)
    group = origin.group
    new_target = origin.target
    new_target_type = origin.target_type
    new_port = origin.port
    new_publish_mode = origin.publish_mode
    new_preferred_agent_id = origin.preferred_agent_id
    new_probe_mode = origin.probe_mode
    if "target" in updates and updates["target"] is not None:
        target_info = parse_target(updates.pop("target"))
        if target_info.record_type == "CNAME" and target_info.value in _group_hostname_values(group):
            raise HTTPException(status_code=400, detail="CNAME 目标不能和当前主机名相同")
        new_target = target_info.value
        new_target_type = target_info.target_type
    if "port" in updates and updates["port"] is not None:
        new_port = updates["port"]
    if "publish_mode" in updates and updates["publish_mode"] is not None:
        new_publish_mode = updates.pop("publish_mode")
    if new_target_type != "hostname" and new_publish_mode == EXPANDED_PUBLISH_MODE:
        raise HTTPException(status_code=400, detail="只有域名目标可以启用展开 IP 池")

    preferred_agent_update_provided = "preferred_agent_id" in updates
    if preferred_agent_update_provided:
        new_preferred_agent_id = _validate_preferred_agent_id(db, updates.pop("preferred_agent_id"))

    probe_mode_update_provided = "probe_mode" in updates
    if probe_mode_update_provided:
        new_probe_mode = _normalize_probe_mode(updates.pop("probe_mode"))

    priority_updates_provided = "expanded_ip_priorities" in updates
    priority_updates = updates.pop("expanded_ip_priorities", None) if priority_updates_provided else None

    duplicate = (
        db.query(Origin)
        .filter(
            Origin.group_id == origin.group_id,
            Origin.id != origin.id,
            Origin.target == new_target,
            Origin.port == new_port,
        )
        .one_or_none()
    )
    if duplicate:
        raise HTTPException(status_code=409, detail=f"{new_target}:{new_port} 已经在备用目标池中")

    endpoint_changed = new_target != origin.target or new_port != origin.port or new_publish_mode != origin.publish_mode
    probe_source_changed = (
        (preferred_agent_update_provided and new_preferred_agent_id != origin.preferred_agent_id)
        or (probe_mode_update_provided and new_probe_mode != origin.probe_mode)
    )
    target_changed = new_target != origin.target or new_target_type != origin.target_type or new_publish_mode != origin.publish_mode
    old_expanded_ip_priorities = expanded_ip_priorities(origin)
    origin.target = new_target
    origin.target_type = new_target_type
    origin.publish_mode = new_publish_mode if new_target_type == "hostname" else DIRECT_PUBLISH_MODE
    origin.preferred_agent_id = new_preferred_agent_id
    origin.probe_mode = new_probe_mode
    if priority_updates_provided:
        _apply_expanded_ip_priorities(origin, priority_updates if new_target_type == "hostname" else {})
    elif new_target_type != "hostname":
        _apply_expanded_ip_priorities(origin, {})
    target_changed = target_changed or (
        origin.publish_mode == EXPANDED_PUBLISH_MODE and old_expanded_ip_priorities != expanded_ip_priorities(origin)
    )
    if "remark" in updates:
        origin.remark = _normalize_remark(updates.pop("remark"))
    for key, value in updates.items():
        setattr(origin, key, value)

    if endpoint_changed or probe_source_changed:
        origin.status = "unknown"
        origin.last_error = "等待本地和探针探测结果"
        origin.last_checked_at = None
        origin.last_rtt_ms = None
        origin.probe_states.clear()
        set_resolved_ips(origin, [])
        set_healthy_ips(origin, [])
        set_published_ips(origin, [])

    checked_expanded_now = False
    if endpoint_changed and origin.publish_mode == EXPANDED_PUBLISH_MODE:
        run_local_checks(db, origin_id=origin.id, include_all=True)
        checked_expanded_now = True

    should_publish_current = group.current_origin_id == origin.id and origin.enabled and target_changed
    if should_publish_current:
        try:
            if origin.publish_mode == EXPANDED_PUBLISH_MODE and not checked_expanded_now:
                run_local_checks(db, origin_id=origin.id, include_all=True)
            if origin.publish_mode == EXPANDED_PUBLISH_MODE and not origin.healthy_ips:
                group.last_error = "展开 IP 池已保存，当前没有健康 IP，暂不发布 DNS"
                record = None
            else:
                record = publish_origin(db, group, origin)
        except Exception as exc:
            db.rollback()
            raise HTTPException(status_code=502, detail=f"DNS 发布失败，修改未保存：{exc}") from exc
        if record is not None:
            group.current_origin_id = origin.id
            group.last_error = None
            payload = {
                "group_id": group.id,
                "hostname": group.hostname,
                "old_origin_id": origin.id,
                "new_origin_id": origin.id,
                "record_id": record["id"],
                "record_type": record["type"],
                "content": record["content"],
            }
            add_event(db, "dns.switched", "info", f"{group.hostname} 已更新到 {record['type']} {record['content']}", payload)
            send_webhooks(db, "dns.switched", payload)
    elif group.enabled:
        if group.current_origin_id == origin.id and not origin.enabled:
            group.current_origin_id = None
        evaluate_failover_groups(db)

    db.commit()
    db.refresh(origin)
    return origin


@router.post("/origins/{origin_id}/run", response_model=Message)
def run_origin_now(origin_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    origin = db.get(Origin, origin_id)
    if origin is None:
        raise HTTPException(status_code=404, detail="源站不存在")
    checked = run_local_checks(db, origin_id=origin_id, include_all=True)
    switches = evaluate_failover_groups(db)
    db.commit()
    return Message(message="目标检测已完成", detail={"checked": checked, "switches": switches})


@router.delete("/origins/{origin_id}", response_model=Message)
def delete_origin(origin_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    origin = db.get(Origin, origin_id)
    if origin is None:
        raise HTTPException(status_code=404, detail="源站不存在")
    if origin.global_origin_id:
        raise HTTPException(status_code=400, detail="这是业务分组的全局备用，请在全局备用里删除")
    db.delete(origin)
    db.commit()
    return Message(message="源站已删除")


@router.post("/{group_id}/run", response_model=Message)
def run_group_now(group_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(FailoverGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    checked = run_local_checks(db, group_id=group_id, include_all=True)
    switches = evaluate_failover_groups(db)
    db.commit()
    return Message(message="切换组检测已完成", detail={"checked": checked, "switches": switches})


@router.post("/run", response_model=Message)
def run_now(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    checked = run_local_checks(db, include_all=True)
    switches = evaluate_failover_groups(db)
    db.commit()
    return Message(message="健康检查已完成", detail={"checked": checked, "switches": switches})
