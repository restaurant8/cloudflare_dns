from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session, selectinload

from ..cloudflare import CloudflareClient
from ..database import get_db
from ..deps import get_current_user
from ..dns_utils import normalize_hostname, parse_target
from ..events import add_event
from ..failover import ensure_group_hostname_entries, evaluate_failover_groups, find_managed_dns_record_by_id, publish_origin, validate_group_hostname_records
from ..health import run_local_checks
from ..models import FailoverCollection, FailoverGlobalOrigin, FailoverGroup, FailoverHostname, Origin, ProbeState, User, Zone
from ..notifier import send_webhooks
from ..origin_expansion import DIRECT_PUBLISH_MODE, EXPANDED_PUBLISH_MODE, set_healthy_ips, set_published_ips, set_resolved_ips
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


def _group_query(db: Session):
    return db.query(FailoverGroup).options(
        selectinload(FailoverGroup.hostnames),
        selectinload(FailoverGroup.origins).selectinload(Origin.probe_states).selectinload(ProbeState.agent),
    )


def _group_hostname_values(group: FailoverGroup) -> set[str]:
    values = {group.hostname}
    values.update(hostname.hostname for hostname in group.hostnames)
    return values


def _origin_from_payload(group: FailoverGroup, payload: OriginCreate) -> Origin:
    target_info = parse_target(payload.target)
    if target_info.record_type == "CNAME" and target_info.value in _group_hostname_values(group):
        raise HTTPException(status_code=400, detail="CNAME 目标不能和当前主机名相同")
    if payload.publish_mode == EXPANDED_PUBLISH_MODE and target_info.target_type != "hostname":
        raise HTTPException(status_code=400, detail="只有域名目标可以启用展开 IP 池")
    return Origin(
        group_id=group.id,
        target=target_info.value,
        target_type=target_info.target_type,
        publish_mode=payload.publish_mode if target_info.target_type == "hostname" else DIRECT_PUBLISH_MODE,
        port=payload.port,
        priority=payload.priority,
        remark=_normalize_remark(payload.remark),
        enabled=payload.enabled,
    )


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


def _global_origin_from_payload(collection: FailoverCollection, payload: FailoverGlobalOriginCreate) -> FailoverGlobalOrigin:
    target_info = parse_target(payload.target)
    if target_info.record_type == "CNAME" and target_info.value in _collection_hostname_values(collection):
        raise HTTPException(status_code=400, detail="全局 CNAME 备用不能和当前业务分组内的主机名相同")
    if payload.publish_mode == EXPANDED_PUBLISH_MODE and target_info.target_type != "hostname":
        raise HTTPException(status_code=400, detail="只有域名目标可以启用展开 IP 池")
    return FailoverGlobalOrigin(
        collection_id=collection.id,
        target=target_info.value,
        target_type=target_info.target_type,
        publish_mode=payload.publish_mode if target_info.target_type == "hostname" else DIRECT_PUBLISH_MODE,
        port=payload.port,
        priority=payload.priority,
        remark=_normalize_remark(payload.remark),
        enabled=payload.enabled,
    )


def _reset_origin_probe_state(origin: Origin) -> None:
    origin.status = "unknown"
    origin.last_error = "等待本地和探针探测结果"
    origin.last_checked_at = None
    origin.last_rtt_ms = None
    origin.probe_states.clear()
    set_resolved_ips(origin, [])
    set_healthy_ips(origin, [])
    set_published_ips(origin, [])


def _copy_global_origin_to_origin(origin: Origin, global_origin: FailoverGlobalOrigin) -> None:
    endpoint_changed = (
        origin.target != global_origin.target
        or origin.target_type != global_origin.target_type
        or origin.port != global_origin.port
        or origin.publish_mode != global_origin.publish_mode
    )
    origin.global_origin_id = global_origin.id
    origin.target = global_origin.target
    origin.target_type = global_origin.target_type
    origin.publish_mode = global_origin.publish_mode
    origin.port = global_origin.port
    origin.priority = global_origin.priority
    origin.remark = global_origin.remark
    origin.enabled = global_origin.enabled
    if endpoint_changed:
        _reset_origin_probe_state(origin)


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


def sync_global_origins_to_group(db: Session, group: FailoverGroup) -> None:
    collection = group.collection
    active_global_ids: set[int] = set()
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
                origin = Origin(group_id=group.id, target=global_origin.target, target_type=global_origin.target_type, port=global_origin.port)
                db.add(origin)
                group.origins.append(origin)
            _copy_global_origin_to_origin(origin, global_origin)

    stale_global_origins = [origin for origin in group.origins if origin.global_origin_id and origin.global_origin_id not in active_global_ids]
    for origin in stale_global_origins:
        if group.current_origin_id == origin.id:
            group.current_origin_id = None
        db.delete(origin)


def sync_global_origins_to_collection(db: Session, collection: FailoverCollection) -> None:
    for group in collection.groups:
        sync_global_origins_to_group(db, group)


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
    global_origin = _global_origin_from_payload(collection, payload)
    _ensure_global_origin_unique(db, collection.id, global_origin.target, global_origin.port)
    db.add(global_origin)
    db.flush()
    collection.global_origins.append(global_origin)
    sync_global_origins_to_collection(db, collection)
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
    if new_target_type != "hostname" and new_publish_mode == EXPANDED_PUBLISH_MODE:
        raise HTTPException(status_code=400, detail="只有域名目标可以启用展开 IP 池")
    _ensure_global_origin_unique(db, global_origin.collection_id, new_target, new_port, exclude_id=global_origin.id)
    _ensure_global_origin_update_has_no_group_conflicts(db, global_origin, new_target, new_port)

    global_origin.target = new_target
    global_origin.target_type = new_target_type
    global_origin.publish_mode = new_publish_mode if new_target_type == "hostname" else DIRECT_PUBLISH_MODE
    global_origin.port = new_port
    if "remark" in updates:
        global_origin.remark = _normalize_remark(updates.pop("remark"))
    for key, value in updates.items():
        setattr(global_origin, key, value)
    sync_global_origins_to_collection(db, global_origin.collection)
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
        db.delete(origin)
    db.delete(global_origin)
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

    client = CloudflareClient(decrypt_secret(group.zone.credential.token_encrypted))
    try:
        existing_record_id = validate_group_hostname_records(client, group.zone.cf_zone_id, hostname, payload.adopt_record_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    hostname_entry = FailoverHostname(
        group=group,
        hostname=hostname,
        current_record_id=payload.adopt_record_id or existing_record_id,
    )
    db.add(hostname_entry)
    db.flush()

    current_origin = db.get(Origin, group.current_origin_id) if group.current_origin_id else None
    if group.enabled and current_origin and current_origin.enabled:
        try:
            publish_origin(db, group, current_origin)
        except Exception as exc:
            db.rollback()
            raise HTTPException(status_code=502, detail=f"DNS 发布失败，主域名未添加：{exc}") from exc
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


@router.post("/{group_id}/origins", response_model=OriginOut)
def create_origin(group_id: int, payload: OriginCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(FailoverGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    origin = _origin_from_payload(group, payload)
    duplicate = (
        db.query(Origin)
        .filter(Origin.group_id == group.id, Origin.target == origin.target, Origin.port == origin.port)
        .one_or_none()
    )
    if duplicate:
        raise HTTPException(status_code=409, detail=f"{origin.target}:{origin.port} 已经在备用目标池中")
    db.add(origin)
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
        origin = _origin_from_payload(group, item)
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
    target_changed = new_target != origin.target or new_target_type != origin.target_type or new_publish_mode != origin.publish_mode
    origin.target = new_target
    origin.target_type = new_target_type
    origin.publish_mode = new_publish_mode if new_target_type == "hostname" else DIRECT_PUBLISH_MODE
    if "remark" in updates:
        origin.remark = _normalize_remark(updates.pop("remark"))
    for key, value in updates.items():
        setattr(origin, key, value)

    if endpoint_changed:
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
