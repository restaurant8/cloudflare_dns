from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from ..database import get_db
from ..deps import get_current_user
from ..dns_utils import parse_target
from ..models import FailoverGroup, Origin, TargetPoolItem, TargetPoolProbeState, User
from ..origin_expansion import DIRECT_PUBLISH_MODE
from ..schemas import (
    Message,
    TargetPoolAssignGroupResult,
    TargetPoolAssignToGroupsOut,
    TargetPoolAssignToGroupsRequest,
    TargetPoolBulkCreate,
    TargetPoolBulkItemResult,
    TargetPoolBulkOut,
    TargetPoolCreate,
    TargetPoolOut,
    TargetPoolUpdate,
)


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


def _group_hostname_values(group: FailoverGroup) -> set[str]:
    values = {group.hostname}
    values.update(hostname.hostname for hostname in group.hostnames)
    return values


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


@router.post("/assign-to-groups", response_model=TargetPoolAssignToGroupsOut)
def assign_target_pool_to_groups(payload: TargetPoolAssignToGroupsRequest, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item_ids = list(dict.fromkeys(payload.item_ids))
    group_ids = list(dict.fromkeys(payload.group_ids))
    items = db.query(TargetPoolItem).filter(TargetPoolItem.id.in_(item_ids)).all()
    items_by_id = {item.id: item for item in items}
    missing_item_ids = [item_id for item_id in item_ids if item_id not in items_by_id]

    if payload.all_groups:
        groups = (
            db.query(FailoverGroup)
            .options(selectinload(FailoverGroup.hostnames), selectinload(FailoverGroup.origins))
            .order_by(FailoverGroup.hostname.asc())
            .all()
        )
    else:
        if not group_ids:
            raise HTTPException(status_code=400, detail="请选择至少一个故障切换组")
        groups = (
            db.query(FailoverGroup)
            .options(selectinload(FailoverGroup.hostnames), selectinload(FailoverGroup.origins))
            .filter(FailoverGroup.id.in_(group_ids))
            .order_by(FailoverGroup.hostname.asc())
            .all()
        )

    groups_by_id = {group.id: group for group in groups}
    missing_group_ids = [] if payload.all_groups else [group_id for group_id in group_ids if group_id not in groups_by_id]
    results: list[TargetPoolAssignGroupResult] = []
    created = skipped = failed = 0

    for item_id in missing_item_ids:
        failed += 1
        results.append(
            TargetPoolAssignGroupResult(
                group_id=0,
                group_hostname="-",
                target=f"pool:{item_id}",
                port=0,
                status="failed",
                message="池子目标不存在",
            )
        )

    for group_id in missing_group_ids:
        failed += 1
        results.append(
            TargetPoolAssignGroupResult(
                group_id=group_id,
                group_hostname="-",
                target="-",
                port=0,
                status="failed",
                message="故障切换组不存在",
            )
        )

    for group in groups:
        existing_keys = {(origin.target, origin.port) for origin in group.origins}
        for item_id in item_ids:
            item = items_by_id.get(item_id)
            if item is None:
                continue
            if item.target_type == "hostname" and item.target in _group_hostname_values(group):
                failed += 1
                results.append(
                    TargetPoolAssignGroupResult(
                        group_id=group.id,
                        group_hostname=group.hostname,
                        target=item.target,
                        port=item.port,
                        status="failed",
                        message="域名目标不能和当前组主机名相同",
                    )
                )
                continue
            key = (item.target, item.port)
            if key in existing_keys:
                skipped += 1
                results.append(
                    TargetPoolAssignGroupResult(
                        group_id=group.id,
                        group_hostname=group.hostname,
                        target=item.target,
                        port=item.port,
                        status="skipped",
                        message="该组已存在相同目标",
                    )
                )
                continue

            origin = Origin(
                group_id=group.id,
                target=item.target,
                target_type=item.target_type,
                publish_mode=DIRECT_PUBLISH_MODE,
                port=item.port,
                priority=payload.priority,
                remark=_normalize_remark(item.remark),
                enabled=payload.enabled,
            )
            db.add(origin)
            db.flush()
            existing_keys.add(key)
            created += 1
            results.append(
                TargetPoolAssignGroupResult(
                    group_id=group.id,
                    group_hostname=group.hostname,
                    target=item.target,
                    port=item.port,
                    status="created",
                    origin_id=origin.id,
                )
            )

    db.commit()
    return TargetPoolAssignToGroupsOut(created=created, skipped=skipped, failed=failed, results=results)


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
        item.last_error = None
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
    return Message(message="IP 池子仅作为备用仓库，不再执行连通性检测", detail={"checked": 0})


@router.delete("/{item_id}", response_model=Message)
def delete_target_pool_item(item_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.get(TargetPoolItem, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="目标不存在")
    db.delete(item)
    db.commit()
    return Message(message="目标已删除")
