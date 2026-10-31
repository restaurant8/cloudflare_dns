"""IP pools: named, reusable address sets (e.g. a group of relay backends B).

Origins and global backups reference pools as their relay backends, so an edit
here reaches every domain using the pool. Addresses can follow a machine from the
external IP list (Nyanpass) by machine_key, and the panel checks them every tick.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from ..database import get_db
from ..deps import get_current_user
from ..dns_utils import parse_target
from ..health import check_pool_items, refresh_relay_dependent_origins
from ..models import ExternalIpItem, FailoverGlobalOrigin, Origin, TargetPool, TargetPoolItem, User
from ..relay import relay_pool_ids
from ..schemas import (
    Message,
    TargetPoolBulkCreate,
    TargetPoolBulkItemResult,
    TargetPoolBulkOut,
    TargetPoolCreate,
    TargetPoolItemCreate,
    TargetPoolItemOut,
    TargetPoolItemUpdate,
    TargetPoolOut,
    TargetPoolUpdate,
)


router = APIRouter(prefix="/target-pool", tags=["target-pool"])


def _normalize_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _pool_or_404(db: Session, pool_id: int) -> TargetPool:
    pool = db.get(TargetPool, pool_id)
    if pool is None:
        raise HTTPException(status_code=404, detail="IP 池子不存在")
    return pool


def _item_or_404(db: Session, item_id: int) -> TargetPoolItem:
    item = db.get(TargetPoolItem, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="池子地址不存在")
    return item


def _ensure_unique(db: Session, pool_id: int, target: str, port: int, item_id: int | None = None) -> None:
    query = db.query(TargetPoolItem).filter(
        TargetPoolItem.pool_id == pool_id,
        TargetPoolItem.target == target,
        TargetPoolItem.port == port,
    )
    if item_id is not None:
        query = query.filter(TargetPoolItem.id != item_id)
    if query.first():
        raise HTTPException(status_code=409, detail=f"{target}:{port} 已经在这个池子里")


def _ensure_pool_name_free(db: Session, name: str, pool_id: int | None = None) -> None:
    query = db.query(TargetPool).filter(TargetPool.name == name)
    if pool_id is not None:
        query = query.filter(TargetPool.id != pool_id)
    if query.first():
        raise HTTPException(status_code=409, detail=f"已经有名为「{name}」的池子")


def _external_binding(db: Session, item_id: int) -> ExternalIpItem:
    external = db.get(ExternalIpItem, item_id)
    if external is None:
        raise HTTPException(status_code=404, detail="外部 IP 不存在，请先刷新外部 IP 列表")
    if not external.machine_key:
        raise HTTPException(status_code=400, detail="该外部 IP 没有机器标识，无法绑定（换 IP 后无法跟踪）")
    return external


def _users(db: Session) -> tuple[dict[int, int], dict[int, int]]:
    """Count origins / global backups referencing each pool."""
    origin_counts: dict[int, int] = {}
    for origin in db.query(Origin).filter(Origin.relay_pool_ids_json.isnot(None)).all():
        for pool_id in relay_pool_ids(origin):
            origin_counts[pool_id] = origin_counts.get(pool_id, 0) + 1
    global_counts: dict[int, int] = {}
    for global_origin in db.query(FailoverGlobalOrigin).filter(FailoverGlobalOrigin.relay_pool_ids_json.isnot(None)).all():
        for pool_id in relay_pool_ids(global_origin):
            global_counts[pool_id] = global_counts.get(pool_id, 0) + 1
    return origin_counts, global_counts


def _pool_out(pool: TargetPool, origin_counts: dict[int, int], global_counts: dict[int, int]) -> TargetPoolOut:
    return TargetPoolOut.model_validate(pool).model_copy(
        update={
            "used_by_origins": origin_counts.get(pool.id, 0),
            "used_by_global_origins": global_counts.get(pool.id, 0),
        }
    )


def _reset_check_state(item: TargetPoolItem) -> None:
    item.status = "unknown"
    item.fail_count = 0
    item.success_count = 0
    item.last_checked_at = None
    item.last_error = None
    item.last_rtt_ms = None


def _refresh_origins(db: Session) -> None:
    """Pool edits change relay verdicts; re-evaluate origins without waiting a tick."""
    db.flush()
    origins = db.query(Origin).filter(Origin.enabled.is_(True)).all()
    refresh_relay_dependent_origins(db, origins)


def _new_item(db: Session, pool: TargetPool, payload: TargetPoolItemCreate) -> TargetPoolItem:
    target, port = payload.target, payload.port
    external = _external_binding(db, payload.external_ip_item_id) if payload.external_ip_item_id is not None else None
    if external is not None:
        # The machine's current address wins; it is followed from now on.
        target = external.target
    target_info = parse_target(target)
    _ensure_unique(db, pool.id, target_info.value, port)
    return TargetPoolItem(
        pool_id=pool.id,
        target=target_info.value,
        target_type=target_info.target_type,
        port=port,
        remark=_normalize_text(payload.remark),
        enabled=payload.enabled,
        external_source_id=external.source_id if external is not None else None,
        external_machine_key=external.machine_key if external is not None else None,
    )


@router.get("", response_model=list[TargetPoolItemOut])
def list_target_pool_items(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Every address of every pool (used for quick-fill when adding a backup)."""
    return (
        db.query(TargetPoolItem)
        .options(selectinload(TargetPoolItem.pool))
        .order_by(TargetPoolItem.pool_id, TargetPoolItem.id)
        .all()
    )


@router.get("/pools", response_model=list[TargetPoolOut])
def list_pools(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    pools = db.query(TargetPool).options(selectinload(TargetPool.items)).order_by(TargetPool.name).all()
    origin_counts, global_counts = _users(db)
    return [_pool_out(pool, origin_counts, global_counts) for pool in pools]


@router.post("/pools", response_model=TargetPoolOut)
def create_pool(payload: TargetPoolCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    name = payload.name.strip()
    _ensure_pool_name_free(db, name)
    pool = TargetPool(name=name, remark=_normalize_text(payload.remark))
    db.add(pool)
    db.commit()
    db.refresh(pool)
    return _pool_out(pool, {}, {})


@router.patch("/pools/{pool_id}", response_model=TargetPoolOut)
def update_pool(pool_id: int, payload: TargetPoolUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    pool = _pool_or_404(db, pool_id)
    updates = payload.model_dump(exclude_unset=True)
    if updates.get("name") is not None:
        name = updates["name"].strip()
        _ensure_pool_name_free(db, name, pool.id)
        pool.name = name
    if "remark" in updates:
        pool.remark = _normalize_text(updates["remark"])
    db.commit()
    db.refresh(pool)
    origin_counts, global_counts = _users(db)
    return _pool_out(pool, origin_counts, global_counts)


@router.delete("/pools/{pool_id}", response_model=Message)
def delete_pool(pool_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    pool = _pool_or_404(db, pool_id)
    origin_counts, global_counts = _users(db)
    used = origin_counts.get(pool.id, 0) + global_counts.get(pool.id, 0)
    if used:
        raise HTTPException(
            status_code=409,
            detail=f"还有 {used} 个源站 / 全局备用把「{pool.name}」当作中转后端，请先在它们上面取消选择",
        )
    db.delete(pool)
    db.commit()
    return Message(message="IP 池子已删除")


@router.post("/pools/{pool_id}/items", response_model=TargetPoolItemOut)
def create_pool_item(pool_id: int, payload: TargetPoolItemCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    pool = _pool_or_404(db, pool_id)
    try:
        item = _new_item(db, pool, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@router.post("/pools/{pool_id}/items/bulk", response_model=TargetPoolBulkOut)
def bulk_create_pool_items(pool_id: int, payload: TargetPoolBulkCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    pool = _pool_or_404(db, pool_id)
    results: list[TargetPoolBulkItemResult] = []
    created = skipped = failed = 0
    for item_payload in payload.items:
        raw_target = item_payload.target.strip()
        try:
            item = _new_item(db, pool, item_payload)
        except HTTPException as exc:
            if exc.status_code == 409:
                skipped += 1
                results.append(TargetPoolBulkItemResult(target=raw_target, port=item_payload.port, status="skipped", message="已存在"))
                continue
            failed += 1
            results.append(TargetPoolBulkItemResult(target=raw_target, port=item_payload.port, status="failed", message=str(exc.detail)))
            continue
        except ValueError as exc:
            failed += 1
            results.append(TargetPoolBulkItemResult(target=raw_target, port=item_payload.port, status="failed", message=str(exc)))
            continue
        db.add(item)
        db.flush()
        created += 1
        results.append(TargetPoolBulkItemResult(target=item.target, port=item.port, status="created", id=item.id))
    db.commit()
    return TargetPoolBulkOut(created=created, skipped=skipped, failed=failed, results=results)


@router.patch("/items/{item_id}", response_model=TargetPoolItemOut)
def update_pool_item(item_id: int, payload: TargetPoolItemUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item = _item_or_404(db, item_id)
    updates = payload.model_dump(exclude_unset=True)
    new_target, new_port = item.target, item.port
    if "external_ip_item_id" in updates:
        external_id = updates.pop("external_ip_item_id")
        if external_id is None:
            item.external_source_id = None
            item.external_machine_key = None
        else:
            external = _external_binding(db, external_id)
            item.external_source_id = external.source_id
            item.external_machine_key = external.machine_key
            if "target" not in updates:
                new_target = external.target
    if updates.get("target") is not None:
        new_target = updates.pop("target")
    if updates.get("port") is not None:
        new_port = updates.pop("port")
    try:
        target_info = parse_target(new_target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    endpoint_changed = target_info.value != item.target or new_port != item.port
    if endpoint_changed:
        _ensure_unique(db, item.pool_id, target_info.value, new_port, item.id)
        item.target = target_info.value
        item.target_type = target_info.target_type
        item.port = new_port
        _reset_check_state(item)
    if "remark" in updates:
        item.remark = _normalize_text(updates.pop("remark"))
    if updates.get("enabled") is not None:
        item.enabled = updates.pop("enabled")
        if not item.enabled:
            _reset_check_state(item)
    _refresh_origins(db)
    db.commit()
    db.refresh(item)
    return item


@router.post("/items/{item_id}/run", response_model=Message)
def run_pool_item_now(item_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item = _item_or_404(db, item_id)
    checked = check_pool_items(db, item_id=item.id)
    _refresh_origins(db)
    db.commit()
    return Message(message="池子地址检测已完成", detail={"checked": checked})


@router.delete("/items/{item_id}", response_model=Message)
def delete_pool_item(item_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item = _item_or_404(db, item_id)
    db.delete(item)
    _refresh_origins(db)
    db.commit()
    return Message(message="池子地址已删除")
