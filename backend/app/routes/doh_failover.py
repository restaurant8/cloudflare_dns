from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from ..database import get_db
from ..deps import get_current_user
from ..dns_utils import normalize_hostname, parse_target
from ..doh import group_doh_hostnames, sync_doh_endpoint
from ..doh_failover import evaluate_doh_failover_groups
from ..models import DohEndpoint, DohFailoverGroup, DohFailoverOrigin, FailoverGroup, User
from ..origin_expansion import published_ips, set_published_ips
from ..schemas import (
    DohFailoverGroupCreate,
    DohFailoverGroupOut,
    DohFailoverGroupUpdate,
    DohFailoverOriginCreate,
    DohFailoverOriginOut,
    DohFailoverOriginUpdate,
    Message,
)


router = APIRouter(prefix="/doh-failover", tags=["doh-failover"])


def _group_query(db: Session):
    return db.query(DohFailoverGroup).options(selectinload(DohFailoverGroup.origins))


def _endpoint(db: Session, endpoint_id: int) -> DohEndpoint:
    endpoint = db.get(DohEndpoint, endpoint_id)
    if endpoint is None or not endpoint.enabled:
        raise HTTPException(status_code=400, detail="Please select an enabled DoH endpoint")
    return endpoint


def _normalize_hostname(value: str) -> str:
    try:
        return normalize_hostname(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _ensure_hostname_available(
    db: Session,
    endpoint_id: int,
    hostname: str,
    exclude_group_id: int | None = None,
) -> None:
    query = db.query(DohFailoverGroup).filter(
        DohFailoverGroup.doh_endpoint_id == endpoint_id,
        DohFailoverGroup.hostname == hostname,
    )
    if exclude_group_id is not None:
        query = query.filter(DohFailoverGroup.id != exclude_group_id)
    if query.first() is not None:
        raise HTTPException(status_code=409, detail="This hostname already has an independent DoH failover group")
    legacy_groups = (
        db.query(FailoverGroup)
        .options(selectinload(FailoverGroup.hostnames))
        .filter(
            FailoverGroup.enabled.is_(True),
            FailoverGroup.doh_enabled.is_(True),
            FailoverGroup.doh_endpoint_id == endpoint_id,
        )
        .all()
    )
    for group in legacy_groups:
        if hostname in group_doh_hostnames(group):
            raise HTTPException(status_code=409, detail=f"This hostname is already published by Cloudflare group {group.id}")


def _best_effort_sync(db: Session, endpoint_ids: set[int]) -> None:
    """Reconcile after local configuration is durable.

    A remote outage must never make a rule impossible to disable or delete. The
    endpoint stores the error/backoff state and the scheduler retries later.
    """
    for endpoint_id in endpoint_ids:
        endpoint = db.get(DohEndpoint, endpoint_id)
        if endpoint is not None and endpoint.enabled:
            sync_doh_endpoint(db, endpoint)
    db.commit()


@router.get("/groups", response_model=list[DohFailoverGroupOut])
def list_groups(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _group_query(db).order_by(DohFailoverGroup.created_at.desc()).all()


@router.post("/groups", response_model=DohFailoverGroupOut)
def create_group(payload: DohFailoverGroupCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    endpoint = _endpoint(db, payload.doh_endpoint_id)
    hostname = _normalize_hostname(payload.hostname)
    _ensure_hostname_available(db, endpoint.id, hostname)
    group = DohFailoverGroup(
        doh_endpoint_id=endpoint.id,
        hostname=hostname,
        ttl=payload.ttl,
        min_switch_interval_seconds=payload.min_switch_interval_seconds,
        enabled=payload.enabled,
    )
    db.add(group)
    db.commit()
    db.refresh(group)
    _best_effort_sync(db, {endpoint.id})
    return _group_query(db).filter(DohFailoverGroup.id == group.id).one()


@router.patch("/groups/{group_id}", response_model=DohFailoverGroupOut)
def update_group(group_id: int, payload: DohFailoverGroupUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = _group_query(db).filter(DohFailoverGroup.id == group_id).one_or_none()
    if group is None:
        raise HTTPException(status_code=404, detail="DoH failover group not found")
    updates = payload.model_dump(exclude_unset=True)
    endpoint_id = int(updates.get("doh_endpoint_id", group.doh_endpoint_id))
    endpoint = db.get(DohEndpoint, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=400, detail="Please select a DoH endpoint")
    if not endpoint.enabled and bool(updates.get("enabled", group.enabled)):
        raise HTTPException(status_code=400, detail="Please select an enabled DoH endpoint")
    hostname = _normalize_hostname(str(updates.get("hostname", group.hostname)))
    _ensure_hostname_available(db, endpoint_id, hostname, exclude_group_id=group.id)
    previous_endpoint_id = group.doh_endpoint_id
    updates["hostname"] = hostname
    for key, value in updates.items():
        setattr(group, key, value)
    group.endpoint = endpoint
    if updates.get("enabled") is False:
        group.current_origin_id = None
        group.last_switch_at = None
    db.commit()
    group = _group_query(db).filter(DohFailoverGroup.id == group_id).one()
    if group.enabled and group.origins:
        evaluate_doh_failover_groups(db, [group.id])
    db.commit()
    _best_effort_sync(db, {previous_endpoint_id, endpoint.id})
    return _group_query(db).filter(DohFailoverGroup.id == group.id).one()


@router.delete("/groups/{group_id}", response_model=Message)
def delete_group(group_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(DohFailoverGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="DoH failover group not found")
    endpoint_id = group.doh_endpoint_id
    db.delete(group)
    db.commit()
    _best_effort_sync(db, {endpoint_id})
    return Message(message="DoH failover group deleted")


@router.post("/groups/{group_id}/origins", response_model=DohFailoverOriginOut)
def create_origin(group_id: int, payload: DohFailoverOriginCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = _group_query(db).filter(DohFailoverGroup.id == group_id).one_or_none()
    if group is None:
        raise HTTPException(status_code=404, detail="DoH failover group not found")
    try:
        target = parse_target(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    duplicate = next(
        (item for item in group.origins if item.target == target.value and item.port == payload.port),
        None,
    )
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="The same target and port already exist")
    origin = DohFailoverOrigin(
        group=group,
        target=target.value,
        target_type=target.target_type,
        port=payload.port,
        priority=payload.priority,
        remark=payload.remark.strip() if payload.remark else None,
        enabled=payload.enabled,
        ignore_health_check=payload.ignore_health_check,
    )
    db.add(origin)
    db.commit()
    db.refresh(origin)
    if group.enabled:
        evaluate_doh_failover_groups(db, [group.id])
    db.commit()
    _best_effort_sync(db, {group.doh_endpoint_id})
    db.refresh(origin)
    return origin


@router.patch("/origins/{origin_id}", response_model=DohFailoverOriginOut)
def update_origin(origin_id: int, payload: DohFailoverOriginUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    origin = db.get(DohFailoverOrigin, origin_id)
    if origin is None:
        raise HTTPException(status_code=404, detail="DoH failover target not found")
    updates = payload.model_dump(exclude_unset=True)
    old_target = origin.target
    old_target_type = origin.target_type
    next_target = origin.target
    if "target" in updates:
        try:
            target = parse_target(str(updates["target"]))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        next_target = target.value
        updates["target"] = target.value
        origin.target_type = target.target_type
    next_port = int(updates.get("port", origin.port))
    if any(item.id != origin.id and item.target == next_target and item.port == next_port for item in origin.group.origins):
        raise HTTPException(status_code=409, detail="The same target and port already exist")
    endpoint_changed = next_target != origin.target or next_port != origin.port
    if endpoint_changed and origin.group.current_origin_id == origin.id and not published_ips(origin):
        # Seed last-known-good state for rules created by the first independent-
        # failover release, which did not persist published address metadata.
        if old_target_type != "hostname":
            set_published_ips(origin, [old_target])
    for key, value in updates.items():
        if key == "remark" and isinstance(value, str):
            value = value.strip() or None
        setattr(origin, key, value)
    if endpoint_changed:
        origin.status = "unknown"
        origin.success_count = 0
        origin.fail_count = 0
        origin.last_checked_at = None
        origin.last_error = None
        origin.last_rtt_ms = None
        origin.resolved_ips_json = "[]"
        origin.healthy_ips_json = "[]"
        origin.ip_probe_states_json = "{}"
    if origin.group.current_origin_id == origin.id and updates.get("enabled") is False:
        origin.group.current_origin_id = None
        origin.group.last_switch_at = None
    db.commit()
    evaluate_doh_failover_groups(db, [origin.group_id])
    db.commit()
    _best_effort_sync(db, {origin.group.doh_endpoint_id})
    db.refresh(origin)
    return origin


@router.delete("/origins/{origin_id}", response_model=Message)
def delete_origin(origin_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    origin = db.get(DohFailoverOrigin, origin_id)
    if origin is None:
        raise HTTPException(status_code=404, detail="DoH failover target not found")
    group = origin.group
    was_current = group.current_origin_id == origin.id
    if was_current:
        group.current_origin_id = None
        group.last_switch_at = None
    db.delete(origin)
    db.commit()
    group = _group_query(db).filter(DohFailoverGroup.id == group.id).one()
    if group.enabled and group.origins:
        evaluate_doh_failover_groups(db, [group.id])
    db.commit()
    _best_effort_sync(db, {group.doh_endpoint_id})
    return Message(message="DoH failover target deleted")


@router.post("/groups/{group_id}/run", response_model=Message)
def run_group(group_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(DohFailoverGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="DoH failover group not found")
    if not group.enabled:
        raise HTTPException(status_code=400, detail="Please enable this DoH failover group first")
    switched = evaluate_doh_failover_groups(db, [group_id])
    db.commit()
    return Message(message="DoH failover check completed", detail={"switches": switched})


@router.post("/run", response_model=Message)
def run_all(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    switched = evaluate_doh_failover_groups(db)
    db.commit()
    return Message(message="DoH failover check completed", detail={"switches": switched})
