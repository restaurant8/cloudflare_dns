"""Relay backends: the B machines an origin (A) forwards to in an A → B → C chain.

A relay program on A accepts connections locally and only then dials B, so a TCP
check of A keeps passing after every B has died while the chain is broken. The B
machines live in IP pools (``TargetPool``); an origin or global backup references
pools, so one pool edit reaches every domain using it. The panel checks pool
addresses itself (B is often unreachable from China by design), and an otherwise
healthy origin counts as ``relay_down`` only when *all* addresses of its selected
pools are down — several Bs are a load-balanced set, one working B keeps the
chain up.

Each address follows the same fail / recovery thresholds as the origin probes, so
a single lost packet never moves traffic.
"""

import json
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session, object_session

from .models import TargetPool, TargetPoolItem


RELAY_DOWN_STATUS = "relay_down"
RELAY_UP_STATUS = "healthy"
RELAY_FAILED_STATUS = "unhealthy"
MAX_RELAY_POOLS = 20


def relay_pool_ids(owner: Any) -> list[int]:
    try:
        values = json.loads(getattr(owner, "relay_pool_ids_json", None) or "[]")
    except (TypeError, ValueError):
        return []
    if not isinstance(values, list):
        return []
    result: list[int] = []
    for value in values:
        try:
            pool_id = int(value)
        except (TypeError, ValueError):
            continue
        if pool_id not in result:
            result.append(pool_id)
    return result


def set_relay_pool_ids(owner: Any, pool_ids: list[int] | None) -> bool:
    """Store the selected pools (order kept, duplicates dropped); return True on change."""
    normalized: list[int] = []
    for value in pool_ids or []:
        pool_id = int(value)
        if pool_id not in normalized:
            normalized.append(pool_id)
    if len(normalized) > MAX_RELAY_POOLS:
        raise ValueError(f"中转池最多选 {MAX_RELAY_POOLS} 个")
    encoded = json.dumps(normalized, separators=(",", ":"))
    if (getattr(owner, "relay_pool_ids_json", None) or "[]") == encoded:
        return False
    owner.relay_pool_ids_json = encoded
    return True


def _session(owner: Any, db: Session | None) -> Session | None:
    return db if db is not None else object_session(owner)


def relay_items(owner: Any, db: Session | None = None) -> list[TargetPoolItem]:
    """Enabled addresses of the owner's selected pools."""
    pool_ids = relay_pool_ids(owner)
    session = _session(owner, db)
    if not pool_ids or session is None:
        return []
    return (
        session.query(TargetPoolItem)
        .filter(TargetPoolItem.pool_id.in_(pool_ids), TargetPoolItem.enabled.is_(True))
        .order_by(TargetPoolItem.pool_id, TargetPoolItem.id)
        .all()
    )


def relay_overview(owner: Any, db: Session | None = None) -> list[dict[str, Any]]:
    """Selected pool addresses with their check state, for the API."""
    session = _session(owner, db)
    pool_ids = relay_pool_ids(owner)
    if not pool_ids or session is None:
        return []
    names = {pool.id: pool.name for pool in session.query(TargetPool).filter(TargetPool.id.in_(pool_ids)).all()}
    return [
        {
            "pool_id": item.pool_id,
            "pool_name": names.get(item.pool_id),
            "target": item.target,
            "port": item.port,
            "status": item.status if item.status in {RELAY_UP_STATUS, RELAY_FAILED_STATUS} else "unknown",
            "last_checked_at": item.last_checked_at.isoformat() if item.last_checked_at else None,
            "last_error": item.last_error,
            "last_rtt_ms": item.last_rtt_ms,
        }
        for item in relay_items(owner, session)
    ]


def relay_verdict(owner: Any, db: Session | None = None) -> str:
    """``none`` (no addresses), ``up`` (one works), ``down`` (all down) or ``unknown``."""
    items = relay_items(owner, db)
    if not items:
        return "none"
    statuses = {item.status for item in items}
    if RELAY_UP_STATUS in statuses:
        return "up"
    if statuses == {RELAY_FAILED_STATUS}:
        return "down"
    return "unknown"


def apply_relay_verdict(origin: Any, db: Session | None = None) -> None:
    """Demote a healthy origin whose every relay address is down.

    Only a healthy origin is touched: a blocked A must keep its "blocked" status so
    the automatic IP change still fires, and a down A is down regardless of B.
    """
    if origin.status != "healthy" or relay_verdict(origin, db) != "down":
        return
    down = ", ".join(f"{item.target}:{item.port}" for item in relay_items(origin, db))
    origin.status = RELAY_DOWN_STATUS
    origin.last_error = f"本机正常，但中转后端全部不通：{down}"


def record_pool_item_result(
    item: TargetPoolItem,
    success: bool,
    rtt_ms: float | None,
    error: str | None,
    *,
    fail_threshold: int,
    recovery_threshold: int,
    now: datetime | None = None,
) -> None:
    if success:
        item.success_count = int(item.success_count or 0) + 1
        item.fail_count = 0
        # A new address is trusted on its first answer; a failed one must recover.
        if item.status not in {RELAY_UP_STATUS, RELAY_FAILED_STATUS} or item.success_count >= max(recovery_threshold, 1):
            item.status = RELAY_UP_STATUS
        item.last_error = None
    else:
        item.fail_count = int(item.fail_count or 0) + 1
        item.success_count = 0
        if item.fail_count >= max(fail_threshold, 1):
            item.status = RELAY_FAILED_STATUS
        item.last_error = error or "连接失败"
    item.last_checked_at = now or datetime.utcnow()
    item.last_rtt_ms = rtt_ms
