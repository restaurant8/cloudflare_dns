"""Load balancing inside one failover node.

A node is a top-level origin plus the load addresses attached to it
(``Origin.load_parent_id``). Priorities, failover and time rules choose a node;
while a node is selected its healthy addresses take turns as the published
origin, switching once per rotation interval by smooth weighted round-robin.
A node without load addresses behaves exactly like a plain origin.

Every address is still an ordinary Origin: it has its own health checks, IP
rotation bindings and publishing. Output channels always publish one selected
address, so IPs and hostnames (CNAME) both work.
"""

import json
from datetime import datetime
from typing import Any

from .health import ORIGIN_AVAILABLE_STATUS


DEFAULT_ROTATION_INTERVAL_SECONDS = 120
MIN_ROTATION_INTERVAL_SECONDS = 30


def origin_is_available(origin: Any) -> bool:
    return bool(
        origin is not None
        and origin.enabled
        and (origin.ignore_health_check or origin.status == ORIGIN_AVAILABLE_STATUS)
    )


def origin_weight(origin: Any) -> int:
    try:
        value = int(getattr(origin, "weight", 1) or 1)
    except (TypeError, ValueError):
        value = 1
    return min(max(value, 1), 100)


def is_load_member(origin: Any) -> bool:
    return getattr(origin, "load_parent_id", None) is not None


def node_members(origins: list[Any], node: Any) -> list[Any]:
    """The node itself followed by its load addresses (oldest first)."""
    if node is None:
        return []
    children = sorted(
        (item for item in origins if getattr(item, "load_parent_id", None) == node.id),
        key=lambda item: item.id,
    )
    return [node, *children]


def node_of(origins: list[Any], origin: Any) -> Any:
    if origin is None or not is_load_member(origin):
        return origin
    return next((item for item in origins if item.id == origin.load_parent_id), origin)


def available_members(origins: list[Any], node: Any) -> list[Any]:
    """Addresses of an enabled node that can serve traffic right now."""
    if node is None or not node.enabled:
        return []
    return [item for item in node_members(origins, node) if origin_is_available(item)]


def node_is_available(origins: list[Any], node: Any) -> bool:
    return bool(available_members(origins, node))


def _load_state(group: Any) -> dict[str, Any]:
    try:
        state = json.loads(getattr(group, "load_balance_state_json", None) or "{}")
    except (TypeError, ValueError):
        return {}
    return state if isinstance(state, dict) else {}


def rotation_interval_seconds(group: Any) -> int:
    try:
        value = int(getattr(group, "load_balance_interval_seconds", None) or DEFAULT_ROTATION_INTERVAL_SECONDS)
    except (TypeError, ValueError):
        value = DEFAULT_ROTATION_INTERVAL_SECONDS
    return max(value, MIN_ROTATION_INTERVAL_SECONDS)


def choose_node_member(group: Any, node: Any, now: datetime) -> tuple[Any, bool]:
    """Return ``(address, rotated)`` to publish for the selected ``node``.

    ``rotated`` is True only for a routine turn away from a still-healthy current
    address. Replacing a failed address or arriving from another node is an
    ordinary failover and keeps its normal reason and notifications.
    """
    members = available_members(group.origins, node)
    if len(node_members(group.origins, node)) < 2 or not members:
        return node, False
    if len(members) == 1:
        return members[0], False
    current = next((item for item in members if item.id == group.current_origin_id), None)
    state = _load_state(group)
    rotated_at = None
    if state.get("rotated_at"):
        try:
            rotated_at = datetime.fromisoformat(str(state["rotated_at"]))
        except ValueError:
            rotated_at = None
    due = rotated_at is None or (now - rotated_at).total_seconds() >= rotation_interval_seconds(group)
    if current is not None and not due:
        return current, False

    # Smooth weighted round-robin: weights 1:1:3 give C, A, C, B, C, ...
    raw_weights = state.get("current_weights") if isinstance(state.get("current_weights"), dict) else {}
    current_weights: dict[str, int] = {}
    for item in members:
        try:
            current_weights[str(item.id)] = int(raw_weights.get(str(item.id), 0))
        except (TypeError, ValueError):
            current_weights[str(item.id)] = 0
    total = sum(origin_weight(item) for item in members)
    for item in members:
        current_weights[str(item.id)] += origin_weight(item)
    chosen = max(members, key=lambda item: (current_weights[str(item.id)], -item.id))
    current_weights[str(chosen.id)] -= total
    group.load_balance_state_json = json.dumps(
        {"current_weights": current_weights, "rotated_at": now.isoformat()},
        sort_keys=True,
        separators=(",", ":"),
    )
    return chosen, current is not None and chosen.id != current.id
