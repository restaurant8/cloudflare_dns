"""Load balancing by rotating the selected origin within one priority tier.

With load balancing enabled on a group, the healthy origins that share the best
priority take turns as the published origin: every rotation interval the engine
switches to the next one, chosen by smooth weighted round-robin. Lower
priorities remain pure failover backups.

Only *which* origin is selected changes. Every output channel still publishes a
single selected origin through the existing switch path, so IPs and hostnames
(CNAME) both work and no provider-specific feature is needed.
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


def load_balance_tier(group: Any, origin: Any) -> list[Any]:
    """Available origins sharing ``origin``'s priority, oldest first."""
    if origin is None:
        return []
    return sorted(
        (item for item in group.origins if item.priority == origin.priority and origin_is_available(item)),
        key=lambda item: item.id,
    )


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


def choose_load_balanced_origin(group: Any, desired: Any, now: datetime) -> tuple[Any, bool]:
    """Return ``(origin, rotated)`` for a group whose priority choice is ``desired``.

    ``rotated`` is True only for a routine turn away from a still-healthy current
    origin; replacing a failed origin or returning from a lower priority is an
    ordinary failover and keeps its normal reason and notifications.
    """
    if desired is None or not getattr(group, "load_balance_enabled", False):
        return desired, False
    tier = load_balance_tier(group, desired)
    if len(tier) < 2:
        return desired, False
    current = next((item for item in tier if item.id == group.current_origin_id), None)
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
    for item in tier:
        try:
            current_weights[str(item.id)] = int(raw_weights.get(str(item.id), 0))
        except (TypeError, ValueError):
            current_weights[str(item.id)] = 0
    total = sum(origin_weight(item) for item in tier)
    for item in tier:
        current_weights[str(item.id)] += origin_weight(item)
    chosen = max(tier, key=lambda item: (current_weights[str(item.id)], -item.id))
    current_weights[str(chosen.id)] -= total
    group.load_balance_state_json = json.dumps(
        {"current_weights": current_weights, "rotated_at": now.isoformat()},
        sort_keys=True,
        separators=(",", ":"),
    )
    return chosen, current is not None and chosen.id != current.id
