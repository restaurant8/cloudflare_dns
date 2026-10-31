"""Relay backends: the B machines an origin (A) forwards to in an A → B → C chain.

A relay program on A accepts connections locally and only then dials B, so a TCP
check of A keeps passing after every B has died while the chain is broken. An
origin can therefore list its relay backends; the panel checks them itself (B is
often unreachable from China by design) and an otherwise healthy origin counts as
``relay_down`` only when *all* of them are down — several Bs are a load-balanced
pool, one working B keeps the chain up.

Each backend follows the same fail / recovery thresholds as the origin probes, so
a single lost packet never moves traffic.
"""

import json
from datetime import datetime
from typing import Any

from .dns_utils import parse_target


RELAY_DOWN_STATUS = "relay_down"
MAX_RELAY_TARGETS = 20


def relay_key(target: str, port: int) -> str:
    return f"{target}|{int(port)}"


def normalize_relay_targets(values: list[Any] | None) -> list[dict[str, Any]]:
    """Validate and dedupe ``[{"target", "port"}]``; raise ValueError on bad input."""
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in values or []:
        if isinstance(value, dict):
            raw_target, raw_port = value.get("target"), value.get("port")
        else:
            raw_target, raw_port = getattr(value, "target", None), getattr(value, "port", None)
        target_info = parse_target(str(raw_target or "").strip())
        port = int(raw_port)
        if not 1 <= port <= 65535:
            raise ValueError(f"中转后端端口无效：{raw_port}")
        key = relay_key(target_info.value, port)
        if key in seen:
            continue
        seen.add(key)
        result.append({"target": target_info.value, "port": port})
    if len(result) > MAX_RELAY_TARGETS:
        raise ValueError(f"中转后端最多 {MAX_RELAY_TARGETS} 个")
    return result


def relay_targets(owner: Any) -> list[dict[str, Any]]:
    try:
        values = json.loads(getattr(owner, "relay_targets_json", None) or "[]")
    except (TypeError, ValueError):
        return []
    if not isinstance(values, list):
        return []
    targets = []
    for value in values:
        if isinstance(value, dict) and value.get("target") and value.get("port"):
            targets.append({"target": str(value["target"]), "port": int(value["port"])})
    return targets


def set_relay_targets(owner: Any, values: list[Any] | None) -> bool:
    """Store the configuration; return True when it changed."""
    normalized = normalize_relay_targets(values)
    encoded = json.dumps(normalized, separators=(",", ":"))
    if (getattr(owner, "relay_targets_json", None) or "[]") == encoded:
        return False
    owner.relay_targets_json = encoded
    if hasattr(owner, "relay_status_json"):
        states = _relay_states(owner)
        keep = {relay_key(item["target"], item["port"]) for item in normalized}
        owner.relay_status_json = json.dumps({key: value for key, value in states.items() if key in keep}, separators=(",", ":"))
    return True


def _relay_states(origin: Any) -> dict[str, dict[str, Any]]:
    try:
        states = json.loads(getattr(origin, "relay_status_json", None) or "{}")
    except (TypeError, ValueError):
        return {}
    return states if isinstance(states, dict) else {}


def record_relay_result(
    origin: Any,
    target: str,
    port: int,
    success: bool,
    rtt_ms: float | None,
    error: str | None,
    *,
    fail_threshold: int,
    recovery_threshold: int,
    now: datetime | None = None,
) -> None:
    states = _relay_states(origin)
    key = relay_key(target, port)
    state = states.get(key) if isinstance(states.get(key), dict) else {}
    status = state.get("status") or "unknown"
    if success:
        successes = int(state.get("successes") or 0) + 1
        fails = 0
        # A new backend is trusted on its first answer; a failed one must recover.
        if status == "unknown" or successes >= max(recovery_threshold, 1):
            status = "up"
    else:
        fails = int(state.get("fails") or 0) + 1
        successes = 0
        if fails >= max(fail_threshold, 1):
            status = "down"
    states[key] = {
        "status": status,
        "fails": fails,
        "successes": successes,
        "last_checked_at": (now or datetime.utcnow()).isoformat(),
        "last_error": None if success else (error or "连接失败"),
        "last_rtt_ms": rtt_ms,
    }
    origin.relay_status_json = json.dumps(states, separators=(",", ":"))


def relay_overview(origin: Any) -> list[dict[str, Any]]:
    """Configured backends with their current check state, for the API."""
    states = _relay_states(origin)
    items = []
    for item in relay_targets(origin):
        state = states.get(relay_key(item["target"], item["port"])) or {}
        items.append(
            {
                "target": item["target"],
                "port": item["port"],
                "status": state.get("status") or "unknown",
                "last_checked_at": state.get("last_checked_at"),
                "last_error": state.get("last_error"),
                "last_rtt_ms": state.get("last_rtt_ms"),
            }
        )
    return items


def relay_verdict(origin: Any) -> str:
    """``none`` (no backends), ``up`` (one works), ``down`` (all down) or ``unknown``."""
    overview = relay_overview(origin)
    if not overview:
        return "none"
    statuses = {item["status"] for item in overview}
    if "up" in statuses:
        return "up"
    if statuses == {"down"}:
        return "down"
    return "unknown"


def apply_relay_verdict(origin: Any) -> None:
    """Demote a healthy origin whose every relay backend is down.

    Only a healthy origin is touched: a blocked A must keep its "blocked" status so
    the automatic IP change still fires, and a down A is down regardless of B.
    """
    if origin.status != "healthy" or relay_verdict(origin) != "down":
        return
    down = ", ".join(f"{item['target']}:{item['port']}" for item in relay_overview(origin))
    origin.status = RELAY_DOWN_STATUS
    origin.last_error = f"本机正常，但中转后端全部不通：{down}"
