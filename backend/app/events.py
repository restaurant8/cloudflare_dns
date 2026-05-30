import json
from typing import Any

from sqlalchemy.orm import Session

from .models import Event


def add_event(db: Session, event_type: str, severity: str, message: str, payload: dict[str, Any] | None = None) -> Event:
    event = Event(
        type=event_type,
        severity=severity,
        message=message,
        payload_json=json.dumps(payload or {}, ensure_ascii=False, separators=(",", ":")),
    )
    db.add(event)
    db.flush()
    return event

