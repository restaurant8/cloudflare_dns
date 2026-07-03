"""Retention pruning for unbounded, high-volume tables.

ProbeResult grows by one row per probe per source (local + every agent + every
expanded IP) every check interval; Event and IpChangeJob grow on every state
change. Without pruning a 30s interval deployment accumulates tens of thousands
of rows per day and the SQLite file grows forever.
"""
import logging
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from .config import get_settings
from .models import Event, IpChangeJob, ProbeResult


logger = logging.getLogger(__name__)


def prune_old_rows(db: Session) -> dict[str, int]:
    settings = get_settings()
    now = datetime.utcnow()
    deleted: dict[str, int] = {}

    deleted["probe_results"] = (
        db.query(ProbeResult)
        .filter(ProbeResult.created_at < now - timedelta(days=settings.probe_result_retention_days))
        .delete(synchronize_session=False)
    )
    deleted["events"] = (
        db.query(Event)
        .filter(Event.created_at < now - timedelta(days=settings.event_retention_days))
        .delete(synchronize_session=False)
    )
    deleted["ip_change_jobs"] = (
        db.query(IpChangeJob)
        .filter(IpChangeJob.created_at < now - timedelta(days=settings.ip_change_job_retention_days))
        .delete(synchronize_session=False)
    )

    total = sum(deleted.values())
    if total:
        logger.info("retention prune removed %s rows: %s", total, deleted)
    return deleted
