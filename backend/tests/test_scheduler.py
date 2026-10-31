"""The scheduler tick must keep running failover when another stage breaks."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main
from app.database import Base


def test_one_failing_stage_does_not_stop_failover(monkeypatch):
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(main, "SessionLocal", sessionmaker(bind=engine, future=True))
    ran = []

    def broken(*_args, **_kwargs):
        ran.append("external_ip_sync")
        raise RuntimeError("nyanpass unreachable")

    def record(name):
        return lambda *_args, **_kwargs: ran.append(name)

    monkeypatch.setattr(main, "mark_stale_agents", record("agents"))
    monkeypatch.setattr(main, "run_local_checks", record("checks"))
    monkeypatch.setattr(main, "reconcile_pending_custom_changes", record("reconcile"))
    monkeypatch.setattr(main, "auto_sync_custom_statuses", record("status_sync"))
    monkeypatch.setattr(main, "sync_due_external_ip_sources", broken)
    monkeypatch.setattr(main, "evaluate_failover_groups", record("failover"))
    monkeypatch.setattr(main, "reconcile_route53_outputs", record("route53"))
    monkeypatch.setattr(main, "evaluate_alibaba_httpdns_groups", record("alibaba"))
    monkeypatch.setattr(main, "sync_due_doh_endpoints", record("doh"))
    monkeypatch.setattr(main, "prune_old_rows", record("prune"))

    interval = main._run_scheduler_tick()

    assert interval > 0
    assert ran[ran.index("external_ip_sync") + 1 :][:4] == ["failover", "route53", "alibaba", "doh"]


def test_sqlite_connections_use_wal(tmp_path):
    import sqlite3

    from app.database import _sqlite_concurrency

    connection = sqlite3.connect(tmp_path / "app.db")
    _sqlite_concurrency(connection, None)
    assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    connection.close()
