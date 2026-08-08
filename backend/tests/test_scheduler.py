from datetime import datetime
from types import SimpleNamespace

from app import main
from app.health import refresh_expanded_origin_ips
from app.models import Origin
from app.origin_expansion import EXPANDED_PUBLISH_MODE


class FakeSession:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def commit(self):
        pass


def test_scheduler_tick_reuses_dns_cache_during_failover_evaluation(monkeypatch):
    db = FakeSession()
    origin = Origin(
        target="pool.example.net",
        target_type="hostname",
        publish_mode=EXPANDED_PUBLISH_MODE,
        port=443,
    )
    resolution_attempts = []
    cache_ids = []

    def fake_resolve(hostname):
        resolution_attempts.append(hostname)
        return ["192.0.2.70"]

    def fake_run_local_checks(db_arg, check_cache=None, dns_cache=None):
        cache_ids.append((id(check_cache), id(dns_cache)))
        refresh_expanded_origin_ips(origin, dns_cache=dns_cache)
        return 1

    def fake_evaluate_failover_groups(db_arg, **kwargs):
        cache_ids.append((id(kwargs["check_cache"]), id(kwargs["dns_cache"])))
        refresh_expanded_origin_ips(origin, dns_cache=kwargs["dns_cache"])
        return 0

    monkeypatch.setattr(main, "SessionLocal", lambda: db)
    monkeypatch.setattr(main, "get_runtime_settings", lambda db_arg: SimpleNamespace(check_interval_seconds=30))
    monkeypatch.setattr(main, "get_settings", lambda: SimpleNamespace(dns_consistency_check_interval_seconds=300))
    monkeypatch.setattr(main, "mark_stale_agents", lambda db_arg: 0)
    monkeypatch.setattr(main, "run_local_checks", fake_run_local_checks)
    monkeypatch.setattr(main, "reconcile_pending_synexvm_changes", lambda db_arg: 0)
    monkeypatch.setattr(main, "auto_sync_synexvm_statuses", lambda db_arg: 0)
    monkeypatch.setattr(main, "sync_due_external_ip_sources", lambda db_arg: 0)
    monkeypatch.setattr(main, "evaluate_failover_groups", fake_evaluate_failover_groups)
    monkeypatch.setattr(main, "prune_old_rows", lambda db_arg: None)
    monkeypatch.setattr("app.health.resolve_hostname_ips", fake_resolve)
    monkeypatch.setattr(main, "_last_prune_at", datetime.utcnow())

    assert main._run_scheduler_tick() == 30
    assert resolution_attempts == ["pool.example.net"]
    assert cache_ids[0] == cache_ids[1]
