import importlib.util
import sys
import threading
from pathlib import Path

import pytest


@pytest.fixture
def probe_agent():
    source_path = Path(__file__).resolve().parents[2] / "agent" / "agent.py"
    spec = importlib.util.spec_from_file_location("probe_agent_for_tests", source_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    try:
        yield module
    finally:
        sys.modules.pop(spec.name, None)


def task(index):
    return {
        "origin_id": index,
        "target": f"192.0.2.{index}",
        "port": 443,
        "timeout_seconds": 3,
    }


def test_run_probe_tasks_executes_checks_concurrently(probe_agent, monkeypatch):
    worker_count = 4
    barrier = threading.Barrier(worker_count)

    def fake_tcp_check(target, port, timeout):
        barrier.wait(timeout=2)
        return probe_agent.TcpResult(True, 1.0, None)

    monkeypatch.setattr(probe_agent, "tcp_check", fake_tcp_check)

    results = probe_agent.run_probe_tasks(
        [task(index) for index in range(1, worker_count + 1)],
        default_timeout=3,
        max_workers=worker_count,
    )

    assert len(results) == worker_count
    assert all(result["success"] for result in results)


def test_run_probe_tasks_returns_one_complete_batch(probe_agent, monkeypatch):
    monkeypatch.setattr(
        probe_agent,
        "tcp_check",
        lambda target, port, timeout: probe_agent.TcpResult(True, 1.0, None),
    )
    results = probe_agent.run_probe_tasks(
        [task(index) for index in range(1, 6)],
        default_timeout=3,
        max_workers=2,
    )

    assert len(results) == 5
    assert {result["origin_id"] for result in results} == {1, 2, 3, 4, 5}


def test_probe_task_turns_unexpected_errors_into_results(probe_agent, monkeypatch):
    def broken_tcp_check(target, port, timeout):
        raise RuntimeError("socket setup failed")

    monkeypatch.setattr(probe_agent, "tcp_check", broken_tcp_check)

    result = probe_agent.probe_task(task(1), default_timeout=3)

    assert result["success"] is False
    assert result["rtt_ms"] is None
    assert result["error"] == "probe failed: socket setup failed"


def test_run_probe_tasks_skips_malformed_task_without_aborting_batch(probe_agent, monkeypatch, capsys):
    monkeypatch.setattr(
        probe_agent,
        "tcp_check",
        lambda target, port, timeout: probe_agent.TcpResult(True, 1.0, None),
    )

    results = probe_agent.run_probe_tasks([task(1), {"target": "192.0.2.2"}], 3, 2)

    assert [result["origin_id"] for result in results] == [1]
    assert "invalid probe task skipped" in capsys.readouterr().out


def test_run_probe_tasks_handles_empty_tasks_and_worker_limits(probe_agent):
    assert probe_agent.run_probe_tasks([], 3, 0) == []
    assert probe_agent.run_probe_tasks(None, 3, -1) == []
    assert probe_agent.normalized_worker_count(0, 10) == 1
    assert probe_agent.normalized_worker_count(-5, 10) == 1
    assert probe_agent.normalized_worker_count(1000, 1000) == 64
    assert probe_agent.normalized_worker_count(16, 3) == 3


def test_agent_interval_subtracts_round_duration_and_backs_off_after_overrun(probe_agent):
    assert probe_agent.remaining_interval_seconds(30, 4.5) == 25.5
    assert probe_agent.remaining_interval_seconds(30, 45) == 1.0


def test_controller_interval_is_clamped_and_invalid_values_use_default(probe_agent, capsys):
    assert probe_agent.controller_interval_seconds(30, 20) == 30
    assert probe_agent.controller_interval_seconds(0, 20) == 20
    assert probe_agent.controller_interval_seconds(-5, 20) == 5
    assert probe_agent.controller_interval_seconds(5000, 20) == 3600
    assert probe_agent.controller_interval_seconds("abc", 20) == 20
    assert "using 20" in capsys.readouterr().out


def test_invalid_worker_environment_uses_safe_default(probe_agent, monkeypatch, capsys):
    monkeypatch.setenv("AGENT_MAX_WORKERS", "many")

    assert probe_agent.env_int("AGENT_MAX_WORKERS", 16, 1, 64) == 16
    assert "using 16" in capsys.readouterr().out


def test_tcp_rtt_excludes_dns_and_previous_failed_address(probe_agent, monkeypatch):
    addresses = [
        (probe_agent.socket.AF_INET6, probe_agent.socket.SOCK_STREAM, 6, "", ("2001:db8::1", 443, 0, 0)),
        (probe_agent.socket.AF_INET, probe_agent.socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443)),
    ]
    monkeypatch.setattr(probe_agent.socket, "getaddrinfo", lambda *args, **kwargs: addresses)

    class FakeSocket:
        attempts = 0

        def settimeout(self, timeout):
            pass

        def connect(self, sockaddr):
            FakeSocket.attempts += 1
            if FakeSocket.attempts == 1:
                raise OSError("IPv6 timeout")

        def close(self):
            pass

    monkeypatch.setattr(probe_agent.socket, "socket", lambda *args: FakeSocket())
    timestamps = iter([10.0, 13.0, 20.0, 20.03])
    monkeypatch.setattr(probe_agent.time, "perf_counter", lambda: next(timestamps))

    result = probe_agent.tcp_check("example.com", 443, 3)

    assert result.success is True
    assert result.rtt_ms == 30.0
