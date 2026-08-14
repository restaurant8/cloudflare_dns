import threading
import time

import pytest

from app import dns_resolution


@pytest.fixture(autouse=True)
def clean_resolution_state():
    dns_resolution.clear_resolution_cache()
    with dns_resolution._LOCK:
        dns_resolution._IN_FLIGHT.clear()
    yield
    dns_resolution.clear_resolution_cache()


def test_negative_cache_prevents_repeated_resolution_work(monkeypatch):
    calls = []

    def fail(hostname, timeout):
        calls.append((hostname, timeout))
        raise TimeoutError("slow resolver")

    monkeypatch.setattr(dns_resolution, "_run_resolution_process", fail)
    for _ in range(5):
        with pytest.raises(RuntimeError, match="slow resolver"):
            dns_resolution.resolve_hostname_ips_bounded("slow.example", 0.1)
    assert len(calls) == 1


def test_same_hostname_uses_one_inflight_resolution(monkeypatch):
    release = threading.Event()
    calls = []

    def resolve(hostname, timeout):
        calls.append(hostname)
        release.wait(1)
        return ["203.0.113.10"]

    monkeypatch.setattr(dns_resolution, "_run_resolution_process", resolve)
    results = []
    threads = [
        threading.Thread(
            target=lambda: results.append(dns_resolution.resolve_hostname_ips_bounded("same.example", 1))
        )
        for _ in range(5)
    ]
    for thread in threads:
        thread.start()
    time.sleep(0.05)
    release.set()
    for thread in threads:
        thread.join()

    assert calls == ["same.example"]
    assert results == [["203.0.113.10"]] * 5


def test_short_timeout_waiter_uses_existing_owner_deadline(monkeypatch):
    started = threading.Event()
    release = threading.Event()
    owner_result = []

    def resolve(_hostname, _timeout):
        started.set()
        release.wait(1)
        return ["203.0.113.30"]

    monkeypatch.setattr(dns_resolution, "_run_resolution_process", resolve)
    owner = threading.Thread(
        target=lambda: owner_result.append(
            dns_resolution.resolve_hostname_ips_bounded("shared.example", 0.5)
        )
    )
    owner.start()
    assert started.wait(0.2)
    timer = threading.Timer(0.15, release.set)
    timer.start()

    # This caller's 20 ms timeout must not turn the owner's still-valid lookup
    # into a false DNS failure.
    assert dns_resolution.resolve_hostname_ips_bounded("shared.example", 0.02) == ["203.0.113.30"]
    owner.join()
    timer.join()
    assert owner_result == [["203.0.113.30"]]


def test_slow_hostname_does_not_starve_unrelated_hostname(monkeypatch):
    release = threading.Event()

    def resolve(hostname, timeout):
        if hostname == "slow.example":
            release.wait(1)
            return ["198.51.100.1"]
        return ["203.0.113.20"]

    monkeypatch.setattr(dns_resolution, "_run_resolution_process", resolve)
    slow = threading.Thread(
        target=lambda: dns_resolution.resolve_hostname_ips_bounded("slow.example", 1)
    )
    slow.start()
    time.sleep(0.05)

    started = time.monotonic()
    assert dns_resolution.resolve_hostname_ips_bounded("fast.example", 0.2) == ["203.0.113.20"]
    assert time.monotonic() - started < 0.1
    release.set()
    slow.join()


def test_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(dns_resolution, "_MAX_CACHE_ENTRIES", 3)
    monkeypatch.setattr(
        dns_resolution,
        "_run_resolution_process",
        lambda hostname, timeout: [f"192.0.2.{int(hostname.split('.')[0]) + 1}"],
    )
    for index in range(5):
        dns_resolution.resolve_hostname_ips_bounded(f"{index}.example", 0.1)
    assert len(dns_resolution._CACHE) == 3
