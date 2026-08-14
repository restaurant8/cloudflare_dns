import ipaddress
import json
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass


_POSITIVE_TTL_SECONDS = 30.0
_NEGATIVE_TTL_SECONDS = 5.0
_MAX_CACHE_ENTRIES = 1024


@dataclass
class _CacheEntry:
    expires_at: float
    addresses: list[str]
    error: str | None = None


@dataclass
class _InFlight:
    event: threading.Event
    deadline: float


_CACHE: OrderedDict[str, _CacheEntry] = OrderedDict()
_IN_FLIGHT: dict[str, _InFlight] = {}
_LOCK = threading.Lock()


_RESOLVER_SCRIPT = r"""
import ipaddress
import json
import socket
import sys

hostname = sys.argv[1]
addresses = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
values = set()
for family, _, _, _, sockaddr in addresses:
    if family not in (socket.AF_INET, socket.AF_INET6):
        continue
    try:
        values.add(str(ipaddress.ip_address(sockaddr[0])))
    except ValueError:
        pass
ordered = sorted(values, key=lambda item: (ipaddress.ip_address(item).version, ipaddress.ip_address(item)))
sys.stdout.write(json.dumps(ordered, separators=(",", ":")))
"""


def _run_resolution_process(hostname: str, timeout_seconds: float) -> list[str]:
    """Run libc name resolution in a process that can actually be terminated."""
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        completed = subprocess.run(
            [sys.executable, "-c", _RESOLVER_SCRIPT, hostname],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            creationflags=creationflags,
        )
    except subprocess.TimeoutExpired as exc:
        # subprocess.run kills and waits for the child on timeout. Unlike
        # Future.cancel(), no blocked getaddrinfo worker is left behind.
        raise TimeoutError(f"DNS resolution timed out for {hostname}") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "DNS resolution failed").strip()
        raise RuntimeError(f"DNS resolution failed for {hostname}: {detail}") from exc

    try:
        values = json.loads(completed.stdout)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"DNS resolver returned invalid data for {hostname}") from exc
    if not isinstance(values, list):
        raise RuntimeError(f"DNS resolver returned invalid data for {hostname}")
    addresses: set[str] = set()
    for value in values:
        try:
            addresses.add(str(ipaddress.ip_address(str(value))))
        except ValueError:
            continue
    return sorted(addresses, key=lambda item: (ipaddress.ip_address(item).version, ipaddress.ip_address(item)))


def _prune_cache(now: float) -> None:
    expired = [key for key, entry in _CACHE.items() if entry.expires_at <= now]
    for key in expired:
        _CACHE.pop(key, None)
    while len(_CACHE) > _MAX_CACHE_ENTRIES:
        _CACHE.popitem(last=False)


def _read_cache(key: str, now: float) -> list[str] | None:
    entry = _CACHE.get(key)
    if entry is None or entry.expires_at <= now:
        _CACHE.pop(key, None)
        return None
    _CACHE.move_to_end(key)
    if entry.error:
        raise RuntimeError(entry.error)
    return list(entry.addresses)


def resolve_hostname_ips_bounded(hostname: str, timeout_seconds: float) -> list[str]:
    """Resolve a hostname with hard timeout, single-flight, and bounded caches.

    Each actual lookup is an independently killable child process, so a slow
    system resolver cannot consume a permanent worker or starve unrelated names.
    Concurrent callers for the same name share one in-flight lookup. Failures are
    briefly cached to prevent every scheduler tick or API request from spawning
    duplicate work.
    """
    key = hostname.strip().rstrip(".").lower()
    if not key:
        raise ValueError("DNS hostname is required")
    timeout = max(float(timeout_seconds), 0.1)
    owner = False
    with _LOCK:
        now = time.monotonic()
        _prune_cache(now)
        cached = _read_cache(key, now)
        if cached is not None:
            return cached
        flight = _IN_FLIGHT.get(key)
        if flight is None:
            flight = _InFlight(event=threading.Event(), deadline=now + timeout)
            _IN_FLIGHT[key] = flight
            owner = True

    if not owner:
        # The lookup already has one owner and one real deadline. A caller with a
        # shorter local timeout must not reinterpret that shared work as a DNS
        # failure and increment origin fail counters. Wait for the owner's hard
        # subprocess timeout (plus a small kill/wait cleanup margin), then consume
        # the same positive or negative cache entry as every other waiter.
        remaining = max(flight.deadline - time.monotonic(), 0.0)
        flight.event.wait(remaining + 1.0)
        with _LOCK:
            cached = _read_cache(key, time.monotonic())
            if cached is None:
                current = _IN_FLIGHT.get(key)
                if current is flight:
                    raise TimeoutError(f"DNS resolution did not finish by its owner deadline for {hostname}")
                raise RuntimeError(f"DNS resolution failed for {hostname}")
            return cached

    try:
        addresses = _run_resolution_process(key, timeout)
        entry = _CacheEntry(
            expires_at=time.monotonic() + _POSITIVE_TTL_SECONDS,
            addresses=addresses,
        )
    except Exception as exc:
        entry = _CacheEntry(
            expires_at=time.monotonic() + _NEGATIVE_TTL_SECONDS,
            addresses=[],
            error=str(exc),
        )
    finally:
        with _LOCK:
            _CACHE[key] = entry
            _CACHE.move_to_end(key)
            _prune_cache(time.monotonic())
            _IN_FLIGHT.pop(key, None)
            flight.event.set()

    if entry.error:
        raise RuntimeError(entry.error)
    return list(entry.addresses)


def clear_resolution_cache() -> None:
    """Clear completed entries; primarily useful for tests and explicit reloads."""
    with _LOCK:
        _CACHE.clear()
