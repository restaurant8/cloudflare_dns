import os
import socket
import time
from dataclasses import dataclass
from typing import Optional

import httpx


@dataclass(frozen=True)
class TcpResult:
    success: bool
    rtt_ms: Optional[float]
    error: Optional[str]


def tcp_check(target: str, port: int, timeout: float) -> TcpResult:
    started = time.perf_counter()
    try:
        addresses = socket.getaddrinfo(target, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return TcpResult(False, None, f"resolve failed: {exc}")

    last_error = None
    for family, socktype, proto, _, sockaddr in addresses:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            return TcpResult(True, round((time.perf_counter() - started) * 1000, 2), None)
        except OSError as exc:
            last_error = str(exc)
        finally:
            sock.close()
    return TcpResult(False, round((time.perf_counter() - started) * 1000, 2), last_error or "connect failed")


def main() -> None:
    control_url = os.environ.get("CONTROL_URL", "").rstrip("/")
    token = os.environ.get("AGENT_TOKEN", "")
    default_interval = int(os.environ.get("AGENT_INTERVAL_SECONDS", "30"))
    default_timeout = float(os.environ.get("AGENT_TIMEOUT_SECONDS", "3"))
    if not control_url or not token:
        raise SystemExit("CONTROL_URL and AGENT_TOKEN are required")

    headers = {"X-Agent-Token": token, "User-Agent": "cloudflare-dns-agent/1.0"}
    while True:
        interval = default_interval
        try:
            with httpx.Client(timeout=20, headers=headers) as client:
                tasks_response = client.get(f"{control_url}/api/agent/tasks")
                tasks_response.raise_for_status()
                payload = tasks_response.json()
                interval = int(payload.get("interval_seconds") or default_interval)
                results = []
                for task in payload.get("tasks", []):
                    timeout = float(task.get("timeout_seconds") or default_timeout)
                    result = tcp_check(task["target"], int(task["port"]), timeout)
                    results.append(
                        {
                            "origin_id": task["origin_id"],
                            "target": task["target"],
                            "port": int(task["port"]),
                            "success": result.success,
                            "rtt_ms": result.rtt_ms,
                            "error": result.error,
                        }
                    )
                client.post(f"{control_url}/api/agent/results", json={"results": results}).raise_for_status()
        except Exception as exc:
            print(f"agent loop failed: {exc}", flush=True)
        time.sleep(max(interval, 5))


if __name__ == "__main__":
    main()
