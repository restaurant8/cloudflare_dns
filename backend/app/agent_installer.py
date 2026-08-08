from pathlib import Path


EMBEDDED_AGENT_SOURCE = r'''import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional

import httpx


@dataclass(frozen=True)
class TcpResult:
    success: bool
    rtt_ms: Optional[float]
    error: Optional[str]


MAX_AGENT_WORKERS = 64
RESULT_POST_TIMEOUT_SECONDS = 40.0


def tcp_check(target: str, port: int, timeout: float) -> TcpResult:
    try:
        addresses = socket.getaddrinfo(target, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return TcpResult(False, None, f"resolve failed: {exc}")

    last_error = None
    last_elapsed: Optional[float] = None
    for family, socktype, proto, _, sockaddr in addresses:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        # Match the controller's RTT definition: measure only the current connect
        # attempt, not DNS resolution or an earlier failed address family.
        attempt_started = time.perf_counter()
        try:
            sock.connect(sockaddr)
            elapsed = (time.perf_counter() - attempt_started) * 1000
            return TcpResult(True, round(elapsed, 2), None)
        except OSError as exc:
            last_error = str(exc)
            last_elapsed = (time.perf_counter() - attempt_started) * 1000
        finally:
            sock.close()
    return TcpResult(
        False,
        round(last_elapsed, 2) if last_elapsed is not None else None,
        last_error or "connect failed",
    )


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw_value = os.environ.get(name, str(default))
    try:
        parsed = int(raw_value)
    except (TypeError, ValueError):
        print(f"invalid {name}={raw_value!r}; using {default}", flush=True)
        return default
    clamped = max(minimum, min(parsed, maximum))
    if clamped != parsed:
        print(f"{name}={parsed} is outside {minimum}-{maximum}; using {clamped}", flush=True)
    return clamped


def env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw_value = os.environ.get(name, str(default))
    try:
        parsed = float(raw_value)
    except (TypeError, ValueError):
        print(f"invalid {name}={raw_value!r}; using {default}", flush=True)
        return default
    clamped = max(minimum, min(parsed, maximum))
    if clamped != parsed:
        print(f"{name}={parsed} is outside {minimum}-{maximum}; using {clamped}", flush=True)
    return clamped


def remaining_interval_seconds(interval_seconds: int, elapsed_seconds: float) -> float:
    return max(float(interval_seconds) - elapsed_seconds, 1.0)


def controller_interval_seconds(value: object, default: int) -> int:
    raw_value = value or default
    try:
        parsed = int(raw_value)
    except (TypeError, ValueError):
        print(f"invalid controller interval_seconds={raw_value!r}; using {default}", flush=True)
        return default
    clamped = max(5, min(parsed, 3600))
    if clamped != parsed:
        print(f"controller interval_seconds={parsed} is outside 5-3600; using {clamped}", flush=True)
    return clamped


def normalized_worker_count(max_workers: int, task_count: int) -> int:
    return max(1, min(int(max_workers), max(task_count, 1), MAX_AGENT_WORKERS))


def probe_task(task: dict, default_timeout: float) -> Optional[dict]:
    """Probe one valid controller task; skip malformed tasks without aborting the batch."""
    try:
        origin_id = int(task["origin_id"])
        target = str(task["target"]).strip()
        port = int(task["port"])
        timeout = float(task.get("timeout_seconds") or default_timeout)
        if not target:
            raise ValueError("target is empty")
        if not 1 <= port <= 65535:
            raise ValueError("port is outside 1-65535")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        print(f"invalid probe task skipped: {exc}", flush=True)
        return None

    try:
        result = tcp_check(target, port, timeout)
    except Exception as exc:
        result = TcpResult(False, None, f"probe failed: {exc}")
    return {
        "origin_id": origin_id,
        "target": target,
        "port": port,
        "success": result.success,
        "rtt_ms": result.rtt_ms,
        "error": result.error,
    }


def run_probe_tasks(
    tasks: Optional[List[dict]],
    default_timeout: float,
    max_workers: int,
) -> List[dict]:
    """Run a probe batch concurrently and return every valid result together."""
    if not tasks:
        return []

    worker_count = normalized_worker_count(max_workers, len(tasks))
    completed_results: List[dict] = []
    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="tcp-probe") as executor:
        futures = [executor.submit(probe_task, task, default_timeout) for task in tasks]
        for future in as_completed(futures):
            result = future.result()
            if result is None:
                continue
            completed_results.append(result)
    return completed_results


def main() -> None:
    control_url = os.environ.get("CONTROL_URL", "").rstrip("/")
    token = os.environ.get("AGENT_TOKEN", "")
    default_interval = env_int("AGENT_INTERVAL_SECONDS", 30, 5, 3600)
    default_timeout = env_float("AGENT_TIMEOUT_SECONDS", 3.0, 0.1, 60.0)
    max_workers = env_int("AGENT_MAX_WORKERS", 16, 1, MAX_AGENT_WORKERS)
    log_rounds = os.environ.get("AGENT_LOG_ROUNDS", "0").strip().lower() in {"1", "true", "yes", "on"}
    if not control_url or not token:
        raise SystemExit("CONTROL_URL and AGENT_TOKEN are required")

    headers = {"X-Agent-Token": token, "User-Agent": "cloudflare-dns-agent/1.0"}
    with httpx.Client(timeout=20, headers=headers) as client:
        while True:
            round_started = time.monotonic()
            interval = default_interval
            try:
                tasks_response = client.get(f"{control_url}/api/agent/tasks")
                tasks_response.raise_for_status()
                payload = tasks_response.json()
                interval = controller_interval_seconds(payload.get("interval_seconds"), default_interval)
                tasks = payload.get("tasks", [])
                results = run_probe_tasks(tasks, default_timeout, max_workers)
                if results:
                    client.post(
                        f"{control_url}/api/agent/results",
                        json={"results": results},
                        timeout=RESULT_POST_TIMEOUT_SECONDS,
                    ).raise_for_status()
                elapsed = time.monotonic() - round_started
                if results and (log_rounds or elapsed >= interval):
                    failed = sum(not result["success"] for result in results)
                    print(
                        f"agent round completed: tasks={len(results)} failed={failed} duration={elapsed:.2f}s",
                        flush=True,
                    )
            except Exception as exc:
                print(f"agent loop failed: {exc}", flush=True)

            # Keep round starts close to the controller interval. The old loop
            # slept for a full interval *after* probing, so slow tasks permanently
            # stretched a 30-second schedule into 30 seconds plus batch duration.
            elapsed = time.monotonic() - round_started
            time.sleep(remaining_interval_seconds(interval, elapsed))


if __name__ == "__main__":
    main()
'''


INSTALLER_TEMPLATE = r'''#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/cloudflare-dns-agent}"
SERVICE_NAME="${SERVICE_NAME:-cloudflare-dns-agent}"
AGENT_INTERVAL_SECONDS="${AGENT_INTERVAL_SECONDS:-30}"
AGENT_TIMEOUT_SECONDS="${AGENT_TIMEOUT_SECONDS:-3}"
AGENT_MAX_WORKERS="${AGENT_MAX_WORKERS:-16}"
AGENT_LOG_ROUNDS="${AGENT_LOG_ROUNDS:-0}"

if [[ -z "${CONTROL_URL:-}" || -z "${AGENT_TOKEN:-}" ]]; then
  echo "ERROR: CONTROL_URL and AGENT_TOKEN are required."
  echo "Example:"
  echo "  CONTROL_URL=https://dns.example.com AGENT_TOKEN=xxx bash /tmp/cloudflare-dns-agent-install.sh"
  exit 1
fi

require_single_line() {
  local name="$1"
  local value="$2"
  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
    echo "ERROR: ${name} must not contain line breaks."
    exit 1
  fi
}

require_single_line CONTROL_URL "$CONTROL_URL"
require_single_line AGENT_TOKEN "$AGENT_TOKEN"
require_single_line AGENT_INTERVAL_SECONDS "$AGENT_INTERVAL_SECONDS"
require_single_line AGENT_TIMEOUT_SECONDS "$AGENT_TIMEOUT_SECONDS"
require_single_line AGENT_MAX_WORKERS "$AGENT_MAX_WORKERS"
require_single_line AGENT_LOG_ROUNDS "$AGENT_LOG_ROUNDS"

if ! [[ "$AGENT_INTERVAL_SECONDS" =~ ^[0-9]+$ ]] || (( 10#$AGENT_INTERVAL_SECONDS < 5 || 10#$AGENT_INTERVAL_SECONDS > 3600 )); then
  echo "ERROR: AGENT_INTERVAL_SECONDS must be an integer between 5 and 3600."
  exit 1
fi

if ! [[ "$AGENT_TIMEOUT_SECONDS" =~ ^([0-9]+([.][0-9]*)?|[.][0-9]+)$ ]] || \
   ! awk -v value="$AGENT_TIMEOUT_SECONDS" 'BEGIN { exit !(value >= 0.1 && value <= 60) }'; then
  echo "ERROR: AGENT_TIMEOUT_SECONDS must be a number between 0.1 and 60."
  exit 1
fi

if ! [[ "$AGENT_MAX_WORKERS" =~ ^[0-9]+$ ]] || (( 10#$AGENT_MAX_WORKERS < 1 || 10#$AGENT_MAX_WORKERS > 64 )); then
  echo "ERROR: AGENT_MAX_WORKERS must be an integer between 1 and 64."
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: please run this installer as root, or use sudo env CONTROL_URL=... AGENT_TOKEN=... bash ..."
  exit 1
fi

CONTROL_URL="${CONTROL_URL%/}"

echo "[1/5] Installing system packages..."
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y python3 python3-venv python3-pip ca-certificates curl
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y python3 python3-pip ca-certificates curl
elif command -v yum >/dev/null 2>&1; then
  yum install -y python3 python3-pip ca-certificates curl
else
  echo "WARN: unsupported package manager. Make sure python3, venv, pip, ca-certificates and curl are installed."
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "ERROR: python3 was not found."
  exit 1
fi

echo "[2/5] Writing agent files to ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"
cat > "${INSTALL_DIR}/agent.py" <<'PY_AGENT'
__AGENT_SOURCE__
PY_AGENT
chmod 700 "$INSTALL_DIR"
chmod 600 "${INSTALL_DIR}/agent.py"

echo "[3/5] Creating Python virtual environment..."
rm -rf "${INSTALL_DIR}/.venv"
"$PYTHON_BIN" -m venv "${INSTALL_DIR}/.venv"
"${INSTALL_DIR}/.venv/bin/python" -m pip install --upgrade pip
"${INSTALL_DIR}/.venv/bin/python" -m pip install "httpx==0.28.1"

write_env_value() {
  local key="$1"
  local value="$2"
  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
    printf 'ERROR: %s must not contain line breaks.\n' "$key" >&2
    return 1
  fi
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s="%s"\n' "$key" "$value"
}

echo "[4/5] Writing service configuration..."
{
  write_env_value CONTROL_URL "$CONTROL_URL"
  write_env_value AGENT_TOKEN "$AGENT_TOKEN"
  write_env_value AGENT_INTERVAL_SECONDS "$AGENT_INTERVAL_SECONDS"
  write_env_value AGENT_TIMEOUT_SECONDS "$AGENT_TIMEOUT_SECONDS"
  write_env_value AGENT_MAX_WORKERS "$AGENT_MAX_WORKERS"
  write_env_value AGENT_LOG_ROUNDS "$AGENT_LOG_ROUNDS"
} > "/etc/${SERVICE_NAME}.env"
chmod 600 "/etc/${SERVICE_NAME}.env"

if command -v systemctl >/dev/null 2>&1; then
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<SERVICE
[Unit]
Description=Cloudflare DNS Failover Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/${SERVICE_NAME}.env
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/.venv/bin/python ${INSTALL_DIR}/agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

  echo "[5/5] Starting ${SERVICE_NAME}..."
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"
  sleep 2
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "OK: ${SERVICE_NAME} is running."
    echo "Logs: journalctl -u ${SERVICE_NAME} -f"
  else
    echo "ERROR: ${SERVICE_NAME} did not start successfully."
    systemctl --no-pager --full status "$SERVICE_NAME" || true
    exit 1
  fi
else
  echo "WARN: systemd was not found. Agent files are installed, but no service was created."
  echo "Run manually:"
  echo "  CONTROL_URL=${CONTROL_URL} AGENT_TOKEN=*** ${INSTALL_DIR}/.venv/bin/python ${INSTALL_DIR}/agent.py"
fi
'''


def _load_agent_source() -> str:
    repo_agent = Path(__file__).resolve().parents[2] / "agent" / "agent.py"
    try:
        return repo_agent.read_text(encoding="utf-8")
    except OSError:
        return EMBEDDED_AGENT_SOURCE


def build_install_script() -> str:
    return INSTALLER_TEMPLATE.replace("__AGENT_SOURCE__", _load_agent_source().rstrip())
