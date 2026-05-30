from pathlib import Path


EMBEDDED_AGENT_SOURCE = r'''import os
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
'''


INSTALLER_TEMPLATE = r'''#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/cloudflare-dns-agent}"
SERVICE_NAME="${SERVICE_NAME:-cloudflare-dns-agent}"
AGENT_INTERVAL_SECONDS="${AGENT_INTERVAL_SECONDS:-30}"
AGENT_TIMEOUT_SECONDS="${AGENT_TIMEOUT_SECONDS:-3}"

if [[ -z "${CONTROL_URL:-}" || -z "${AGENT_TOKEN:-}" ]]; then
  echo "ERROR: CONTROL_URL and AGENT_TOKEN are required."
  echo "Example:"
  echo "  CONTROL_URL=https://dns.example.com AGENT_TOKEN=xxx bash /tmp/cloudflare-dns-agent-install.sh"
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
