import os
import subprocess
from pathlib import Path

from app.agent_installer import EMBEDDED_AGENT_SOURCE, build_install_script


def test_build_install_script_contains_agent_service_and_envs():
    script = build_install_script()

    assert "CONTROL_URL and AGENT_TOKEN are required" in script
    assert "cloudflare-dns-agent" in script
    assert "EnvironmentFile=/etc/${SERVICE_NAME}.env" in script
    assert "httpx==0.28.1" in script
    assert "def tcp_check" in script
    assert 'AGENT_MAX_WORKERS="${AGENT_MAX_WORKERS:-16}"' in script
    assert 'AGENT_LOG_ROUNDS="${AGENT_LOG_ROUNDS:-0}"' in script
    assert "AGENT_INTERVAL_SECONDS must be an integer between 5 and 3600" in script
    assert "AGENT_TIMEOUT_SECONDS must be a number between 0.1 and 60" in script
    assert "AGENT_MAX_WORKERS must be an integer between 1 and 64" in script
    assert "must not contain line breaks" in script
    assert "run_probe_tasks" in script


def test_embedded_agent_stays_in_sync_with_repository_agent():
    agent_source = (Path(__file__).resolve().parents[2] / "agent" / "agent.py").read_text(encoding="utf-8")

    assert EMBEDDED_AGENT_SOURCE.strip() == agent_source.strip()


def test_install_script_rejects_invalid_numeric_agent_settings():
    script = build_install_script()
    base_env = {
        **os.environ,
        "CONTROL_URL": "https://controller.example.com",
        "AGENT_TOKEN": "token",
    }
    cases = [
        ({"AGENT_INTERVAL_SECONDS": "-5"}, "AGENT_INTERVAL_SECONDS"),
        ({"AGENT_TIMEOUT_SECONDS": "many"}, "AGENT_TIMEOUT_SECONDS"),
        ({"AGENT_MAX_WORKERS": "0"}, "AGENT_MAX_WORKERS"),
    ]

    for overrides, expected_error in cases:
        completed = subprocess.run(
            ["bash"],
            input=script,
            text=True,
            capture_output=True,
            env={**base_env, **overrides},
            check=False,
        )
        assert completed.returncode == 1
        assert expected_error in completed.stdout
