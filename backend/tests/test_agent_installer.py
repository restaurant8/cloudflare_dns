from app.agent_installer import build_install_script


def test_build_install_script_contains_agent_service_and_envs():
    script = build_install_script()

    assert "CONTROL_URL and AGENT_TOKEN are required" in script
    assert "cloudflare-dns-agent" in script
    assert "EnvironmentFile=/etc/${SERVICE_NAME}.env" in script
    assert "httpx==0.28.1" in script
    assert "def tcp_check" in script
