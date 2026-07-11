from types import SimpleNamespace

from app.notifier import render_telegram_message, should_send_telegram


def test_render_telegram_dns_switch_template():
    message = render_telegram_message(
        "dns.switched",
        {
            "hostname": "www.example.com",
            "record_type": "AAAA",
            "content": "2001:db8::1",
            "new_origin_id": 2,
            "old_origin_id": 1,
            "switch_reason": "time_rule",
            "time_rule_id": 7,
        },
    )

    assert "DNS 已切换" in message
    assert "www.example.com" in message
    assert "AAAA 2001:db8::1" in message
    assert "分时入口" in message
    assert "分时规则 ID" in message


def test_render_telegram_escapes_html():
    message = render_telegram_message("dns.publish_failed", {"hostname": "a.example.com", "error": "<bad token>"})

    assert "&lt;bad token&gt;" in message
    assert "<bad token>" not in message


def test_render_telegram_uses_shanghai_time():
    message = render_telegram_message(
        "agent.status_changed",
        {
            "name": "mainland",
            "region": "china",
            "status": "offline",
            "last_seen_at": "2026-06-01T05:22:51",
        },
    )

    assert "2026-06-01 13:22:51 Asia/Shanghai" in message
    assert "UTC" not in message


def test_important_telegram_level_skips_noisy_origin_status_changes():
    channel = SimpleNamespace(notify_level="important")

    assert should_send_telegram(channel, "origin.status_changed", {"status": "blocked"}) is False
    assert should_send_telegram(channel, "dns.switched", {"hostname": "www.example.com"}) is True
    assert should_send_telegram(channel, "agent.status_changed", {"status": "offline"}) is True
    assert should_send_telegram(channel, "agent.status_changed", {"status": "online"}) is False


def test_critical_telegram_level_includes_dns_switches():
    channel = SimpleNamespace(notify_level="critical")

    assert should_send_telegram(channel, "dns.switched", {"hostname": "www.example.com"}) is True
    assert should_send_telegram(channel, "origin.status_changed", {"status": "blocked"}) is False


def test_all_telegram_level_includes_origin_status_changes():
    channel = SimpleNamespace(notify_level="all")

    assert should_send_telegram(channel, "origin.status_changed", {"status": "healthy"}) is True
