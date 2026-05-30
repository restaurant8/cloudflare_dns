from app.notifier import render_telegram_message


def test_render_telegram_dns_switch_template():
    message = render_telegram_message(
        "dns.switched",
        {
            "hostname": "www.example.com",
            "record_type": "AAAA",
            "content": "2001:db8::1",
            "new_origin_id": 2,
            "old_origin_id": 1,
        },
    )

    assert "DNS 已切换" in message
    assert "www.example.com" in message
    assert "AAAA 2001:db8::1" in message


def test_render_telegram_escapes_html():
    message = render_telegram_message("dns.publish_failed", {"hostname": "a.example.com", "error": "<bad token>"})

    assert "&lt;bad token&gt;" in message
    assert "<bad token>" not in message

