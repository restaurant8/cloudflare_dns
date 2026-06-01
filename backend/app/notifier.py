import json
from html import escape
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy.orm import Session

from .events import add_event
from .models import TelegramNotification, Webhook
from .security import decrypt_secret, sign_webhook_payload


EVENT_NAMES = {
    "dns.switched": "DNS 已切换",
    "origin.status_changed": "源站状态变化",
    "agent.status_changed": "探针状态变化",
    "failover.no_healthy_origin": "无健康源站",
    "dns.publish_failed": "DNS 发布失败",
    "cloudflare.sync_failed": "Cloudflare 同步失败",
    "cloudflare.synced": "Cloudflare 已同步",
}


STATUS_NAMES = {
    "healthy": "健康",
    "unhealthy": "不可用",
    "blocked": "疑似被墙",
    "machine_down": "机器疑似挂了",
    "regional_issue": "本地探测异常",
    "unknown": "未知",
    "disabled": "已禁用",
    "enabled": "已启用",
    "online": "在线",
    "offline": "离线",
}


REGION_NAMES = {
    "china": "国内",
    "foreign": "国外",
}

SHANGHAI_TZ = timezone(timedelta(hours=8), "Asia/Shanghai")

TELEGRAM_LEVEL_PRIORITIES = {
    "all": 10,
    "important": 20,
    "critical": 30,
}

TELEGRAM_EVENT_PRIORITIES = {
    "origin.status_changed": 10,
    "agent.status_changed": 10,
    "cloudflare.synced": 10,
    "dns.switched": 20,
    "dns.publish_failed": 30,
    "failover.no_healthy_origin": 30,
    "cloudflare.sync_failed": 30,
}


def _decrypt_or_plaintext(value: str) -> str:
    try:
        return decrypt_secret(value)
    except Exception:
        return value


def _line(label: str, value: Any) -> str:
    if value is None or value == "":
        value = "-"
    return f"{escape(label)}: <code>{escape(str(value))}</code>"


def _format_shanghai_time(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    else:
        return str(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(SHANGHAI_TZ).strftime("%Y-%m-%d %H:%M:%S Asia/Shanghai")


def render_telegram_message(event_type: str, payload: dict[str, Any]) -> str:
    title = EVENT_NAMES.get(event_type, "系统事件")
    lines = [f"<b>{escape(title)}</b>"]

    if event_type == "dns.switched":
        lines.extend(
            [
                _line("主机名", payload.get("hostname")),
                _line("记录", f"{payload.get('record_type', '-')} {payload.get('content', '-')}"),
                _line("源站 ID", payload.get("new_origin_id")),
                _line("旧源站 ID", payload.get("old_origin_id")),
            ]
        )
    elif event_type == "origin.status_changed":
        lines.extend(
            [
                _line("源站", f"{payload.get('target', '-')}:{payload.get('port', '-')}"),
                _line("状态", STATUS_NAMES.get(str(payload.get("status")), payload.get("status"))),
            ]
        )
    elif event_type == "agent.status_changed":
        lines.extend(
            [
                _line("探针", payload.get("name") or payload.get("agent_id")),
                _line("区域", REGION_NAMES.get(str(payload.get("region")), payload.get("region"))),
                _line("状态", STATUS_NAMES.get(str(payload.get("status")), payload.get("status"))),
                _line("最后 IP", payload.get("last_ip")),
                _line("最后上报", _format_shanghai_time(payload.get("last_seen_at"))),
            ]
        )
    elif event_type == "failover.no_healthy_origin":
        lines.extend([_line("主机名", payload.get("hostname")), "请检查源站池和探针连通性。"])
    elif event_type == "dns.publish_failed":
        lines.extend([_line("主机名", payload.get("hostname")), _line("错误", payload.get("error"))])
    elif event_type.startswith("cloudflare."):
        lines.extend([_line("凭据 ID", payload.get("credential_id")), _line("错误", payload.get("error"))])
    else:
        for key, value in payload.items():
            if isinstance(value, (str, int, float, bool)) or value is None:
                lines.append(_line(key, value))

    lines.append(_line("时间", _format_shanghai_time(datetime.now(timezone.utc))))
    return "\n".join(lines)


def telegram_event_priority(event_type: str, payload: dict[str, Any]) -> int:
    if event_type == "telegram.test":
        return 30
    if event_type == "agent.status_changed":
        return 30 if payload.get("status") in {"offline", "disabled"} else 10
    return TELEGRAM_EVENT_PRIORITIES.get(event_type, 10)


def should_send_telegram(channel: TelegramNotification, event_type: str, payload: dict[str, Any]) -> bool:
    level = getattr(channel, "notify_level", None) or "important"
    minimum_priority = TELEGRAM_LEVEL_PRIORITIES.get(level, TELEGRAM_LEVEL_PRIORITIES["important"])
    return telegram_event_priority(event_type, payload) >= minimum_priority


def send_webhooks(db: Session, event_type: str, payload: dict[str, Any]) -> None:
    send_telegram_notifications(db, event_type, payload)
    webhooks = db.query(Webhook).filter(Webhook.enabled.is_(True)).all()
    if not webhooks:
        return

    body = json.dumps({"type": event_type, "payload": payload}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    for webhook in webhooks:
        headers = {"Content-Type": "application/json", "User-Agent": "cloudflare-dns-failover/1.0"}
        if webhook.secret:
            headers["X-Failover-Signature"] = sign_webhook_payload(_decrypt_or_plaintext(webhook.secret), body)
        last_error = None
        for _ in range(3):
            try:
                response = httpx.post(webhook.url, content=body, headers=headers, timeout=10)
                response.raise_for_status()
                webhook.last_sent_at = datetime.utcnow()
                webhook.last_error = None
                break
            except Exception as exc:  # pragma: no cover - network dependent
                last_error = str(exc)
        else:
            webhook.last_error = last_error
            add_event(
                db,
                "webhook.failed",
                "warning",
                f"Webhook {webhook.name} 发送失败",
                {"webhook_id": webhook.id, "error": last_error},
            )


def send_telegram_notifications(db: Session, event_type: str, payload: dict[str, Any]) -> None:
    channels = db.query(TelegramNotification).filter(TelegramNotification.enabled.is_(True)).all()
    if not channels:
        return

    for channel in channels:
        if not should_send_telegram(channel, event_type, payload):
            continue
        text = render_telegram_message(event_type, payload)
        send_telegram_channel(db, channel, event_type, payload, text=text)


def send_telegram_channel(
    db: Session,
    channel: TelegramNotification,
    event_type: str,
    payload: dict[str, Any],
    text: str | None = None,
) -> None:
    last_error = None
    message_text = text or render_telegram_message(event_type, payload)
    for _ in range(3):
        try:
            token = decrypt_secret(channel.bot_token_encrypted)
            response = httpx.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={
                    "chat_id": channel.chat_id,
                    "text": message_text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                },
                timeout=10,
            )
            response.raise_for_status()
            result = response.json()
            if not result.get("ok", False):
                raise RuntimeError(result.get("description") or "Telegram API 返回失败")
            channel.last_sent_at = datetime.utcnow()
            channel.last_error = None
            break
        except Exception as exc:  # pragma: no cover - network dependent
            last_error = str(exc)
    else:
        channel.last_error = last_error
        add_event(
            db,
            "telegram.failed",
            "warning",
            f"Telegram 通知 {channel.name} 发送失败",
            {"telegram_id": channel.id, "error": last_error},
        )
