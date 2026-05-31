from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import TelegramNotification, User
from ..notifier import send_telegram_channel
from ..schemas import Message, TelegramNotificationCreate, TelegramNotificationOut, TelegramNotificationUpdate
from ..security import encrypt_secret


router = APIRouter(prefix="/telegram", tags=["telegram"])


@router.get("", response_model=list[TelegramNotificationOut])
def list_telegram(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(TelegramNotification).order_by(TelegramNotification.created_at.desc()).all()


@router.post("", response_model=TelegramNotificationOut)
def create_telegram(payload: TelegramNotificationCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    channel = TelegramNotification(
        name=payload.name,
        bot_token_encrypted=encrypt_secret(payload.bot_token),
        chat_id=payload.chat_id,
        notify_level=payload.notify_level,
        enabled=payload.enabled,
    )
    db.add(channel)
    db.commit()
    db.refresh(channel)
    return channel


@router.patch("/{telegram_id}", response_model=TelegramNotificationOut)
def update_telegram(telegram_id: int, payload: TelegramNotificationUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    channel = db.get(TelegramNotification, telegram_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="Telegram 通知不存在")
    updates = payload.model_dump(exclude_unset=True)
    if "bot_token" in updates:
        bot_token = updates.pop("bot_token")
        if bot_token:
            channel.bot_token_encrypted = encrypt_secret(bot_token)
    for key, value in updates.items():
        setattr(channel, key, value)
    db.commit()
    db.refresh(channel)
    return channel


@router.post("/{telegram_id}/test", response_model=Message)
def test_telegram(telegram_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    channel = db.get(TelegramNotification, telegram_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="Telegram 通知不存在")
    send_telegram_channel(
        db,
        channel,
        "telegram.test",
        {"name": channel.name, "message": "这是一条测试通知"},
    )
    db.commit()
    db.refresh(channel)
    if channel.last_error:
        raise HTTPException(status_code=400, detail=channel.last_error)
    return Message(message="Telegram 测试通知已发送")


@router.delete("/{telegram_id}", response_model=Message)
def delete_telegram(telegram_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    channel = db.get(TelegramNotification, telegram_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="Telegram 通知不存在")
    db.delete(channel)
    db.commit()
    return Message(message="Telegram 通知已删除")
