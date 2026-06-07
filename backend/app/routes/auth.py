import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user, require_cloudflare_access
from ..models import User
from ..request_utils import client_ip_from_request
from ..runtime_settings import RuntimeSettings, get_runtime_settings
from ..schemas import BootstrapRequest, LoginRequest, Message, PasswordChangeRequest, SetupStatus, TokenResponse, UserProfileOut, UsernameChangeRequest
from ..security import create_access_token, hash_password, verify_password


router = APIRouter(prefix="/auth", tags=["auth"])
_login_failures: dict[str, dict[str, float]] = {}


def _client_ip(request: Request) -> str:
    return client_ip_from_request(request) or "unknown"


def _login_key(request: Request, username: str) -> str:
    return f"{_client_ip(request)}:{username.strip().lower()}"


def _check_login_limiter(key: str, settings: RuntimeSettings | None = None) -> None:
    settings = settings or get_runtime_settings()
    if not getattr(settings, "login_lockout_enabled", 1):
        return
    now = time.time()
    state = _login_failures.get(key)
    if not state:
        return
    if state.get("locked_until", 0) > now:
        remaining = int(state["locked_until"] - now) + 1
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=f"登录失败次数过多，请 {remaining} 秒后再试")
    if now - state.get("first_failed_at", now) > settings.login_failure_window_seconds:
        _login_failures.pop(key, None)


def _record_login_failure(key: str, settings: RuntimeSettings | None = None) -> None:
    settings = settings or get_runtime_settings()
    if not getattr(settings, "login_lockout_enabled", 1):
        return
    now = time.time()
    state = _login_failures.get(key)
    if not state or now - state.get("first_failed_at", now) > settings.login_failure_window_seconds:
        state = {"count": 0, "first_failed_at": now, "locked_until": 0}
    state["count"] = state.get("count", 0) + 1
    if state["count"] >= settings.login_max_failures:
        state["locked_until"] = now + settings.login_lockout_seconds
    _login_failures[key] = state


def _clear_login_failures(key: str) -> None:
    _login_failures.pop(key, None)


@router.get("/setup-required", response_model=SetupStatus)
def setup_required(db: Session = Depends(get_db)):
    return SetupStatus(setup_required=db.query(User).count() == 0)


@router.post("/bootstrap", response_model=TokenResponse)
def bootstrap(payload: BootstrapRequest, db: Session = Depends(get_db)):
    if db.query(User).count() > 0:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="管理员账号已存在")
    user = User(username=payload.username, password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return TokenResponse(access_token=create_access_token(user.id))


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    settings = get_runtime_settings(db)
    require_cloudflare_access(request, db)
    key = _login_key(request, payload.username)
    _check_login_limiter(key, settings)
    user = db.query(User).filter(User.username == payload.username).one_or_none()
    if user is None or not verify_password(payload.password, user.password_hash):
        _record_login_failure(key, settings)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误")
    _clear_login_failures(key)
    ttl_seconds = settings.access_token_remember_ttl_seconds if payload.remember_me else settings.access_token_ttl_seconds
    return TokenResponse(access_token=create_access_token(user.id, ttl_seconds=ttl_seconds))


@router.get("/me", response_model=UserProfileOut)
def current_user(user: User = Depends(get_current_user)):
    return user


@router.patch("/username", response_model=UserProfileOut)
def change_username(payload: UsernameChangeRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="当前密码不正确")
    next_username = payload.username.strip()
    if db.query(User).filter(User.username == next_username, User.id != user.id).one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="用户名已存在")
    user.username = next_username
    db.commit()
    db.refresh(user)
    return user


@router.patch("/password", response_model=Message)
def change_password(payload: PasswordChangeRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="当前密码不正确")
    user.password_hash = hash_password(payload.new_password)
    db.commit()
    return Message(message="登录密码已修改")
