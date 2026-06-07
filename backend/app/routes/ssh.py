from urllib.parse import urlparse

import httpx
import websockets
from fastapi import APIRouter, Depends, HTTPException, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import cloudflare_access_allowed, get_current_user, require_cloudflare_access
from ..models import AppSetting, User
from ..schemas import Message, SshSessionOut, SshSettingsOut, SshSettingsUpdate
from ..security import create_access_token, verify_access_token


router = APIRouter(prefix="/ssh", tags=["ssh"])

SSH_COOKIE_NAME = "cf_dns_ssh_session"
SSH_ENTRY_PATH = "/api/ssh/proxy/"
SSH_SETTING_ENABLED = "ssh.enabled"
SSH_SETTING_UPSTREAM_URL = "ssh.upstream_url"
SSH_SETTING_SESSION_TTL = "ssh.session_ttl_seconds"
DEFAULT_UPSTREAM_URL = "http://127.0.0.1:8182"
DEFAULT_SESSION_TTL_SECONDS = 300
HOP_BY_HOP_HEADERS = {
    "connection",
    "content-encoding",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def _setting_value(db: Session, key: str, default: str) -> str:
    row = db.get(AppSetting, key)
    return row.value if row else default


def _set_setting_value(db: Session, key: str, value: str) -> None:
    row = db.get(AppSetting, key)
    if row is None:
        db.add(AppSetting(key=key, value=value))
    else:
        row.value = value


def _bool_setting(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _ssh_settings(db: Session) -> SshSettingsOut:
    raw_ttl = _setting_value(db, SSH_SETTING_SESSION_TTL, str(DEFAULT_SESSION_TTL_SECONDS))
    try:
        session_ttl = max(60, min(3600, int(raw_ttl)))
    except ValueError:
        session_ttl = DEFAULT_SESSION_TTL_SECONDS
    return SshSettingsOut(
        enabled=_bool_setting(_setting_value(db, SSH_SETTING_ENABLED, "false")),
        upstream_url=_setting_value(db, SSH_SETTING_UPSTREAM_URL, DEFAULT_UPSTREAM_URL).rstrip("/"),
        session_ttl_seconds=session_ttl,
        entry_path=SSH_ENTRY_PATH,
    )


def _require_local_upstream(upstream_url: str) -> None:
    parsed = urlparse(upstream_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise HTTPException(status_code=400, detail="SSH upstream 只能填写本机地址")


def _require_ssh_session(request: Request, db: Session) -> None:
    token = request.cookies.get(SSH_COOKIE_NAME)
    user_id = verify_access_token(token or "")
    if user_id is None or db.get(User, user_id) is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="SSH 访问会话已失效，请从 SSH 菜单重新打开")


def _require_ssh_cookie(cookie: str | None, db: Session) -> bool:
    user_id = verify_access_token(cookie or "")
    return user_id is not None and db.get(User, user_id) is not None


def _target_url(upstream_url: str, path: str, query: bytes) -> str:
    target = f"{upstream_url.rstrip('/')}/{path.lstrip('/')}"
    if query:
        target = f"{target}?{query.decode('utf-8', errors='ignore')}"
    return target


def _proxy_headers(request: Request) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in request.headers.items():
        lower = key.lower()
        if lower in HOP_BY_HOP_HEADERS or lower == "host":
            continue
        headers[key] = value
    return headers


def _ssh_error_response(status_code: int, title: str, detail: str) -> Response:
    html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <style>
    body {{
      background: #0f172a;
      color: #dbeafe;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      padding: 24px;
    }}
    h1 {{ color: #ffffff; font-size: 20px; margin: 0 0 10px; }}
    p {{ color: #bfdbfe; line-height: 1.7; margin: 0; }}
    code {{
      background: rgba(255,255,255,0.08);
      border-radius: 6px;
      color: #ffffff;
      padding: 2px 6px;
    }}
  </style>
</head>
<body>
  <h1>{title}</h1>
  <p>{detail}</p>
</body>
</html>"""
    return Response(content=html, status_code=status_code, media_type="text/html; charset=utf-8")


@router.get("/settings", response_model=SshSettingsOut)
def read_ssh_settings(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _ssh_settings(db)


@router.patch("/settings", response_model=SshSettingsOut)
def update_ssh_settings(payload: SshSettingsUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    updates = payload.model_dump(exclude_unset=True)
    if "upstream_url" in updates and updates["upstream_url"] is not None:
        _require_local_upstream(updates["upstream_url"])
        _set_setting_value(db, SSH_SETTING_UPSTREAM_URL, updates["upstream_url"].rstrip("/"))
    if "enabled" in updates and updates["enabled"] is not None:
        _set_setting_value(db, SSH_SETTING_ENABLED, "true" if updates["enabled"] else "false")
    if "session_ttl_seconds" in updates and updates["session_ttl_seconds"] is not None:
        _set_setting_value(db, SSH_SETTING_SESSION_TTL, str(updates["session_ttl_seconds"]))
    db.commit()
    return _ssh_settings(db)


@router.post("/session", response_model=SshSessionOut)
def create_ssh_session(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    settings = _ssh_settings(db)
    if not settings.enabled:
        raise HTTPException(status_code=400, detail="SSH 功能尚未启用")
    _require_local_upstream(settings.upstream_url)
    token = create_access_token(user.id, ttl_seconds=settings.session_ttl_seconds)
    payload = SshSessionOut(entry_url=settings.entry_path, expires_in=settings.session_ttl_seconds)
    response = JSONResponse(payload.model_dump())
    response.set_cookie(
        SSH_COOKIE_NAME,
        token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        samesite="lax",
        path=SSH_ENTRY_PATH.rstrip("/"),
    )
    return response


@router.delete("/session", response_model=Message)
def clear_ssh_session(_: User = Depends(get_current_user)):
    response = JSONResponse(Message(message="SSH 会话已关闭").model_dump())
    response.delete_cookie(SSH_COOKIE_NAME, path=SSH_ENTRY_PATH.rstrip("/"))
    return response


@router.api_route("/proxy", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@router.api_route("/proxy/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def ssh_http_proxy(path: str = "", request: Request = None, db: Session = Depends(get_db)):
    if request is None:
        raise HTTPException(status_code=400, detail="请求无效")
    settings = _ssh_settings(db)
    if not settings.enabled:
        raise HTTPException(status_code=404, detail="SSH 功能未启用")
    _require_local_upstream(settings.upstream_url)
    require_cloudflare_access(request, db)
    _require_ssh_session(request, db)
    target_url = _target_url(settings.upstream_url, path, request.url.query.encode("utf-8"))
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=60.0) as client:
            upstream = await client.request(
                request.method,
                target_url,
                headers=_proxy_headers(request),
                content=await request.body(),
            )
    except httpx.RequestError as exc:
        return _ssh_error_response(
            502,
            "Sshwifty 未连接",
            f"后端无法连接 <code>{settings.upstream_url}</code>。请确认 Sshwifty 容器已经启动，并且只监听本机地址 127.0.0.1:8182。错误：{exc}",
        )
    response_headers = {
        key: value
        for key, value in upstream.headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
    }
    location = response_headers.get("location")
    if location and location.startswith(settings.upstream_url):
        response_headers["location"] = location.replace(settings.upstream_url, SSH_ENTRY_PATH.rstrip("/"), 1)
    return Response(content=upstream.content, status_code=upstream.status_code, headers=response_headers)


@router.websocket("/proxy")
@router.websocket("/proxy/{path:path}")
async def ssh_websocket_proxy(websocket: WebSocket, path: str = "", db: Session = Depends(get_db)):
    settings = _ssh_settings(db)
    try:
        _require_local_upstream(settings.upstream_url)
    except HTTPException:
        await websocket.close(code=1008)
        return
    if not cloudflare_access_allowed(websocket.headers, websocket.cookies, db):
        await websocket.close(code=4403)
        return
    if not settings.enabled or not _require_ssh_cookie(websocket.cookies.get(SSH_COOKIE_NAME), db):
        await websocket.close(code=4401)
        return

    parsed = urlparse(settings.upstream_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    upstream_base = f"{scheme}://{parsed.netloc}"
    target_url = _target_url(upstream_base, path, websocket.scope.get("query_string", b""))
    await websocket.accept()

    async def client_to_upstream(upstream):
        try:
            while True:
                message = await websocket.receive()
                if message.get("type") == "websocket.disconnect":
                    await upstream.close()
                    return
                if "text" in message:
                    await upstream.send(message["text"])
                elif "bytes" in message:
                    await upstream.send(message["bytes"])
        except WebSocketDisconnect:
            await upstream.close()

    async def upstream_to_client(upstream):
        async for message in upstream:
            if isinstance(message, bytes):
                await websocket.send_bytes(message)
            else:
                await websocket.send_text(message)

    try:
        async with websockets.connect(target_url, open_timeout=10) as upstream:
            import asyncio

            first = asyncio.create_task(client_to_upstream(upstream))
            second = asyncio.create_task(upstream_to_client(upstream))
            done, pending = await asyncio.wait({first, second}, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for task in done:
                task.result()
    except Exception:
        await websocket.close(code=1011)
