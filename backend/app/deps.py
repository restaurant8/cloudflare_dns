from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .database import get_db
from .models import Agent, User
from .runtime_settings import get_runtime_settings
from .security import verify_access_token, verify_token_hash


bearer = HTTPBearer(auto_error=False)


def cloudflare_access_allowed(headers, cookies, db: Session) -> bool:
    settings = get_runtime_settings(db)
    if not getattr(settings, "cloudflare_access_enabled", 0):
        return True
    email = headers.get("cf-access-authenticated-user-email")
    assertion = headers.get("cf-access-jwt-assertion") or cookies.get("CF_Authorization")
    return bool(email and assertion)


def require_cloudflare_access(request: Request, db: Session) -> None:
    if not cloudflare_access_allowed(request.headers, request.cookies, db):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cloudflare Access 未通过或未配置")


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    require_cloudflare_access(request, db)
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少登录令牌")
    user_id = verify_access_token(credentials.credentials)
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="登录令牌无效")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="登录令牌无效")
    return user


def get_agent(
    x_agent_token: str | None = Header(default=None, alias="X-Agent-Token"),
    db: Session = Depends(get_db),
) -> Agent:
    if not x_agent_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少探针令牌")
    agents = db.query(Agent).filter(Agent.enabled.is_(True)).all()
    for agent in agents:
        if verify_token_hash(x_agent_token, agent.token_hash):
            return agent
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="探针令牌无效")
