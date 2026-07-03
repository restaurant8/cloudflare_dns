import logging

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .cloudflare_access import verify_access_jwt
from .config import get_settings
from .database import get_db
from .models import Agent, User
from .runtime_settings import get_runtime_settings
from .security import hash_token, verify_access_token


logger = logging.getLogger(__name__)
bearer = HTTPBearer(auto_error=False)


def cloudflare_access_allowed(headers, cookies, db: Session) -> bool:
    settings = get_runtime_settings(db)
    if not getattr(settings, "cloudflare_access_enabled", 0):
        return True
    email = headers.get("cf-access-authenticated-user-email")
    assertion = headers.get("cf-access-jwt-assertion") or cookies.get("CF_Authorization")
    if not (email and assertion):
        return False
    app_settings = get_settings()
    team_domain = app_settings.cloudflare_access_team_domain.strip()
    audience = app_settings.cloudflare_access_aud.strip()
    if team_domain and audience:
        return verify_access_jwt(assertion, team_domain, audience)
    # No team domain/AUD configured: fall back to the legacy presence check, but make
    # the missing verification visible instead of silently trusting spoofable headers.
    logger.warning(
        "Cloudflare Access is enabled but CLOUDFLARE_ACCESS_TEAM_DOMAIN/AUD are unset; "
        "the JWT signature is NOT being verified."
    )
    return True


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
    # token_hash is a deterministic sha256, so look it up directly instead of
    # scanning every enabled agent.
    agent = (
        db.query(Agent)
        .filter(Agent.enabled.is_(True), Agent.token_hash == hash_token(x_agent_token))
        .first()
    )
    if agent is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="探针令牌无效")
    return agent
