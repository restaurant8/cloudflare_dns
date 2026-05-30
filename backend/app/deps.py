from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .database import get_db
from .models import Agent, User
from .security import verify_access_token, verify_token_hash


bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
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
