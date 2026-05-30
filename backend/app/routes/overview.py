from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import Agent, CloudflareCredential, Event, FailoverGroup, Origin, User, Zone
from ..schemas import Overview


router = APIRouter(prefix="/overview", tags=["overview"])


@router.get("", response_model=Overview)
def overview(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    recent_events = db.query(Event).order_by(Event.created_at.desc()).limit(10).all()
    return Overview(
        credentials=db.query(CloudflareCredential).count(),
        zones=db.query(Zone).count(),
        groups=db.query(FailoverGroup).count(),
        enabled_groups=db.query(FailoverGroup).filter(FailoverGroup.enabled.is_(True)).count(),
        origins=db.query(Origin).count(),
        unhealthy_origins=db.query(Origin).filter(Origin.status == "unhealthy").count(),
        agents=db.query(Agent).count(),
        recent_events=recent_events,
    )

