from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import Event, User
from ..schemas import EventOut


router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=list[EventOut])
def list_events(limit: int = Query(default=100, ge=1, le=500), _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Event).order_by(Event.created_at.desc()).limit(limit).all()

