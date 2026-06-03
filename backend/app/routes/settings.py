from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import User
from ..runtime_settings import get_runtime_settings, update_runtime_settings
from ..schemas import SystemSettingsOut, SystemSettingsUpdate


router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("", response_model=SystemSettingsOut)
def read_system_settings(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return SystemSettingsOut(**get_runtime_settings(db).model_dump())


@router.patch("", response_model=SystemSettingsOut)
def update_system_settings(payload: SystemSettingsUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        settings = update_runtime_settings(db, payload.model_dump(exclude_unset=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    return SystemSettingsOut(**settings.model_dump())
