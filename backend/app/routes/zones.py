from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import DnsRecord, User, Zone
from ..schemas import DnsRecordOut, Message, ZoneOut
from ..sync import sync_zone_records


router = APIRouter(prefix="/zones", tags=["zones"])


@router.get("", response_model=list[ZoneOut])
def list_zones(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Zone).order_by(Zone.name.asc()).all()


@router.get("/records/search", response_model=list[DnsRecordOut])
def search_records(zone_id: int = Query(...), q: str = Query(default=""), _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(DnsRecord).filter(DnsRecord.zone_id == zone_id)
    if q:
        query = query.filter(DnsRecord.name.contains(q))
    return query.order_by(DnsRecord.name.asc()).limit(100).all()


@router.get("/{zone_id}/records", response_model=list[DnsRecordOut])
def list_records(zone_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    zone = db.get(Zone, zone_id)
    if zone is None:
        raise HTTPException(status_code=404, detail="域名区域不存在")
    return db.query(DnsRecord).filter(DnsRecord.zone_id == zone_id).order_by(DnsRecord.name.asc(), DnsRecord.type.asc()).all()


@router.post("/{zone_id}/records/sync", response_model=Message)
def sync_records(zone_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    zone = db.get(Zone, zone_id)
    if zone is None:
        raise HTTPException(status_code=404, detail="域名区域不存在")
    sync_zone_records(db, zone.credential, zone)
    db.commit()
    return Message(message="解析记录已同步")
