from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, selectinload

from ..alibaba_httpdns import (
    evaluate_alibaba_httpdns_groups,
    list_credential_records,
    list_credential_zones,
    list_remote_accounts,
    list_remote_records,
    list_remote_zones,
)
from ..database import get_db
from ..deps import get_current_user
from ..dns_utils import normalize_hostname, parse_target
from ..events import add_event
from ..models import AlibabaHttpDnsCredential, AlibabaHttpDnsGroup, AlibabaHttpDnsOrigin, FailoverGroup, Origin, User
from ..schemas import (
    AlibabaHttpDnsGroupCreate,
    AlibabaHttpDnsGroupOut,
    AlibabaHttpDnsGroupUpdate,
    AlibabaHttpDnsCredentialCreate,
    AlibabaHttpDnsCredentialOut,
    AlibabaHttpDnsCredentialUpdate,
    AlibabaHttpDnsOriginCreate,
    AlibabaHttpDnsOriginOut,
    AlibabaHttpDnsOriginUpdate,
    AlibabaHttpDnsRemoteAccountOut,
    AlibabaHttpDnsRemoteRecordOut,
    AlibabaHttpDnsRemoteZoneOut,
    AlibabaHttpDnsZoneAdopt,
    AlibabaHttpDnsZoneRelease,
    Message,
)
from ..origin_expansion import published_ips, set_published_ips
from ..security import encrypt_secret


router = APIRouter(prefix="/alibaba-httpdns", tags=["alibaba-httpdns"])


def _group_query(db: Session):
    return db.query(AlibabaHttpDnsGroup).options(selectinload(AlibabaHttpDnsGroup.origins))


def _find_remote_record(
    db: Session,
    account_id: int,
    zone_id: str,
    record_id: str,
    credential: AlibabaHttpDnsCredential | None = None,
) -> dict:
    records = list_credential_records(credential, zone_id) if credential is not None else list_remote_records(db, account_id, zone_id)
    record = next((item for item in records if str(item.get("RecordId") or "") == record_id), None)
    if record is None:
        raise HTTPException(status_code=404, detail="阿里云 HTTPDNS 解析记录不存在")
    if str(record.get("Type") or "").upper() not in {"A", "AAAA", "CNAME"}:
        raise HTTPException(status_code=400, detail="故障切换仅支持 A、AAAA 和 CNAME 记录")
    return record


def _record_enabled(record: dict) -> bool:
    return str(record.get("EnableStatus") or "enable").strip().lower() not in {"disable", "disabled", "false", "0"}


def _target_allowed(record_type: str, target_type: str) -> bool:
    if record_type == "CNAME":
        return target_type == "hostname"
    if target_type == "hostname":
        return record_type in {"A", "AAAA"}
    return (record_type, target_type) in {("A", "ipv4"), ("AAAA", "ipv6")}


def _adopt_record(
    db: Session,
    *,
    remote_account_id: int,
    account_name: str,
    zone_id: str,
    zone_name: str,
    record: dict,
    primary_port: int,
    enabled: bool,
    min_switch_interval_seconds: int,
    credential_id: int | None = None,
) -> AlibabaHttpDnsGroup:
    record_id = str(record.get("RecordId") or "").strip()
    if not record_id:
        raise ValueError("阿里云 HTTPDNS 记录缺少 RecordId")
    duplicate = db.query(AlibabaHttpDnsGroup).filter(
        AlibabaHttpDnsGroup.remote_account_id == remote_account_id,
        AlibabaHttpDnsGroup.zone_id == zone_id,
        AlibabaHttpDnsGroup.record_id == record_id,
    ).one_or_none()
    if duplicate is not None:
        return duplicate
    record_type = str(record.get("Type") or "").upper()
    if record_type not in {"A", "AAAA", "CNAME"}:
        raise ValueError(f"故障切换不支持 {record_type or '未知'} 记录")
    target = parse_target(str(record.get("Value") or ""))
    if target.record_type != record_type:
        raise ValueError(f"记录 {record_id} 的类型和值不匹配")
    group = AlibabaHttpDnsGroup(
        credential_id=credential_id,
        remote_account_id=remote_account_id,
        account_name=account_name.strip(),
        zone_id=zone_id.strip(),
        zone_name=zone_name.strip(),
        record_id=record_id,
        rr=str(record.get("Rr") or "@").strip(),
        record_type=record_type,
        ttl=int(record.get("Ttl") or 60),
        request_source=str(record.get("RequestSource") or "default"),
        weight=int(record.get("Weight") or 1),
        priority=int(record.get("Priority") or 1),
        remark=str(record.get("Remark") or "").strip() or None,
        enabled=enabled,
        min_switch_interval_seconds=min_switch_interval_seconds,
        last_published_value=target.value,
    )
    db.add(group)
    db.flush()
    if credential_id is not None:
        hostname = normalize_hostname(f"{group.rr}.{group.zone_name}".replace("@.", ""))
        source_group = FailoverGroup(
            provider_type="alibaba_httpdns",
            zone_id=None,
            hostname=hostname,
            ttl=group.ttl,
            enabled=enabled,
            min_switch_interval_seconds=min_switch_interval_seconds,
            cloudflare_publish_enabled=False,
            doh_enabled=False,
        )
        db.add(source_group)
        db.flush()
        source_origin = Origin(
            group_id=source_group.id,
            target=target.value,
            target_type=target.target_type,
            publish_mode="expanded" if target.target_type == "hostname" and record_type != "CNAME" else "direct",
            port=primary_port,
            priority=0,
            remark="Alibaba HTTPDNS primary",
            enabled=True,
            status="unknown",
        )
        db.add(source_origin)
        db.flush()
        source_group.current_origin_id = source_origin.id
        group.source_group_id = source_group.id
        group.source_current_origin_id = source_origin.id
        return group
    origin = AlibabaHttpDnsOrigin(
        group_id=group.id,
        target=target.value,
        target_type=target.target_type,
        port=primary_port,
        priority=0,
        remark="当前阿里云解析（主用）",
        enabled=True,
    )
    db.add(origin)
    db.flush()
    if target.target_type != "hostname":
        set_published_ips(origin, [target.value])
    group.current_origin_id = origin.id
    return group


def _credential(db: Session, credential_id: int) -> AlibabaHttpDnsCredential:
    credential = db.get(AlibabaHttpDnsCredential, credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="Alibaba HTTPDNS credential not found")
    return credential


@router.get("/credentials", response_model=list[AlibabaHttpDnsCredentialOut])
def credentials(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(AlibabaHttpDnsCredential).order_by(AlibabaHttpDnsCredential.name).all()


@router.post("/credentials", response_model=AlibabaHttpDnsCredentialOut)
def create_credential(
    payload: AlibabaHttpDnsCredentialCreate,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    credential = AlibabaHttpDnsCredential(
        name=payload.name.strip(),
        access_key_id_encrypted=encrypt_secret(payload.access_key_id.strip()),
        access_key_secret_encrypted=encrypt_secret(payload.access_key_secret.strip()),
        region=payload.region.strip(),
        endpoint=payload.endpoint.strip(),
        enabled=True,
    )
    db.add(credential)
    try:
        db.flush()
        list_credential_zones(credential)
        credential.enabled = payload.enabled
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Alibaba HTTPDNS credential test failed: {exc}") from exc
    db.commit()
    db.refresh(credential)
    return credential


@router.patch("/credentials/{credential_id}", response_model=AlibabaHttpDnsCredentialOut)
def update_credential(
    credential_id: int,
    payload: AlibabaHttpDnsCredentialUpdate,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    credential = _credential(db, credential_id)
    updates = payload.model_dump(exclude_unset=True)
    requested_enabled = updates.pop("enabled", credential.enabled)
    if "access_key_id" in updates:
        value = updates.pop("access_key_id")
        if value:
            credential.access_key_id_encrypted = encrypt_secret(value.strip())
    if "access_key_secret" in updates:
        value = updates.pop("access_key_secret")
        if value:
            credential.access_key_secret_encrypted = encrypt_secret(value.strip())
    for key, value in updates.items():
        setattr(credential, key, value.strip() if isinstance(value, str) else value)
    try:
        credential.enabled = True
        list_credential_zones(credential)
        credential.enabled = requested_enabled
        credential.last_error = None
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Alibaba HTTPDNS credential test failed: {exc}") from exc
    db.commit()
    db.refresh(credential)
    return credential


@router.delete("/credentials/{credential_id}", response_model=Message)
def delete_credential(
    credential_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    credential = _credential(db, credential_id)
    used = db.query(AlibabaHttpDnsGroup).filter(AlibabaHttpDnsGroup.credential_id == credential.id).count()
    if used:
        raise HTTPException(status_code=409, detail=f"Credential is used by {used} Alibaba HTTPDNS rule(s)")
    db.delete(credential)
    db.commit()
    return Message(message="Alibaba HTTPDNS credential deleted")


@router.get("/credentials/{credential_id}/zones", response_model=list[AlibabaHttpDnsRemoteZoneOut])
def credential_zones(
    credential_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    credential = _credential(db, credential_id)
    try:
        result = list_credential_zones(credential)
        credential.last_error = None
        db.commit()
        return result
    except Exception as exc:
        credential.last_error = str(exc)
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/credentials/{credential_id}/zones/{zone_id}/records", response_model=list[AlibabaHttpDnsRemoteRecordOut])
def credential_records(
    credential_id: int,
    zone_id: str,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    credential = _credential(db, credential_id)
    try:
        return [
            item
            for item in list_credential_records(credential, zone_id)
            if str(item.get("Type") or "").upper() in {"A", "AAAA", "CNAME"}
        ]
    except Exception as exc:
        credential.last_error = str(exc)
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/remote/accounts", response_model=list[AlibabaHttpDnsRemoteAccountOut])
def remote_accounts(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        return list_remote_accounts(db)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/remote/zones", response_model=list[AlibabaHttpDnsRemoteZoneOut])
def remote_zones(account_id: int = Query(..., ge=1), _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        return list_remote_zones(db, account_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/remote/records", response_model=list[AlibabaHttpDnsRemoteRecordOut])
def remote_records(account_id: int = Query(..., ge=1), zone_id: str = Query(...), _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        return [item for item in list_remote_records(db, account_id, zone_id) if str(item.get("Type") or "").upper() in {"A", "AAAA", "CNAME"}]
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/groups", response_model=list[AlibabaHttpDnsGroupOut])
def list_groups(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _group_query(db).order_by(AlibabaHttpDnsGroup.created_at.desc()).all()


@router.post("/zones", response_model=Message)
def adopt_zone(payload: AlibabaHttpDnsZoneAdopt, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    credential = _credential(db, payload.credential_id) if payload.credential_id is not None else None
    account_id = -credential.id if credential is not None else payload.remote_account_id
    try:
        records = (
            list_credential_records(credential, payload.zone_id)
            if credential is not None
            else list_remote_records(db, account_id, payload.zone_id)
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    candidates = [
        item
        for item in records
        if str(item.get("Type") or "").upper() in {"A", "AAAA", "CNAME"} and _record_enabled(item)
    ]
    if not candidates:
        raise HTTPException(status_code=400, detail="这个内置权威域名下没有已启用的 A、AAAA 或 CNAME 记录")
    existing_ids = {
        item.record_id
        for item in db.query(AlibabaHttpDnsGroup).filter(
            AlibabaHttpDnsGroup.remote_account_id == account_id,
            AlibabaHttpDnsGroup.zone_id == payload.zone_id,
        ).all()
    }
    created = 0
    skipped = 0
    errors: list[str] = []
    for record in candidates:
        record_id = str(record.get("RecordId") or "")
        if record_id in existing_ids:
            skipped += 1
            continue
        try:
            _adopt_record(
                db,
                remote_account_id=account_id,
                account_name=credential.name if credential is not None else payload.account_name,
                zone_id=payload.zone_id,
                zone_name=payload.zone_name,
                record=record,
                primary_port=payload.primary_port,
                enabled=payload.enabled,
                min_switch_interval_seconds=payload.min_switch_interval_seconds,
                credential_id=credential.id if credential is not None else None,
            )
            created += 1
        except ValueError as exc:
            errors.append(str(exc))
    if created == 0 and skipped == 0:
        raise HTTPException(status_code=400, detail=errors[0] if errors else "没有可接管的解析记录")
    add_event(
        db,
        "alibaba_httpdns.zone_adopted",
        "info",
        f"阿里云 HTTPDNS 权威域名 {payload.zone_name} 已接管，新增 {created} 条记录",
        {"account_id": account_id, "credential_id": payload.credential_id, "zone_id": payload.zone_id, "created": created, "existing": skipped, "errors": errors},
    )
    db.commit()
    return Message(message=f"权威域名已同步：新增 {created} 条，已有 {skipped} 条", detail={"created": created, "existing": skipped, "errors": errors})


def _release_zone(db: Session, remote_account_id: int, zone_id: str) -> Message:
    groups = _group_query(db).filter(
        AlibabaHttpDnsGroup.remote_account_id == remote_account_id,
        AlibabaHttpDnsGroup.zone_id == zone_id,
    ).all()
    if not groups:
        raise HTTPException(status_code=404, detail="这个权威域名尚未接管")
    if any(group.source_group is not None and group.source_group.provider_type == "alibaba_httpdns" for group in groups):
        raise HTTPException(
            status_code=409,
            detail="Direct Alibaba rules own full failover groups; delete them individually in the Alibaba failover list so every source deletion is explicit",
        )
    for group in groups:
        db.delete(group)
    db.commit()
    return Message(message=f"已取消管理 {len(groups)} 条记录，阿里云云端解析保持不变")


@router.post("/zones/release", response_model=Message)
def release_zone_action(payload: AlibabaHttpDnsZoneRelease, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """POST compatibility endpoint for reverse proxies that do not forward DELETE reliably."""
    account_id = -payload.credential_id if payload.credential_id is not None else payload.remote_account_id
    return _release_zone(db, account_id, payload.zone_id)


@router.delete("/zones/{remote_account_id}/{zone_id}", response_model=Message)
def release_zone(remote_account_id: int, zone_id: str, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _release_zone(db, remote_account_id, zone_id)


@router.post("/groups", response_model=AlibabaHttpDnsGroupOut)
def create_group(payload: AlibabaHttpDnsGroupCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    credential = _credential(db, payload.credential_id) if payload.credential_id is not None else None
    account_id = -credential.id if credential is not None else payload.remote_account_id
    duplicate = db.query(AlibabaHttpDnsGroup).filter(
        AlibabaHttpDnsGroup.remote_account_id == account_id,
        AlibabaHttpDnsGroup.zone_id == payload.zone_id,
        AlibabaHttpDnsGroup.record_id == payload.record_id,
    ).one_or_none()
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="这条阿里云 HTTPDNS 记录已经创建切换组")
    try:
        record = _find_remote_record(db, account_id, payload.zone_id, payload.record_id, credential)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    group = _adopt_record(
        db,
        remote_account_id=account_id,
        account_name=credential.name if credential is not None else payload.account_name.strip(),
        zone_id=payload.zone_id.strip(),
        zone_name=payload.zone_name.strip(),
        record=record,
        primary_port=payload.primary_port,
        enabled=payload.enabled,
        min_switch_interval_seconds=payload.min_switch_interval_seconds,
        credential_id=credential.id if credential is not None else None,
    )
    add_event(db, "alibaba_httpdns.group_created", "info", f"阿里云 HTTPDNS {group.rr}.{group.zone_name} 切换组已创建", {"group_id": group.id, "record_id": group.record_id})
    db.commit()
    return _group_query(db).filter(AlibabaHttpDnsGroup.id == group.id).one()


@router.patch("/groups/{group_id}", response_model=AlibabaHttpDnsGroupOut)
def update_group(group_id: int, payload: AlibabaHttpDnsGroupUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(AlibabaHttpDnsGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="阿里云 HTTPDNS 切换组不存在")
    updates = payload.model_dump(exclude_unset=True)
    if "source_group_id" in updates and updates["source_group_id"] is not None:
        source = db.get(FailoverGroup, updates["source_group_id"])
        if source is None:
            raise HTTPException(status_code=404, detail="Linked failover group not found")
    if "source_group_id" in updates and updates["source_group_id"] != group.source_group_id:
        group.source_current_origin_id = None
        group.last_switch_at = None
    for key, value in updates.items():
        setattr(group, key, value)
    db.commit()
    if group.enabled:
        evaluate_alibaba_httpdns_groups(db, [group.id], force_consistency=True)
        db.commit()
    return _group_query(db).filter(AlibabaHttpDnsGroup.id == group.id).one()


@router.delete("/groups/{group_id}", response_model=Message)
def delete_group(group_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(AlibabaHttpDnsGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="阿里云 HTTPDNS 切换组不存在")
    if group.source_group is not None and group.source_group.provider_type == "alibaba_httpdns":
        raise HTTPException(
            status_code=409,
            detail="Delete this direct Alibaba rule from its full failover group card",
        )
    db.delete(group)
    db.commit()
    return Message(message="阿里云 HTTPDNS 切换组已删除，云端记录保持不变")


@router.post("/groups/{group_id}/origins", response_model=AlibabaHttpDnsOriginOut)
def create_origin(group_id: int, payload: AlibabaHttpDnsOriginCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(AlibabaHttpDnsGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="阿里云 HTTPDNS 切换组不存在")
    try:
        target = parse_target(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not _target_allowed(group.record_type, target.target_type):
        raise HTTPException(status_code=400, detail=f"当前记录是 {group.record_type}，目标将被识别为 {target.record_type}")
    if target.record_type == "CNAME" and target.value.rstrip(".").lower() == f"{group.rr}.{group.zone_name}".replace("@.", "").rstrip(".").lower():
        raise HTTPException(status_code=400, detail="CNAME 目标不能和当前记录名称相同")
    duplicate = next(
        (item for item in group.origins if item.target.rstrip(".").lower() == target.value.rstrip(".").lower() and item.port == payload.port),
        None,
    )
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="相同目标和端口已经存在")
    origin = AlibabaHttpDnsOrigin(group_id=group.id, target=target.value, target_type=target.target_type, port=payload.port, priority=payload.priority, remark=payload.remark.strip() if payload.remark else None, enabled=payload.enabled, ignore_health_check=payload.ignore_health_check)
    db.add(origin)
    db.commit()
    db.refresh(origin)
    if group.enabled:
        evaluate_alibaba_httpdns_groups(db, [group.id])
        db.commit()
        db.refresh(origin)
    return origin


@router.patch("/origins/{origin_id}", response_model=AlibabaHttpDnsOriginOut)
def update_origin(origin_id: int, payload: AlibabaHttpDnsOriginUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    origin = db.get(AlibabaHttpDnsOrigin, origin_id)
    if origin is None:
        raise HTTPException(status_code=404, detail="阿里云 HTTPDNS 源站不存在")
    updates = payload.model_dump(exclude_unset=True)
    old_target = origin.target
    old_target_type = origin.target_type
    next_target_value = origin.target
    next_target_type = origin.target_type
    if "target" in updates:
        try:
            target = parse_target(updates["target"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not _target_allowed(origin.group.record_type, target.target_type):
            raise HTTPException(status_code=400, detail=f"当前记录是 {origin.group.record_type}，目标将被识别为 {target.record_type}")
        if target.record_type == "CNAME" and target.value.rstrip(".").lower() == f"{origin.group.rr}.{origin.group.zone_name}".replace("@.", "").rstrip(".").lower():
            raise HTTPException(status_code=400, detail="CNAME 目标不能和当前记录名称相同")
        next_target_value = target.value
        next_target_type = target.target_type
        updates["target"] = target.value
    next_port = int(updates.get("port", origin.port))
    duplicate = next(
        (
            item
            for item in origin.group.origins
            if item.id != origin.id
            and item.target.rstrip(".").lower() == next_target_value.rstrip(".").lower()
            and item.port == next_port
        ),
        None,
    )
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="相同目标和端口已经存在")
    endpoint_changed = next_target_value != origin.target or next_port != origin.port
    if endpoint_changed and origin.group.current_origin_id == origin.id:
        if not origin.group.last_published_value:
            origin.group.last_published_value = old_target
        if not published_ips(origin) and old_target_type != "hostname":
            set_published_ips(origin, [old_target])
    origin.target_type = next_target_type
    for key, value in updates.items():
        if key == "remark" and isinstance(value, str):
            value = value.strip() or None
        setattr(origin, key, value)
    if endpoint_changed:
        origin.status = "unknown"
        origin.success_count = 0
        origin.fail_count = 0
        origin.last_checked_at = None
        origin.last_error = None
        origin.last_rtt_ms = None
        origin.resolved_ips_json = "[]"
        origin.healthy_ips_json = "[]"
        origin.ip_probe_states_json = "{}"
    db.commit()
    if origin.group.enabled:
        evaluate_alibaba_httpdns_groups(db, [origin.group_id])
        db.commit()
    db.refresh(origin)
    return origin


def _delete_origin(db: Session, origin_id: int) -> Message:
    origin = db.get(AlibabaHttpDnsOrigin, origin_id)
    if origin is None:
        raise HTTPException(status_code=404, detail="阿里云 HTTPDNS 源站不存在")
    group = origin.group
    if len(group.origins) <= 1:
        raise HTTPException(status_code=400, detail="至少需要保留一个源站")
    was_current = group.current_origin_id == origin.id
    if was_current:
        group.current_origin_id = None
        group.last_switch_at = None
    db.delete(origin)
    # Persist the requested deletion before any optional cloud-side re-evaluation.
    # Removing a backup target must never depend on azpanel/Alibaba availability.
    db.commit()
    if was_current and group.enabled:
        evaluate_alibaba_httpdns_groups(db, [group.id])
        db.commit()
    return Message(message="源站已删除")


@router.post("/origins/{origin_id}/delete", response_model=Message)
def delete_origin_action(origin_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """POST compatibility endpoint for reverse proxies that do not forward DELETE reliably."""
    return _delete_origin(db, origin_id)


@router.delete("/origins/{origin_id}", response_model=Message)
def delete_origin(origin_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _delete_origin(db, origin_id)


@router.post("/run", response_model=Message)
def run_now(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    switched = evaluate_alibaba_httpdns_groups(db, force_consistency=True)
    db.commit()
    return Message(message=f"阿里云 HTTPDNS 检查完成，本次切换 {switched} 组")


@router.post("/groups/{group_id}/run", response_model=Message)
def run_group_now(group_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(AlibabaHttpDnsGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="阿里云 HTTPDNS 切换组不存在")
    if not group.enabled:
        raise HTTPException(status_code=400, detail="请先启用这个切换组")
    switched = evaluate_alibaba_httpdns_groups(db, [group_id], force_consistency=True)
    db.commit()
    return Message(message=f"检查完成，本次切换 {switched} 组")
