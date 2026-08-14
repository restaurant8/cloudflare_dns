import json
from collections.abc import Collection

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session, selectinload

from ..cloudflare import CloudflareClient, CloudflareError
from ..alibaba_httpdns import (
    AlibabaOutputConfigurationError,
    required_alibaba_origin_publish_mode,
    sync_group_alibaba_outputs,
    validate_alibaba_origin_for_outputs,
)
from ..database import get_db
from ..deps import get_current_user
from ..dns_utils import normalize_hostname, parse_target
from ..events import add_event
from ..doh import sync_doh_endpoint, sync_group_doh_endpoint, validate_doh_hostname_conflicts
from ..failover import ensure_group_hostname_entries, evaluate_failover_groups, find_managed_dns_record_by_id, publish_origin, validate_group_hostname_records, zone_for_hostname
from ..health import run_local_checks
from ..integrations import azpanel_settings, refresh_legacy_origin_mirror, sync_resource_current_ip_to_origin
from ..models import Agent, AlibabaHttpDnsGroup, AzPanelRemoteResource, AzPanelResource, DohEndpoint, ExternalIpItem, FailoverCollection, FailoverGlobalOrigin, FailoverGroup, FailoverHostname, FailoverTimeRule, Origin, ProbeState, User, Zone
from ..notifier import send_webhooks
from ..origin_expansion import (
    DIRECT_PUBLISH_MODE,
    EXPANDED_PUBLISH_MODE,
    expanded_ip_priorities,
    set_expanded_ip_priorities,
    set_healthy_ips,
    set_published_ips,
    set_resolved_ips,
)
from ..route53 import sync_group_route53_outputs
from ..schemas import (
    FailoverCollectionCreate,
    FailoverCollectionOut,
    FailoverCollectionUpdate,
    FailoverGlobalOriginCreate,
    FailoverGlobalOriginOut,
    FailoverGlobalOriginUpdate,
    FailoverGroupCreate,
    FailoverGroupOut,
    FailoverGroupUpdate,
    FailoverHostnameCreate,
    FailoverTimeRuleOut,
    FailoverTimeRuleUpsert,
    Message,
    OriginBulkCreate,
    OriginCreate,
    OriginOut,
    OriginUpdate,
)
from ..security import decrypt_secret
from ..sync import MANAGED_RECORD_TYPES


router = APIRouter(prefix="/groups", tags=["groups"])


def _evaluate_locally(db: Session, group_ids: Collection[int]) -> None:
    """Re-evaluate only the groups this edit actually touched.

    Editing one origin used to evaluate *every* enabled group, which probed their
    targets, could rotate their azpanel/SynexVM IPs, and cost one Cloudflare API
    call per hostname for the steady-state drift check — seconds of latency and
    side effects on groups the user never touched. Scoping to the affected groups
    keeps the part that must stay synchronous (a deleted or edited *current*
    origin has to republish before the response returns, or DNS would keep
    pointing at it) and drops the rest. Drift repair and IP rotation stay the
    scheduler's job.
    """
    ids = sorted({int(value) for value in group_ids})
    if not ids:
        return
    evaluate_failover_groups(db, group_ids=ids, check_dns_consistency=False, trigger_ip_changes=False)


def _require_group_doh_sync(db: Session, group: FailoverGroup) -> None:
    if sync_group_doh_endpoint(db, group):
        return
    endpoint = db.get(DohEndpoint, group.doh_endpoint_id) if group.doh_endpoint_id else None
    raise RuntimeError(endpoint.last_error if endpoint and endpoint.last_error else "DoH endpoint did not accept the snapshot")


def _enabled_collection_group_ids(collection: FailoverCollection) -> list[int]:
    return [group.id for group in collection.groups if group.enabled]


def _normalize_remark(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _apply_expanded_ip_priorities(target, values: dict[str, int] | None) -> None:
    try:
        set_expanded_ip_priorities(target, values or {})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _validate_preferred_agent_id(db: Session, agent_id: int | None) -> int | None:
    if agent_id is None:
        return None
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="指定探针不存在")
    return agent.id


def _azpanel_resource(db: Session, resource_id: int | None) -> AzPanelResource | None:
    if resource_id is None:
        return None
    resource = db.get(AzPanelResource, resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="azpanel 云资源不存在")
    return resource


def _refresh_azpanel_resource_bindings(db: Session, resource_ids: Collection[int | None]) -> None:
    """Refresh the legacy single-origin mirror after target-side binding changes."""
    db.flush()
    for resource_id in sorted({int(value) for value in resource_ids if value is not None}):
        resource = db.get(AzPanelResource, resource_id)
        if resource is not None:
            refresh_legacy_origin_mirror(db, resource)


def _normalize_probe_mode(value: str | None) -> str:
    return value if value in {"default", "local_only", "china_only", "any"} else "default"


def _parse_target_or_400(value: str):
    try:
        return parse_target(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _normalize_doh_hostnames(values: list[str] | None, fallback: str) -> list[str]:
    try:
        normalized = [normalize_hostname(value) for value in (values or [])]
        normalized_fallback = normalize_hostname(fallback)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = list(dict.fromkeys(normalized))
    return result or [normalized_fallback]


def _validate_group_outputs(
    db: Session,
    *,
    cloudflare_publish_enabled: bool,
    doh_enabled: bool,
    doh_endpoint_id: int | None,
    doh_hostnames: list[str],
    group_id: int | None = None,
) -> None:
    # Origin selection and output publication are deliberately decoupled. A group
    # may temporarily have no output while it is being assembled, disabled, or
    # moved between providers. Provider-specific routes validate their bindings.
    if doh_enabled:
        endpoint = db.get(DohEndpoint, doh_endpoint_id) if doh_endpoint_id else None
        if endpoint is None or not endpoint.enabled:
            raise HTTPException(status_code=400, detail="Enabled DoH publishing requires an enabled DoH endpoint")
        try:
            validate_doh_hostname_conflicts(
                db,
                endpoint_id=endpoint.id,
                hostnames=doh_hostnames,
                exclude_group_id=group_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc


def _group_query(db: Session):
    return db.query(FailoverGroup).options(
        selectinload(FailoverGroup.hostnames),
        selectinload(FailoverGroup.origins).selectinload(Origin.probe_states).selectinload(ProbeState.agent),
        selectinload(FailoverGroup.alibaba_httpdns_outputs),
        selectinload(FailoverGroup.time_rule),
    )


def _minute_of_day(value: str) -> int:
    hour, minute = (int(part) for part in value.split(":"))
    return hour * 60 + minute


def _weekdays_mask(weekdays: list[int]) -> int:
    return sum(1 << day for day in weekdays)


def _delete_time_rule_for_origin(db: Session, origin: Origin) -> None:
    rule = db.query(FailoverTimeRule).filter(FailoverTimeRule.origin_id == origin.id).one_or_none()
    if rule is None:
        return
    if rule.last_active:
        origin.group.last_switch_at = None
    db.delete(rule)


def _group_hostname_values(group: FailoverGroup) -> set[str]:
    values = {group.hostname}
    values.update(hostname.hostname for hostname in group.hostnames)
    return values


def _zone_matches_hostname(zone_name: str, hostname: str) -> bool:
    zone_name = (zone_name or "").rstrip(".").lower()
    hostname = (hostname or "").rstrip(".").lower()
    return bool(zone_name) and (hostname == zone_name or hostname.endswith("." + zone_name))


def _resolve_hostname_zone(db: Session, group: FailoverGroup, hostname: str) -> Zone | None:
    """Find the registered Cloudflare zone a hostname belongs to.

    Prefers the longest matching zone name, then the group's own credential so a
    same-zone hostname always resolves to the group's zone.
    """
    candidates = [zone for zone in db.query(Zone).all() if _zone_matches_hostname(zone.name, hostname)]
    if not candidates:
        return None
    group_credential_id = group.zone.credential_id if group.zone is not None else None
    candidates.sort(
        key=lambda zone: (
            len(zone.name or ""),
            1 if group_credential_id is not None and zone.credential_id == group_credential_id else 0,
        ),
        reverse=True,
    )
    return candidates[0]


def _external_binding_from_item_id(db: Session, item_id: int) -> tuple[int, str]:
    item = db.get(ExternalIpItem, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="外部 IP 不存在，请先刷新外部 IP 列表")
    if not item.machine_key:
        raise HTTPException(status_code=400, detail="该外部 IP 没有机器标识，无法绑定（换 IP 后无法跟踪）")
    return item.source_id, item.machine_key


def _origin_from_payload(db: Session, group: FailoverGroup, payload: OriginCreate) -> Origin:
    target_info = _parse_target_or_400(payload.target)
    if target_info.record_type == "CNAME" and target_info.value in _group_hostname_values(group):
        raise HTTPException(status_code=400, detail="CNAME 目标不能和当前主机名相同")
    if payload.publish_mode == EXPANDED_PUBLISH_MODE and target_info.target_type != "hostname":
        raise HTTPException(status_code=400, detail="只有域名目标可以启用展开 IP 池")
    external_source_id = None
    external_machine_key = None
    if payload.external_ip_item_id is not None:
        external_source_id, external_machine_key = _external_binding_from_item_id(db, payload.external_ip_item_id)
    try:
        publish_mode = required_alibaba_origin_publish_mode(
            group,
            target_info.target_type,
            payload.publish_mode,
        )
        validate_alibaba_origin_for_outputs(
            group,
            target_type=target_info.target_type,
            publish_mode=publish_mode,
            enabled=payload.enabled,
        )
    except AlibabaOutputConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    origin = Origin(
        group_id=group.id,
        target=target_info.value,
        target_type=target_info.target_type,
        publish_mode=publish_mode,
        port=payload.port,
        priority=payload.priority,
        preferred_agent_id=_validate_preferred_agent_id(db, payload.preferred_agent_id),
        probe_mode=_normalize_probe_mode(payload.probe_mode),
        remark=_normalize_remark(payload.remark),
        enabled=payload.enabled,
        ignore_health_check=payload.ignore_health_check,
        external_source_id=external_source_id,
        external_machine_key=external_machine_key,
    )
    _apply_expanded_ip_priorities(origin, payload.expanded_ip_priorities if target_info.target_type == "hostname" else {})
    return origin


def _origin_from_dns_record(group: FailoverGroup, record: dict, port: int) -> Origin:
    if record.get("type") not in MANAGED_RECORD_TYPES:
        raise HTTPException(status_code=400, detail="只支持接管 A/AAAA/CNAME 记录")
    target_info = _parse_target_or_400(str(record.get("content") or ""))
    if target_info.record_type == "CNAME" and target_info.value in _group_hostname_values(group):
        raise HTTPException(status_code=400, detail="CNAME 目标不能和当前主机名相同")
    return Origin(
        group_id=group.id,
        target=target_info.value,
        target_type=target_info.target_type,
        publish_mode=DIRECT_PUBLISH_MODE,
        port=port,
        priority=0,
        enabled=True,
    )


def _collection_query(db: Session):
    return db.query(FailoverCollection).options(selectinload(FailoverCollection.global_origins))


def _collection_hostname_values(collection: FailoverCollection) -> set[str]:
    values: set[str] = set()
    for group in collection.groups:
        values.update(_group_hostname_values(group))
    return values


def _global_origin_from_payload(db: Session, collection: FailoverCollection, payload: FailoverGlobalOriginCreate) -> FailoverGlobalOrigin:
    resource = _azpanel_resource(db, payload.azpanel_resource_id)
    target = payload.target
    port = payload.port
    # An external-machine binding owns the observed address. Otherwise a bound
    # azpanel/SynexVM resource's current address is authoritative immediately.
    if payload.external_ip_item_id is None and resource is not None and resource.auto_update_origin and resource.current_ip:
        target = resource.current_ip
        port = resource.port
    target_info = _parse_target_or_400(target)
    if target_info.record_type == "CNAME" and target_info.value in _collection_hostname_values(collection):
        raise HTTPException(status_code=400, detail="全局 CNAME 备用不能和当前业务分组内的主机名相同")
    if payload.publish_mode == EXPANDED_PUBLISH_MODE and target_info.target_type != "hostname":
        raise HTTPException(status_code=400, detail="只有域名目标可以启用展开 IP 池")
    external_source_id = None
    external_machine_key = None
    if payload.external_ip_item_id is not None:
        external_source_id, external_machine_key = _external_binding_from_item_id(db, payload.external_ip_item_id)
    global_origin = FailoverGlobalOrigin(
        collection_id=collection.id,
        target=target_info.value,
        target_type=target_info.target_type,
        publish_mode=payload.publish_mode if target_info.target_type == "hostname" else DIRECT_PUBLISH_MODE,
        port=port,
        priority=payload.priority,
        external_source_id=external_source_id,
        external_machine_key=external_machine_key,
        azpanel_resource_id=resource.id if resource is not None else None,
        preferred_agent_id=_validate_preferred_agent_id(db, payload.preferred_agent_id),
        probe_mode=_normalize_probe_mode(payload.probe_mode),
        remark=_normalize_remark(payload.remark),
        enabled=payload.enabled,
        ignore_health_check=payload.ignore_health_check,
    )
    _apply_expanded_ip_priorities(global_origin, payload.expanded_ip_priorities if target_info.target_type == "hostname" else {})
    return global_origin


def _reset_origin_probe_state(origin: Origin) -> None:
    origin.status = "unknown"
    origin.last_error = "等待本地和探针探测结果"
    origin.last_checked_at = None
    origin.last_rtt_ms = None
    origin.probe_states.clear()
    set_resolved_ips(origin, [])
    set_healthy_ips(origin, [])
    set_published_ips(origin, [])


def _copy_global_origin_to_origin(origin: Origin, global_origin: FailoverGlobalOrigin) -> bool:
    endpoint_changed = (
        origin.target != global_origin.target
        or origin.target_type != global_origin.target_type
        or origin.port != global_origin.port
        or origin.publish_mode != global_origin.publish_mode
    )
    probe_source_changed = (
        origin.preferred_agent_id != global_origin.preferred_agent_id
        or origin.probe_mode != global_origin.probe_mode
    )
    origin.global_origin_id = global_origin.id
    origin.preferred_agent_id = global_origin.preferred_agent_id
    origin.probe_mode = global_origin.probe_mode
    # The mirror carries the binding for display, but the global origin is what the
    # external sync updates — see sync_origins_from_source, which skips mirrors so
    # the two never write the same target from different directions.
    origin.external_source_id = global_origin.external_source_id
    origin.external_machine_key = global_origin.external_machine_key
    origin.azpanel_resource_id = global_origin.azpanel_resource_id
    origin.target = global_origin.target
    origin.target_type = global_origin.target_type
    origin.publish_mode = global_origin.publish_mode
    origin.port = global_origin.port
    origin.priority = global_origin.priority
    origin.remark = global_origin.remark
    origin.enabled = global_origin.enabled
    origin.ignore_health_check = global_origin.ignore_health_check
    origin.expanded_ip_priorities_json = global_origin.expanded_ip_priorities_json
    if endpoint_changed or probe_source_changed:
        _reset_origin_probe_state(origin)
    return endpoint_changed


def _ensure_global_origin_unique(
    db: Session,
    collection_id: int,
    target: str,
    port: int,
    exclude_id: int | None = None,
    external_source_id: int | None = None,
    external_machine_key: str | None = None,
) -> None:
    """Reject duplicates by identity, which differs between the two kinds of backup.

    A machine-bound backup is the same backup as another one when it points at the
    same machine — its address is only the machine's current IP and will change.
    ``external_source_id`` is part of that key because ``machine_key`` is only
    unique within one source. A static-IP backup is still identified by its address.
    """
    if external_machine_key:
        machine_query = db.query(FailoverGlobalOrigin).filter(
            FailoverGlobalOrigin.collection_id == collection_id,
            FailoverGlobalOrigin.external_source_id == external_source_id,
            FailoverGlobalOrigin.external_machine_key == external_machine_key,
            FailoverGlobalOrigin.port == port,
        )
        if exclude_id is not None:
            machine_query = machine_query.filter(FailoverGlobalOrigin.id != exclude_id)
        if machine_query.first():
            raise HTTPException(status_code=409, detail=f"这台机器的 {port} 端口已经是这个业务分组的全局备用")
        return

    query = db.query(FailoverGlobalOrigin).filter(
        FailoverGlobalOrigin.collection_id == collection_id,
        FailoverGlobalOrigin.target == target,
        FailoverGlobalOrigin.port == port,
        FailoverGlobalOrigin.external_machine_key.is_(None),
    )
    if exclude_id is not None:
        query = query.filter(FailoverGlobalOrigin.id != exclude_id)
    if query.first():
        raise HTTPException(status_code=409, detail=f"{target}:{port} 已经是这个业务分组的全局备用")


def _ensure_global_origin_update_has_no_group_conflicts(db: Session, global_origin: FailoverGlobalOrigin, target: str, port: int) -> None:
    if global_origin.target == target and global_origin.port == port:
        return
    conflicts = (
        db.query(Origin)
        .join(FailoverGroup)
        .filter(
            FailoverGroup.collection_id == global_origin.collection_id,
            or_(Origin.global_origin_id.is_(None), Origin.global_origin_id != global_origin.id),
            Origin.target == target,
            Origin.port == port,
        )
        .limit(3)
        .all()
    )
    if conflicts:
        names = ", ".join(origin.group.hostname for origin in conflicts)
        raise HTTPException(status_code=409, detail=f"这些切换组已存在相同目标，无法整体修改：{names}")


def sync_global_origins_to_group(db: Session, group: FailoverGroup) -> bool:
    collection = group.collection
    active_global_ids: set[int] = set()
    current_endpoint_changed = False
    if collection:
        global_origins = sorted(collection.global_origins, key=lambda item: (item.priority, item.id))
        for global_origin in global_origins:
            if global_origin.target_type == "hostname" and global_origin.target in _group_hostname_values(group):
                raise HTTPException(status_code=400, detail=f"{group.hostname} 的主机名和全局 CNAME 备用冲突")
            active_global_ids.add(global_origin.id)
            origin = next((item for item in group.origins if item.global_origin_id == global_origin.id), None)
            if origin is None:
                origin = next(
                    (
                        item
                        for item in group.origins
                        if item.global_origin_id is None and item.target == global_origin.target and item.port == global_origin.port
                    ),
                    None,
                )
            if origin is None:
                origin = Origin(
                    group_id=group.id,
                    preferred_agent_id=global_origin.preferred_agent_id,
                    target=global_origin.target,
                    target_type=global_origin.target_type,
                    port=global_origin.port,
                )
                db.add(origin)
                group.origins.append(origin)
            was_current = group.current_origin_id == origin.id
            previous_priority = origin.priority
            previous_enabled = origin.enabled
            endpoint_changed = _copy_global_origin_to_origin(origin, global_origin)
            if was_current and endpoint_changed:
                current_endpoint_changed = True
            if was_current and (endpoint_changed or previous_priority != origin.priority or previous_enabled != origin.enabled):
                group.last_switch_at = None

    stale_global_origins = [origin for origin in group.origins if origin.global_origin_id and origin.global_origin_id not in active_global_ids]
    for origin in stale_global_origins:
        if group.current_origin_id == origin.id:
            group.current_origin_id = None
            group.last_switch_at = None
        _delete_time_rule_for_origin(db, origin)
        db.delete(origin)
    return current_endpoint_changed


def sync_global_origins_to_collection(db: Session, collection: FailoverCollection) -> list[FailoverGroup]:
    current_endpoint_changed_groups: list[FailoverGroup] = []
    for group in collection.groups:
        if sync_global_origins_to_group(db, group):
            current_endpoint_changed_groups.append(group)
    return current_endpoint_changed_groups


def _publish_current_group_origin(db: Session, group: FailoverGroup) -> None:
    if not group.enabled or not group.current_origin_id:
        return
    current_origin = next((origin for origin in group.origins if origin.id == group.current_origin_id), None)
    if current_origin is None:
        current_origin = db.get(Origin, group.current_origin_id)
    if current_origin is None or not current_origin.enabled:
        return
    try:
        if group.cloudflare_publish_enabled:
            publish_origin(db, group, current_origin)
        if group.doh_enabled:
            _require_group_doh_sync(db, group)
        if any(output.enabled for output in group.route53_outputs):
            sync_group_route53_outputs(db, group, current_origin, force_consistency=True)
        if any(output.enabled for output in group.alibaba_httpdns_outputs):
            sync_group_alibaba_outputs(db, group, current_origin, force_consistency=True)
    except Exception as exc:
        group.last_error = str(exc)
    else:
        group.last_error = None


def _validate_group_collection(group: FailoverGroup, collection: FailoverCollection | None) -> None:
    if collection is None:
        return
    if collection.provider_type != group.provider_type:
        raise HTTPException(status_code=400, detail="A failover group can only use a business group from the same provider")
    group_hostnames = _group_hostname_values(group)
    conflict = next(
        (
            global_origin
            for global_origin in collection.global_origins
            if global_origin.target_type == "hostname" and global_origin.target in group_hostnames
        ),
        None,
    )
    if conflict:
        raise HTTPException(status_code=400, detail=f"业务分组里的全局 CNAME 备用 {conflict.target} 和该切换组主机名冲突")


@router.get("/collections", response_model=list[FailoverCollectionOut])
def list_collections(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _collection_query(db).order_by(FailoverCollection.created_at.asc()).all()


@router.post("/collections", response_model=FailoverCollectionOut)
def create_collection(payload: FailoverCollectionCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    name = payload.name.strip()
    existing = db.query(FailoverCollection).filter(FailoverCollection.name == name).one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="业务分组名称已经存在")
    collection = FailoverCollection(name=name, provider_type=payload.provider_type)
    db.add(collection)
    db.commit()
    return _collection_query(db).filter(FailoverCollection.id == collection.id).one()


@router.patch("/collections/{collection_id}", response_model=FailoverCollectionOut)
def update_collection(collection_id: int, payload: FailoverCollectionUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    collection = db.get(FailoverCollection, collection_id)
    if collection is None:
        raise HTTPException(status_code=404, detail="业务分组不存在")
    updates = payload.model_dump(exclude_unset=True)
    if "name" in updates and updates["name"] is not None:
        name = updates["name"].strip()
        duplicate = (
            db.query(FailoverCollection)
            .filter(FailoverCollection.id != collection.id, FailoverCollection.name == name)
            .one_or_none()
        )
        if duplicate:
            raise HTTPException(status_code=409, detail="业务分组名称已经存在")
        collection.name = name
    db.commit()
    return _collection_query(db).filter(FailoverCollection.id == collection_id).one()


@router.delete("/collections/{collection_id}", response_model=Message)
def delete_collection(collection_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    collection = (
        db.query(FailoverCollection)
        .options(selectinload(FailoverCollection.groups).selectinload(FailoverGroup.origins), selectinload(FailoverCollection.global_origins))
        .filter(FailoverCollection.id == collection_id)
        .one_or_none()
    )
    if collection is None:
        raise HTTPException(status_code=404, detail="业务分组不存在")
    azpanel_resource_ids = [origin.azpanel_resource_id for origin in collection.global_origins]
    groups = list(collection.groups)
    affected_group_ids = [group.id for group in groups if group.enabled]
    for group in groups:
        group.collection = None
        group.collection_id = None
        sync_global_origins_to_group(db, group)
    db.delete(collection)
    db.flush()
    _refresh_azpanel_resource_bindings(db, azpanel_resource_ids)
    _evaluate_locally(db, affected_group_ids)
    db.commit()
    return Message(message="业务分组已删除")


@router.post("/collections/{collection_id}/global-origins", response_model=FailoverCollectionOut)
def create_global_origin(collection_id: int, payload: FailoverGlobalOriginCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    collection = (
        db.query(FailoverCollection)
        .options(
            selectinload(FailoverCollection.groups).selectinload(FailoverGroup.hostnames),
            selectinload(FailoverCollection.groups).selectinload(FailoverGroup.origins).selectinload(Origin.probe_states),
            selectinload(FailoverCollection.global_origins),
        )
        .filter(FailoverCollection.id == collection_id)
        .one_or_none()
    )
    if collection is None:
        raise HTTPException(status_code=404, detail="业务分组不存在")
    global_origin = _global_origin_from_payload(db, collection, payload)
    _ensure_global_origin_unique(
        db,
        collection.id,
        global_origin.target,
        global_origin.port,
        external_source_id=global_origin.external_source_id,
        external_machine_key=global_origin.external_machine_key,
    )
    db.add(global_origin)
    db.flush()
    collection.global_origins.append(global_origin)
    current_endpoint_changed_groups = sync_global_origins_to_collection(db, collection)
    if global_origin.azpanel_resource_id:
        resource = db.get(AzPanelResource, global_origin.azpanel_resource_id)
        if resource is not None:
            _refresh_azpanel_resource_bindings(db, [resource.id])
            sync_resource_current_ip_to_origin(db, resource)
    for group in current_endpoint_changed_groups:
        _publish_current_group_origin(db, group)
    _evaluate_locally(db, _enabled_collection_group_ids(collection))
    db.commit()
    return _collection_query(db).filter(FailoverCollection.id == collection_id).one()


@router.patch("/global-origins/{global_origin_id}", response_model=FailoverGlobalOriginOut)
def update_global_origin(global_origin_id: int, payload: FailoverGlobalOriginUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    global_origin = (
        db.query(FailoverGlobalOrigin)
        .options(
            selectinload(FailoverGlobalOrigin.collection).selectinload(FailoverCollection.groups).selectinload(FailoverGroup.hostnames),
            selectinload(FailoverGlobalOrigin.collection).selectinload(FailoverCollection.groups).selectinload(FailoverGroup.origins).selectinload(Origin.probe_states),
            selectinload(FailoverGlobalOrigin.collection).selectinload(FailoverCollection.global_origins),
        )
        .filter(FailoverGlobalOrigin.id == global_origin_id)
        .one_or_none()
    )
    if global_origin is None:
        raise HTTPException(status_code=404, detail="全局备用不存在")
    updates = payload.model_dump(exclude_unset=True)
    new_target = global_origin.target
    new_target_type = global_origin.target_type
    new_port = global_origin.port
    new_publish_mode = global_origin.publish_mode
    new_preferred_agent_id = global_origin.preferred_agent_id
    new_probe_mode = global_origin.probe_mode
    if "target" in updates and updates["target"] is not None:
        target_info = _parse_target_or_400(updates.pop("target"))
        if target_info.record_type == "CNAME" and target_info.value in _collection_hostname_values(global_origin.collection):
            raise HTTPException(status_code=400, detail="全局 CNAME 备用不能和当前业务分组内的主机名相同")
        new_target = target_info.value
        new_target_type = target_info.target_type
    if "port" in updates and updates["port"] is not None:
        new_port = updates["port"]
    if "publish_mode" in updates and updates["publish_mode"] is not None:
        new_publish_mode = updates.pop("publish_mode")
    priority_updates_provided = "expanded_ip_priorities" in updates
    priority_updates = updates.pop("expanded_ip_priorities", None) if priority_updates_provided else None
    if new_target_type != "hostname" and new_publish_mode == EXPANDED_PUBLISH_MODE:
        raise HTTPException(status_code=400, detail="只有域名目标可以启用展开 IP 池")
    if "preferred_agent_id" in updates:
        new_preferred_agent_id = _validate_preferred_agent_id(db, updates.pop("preferred_agent_id"))
    if "probe_mode" in updates:
        new_probe_mode = _normalize_probe_mode(updates.pop("probe_mode"))

    new_external_source_id = global_origin.external_source_id
    new_external_machine_key = global_origin.external_machine_key
    if "external_ip_item_id" in updates:
        item_id = updates.pop("external_ip_item_id")
        if item_id is None:
            new_external_source_id = None
            new_external_machine_key = None
        else:
            new_external_source_id, new_external_machine_key = _external_binding_from_item_id(db, item_id)
            bound_item = db.get(ExternalIpItem, item_id)
            # Binding to a machine means its current address wins: the sync would
            # overwrite the target on its next run anyway, so do it now instead of
            # leaving a stale IP published until then.
            if bound_item is not None and "target" not in payload.model_fields_set:
                new_target = bound_item.target
                new_target_type = bound_item.target_type

    old_azpanel_resource_id = global_origin.azpanel_resource_id
    new_azpanel_resource_id = old_azpanel_resource_id
    azpanel_resource = None
    if "azpanel_resource_id" in updates:
        new_azpanel_resource_id = updates.pop("azpanel_resource_id")
        azpanel_resource = _azpanel_resource(db, new_azpanel_resource_id)
    elif new_azpanel_resource_id is not None:
        azpanel_resource = db.get(AzPanelResource, new_azpanel_resource_id)
    if (
        azpanel_resource is not None
        and not new_external_machine_key
        and azpanel_resource.auto_update_origin
        and azpanel_resource.current_ip
    ):
        resource_target = _parse_target_or_400(azpanel_resource.current_ip)
        new_target = resource_target.value
        new_target_type = resource_target.target_type
        new_port = azpanel_resource.port

    _ensure_global_origin_unique(
        db,
        global_origin.collection_id,
        new_target,
        new_port,
        exclude_id=global_origin.id,
        external_source_id=new_external_source_id,
        external_machine_key=new_external_machine_key,
    )
    _ensure_global_origin_update_has_no_group_conflicts(db, global_origin, new_target, new_port)

    global_origin.external_source_id = new_external_source_id
    global_origin.external_machine_key = new_external_machine_key
    global_origin.azpanel_resource_id = new_azpanel_resource_id
    global_origin.target = new_target
    global_origin.target_type = new_target_type
    global_origin.publish_mode = new_publish_mode if new_target_type == "hostname" else DIRECT_PUBLISH_MODE
    global_origin.port = new_port
    global_origin.preferred_agent_id = new_preferred_agent_id
    global_origin.probe_mode = new_probe_mode
    if priority_updates_provided:
        _apply_expanded_ip_priorities(global_origin, priority_updates if new_target_type == "hostname" else {})
    elif new_target_type != "hostname":
        _apply_expanded_ip_priorities(global_origin, {})
    if "remark" in updates:
        global_origin.remark = _normalize_remark(updates.pop("remark"))
    for key, value in updates.items():
        setattr(global_origin, key, value)
    current_endpoint_changed_groups = sync_global_origins_to_collection(db, global_origin.collection)
    _refresh_azpanel_resource_bindings(db, [old_azpanel_resource_id, new_azpanel_resource_id])
    if azpanel_resource is not None:
        sync_resource_current_ip_to_origin(db, azpanel_resource)
    for group in current_endpoint_changed_groups:
        _publish_current_group_origin(db, group)
    _evaluate_locally(db, _enabled_collection_group_ids(global_origin.collection))
    db.commit()
    db.refresh(global_origin)
    return global_origin


@router.delete("/global-origins/{global_origin_id}", response_model=Message)
def delete_global_origin(global_origin_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    global_origin = (
        db.query(FailoverGlobalOrigin)
        .options(selectinload(FailoverGlobalOrigin.collection).selectinload(FailoverCollection.groups).selectinload(FailoverGroup.origins))
        .filter(FailoverGlobalOrigin.id == global_origin_id)
        .one_or_none()
    )
    if global_origin is None:
        raise HTTPException(status_code=404, detail="全局备用不存在")
    azpanel_resource_id = global_origin.azpanel_resource_id
    collection = global_origin.collection
    affected_group_ids = [group.id for group in collection.groups if group.enabled]
    mirrored_origins = db.query(Origin).filter(Origin.global_origin_id == global_origin.id).all()
    for origin in mirrored_origins:
        if origin.group.current_origin_id == origin.id:
            origin.group.current_origin_id = None
            origin.group.last_switch_at = None
        _delete_time_rule_for_origin(db, origin)
        db.delete(origin)
    db.delete(global_origin)
    db.flush()
    _refresh_azpanel_resource_bindings(db, [azpanel_resource_id])
    db.expire_all()
    _evaluate_locally(db, affected_group_ids)
    db.commit()
    return Message(message="全局备用已删除")


@router.get("", response_model=list[FailoverGroupOut])
def list_groups(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _group_query(db).order_by(FailoverGroup.created_at.desc()).all()


@router.post("", response_model=FailoverGroupOut)
def create_group(payload: FailoverGroupCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    zone = db.get(Zone, payload.zone_id) if payload.zone_id is not None else None
    if payload.zone_id is not None and zone is None:
        raise HTTPException(status_code=404, detail="域名区域不存在")
    if payload.provider_type != "cloudflare" and (payload.zone_id is not None or payload.cloudflare_publish_enabled):
        raise HTTPException(status_code=400, detail="Only Cloudflare groups can own a Cloudflare zone or public output")
    if payload.provider_type == "cloudflare" and payload.ttl < 30:
        raise HTTPException(status_code=400, detail="Cloudflare group TTL must be at least 30 seconds")
    if payload.provider_type == "alibaba_httpdns" and payload.ttl not in {5, 30, 60, 3600, 43200, 86400}:
        raise HTTPException(status_code=400, detail="Alibaba HTTPDNS TTL must be one of 5, 30, 60, 3600, 43200 or 86400")
    collection = db.get(FailoverCollection, payload.collection_id) if payload.collection_id else None
    if payload.collection_id and collection is None:
        raise HTTPException(status_code=404, detail="业务分组不存在")
    try:
        hostname = normalize_hostname(payload.hostname)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    doh_hostnames = _normalize_doh_hostnames(payload.doh_hostnames, hostname)
    _validate_group_outputs(
        db,
        cloudflare_publish_enabled=payload.cloudflare_publish_enabled,
        doh_enabled=payload.doh_enabled,
        doh_endpoint_id=payload.doh_endpoint_id,
        doh_hostnames=doh_hostnames,
    )
    if zone is None and payload.cloudflare_publish_enabled:
        raise HTTPException(status_code=400, detail="Cloudflare output requires a Cloudflare zone")
    if zone is None and payload.adopt_record_id:
        raise HTTPException(status_code=400, detail="A Cloudflare record cannot be adopted without a Cloudflare zone")
    existing_query = db.query(FailoverGroup).filter(
        FailoverGroup.provider_type == payload.provider_type,
        FailoverGroup.hostname == hostname,
    )
    existing_query = (
        existing_query.filter(FailoverGroup.zone_id == zone.id)
        if zone is not None
        else existing_query.filter(FailoverGroup.zone_id.is_(None))
    )
    existing = existing_query.one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="该主机名已经存在故障切换组")
    client = None
    existing_record_id = None
    if payload.cloudflare_publish_enabled:
        client = CloudflareClient(decrypt_secret(zone.credential.token_encrypted))
        try:
            existing_record_id = validate_group_hostname_records(client, zone.cf_zone_id, hostname, payload.adopt_record_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    group = FailoverGroup(
        provider_type=payload.provider_type,
        zone_id=zone.id if zone else None,
        collection_id=collection.id if collection else None,
        hostname=hostname,
        ttl=payload.ttl,
        enabled=payload.enabled,
        min_switch_interval_seconds=payload.min_switch_interval_seconds,
        current_record_id=payload.adopt_record_id or existing_record_id,
        cloudflare_publish_enabled=payload.cloudflare_publish_enabled,
        doh_enabled=payload.doh_enabled,
        doh_endpoint_id=payload.doh_endpoint_id,
        doh_hostnames_json=json.dumps(doh_hostnames),
    )
    db.add(group)
    db.flush()
    db.add(FailoverHostname(group_id=group.id, hostname=hostname, current_record_id=group.current_record_id))
    db.flush()
    managed_record_id = group.current_record_id
    if managed_record_id and client is not None:
        current_record = find_managed_dns_record_by_id(client, zone.cf_zone_id, managed_record_id)
        if current_record is None:
            raise HTTPException(status_code=404, detail="未找到要接管的当前解析记录")
        primary_origin = _origin_from_dns_record(group, current_record, payload.primary_port)
        db.add(primary_origin)
        db.flush()
        group.current_origin_id = primary_origin.id
    if collection:
        db.refresh(group)
        _validate_group_collection(group, collection)
        group.collection = collection
        sync_global_origins_to_group(db, group)
    add_event(db, "group.created", "info", f"{hostname} 的故障切换组已创建", {"group_id": group.id})
    db.commit()
    return _group_query(db).filter(FailoverGroup.id == group.id).one()


@router.patch("/{group_id}", response_model=FailoverGroupOut)
def update_group(group_id: int, payload: FailoverGroupUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = (
        db.query(FailoverGroup)
        .options(
            selectinload(FailoverGroup.hostnames),
            selectinload(FailoverGroup.origins).selectinload(Origin.probe_states),
            selectinload(FailoverGroup.collection).selectinload(FailoverCollection.global_origins),
        )
        .filter(FailoverGroup.id == group_id)
        .one_or_none()
    )
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    previous_doh_endpoint_id = group.doh_endpoint_id if group.doh_enabled else None
    updates = payload.model_dump(exclude_unset=True)
    if group.provider_type != "cloudflare" and updates.get("cloudflare_publish_enabled"):
        raise HTTPException(status_code=400, detail="This provider group cannot enable Cloudflare output")
    next_ttl = updates.get("ttl", group.ttl)
    if group.provider_type == "cloudflare" and next_ttl < 30:
        raise HTTPException(status_code=400, detail="Cloudflare group TTL must be at least 30 seconds")
    if group.provider_type == "alibaba_httpdns" and next_ttl not in {5, 30, 60, 3600, 43200, 86400}:
        raise HTTPException(status_code=400, detail="Alibaba HTTPDNS TTL must be one of 5, 30, 60, 3600, 43200 or 86400")
    previous_doh_hostnames = group.doh_hostnames or [entry.hostname for entry in group.hostnames] or [group.hostname]
    previous_outputs = (
        group.cloudflare_publish_enabled,
        group.doh_enabled,
        group.doh_endpoint_id,
        tuple(previous_doh_hostnames),
    )
    next_doh_enabled = updates.get("doh_enabled", group.doh_enabled)
    next_doh_endpoint_id = updates.get("doh_endpoint_id", group.doh_endpoint_id)
    if "doh_hostnames" in updates:
        next_doh_hostnames = (
            _normalize_doh_hostnames(updates["doh_hostnames"], group.hostname)
            if updates["doh_hostnames"]
            else [entry.hostname for entry in group.hostnames] or [group.hostname]
        )
    else:
        next_doh_hostnames = group.doh_hostnames or [entry.hostname for entry in group.hostnames] or [group.hostname]
    _validate_group_outputs(
        db,
        cloudflare_publish_enabled=updates.get("cloudflare_publish_enabled", group.cloudflare_publish_enabled),
        doh_enabled=next_doh_enabled,
        doh_endpoint_id=next_doh_endpoint_id,
        doh_hostnames=next_doh_hostnames,
        group_id=group.id,
    )
    if updates.get("cloudflare_publish_enabled", group.cloudflare_publish_enabled) and group.zone_id is None:
        raise HTTPException(status_code=400, detail="Cloudflare output requires a Cloudflare zone")
    if "doh_hostnames" in updates:
        updates.pop("doh_hostnames")
        updates["doh_hostnames_json"] = json.dumps(next_doh_hostnames)
    collection_changed = "collection_id" in updates and updates["collection_id"] != group.collection_id
    if "collection_id" in updates:
        collection_id = updates.pop("collection_id")
        collection = db.get(FailoverCollection, collection_id) if collection_id else None
        if collection_id and collection is None:
            raise HTTPException(status_code=404, detail="业务分组不存在")
        _validate_group_collection(group, collection)
        group.collection = collection
        group.collection_id = collection.id if collection else None
        sync_global_origins_to_group(db, group)
    ttl_changed = "ttl" in updates and updates["ttl"] != group.ttl
    for key, value in updates.items():
        setattr(group, key, value)
    if ttl_changed:
        for output in group.route53_outputs:
            output.ttl = group.ttl
        for output in group.alibaba_httpdns_outputs:
            output.ttl = group.ttl
    outputs_changed = previous_outputs != (
        group.cloudflare_publish_enabled,
        group.doh_enabled,
        group.doh_endpoint_id,
        tuple(group.doh_hostnames or [entry.hostname for entry in group.hostnames] or [group.hostname]),
    )
    if group.enabled or collection_changed:
        _evaluate_locally(db, [group.id])
    if (outputs_changed or ttl_changed) and group.enabled and group.current_origin_id:
        current_origin = db.get(Origin, group.current_origin_id)
        if current_origin and current_origin.enabled:
            try:
                if group.cloudflare_publish_enabled:
                    publish_origin(db, group, current_origin)
                if group.doh_enabled:
                    _require_group_doh_sync(db, group)
                if any(output.enabled for output in group.route53_outputs):
                    sync_group_route53_outputs(db, group, current_origin, force_consistency=ttl_changed)
                if any(output.enabled for output in group.alibaba_httpdns_outputs):
                    sync_group_alibaba_outputs(db, group, current_origin, force_consistency=ttl_changed)
            except Exception as exc:
                db.rollback()
                raise HTTPException(status_code=502, detail=f"Output publishing failed; changes were not saved: {exc}") from exc
    if outputs_changed and previous_doh_endpoint_id and previous_doh_endpoint_id != (group.doh_endpoint_id if group.doh_enabled else None):
        previous_endpoint = db.get(DohEndpoint, previous_doh_endpoint_id)
        if previous_endpoint is not None:
            sync_doh_endpoint(db, previous_endpoint, force=True, ignore_backoff=True)
    db.commit()
    return _group_query(db).filter(FailoverGroup.id == group_id).one()


@router.put("/{group_id}/time-rule", response_model=FailoverTimeRuleOut)
def upsert_time_rule(
    group_id: int,
    payload: FailoverTimeRuleUpsert,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    group = _group_query(db).filter(FailoverGroup.id == group_id).one_or_none()
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    origin = db.get(Origin, payload.origin_id)
    if origin is None:
        raise HTTPException(status_code=404, detail="指定源站不存在")
    if origin.group_id != group.id:
        raise HTTPException(status_code=400, detail="指定源站不属于这个切换组")

    rule = group.time_rule
    if rule is None:
        rule = FailoverTimeRule(group=group, origin_id=origin.id)
        db.add(rule)
    rule.origin_id = origin.id
    rule.name = payload.name
    rule.timezone = payload.timezone
    rule.weekdays_mask = _weekdays_mask(payload.weekdays)
    rule.start_minute = _minute_of_day(payload.start_time)
    rule.end_minute = _minute_of_day(payload.end_time)
    rule.enabled = payload.enabled
    db.flush()
    _evaluate_locally(db, [group.id])
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/{group_id}/time-rule", response_model=Message)
def delete_time_rule(group_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = _group_query(db).filter(FailoverGroup.id == group_id).one_or_none()
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    rule = group.time_rule
    if rule is None:
        raise HTTPException(status_code=404, detail="时间规则不存在")
    if rule.last_active:
        group.last_switch_at = None
    db.delete(rule)
    db.flush()
    db.expire(group, ["time_rule"])
    _evaluate_locally(db, [group.id])
    db.commit()
    return Message(message="时间规则已删除")


@router.post("/{group_id}/hostnames", response_model=FailoverGroupOut)
def add_group_hostname(group_id: int, payload: FailoverHostnameCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(FailoverGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    if group.provider_type != "cloudflare":
        raise HTTPException(status_code=400, detail="Additional managed hostnames are only supported by Cloudflare groups")
    ensure_group_hostname_entries(db, group)
    try:
        hostname = normalize_hostname(payload.hostname)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    duplicate_in_group = (
        db.query(FailoverHostname)
        .filter(FailoverHostname.group_id == group.id, FailoverHostname.hostname == hostname)
        .one_or_none()
    )
    if duplicate_in_group:
        raise HTTPException(status_code=409, detail="该主域名已经在这个切换组中")
    duplicate_in_zone = (
        db.query(FailoverHostname)
        .join(FailoverGroup)
        .filter(FailoverGroup.zone_id == group.zone_id, FailoverGroup.id != group.id, FailoverHostname.hostname == hostname)
        .one_or_none()
    )
    legacy_group = (
        db.query(FailoverGroup)
        .filter(FailoverGroup.zone_id == group.zone_id, FailoverGroup.id != group.id, FailoverGroup.hostname == hostname)
        .one_or_none()
    )
    if duplicate_in_zone or legacy_group:
        raise HTTPException(status_code=409, detail="该主域名已经被其他切换组接管")
    if group.doh_enabled and group.doh_endpoint_id and not group.doh_hostnames:
        try:
            validate_doh_hostname_conflicts(
                db,
                endpoint_id=group.doh_endpoint_id,
                hostnames=[entry.hostname for entry in group.hostnames] + [hostname],
                exclude_group_id=group.id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    if group.collection:
        conflict = next(
            (
                global_origin
                for global_origin in group.collection.global_origins
                if global_origin.target_type == "hostname" and global_origin.target == hostname
            ),
            None,
        )
        if conflict:
            raise HTTPException(status_code=400, detail=f"该主域名和业务分组全局备用 {conflict.target} 冲突")

    target_zone = _resolve_hostname_zone(db, group, hostname)
    if target_zone is None and group.cloudflare_publish_enabled:
        raise HTTPException(
            status_code=409,
            detail=f"域名 {hostname} 所属的 Cloudflare 区域尚未在系统中添加，请先在区域页面同步该区域后再试",
        )

    existing_record_id = None
    if group.cloudflare_publish_enabled:
        client = CloudflareClient(decrypt_secret(target_zone.credential.token_encrypted))
        try:
            existing_record_id = validate_group_hostname_records(client, target_zone.cf_zone_id, hostname, payload.adopt_record_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    hostname_entry = FailoverHostname(
        group=group,
        hostname=hostname,
        zone_id=(
            target_zone.id
            if target_zone is not None and group.zone_id is not None and target_zone.id != group.zone_id
            else None
        ),
        current_record_id=payload.adopt_record_id or existing_record_id,
    )
    db.add(hostname_entry)
    db.flush()

    current_origin = db.get(Origin, group.current_origin_id) if group.current_origin_id else None
    if group.enabled and current_origin and current_origin.enabled:
        try:
            if group.cloudflare_publish_enabled:
                publish_origin(db, group, current_origin, hostname_entries=[hostname_entry])
            if group.doh_enabled:
                _require_group_doh_sync(db, group)
        except Exception as exc:
            message = f"DNS 发布失败，主域名已保存但暂未完全接管：{exc}"
            group.last_error = message
            add_event(
                db,
                "dns.publish_failed",
                "error",
                f"{group.hostname} 添加主域名 {hostname} 后发布 DNS 失败: {exc}",
                {"group_id": group.id, "hostname": hostname, "error": str(exc)},
            )
        else:
            group.last_error = None
    add_event(db, "group.hostname_added", "info", f"{group.hostname} 已添加主域名 {hostname}", {"group_id": group.id, "hostname": hostname})
    db.commit()
    return _group_query(db).filter(FailoverGroup.id == group_id).one()


@router.delete("/hostnames/{hostname_id}", response_model=FailoverGroupOut)
def delete_group_hostname(hostname_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    hostname_entry = db.get(FailoverHostname, hostname_id)
    if hostname_entry is None:
        raise HTTPException(status_code=404, detail="主域名不存在")
    group = hostname_entry.group
    if group.provider_type != "cloudflare":
        raise HTTPException(status_code=400, detail="Managed hostname removal is only supported by Cloudflare groups")
    ensure_group_hostname_entries(db, group)
    remaining = [item for item in group.hostnames if item.id != hostname_entry.id]
    if not remaining:
        raise HTTPException(status_code=400, detail="至少需要保留一个主域名")
    removed_hostname = hostname_entry.hostname
    was_primary = removed_hostname == group.hostname
    record_ids = [item.strip() for item in (hostname_entry.current_record_id or "").split(",") if item.strip()]
    if record_ids and group.cloudflare_publish_enabled:
        zone = zone_for_hostname(db, group, hostname_entry)
        client = CloudflareClient(decrypt_secret(zone.credential.token_encrypted))
        for record_id in record_ids:
            try:
                client.delete_dns_record(zone.cf_zone_id, record_id)
            except CloudflareError as exc:
                if exc.status_code == 404:
                    continue
                raise HTTPException(status_code=502, detail=f"删除 Cloudflare DNS 记录失败：{exc}") from exc
    db.delete(hostname_entry)
    if was_primary:
        next_primary = sorted(remaining, key=lambda item: item.id)[0]
        group.hostname = next_primary.hostname
        group.current_record_id = next_primary.current_record_id
    db.flush()
    if group.doh_enabled and group.doh_endpoint_id:
        db.expire(group, ["hostnames"])
        try:
            _require_group_doh_sync(db, group)
        except Exception as exc:
            db.rollback()
            raise HTTPException(status_code=502, detail=f"DoH output publishing failed; hostname was not removed: {exc}") from exc
    add_event(db, "group.hostname_removed", "info", f"{group.hostname} 已取消接管主域名 {removed_hostname}", {"group_id": group.id, "hostname": removed_hostname})
    db.commit()
    return _group_query(db).filter(FailoverGroup.id == group.id).one()


@router.delete("/{group_id}", response_model=Message)
def delete_group(group_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(FailoverGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    doh_endpoint_id = group.doh_endpoint_id if group.doh_enabled else None
    route53_endpoint_ids = {output.doh_endpoint_id for output in group.route53_outputs}
    azpanel_resource_ids = {origin.azpanel_resource_id for origin in group.origins if origin.azpanel_resource_id}
    for origin in group.origins:
        if origin.global_origin_id:
            global_origin = db.get(FailoverGlobalOrigin, origin.global_origin_id)
            if global_origin is not None and global_origin.azpanel_resource_id:
                azpanel_resource_ids.add(global_origin.azpanel_resource_id)
    if group.provider_type == "alibaba_httpdns":
        db.query(AlibabaHttpDnsGroup).filter(AlibabaHttpDnsGroup.source_group_id == group.id).delete(
            synchronize_session=False,
        )
    else:
        # Legacy shared outputs are preserved when their original Cloudflare group
        # is removed. They can then be migrated or deleted explicitly.
        db.query(AlibabaHttpDnsGroup).filter(AlibabaHttpDnsGroup.source_group_id == group.id).update(
            {AlibabaHttpDnsGroup.source_group_id: None, AlibabaHttpDnsGroup.source_current_origin_id: None},
            synchronize_session=False,
        )
    db.delete(group)
    db.flush()
    _refresh_azpanel_resource_bindings(db, azpanel_resource_ids)
    if doh_endpoint_id:
        endpoint = db.get(DohEndpoint, doh_endpoint_id)
        if endpoint is not None:
            sync_doh_endpoint(db, endpoint, force=True, ignore_backoff=True)
    for endpoint_id in route53_endpoint_ids:
        endpoint = db.get(DohEndpoint, endpoint_id)
        if endpoint is not None:
            sync_doh_endpoint(db, endpoint, force=True, ignore_backoff=True)
    db.commit()
    detail = {"route53_record_preserved": True} if group.provider_type == "route53" else None
    return Message(message="切换组已删除", detail=detail)


def _resource_from_remote_key(db: Session, remote_key: str, port: int) -> AzPanelResource:
    """Resolve an azpanel remote-resource key into a local AzPanelResource.

    Reuses an existing local resource for the same machine (so picking an
    already-added machine rebinds instead of duplicating it); otherwise creates
    one with auto-change defaults from the cached remote listing.
    """
    remote = db.query(AzPanelRemoteResource).filter(AzPanelRemoteResource.key == remote_key).one_or_none()
    if remote is None:
        raise HTTPException(status_code=404, detail="azpanel 远端资源不存在，请重新刷新资源")
    candidates = (
        db.query(AzPanelResource)
        .filter(
            AzPanelResource.provider == remote.provider,
            AzPanelResource.resource_id == remote.resource_id,
            AzPanelResource.ip_version == remote.ip_version,
        )
        .all()
    )
    existing = next(
        (
            item
            for item in candidates
            if (item.account_id or "") == (remote.account_id or "") and (item.region or "") == (remote.region or "")
        ),
        None,
    )
    if existing is not None:
        return existing
    resource = AzPanelResource(
        name=remote.name,
        provider=remote.provider,
        resource_id=remote.resource_id,
        account_id=remote.account_id or None,
        region=remote.region or None,
        ip_version=remote.ip_version,
        current_ip=remote.current_ip,
        port=port,
        enabled=True,
        auto_change_on_blocked=True,
        auto_update_origin=True,
        cooldown_seconds=azpanel_settings(db)["default_cooldown_seconds"],
        remark=remote.remark,
    )
    db.add(resource)
    return resource


@router.post("/{group_id}/origins", response_model=OriginOut)
def create_origin(group_id: int, payload: OriginCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(FailoverGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    resource = None
    if payload.azpanel_resource_id is not None:
        resource = db.get(AzPanelResource, payload.azpanel_resource_id)
        if resource is None:
            raise HTTPException(status_code=404, detail="azpanel 云资源不存在")
    elif payload.azpanel_remote_key:
        resource = _resource_from_remote_key(db, payload.azpanel_remote_key, payload.port)
    origin = _origin_from_payload(db, group, payload)
    duplicate = (
        db.query(Origin)
        .filter(Origin.group_id == group.id, Origin.target == origin.target, Origin.port == origin.port)
        .one_or_none()
    )
    if duplicate:
        raise HTTPException(status_code=409, detail=f"{origin.target}:{origin.port} 已经在备用目标池中")
    db.add(origin)
    if resource is not None:
        db.flush()
        # The binding lives on the origin, so binding a second backup to the same
        # machine no longer silently steals it from the first.
        origin.azpanel_resource_id = resource.id
        refresh_legacy_origin_mirror(db, resource)
        try:
            sync_resource_current_ip_to_origin(db, resource)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"云资源当前 IP 无法同步到源站: {exc}") from exc
    db.commit()
    db.refresh(origin)
    return origin


@router.post("/{group_id}/origins/bulk", response_model=FailoverGroupOut)
def create_origins_bulk(group_id: int, payload: OriginBulkCreate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(FailoverGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    existing_keys = {(origin.target, origin.port) for origin in group.origins}
    new_origins: list[Origin] = []
    new_keys: set[tuple[str, int]] = set()
    for item in payload.origins:
        origin = _origin_from_payload(db, group, item)
        key = (origin.target, origin.port)
        if key in existing_keys or key in new_keys:
            raise HTTPException(status_code=409, detail=f"{origin.target}:{origin.port} 已经在备用目标池中")
        new_keys.add(key)
        new_origins.append(origin)
    db.add_all(new_origins)
    db.commit()
    return _group_query(db).filter(FailoverGroup.id == group_id).one()


@router.patch("/origins/{origin_id}", response_model=OriginOut)
def update_origin(origin_id: int, payload: OriginUpdate, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    origin = db.get(Origin, origin_id)
    if origin is None:
        raise HTTPException(status_code=404, detail="源站不存在")
    if origin.global_origin_id:
        raise HTTPException(status_code=400, detail="这是业务分组的全局备用，请在全局备用里修改")
    updates = payload.model_dump(exclude_unset=True)
    if "external_ip_item_id" in updates:
        item_id = updates.pop("external_ip_item_id")
        if item_id is None:
            origin.external_source_id = None
            origin.external_machine_key = None
        else:
            origin.external_source_id, origin.external_machine_key = _external_binding_from_item_id(db, item_id)
    group = origin.group
    new_target = origin.target
    new_target_type = origin.target_type
    new_port = origin.port
    new_publish_mode = origin.publish_mode
    new_preferred_agent_id = origin.preferred_agent_id
    new_probe_mode = origin.probe_mode
    old_azpanel_resource_id = origin.azpanel_resource_id
    new_azpanel_resource_id = old_azpanel_resource_id
    azpanel_resource = None
    if "azpanel_resource_id" in updates:
        new_azpanel_resource_id = updates.pop("azpanel_resource_id")
        azpanel_resource = _azpanel_resource(db, new_azpanel_resource_id)
    elif new_azpanel_resource_id is not None:
        azpanel_resource = db.get(AzPanelResource, new_azpanel_resource_id)
    if "target" in updates and updates["target"] is not None:
        target_info = _parse_target_or_400(updates.pop("target"))
        if target_info.record_type == "CNAME" and target_info.value in _group_hostname_values(group):
            raise HTTPException(status_code=400, detail="CNAME 目标不能和当前主机名相同")
        new_target = target_info.value
        new_target_type = target_info.target_type
    if "port" in updates and updates["port"] is not None:
        new_port = updates["port"]
    if (
        azpanel_resource is not None
        and not origin.external_machine_key
        and azpanel_resource.auto_update_origin
        and azpanel_resource.current_ip
    ):
        resource_target = _parse_target_or_400(azpanel_resource.current_ip)
        new_target = resource_target.value
        new_target_type = resource_target.target_type
        new_port = azpanel_resource.port
    if "publish_mode" in updates and updates["publish_mode"] is not None:
        new_publish_mode = updates.pop("publish_mode")
    if new_target_type != "hostname" and new_publish_mode == EXPANDED_PUBLISH_MODE:
        raise HTTPException(status_code=400, detail="只有域名目标可以启用展开 IP 池")
    try:
        new_publish_mode = required_alibaba_origin_publish_mode(
            group,
            new_target_type,
            new_publish_mode,
        )
        validate_alibaba_origin_for_outputs(
            group,
            target_type=new_target_type,
            publish_mode=new_publish_mode,
            enabled=bool(updates.get("enabled", origin.enabled)),
        )
    except AlibabaOutputConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    preferred_agent_update_provided = "preferred_agent_id" in updates
    if preferred_agent_update_provided:
        new_preferred_agent_id = _validate_preferred_agent_id(db, updates.pop("preferred_agent_id"))

    probe_mode_update_provided = "probe_mode" in updates
    if probe_mode_update_provided:
        new_probe_mode = _normalize_probe_mode(updates.pop("probe_mode"))

    priority_updates_provided = "expanded_ip_priorities" in updates
    priority_updates = updates.pop("expanded_ip_priorities", None) if priority_updates_provided else None

    duplicate = (
        db.query(Origin)
        .filter(
            Origin.group_id == origin.group_id,
            Origin.id != origin.id,
            Origin.target == new_target,
            Origin.port == new_port,
        )
        .one_or_none()
    )
    if duplicate:
        raise HTTPException(status_code=409, detail=f"{new_target}:{new_port} 已经在备用目标池中")

    endpoint_changed = new_target != origin.target or new_port != origin.port or new_publish_mode != origin.publish_mode
    probe_source_changed = (
        (preferred_agent_update_provided and new_preferred_agent_id != origin.preferred_agent_id)
        or (probe_mode_update_provided and new_probe_mode != origin.probe_mode)
    )
    target_changed = new_target != origin.target or new_target_type != origin.target_type or new_publish_mode != origin.publish_mode
    old_expanded_ip_priorities = expanded_ip_priorities(origin)
    origin.target = new_target
    origin.target_type = new_target_type
    origin.publish_mode = new_publish_mode if new_target_type == "hostname" else DIRECT_PUBLISH_MODE
    origin.preferred_agent_id = new_preferred_agent_id
    origin.probe_mode = new_probe_mode
    origin.azpanel_resource_id = new_azpanel_resource_id
    if priority_updates_provided:
        _apply_expanded_ip_priorities(origin, priority_updates if new_target_type == "hostname" else {})
    elif new_target_type != "hostname":
        _apply_expanded_ip_priorities(origin, {})
    target_changed = target_changed or (
        origin.publish_mode == EXPANDED_PUBLISH_MODE and old_expanded_ip_priorities != expanded_ip_priorities(origin)
    )
    if "remark" in updates:
        origin.remark = _normalize_remark(updates.pop("remark"))
    for key, value in updates.items():
        setattr(origin, key, value)

    if endpoint_changed or probe_source_changed:
        origin.status = "unknown"
        origin.last_error = "等待本地和探针探测结果"
        origin.last_checked_at = None
        origin.last_rtt_ms = None
        origin.probe_states.clear()
        set_resolved_ips(origin, [])
        set_healthy_ips(origin, [])
        set_published_ips(origin, [])

    _refresh_azpanel_resource_bindings(db, [old_azpanel_resource_id, new_azpanel_resource_id])
    if azpanel_resource is not None:
        sync_resource_current_ip_to_origin(db, azpanel_resource)

    checked_expanded_now = False
    if endpoint_changed and origin.publish_mode == EXPANDED_PUBLISH_MODE:
        run_local_checks(db, origin_id=origin.id, include_all=True)
        checked_expanded_now = True

    should_publish_current = group.current_origin_id == origin.id and origin.enabled and target_changed
    if should_publish_current:
        try:
            if origin.publish_mode == EXPANDED_PUBLISH_MODE and not checked_expanded_now:
                run_local_checks(db, origin_id=origin.id, include_all=True)
            if origin.publish_mode == EXPANDED_PUBLISH_MODE and not origin.healthy_ips:
                group.last_error = "展开 IP 池已保存，当前没有健康 IP，暂不发布 DNS"
                record = None
            else:
                record = publish_origin(db, group, origin) if group.cloudflare_publish_enabled else None
                if group.doh_enabled:
                    _require_group_doh_sync(db, group)
        except Exception as exc:
            db.rollback()
            raise HTTPException(status_code=502, detail=f"DNS 发布失败，修改未保存：{exc}") from exc
        if record is not None or group.doh_enabled:
            group.current_origin_id = origin.id
            group.last_error = None
            payload = {
                "group_id": group.id,
                "hostname": group.hostname,
                "old_origin_id": origin.id,
                "new_origin_id": origin.id,
                "record_id": record["id"] if record else None,
                "record_type": record["type"] if record else None,
                "content": record["content"] if record else origin.target,
            }
            if record is None:
                add_event(db, "doh.switched", "info", f"{group.hostname} DoH output updated", payload)
                send_webhooks(db, "doh.switched", payload)
                db.commit()
                db.refresh(origin)
                return origin
            add_event(db, "dns.switched", "info", f"{group.hostname} 已更新到 {record['type']} {record['content']}", payload)
            send_webhooks(db, "dns.switched", payload)
    elif group.enabled:
        if group.current_origin_id == origin.id and not origin.enabled:
            group.current_origin_id = None
        _evaluate_locally(db, [group.id])

    db.commit()
    db.refresh(origin)
    return origin


@router.post("/origins/{origin_id}/run", response_model=Message)
def run_origin_now(origin_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    origin = db.get(Origin, origin_id)
    if origin is None:
        raise HTTPException(status_code=404, detail="源站不存在")
    checked = run_local_checks(db, origin_id=origin_id, include_all=True)
    # An explicit probe keeps the full semantics (drift check + auto IP change) but
    # only for the group that owns this origin.
    switches = evaluate_failover_groups(db, group_ids=[origin.group_id])
    db.commit()
    return Message(message="目标检测已完成", detail={"checked": checked, "switches": switches})


@router.delete("/origins/{origin_id}", response_model=Message)
def delete_origin(origin_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    origin = db.get(Origin, origin_id)
    if origin is None:
        raise HTTPException(status_code=404, detail="源站不存在")
    if origin.global_origin_id:
        raise HTTPException(status_code=400, detail="这是业务分组的全局备用，请在全局备用里删除")
    azpanel_resource_id = origin.azpanel_resource_id
    group = origin.group
    _delete_time_rule_for_origin(db, origin)
    if group.current_origin_id == origin.id:
        group.current_origin_id = None
        group.last_switch_at = None
    db.delete(origin)
    db.flush()
    _refresh_azpanel_resource_bindings(db, [azpanel_resource_id])
    if group.enabled:
        _evaluate_locally(db, [group.id])
    db.commit()
    return Message(message="源站已删除")


@router.post("/{group_id}/run", response_model=Message)
def run_group_now(group_id: int, _: User = Depends(get_current_user), db: Session = Depends(get_db)):
    group = db.get(FailoverGroup, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="切换组不存在")
    checked = run_local_checks(db, group_id=group_id, include_all=True)
    switches = evaluate_failover_groups(db, group_ids=[group_id])
    db.commit()
    return Message(message="切换组检测已完成", detail={"checked": checked, "switches": switches})


@router.post("/run", response_model=Message)
def run_now(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    checked = run_local_checks(db, include_all=True)
    switches = evaluate_failover_groups(db)
    db.commit()
    return Message(message="健康检查已完成", detail={"checked": checked, "switches": switches})
