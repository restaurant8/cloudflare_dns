from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from ..database import get_db
from ..deps import get_current_user
from ..dns_utils import normalize_hostname, parse_target
from ..doh import sync_doh_endpoint, validate_doh_hostname_conflicts
from ..models import AwsRoute53Credential, AwsRoute53Output, DohEndpoint, FailoverGroup, Origin, User
from ..route53 import (
    Route53AdoptionRequired,
    Route53TrafficPolicyManaged,
    create_private_hosted_zone,
    delete_empty_private_hosted_zone,
    get_private_hosted_zone,
    list_private_hosted_zones,
    list_vpcs,
    normalize_hosted_zone_id,
    publish_route53_output,
    route53_client,
    route53_output_matches,
    validate_route53_adoption,
    validate_hostname_in_zone,
)
from ..schemas import (
    AwsRoute53CredentialCreate,
    AwsRoute53CredentialOut,
    AwsRoute53CredentialUpdate,
    AwsRoute53PrivateHostedZoneCreate,
    AwsRoute53PrivateHostedZoneDelete,
    AwsRoute53PrivateHostedZoneOut,
    AwsRoute53VpcOut,
    AwsRoute53OutputCreate,
    AwsRoute53OutputOut,
    AwsRoute53OutputUpdate,
    AwsRoute53StandaloneGroupCreate,
    FailoverGroupOut,
    Message,
)
from ..security import encrypt_secret


router = APIRouter(prefix="/route53", tags=["route53"])


@router.get("/credentials", response_model=list[AwsRoute53CredentialOut])
def credentials(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(AwsRoute53Credential).order_by(AwsRoute53Credential.name).all()


@router.post("/credentials", response_model=AwsRoute53CredentialOut)
def create_credential(
    payload: AwsRoute53CredentialCreate,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not payload.use_instance_role and (not payload.access_key_id or not payload.secret_access_key):
        raise HTTPException(status_code=400, detail="Access Key ID and Secret Access Key are required")
    credential = AwsRoute53Credential(
        name=payload.name.strip(),
        access_key_id_encrypted=encrypt_secret(payload.access_key_id.strip()) if payload.access_key_id else None,
        secret_access_key_encrypted=encrypt_secret(payload.secret_access_key) if payload.secret_access_key else None,
        session_token_encrypted=encrypt_secret(payload.session_token) if payload.session_token else None,
        region=payload.region.strip(),
        use_instance_role=payload.use_instance_role,
        enabled=payload.enabled,
    )
    db.add(credential)
    try:
        db.flush()
        route53_client(credential).list_hosted_zones(MaxItems="1")
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"AWS Route 53 credential test failed: {exc}") from exc
    db.commit()
    db.refresh(credential)
    return credential


@router.patch("/credentials/{credential_id}", response_model=AwsRoute53CredentialOut)
def update_credential(
    credential_id: int,
    payload: AwsRoute53CredentialUpdate,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    credential = db.get(AwsRoute53Credential, credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="AWS Route 53 credential not found")
    updates = payload.model_dump(exclude_unset=True)
    for field, encrypted_field in (
        ("access_key_id", "access_key_id_encrypted"),
        ("secret_access_key", "secret_access_key_encrypted"),
        ("session_token", "session_token_encrypted"),
    ):
        if field in updates:
            value = updates.pop(field)
            if value:
                setattr(credential, encrypted_field, encrypt_secret(value.strip() if field == "access_key_id" else value))
    for key, value in updates.items():
        setattr(credential, key, value.strip() if isinstance(value, str) else value)
    if not credential.use_instance_role and not credential.secret_configured:
        raise HTTPException(status_code=400, detail="Access Key ID and Secret Access Key are required")
    try:
        route53_client(credential).list_hosted_zones(MaxItems="1")
        credential.last_error = None
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"AWS Route 53 credential test failed: {exc}") from exc
    db.commit()
    db.refresh(credential)
    return credential


@router.delete("/credentials/{credential_id}", response_model=Message)
def delete_credential(
    credential_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    credential = db.get(AwsRoute53Credential, credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="AWS Route 53 credential not found")
    used = db.query(AwsRoute53Output).filter(AwsRoute53Output.credential_id == credential.id).count()
    if used:
        raise HTTPException(status_code=409, detail=f"Credential is used by {used} AWS DoH rule(s)")
    db.delete(credential)
    db.commit()
    return Message(message="AWS Route 53 credential deleted")


@router.get("/credentials/{credential_id}/private-hosted-zones", response_model=list[AwsRoute53PrivateHostedZoneOut])
def private_hosted_zones(
    credential_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    credential = db.get(AwsRoute53Credential, credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="AWS Route 53 credential not found")
    try:
        return list_private_hosted_zones(credential)
    except Exception as exc:
        credential.last_error = str(exc)
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/credentials/{credential_id}/vpcs", response_model=list[AwsRoute53VpcOut])
def vpcs(
    credential_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    credential = _credential(db, credential_id)
    try:
        values = list_vpcs(credential)
        credential.last_error = None
        db.commit()
        return values
    except Exception as exc:
        credential.last_error = str(exc)
        db.commit()
        raise HTTPException(status_code=502, detail=f"Could not list AWS VPCs: {exc}") from exc


@router.post(
    "/credentials/{credential_id}/private-hosted-zones",
    response_model=AwsRoute53PrivateHostedZoneOut,
)
def create_hosted_zone(
    credential_id: int,
    payload: AwsRoute53PrivateHostedZoneCreate,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    credential = _credential(db, credential_id)
    try:
        name = normalize_hostname(payload.name)
        if payload.vpc_region != credential.region:
            raise ValueError(
                f"Selected VPC region {payload.vpc_region} does not match credential region {credential.region}"
            )
        available_vpcs = {item["id"] for item in list_vpcs(credential)}
        if payload.vpc_id not in available_vpcs:
            raise ValueError(f"VPC {payload.vpc_id} was not found in {payload.vpc_region}")
        result = create_private_hosted_zone(
            credential,
            name=name,
            vpc_id=payload.vpc_id,
            vpc_region=payload.vpc_region,
            comment=payload.comment,
        )
        credential.last_error = None
        db.commit()
        return result
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        credential.last_error = str(exc)
        db.commit()
        raise HTTPException(status_code=502, detail=f"Could not create Route 53 private hosted zone: {exc}") from exc


@router.delete("/credentials/{credential_id}/private-hosted-zones/{hosted_zone_id}", response_model=Message)
def delete_hosted_zone(
    credential_id: int,
    hosted_zone_id: str,
    payload: AwsRoute53PrivateHostedZoneDelete,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    credential = _credential(db, credential_id)
    zone_id = normalize_hosted_zone_id(hosted_zone_id)
    try:
        zone = get_private_hosted_zone(credential, zone_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not inspect Route 53 private hosted zone: {exc}") from exc
    if payload.confirm_name.strip().rstrip(".").lower() != zone["name"].lower():
        raise HTTPException(status_code=400, detail="Hosted zone confirmation name does not match")
    bindings = db.query(AwsRoute53Output).filter(
        AwsRoute53Output.credential_id == credential.id,
        AwsRoute53Output.hosted_zone_id == zone_id,
    ).count()
    if bindings:
        raise HTTPException(
            status_code=409,
            detail=f"Private hosted zone is still used by {bindings} AWS DoH failover group(s); delete those groups first",
        )
    try:
        change = delete_empty_private_hosted_zone(credential, zone_id)
        credential.last_error = None
        db.commit()
        return Message(message="Route 53 private hosted zone deleted", detail={"change": change})
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        credential.last_error = str(exc)
        db.commit()
        raise HTTPException(status_code=502, detail=f"Could not delete Route 53 private hosted zone: {exc}") from exc


def _output_query(db: Session):
    return db.query(AwsRoute53Output).options(
        selectinload(AwsRoute53Output.credential),
        selectinload(AwsRoute53Output.group).selectinload(FailoverGroup.origins),
    )


def _credential(db: Session, credential_id: int) -> AwsRoute53Credential:
    credential = db.get(AwsRoute53Credential, credential_id)
    if credential is None or not credential.enabled or not credential.secret_configured:
        raise HTTPException(status_code=400, detail="Please select an enabled AWS Route 53 credential")
    return credential


def _validate_output_identity(
    db: Session,
    *,
    credential_id: int,
    hosted_zone_id: str,
    hosted_zone_name: str,
    hostname: str,
    exclude_id: int | None = None,
    doh_endpoint_id: int | None = None,
    current_output: AwsRoute53Output | None = None,
    exclude_group_id: int | None = None,
    adopt_existing: bool = False,
) -> tuple[AwsRoute53Credential, str, str, str]:
    credential = _credential(db, credential_id)
    zone_id = normalize_hosted_zone_id(hosted_zone_id)
    zone_name = hosted_zone_name.strip().rstrip(".").lower()
    try:
        normalized = normalize_hostname(hostname)
        validate_hostname_in_zone(normalized, zone_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    query = db.query(AwsRoute53Output).filter(
        AwsRoute53Output.credential_id == credential.id,
        AwsRoute53Output.hosted_zone_id == zone_id,
        AwsRoute53Output.hostname == normalized,
    )
    if exclude_id is not None:
        query = query.filter(AwsRoute53Output.id != exclude_id)
    if query.first() is not None:
        raise HTTPException(status_code=409, detail="This Route 53 private record is already managed")
    if doh_endpoint_id is not None:
        try:
            validate_doh_hostname_conflicts(
                db,
                endpoint_id=doh_endpoint_id,
                hostnames=[normalized],
                exclude_group_id=exclude_group_id,
                exclude_route53_output_id=exclude_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        output_query = db.query(AwsRoute53Output).filter(
            AwsRoute53Output.doh_endpoint_id == doh_endpoint_id,
            AwsRoute53Output.hostname == normalized,
        )
        if exclude_id is not None:
            output_query = output_query.filter(AwsRoute53Output.id != exclude_id)
        if output_query.first() is not None:
            raise HTTPException(status_code=409, detail="This hostname is already allowed by the selected DoH endpoint")
    identity_changed = (
        current_output is None
        or current_output.credential_id != credential.id
        or normalize_hosted_zone_id(current_output.hosted_zone_id) != zone_id
        or current_output.hostname.rstrip(".").lower() != normalized
    )
    if identity_changed:
        try:
            validate_route53_adoption(
                credential,
                zone_id,
                normalized,
                adopt_existing=adopt_existing,
            )
        except (Route53AdoptionRequired, Route53TrafficPolicyManaged) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Could not inspect existing Route 53 records for {normalized}: {exc}",
            ) from exc
    return credential, zone_id, zone_name, normalized


def _doh_endpoint(db: Session, endpoint_id: int) -> DohEndpoint:
    endpoint = db.get(DohEndpoint, endpoint_id)
    if endpoint is None or not endpoint.enabled:
        raise HTTPException(status_code=400, detail="Please select an enabled AWS DoH endpoint")
    return endpoint


@router.post("/groups", response_model=FailoverGroupOut)
def create_standalone_group(
    payload: AwsRoute53StandaloneGroupCreate,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    credential = _credential(db, payload.credential_id)
    endpoint = _doh_endpoint(db, payload.doh_endpoint_id)
    try:
        zone = get_private_hosted_zone(credential, payload.hosted_zone_id)
        hostname = normalize_hostname(zone["name"])
        target = parse_target(payload.primary_target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not inspect Route 53 private hosted zone: {exc}") from exc
    duplicate = (
        db.query(FailoverGroup)
        .options(selectinload(FailoverGroup.origins), selectinload(FailoverGroup.route53_outputs))
        .filter(
            FailoverGroup.zone_id.is_(None),
            FailoverGroup.provider_type == "route53",
            FailoverGroup.hostname == hostname,
        )
        .order_by(FailoverGroup.id)
        .first()
    )
    if duplicate is not None and duplicate.route53_outputs:
        raise HTTPException(status_code=409, detail="This standalone failover hostname already has a Route 53 output")
    credential, zone_id, zone_name, hostname = _validate_output_identity(
        db,
        credential_id=credential.id,
        hosted_zone_id=zone["id"],
        hosted_zone_name=zone["name"],
        hostname=hostname,
        doh_endpoint_id=endpoint.id,
        exclude_group_id=duplicate.id if duplicate is not None else None,
        adopt_existing=payload.adopt_existing,
    )
    if duplicate is None:
        group = FailoverGroup(
            provider_type="route53",
            zone_id=None,
            hostname=hostname,
            ttl=payload.ttl,
            enabled=True,
            min_switch_interval_seconds=payload.min_switch_interval_seconds,
            cloudflare_publish_enabled=False,
            doh_enabled=False,
        )
        db.add(group)
        db.flush()
    else:
        group = duplicate
        group.ttl = payload.ttl
        group.enabled = True
        group.min_switch_interval_seconds = payload.min_switch_interval_seconds
        group.last_error = None
    if not group.origins:
        origin = Origin(
            group_id=group.id,
            target=target.value,
            target_type=target.target_type,
            publish_mode="expanded" if target.target_type == "hostname" else "direct",
            port=payload.primary_port,
            priority=0,
            remark="AWS private DoH primary",
            enabled=True,
            status="unknown",
        )
        db.add(origin)
        db.flush()
        group.current_origin_id = None
    output = AwsRoute53Output(
        group_id=group.id,
        credential_id=credential.id,
        doh_endpoint_id=endpoint.id,
        hosted_zone_id=zone_id,
        hosted_zone_name=zone_name,
        hostname=hostname,
        ttl=payload.ttl,
        enabled=True,
    )
    db.add(output)
    db.flush()
    current_origin = next((item for item in group.origins if item.id == group.current_origin_id), None)
    if duplicate is not None and current_origin is not None and current_origin.enabled:
        # Preserve service continuity while upgrading a migrated static rule.
        # The legacy DoH sync already persisted its last-known-good addresses;
        # expanded mode lets Route 53 publish that address at the zone apex.
        if current_origin.target_type == "hostname" and current_origin.publish_mode != "expanded":
            current_origin.publish_mode = "expanded"
        try:
            publish_route53_output(
                output,
                current_origin,
                require_adoption=True,
                adopt_existing=payload.adopt_existing,
            )
        except Exception as exc:
            db.rollback()
            raise HTTPException(
                status_code=502,
                detail=f"Route 53 first publish failed; the legacy static DoH rule was left unchanged: {exc}",
            ) from exc
    # A migrated legacy rule may still publish authoritative values directly to
    # EC2. Once Route 53 owns the same name, keep a single snapshot owner and let
    # the VPC Resolver become the source of truth.
    group.doh_enabled = False
    group.doh_endpoint_id = None
    group.doh_hostnames_json = "[]"
    _best_effort_allowlist_sync(db, endpoint)
    db.commit()
    return (
        db.query(FailoverGroup)
        .options(selectinload(FailoverGroup.origins), selectinload(FailoverGroup.route53_outputs))
        .filter(FailoverGroup.id == group.id)
        .one()
    )


def _best_effort_allowlist_sync(db: Session, endpoint: DohEndpoint) -> None:
    sync_doh_endpoint(db, endpoint, force=True, ignore_backoff=True)


@router.get("/outputs", response_model=list[AwsRoute53OutputOut])
def outputs(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _output_query(db).order_by(AwsRoute53Output.created_at.desc()).all()


@router.post("/outputs", response_model=AwsRoute53OutputOut)
def create_output(
    payload: AwsRoute53OutputCreate,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    group = db.get(FailoverGroup, payload.group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Failover group not found")
    endpoint = _doh_endpoint(db, payload.doh_endpoint_id)
    credential, zone_id, zone_name, hostname = _validate_output_identity(
        db,
        credential_id=payload.credential_id,
        hosted_zone_id=payload.hosted_zone_id,
        hosted_zone_name=payload.hosted_zone_name,
        hostname=payload.hostname,
        doh_endpoint_id=endpoint.id,
        adopt_existing=payload.adopt_existing,
    )
    output = AwsRoute53Output(
        group_id=group.id,
        credential_id=credential.id,
        doh_endpoint_id=endpoint.id,
        hosted_zone_id=zone_id,
        hosted_zone_name=zone_name,
        hostname=hostname,
        ttl=payload.ttl,
        enabled=payload.enabled,
    )
    db.add(output)
    db.flush()
    origin = db.get(Origin, group.current_origin_id) if group.current_origin_id else None
    if output.enabled and origin is not None and origin.enabled:
        try:
            publish_route53_output(
                output,
                origin,
                require_adoption=True,
                adopt_existing=payload.adopt_existing,
            )
        except (Route53AdoptionRequired, Route53TrafficPolicyManaged) as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except Exception as exc:
            # The local configuration remains editable/deletable while AWS is
            # unavailable. The scheduler retries from desired state later.
            output.last_error = str(exc)
            credential.last_error = str(exc)
    _best_effort_allowlist_sync(db, endpoint)
    db.commit()
    return _output_query(db).filter(AwsRoute53Output.id == output.id).one()


@router.patch("/outputs/{output_id}", response_model=AwsRoute53OutputOut)
def update_output(
    output_id: int,
    payload: AwsRoute53OutputUpdate,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    output = _output_query(db).filter(AwsRoute53Output.id == output_id).one_or_none()
    if output is None:
        raise HTTPException(status_code=404, detail="Route 53 output not found")
    updates = payload.model_dump(exclude_unset=True)
    adopt_existing = bool(updates.pop("adopt_existing", False))
    credential_id = int(updates.get("credential_id", output.credential_id))
    endpoint_id = int(updates.get("doh_endpoint_id", output.doh_endpoint_id))
    zone_id = str(updates.get("hosted_zone_id", output.hosted_zone_id))
    zone_name = str(updates.get("hosted_zone_name", output.hosted_zone_name))
    hostname = str(updates.get("hostname", output.hostname))
    endpoint = _doh_endpoint(db, endpoint_id)
    credential, zone_id, zone_name, hostname = _validate_output_identity(
        db,
        credential_id=credential_id,
        hosted_zone_id=zone_id,
        hosted_zone_name=zone_name,
        hostname=hostname,
        exclude_id=output.id,
        doh_endpoint_id=endpoint.id,
        current_output=output,
        adopt_existing=adopt_existing,
    )
    identity_changed = (
        output.credential_id != credential.id
        or normalize_hosted_zone_id(output.hosted_zone_id) != zone_id
        or output.hostname.rstrip(".").lower() != hostname
    )
    previous_endpoint = output.doh_endpoint
    output.credential = credential
    output.credential_id = credential.id
    output.doh_endpoint = endpoint
    output.doh_endpoint_id = endpoint.id
    output.hosted_zone_id = zone_id
    output.hosted_zone_name = zone_name
    output.hostname = hostname
    if "ttl" in updates:
        output.ttl = int(updates["ttl"])
    if "enabled" in updates:
        output.enabled = bool(updates["enabled"])
    output.last_error = None
    origin = db.get(Origin, output.group.current_origin_id) if output.group.current_origin_id else None
    if output.enabled and origin is not None and origin.enabled:
        try:
            publish_route53_output(
                output,
                origin,
                require_adoption=identity_changed,
                adopt_existing=adopt_existing,
            )
        except (Route53AdoptionRequired, Route53TrafficPolicyManaged) as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except Exception as exc:
            output.last_error = str(exc)
            credential.last_error = str(exc)
    _best_effort_allowlist_sync(db, endpoint)
    if previous_endpoint.id != endpoint.id:
        _best_effort_allowlist_sync(db, previous_endpoint)
    db.commit()
    return _output_query(db).filter(AwsRoute53Output.id == output.id).one()


@router.delete("/outputs/{output_id}", response_model=Message)
def delete_output(
    output_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    output = db.get(AwsRoute53Output, output_id)
    if output is None:
        raise HTTPException(status_code=404, detail="Route 53 output not found")
    # Deliberately leave the remote record intact, matching Cloudflare's
    # "stop managing" behaviour. Deletion never depends on AWS availability.
    endpoint = output.doh_endpoint
    db.delete(output)
    db.flush()
    _best_effort_allowlist_sync(db, endpoint)
    db.commit()
    return Message(message="Route 53 output removed; the current AWS record was preserved")


@router.post("/outputs/{output_id}/run", response_model=Message)
def run_output(
    output_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    output = _output_query(db).filter(AwsRoute53Output.id == output_id).one_or_none()
    if output is None:
        raise HTTPException(status_code=404, detail="Route 53 output not found")
    origin = next((item for item in output.group.origins if item.id == output.group.current_origin_id), None)
    if not output.enabled or origin is None or not origin.enabled:
        raise HTTPException(status_code=400, detail="Output is disabled or its failover group has no current origin")
    try:
        matched = route53_output_matches(output, origin)
        output.last_consistency_check_at = datetime.utcnow()
        if not matched:
            publish_route53_output(output, origin)
    except Exception as exc:
        output.last_error = str(exc)
        output.credential.last_error = str(exc)
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.commit()
    return Message(message="Route 53 output checked", detail={"repaired": not matched})
