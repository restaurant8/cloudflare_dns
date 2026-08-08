from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.health import run_local_checks
from app.models import (
    Agent,
    CloudflareCredential,
    FailoverCollection,
    FailoverGlobalOrigin,
    FailoverGroup,
    Origin,
    ProbeResult,
    ProbeState,
    TargetPoolItem,
    Zone,
)
from app.origin_expansion import EXPANDED_PUBLISH_MODE, expanded_source_key, resolved_ips, set_resolved_ips
from app.routes.agents import agent_results, agent_tasks, update_agent
from app.schemas import AgentResultIn, AgentResultsIn, AgentUpdate
from app.security import encrypt_secret


def make_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def request(headers=None, client_host="127.0.0.1"):
    return SimpleNamespace(headers=headers or {}, client=SimpleNamespace(host=client_host))


def make_group_with_duplicate_origins(db):
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.flush()
    current = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=443, priority=1)
    backup = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=443, priority=2)
    agent = Agent(name="china", region="china", token_hash="hash", status="online", last_seen_at=datetime.utcnow())
    db.add_all([current, backup, agent])
    db.commit()
    db.refresh(current)
    db.refresh(backup)
    db.refresh(agent)
    return current, backup, agent


def test_agent_tasks_reuses_duplicate_targets():
    db = make_session()
    current, backup, agent = make_group_with_duplicate_origins(db)

    response = agent_tasks(request(), agent=agent, db=db)

    assert len(response.tasks) == 1
    assert response.tasks[0].origin_id == current.id
    assert response.tasks[0].target == current.target
    assert response.tasks[0].port == current.port == backup.port


def test_agent_tasks_newly_online_probe_gets_tasks_in_first_request():
    db = make_session()
    current, _, agent = make_group_with_duplicate_origins(db)
    agent.status = "unknown"
    agent.last_seen_at = None
    db.commit()

    response = agent_tasks(request(), agent=agent, db=db)

    assert agent.status == "online"
    assert len(response.tasks) == 1
    assert response.tasks[0].target == current.target


def test_agent_tasks_persist_liveness_when_later_task_selection_fails(monkeypatch):
    db = make_session()
    _, _, agent = make_group_with_duplicate_origins(db)
    agent.status = "unknown"
    agent.last_seen_at = None
    db.commit()

    def fail_after_liveness(*args, **kwargs):
        raise RuntimeError("task selection failed")

    monkeypatch.setattr("app.routes.agents.active_agents", fail_after_liveness)

    with pytest.raises(RuntimeError, match="task selection failed"):
        agent_tasks(request(), agent=agent, db=db)

    db.rollback()
    db.expire_all()
    persisted = db.get(Agent, agent.id)
    assert persisted.status == "online"
    assert persisted.last_seen_at is not None


def test_agent_tasks_read_controller_expanded_pool_without_resolving(monkeypatch):
    db = make_session()
    current, backup, agent = make_group_with_duplicate_origins(db)
    backup.enabled = False
    current.target = "geo.example.net"
    current.target_type = "hostname"
    current.publish_mode = EXPANDED_PUBLISH_MODE
    set_resolved_ips(current, ["203.0.113.1"])
    db.commit()
    resolution_attempts = []

    def alternate_view(hostname):
        resolution_attempts.append(hostname)
        return ["198.51.100.7"]

    monkeypatch.setattr("app.health.resolve_hostname_ips", alternate_view)

    response = agent_tasks(request(), agent=agent, db=db)

    assert resolution_attempts == []
    assert resolved_ips(current) == ["203.0.113.1"]
    assert [task.target for task in response.tasks] == ["203.0.113.1"]


def test_expanded_pool_flows_from_controller_to_agent_tasks_and_results(monkeypatch):
    db = make_session()
    current, backup, agent = make_group_with_duplicate_origins(db)
    backup.enabled = False
    current.target = "pool.example.net"
    current.target_type = "hostname"
    current.publish_mode = EXPANDED_PUBLISH_MODE
    current.probe_mode = "china_only"
    db.commit()
    controller_ips = ["192.0.2.60", "192.0.2.61"]

    monkeypatch.setattr("app.health.resolve_hostname_ips", lambda hostname: controller_ips)
    monkeypatch.setattr(
        "app.health.tcp_check",
        lambda *args: (_ for _ in ()).throw(AssertionError("china_only must not run local TCP checks")),
    )

    assert run_local_checks(db) == 0
    assert resolved_ips(current) == controller_ips

    tasks_response = agent_tasks(request(), agent=agent, db=db)
    assert [task.target for task in tasks_response.tasks] == controller_ips

    agent_results(
        AgentResultsIn(
            results=[
                AgentResultIn(
                    origin_id=task.origin_id,
                    target=task.target,
                    port=task.port,
                    success=True,
                    rtt_ms=1.0,
                )
                for task in tasks_response.tasks
            ]
        ),
        request(),
        agent=agent,
        db=db,
    )

    states = db.query(ProbeState).filter_by(origin_id=current.id, agent_id=agent.id).all()
    assert {state.source_key for state in states} == {
        expanded_source_key(f"agent:{agent.id}", ip) for ip in controller_ips
    }
    assert db.query(ProbeResult).filter_by(origin_id=current.id, agent_id=agent.id).count() == 2


def test_agent_tasks_prefers_global_origin_over_matching_backup():
    db = make_session()
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    collection = FailoverCollection(name="production")
    db.add_all([credential, collection])
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    primary_group = FailoverGroup(zone_id=zone.id, collection_id=collection.id, hostname="a.example.com")
    secondary_group = FailoverGroup(zone_id=zone.id, collection_id=collection.id, hostname="b.example.com")
    db.add_all([primary_group, secondary_group])
    db.flush()
    matching_backup = Origin(
        group_id=secondary_group.id,
        target="198.51.100.10",
        target_type="ipv4",
        port=22,
        priority=5,
    )
    global_origin_template = FailoverGlobalOrigin(
        collection_id=collection.id,
        target=matching_backup.target,
        target_type="ipv4",
        port=22,
        priority=1,
    )
    db.add_all([matching_backup, global_origin_template])
    db.flush()
    global_origin = Origin(
        group_id=primary_group.id,
        global_origin_id=global_origin_template.id,
        target=global_origin_template.target,
        target_type="ipv4",
        port=22,
        priority=1,
    )
    agent = Agent(name="china", region="china", token_hash="hash", status="online", last_seen_at=datetime.utcnow())
    db.add_all([global_origin, agent])
    db.commit()
    db.refresh(global_origin)
    db.refresh(agent)

    response = agent_tasks(request(), agent=agent, db=db)

    assert len(response.tasks) == 1
    assert response.tasks[0].origin_id == global_origin.id
    assert response.tasks[0].target == matching_backup.target


def test_update_agent_renames_probe():
    db = make_session()
    _, _, agent = make_group_with_duplicate_origins(db)

    response = update_agent(agent.id, AgentUpdate(name="  mainland probe  "), _=SimpleNamespace(), db=db)

    assert response.name == "mainland probe"
    assert db.get(Agent, agent.id).name == "mainland probe"


def test_update_agent_sets_unique_default_probe():
    db = make_session()
    _, _, first_agent = make_group_with_duplicate_origins(db)
    second_agent = Agent(name="china-2", region="china", token_hash="hash-2", status="online", last_seen_at=datetime.utcnow(), is_default=True)
    db.add(second_agent)
    db.commit()
    db.refresh(second_agent)

    response = update_agent(first_agent.id, AgentUpdate(is_default=True), _=SimpleNamespace(), db=db)

    assert response.is_default is True
    assert db.get(Agent, first_agent.id).is_default is True
    assert db.get(Agent, second_agent.id).is_default is False


def test_agent_results_apply_duplicate_target_to_all_matching_origins():
    db = make_session()
    current, backup, agent = make_group_with_duplicate_origins(db)

    payload = AgentResultsIn(
        results=[
            AgentResultIn(
                origin_id=current.id,
                target=current.target,
                port=current.port,
                success=True,
                rtt_ms=8.5,
            )
        ]
    )

    agent_results(payload, request(), agent=agent, db=db)

    states = db.query(ProbeState).filter(ProbeState.origin_id.in_([current.id, backup.id])).all()
    results = db.query(ProbeResult).filter(ProbeResult.origin_id.in_([current.id, backup.id])).all()

    assert {state.origin_id for state in states} == {current.id, backup.id}
    assert {result.origin_id for result in results} == {current.id, backup.id}


def test_agent_results_have_same_final_state_when_requests_are_split():
    # Controller-side contract regression: even though current agents submit one
    # batch, split/retried HTTP requests must converge to the same database state.
    def run(split: bool):
        db = make_session()
        current, backup, agent = make_group_with_duplicate_origins(db)
        backup.target = "192.0.2.20"
        db.commit()
        items = [
            AgentResultIn(origin_id=current.id, target=current.target, port=current.port, success=True, rtt_ms=8.5),
            AgentResultIn(origin_id=backup.id, target=backup.target, port=backup.port, success=False, rtt_ms=3000, error="timed out"),
        ]
        payloads = [AgentResultsIn(results=[item]) for item in items] if split else [AgentResultsIn(results=items)]
        for payload in payloads:
            agent_results(payload, request(), agent=agent, db=db)
        origins = db.query(Origin).filter(Origin.id.in_([current.id, backup.id])).order_by(Origin.target).all()
        snapshot = []
        for origin in origins:
            states = db.query(ProbeState).filter(ProbeState.origin_id == origin.id).order_by(ProbeState.source_key).all()
            snapshot.append(
                (
                    origin.target,
                    origin.status,
                    origin.last_error,
                    [(state.source_key, state.status, state.success_count, state.fail_count, state.last_error, state.last_rtt_ms) for state in states],
                )
            )
        return snapshot, db.query(ProbeResult).count()

    assert run(split=False) == run(split=True)


def test_agent_results_ignore_stale_task_after_origin_target_changes():
    db = make_session()
    current, backup, agent = make_group_with_duplicate_origins(db)
    old_target = current.target
    current.target = "198.51.100.20"
    backup.target = "198.51.100.30"
    db.commit()

    payload = AgentResultsIn(
        results=[
            AgentResultIn(
                origin_id=current.id,
                target=old_target,
                port=current.port,
                success=False,
                rtt_ms=None,
                error="old target failed",
            )
        ]
    )

    agent_results(payload, request(), agent=agent, db=db)

    states = db.query(ProbeState).filter(ProbeState.origin_id.in_([current.id, backup.id])).all()
    results = db.query(ProbeResult).filter(ProbeResult.origin_id.in_([current.id, backup.id])).all()

    assert states == []
    assert results == []


def test_agent_results_do_not_update_origin_assigned_to_another_probe():
    db = make_session()
    current, backup, primary_agent = make_group_with_duplicate_origins(db)
    secondary_agent = Agent(name="china-2", region="china", token_hash="hash-2", status="online", last_seen_at=datetime.utcnow())
    db.add(secondary_agent)
    db.flush()
    current.preferred_agent_id = primary_agent.id
    backup.preferred_agent_id = secondary_agent.id
    db.commit()

    payload = AgentResultsIn(
        results=[
            AgentResultIn(
                origin_id=current.id,
                target=current.target,
                port=current.port,
                success=True,
                rtt_ms=8.5,
            )
        ]
    )

    agent_results(payload, request(), agent=primary_agent, db=db)

    states = db.query(ProbeState).filter(ProbeState.origin_id.in_([current.id, backup.id])).all()

    assert {state.origin_id for state in states} == {current.id}


def test_agent_tasks_only_use_first_same_region_probe_until_it_fails():
    db = make_session()
    current, _, primary_agent = make_group_with_duplicate_origins(db)
    secondary_agent = Agent(name="china-2", region="china", token_hash="hash-2", status="online", last_seen_at=datetime.utcnow())
    db.add(secondary_agent)
    db.commit()
    db.refresh(secondary_agent)

    primary_response = agent_tasks(request(), agent=primary_agent, db=db)
    secondary_response = agent_tasks(request(), agent=secondary_agent, db=db)

    assert len(primary_response.tasks) == 1
    assert primary_response.tasks[0].target == current.target
    assert secondary_response.tasks == []


def test_agent_tasks_use_default_probe_before_other_regions():
    db = make_session()
    current, _, default_probe = make_group_with_duplicate_origins(db)
    default_probe.is_default = True
    backup_probe = Agent(name="foreign-backup", region="foreign", token_hash="hash-2", status="online", last_seen_at=datetime.utcnow())
    db.add(backup_probe)
    db.commit()
    db.refresh(backup_probe)

    default_response = agent_tasks(request(), agent=default_probe, db=db)
    backup_response = agent_tasks(request(), agent=backup_probe, db=db)

    assert len(default_response.tasks) == 1
    assert default_response.tasks[0].target == current.target
    assert backup_response.tasks == []


def test_agent_tasks_use_backup_when_default_probe_is_offline():
    db = make_session()
    current, _, default_probe = make_group_with_duplicate_origins(db)
    default_probe.is_default = True
    default_probe.status = "offline"
    default_probe.last_seen_at = datetime.utcnow() - timedelta(minutes=10)
    backup_probe = Agent(name="foreign-backup", region="foreign", token_hash="hash-2", status="online", last_seen_at=datetime.utcnow())
    db.add(backup_probe)
    db.commit()
    db.refresh(backup_probe)

    response = agent_tasks(request(), agent=backup_probe, db=db)

    assert len(response.tasks) == 1
    assert response.tasks[0].target == current.target


def test_agent_tasks_origin_preferred_probe_overrides_default_probe():
    db = make_session()
    current, backup, default_probe = make_group_with_duplicate_origins(db)
    default_probe.is_default = True
    backup.enabled = False
    preferred_probe = Agent(name="preferred", region="foreign", token_hash="hash-2", status="online", last_seen_at=datetime.utcnow())
    db.add(preferred_probe)
    db.flush()
    current.preferred_agent_id = preferred_probe.id
    db.commit()
    db.refresh(preferred_probe)

    default_response = agent_tasks(request(), agent=default_probe, db=db)
    preferred_response = agent_tasks(request(), agent=preferred_probe, db=db)

    assert default_response.tasks == []
    assert len(preferred_response.tasks) == 1
    assert preferred_response.tasks[0].target == current.target


def test_agent_tasks_skip_local_only_origin():
    db = make_session()
    current, backup, agent = make_group_with_duplicate_origins(db)
    backup.enabled = False
    current.probe_mode = "local_only"
    db.commit()

    response = agent_tasks(request(), agent=agent, db=db)

    assert response.tasks == []


def test_agent_tasks_any_probe_mode_uses_china_probe_not_foreign_probe():
    db = make_session()
    current, backup, china_agent = make_group_with_duplicate_origins(db)
    backup.enabled = False
    current.probe_mode = "any"
    foreign_agent = Agent(name="foreign", region="foreign", token_hash="hash-2", status="online", last_seen_at=datetime.utcnow())
    db.add(foreign_agent)
    db.commit()
    db.refresh(foreign_agent)

    china_response = agent_tasks(request(), agent=china_agent, db=db)
    foreign_response = agent_tasks(request(), agent=foreign_agent, db=db)

    assert len(china_response.tasks) == 1
    assert china_response.tasks[0].target == current.target
    assert foreign_response.tasks == []


def test_agent_tasks_use_second_same_region_probe_after_first_fails():
    db = make_session()
    current, _, primary_agent = make_group_with_duplicate_origins(db)
    secondary_agent = Agent(name="china-2", region="china", token_hash="hash-2", status="online", last_seen_at=datetime.utcnow())
    db.add(secondary_agent)
    db.commit()
    db.refresh(secondary_agent)
    db.add(
        ProbeState(
            origin_id=current.id,
            source_key=f"agent:{primary_agent.id}",
            status="unhealthy",
            last_checked_at=datetime.utcnow(),
            last_error="connect failed",
        )
    )
    db.commit()

    response = agent_tasks(request(), agent=secondary_agent, db=db)

    assert len(response.tasks) == 1
    assert response.tasks[0].target == current.target


def test_china_agent_tasks_include_all_enabled_origins_when_current_is_lower_priority():
    db = make_session()
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.flush()
    primary = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=443, priority=1)
    current = Origin(group_id=group.id, target="192.0.2.20", target_type="ipv4", port=443, priority=5, status="healthy")
    later_backup = Origin(group_id=group.id, target="192.0.2.30", target_type="ipv4", port=443, priority=10)
    agent = Agent(name="china", region="china", token_hash="hash", status="online", last_seen_at=datetime.utcnow())
    db.add_all([primary, current, later_backup, agent])
    db.flush()
    group.current_origin_id = current.id
    db.commit()

    response = agent_tasks(request(), agent=agent, db=db)

    assert {(task.target, task.port) for task in response.tasks} == {
        ("192.0.2.10", 443),
        ("192.0.2.20", 443),
        ("192.0.2.30", 443),
    }


def test_china_agent_tasks_include_backup_when_current_is_best_priority():
    db = make_session()
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.flush()
    current = Origin(group_id=group.id, target="192.0.2.20", target_type="ipv4", port=443, priority=1)
    backup = Origin(group_id=group.id, target="192.0.2.30", target_type="ipv4", port=443, priority=10)
    agent = Agent(name="china", region="china", token_hash="hash", status="online", last_seen_at=datetime.utcnow())
    db.add_all([current, backup, agent])
    db.flush()
    group.current_origin_id = current.id
    db.commit()

    response = agent_tasks(request(), agent=agent, db=db)

    assert {(task.target, task.port) for task in response.tasks} == {
        ("192.0.2.20", 443),
        ("192.0.2.30", 443),
    }


def test_china_agent_tasks_include_all_enabled_origins_when_current_is_unhealthy():
    db = make_session()
    credential = CloudflareCredential(name="cf", token_encrypted=encrypt_secret("token"))
    db.add(credential)
    db.flush()
    zone = Zone(credential_id=credential.id, cf_zone_id="zone-1", name="example.com")
    db.add(zone)
    db.flush()
    group = FailoverGroup(zone_id=zone.id, hostname="www.example.com")
    db.add(group)
    db.flush()
    primary = Origin(group_id=group.id, target="192.0.2.10", target_type="ipv4", port=443, priority=1)
    current = Origin(group_id=group.id, target="192.0.2.20", target_type="ipv4", port=443, priority=5, status="machine_down")
    later_backup = Origin(group_id=group.id, target="192.0.2.30", target_type="ipv4", port=443, priority=10)
    agent = Agent(name="china", region="china", token_hash="hash", status="online", last_seen_at=datetime.utcnow())
    db.add_all([primary, current, later_backup, agent])
    db.flush()
    group.current_origin_id = current.id
    db.commit()

    response = agent_tasks(request(), agent=agent, db=db)

    assert {(task.target, task.port) for task in response.tasks} == {
        ("192.0.2.10", 443),
        ("192.0.2.20", 443),
        ("192.0.2.30", 443),
    }


def test_agent_tasks_skip_target_pool_items():
    db = make_session()
    china_agent = Agent(name="china", region="china", token_hash="hash", status="online", last_seen_at=datetime.utcnow())
    foreign_agent = Agent(name="foreign", region="foreign", token_hash="hash-2", status="online", last_seen_at=datetime.utcnow())
    pool_item = TargetPoolItem(target="198.51.100.10", target_type="ipv4", port=22, enabled=True)
    db.add_all([china_agent, foreign_agent, pool_item])
    db.commit()

    china_response = agent_tasks(request(), agent=china_agent, db=db)
    foreign_response = agent_tasks(request(), agent=foreign_agent, db=db)

    assert china_response.tasks == []
    assert foreign_response.tasks == []
