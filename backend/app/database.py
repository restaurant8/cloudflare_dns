import logging
from pathlib import Path

from sqlalchemy import MetaData, create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import get_settings


logger = logging.getLogger(__name__)

settings = get_settings()

connect_args = {}
if settings.database_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    # Background notification delivery writes results from worker threads while the
    # scheduler transaction may still be open; give SQLite time to wait for the
    # write lock instead of failing immediately with "database is locked".
    connect_args["timeout"] = 30
    db_path = settings.database_url.replace("sqlite:///", "", 1)
    if db_path and db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(settings.database_url, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


def init_db() -> None:
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _migrate_existing_schema()


def _migrate_existing_schema() -> None:
    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    dialect = engine.dialect.name
    with engine.begin() as connection:
        if "origins" in table_names:
            existing = {column["name"] for column in inspector.get_columns("origins")}
            for column_name, statement in _origin_migration_statements(dialect).items():
                if column_name not in existing:
                    connection.execute(text(statement))
            if "azpanel_resource_id" not in existing and "azpanel_resources" in table_names:
                # The binding moved from azpanel_resources.origin_id onto the origin, so
                # that one resource can drive many backups. Carry existing bindings over
                # once, gated on the column having just been added so it cannot re-fire.
                # MIN(id) reproduces the pre-upgrade winner (the old code sorted resources
                # by id and acted on the first), so nothing changes hands on upgrade.
                connection.execute(
                    text(
                        """
                        UPDATE origins
                        SET azpanel_resource_id = (
                            SELECT MIN(r.id) FROM azpanel_resources r WHERE r.origin_id = origins.id
                        )
                        WHERE EXISTS (
                            SELECT 1 FROM azpanel_resources r WHERE r.origin_id = origins.id
                        )
                        """
                    )
                )

        if "failover_global_origins" in table_names:
            existing = {column["name"] for column in inspector.get_columns("failover_global_origins")}
            for column_name, statement in _global_origin_migration_statements(dialect).items():
                if column_name not in existing:
                    connection.execute(text(statement))
            # Constraint changes need their own transactions (see below), so they run
            # after this block rather than inline with the column additions.

        if "target_pool_items" in table_names:
            existing = {column["name"] for column in inspector.get_columns("target_pool_items")}
            for column_name, statement in _target_pool_migration_statements(dialect).items():
                if column_name not in existing:
                    connection.execute(text(statement))

        if "external_ip_items" in table_names:
            existing = {column["name"] for column in inspector.get_columns("external_ip_items")}
            for column_name, statement in _external_ip_item_migration_statements(dialect).items():
                if column_name not in existing:
                    connection.execute(text(statement))

        if "agents" in table_names:
            existing = {column["name"] for column in inspector.get_columns("agents")}
            if "region" not in existing:
                connection.execute(text("ALTER TABLE agents ADD COLUMN region VARCHAR(20) NOT NULL DEFAULT 'china'"))
            if "is_default" not in existing:
                connection.execute(text(_agent_default_migration_statement(dialect)))

        if "failover_groups" in table_names:
            existing_columns = {column["name"]: column for column in inspector.get_columns("failover_groups")}
            if "collection_id" not in existing_columns:
                connection.execute(text(_failover_group_collection_migration_statement(dialect)))
            if "no_healthy_notified_at" not in existing_columns:
                connection.execute(text(_failover_group_no_healthy_migration_statement(dialect)))
            for column_name, statement in _failover_group_output_migration_statements(dialect).items():
                if column_name not in existing_columns:
                    connection.execute(text(statement))
            # A short-lived development build used fixed/disabled modes. Map both
            # to the corrected semantics: leave the existing Cloudflare record
            # untouched and let DoH publish the selected real origin.
            if "cloudflare_publish_enabled" not in existing_columns and "cloudflare_publish_mode" in existing_columns:
                connection.execute(
                    text(
                        "UPDATE failover_groups SET cloudflare_publish_enabled = "
                        "CASE WHEN cloudflare_publish_mode IN ('fixed', 'disabled') THEN FALSE ELSE TRUE END"
                    )
                )
            current_record_id = existing_columns.get("current_record_id")
            if current_record_id is not None:
                column_type = str(current_record_id["type"]).lower()
                if dialect == "mysql" and "text" not in column_type:
                    connection.execute(text("ALTER TABLE failover_groups MODIFY current_record_id TEXT NULL"))
                elif dialect == "postgresql" and "text" not in column_type:
                    connection.execute(text("ALTER TABLE failover_groups ALTER COLUMN current_record_id TYPE TEXT"))
            if "failover_hostnames" in table_names:
                connection.execute(
                    text(
                        """
                        INSERT INTO failover_hostnames (group_id, hostname, current_record_id, created_at, updated_at)
                        SELECT g.id, g.hostname, g.current_record_id, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                        FROM failover_groups g
                        WHERE NOT EXISTS (
                            SELECT 1
                            FROM failover_hostnames h
                            WHERE h.group_id = g.id AND h.hostname = g.hostname
                        )
                        """
                    )
                )

        if "failover_hostnames" in table_names:
            existing = {column["name"] for column in inspector.get_columns("failover_hostnames")}
            if "zone_id" not in existing:
                connection.execute(text(_failover_hostname_zone_migration_statement(dialect)))

        if "doh_endpoints" in table_names:
            existing = {column["name"] for column in inspector.get_columns("doh_endpoints")}
            for column_name, statement in _doh_endpoint_migration_statements(dialect).items():
                if column_name not in existing:
                    connection.execute(text(statement))

        if "doh_failover_origins" in table_names:
            existing = {column["name"] for column in inspector.get_columns("doh_failover_origins")}
            for column_name, statement in _doh_failover_origin_migration_statements(dialect).items():
                if column_name not in existing:
                    connection.execute(text(statement))

        if "alibaba_httpdns_groups" in table_names:
            existing = {column["name"] for column in inspector.get_columns("alibaba_httpdns_groups")}
            for column_name, statement in _alibaba_httpdns_group_migration_statements(dialect).items():
                if column_name not in existing:
                    connection.execute(text(statement))

        if "alibaba_httpdns_origins" in table_names:
            existing = {column["name"] for column in inspector.get_columns("alibaba_httpdns_origins")}
            for column_name, statement in _alibaba_httpdns_origin_migration_statements(dialect).items():
                if column_name not in existing:
                    connection.execute(text(statement))

        if "telegram_notifications" in table_names:
            existing = {column["name"] for column in inspector.get_columns("telegram_notifications")}
            if "notify_level" not in existing:
                connection.execute(text("ALTER TABLE telegram_notifications ADD COLUMN notify_level VARCHAR(20) NOT NULL DEFAULT 'important'"))

        if "azpanel_resources" in table_names:
            existing = {column["name"] for column in inspector.get_columns("azpanel_resources")}
            if "ip_change_method" not in existing:
                connection.execute(text("ALTER TABLE azpanel_resources ADD COLUMN ip_change_method VARCHAR(20) NOT NULL DEFAULT 'eip'"))
            if "api_url" not in existing:
                connection.execute(text("ALTER TABLE azpanel_resources ADD COLUMN api_url VARCHAR(255) NULL"))
            if "api_token" not in existing:
                connection.execute(text("ALTER TABLE azpanel_resources ADD COLUMN api_token VARCHAR(500) NULL"))
            timestamp_type = "TIMESTAMP" if dialect == "postgresql" else "DATETIME"
            if "pending_change_at" not in existing:
                connection.execute(text(f"ALTER TABLE azpanel_resources ADD COLUMN pending_change_at {timestamp_type} NULL"))
            if "pending_candidate_ip" not in existing:
                connection.execute(text("ALTER TABLE azpanel_resources ADD COLUMN pending_candidate_ip VARCHAR(120) NULL"))
            if "status_sync_interval_seconds" not in existing:
                connection.execute(text("ALTER TABLE azpanel_resources ADD COLUMN status_sync_interval_seconds INTEGER NOT NULL DEFAULT 0"))
            if "last_status_sync_at" not in existing:
                connection.execute(text(f"ALTER TABLE azpanel_resources ADD COLUMN last_status_sync_at {timestamp_type} NULL"))

    if "failover_global_origins" in table_names:
        _migrate_global_origin_constraints(dialect)


def _global_origin_constraint_names() -> set[str]:
    inspector = inspect(engine)
    names = {index["name"] for index in inspector.get_indexes("failover_global_origins")}
    return names | {unique["name"] for unique in inspector.get_unique_constraints("failover_global_origins")}


def _migrate_global_origin_constraints(dialect: str) -> None:
    """Swap the target-based uniqueness for the machine-based one.

    Each step gets its own transaction: the SQLite path rebuilds the table, and a
    failure part-way through must roll back on its own without poisoning the rest
    of the migration.
    """
    if _LEGACY_GLOBAL_ORIGIN_UNIQUE in _global_origin_constraint_names():
        try:
            with engine.begin() as connection:
                _drop_legacy_global_origin_unique(connection, dialect)
        except Exception:
            # Keeping the old constraint only degrades a rare edge case (two machines
            # briefly sharing an address). A database that refuses to start is worse.
            logger.exception("could not drop the legacy global-origin unique constraint; keeping the old schema")

    if "uq_failover_global_origin_machine" not in _global_origin_constraint_names():
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE UNIQUE INDEX uq_failover_global_origin_machine "
                    "ON failover_global_origins (collection_id, external_source_id, external_machine_key, port)"
                )
            )


def _origin_migration_statements(dialect: str) -> dict[str, str]:
    if dialect == "mysql":
        return {
            "global_origin_id": "ALTER TABLE origins ADD COLUMN global_origin_id INT NULL",
            "preferred_agent_id": "ALTER TABLE origins ADD COLUMN preferred_agent_id INT NULL",
            "probe_mode": "ALTER TABLE origins ADD COLUMN probe_mode VARCHAR(20) NOT NULL DEFAULT 'default'",
            "publish_mode": "ALTER TABLE origins ADD COLUMN publish_mode VARCHAR(20) NOT NULL DEFAULT 'direct'",
            "remark": "ALTER TABLE origins ADD COLUMN remark TEXT NULL",
            "resolved_ips_json": "ALTER TABLE origins ADD COLUMN resolved_ips_json TEXT NULL",
            "healthy_ips_json": "ALTER TABLE origins ADD COLUMN healthy_ips_json TEXT NULL",
            "published_ips_json": "ALTER TABLE origins ADD COLUMN published_ips_json TEXT NULL",
            "expanded_ip_priorities_json": "ALTER TABLE origins ADD COLUMN expanded_ip_priorities_json TEXT NULL",
            "external_source_id": "ALTER TABLE origins ADD COLUMN external_source_id INT NULL",
            "external_machine_key": "ALTER TABLE origins ADD COLUMN external_machine_key VARCHAR(255) NULL",
            "azpanel_resource_id": "ALTER TABLE origins ADD COLUMN azpanel_resource_id INT NULL",
            "ignore_health_check": "ALTER TABLE origins ADD COLUMN ignore_health_check TINYINT(1) NOT NULL DEFAULT 0",
        }
    return {
        "global_origin_id": "ALTER TABLE origins ADD COLUMN global_origin_id INTEGER",
        "preferred_agent_id": "ALTER TABLE origins ADD COLUMN preferred_agent_id INTEGER",
        "probe_mode": "ALTER TABLE origins ADD COLUMN probe_mode VARCHAR(20) NOT NULL DEFAULT 'default'",
        "publish_mode": "ALTER TABLE origins ADD COLUMN publish_mode VARCHAR(20) NOT NULL DEFAULT 'direct'",
        "remark": "ALTER TABLE origins ADD COLUMN remark TEXT",
        "resolved_ips_json": "ALTER TABLE origins ADD COLUMN resolved_ips_json TEXT NOT NULL DEFAULT '[]'",
        "healthy_ips_json": "ALTER TABLE origins ADD COLUMN healthy_ips_json TEXT NOT NULL DEFAULT '[]'",
        "published_ips_json": "ALTER TABLE origins ADD COLUMN published_ips_json TEXT NOT NULL DEFAULT '[]'",
        "expanded_ip_priorities_json": "ALTER TABLE origins ADD COLUMN expanded_ip_priorities_json TEXT NOT NULL DEFAULT '{}'",
        "external_source_id": "ALTER TABLE origins ADD COLUMN external_source_id INTEGER",
        "external_machine_key": "ALTER TABLE origins ADD COLUMN external_machine_key VARCHAR(255)",
        "azpanel_resource_id": "ALTER TABLE origins ADD COLUMN azpanel_resource_id INTEGER",
        "ignore_health_check": "ALTER TABLE origins ADD COLUMN ignore_health_check BOOLEAN NOT NULL DEFAULT FALSE",
    }


def _agent_default_migration_statement(dialect: str) -> str:
    if dialect == "mysql":
        return "ALTER TABLE agents ADD COLUMN is_default TINYINT(1) NOT NULL DEFAULT 0"
    if dialect == "postgresql":
        return "ALTER TABLE agents ADD COLUMN is_default BOOLEAN NOT NULL DEFAULT FALSE"
    return "ALTER TABLE agents ADD COLUMN is_default BOOLEAN NOT NULL DEFAULT 0"


_LEGACY_GLOBAL_ORIGIN_UNIQUE = "uq_failover_global_origin_target_port"


def _drop_legacy_global_origin_unique(connection, dialect: str) -> None:
    """Drop the old (collection_id, target, port) uniqueness on global backups.

    Machine-bound backups follow their machine's current IP, so two of them may
    hold the same address for a sync cycle — most often when a provider recycles
    an IP between machines. The old constraint turns that into an IntegrityError
    mid-sync. SQLite cannot drop a table-level constraint, so it needs the usual
    create/copy/swap; the other dialects drop it in place.
    """
    from .models import FailoverGlobalOrigin

    if dialect == "mysql":
        connection.execute(text(f"ALTER TABLE failover_global_origins DROP INDEX {_LEGACY_GLOBAL_ORIGIN_UNIQUE}"))
        return
    if dialect == "postgresql":
        connection.execute(text(f"ALTER TABLE failover_global_origins DROP CONSTRAINT IF EXISTS {_LEGACY_GLOBAL_ORIGIN_UNIQUE}"))
        return

    # SQLite: rebuild the table from the current model definition. The rebuilt table
    # carries the machine constraint, so its name must be free before we start.
    connection.execute(text("DROP INDEX IF EXISTS uq_failover_global_origin_machine"))
    source_table = FailoverGlobalOrigin.__table__
    rebuild_metadata = MetaData()
    # to_metadata resolves foreign keys by table name inside the target metadata, so
    # the referenced tables have to be copied across first. Only the rebuilt table is
    # ever created — the copies exist purely to satisfy that lookup.
    for foreign_key in source_table.foreign_keys:
        referenced = foreign_key.column.table
        if referenced.name not in rebuild_metadata.tables:
            referenced.to_metadata(rebuild_metadata)
    rebuilt = source_table.to_metadata(rebuild_metadata, name="failover_global_origins_rebuild")
    rebuilt.create(bind=connection)
    columns = ", ".join(column.name for column in FailoverGlobalOrigin.__table__.columns)
    connection.execute(
        text(f"INSERT INTO failover_global_origins_rebuild ({columns}) SELECT {columns} FROM failover_global_origins")
    )
    connection.execute(text("DROP TABLE failover_global_origins"))
    connection.execute(text("ALTER TABLE failover_global_origins_rebuild RENAME TO failover_global_origins"))


def _global_origin_migration_statements(dialect: str) -> dict[str, str]:
    if dialect == "mysql":
        return {
            "preferred_agent_id": "ALTER TABLE failover_global_origins ADD COLUMN preferred_agent_id INT NULL",
            "probe_mode": "ALTER TABLE failover_global_origins ADD COLUMN probe_mode VARCHAR(20) NOT NULL DEFAULT 'default'",
            "expanded_ip_priorities_json": "ALTER TABLE failover_global_origins ADD COLUMN expanded_ip_priorities_json TEXT NULL",
            "ignore_health_check": "ALTER TABLE failover_global_origins ADD COLUMN ignore_health_check TINYINT(1) NOT NULL DEFAULT 0",
            "external_source_id": "ALTER TABLE failover_global_origins ADD COLUMN external_source_id INT NULL",
            "external_machine_key": "ALTER TABLE failover_global_origins ADD COLUMN external_machine_key VARCHAR(255) NULL",
            "azpanel_resource_id": "ALTER TABLE failover_global_origins ADD COLUMN azpanel_resource_id INT NULL",
        }
    return {
        "preferred_agent_id": "ALTER TABLE failover_global_origins ADD COLUMN preferred_agent_id INTEGER",
        "probe_mode": "ALTER TABLE failover_global_origins ADD COLUMN probe_mode VARCHAR(20) NOT NULL DEFAULT 'default'",
        "expanded_ip_priorities_json": "ALTER TABLE failover_global_origins ADD COLUMN expanded_ip_priorities_json TEXT NOT NULL DEFAULT '{}'",
        "ignore_health_check": "ALTER TABLE failover_global_origins ADD COLUMN ignore_health_check BOOLEAN NOT NULL DEFAULT FALSE",
        "external_source_id": "ALTER TABLE failover_global_origins ADD COLUMN external_source_id INTEGER",
        "external_machine_key": "ALTER TABLE failover_global_origins ADD COLUMN external_machine_key VARCHAR(255)",
        "azpanel_resource_id": "ALTER TABLE failover_global_origins ADD COLUMN azpanel_resource_id INTEGER",
    }


def _target_pool_migration_statements(dialect: str) -> dict[str, str]:
    if dialect == "mysql":
        return {
            "check_interval_seconds": "ALTER TABLE target_pool_items ADD COLUMN check_interval_seconds INT NOT NULL DEFAULT 600",
            "status": "ALTER TABLE target_pool_items ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'unknown'",
            "last_checked_at": "ALTER TABLE target_pool_items ADD COLUMN last_checked_at DATETIME NULL",
            "last_error": "ALTER TABLE target_pool_items ADD COLUMN last_error TEXT NULL",
            "last_rtt_ms": "ALTER TABLE target_pool_items ADD COLUMN last_rtt_ms FLOAT NULL",
        }
    if dialect == "postgresql":
        return {
            "check_interval_seconds": "ALTER TABLE target_pool_items ADD COLUMN check_interval_seconds INTEGER NOT NULL DEFAULT 600",
            "status": "ALTER TABLE target_pool_items ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'unknown'",
            "last_checked_at": "ALTER TABLE target_pool_items ADD COLUMN last_checked_at TIMESTAMP NULL",
            "last_error": "ALTER TABLE target_pool_items ADD COLUMN last_error TEXT NULL",
            "last_rtt_ms": "ALTER TABLE target_pool_items ADD COLUMN last_rtt_ms FLOAT NULL",
        }
    return {
        "check_interval_seconds": "ALTER TABLE target_pool_items ADD COLUMN check_interval_seconds INTEGER NOT NULL DEFAULT 600",
        "status": "ALTER TABLE target_pool_items ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'unknown'",
        "last_checked_at": "ALTER TABLE target_pool_items ADD COLUMN last_checked_at DATETIME",
        "last_error": "ALTER TABLE target_pool_items ADD COLUMN last_error TEXT",
        "last_rtt_ms": "ALTER TABLE target_pool_items ADD COLUMN last_rtt_ms FLOAT",
    }


def _external_ip_item_migration_statements(dialect: str) -> dict[str, str]:
    if dialect == "mysql":
        return {
            "machine_key": "ALTER TABLE external_ip_items ADD COLUMN machine_key VARCHAR(255) NULL",
            "country": "ALTER TABLE external_ip_items ADD COLUMN country VARCHAR(120) NULL",
        }
    return {
        "machine_key": "ALTER TABLE external_ip_items ADD COLUMN machine_key VARCHAR(255)",
        "country": "ALTER TABLE external_ip_items ADD COLUMN country VARCHAR(120)",
    }


def _failover_group_no_healthy_migration_statement(dialect: str) -> str:
    if dialect == "postgresql":
        return "ALTER TABLE failover_groups ADD COLUMN no_healthy_notified_at TIMESTAMP NULL"
    return "ALTER TABLE failover_groups ADD COLUMN no_healthy_notified_at DATETIME NULL"


def _failover_hostname_zone_migration_statement(dialect: str) -> str:
    if dialect == "mysql":
        return "ALTER TABLE failover_hostnames ADD COLUMN zone_id INT NULL"
    return "ALTER TABLE failover_hostnames ADD COLUMN zone_id INTEGER"


def _failover_group_collection_migration_statement(dialect: str) -> str:
    if dialect == "mysql":
        return "ALTER TABLE failover_groups ADD COLUMN collection_id INT NULL"
    return "ALTER TABLE failover_groups ADD COLUMN collection_id INTEGER"


def _failover_group_output_migration_statements(dialect: str) -> dict[str, str]:
    if dialect == "mysql":
        return {
            "cloudflare_publish_enabled": "ALTER TABLE failover_groups ADD COLUMN cloudflare_publish_enabled TINYINT(1) NOT NULL DEFAULT 1",
            "doh_enabled": "ALTER TABLE failover_groups ADD COLUMN doh_enabled TINYINT(1) NOT NULL DEFAULT 0",
            "doh_endpoint_id": "ALTER TABLE failover_groups ADD COLUMN doh_endpoint_id INT NULL",
            "doh_hostnames_json": "ALTER TABLE failover_groups ADD COLUMN doh_hostnames_json TEXT NULL",
        }
    return {
        "cloudflare_publish_enabled": "ALTER TABLE failover_groups ADD COLUMN cloudflare_publish_enabled BOOLEAN NOT NULL DEFAULT TRUE",
        "doh_enabled": "ALTER TABLE failover_groups ADD COLUMN doh_enabled BOOLEAN NOT NULL DEFAULT FALSE",
        "doh_endpoint_id": "ALTER TABLE failover_groups ADD COLUMN doh_endpoint_id INTEGER",
        "doh_hostnames_json": "ALTER TABLE failover_groups ADD COLUMN doh_hostnames_json TEXT NOT NULL DEFAULT '[]'",
    }


def _doh_endpoint_migration_statements(dialect: str) -> dict[str, str]:
    timestamp_type = "TIMESTAMP" if dialect == "postgresql" else "DATETIME"
    return {
        "sync_failure_count": "ALTER TABLE doh_endpoints ADD COLUMN sync_failure_count INTEGER NOT NULL DEFAULT 0",
        "next_sync_retry_at": f"ALTER TABLE doh_endpoints ADD COLUMN next_sync_retry_at {timestamp_type} NULL",
    }


def _doh_failover_origin_migration_statements(dialect: str) -> dict[str, str]:
    if dialect == "mysql":
        return {
            "resolved_ips_json": "ALTER TABLE doh_failover_origins ADD COLUMN resolved_ips_json TEXT NULL",
            "healthy_ips_json": "ALTER TABLE doh_failover_origins ADD COLUMN healthy_ips_json TEXT NULL",
            "published_ips_json": "ALTER TABLE doh_failover_origins ADD COLUMN published_ips_json TEXT NULL",
            "ip_probe_states_json": "ALTER TABLE doh_failover_origins ADD COLUMN ip_probe_states_json TEXT NULL",
        }
    return {
        "resolved_ips_json": "ALTER TABLE doh_failover_origins ADD COLUMN resolved_ips_json TEXT NOT NULL DEFAULT '[]'",
        "healthy_ips_json": "ALTER TABLE doh_failover_origins ADD COLUMN healthy_ips_json TEXT NOT NULL DEFAULT '[]'",
        "published_ips_json": "ALTER TABLE doh_failover_origins ADD COLUMN published_ips_json TEXT NOT NULL DEFAULT '[]'",
        "ip_probe_states_json": "ALTER TABLE doh_failover_origins ADD COLUMN ip_probe_states_json TEXT NOT NULL DEFAULT '{}'",
    }


def _alibaba_httpdns_group_migration_statements(dialect: str) -> dict[str, str]:
    return {
        "last_published_value": "ALTER TABLE alibaba_httpdns_groups ADD COLUMN last_published_value VARCHAR(255) NULL",
    }


def _alibaba_httpdns_origin_migration_statements(dialect: str) -> dict[str, str]:
    if dialect == "mysql":
        return {
            "resolved_ips_json": "ALTER TABLE alibaba_httpdns_origins ADD COLUMN resolved_ips_json TEXT NULL",
            "healthy_ips_json": "ALTER TABLE alibaba_httpdns_origins ADD COLUMN healthy_ips_json TEXT NULL",
            "published_ips_json": "ALTER TABLE alibaba_httpdns_origins ADD COLUMN published_ips_json TEXT NULL",
            "ip_probe_states_json": "ALTER TABLE alibaba_httpdns_origins ADD COLUMN ip_probe_states_json TEXT NULL",
        }
    return {
        "resolved_ips_json": "ALTER TABLE alibaba_httpdns_origins ADD COLUMN resolved_ips_json TEXT NOT NULL DEFAULT '[]'",
        "healthy_ips_json": "ALTER TABLE alibaba_httpdns_origins ADD COLUMN healthy_ips_json TEXT NOT NULL DEFAULT '[]'",
        "published_ips_json": "ALTER TABLE alibaba_httpdns_origins ADD COLUMN published_ips_json TEXT NOT NULL DEFAULT '[]'",
        "ip_probe_states_json": "ALTER TABLE alibaba_httpdns_origins ADD COLUMN ip_probe_states_json TEXT NOT NULL DEFAULT '{}'",
    }


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
