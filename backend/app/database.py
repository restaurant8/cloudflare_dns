from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import get_settings


settings = get_settings()

connect_args = {}
if settings.database_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False
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

        if "failover_groups" in table_names:
            existing_columns = {column["name"]: column for column in inspector.get_columns("failover_groups")}
            if "no_healthy_notified_at" not in existing_columns:
                connection.execute(text(_failover_group_no_healthy_migration_statement(dialect)))
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

        if "telegram_notifications" in table_names:
            existing = {column["name"] for column in inspector.get_columns("telegram_notifications")}
            if "notify_level" not in existing:
                connection.execute(text("ALTER TABLE telegram_notifications ADD COLUMN notify_level VARCHAR(20) NOT NULL DEFAULT 'important'"))


def _origin_migration_statements(dialect: str) -> dict[str, str]:
    if dialect == "mysql":
        return {
            "publish_mode": "ALTER TABLE origins ADD COLUMN publish_mode VARCHAR(20) NOT NULL DEFAULT 'direct'",
            "remark": "ALTER TABLE origins ADD COLUMN remark TEXT NULL",
            "resolved_ips_json": "ALTER TABLE origins ADD COLUMN resolved_ips_json TEXT NULL",
            "healthy_ips_json": "ALTER TABLE origins ADD COLUMN healthy_ips_json TEXT NULL",
            "published_ips_json": "ALTER TABLE origins ADD COLUMN published_ips_json TEXT NULL",
        }
    return {
        "publish_mode": "ALTER TABLE origins ADD COLUMN publish_mode VARCHAR(20) NOT NULL DEFAULT 'direct'",
        "remark": "ALTER TABLE origins ADD COLUMN remark TEXT",
        "resolved_ips_json": "ALTER TABLE origins ADD COLUMN resolved_ips_json TEXT NOT NULL DEFAULT '[]'",
        "healthy_ips_json": "ALTER TABLE origins ADD COLUMN healthy_ips_json TEXT NOT NULL DEFAULT '[]'",
        "published_ips_json": "ALTER TABLE origins ADD COLUMN published_ips_json TEXT NOT NULL DEFAULT '[]'",
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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
