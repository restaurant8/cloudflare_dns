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

        if "agents" in table_names:
            existing = {column["name"] for column in inspector.get_columns("agents")}
            if "region" not in existing:
                connection.execute(text("ALTER TABLE agents ADD COLUMN region VARCHAR(20) NOT NULL DEFAULT 'china'"))

        if "failover_groups" in table_names:
            existing_columns = {column["name"]: column for column in inspector.get_columns("failover_groups")}
            current_record_id = existing_columns.get("current_record_id")
            if current_record_id is not None:
                column_type = str(current_record_id["type"]).lower()
                if dialect == "mysql" and "text" not in column_type:
                    connection.execute(text("ALTER TABLE failover_groups MODIFY current_record_id TEXT NULL"))
                elif dialect == "postgresql" and "text" not in column_type:
                    connection.execute(text("ALTER TABLE failover_groups ALTER COLUMN current_record_id TYPE TEXT"))

        if "telegram_notifications" in table_names:
            existing = {column["name"] for column in inspector.get_columns("telegram_notifications")}
            if "notify_level" not in existing:
                connection.execute(text("ALTER TABLE telegram_notifications ADD COLUMN notify_level VARCHAR(20) NOT NULL DEFAULT 'important'"))


def _origin_migration_statements(dialect: str) -> dict[str, str]:
    if dialect == "mysql":
        return {
            "publish_mode": "ALTER TABLE origins ADD COLUMN publish_mode VARCHAR(20) NOT NULL DEFAULT 'direct'",
            "resolved_ips_json": "ALTER TABLE origins ADD COLUMN resolved_ips_json TEXT NULL",
            "healthy_ips_json": "ALTER TABLE origins ADD COLUMN healthy_ips_json TEXT NULL",
            "published_ips_json": "ALTER TABLE origins ADD COLUMN published_ips_json TEXT NULL",
        }
    return {
        "publish_mode": "ALTER TABLE origins ADD COLUMN publish_mode VARCHAR(20) NOT NULL DEFAULT 'direct'",
        "resolved_ips_json": "ALTER TABLE origins ADD COLUMN resolved_ips_json TEXT NOT NULL DEFAULT '[]'",
        "healthy_ips_json": "ALTER TABLE origins ADD COLUMN healthy_ips_json TEXT NOT NULL DEFAULT '[]'",
        "published_ips_json": "ALTER TABLE origins ADD COLUMN published_ips_json TEXT NOT NULL DEFAULT '[]'",
    }


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
