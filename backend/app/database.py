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
    if settings.database_url.startswith("sqlite"):
        _migrate_sqlite()


def _migrate_sqlite() -> None:
    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    with engine.begin() as connection:
        if "origins" in table_names:
            existing = {column["name"] for column in inspector.get_columns("origins")}
            statements = {
                "publish_mode": "ALTER TABLE origins ADD COLUMN publish_mode VARCHAR(20) NOT NULL DEFAULT 'direct'",
                "resolved_ips_json": "ALTER TABLE origins ADD COLUMN resolved_ips_json TEXT NOT NULL DEFAULT '[]'",
                "healthy_ips_json": "ALTER TABLE origins ADD COLUMN healthy_ips_json TEXT NOT NULL DEFAULT '[]'",
                "published_ips_json": "ALTER TABLE origins ADD COLUMN published_ips_json TEXT NOT NULL DEFAULT '[]'",
            }
            for column_name, statement in statements.items():
                if column_name not in existing:
                    connection.execute(text(statement))

        if "agents" in table_names:
            existing = {column["name"] for column in inspector.get_columns("agents")}
            if "region" not in existing:
                connection.execute(text("ALTER TABLE agents ADD COLUMN region VARCHAR(20) NOT NULL DEFAULT 'china'"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
