from sqlalchemy import Column, Integer, MetaData, Table, create_engine, inspect, text
from sqlalchemy.orm import Session

from app import database
from app.models import FailoverGroup


def test_provider_columns_are_additive_for_existing_installations():
    assert "provider_type" in database._failover_group_output_migration_statements("sqlite")
    assert "provider_type" in database._doh_endpoint_migration_statements("sqlite")
    assert "credential_id" in database._alibaba_httpdns_group_migration_statements("sqlite")
    assert "source_current_origin_id" in database._alibaba_httpdns_group_migration_statements("sqlite")


def test_alibaba_shared_output_migration_splits_origin_id_spaces(monkeypatch):
    migration_engine = create_engine("sqlite:///:memory:", future=True)
    with migration_engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE alibaba_httpdns_groups ("
                "id INTEGER PRIMARY KEY, source_group_id INTEGER NULL, "
                "current_origin_id INTEGER NULL)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO alibaba_httpdns_groups "
                "(id, source_group_id, current_origin_id) VALUES "
                "(1, 10, 77), (2, NULL, 88)"
            )
        )

    monkeypatch.setattr(database, "engine", migration_engine)
    database._migrate_existing_schema()

    with migration_engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT id, current_origin_id, source_current_origin_id "
                "FROM alibaba_httpdns_groups ORDER BY id"
            )
        ).all()
    assert rows == [(1, None, 77), (2, 88, None)]

    # Backfill is intentionally one-shot. A group linked after the upgrade can
    # retain its legacy candidate id while waiting for its first shared publish.
    with migration_engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE alibaba_httpdns_groups SET current_origin_id = 99, "
                "source_current_origin_id = NULL WHERE id = 1"
            )
        )
    database._migrate_existing_schema()
    with migration_engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT current_origin_id, source_current_origin_id "
                "FROM alibaba_httpdns_groups WHERE id = 1"
            )
        ).one()
    assert row == (99, None)


def test_sqlite_failover_group_rebuild_preserves_rows_and_allows_provider_only_group(
    monkeypatch,
):
    migration_engine = create_engine("sqlite:///:memory:", future=True)
    with migration_engine.begin() as connection:
        connection.execute(text("CREATE TABLE zones (id INTEGER PRIMARY KEY)"))
        connection.execute(text("CREATE TABLE failover_collections (id INTEGER PRIMARY KEY)"))
        connection.execute(text("CREATE TABLE doh_endpoints (id INTEGER PRIMARY KEY)"))
        connection.execute(text("INSERT INTO zones (id) VALUES (1)"))

    source = FailoverGroup.__table__
    legacy_metadata = MetaData()
    for foreign_key in source.foreign_keys:
        referenced = foreign_key.column.table
        if referenced.name not in legacy_metadata.tables:
            # Only the referenced table name/primary key is needed for DDL
            # resolution; the real minimal tables already exist above.
            Table(referenced.name, legacy_metadata, Column("id", Integer, primary_key=True))
    legacy = source.to_metadata(legacy_metadata)
    legacy.c.zone_id.nullable = False
    legacy.create(bind=migration_engine)

    with migration_engine.begin() as connection:
        connection.execute(
            legacy.insert().values(
                id=1,
                zone_id=1,
                hostname="existing.example.com",
                cloudflare_publish_enabled=True,
            )
        )
        connection.execute(
            text(
                "CREATE TABLE origin_probe ("
                "id INTEGER PRIMARY KEY, "
                "group_id INTEGER NOT NULL REFERENCES failover_groups(id)"
                ")"
            )
        )
        connection.execute(text("INSERT INTO origin_probe (id, group_id) VALUES (1, 1)"))

    monkeypatch.setattr(database, "engine", migration_engine)
    database._rebuild_sqlite_failover_groups_with_nullable_zone()

    columns = {column["name"]: column for column in inspect(migration_engine).get_columns("failover_groups")}
    assert columns["zone_id"]["nullable"] is True
    assert inspect(migration_engine).get_foreign_keys("origin_probe")[0]["referred_table"] == "failover_groups"

    with Session(migration_engine) as session:
        assert session.get(FailoverGroup, 1).hostname == "existing.example.com"
        session.add(
            FailoverGroup(
                zone_id=None,
                hostname="private.example.net",
                cloudflare_publish_enabled=False,
            )
        )
        session.commit()
        assert session.query(FailoverGroup).filter(FailoverGroup.zone_id.is_(None)).count() == 1
