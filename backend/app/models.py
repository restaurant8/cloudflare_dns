from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base
from .origin_expansion import healthy_ips, published_ips, resolved_ips


def utcnow() -> datetime:
    return datetime.utcnow()


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)


class CloudflareCredential(Base, TimestampMixin):
    __tablename__ = "cloudflare_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    token_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="unknown", nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text)
    synced_at: Mapped[datetime | None] = mapped_column(DateTime)

    zones: Mapped[list["Zone"]] = relationship("Zone", back_populates="credential", cascade="all, delete-orphan")


class Zone(Base, TimestampMixin):
    __tablename__ = "zones"
    __table_args__ = (UniqueConstraint("credential_id", "cf_zone_id", name="uq_zone_credential_cf_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    credential_id: Mapped[int] = mapped_column(ForeignKey("cloudflare_credentials.id", ondelete="CASCADE"), nullable=False)
    cf_zone_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    account_id: Mapped[str | None] = mapped_column(String(64))
    account_name: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str | None] = mapped_column(String(80))
    synced_at: Mapped[datetime | None] = mapped_column(DateTime)

    credential: Mapped["CloudflareCredential"] = relationship("CloudflareCredential", back_populates="zones")
    records: Mapped[list["DnsRecord"]] = relationship("DnsRecord", back_populates="zone", cascade="all, delete-orphan")
    groups: Mapped[list["FailoverGroup"]] = relationship("FailoverGroup", back_populates="zone", cascade="all, delete-orphan")


class DnsRecord(Base, TimestampMixin):
    __tablename__ = "dns_records"
    __table_args__ = (UniqueConstraint("zone_id", "cf_record_id", name="uq_dns_record_zone_cf_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    zone_id: Mapped[int] = mapped_column(ForeignKey("zones.id", ondelete="CASCADE"), nullable=False)
    cf_record_id: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    ttl: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    proxied: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    synced_at: Mapped[datetime | None] = mapped_column(DateTime)

    zone: Mapped["Zone"] = relationship("Zone", back_populates="records")


class FailoverGroup(Base, TimestampMixin):
    __tablename__ = "failover_groups"
    __table_args__ = (UniqueConstraint("zone_id", "hostname", name="uq_failover_group_zone_hostname"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    zone_id: Mapped[int] = mapped_column(ForeignKey("zones.id", ondelete="CASCADE"), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    ttl: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    min_switch_interval_seconds: Mapped[int] = mapped_column(Integer, default=120, nullable=False)
    current_origin_id: Mapped[int | None] = mapped_column(Integer)
    current_record_id: Mapped[str | None] = mapped_column(Text)
    last_switch_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(Text)

    zone: Mapped["Zone"] = relationship("Zone", back_populates="groups")
    origins: Mapped[list["Origin"]] = relationship("Origin", back_populates="group", cascade="all, delete-orphan")


class Origin(Base, TimestampMixin):
    __tablename__ = "origins"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("failover_groups.id", ondelete="CASCADE"), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str] = mapped_column(String(20), nullable=False)
    publish_mode: Mapped[str] = mapped_column(String(20), default="direct", nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    weight: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_rtt_ms: Mapped[float | None] = mapped_column(Float)
    resolved_ips_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    healthy_ips_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    published_ips_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)

    group: Mapped["FailoverGroup"] = relationship("FailoverGroup", back_populates="origins")
    probe_states: Mapped[list["ProbeState"]] = relationship("ProbeState", back_populates="origin", cascade="all, delete-orphan")

    @property
    def resolved_ips(self) -> list[str]:
        return resolved_ips(self)

    @property
    def healthy_ips(self) -> list[str]:
        return healthy_ips(self)

    @property
    def published_ips(self) -> list[str]:
        return published_ips(self)


class TargetPoolItem(Base, TimestampMixin):
    __tablename__ = "target_pool_items"
    __table_args__ = (UniqueConstraint("target", "port", name="uq_target_pool_target_port"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str] = mapped_column(String(20), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=22, nullable=False)
    remark: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class ExternalIpSource(Base, TimestampMixin):
    __tablename__ = "external_ip_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    source_type: Mapped[str] = mapped_column(String(40), default="nyanpass", nullable=False)
    base_url: Mapped[str] = mapped_column(Text, nullable=False)
    token_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    default_port: Mapped[int] = mapped_column(Integer, default=22, nullable=False)
    sync_interval_seconds: Mapped[int] = mapped_column(Integer, default=600, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="unknown", nullable=False)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(Text)

    items: Mapped[list["ExternalIpItem"]] = relationship("ExternalIpItem", back_populates="source", cascade="all, delete-orphan")


class ExternalIpItem(Base, TimestampMixin):
    __tablename__ = "external_ip_items"
    __table_args__ = (UniqueConstraint("source_id", "target", "port", name="uq_external_ip_item_source_target_port"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("external_ip_sources.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    group_name: Mapped[str | None] = mapped_column(String(255))
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str] = mapped_column(String(20), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=22, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="healthy", nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime)

    source: Mapped["ExternalIpSource"] = relationship("ExternalIpSource", back_populates="items")


class Agent(Base, TimestampMixin):
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    region: Mapped[str] = mapped_column(String(20), default="china", nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_ip: Mapped[str | None] = mapped_column(String(80))

    probe_states: Mapped[list["ProbeState"]] = relationship("ProbeState", back_populates="agent", cascade="all, delete-orphan")


class ProbeState(Base, TimestampMixin):
    __tablename__ = "probe_states"
    __table_args__ = (UniqueConstraint("origin_id", "source_key", name="uq_probe_state_origin_source"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    origin_id: Mapped[int] = mapped_column(ForeignKey("origins.id", ondelete="CASCADE"), nullable=False)
    agent_id: Mapped[int | None] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    source_key: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    success_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    fail_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_rtt_ms: Mapped[float | None] = mapped_column(Float)

    origin: Mapped["Origin"] = relationship("Origin", back_populates="probe_states")
    agent: Mapped["Agent"] = relationship("Agent", back_populates="probe_states")

    @property
    def agent_name(self) -> str | None:
        return self.agent.name if self.agent else None


class ProbeResult(Base, TimestampMixin):
    __tablename__ = "probe_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    origin_id: Mapped[int] = mapped_column(ForeignKey("origins.id", ondelete="CASCADE"), nullable=False)
    agent_id: Mapped[int | None] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    rtt_ms: Mapped[float | None] = mapped_column(Float)
    error: Mapped[str | None] = mapped_column(Text)


class Event(Base, TimestampMixin):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="info", nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    payload_json: Mapped[str | None] = mapped_column(Text)


class Webhook(Base, TimestampMixin):
    __tablename__ = "webhooks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    secret: Mapped[str | None] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(Text)


class TelegramNotification(Base, TimestampMixin):
    __tablename__ = "telegram_notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    bot_token_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    chat_id: Mapped[str] = mapped_column(String(120), nullable=False)
    notify_level: Mapped[str] = mapped_column(String(20), default="important", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
