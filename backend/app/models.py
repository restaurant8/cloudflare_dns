from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base
from .origin_expansion import expanded_ip_priorities, healthy_ips, published_ips, resolved_ips


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


class AppSetting(Base, TimestampMixin):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)


class SavedSnippet(Base, TimestampMixin):
    __tablename__ = "saved_snippets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(160), index=True, nullable=False)
    category: Mapped[str] = mapped_column(String(40), default="command", nullable=False)
    address: Mapped[str | None] = mapped_column(String(255))
    username: Mapped[str | None] = mapped_column(String(120))
    port: Mapped[int | None] = mapped_column(Integer)
    tags: Mapped[str | None] = mapped_column(String(255))
    content: Mapped[str | None] = mapped_column(Text)
    code: Mapped[str | None] = mapped_column(Text)


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


class FailoverCollection(Base, TimestampMixin):
    __tablename__ = "failover_collections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True, nullable=False)

    groups: Mapped[list["FailoverGroup"]] = relationship("FailoverGroup", back_populates="collection")
    global_origins: Mapped[list["FailoverGlobalOrigin"]] = relationship(
        "FailoverGlobalOrigin",
        back_populates="collection",
        cascade="all, delete-orphan",
    )


class FailoverGroup(Base, TimestampMixin):
    __tablename__ = "failover_groups"
    __table_args__ = (UniqueConstraint("zone_id", "hostname", name="uq_failover_group_zone_hostname"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    zone_id: Mapped[int] = mapped_column(ForeignKey("zones.id", ondelete="CASCADE"), nullable=False)
    collection_id: Mapped[int | None] = mapped_column(ForeignKey("failover_collections.id", ondelete="SET NULL"))
    hostname: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    ttl: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    min_switch_interval_seconds: Mapped[int] = mapped_column(Integer, default=120, nullable=False)
    current_origin_id: Mapped[int | None] = mapped_column(Integer)
    current_record_id: Mapped[str | None] = mapped_column(Text)
    last_switch_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
    no_healthy_notified_at: Mapped[datetime | None] = mapped_column(DateTime)

    zone: Mapped["Zone"] = relationship("Zone", back_populates="groups")
    collection: Mapped["FailoverCollection | None"] = relationship("FailoverCollection", back_populates="groups")
    origins: Mapped[list["Origin"]] = relationship("Origin", back_populates="group", cascade="all, delete-orphan")
    hostnames: Mapped[list["FailoverHostname"]] = relationship("FailoverHostname", back_populates="group", cascade="all, delete-orphan")


class FailoverHostname(Base, TimestampMixin):
    __tablename__ = "failover_hostnames"
    __table_args__ = (UniqueConstraint("group_id", "hostname", name="uq_failover_hostname_group_hostname"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("failover_groups.id", ondelete="CASCADE"), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    current_record_id: Mapped[str | None] = mapped_column(Text)

    group: Mapped["FailoverGroup"] = relationship("FailoverGroup", back_populates="hostnames")


class Origin(Base, TimestampMixin):
    __tablename__ = "origins"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("failover_groups.id", ondelete="CASCADE"), nullable=False)
    global_origin_id: Mapped[int | None] = mapped_column(ForeignKey("failover_global_origins.id", ondelete="SET NULL"))
    preferred_agent_id: Mapped[int | None] = mapped_column(ForeignKey("agents.id", ondelete="SET NULL"))
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str] = mapped_column(String(20), nullable=False)
    publish_mode: Mapped[str] = mapped_column(String(20), default="direct", nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    weight: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    remark: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_rtt_ms: Mapped[float | None] = mapped_column(Float)
    resolved_ips_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    healthy_ips_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    published_ips_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    expanded_ip_priorities_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)

    group: Mapped["FailoverGroup"] = relationship("FailoverGroup", back_populates="origins")
    global_origin: Mapped["FailoverGlobalOrigin | None"] = relationship("FailoverGlobalOrigin", back_populates="mirrored_origins")
    preferred_agent: Mapped["Agent | None"] = relationship("Agent", foreign_keys=[preferred_agent_id])
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

    @property
    def expanded_ip_priorities(self) -> dict[str, int]:
        return expanded_ip_priorities(self)


class FailoverGlobalOrigin(Base, TimestampMixin):
    __tablename__ = "failover_global_origins"
    __table_args__ = (UniqueConstraint("collection_id", "target", "port", name="uq_failover_global_origin_target_port"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    collection_id: Mapped[int] = mapped_column(ForeignKey("failover_collections.id", ondelete="CASCADE"), nullable=False)
    preferred_agent_id: Mapped[int | None] = mapped_column(ForeignKey("agents.id", ondelete="SET NULL"))
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str] = mapped_column(String(20), nullable=False)
    publish_mode: Mapped[str] = mapped_column(String(20), default="direct", nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    remark: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expanded_ip_priorities_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)

    @property
    def expanded_ip_priorities(self) -> dict[str, int]:
        return expanded_ip_priorities(self)

    collection: Mapped["FailoverCollection"] = relationship("FailoverCollection", back_populates="global_origins")
    preferred_agent: Mapped["Agent | None"] = relationship("Agent", foreign_keys=[preferred_agent_id])
    mirrored_origins: Mapped[list["Origin"]] = relationship("Origin", back_populates="global_origin")


class TargetPoolItem(Base, TimestampMixin):
    __tablename__ = "target_pool_items"
    __table_args__ = (UniqueConstraint("target", "port", name="uq_target_pool_target_port"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str] = mapped_column(String(20), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=22, nullable=False)
    remark: Mapped[str | None] = mapped_column(Text)
    check_interval_seconds: Mapped[int] = mapped_column(Integer, default=600, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_rtt_ms: Mapped[float | None] = mapped_column(Float)

    probe_states: Mapped[list["TargetPoolProbeState"]] = relationship("TargetPoolProbeState", back_populates="pool_item", cascade="all, delete-orphan")


class TargetPoolProbeState(Base, TimestampMixin):
    __tablename__ = "target_pool_probe_states"
    __table_args__ = (UniqueConstraint("item_id", "source_key", name="uq_target_pool_probe_state_item_source"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("target_pool_items.id", ondelete="CASCADE"), nullable=False)
    agent_id: Mapped[int | None] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"))
    source_key: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    success_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    fail_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_rtt_ms: Mapped[float | None] = mapped_column(Float)

    pool_item: Mapped["TargetPoolItem"] = relationship("TargetPoolItem", back_populates="probe_states")
    agent: Mapped["Agent"] = relationship("Agent")

    @property
    def agent_name(self) -> str | None:
        return self.agent.name if self.agent else None

    @property
    def agent_enabled(self) -> bool:
        return True if self.agent is None else self.agent.enabled


class AzPanelResource(Base, TimestampMixin):
    __tablename__ = "azpanel_resources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160), index=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(20), default="azure", nullable=False)
    resource_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    account_id: Mapped[str | None] = mapped_column(String(120))
    region: Mapped[str | None] = mapped_column(String(120))
    ip_version: Mapped[str] = mapped_column(String(10), default="ipv4", nullable=False)
    origin_id: Mapped[int | None] = mapped_column(ForeignKey("origins.id", ondelete="SET NULL"))
    current_ip: Mapped[str | None] = mapped_column(String(120))
    port: Mapped[int] = mapped_column(Integer, default=22, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    auto_change_on_blocked: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    auto_update_origin: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=1800, nullable=False)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_change_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
    remark: Mapped[str | None] = mapped_column(Text)

    origin: Mapped["Origin | None"] = relationship("Origin")
    xboard_nodes: Mapped[list["XboardNodeBinding"]] = relationship("XboardNodeBinding", back_populates="azpanel_resource")
    jobs: Mapped[list["IpChangeJob"]] = relationship("IpChangeJob", back_populates="azpanel_resource")


class AzPanelRemoteResource(Base, TimestampMixin):
    __tablename__ = "azpanel_remote_resources"
    __table_args__ = (
        UniqueConstraint(
            "provider",
            "account_id",
            "region",
            "resource_id",
            "ip_version",
            name="uq_azpanel_remote_resource_identity",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    resource_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    account_id: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    region: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    ip_version: Mapped[str] = mapped_column(String(10), default="ipv4", nullable=False)
    current_ip: Mapped[str | None] = mapped_column(String(120))
    status: Mapped[str | None] = mapped_column(String(40))
    remark: Mapped[str | None] = mapped_column(Text)
    port: Mapped[int] = mapped_column(Integer, default=22, nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime)
    source_json: Mapped[str | None] = mapped_column(Text)


class XboardNodeBinding(Base, TimestampMixin):
    __tablename__ = "xboard_node_bindings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160), index=True, nullable=False)
    xboard_node_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    node_type: Mapped[str | None] = mapped_column(String(40))
    host: Mapped[str | None] = mapped_column(String(255))
    port: Mapped[int | None] = mapped_column(Integer)
    origin_id: Mapped[int | None] = mapped_column(ForeignKey("origins.id", ondelete="SET NULL"))
    azpanel_resource_id: Mapped[int | None] = mapped_column(ForeignKey("azpanel_resources.id", ondelete="SET NULL"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    auto_update_after_change: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
    remark: Mapped[str | None] = mapped_column(Text)

    origin: Mapped["Origin | None"] = relationship("Origin")
    azpanel_resource: Mapped["AzPanelResource | None"] = relationship("AzPanelResource", back_populates="xboard_nodes")
    jobs: Mapped[list["IpChangeJob"]] = relationship("IpChangeJob", back_populates="xboard_node")


class IpChangeJob(Base, TimestampMixin):
    __tablename__ = "ip_change_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    trigger_type: Mapped[str] = mapped_column(String(40), default="manual", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="running", nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    provider: Mapped[str | None] = mapped_column(String(20))
    azpanel_resource_id: Mapped[int | None] = mapped_column(ForeignKey("azpanel_resources.id", ondelete="SET NULL"))
    xboard_node_id: Mapped[int | None] = mapped_column(ForeignKey("xboard_node_bindings.id", ondelete="SET NULL"))
    origin_id: Mapped[int | None] = mapped_column(ForeignKey("origins.id", ondelete="SET NULL"))
    old_ip: Mapped[str | None] = mapped_column(String(120))
    new_ip: Mapped[str | None] = mapped_column(String(120))
    request_json: Mapped[str | None] = mapped_column(Text)
    response_json: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)

    azpanel_resource: Mapped["AzPanelResource | None"] = relationship("AzPanelResource", back_populates="jobs")
    xboard_node: Mapped["XboardNodeBinding | None"] = relationship("XboardNodeBinding", back_populates="jobs")
    origin: Mapped["Origin | None"] = relationship("Origin")


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
    machine_key: Mapped[str | None] = mapped_column(String(255))
    country: Mapped[str | None] = mapped_column(String(120))
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
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
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

    @property
    def agent_enabled(self) -> bool:
        return True if self.agent is None else self.agent.enabled


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
