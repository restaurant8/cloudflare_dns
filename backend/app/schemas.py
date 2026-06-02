from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class SetupStatus(BaseModel):
    setup_required: bool


class BootstrapRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=8, max_length=200)


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=8, max_length=200)


class CloudflareCredentialCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    token: str = Field(min_length=10)


class CloudflareCredentialOut(BaseModel):
    id: int
    name: str
    status: str
    last_error: str | None
    synced_at: datetime | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ZoneOut(BaseModel):
    id: int
    credential_id: int
    cf_zone_id: str
    name: str
    account_id: str | None
    account_name: str | None
    status: str | None
    synced_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class DnsRecordOut(BaseModel):
    id: int
    zone_id: int
    cf_record_id: str
    name: str
    type: str
    content: str
    ttl: int
    proxied: bool
    synced_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class FailoverGroupCreate(BaseModel):
    zone_id: int
    hostname: str = Field(min_length=1, max_length=255)
    ttl: int = Field(default=60, ge=30, le=86400)
    primary_port: int = Field(default=22, ge=1, le=65535)
    enabled: bool = True
    min_switch_interval_seconds: int = Field(default=120, ge=0, le=86400)
    adopt_record_id: str | None = None


class FailoverGroupUpdate(BaseModel):
    ttl: int | None = Field(default=None, ge=30, le=86400)
    enabled: bool | None = None
    min_switch_interval_seconds: int | None = Field(default=None, ge=0, le=86400)


class OriginCreate(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    priority: int = Field(default=10, ge=0, le=100000)
    publish_mode: Literal["direct", "expanded"] = "direct"
    remark: str | None = Field(default=None, max_length=500)
    enabled: bool = True


class OriginBulkCreate(BaseModel):
    origins: list[OriginCreate] = Field(min_length=1, max_length=100)


class OriginUpdate(BaseModel):
    target: str | None = Field(default=None, min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    priority: int | None = Field(default=None, ge=0, le=100000)
    publish_mode: Literal["direct", "expanded"] | None = None
    remark: str | None = Field(default=None, max_length=500)
    enabled: bool | None = None


class ProbeStateOut(BaseModel):
    id: int
    source_key: str
    agent_name: str | None = None
    agent_enabled: bool = True
    status: str
    success_count: int
    fail_count: int
    last_checked_at: datetime | None
    last_error: str | None
    last_rtt_ms: float | None

    model_config = ConfigDict(from_attributes=True)


def _enabled_probe_states(probe_states: list[ProbeStateOut]) -> list[ProbeStateOut]:
    return [state for state in probe_states if state.agent_enabled]


class OriginOut(BaseModel):
    id: int
    group_id: int
    target: str
    target_type: str
    publish_mode: str
    port: int
    priority: int
    remark: str | None
    enabled: bool
    status: str
    last_checked_at: datetime | None
    last_error: str | None
    last_rtt_ms: float | None
    resolved_ips: list[str] = []
    healthy_ips: list[str] = []
    published_ips: list[str] = []
    probe_states: list[ProbeStateOut] = []

    model_config = ConfigDict(from_attributes=True)

    @model_validator(mode="after")
    def hide_disabled_agent_probe_states(self):
        self.probe_states = _enabled_probe_states(self.probe_states)
        return self


class TargetPoolCreate(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    remark: str | None = Field(default=None, max_length=500)
    check_interval_seconds: int = Field(default=600, ge=60, le=86400)
    enabled: bool = True


class TargetPoolUpdate(BaseModel):
    target: str | None = Field(default=None, min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    remark: str | None = Field(default=None, max_length=500)
    check_interval_seconds: int | None = Field(default=None, ge=60, le=86400)
    enabled: bool | None = None


class TargetPoolBulkCreate(BaseModel):
    items: list[TargetPoolCreate] = Field(min_length=1, max_length=500)


class TargetPoolBulkItemResult(BaseModel):
    target: str
    port: int
    status: str
    message: str | None = None
    id: int | None = None


class TargetPoolBulkOut(BaseModel):
    created: int
    skipped: int
    failed: int
    results: list[TargetPoolBulkItemResult]


class TargetPoolOut(BaseModel):
    id: int
    target: str
    target_type: str
    port: int
    remark: str | None
    check_interval_seconds: int
    enabled: bool
    status: str
    last_checked_at: datetime | None
    last_error: str | None
    last_rtt_ms: float | None
    probe_states: list[ProbeStateOut] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @model_validator(mode="after")
    def hide_disabled_agent_probe_states(self):
        self.probe_states = _enabled_probe_states(self.probe_states)
        return self


class ExternalIpSourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    base_url: HttpUrl
    token: str = Field(min_length=1, max_length=500)
    default_port: int = Field(default=22, ge=1, le=65535)
    sync_interval_seconds: int = Field(default=600, ge=60, le=86400)
    enabled: bool = True


class ExternalIpSourceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    base_url: HttpUrl | None = None
    token: str | None = Field(default=None, min_length=1, max_length=500)
    default_port: int | None = Field(default=None, ge=1, le=65535)
    sync_interval_seconds: int | None = Field(default=None, ge=60, le=86400)
    enabled: bool | None = None


class ExternalIpItemOut(BaseModel):
    id: int
    source_id: int
    name: str
    group_name: str | None
    machine_key: str | None
    country: str | None
    target: str
    target_type: str
    port: int
    status: str
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ExternalIpSourceOut(BaseModel):
    id: int
    name: str
    source_type: str
    base_url: str
    default_port: int
    sync_interval_seconds: int
    enabled: bool
    status: str
    last_synced_at: datetime | None
    last_error: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FailoverGroupOut(BaseModel):
    id: int
    zone_id: int
    hostname: str
    ttl: int
    enabled: bool
    min_switch_interval_seconds: int
    current_origin_id: int | None
    current_record_id: str | None
    last_switch_at: datetime | None
    last_error: str | None
    origins: list[OriginOut] = []

    model_config = ConfigDict(from_attributes=True)


class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    region: Literal["china", "foreign"] = "china"


class AgentUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class AgentOut(BaseModel):
    id: int
    name: str
    region: str
    enabled: bool
    status: str
    last_seen_at: datetime | None
    last_ip: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AgentCreated(BaseModel):
    agent: AgentOut
    token: str


class AgentTask(BaseModel):
    origin_id: int
    target: str
    port: int
    timeout_seconds: float


class AgentTasksResponse(BaseModel):
    interval_seconds: int
    tasks: list[AgentTask]


class AgentResultIn(BaseModel):
    origin_id: int
    target: str
    port: int
    success: bool
    rtt_ms: float | None = None
    error: str | None = None


class AgentResultsIn(BaseModel):
    results: list[AgentResultIn]


class WebhookCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    url: HttpUrl
    secret: str | None = None
    enabled: bool = True


class WebhookUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    url: HttpUrl | None = None
    secret: str | None = None
    enabled: bool | None = None


class WebhookOut(BaseModel):
    id: int
    name: str
    url: str
    enabled: bool
    last_sent_at: datetime | None
    last_error: str | None

    model_config = ConfigDict(from_attributes=True)


class TelegramNotificationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    bot_token: str = Field(min_length=20, max_length=200)
    chat_id: str = Field(min_length=1, max_length=120)
    notify_level: Literal["important", "critical", "all"] = "important"
    enabled: bool = True


class TelegramNotificationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    bot_token: str | None = Field(default=None, min_length=20, max_length=200)
    chat_id: str | None = Field(default=None, min_length=1, max_length=120)
    notify_level: Literal["important", "critical", "all"] | None = None
    enabled: bool | None = None


class TelegramNotificationOut(BaseModel):
    id: int
    name: str
    chat_id: str
    notify_level: str
    enabled: bool
    last_sent_at: datetime | None
    last_error: str | None

    model_config = ConfigDict(from_attributes=True)


class EventOut(BaseModel):
    id: int
    type: str
    severity: str
    message: str
    payload_json: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Overview(BaseModel):
    credentials: int
    zones: int
    groups: int
    enabled_groups: int
    origins: int
    unhealthy_origins: int
    agents: int
    recent_events: list[EventOut]


class Message(BaseModel):
    message: str
    detail: Any | None = None
