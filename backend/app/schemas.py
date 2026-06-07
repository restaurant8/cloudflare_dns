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
    remember_me: bool = False


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=8, max_length=200)


class SystemSettingsOut(BaseModel):
    check_interval_seconds: int
    check_timeout_seconds: float
    fail_threshold: int
    recovery_threshold: int
    no_healthy_notification_interval_seconds: int
    external_ip_sync_interval_seconds: int
    access_token_ttl_seconds: int
    access_token_remember_ttl_seconds: int
    login_max_failures: int
    login_failure_window_seconds: int
    login_lockout_seconds: int


class SystemSettingsUpdate(BaseModel):
    check_interval_seconds: int | None = Field(default=None, ge=10, le=3600)
    check_timeout_seconds: float | None = Field(default=None, ge=1.0, le=60.0)
    fail_threshold: int | None = Field(default=None, ge=1, le=20)
    recovery_threshold: int | None = Field(default=None, ge=1, le=20)
    no_healthy_notification_interval_seconds: int | None = Field(default=None, ge=60, le=86400)
    external_ip_sync_interval_seconds: int | None = Field(default=None, ge=60, le=86400)
    access_token_ttl_seconds: int | None = Field(default=None, ge=3600, le=31_536_000)
    access_token_remember_ttl_seconds: int | None = Field(default=None, ge=3600, le=31_536_000)
    login_max_failures: int | None = Field(default=None, ge=1, le=100)
    login_failure_window_seconds: int | None = Field(default=None, ge=60, le=86400)
    login_lockout_seconds: int | None = Field(default=None, ge=60, le=86400)


class SavedSnippetCreate(BaseModel):
    title: str = Field(min_length=1, max_length=160)
    category: Literal["ssh", "command", "address", "note"] = "command"
    address: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=120)
    port: int | None = Field(default=None, ge=1, le=65535)
    tags: str | None = Field(default=None, max_length=255)
    content: str | None = Field(default=None, max_length=10000)
    code: str | None = Field(default=None, max_length=20000)


class SavedSnippetUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=160)
    category: Literal["ssh", "command", "address", "note"] | None = None
    address: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=120)
    port: int | None = Field(default=None, ge=1, le=65535)
    tags: str | None = Field(default=None, max_length=255)
    content: str | None = Field(default=None, max_length=10000)
    code: str | None = Field(default=None, max_length=20000)


class SavedSnippetOut(BaseModel):
    id: int
    title: str
    category: str
    address: str | None
    username: str | None
    port: int | None
    tags: str | None
    content: str | None
    code: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


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


class DnsRecordCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    type: Literal["A", "AAAA", "CNAME"]
    content: str = Field(min_length=1, max_length=255)
    ttl: int = Field(ge=1, le=86400)
    proxied: bool = False


class DnsRecordUpdate(DnsRecordCreate):
    pass


class FailoverGroupCreate(BaseModel):
    zone_id: int
    collection_id: int | None = None
    hostname: str = Field(min_length=1, max_length=255)
    ttl: int = Field(default=60, ge=30, le=86400)
    primary_port: int = Field(default=22, ge=1, le=65535)
    enabled: bool = True
    min_switch_interval_seconds: int = Field(default=120, ge=0, le=86400)
    adopt_record_id: str | None = None


class FailoverGroupUpdate(BaseModel):
    collection_id: int | None = None
    ttl: int | None = Field(default=None, ge=30, le=86400)
    enabled: bool | None = None
    min_switch_interval_seconds: int | None = Field(default=None, ge=0, le=86400)


class FailoverCollectionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class FailoverCollectionUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)


class FailoverHostnameCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    adopt_record_id: str | None = None


class FailoverHostnameOut(BaseModel):
    id: int
    group_id: int
    hostname: str
    current_record_id: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


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
    global_origin_id: int | None
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


class FailoverGlobalOriginCreate(OriginCreate):
    pass


class FailoverGlobalOriginUpdate(OriginUpdate):
    pass


class FailoverGlobalOriginOut(BaseModel):
    id: int
    collection_id: int
    target: str
    target_type: str
    publish_mode: str
    port: int
    priority: int
    remark: str | None
    enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FailoverCollectionOut(BaseModel):
    id: int
    name: str
    global_origins: list[FailoverGlobalOriginOut] = []
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


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


class TargetPoolAssignToGroupsRequest(BaseModel):
    item_ids: list[int] = Field(min_length=1, max_length=500)
    all_groups: bool = False
    group_ids: list[int] = Field(default_factory=list, max_length=500)
    priority: int = Field(default=10, ge=0, le=100000)
    enabled: bool = True


class TargetPoolAssignGroupResult(BaseModel):
    group_id: int
    group_hostname: str
    target: str
    port: int
    status: str
    message: str | None = None
    origin_id: int | None = None


class TargetPoolAssignToGroupsOut(BaseModel):
    created: int
    skipped: int
    failed: int
    results: list[TargetPoolAssignGroupResult]


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
    collection_id: int | None
    hostname: str
    ttl: int
    enabled: bool
    min_switch_interval_seconds: int
    current_origin_id: int | None
    current_record_id: str | None
    last_switch_at: datetime | None
    last_error: str | None
    hostnames: list[FailoverHostnameOut] = []
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
