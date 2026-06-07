export type Credential = {
  id: number;
  name: string;
  status: string;
  last_error: string | null;
  synced_at: string | null;
  created_at: string;
};

export type Zone = {
  id: number;
  credential_id: number;
  cf_zone_id: string;
  name: string;
  account_id: string | null;
  account_name: string | null;
  status: string | null;
  synced_at: string | null;
};

export type DnsRecord = {
  id: number;
  zone_id: number;
  cf_record_id: string;
  name: string;
  type: string;
  content: string;
  ttl: number;
  proxied: boolean;
  synced_at: string | null;
};

export type ProbeState = {
  id: number;
  source_key: string;
  agent_name: string | null;
  agent_enabled: boolean;
  status: string;
  success_count: number;
  fail_count: number;
  last_checked_at: string | null;
  last_error: string | null;
  last_rtt_ms: number | null;
};

export type Origin = {
  id: number;
  group_id: number;
  global_origin_id: number | null;
  target: string;
  target_type: string;
  publish_mode: string;
  port: number;
  priority: number;
  remark: string | null;
  enabled: boolean;
  status: string;
  last_checked_at: string | null;
  last_error: string | null;
  last_rtt_ms: number | null;
  resolved_ips: string[];
  healthy_ips: string[];
  published_ips: string[];
  probe_states: ProbeState[];
};

export type TargetPoolItem = {
  id: number;
  target: string;
  target_type: string;
  port: number;
  remark: string | null;
  check_interval_seconds: number;
  enabled: boolean;
  status: string;
  last_checked_at: string | null;
  last_error: string | null;
  last_rtt_ms: number | null;
  probe_states: ProbeState[];
  created_at: string;
  updated_at: string;
};

export type FailoverHostname = {
  id: number;
  group_id: number;
  hostname: string;
  current_record_id: string | null;
  created_at: string;
};

export type FailoverGlobalOrigin = {
  id: number;
  collection_id: number;
  target: string;
  target_type: string;
  publish_mode: string;
  port: number;
  priority: number;
  remark: string | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
};

export type FailoverCollection = {
  id: number;
  name: string;
  global_origins: FailoverGlobalOrigin[];
  created_at: string;
  updated_at: string;
};

export type ExternalIpSource = {
  id: number;
  name: string;
  source_type: string;
  base_url: string;
  default_port: number;
  sync_interval_seconds: number;
  enabled: boolean;
  status: string;
  last_synced_at: string | null;
  last_error: string | null;
  created_at: string;
};

export type ExternalIpItem = {
  id: number;
  source_id: number;
  name: string;
  group_name: string | null;
  machine_key: string | null;
  country: string | null;
  target: string;
  target_type: string;
  port: number;
  status: string;
  last_seen_at: string | null;
  created_at: string;
  updated_at: string;
};

export type FailoverGroup = {
  id: number;
  zone_id: number;
  collection_id: number | null;
  hostname: string;
  ttl: number;
  enabled: boolean;
  min_switch_interval_seconds: number;
  current_origin_id: number | null;
  current_record_id: string | null;
  last_switch_at: string | null;
  last_error: string | null;
  hostnames: FailoverHostname[];
  origins: Origin[];
};

export type Agent = {
  id: number;
  name: string;
  region: string;
  enabled: boolean;
  status: string;
  last_seen_at: string | null;
  last_ip: string | null;
  created_at: string;
};

export type Webhook = {
  id: number;
  name: string;
  url: string;
  enabled: boolean;
  last_sent_at: string | null;
  last_error: string | null;
};

export type TelegramNotification = {
  id: number;
  name: string;
  chat_id: string;
  notify_level: string;
  enabled: boolean;
  last_sent_at: string | null;
  last_error: string | null;
};

export type SavedSnippet = {
  id: number;
  title: string;
  category: string;
  address: string | null;
  username: string | null;
  port: number | null;
  tags: string | null;
  content: string | null;
  code: string | null;
  created_at: string;
  updated_at: string;
};

export type UserProfile = {
  id: number;
  username: string;
};

export type EventItem = {
  id: number;
  type: string;
  severity: string;
  message: string;
  payload_json: string | null;
  created_at: string;
};

export type SystemSettings = {
  check_interval_seconds: number;
  check_timeout_seconds: number;
  fail_threshold: number;
  recovery_threshold: number;
  no_healthy_notification_interval_seconds: number;
  external_ip_sync_interval_seconds: number;
  access_token_ttl_seconds: number;
  access_token_remember_ttl_seconds: number;
  login_lockout_enabled: number;
  login_max_failures: number;
  login_failure_window_seconds: number;
  login_lockout_seconds: number;
  cloudflare_access_enabled: number;
};

export type SshSettings = {
  enabled: boolean;
  external_url: string;
  upstream_url: string;
  session_ttl_seconds: number;
  entry_path: string;
};

export type Overview = {
  credentials: number;
  zones: number;
  groups: number;
  enabled_groups: number;
  origins: number;
  unhealthy_origins: number;
  agents: number;
  recent_events: EventItem[];
};
