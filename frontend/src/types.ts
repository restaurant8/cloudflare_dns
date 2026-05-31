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
  target: string;
  target_type: string;
  publish_mode: string;
  port: number;
  priority: number;
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
  enabled: boolean;
  created_at: string;
  updated_at: string;
};

export type FailoverGroup = {
  id: number;
  zone_id: number;
  hostname: string;
  ttl: number;
  enabled: boolean;
  min_switch_interval_seconds: number;
  current_origin_id: number | null;
  current_record_id: string | null;
  last_switch_at: string | null;
  last_error: string | null;
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

export type EventItem = {
  id: number;
  type: string;
  severity: string;
  message: string;
  payload_json: string | null;
  created_at: string;
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
