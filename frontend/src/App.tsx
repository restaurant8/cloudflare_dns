import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  ChevronDown,
  ChevronRight,
  Cloud,
  Copy,
  DatabaseZap,
  FileCode2,
  Globe2,
  KeyRound,
  Link2,
  ListRestart,
  LockKeyhole,
  LogOut,
  Pencil,
  Play,
  Plus,
  Power,
  PowerOff,
  RadioTower,
  RefreshCw,
  Save,
  Server,
  ShieldCheck,
  SlidersHorizontal,
  SquareTerminal,
  Trash2,
  Webhook as WebhookIcon
} from "lucide-react";
import { apiFetch, fmtDate, fmtTime } from "./api";
import type { Agent, AzPanelRemoteResource, AzPanelResource, AzPanelSettings, Credential, DnsRecord, EventItem, ExternalIpItem, ExternalIpSource, FailoverCollection, FailoverGlobalOrigin, FailoverGroup, IpChangeJob, Origin, Overview, ProbeState, SavedSnippet, SshSettings, SystemSettings, TargetPoolItem, TelegramNotification, UserProfile, Webhook, XboardNodeBinding, XboardSettings, Zone } from "./types";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger
} from "@/components/ui/sidebar";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { ThemeToggle } from "@/components/theme-toggle";

type Section = "overview" | "cloudflare" | "records" | "groups" | "targetPool" | "externalIps" | "azpanel" | "snippets" | "ssh" | "agents" | "webhooks" | "settings" | "account" | "events";
type ExpandedIpPriorityMap = Record<string, number>;
type ProbeMode = "default" | "local_only" | "china_only" | "any";
type OriginAddDraft = { target: string; port: number; priority: number; publish_mode: string; expanded_ip_priorities: ExpandedIpPriorityMap; preferred_agent_id: number | ""; probe_mode: ProbeMode; remark: string; enabled: boolean };
type OriginEditDraft = { target: string; port: number; priority: number; publish_mode: string; expanded_ip_priorities: ExpandedIpPriorityMap; preferred_agent_id: number | ""; probe_mode: ProbeMode; remark: string; enabled: boolean };
type GlobalOriginDraft = OriginAddDraft;
type CollectionDraft = { name: string };
type GroupEditDraft = { ttl: number; min_switch_interval_seconds: number; enabled: boolean; collection_id: number | "" };
type HostnameAddDraft = { hostname: string; adopt_record_id: string };
type DnsRecordType = "A" | "AAAA" | "CNAME";
type DnsRecordEditDraft = { name: string; type: DnsRecordType; content: string; ttl: number; proxied: boolean };
type TargetPoolDraft = { target: string; port: number; remark: string; check_interval_seconds: number; enabled: boolean };
type ExternalIpSourceDraft = { name: string; base_url: string; token: string; default_port: number; sync_interval_seconds: number; enabled: boolean };
type SnippetDraft = { title: string; category: string; address: string; username: string; port: string; tags: string; content: string; code: string };
type SshSettingsDraft = { enabled: boolean; external_url: string };
type AzPanelSettingsDraft = { enabled: boolean; base_url: string; api_token: string; timeout_seconds: number; default_cooldown_seconds: number };
type AzPanelResourceDraft = { name: string; provider: string; resource_id: string; account_id: string; region: string; ip_version: string; origin_id: number | ""; current_ip: string; port: number; enabled: boolean; auto_change_on_blocked: boolean; auto_update_origin: boolean; cooldown_seconds: number; remark: string };
type XboardSettingsDraft = { enabled: boolean; base_url: string; api_token: string; timeout_seconds: number };
type XboardNodeDraft = { name: string; xboard_node_id: number; node_type: string; host: string; port: number | ""; origin_id: number | ""; azpanel_resource_id: number | ""; enabled: boolean; auto_update_after_change: boolean; remark: string };
type AgentEditDraft = { name: string };
type SystemSettingsDraft = { [K in keyof SystemSettings]: string };
type SystemSettingField = { key: keyof SystemSettings; label: string; min?: number; max?: number; step?: number; hint?: string; type?: "number" | "toggle" };
type ToastTone = "info" | "success" | "error" | "loading";
type ActionRunner = <T>(fn: () => Promise<T>, done?: string, afterSuccess?: () => void) => Promise<boolean>;

const nav: { id: Section; label: string; icon: typeof Activity }[] = [
  { id: "overview", label: "总览", icon: Activity },
  { id: "cloudflare", label: "Cloudflare", icon: KeyRound },
  { id: "records", label: "解析记录", icon: Cloud },
  { id: "groups", label: "故障切换", icon: ListRestart },
  { id: "targetPool", label: "IP 池子", icon: Server },
  { id: "externalIps", label: "外部 IP", icon: Globe2 },
  { id: "azpanel", label: "自动换 IP", icon: RefreshCw },
  { id: "snippets", label: "命令库", icon: FileCode2 },
  { id: "ssh", label: "SSH", icon: SquareTerminal },
  { id: "agents", label: "探针", icon: RadioTower },
  { id: "webhooks", label: "通知", icon: WebhookIcon },
  { id: "settings", label: "设置", icon: SlidersHorizontal },
  { id: "account", label: "账户", icon: LockKeyhole },
  { id: "events", label: "事件", icon: DatabaseZap }
];

const sectionStorageKey = "cloudflareDnsActiveSection";
const defaultExpandedIpPriority = 100;

const statusLabels: Record<string, string> = {
  ok: "正常",
  error: "错误",
  unknown: "未知",
  healthy: "健康",
  unhealthy: "不可用",
  blocked: "疑似被墙",
  machine_down: "机器疑似挂了",
  regional_issue: "本地探测异常",
  disabled: "已禁用",
  enabled: "已启用",
  online: "在线",
  offline: "离线",
  warning: "警告",
  info: "信息",
  running: "执行中",
  success: "成功",
  failed: "失败",
  skipped: "已跳过"
};

const targetTypeLabels: Record<string, string> = {
  ipv4: "IPv4",
  ipv6: "IPv6",
  hostname: "域名"
};

const eventTypeLabels: Record<string, string> = {
  "cloudflare.synced": "Cloudflare 已同步",
  "cloudflare.sync_failed": "Cloudflare 同步失败",
  "group.created": "切换组已创建",
  "probe.status_changed": "探测状态变化",
  "origin.status_changed": "源站状态变化",
  "agent.status_changed": "探针状态变化",
  "failover.no_healthy_origin": "无健康源站",
  "dns.publish_failed": "DNS 发布失败",
  "dns.switched": "DNS 已切换",
  "webhook.failed": "Webhook 发送失败",
  "telegram.failed": "Telegram 发送失败",
  "telegram.test": "Telegram 测试",
  "azpanel.ip_changed": "AzPanel IP 已更换",
  "azpanel.ip_change_failed": "AzPanel IP 更换失败",
  "xboard.node_update_failed": "Xboard 节点更新失败"
};

const telegramNotifyLevelLabels: Record<string, string> = {
  important: "重要通知",
  critical: "故障和切换",
  all: "全部通知"
};

function statusText(value: string): string {
  return statusLabels[value] || value;
}

function targetTypeText(value: string): string {
  return targetTypeLabels[value] || value;
}

function agentRegionText(value: string): string {
  return value === "foreign" ? "国外探针" : "国内探针";
}

function agentSelectLabel(agent: Agent): string {
  return `${agent.name}${agent.is_default ? " · 默认" : ""} · ${agentRegionText(agent.region)} · ${agent.enabled ? "启用" : "停用"}`;
}

const probeModeOptions: { value: ProbeMode; label: string }[] = [
  { value: "default", label: "默认：本地 + 探针综合判断" },
  { value: "local_only", label: "只看本地检测" },
  { value: "china_only", label: "只看国内探针" },
  { value: "any", label: "本地或国内任一可用" }
];

function normalizeProbeMode(value?: string | null): ProbeMode {
  return value === "local_only" || value === "china_only" || value === "any" ? value : "default";
}

function probeModeText(value?: string | null): string {
  return probeModeOptions.find((option) => option.value === normalizeProbeMode(value))?.label || probeModeOptions[0].label;
}

function telegramNotifyLevelText(value: string): string {
  return telegramNotifyLevelLabels[value] || value;
}

function guessDnsRecordType(value: string): DnsRecordType | null {
  const cleaned = value.trim();
  if (!cleaned) return null;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(cleaned)) return "A";
  if (cleaned.includes(":")) return "AAAA";
  if (/^[A-Za-z0-9.-]+\.[A-Za-z0-9-]+\.?$/.test(cleaned)) return "CNAME";
  return null;
}

function recordTypeForTargetType(value: string, publishMode = "direct"): string {
  if (value === "ipv4") return "A";
  if (value === "ipv6") return "AAAA";
  if (value === "hostname") return publishMode === "expanded" ? "A/AAAA IP池" : "CNAME";
  return "-";
}

function probeSourceText(probe: ProbeState): string {
  const value = probe.source_key;
  const [source, ip] = value.split("|");
  if (source === "local") return ip ? `本地 ${ip}` : "本地";
  if (source.startsWith("agent:")) {
    const name = probe.agent_name || `探针 ${source.slice(6)}`;
    return ip ? `${name} ${ip}` : name;
  }
  return value;
}

function probeSourceIp(value: string): string | null {
  const [, ip] = value.split("|");
  return ip || null;
}

function displayTargetWithRemark(target: string, port: number, remark?: string | null): string {
  return remark?.trim() || `${target}:${port}`;
}

function originOptions(groups: FailoverGroup[]) {
  return groups.flatMap((group) =>
    group.origins.map((origin) => ({
      id: origin.id,
      label: `${group.hostname} · ${displayTargetWithRemark(origin.target, origin.port, origin.remark)}`
    }))
  );
}

function externalIpFamilyText(item: ExternalIpItem): string {
  if (item.target_type === "ipv4") return "IPv4";
  if (item.target_type === "ipv6") return "IPv6";
  return targetTypeText(item.target_type);
}

function externalIpLabel(item: ExternalIpItem): string {
  const country = item.country ? ` · ${item.country}` : "";
  return `${item.name}${country} · ${externalIpFamilyText(item)} ${item.target}:${item.port}`;
}

function externalIpPoolRemark(item: ExternalIpItem): string {
  return [item.name, item.country].filter(Boolean).join(" · ");
}

function activeProbeStates(probeStates: ProbeState[]) {
  return probeStates.filter((probe) => probe.agent_enabled !== false);
}

function currentProbeStates(origin: Origin) {
  const activeStates = activeProbeStates(origin.probe_states);
  if (origin.publish_mode !== "expanded") return activeStates;
  const currentIps = new Set(origin.resolved_ips);
  return activeStates.filter((probe) => {
    const ip = probeSourceIp(probe.source_key);
    return !ip || currentIps.has(ip);
  });
}

function IpList({ label, values, empty = "暂无" }: { label: string; values: string[]; empty?: string }) {
  return (
    <div className="ipListRow">
      <span>{label}</span>
      <div>
        {values.length > 0 ? values.map((value) => <code key={value}>{value}</code>) : <em>{empty}</em>}
      </div>
    </div>
  );
}

function setExpandedIpPriority(map: ExpandedIpPriorityMap, ip: string, priority: number): ExpandedIpPriorityMap {
  return { ...map, [ip]: Math.max(0, Math.min(100000, Math.trunc(priority || 0))) };
}

function ExpandedIpPriorityEditor({
  origin,
  draft,
  onChange
}: {
  origin: Origin;
  draft: OriginEditDraft;
  onChange: (next: OriginEditDraft) => void;
}) {
  const ips = origin.resolved_ips;
  if (ips.length === 0) return null;
  const healthy = new Set(origin.healthy_ips);
  const published = new Set(origin.published_ips);
  return (
    <div className="expandedIpPriorityEditor">
      <div className="expandedIpPriorityHead">
        <strong>展开 IP 优先级</strong>
        <span>数字越小越优先，只发布一个健康 IP。</span>
      </div>
      {ips.map((ip) => (
        <label className="expandedIpPriorityItem" key={ip}>
          <span>
            <code>{ip}</code>
            {healthy.has(ip) && <em>健康</em>}
            {published.has(ip) && <em>已发布</em>}
          </span>
          <input
            type="number"
            min={0}
            max={100000}
            value={draft.expanded_ip_priorities[ip] ?? defaultExpandedIpPriority}
            onChange={(event) =>
              onChange({
                ...draft,
                expanded_ip_priorities: setExpandedIpPriority(draft.expanded_ip_priorities, ip, Number(event.target.value))
              })
            }
          />
        </label>
      ))}
    </div>
  );
}

function ExpandedIpPrioritySummary({ origin }: { origin: Origin }) {
  const priorities = origin.expanded_ip_priorities || {};
  const values = origin.resolved_ips.map((ip) => `${ip} #${priorities[ip] ?? defaultExpandedIpPriority}`);
  return <IpList label="优先级" values={values} empty="默认同级" />;
}

function inferDraftTargetType(value: string): string {
  const cleaned = value.trim();
  if (!cleaned) return "";
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(cleaned)) return "ipv4";
  if (cleaned.includes(":")) return "ipv6";
  return "hostname";
}

function shellQuote(value: string): string {
  return "'" + value.replace(/'/g, "'\\''") + "'";
}

function eventTypeText(value: string): string {
  return eventTypeLabels[value] || value;
}

function isSection(value: string | null | undefined): value is Section {
  return nav.some((item) => item.id === value);
}

function sectionFromHash(): Section | null {
  if (typeof window === "undefined") return null;
  const value = window.location.hash.replace(/^#/, "");
  return isSection(value) ? value : null;
}

function initialSection(): Section {
  const hashSection = sectionFromHash();
  if (hashSection) return hashSection;
  try {
    const stored = localStorage.getItem(sectionStorageKey);
    return isSection(stored) ? stored : "overview";
  } catch {
    return "overview";
  }
}

function zoneMatches(zone: Zone, query: string): boolean {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return true;
  return [zone.name, zone.account_name || "", zone.status || ""].join(" ").toLowerCase().includes(normalized);
}

function filteredZoneList(zones: Zone[], query: string, selectedZoneId: number | ""): Zone[] {
  const filtered = zones.filter((zone) => zoneMatches(zone, query));
  const selected = zones.find((zone) => zone.id === selectedZoneId);
  if (selected && !filtered.some((zone) => zone.id === selected.id)) {
    return [selected, ...filtered];
  }
  return filtered;
}

const emptyOverview: Overview = {
  credentials: 0,
  zones: 0,
  groups: 0,
  enabled_groups: 0,
  origins: 0,
  unhealthy_origins: 0,
  agents: 0,
  recent_events: []
};

const defaultOriginAddDraft: OriginAddDraft = { target: "", port: 22, priority: 10, publish_mode: "direct", expanded_ip_priorities: {}, preferred_agent_id: "", probe_mode: "default", remark: "", enabled: true };
const defaultGlobalOriginDraft: GlobalOriginDraft = { target: "", port: 22, priority: 10, publish_mode: "direct", expanded_ip_priorities: {}, preferred_agent_id: "", probe_mode: "default", remark: "", enabled: true };
const dnsRecordTypes: DnsRecordType[] = ["A", "AAAA", "CNAME"];
const defaultTargetPoolDraft: TargetPoolDraft = { target: "", port: 22, remark: "", check_interval_seconds: 600, enabled: true };
const defaultExternalIpSourceDraft: ExternalIpSourceDraft = { name: "", base_url: "", token: "", default_port: 22, sync_interval_seconds: 600, enabled: true };
const defaultSnippetDraft: SnippetDraft = { title: "", category: "command", address: "", username: "", port: "22", tags: "", content: "", code: "" };
const liveRefreshIntervalMs = 10000;
const accessTokenStorageKey = "accessToken";
const rememberedUsernameStorageKey = "cloudflareDnsRememberedUsername";

function systemSettingsToDraft(settings: SystemSettings): SystemSettingsDraft {
  return Object.fromEntries(Object.entries(settings).map(([key, value]) => [key, String(value)])) as SystemSettingsDraft;
}

function getStoredAccessToken(): string | null {
  try {
    return localStorage.getItem(accessTokenStorageKey) || sessionStorage.getItem(accessTokenStorageKey);
  } catch {
    return null;
  }
}

function getRememberedUsername(): string {
  try {
    return localStorage.getItem(rememberedUsernameStorageKey) || "admin";
  } catch {
    return "admin";
  }
}

export default function App() {
  const [token, setToken] = useState<string | null>(() => getStoredAccessToken());
  const [setupRequired, setSetupRequired] = useState<boolean | null>(null);
  const [bootError, setBootError] = useState("");
  const [section, setSection] = useState<Section>(() => initialSection());
  const [message, setMessage] = useState("");
  const [messageTone, setMessageTone] = useState<ToastTone>("info");
  const [busy, setBusy] = useState(false);
  const [liveUpdatedAt, setLiveUpdatedAt] = useState<string | null>(null);
  const messageTimer = useRef<number | null>(null);
  const pendingActionButton = useRef<{ element: HTMLButtonElement; startedAt: number } | null>(null);

  const [overview, setOverview] = useState<Overview>(emptyOverview);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [selectedZoneId, setSelectedZoneId] = useState<number | "">("");
  const [records, setRecords] = useState<DnsRecord[]>([]);
  const [failoverCollections, setFailoverCollections] = useState<FailoverCollection[]>([]);
  const [groups, setGroups] = useState<FailoverGroup[]>([]);
  const [targetPool, setTargetPool] = useState<TargetPoolItem[]>([]);
  const [externalIpSources, setExternalIpSources] = useState<ExternalIpSource[]>([]);
  const [externalIpItems, setExternalIpItems] = useState<ExternalIpItem[]>([]);
  const [snippets, setSnippets] = useState<SavedSnippet[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [telegramNotifications, setTelegramNotifications] = useState<TelegramNotification[]>([]);
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [systemSettings, setSystemSettings] = useState<SystemSettings | null>(null);
  const [sshSettings, setSshSettings] = useState<SshSettings | null>(null);
  const [azPanelSettings, setAzPanelSettings] = useState<AzPanelSettings | null>(null);
  const [azPanelResources, setAzPanelResources] = useState<AzPanelResource[]>([]);
  const [ipChangeJobs, setIpChangeJobs] = useState<IpChangeJob[]>([]);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [agentToken, setAgentToken] = useState("");

  const selectedZone = useMemo(() => zones.find((zone) => zone.id === selectedZoneId), [selectedZoneId, zones]);
  const sectionSubtitle =
    section === "ssh"
      ? "Sshwifty 通过本项目临时会话访问"
      : section === "azpanel"
        ? "源站被墙后调用 azpanel 更换公网 IP"
        : selectedZone
          ? selectedZone.name
          : "尚未选择域名区域";

  async function loadSetup() {
    setBootError("");
    const data = await apiFetch<{ setup_required: boolean }>("/api/auth/setup-required");
    setSetupRequired(data.setup_required);
  }

  async function loadAll(activeToken = token) {
    if (!activeToken) return;
    const [nextOverview, nextCredentials, nextZones, nextCollections, nextGroups, nextTargetPool, nextExternalIpSources, nextExternalIpItems, nextAzPanelSettings, nextAzPanelResources, nextIpChangeJobs, nextSnippets, nextAgents, nextTelegram, nextWebhooks, nextSystemSettings, nextSshSettings, nextEvents] = await Promise.all([
      apiFetch<Overview>("/api/overview", activeToken),
      apiFetch<Credential[]>("/api/credentials", activeToken),
      apiFetch<Zone[]>("/api/zones", activeToken),
      apiFetch<FailoverCollection[]>("/api/groups/collections", activeToken),
      apiFetch<FailoverGroup[]>("/api/groups", activeToken),
      apiFetch<TargetPoolItem[]>("/api/target-pool", activeToken),
      apiFetch<ExternalIpSource[]>("/api/external-ips/sources", activeToken),
      apiFetch<ExternalIpItem[]>("/api/external-ips/items", activeToken),
      apiFetch<AzPanelSettings>("/api/integrations/azpanel/settings", activeToken),
      apiFetch<AzPanelResource[]>("/api/integrations/azpanel/resources", activeToken),
      apiFetch<IpChangeJob[]>("/api/integrations/ip-change-jobs", activeToken),
      apiFetch<SavedSnippet[]>("/api/snippets", activeToken),
      apiFetch<Agent[]>("/api/agents", activeToken),
      apiFetch<TelegramNotification[]>("/api/telegram", activeToken),
      apiFetch<Webhook[]>("/api/webhooks", activeToken),
      apiFetch<SystemSettings>("/api/settings", activeToken),
      apiFetch<SshSettings>("/api/ssh/settings", activeToken),
      apiFetch<EventItem[]>("/api/events?limit=100", activeToken)
    ]);
    setOverview(nextOverview);
    setCredentials(nextCredentials);
    setZones(nextZones);
    setFailoverCollections(nextCollections);
    setGroups(nextGroups);
    setTargetPool(nextTargetPool);
    setExternalIpSources(nextExternalIpSources);
    setExternalIpItems(nextExternalIpItems);
    setAzPanelSettings(nextAzPanelSettings);
    setAzPanelResources(nextAzPanelResources);
    setIpChangeJobs(nextIpChangeJobs);
    setSnippets(nextSnippets);
    setAgents(nextAgents);
    setTelegramNotifications(nextTelegram);
    setWebhooks(nextWebhooks);
    setSystemSettings(nextSystemSettings);
    setSshSettings(nextSshSettings);
    setEvents(nextEvents);
    if (!selectedZoneId && nextZones.length > 0) {
      setSelectedZoneId(nextZones[0].id);
    }
  }

  async function loadRecords(zoneId = selectedZoneId) {
    if (!token || !zoneId) return;
    const data = await apiFetch<DnsRecord[]>(`/api/zones/${zoneId}/records`, token);
    setRecords(data);
  }

  async function loadLiveStatus(activeToken = token) {
    if (!activeToken) return;
    const [nextOverview, nextCollections, nextGroups, nextTargetPool, nextExternalIpSources, nextExternalIpItems, nextAzPanelResources, nextIpChangeJobs, nextSnippets, nextAgents, nextEvents] = await Promise.all([
      apiFetch<Overview>("/api/overview", activeToken),
      apiFetch<FailoverCollection[]>("/api/groups/collections", activeToken),
      apiFetch<FailoverGroup[]>("/api/groups", activeToken),
      apiFetch<TargetPoolItem[]>("/api/target-pool", activeToken),
      apiFetch<ExternalIpSource[]>("/api/external-ips/sources", activeToken),
      apiFetch<ExternalIpItem[]>("/api/external-ips/items", activeToken),
      apiFetch<AzPanelResource[]>("/api/integrations/azpanel/resources", activeToken),
      apiFetch<IpChangeJob[]>("/api/integrations/ip-change-jobs", activeToken),
      apiFetch<SavedSnippet[]>("/api/snippets", activeToken),
      apiFetch<Agent[]>("/api/agents", activeToken),
      apiFetch<EventItem[]>("/api/events?limit=100", activeToken)
    ]);
    setOverview(nextOverview);
    setFailoverCollections(nextCollections);
    setGroups(nextGroups);
    setTargetPool(nextTargetPool);
    setExternalIpSources(nextExternalIpSources);
    setExternalIpItems(nextExternalIpItems);
    setAzPanelResources(nextAzPanelResources);
    setIpChangeJobs(nextIpChangeJobs);
    setSnippets(nextSnippets);
    setAgents(nextAgents);
    setEvents(nextEvents);
    setLiveUpdatedAt(new Date().toISOString());
  }

  function showMessage(text: string, tone: ToastTone = "info", timeoutMs = 1800) {
    if (messageTimer.current) {
      window.clearTimeout(messageTimer.current);
    }
    setMessage(text);
    setMessageTone(tone);
    if (timeoutMs > 0) {
      messageTimer.current = window.setTimeout(() => {
        setMessage("");
        messageTimer.current = null;
      }, timeoutMs);
    } else {
      messageTimer.current = null;
    }
  }

  async function act<T>(fn: () => Promise<T>, done = "已完成", afterSuccess?: () => void) {
    const pending = pendingActionButton.current;
    pendingActionButton.current = null;
    const actionButton =
      pending && Date.now() - pending.startedAt < 1500 && document.contains(pending.element)
        ? pending.element
        : null;
    setBusy(true);
    if (messageTimer.current) {
      window.clearTimeout(messageTimer.current);
      messageTimer.current = null;
    }
    setMessage("");
    actionButton?.classList.add("buttonLoading");
    actionButton?.setAttribute("aria-busy", "true");
    try {
      await fn();
      afterSuccess?.();
      showMessage(done, "success", 1800);
      await loadAll();
      if (selectedZoneId) await loadRecords();
      return true;
    } catch (error) {
      showMessage(error instanceof Error ? error.message : "请求失败", "error", 5000);
      return false;
    } finally {
      actionButton?.classList.remove("buttonLoading");
      actionButton?.removeAttribute("aria-busy");
      setBusy(false);
    }
  }

  useEffect(() => {
    loadSetup().catch((error) => setBootError(error instanceof Error ? error.message : "无法连接后端 API"));
  }, []);

  useEffect(() => {
    function markClickedButton(event: PointerEvent) {
      const target = event.target;
      if (!(target instanceof Element)) return;
      const button = target.closest("button");
      if (!(button instanceof HTMLButtonElement) || button.disabled) return;
      pendingActionButton.current = { element: button, startedAt: Date.now() };
      button.classList.remove("buttonClicked");
      void button.offsetWidth;
      button.classList.add("buttonClicked");
      window.setTimeout(() => button.classList.remove("buttonClicked"), 360);
    }

    document.addEventListener("pointerdown", markClickedButton, true);
    return () => {
      document.removeEventListener("pointerdown", markClickedButton, true);
      if (messageTimer.current) {
        window.clearTimeout(messageTimer.current);
      }
    };
  }, []);

  useEffect(() => {
    if (token) {
      loadAll(token).catch((error) => showMessage(error.message, "error", 5000));
    }
  }, [token]);

  useEffect(() => {
    try {
      localStorage.setItem(sectionStorageKey, section);
    } catch {
      // Ignore private browsing or storage-disabled environments.
    }
    const nextHash = `#${section}`;
    if (window.location.hash !== nextHash) {
      window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}${nextHash}`);
    }
  }, [section]);

  useEffect(() => {
    function syncSectionFromHash() {
      const nextSection = sectionFromHash();
      if (nextSection) {
        setSection(nextSection);
      }
    }
    window.addEventListener("hashchange", syncSectionFromHash);
    return () => window.removeEventListener("hashchange", syncSectionFromHash);
  }, []);

  useEffect(() => {
    if (!token) return;
    const timer = window.setInterval(() => {
      if (document.hidden) return;
      loadLiveStatus(token).catch(() => undefined);
    }, liveRefreshIntervalMs);
    return () => window.clearInterval(timer);
  }, [token]);

  useEffect(() => {
    if (selectedZoneId) {
      loadRecords(selectedZoneId).catch((error) => showMessage(error.message, "error", 5000));
    }
  }, [selectedZoneId]);

  function onAuth(nextToken: string, options: { rememberLogin: boolean; rememberUsername: boolean; username: string }) {
    try {
      const persistentStorage = options.rememberLogin ? localStorage : sessionStorage;
      const otherStorage = options.rememberLogin ? sessionStorage : localStorage;
      otherStorage.removeItem(accessTokenStorageKey);
      persistentStorage.setItem(accessTokenStorageKey, nextToken);
      if (options.rememberUsername) {
        localStorage.setItem(rememberedUsernameStorageKey, options.username);
      } else {
        localStorage.removeItem(rememberedUsernameStorageKey);
      }
    } catch {
      // Keep the in-memory token even if browser storage is unavailable.
    }
    setToken(nextToken);
    setSetupRequired(false);
  }

  function logout() {
    try {
      localStorage.removeItem(accessTokenStorageKey);
      sessionStorage.removeItem(accessTokenStorageKey);
    } catch {
      // Ignore private browsing or storage-disabled environments.
    }
    setToken(null);
  }

  if (setupRequired === null) {
    return (
      <div className="legacy-ui">
        <div className="loadingState">
          <div className="loadingBox">
            <strong>{bootError ? "后端连接失败" : "加载中"}</strong>
            {bootError && (
              <>
                <p>{bootError}</p>
                <button onClick={() => loadSetup().catch((error) => setBootError(error instanceof Error ? error.message : "无法连接后端 API"))}>
                  <RefreshCw size={16} />
                  <span>重试</span>
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    );
  }

  if (!token) {
    return <AuthScreen setupRequired={setupRequired} onAuth={onAuth} />;
  }

  return (
    <SidebarProvider>
      <Sidebar collapsible="icon">
        <SidebarHeader>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton size="lg" className="data-[slot=sidebar-menu-button]:!p-1.5">
                <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground">
                  <ShieldCheck className="size-5" />
                </div>
                <div className="grid flex-1 text-start text-sm leading-tight">
                  <span className="truncate font-semibold">DNS 故障切换</span>
                  <span className="truncate text-xs text-muted-foreground">Cloudflare</span>
                </div>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel>导航</SidebarGroupLabel>
            <SidebarMenu>
              {nav.map((item) => {
                const Icon = item.icon;
                return (
                  <SidebarMenuItem key={item.id}>
                    <SidebarMenuButton isActive={section === item.id} tooltip={item.label} onClick={() => setSection(item.id)}>
                      <Icon />
                      <span>{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroup>
        </SidebarContent>
        <SidebarFooter>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton tooltip="退出登录" onClick={logout}>
                <LogOut />
                <span>退出登录</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
        <SidebarRail />
      </Sidebar>

      <SidebarInset>
        <header className="sticky top-0 z-10 flex h-16 shrink-0 items-center gap-2 border-b bg-background/95 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/60">
          <SidebarTrigger className="-ms-1" />
          <Separator orientation="vertical" className="me-1 h-6" />
          <div className="min-w-0 flex-1">
            <h1 className="truncate text-sm font-semibold">{nav.find((item) => item.id === section)?.label}</h1>
            <p className="truncate text-xs text-muted-foreground">
              {sectionSubtitle}
              <span className="ms-2">实时更新{liveUpdatedAt ? ` · ${fmtTime(liveUpdatedAt)}` : ""}</span>
            </p>
          </div>
          <ThemeToggle />
          <Button variant="outline" size="sm" disabled={busy} onClick={() => act(() => loadAll(), "已刷新")}>
            <RefreshCw className="size-4" />
            <span className="hidden sm:inline">刷新</span>
          </Button>
          <Button size="sm" disabled={busy} onClick={() => act(() => apiFetch("/api/groups/run", token, { method: "POST" }), "健康检查已完成")}>
            <Play className="size-4" />
            <span className="hidden sm:inline">立即检查</span>
          </Button>
        </header>

        <main className="legacy-ui flex-1 p-4 md:p-6">
          {message && <div className={`notice ${messageTone}`} aria-live="polite">{message}</div>}

          {section === "overview" && <OverviewPanel overview={overview} />}
        {section === "cloudflare" && (
          <CloudflarePanel
            token={token}
            credentials={credentials}
            busy={busy}
            act={act}
          />
        )}
        {section === "records" && (
          <RecordsPanel
            token={token}
            zones={zones}
            selectedZoneId={selectedZoneId}
            setSelectedZoneId={setSelectedZoneId}
            records={records}
            setSection={setSection}
            act={act}
          />
        )}
        {section === "groups" && (
          <GroupsPanel token={token} collections={failoverCollections} groups={groups} targetPool={targetPool} externalIpItems={externalIpItems} agents={agents} act={act} />
        )}
        {section === "targetPool" && (
          <TargetPoolPanel token={token} targetPool={targetPool} groups={groups} act={act} />
        )}
        {section === "externalIps" && (
          <ExternalIpsPanel token={token} externalIpSources={externalIpSources} externalIpItems={externalIpItems} act={act} />
        )}
        {section === "azpanel" && azPanelSettings && (
          <AzPanelPanel token={token} settings={azPanelSettings} resources={azPanelResources} groups={groups} jobs={ipChangeJobs} act={act} />
        )}
        {section === "snippets" && <SnippetsPanel token={token} snippets={snippets} act={act} />}
        {section === "ssh" && sshSettings && <SshPanel token={token} settings={sshSettings} act={act} />}
        {section === "agents" && (
          <AgentsPanel token={token} agents={agents} agentToken={agentToken} setAgentToken={setAgentToken} act={act} />
        )}
        {section === "webhooks" && <NotificationsPanel token={token} telegramNotifications={telegramNotifications} webhooks={webhooks} act={act} />}
        {section === "settings" && systemSettings && <SettingsPanel token={token} settings={systemSettings} act={act} />}
        {section === "account" && <AccountPanel token={token} onPasswordChanged={logout} />}
        {section === "events" && <EventsPanel events={events} />}
        </main>
      </SidebarInset>
    </SidebarProvider>
  );
}

function AuthScreen({
  setupRequired,
  onAuth
}: {
  setupRequired: boolean;
  onAuth: (token: string, options: { rememberLogin: boolean; rememberUsername: boolean; username: string }) => void;
}) {
  const [username, setUsername] = useState(() => getRememberedUsername());
  const [password, setPassword] = useState("");
  const [rememberLogin, setRememberLogin] = useState(true);
  const [rememberUsername, setRememberUsername] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const path = setupRequired ? "/api/auth/bootstrap" : "/api/auth/login";
      const data = await apiFetch<{ access_token: string }>(path, null, {
        method: "POST",
        body: JSON.stringify(setupRequired ? { username, password } : { username, password, remember_me: rememberLogin })
      });
      onAuth(data.access_token, { rememberLogin, rememberUsername, username: username.trim() });
    } catch (err) {
      setError(err instanceof Error ? err.message : "登录失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="legacy-ui">
      <main className="auth">
      <form className="authBox" onSubmit={submit}>
        <div className="brand authBrand">
          <ShieldCheck size={32} />
          <div>
            <strong>DNS 故障切换</strong>
            <span>{setupRequired ? "创建管理员" : "管理员登录"}</span>
          </div>
        </div>
        <label>
          用户名
          <input value={username} onChange={(event) => setUsername(event.target.value)} />
        </label>
        <label>
          密码
          <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
        </label>
        <div className="authOptions">
          <label className="inlineCheck">
            <input type="checkbox" checked={rememberLogin} onChange={(event) => setRememberLogin(event.target.checked)} />
            记住登录
          </label>
          <label className="inlineCheck">
            <input type="checkbox" checked={rememberUsername} onChange={(event) => setRememberUsername(event.target.checked)} />
            记住账号
          </label>
        </div>
        <p className="authHint">不会保存明文密码。</p>
        {error && <div className="error">{error}</div>}
        <button disabled={busy}>
          <KeyRound size={16} />
          <span>{setupRequired ? "创建" : "登录"}</span>
        </button>
      </form>
      </main>
    </div>
  );
}

function OverviewPanel({ overview }: { overview: Overview }) {
  const cards = [
    ["凭据", overview.credentials],
    ["域名区域", overview.zones],
    ["切换组", `${overview.enabled_groups}/${overview.groups}`],
    ["源站", overview.origins],
    ["不可用", overview.unhealthy_origins],
    ["探针", overview.agents]
  ];
  return (
    <section className="stack">
      <div className="metrics">
        {cards.map(([label, value]) => (
          <div className="metric" key={label}>
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>
      <EventsPanel events={overview.recent_events} compact />
    </section>
  );
}

function CloudflarePanel({ token, credentials, busy, act }: { token: string; credentials: Credential[]; busy: boolean; act: ActionRunner }) {
  const [name, setName] = useState("");
  const [cfToken, setCfToken] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    await act(
      () =>
        apiFetch("/api/credentials", token, {
          method: "POST",
          body: JSON.stringify({ name, token: cfToken })
        }),
      "Cloudflare Token 已保存"
    );
    setName("");
    setCfToken("");
  }

  return (
    <section className="gridTwo">
      <form className="panel" onSubmit={submit}>
        <h2>添加 Token</h2>
        <label>
          名称
          <input value={name} onChange={(event) => setName(event.target.value)} required />
        </label>
        <label>
          API Token
          <input value={cfToken} onChange={(event) => setCfToken(event.target.value)} required />
        </label>
        <button disabled={busy}>
          <Save size={16} />
          <span>保存</span>
        </button>
      </form>
      <div className="panel">
        <h2>Token 列表</h2>
        <div className="list">
          {credentials.map((item) => (
            <div className="row" key={item.id}>
              <div>
                <strong>{item.name}</strong>
                <span>{statusText(item.status)} · {fmtDate(item.synced_at)}</span>
                {item.last_error && <small className="danger">{item.last_error}</small>}
              </div>
              <div className="rowActions">
                <button className="icon" disabled={busy} title="同步" onClick={() => act(() => apiFetch(`/api/credentials/${item.id}/sync`, token, { method: "POST" }), "已同步")}>
                  <RefreshCw size={16} />
                </button>
                <button className="icon dangerBtn" disabled={busy} title="删除" onClick={() => act(() => apiFetch(`/api/credentials/${item.id}`, token, { method: "DELETE" }), "Cloudflare Token 已删除")}>
                  <Trash2 size={15} />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function RecordsPanel({
  token,
  zones,
  selectedZoneId,
  setSelectedZoneId,
  records,
  setSection,
  act
}: {
  token: string;
  zones: Zone[];
  selectedZoneId: number | "";
  setSelectedZoneId: (value: number | "") => void;
  records: DnsRecord[];
  setSection: (section: Section) => void;
  act: ActionRunner;
}) {
  const [query, setQuery] = useState("");
  const [zoneQuery, setZoneQuery] = useState("");
  const [manageRecord, setManageRecord] = useState<DnsRecord | null>(null);
  const [managePort, setManagePort] = useState(22);
  const [addRecordOpen, setAddRecordOpen] = useState(false);
  const [recordAdd, setRecordAdd] = useState<DnsRecordEditDraft>({ name: "", type: "A", content: "", ttl: 60, proxied: false });
  const [editRecord, setEditRecord] = useState<DnsRecord | null>(null);
  const [recordEdit, setRecordEdit] = useState<DnsRecordEditDraft>({ name: "", type: "A", content: "", ttl: 60, proxied: false });
  const filteredZones = zones.filter((zone) => zoneMatches(zone, zoneQuery));
  const selectedZone = zones.find((zone) => zone.id === selectedZoneId);
  const normalizedQuery = query.trim().toLowerCase();
  const filteredRecords = normalizedQuery
    ? records.filter((record) =>
        [record.name, record.type, record.content, record.cf_record_id, record.proxied ? "已代理 proxied" : "仅 DNS DNS-only"]
          .join(" ")
          .toLowerCase()
          .includes(normalizedQuery)
      )
    : records;

  function openManageRecord(record: DnsRecord) {
    setManageRecord(record);
    setManagePort(22);
  }

  function openAddRecord() {
    setRecordAdd({ name: "", type: "A", content: "", ttl: 60, proxied: false });
    setAddRecordOpen(true);
  }

  function openEditRecord(record: DnsRecord) {
    const recordType = dnsRecordTypes.includes(record.type as DnsRecordType) ? (record.type as DnsRecordType) : "A";
    setEditRecord(record);
    setRecordEdit({ name: record.name, type: recordType, content: record.content, ttl: record.ttl, proxied: record.proxied });
  }

  function updateAddRecordContent(value: string) {
    const detectedType = guessDnsRecordType(value);
    setRecordAdd((draft) => ({
      ...draft,
      content: value,
      type: detectedType || draft.type
    }));
  }

  function updateRecordContent(value: string) {
    const detectedType = guessDnsRecordType(value);
    setRecordEdit((draft) => ({
      ...draft,
      content: value,
      type: detectedType || draft.type
    }));
  }

  async function saveRecordAdd() {
    if (!selectedZoneId) return;
    await act(
      () =>
        apiFetch(`/api/zones/${selectedZoneId}/records`, token, {
          method: "POST",
          body: JSON.stringify({
            name: recordAdd.name.trim(),
            type: recordAdd.type,
            content: recordAdd.content.trim(),
            ttl: Number(recordAdd.ttl),
            proxied: recordAdd.proxied
          })
        }),
      "解析记录已添加",
      () => setAddRecordOpen(false)
    );
  }

  async function saveRecordEdit() {
    if (!editRecord) return;
    await act(
      () =>
        apiFetch(`/api/zones/records/${editRecord.id}`, token, {
          method: "PATCH",
          body: JSON.stringify({
            name: recordEdit.name.trim(),
            type: recordEdit.type,
            content: recordEdit.content.trim(),
            ttl: Number(recordEdit.ttl),
            proxied: recordEdit.proxied
          })
        }),
      "解析记录已修改",
      () => setEditRecord(null)
    );
  }

  async function deleteRecord(record: DnsRecord) {
    const confirmed = window.confirm(`确认删除 ${record.type} ${record.name} -> ${record.content} 吗？`);
    if (!confirmed) return;
    await act(
      () => apiFetch(`/api/zones/records/${record.id}`, token, { method: "DELETE" }),
      "解析记录已删除"
    );
  }

  async function confirmManageRecord() {
    if (!manageRecord) return;
    await act(
      () =>
        apiFetch("/api/groups", token, {
          method: "POST",
          body: JSON.stringify({
            zone_id: manageRecord.zone_id,
            hostname: manageRecord.name,
            ttl: manageRecord.ttl >= 30 ? manageRecord.ttl : 60,
            primary_port: managePort,
            enabled: true,
            min_switch_interval_seconds: 120,
            adopt_record_id: manageRecord.cf_record_id
          })
        }),
      "故障切换组已创建",
      () => {
        setManageRecord(null);
        setSection("groups");
      }
    );
  }

  return (
    <section className="panel">
      <div className="zoneSearchBox">
        <div className="searchBar">
          <input
            value={zoneQuery}
            onChange={(event) => setZoneQuery(event.target.value)}
            placeholder="搜索域名区域"
          />
          <span>{filteredZones.length}/{zones.length}</span>
        </div>
        <div className="zoneResultList">
          {filteredZones.slice(0, 12).map((zone) => (
            <button type="button" className={zone.id === selectedZoneId ? "zonePill active" : "zonePill"} key={zone.id} onClick={() => setSelectedZoneId(zone.id)}>
              {zone.name}
            </button>
          ))}
          {filteredZones.length === 0 && <span>没有匹配的域名区域</span>}
        </div>
      </div>
      <div className="toolbar">
        <div className="selectedZoneLabel">当前域名：{selectedZone ? selectedZone.name : "未选择"}</div>
        <button disabled={!selectedZoneId} onClick={openAddRecord}>
          <Plus size={16} />
          <span>添加解析</span>
        </button>
        <button className="secondary" disabled={!selectedZoneId} onClick={() => act(() => apiFetch(`/api/zones/${selectedZoneId}/records/sync`, token, { method: "POST" }), "解析记录已同步")}>
          <RefreshCw size={16} />
          <span>同步</span>
        </button>
      </div>
      <div className="searchBar">
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="搜索记录名称、类型或内容"
        />
        <span>{filteredRecords.length}/{records.length}</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>名称</th>
            <th>类型</th>
            <th>内容</th>
            <th>TTL</th>
            <th>代理状态</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {filteredRecords.map((record) => (
            <tr key={record.id}>
              <td>{record.name}</td>
              <td><Badge value={record.type} /></td>
              <td className="mono">{record.content}</td>
              <td>{record.ttl}</td>
              <td>{record.proxied ? "已代理" : "仅 DNS"}</td>
              <td>
                <div className="rowActions">
                  <button className="icon secondaryIcon" title="修改记录" onClick={() => openEditRecord(record)}>
                    <Pencil size={16} />
                  </button>
                  <button className="icon" title="管理" disabled={record.proxied} onClick={() => openManageRecord(record)}>
                    <Link2 size={16} />
                  </button>
                  <button className="icon dangerBtn" title="删除记录" onClick={() => deleteRecord(record)}>
                    <Trash2 size={16} />
                  </button>
                </div>
              </td>
            </tr>
          ))}
          {filteredRecords.length === 0 && (
            <tr>
              <td colSpan={6} className="emptyCell">没有匹配的解析记录</td>
            </tr>
          )}
        </tbody>
      </table>
      {addRecordOpen && (
        <div className="modalBackdrop" role="dialog" aria-modal="true">
          <div className="modalPanel">
            <div className="panelTitle">
              <h2>添加解析记录</h2>
              <p>名称可填 @、www，或完整域名；内容支持 IPv4、IPv6 或域名。</p>
            </div>
            <div className="modalFormGrid">
              <label>
                记录名称
                <input value={recordAdd.name} onChange={(event) => setRecordAdd((draft) => ({ ...draft, name: event.target.value }))} placeholder="例如 @、www 或 www.example.com" />
              </label>
              <label>
                类型
                <select value={recordAdd.type} onChange={(event) => setRecordAdd((draft) => ({ ...draft, type: event.target.value as DnsRecordType }))}>
                  {dnsRecordTypes.map((type) => (
                    <option key={type} value={type}>{type}</option>
                  ))}
                </select>
              </label>
              <label>
                内容
                <input value={recordAdd.content} onChange={(event) => updateAddRecordContent(event.target.value)} placeholder="IPv4、IPv6 或域名" />
              </label>
              <label>
                TTL（秒）
                <input type="number" min={1} max={86400} value={recordAdd.ttl} onChange={(event) => setRecordAdd((draft) => ({ ...draft, ttl: Number(event.target.value) }))} />
              </label>
              <label className="inlineCheck">
                <input type="checkbox" checked={recordAdd.proxied} onChange={(event) => setRecordAdd((draft) => ({ ...draft, proxied: event.target.checked }))} />
                Cloudflare 代理（橙云）
              </label>
            </div>
            <div className="confirmRecordBox">
              <span>域名区域</span>
              <strong>{selectedZone ? selectedZone.name : "-"}</strong>
              <span>代理状态</span>
              <strong>{recordAdd.proxied ? "已代理" : "仅 DNS"}</strong>
            </div>
            <div className="modalActions">
              <button type="button" className="secondary" onClick={() => setAddRecordOpen(false)}>取消</button>
              <button type="button" onClick={saveRecordAdd}>
                <Plus size={16} />
                <span>确认添加</span>
              </button>
            </div>
          </div>
        </div>
      )}
      {editRecord && (
        <div className="modalBackdrop" role="dialog" aria-modal="true">
          <div className="modalPanel">
            <div className="panelTitle">
              <h2>修改解析记录</h2>
              <p>会直接修改 Cloudflare 上的记录。A/AAAA/CNAME 会按内容自动识别，也可以手动选择。</p>
            </div>
            <div className="modalFormGrid">
              <label>
                记录名称
                <input value={recordEdit.name} onChange={(event) => setRecordEdit((draft) => ({ ...draft, name: event.target.value }))} placeholder="例如 www.example.com 或 @" />
              </label>
              <label>
                类型
                <select value={recordEdit.type} onChange={(event) => setRecordEdit((draft) => ({ ...draft, type: event.target.value as DnsRecordType }))}>
                  {dnsRecordTypes.map((type) => (
                    <option key={type} value={type}>{type}</option>
                  ))}
                </select>
              </label>
              <label>
                内容
                <input value={recordEdit.content} onChange={(event) => updateRecordContent(event.target.value)} placeholder="IPv4、IPv6 或域名" />
              </label>
              <label>
                TTL（秒）
                <input type="number" min={1} max={86400} value={recordEdit.ttl} onChange={(event) => setRecordEdit((draft) => ({ ...draft, ttl: Number(event.target.value) }))} />
              </label>
              <label className="inlineCheck">
                <input type="checkbox" checked={recordEdit.proxied} onChange={(event) => setRecordEdit((draft) => ({ ...draft, proxied: event.target.checked }))} />
                Cloudflare 代理（橙云）
              </label>
            </div>
            <div className="confirmRecordBox">
              <span>记录 ID</span>
              <strong>{editRecord.cf_record_id}</strong>
              <span>代理状态</span>
              <strong>{recordEdit.proxied ? "已代理" : "仅 DNS"}</strong>
            </div>
            <div className="modalActions">
              <button type="button" className="secondary" onClick={() => setEditRecord(null)}>取消</button>
              <button type="button" onClick={saveRecordEdit}>
                <Save size={16} />
                <span>保存修改</span>
              </button>
            </div>
          </div>
        </div>
      )}
      {manageRecord && (
        <div className="modalBackdrop" role="dialog" aria-modal="true">
          <div className="modalPanel">
            <div className="panelTitle">
              <h2>加入故障切换</h2>
              <p>确认后会把这条解析记录接管为主用目标，并自动创建对应的故障切换组。</p>
            </div>
            <div className="confirmRecordBox">
              <span>主机名</span>
              <strong>{manageRecord.name}</strong>
              <span>当前解析</span>
              <strong>{manageRecord.type} {manageRecord.content}</strong>
              <span>TTL</span>
              <strong>{manageRecord.ttl}</strong>
            </div>
            <label>
              主用检查端口
              <input type="number" min={1} max={65535} value={managePort} onChange={(event) => setManagePort(Number(event.target.value))} />
            </label>
            <div className="modalActions">
              <button type="button" className="secondary" onClick={() => setManageRecord(null)}>取消</button>
              <button type="button" onClick={confirmManageRecord}>
                <Plus size={16} />
                <span>确认添加</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

function TargetPoolPanel({ token, targetPool, groups, act }: { token: string; targetPool: TargetPoolItem[]; groups: FailoverGroup[]; act: ActionRunner }) {
  const [poolDraft, setPoolDraft] = useState<TargetPoolDraft>(defaultTargetPoolDraft);
  const [batchText, setBatchText] = useState("");
  const [batchPort, setBatchPort] = useState(22);
  const [batchInterval, setBatchInterval] = useState(600);
  const [batchRemark, setBatchRemark] = useState("");
  const [editingPoolId, setEditingPoolId] = useState<number | null>(null);
  const [poolEdits, setPoolEdits] = useState<Record<number, TargetPoolDraft>>({});
  const [selectedPoolIds, setSelectedPoolIds] = useState<Set<number>>(new Set());
  const [assignModalOpen, setAssignModalOpen] = useState(false);
  const [assignAllGroups, setAssignAllGroups] = useState(true);
  const [assignGroupIds, setAssignGroupIds] = useState<Set<number>>(new Set());
  const [assignPriority, setAssignPriority] = useState(10);
  const selectedPoolItems = targetPool.filter((item) => selectedPoolIds.has(item.id));
  const allPoolSelected = targetPool.length > 0 && targetPool.every((item) => selectedPoolIds.has(item.id));

  async function createPoolItem(event: FormEvent) {
    event.preventDefault();
    await act(
      () =>
        apiFetch("/api/target-pool", token, {
          method: "POST",
          body: JSON.stringify({
            target: poolDraft.target.trim(),
            port: poolDraft.port,
            remark: poolDraft.remark.trim() || null,
            check_interval_seconds: poolDraft.check_interval_seconds,
            enabled: poolDraft.enabled
          })
        }),
      "目标已加入池子",
      () => setPoolDraft(defaultTargetPoolDraft)
    );
  }

  function parseBatchTargets() {
    return batchText
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"))
      .map((line) => {
        const parts = line.includes(",") ? line.split(",").map((part) => part.trim()) : line.split(/\s+/);
        const target = parts[0] || "";
        const port = parts[1] ? Number(parts[1]) : batchPort;
        const remark = parts.slice(2).join(" ").trim() || batchRemark.trim() || null;
        return {
          target,
          port,
          remark,
          check_interval_seconds: batchInterval,
          enabled: true
        };
      });
  }

  async function createBatchPoolItems(event: FormEvent) {
    event.preventDefault();
    const items = parseBatchTargets();
    if (items.length === 0) {
      await act(async () => {
        throw new Error("请先输入要批量添加的 IP 或域名");
      });
      return;
    }
    const invalid = items.find((item) => !item.target || !Number.isInteger(item.port) || item.port < 1 || item.port > 65535);
    if (invalid) {
      await act(async () => {
        throw new Error(`批量内容格式有误：${invalid.target || "空目标"}`);
      });
      return;
    }
    await act(
      () =>
        apiFetch("/api/target-pool/bulk", token, {
          method: "POST",
          body: JSON.stringify({ items })
        }),
      "批量添加已完成",
      () => setBatchText("")
    );
  }

  function beginEditPoolItem(item: TargetPoolItem) {
    setEditingPoolId(item.id);
    setPoolEdits((current) => ({
      ...current,
      [item.id]: {
        target: item.target,
        port: item.port,
        remark: item.remark || "",
        check_interval_seconds: item.check_interval_seconds,
        enabled: item.enabled
      }
    }));
  }

  async function savePoolItem(itemId: number) {
    const draft = poolEdits[itemId];
    if (!draft) return;
    await act(
      () =>
        apiFetch(`/api/target-pool/${itemId}`, token, {
          method: "PATCH",
          body: JSON.stringify({
            target: draft.target.trim(),
            port: draft.port,
            remark: draft.remark.trim() || null,
            check_interval_seconds: draft.check_interval_seconds,
            enabled: draft.enabled
          })
        }),
      "目标池已更新",
      () => setEditingPoolId(null)
    );
  }

  function togglePoolSelected(itemId: number) {
    setSelectedPoolIds((current) => {
      const next = new Set(current);
      if (next.has(itemId)) {
        next.delete(itemId);
      } else {
        next.add(itemId);
      }
      return next;
    });
  }

  function toggleAllPoolSelected() {
    setSelectedPoolIds((current) => {
      if (targetPool.length > 0 && targetPool.every((item) => current.has(item.id))) {
        return new Set();
      }
      return new Set(targetPool.map((item) => item.id));
    });
  }

  async function openAssignModal() {
    if (selectedPoolItems.length === 0) {
      await act(async () => {
        throw new Error("请先选择要加入故障组的池子目标");
      });
      return;
    }
    if (groups.length === 0) {
      await act(async () => {
        throw new Error("还没有可加入的故障切换组");
      });
      return;
    }
    setAssignAllGroups(true);
    setAssignGroupIds(new Set(groups.map((group) => group.id)));
    setAssignModalOpen(true);
  }

  function toggleAssignGroup(groupId: number) {
    setAssignGroupIds((current) => {
      const next = new Set(current);
      if (next.has(groupId)) {
        next.delete(groupId);
      } else {
        next.add(groupId);
      }
      return next;
    });
  }

  function toggleAssignAllVisibleGroups() {
    setAssignGroupIds((current) => {
      if (groups.length > 0 && groups.every((group) => current.has(group.id))) {
        return new Set();
      }
      return new Set(groups.map((group) => group.id));
    });
  }

  async function assignSelectedPoolToGroups() {
    const groupIds = Array.from(assignGroupIds);
    if (!assignAllGroups && groupIds.length === 0) {
      await act(async () => {
        throw new Error("请选择至少一个故障切换组");
      });
      return;
    }
    await act(
      () =>
        apiFetch("/api/target-pool/assign-to-groups", token, {
          method: "POST",
          body: JSON.stringify({
            item_ids: selectedPoolItems.map((item) => item.id),
            all_groups: assignAllGroups,
            group_ids: assignAllGroups ? [] : groupIds,
            priority: assignPriority,
            enabled: true
          })
        }),
      "池子目标已加入故障组",
      () => {
        setAssignModalOpen(false);
        setSelectedPoolIds(new Set());
      }
    );
  }

  return (
    <section className="stack">
      <div className="panelTitle groupsIntro">
        <h2>IP 池子</h2>
        <p>把常用 IP、IPv6 或域名放进池子，故障切换组添加备用时可直接选择。</p>
      </div>
      <div className="targetPoolPanel">
        <div className="targetPoolTools">
          <form className="panel targetPoolForm" onSubmit={createPoolItem}>
            <div className="panelTitle">
              <h2>单个添加</h2>
              <p>支持 IPv4、IPv6 和域名，系统会自动识别发布类型。</p>
            </div>
            <div className="poolFormGrid">
              <label>
                IP / IPv6 / 域名
                <input placeholder="例如 192.0.2.10" value={poolDraft.target} onChange={(event) => setPoolDraft((current) => ({ ...current, target: event.target.value }))} required />
              </label>
              <label>
                检查端口
                <input type="number" min={1} max={65535} value={poolDraft.port} onChange={(event) => setPoolDraft((current) => ({ ...current, port: Number(event.target.value) }))} />
              </label>
            </div>
            <label>
              备注
              <input placeholder="例如 香港备用、洛杉矶 1 号" value={poolDraft.remark} onChange={(event) => setPoolDraft((current) => ({ ...current, remark: event.target.value }))} />
            </label>
            <button>
              <Plus size={16} />
              <span>加入池子</span>
            </button>
          </form>
          <form className="panel targetPoolForm" onSubmit={createBatchPoolItems}>
            <div className="panelTitle">
              <h2>批量添加</h2>
              <p>每行一个目标；也可以写成：目标,端口,备注。</p>
            </div>
            <label>
              批量目标
              <textarea
                rows={8}
                placeholder={"8.8.8.8\n1.1.1.1,443,Cloudflare\n2001:4860:4860::8888"}
                value={batchText}
                onChange={(event) => setBatchText(event.target.value)}
              />
            </label>
            <div className="batchPoolGrid">
              <label>
                默认端口
                <input type="number" min={1} max={65535} value={batchPort} onChange={(event) => setBatchPort(Number(event.target.value))} />
              </label>
            </div>
            <label>
              默认备注
              <input placeholder="每行没有备注时使用" value={batchRemark} onChange={(event) => setBatchRemark(event.target.value)} />
            </label>
            <button>
              <Plus size={16} />
              <span>批量加入</span>
            </button>
          </form>
        </div>
        <div className="panel poolListPanel">
          <div className="panelTitle">
            <h2>池子列表</h2>
            <p>故障切换组里点击添加备用，即可从这里选择目标。</p>
          </div>
          <div className="poolBulkBar">
            <label className="inlineCheck">
              <input type="checkbox" checked={allPoolSelected} onChange={toggleAllPoolSelected} disabled={targetPool.length === 0} />
              全选池子目标
            </label>
            <span>已选 {selectedPoolItems.length}/{targetPool.length}</span>
            <button className="secondary compactBtn" type="button" disabled={selectedPoolItems.length === 0 || groups.length === 0} onClick={openAssignModal}>
              <Plus size={15} />
              <span>加入故障组</span>
            </button>
          </div>
          <div className="poolList">
            {targetPool.map((item) => {
              const edit = poolEdits[item.id] || {
                target: item.target,
                port: item.port,
                remark: item.remark || "",
                check_interval_seconds: item.check_interval_seconds,
                enabled: item.enabled
              };
              return (
                <div className="poolItem" key={item.id}>
                  <label className="poolSelectCheck" title="选择这个池子目标">
                    <input type="checkbox" checked={selectedPoolIds.has(item.id)} onChange={() => togglePoolSelected(item.id)} />
                  </label>
                  {editingPoolId === item.id ? (
                    <>
                      <div className="poolEditGrid">
                        <input value={edit.target} onChange={(event) => setPoolEdits((current) => ({ ...current, [item.id]: { ...edit, target: event.target.value } }))} />
                        <input type="number" min={1} max={65535} value={edit.port} onChange={(event) => setPoolEdits((current) => ({ ...current, [item.id]: { ...edit, port: Number(event.target.value) } }))} />
                        <input value={edit.remark} onChange={(event) => setPoolEdits((current) => ({ ...current, [item.id]: { ...edit, remark: event.target.value } }))} placeholder="备注" />
                        <label className="inlineCheck">
                          <input type="checkbox" checked={edit.enabled} onChange={(event) => setPoolEdits((current) => ({ ...current, [item.id]: { ...edit, enabled: event.target.checked } }))} />
                          启用
                        </label>
                      </div>
                      <div className="rowActions">
                        <button className="icon" title="保存" onClick={() => savePoolItem(item.id)}>
                          <Save size={15} />
                        </button>
                        <button className="icon secondaryIcon" title="取消" onClick={() => setEditingPoolId(null)}>
                          ×
                        </button>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="poolItemMain">
                        <strong title={`${item.target}:${item.port}`}>{displayTargetWithRemark(item.target, item.port, item.remark)}</strong>
                        <span>{targetTypeText(item.target_type)} · 发布为 {recordTypeForTargetType(item.target_type)} · 备用仓库，不做连通性检测</span>
                      </div>
                      <div className="rowActions">
                        <Status value={item.enabled ? "enabled" : "disabled"} />
                        <button className="icon secondaryIcon" title="修改" onClick={() => beginEditPoolItem(item)}>
                          <Pencil size={15} />
                        </button>
                        <button className="icon dangerBtn" title="删除" onClick={() => act(() => apiFetch(`/api/target-pool/${item.id}`, token, { method: "DELETE" }), "目标已删除")}>
                          <Trash2 size={15} />
                        </button>
                      </div>
                    </>
                  )}
                </div>
              );
            })}
            {targetPool.length === 0 && <div className="emptyCell">还没有池子目标</div>}
          </div>
        </div>
      </div>
      {assignModalOpen && (
        <div className="modalBackdrop" role="dialog" aria-modal="true">
          <div className="modalPanel wideModal">
            <div className="panelTitle">
              <h2>池子目标加入故障组</h2>
              <p>把已选择的池子目标批量加入为备用源站；同组已存在的相同 IP/端口会自动跳过。</p>
            </div>
            <div className="bulkAssignSummary">
              <span>已选池子目标</span>
              <div>
                {selectedPoolItems.map((item) => (
                  <code key={item.id}>{displayTargetWithRemark(item.target, item.port, item.remark)}</code>
                ))}
              </div>
            </div>
            <div className="modalFormGrid">
              <label>
                统一优先级
                <input type="number" min={0} max={100000} value={assignPriority} onChange={(event) => setAssignPriority(Number(event.target.value))} />
              </label>
              <label className="inlineCheck assignAllCheck">
                <input type="checkbox" checked={assignAllGroups} onChange={(event) => setAssignAllGroups(event.target.checked)} />
                加入所有故障切换组
              </label>
            </div>
            {!assignAllGroups && (
              <div className="groupPicker">
                <div className="groupPickerHead">
                  <strong>选择故障切换组</strong>
                  <button type="button" className="miniBtn" onClick={toggleAssignAllVisibleGroups}>
                    {groups.every((group) => assignGroupIds.has(group.id)) ? "取消全选" : "全选"}
                  </button>
                </div>
                <div className="groupPickerList">
                  {groups.map((group) => (
                    <label className="groupPickerItem" key={group.id}>
                      <input type="checkbox" checked={assignGroupIds.has(group.id)} onChange={() => toggleAssignGroup(group.id)} />
                      <span>
                        <strong>{group.hostname}</strong>
                        <em>{group.enabled ? "已启用" : "已停用"} · 源站 {group.origins.length} 个</em>
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            )}
            <div className="modalActions">
              <button type="button" className="secondary" onClick={() => setAssignModalOpen(false)}>取消</button>
              <button type="button" onClick={assignSelectedPoolToGroups}>
                <Plus size={16} />
                <span>确认加入</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

function GroupsPanel({
  token,
  collections,
  groups,
  targetPool,
  externalIpItems,
  agents,
  act
}: {
  token: string;
  collections: FailoverCollection[];
  groups: FailoverGroup[];
  targetPool: TargetPoolItem[];
  externalIpItems: ExternalIpItem[];
  agents: Agent[];
  act: ActionRunner;
}) {
  const [collectionDraft, setCollectionDraft] = useState<CollectionDraft>({ name: "" });
  const [editingCollectionId, setEditingCollectionId] = useState<number | null>(null);
  const [collectionEdits, setCollectionEdits] = useState<Record<number, CollectionDraft>>({});
  const [addingGlobalCollectionId, setAddingGlobalCollectionId] = useState<number | null>(null);
  const [globalOriginAdd, setGlobalOriginAdd] = useState<GlobalOriginDraft>(defaultGlobalOriginDraft);
  const [editingGlobalOriginId, setEditingGlobalOriginId] = useState<number | null>(null);
  const [globalOriginEdits, setGlobalOriginEdits] = useState<Record<number, GlobalOriginDraft>>({});
  const [addingGroupId, setAddingGroupId] = useState<number | null>(null);
  const [originAdd, setOriginAdd] = useState<OriginAddDraft>(defaultOriginAddDraft);
  const [editingGroupId, setEditingGroupId] = useState<number | null>(null);
  const [groupEdits, setGroupEdits] = useState<Record<number, GroupEditDraft>>({});
  const [addingHostnameGroupId, setAddingHostnameGroupId] = useState<number | null>(null);
  const [hostnameAdd, setHostnameAdd] = useState<HostnameAddDraft>({ hostname: "", adopt_record_id: "" });
  const [editingOriginId, setEditingOriginId] = useState<number | null>(null);
  const [originEdits, setOriginEdits] = useState<Record<number, OriginEditDraft>>({});
  const [collapsedCollectionIds, setCollapsedCollectionIds] = useState<Set<string>>(new Set());
  const [collapsedGroupIds, setCollapsedGroupIds] = useState<Set<number>>(new Set());
  const addingGlobalCollection = addingGlobalCollectionId ? collections.find((collection) => collection.id === addingGlobalCollectionId) : undefined;
  const addingGroup = addingGroupId ? groups.find((group) => group.id === addingGroupId) : undefined;
  const addingHostnameGroup = addingHostnameGroupId ? groups.find((group) => group.id === addingHostnameGroupId) : undefined;
  const enabledPoolItems = targetPool.filter((item) => item.enabled);
  const healthyExternalItems = externalIpItems.filter((item) => item.status === "healthy");
  const addTargetType = inferDraftTargetType(originAdd.target);
  const globalAddTargetType = inferDraftTargetType(globalOriginAdd.target);
  const selectedPoolItemId = enabledPoolItems.find((item) => item.target === originAdd.target && item.port === originAdd.port)?.id || "";
  const selectedExternalItemId = healthyExternalItems.find((item) => item.target === originAdd.target && item.port === originAdd.port)?.id || "";
  const selectedGlobalPoolItemId = enabledPoolItems.find((item) => item.target === globalOriginAdd.target && item.port === globalOriginAdd.port)?.id || "";
  const selectedGlobalExternalItemId = healthyExternalItems.find((item) => item.target === globalOriginAdd.target && item.port === globalOriginAdd.port)?.id || "";
  const groupedSections = useMemo(() => {
    const sortedCollections = [...collections].sort((left, right) => left.name.localeCompare(right.name) || left.id - right.id);
    const sortedGroups = [...groups].sort((left, right) => left.hostname.localeCompare(right.hostname) || left.id - right.id);
    const sections: { collection: FailoverCollection | null; groups: FailoverGroup[] }[] = sortedCollections.map((collection) => ({
      collection,
      groups: sortedGroups.filter((group) => group.collection_id === collection.id)
    }));
    const ungrouped = sortedGroups.filter((group) => !group.collection_id);
    if (ungrouped.length > 0) {
      sections.push({ collection: null, groups: ungrouped });
    }
    return sections;
  }, [collections, groups]);

  async function createCollection(event: FormEvent) {
    event.preventDefault();
    await act(
      () => {
        if (!collectionDraft.name.trim()) {
          throw new Error("请填写业务分组名称");
        }
        return apiFetch("/api/groups/collections", token, {
          method: "POST",
          body: JSON.stringify({ name: collectionDraft.name.trim() })
        });
      },
      "业务分组已创建",
      () => setCollectionDraft({ name: "" })
    );
  }

  function beginEditCollection(collection: FailoverCollection) {
    setEditingCollectionId(collection.id);
    setCollectionEdits((current) => ({ ...current, [collection.id]: { name: collection.name } }));
  }

  async function saveCollectionEdit(collectionId: number) {
    const draft = collectionEdits[collectionId];
    if (!draft) return;
    await act(
      () =>
        apiFetch(`/api/groups/collections/${collectionId}`, token, {
          method: "PATCH",
          body: JSON.stringify({ name: draft.name.trim() })
        }),
      "业务分组已更新",
      () => setEditingCollectionId(null)
    );
  }

  function beginAddGlobalOrigin(collection: FailoverCollection) {
    const maxPriority = collection.global_origins.reduce((value, origin) => Math.max(value, origin.priority), 0);
    setAddingGlobalCollectionId(collection.id);
    setGlobalOriginAdd({
      target: "",
      port: 22,
      priority: maxPriority + 10,
      publish_mode: "direct",
      expanded_ip_priorities: {},
      preferred_agent_id: "",
      probe_mode: "default",
      remark: "",
      enabled: true
    });
  }

  async function createGlobalOrigin() {
    if (!addingGlobalCollection) return;
    await act(
      () => {
        if (!globalOriginAdd.target.trim()) {
          throw new Error("请填写全局备用目标");
        }
        return apiFetch(`/api/groups/collections/${addingGlobalCollection.id}/global-origins`, token, {
          method: "POST",
          body: JSON.stringify({
            target: globalOriginAdd.target.trim(),
            port: globalOriginAdd.port,
            priority: globalOriginAdd.priority,
            publish_mode: globalAddTargetType === "hostname" ? globalOriginAdd.publish_mode : "direct",
            expanded_ip_priorities: globalAddTargetType === "hostname" ? globalOriginAdd.expanded_ip_priorities : {},
            preferred_agent_id: globalOriginAdd.preferred_agent_id === "" ? null : globalOriginAdd.preferred_agent_id,
            probe_mode: globalOriginAdd.probe_mode,
            remark: globalOriginAdd.remark.trim() || null,
            enabled: globalOriginAdd.enabled
          })
        });
      },
      "全局备用已同步到该业务分组",
      () => {
        setAddingGlobalCollectionId(null);
        setGlobalOriginAdd(defaultGlobalOriginDraft);
      }
    );
  }

  function beginEditGlobalOrigin(origin: FailoverGlobalOrigin) {
    setEditingGlobalOriginId(origin.id);
    setGlobalOriginEdits((current) => ({
      ...current,
      [origin.id]: {
        target: origin.target,
        port: origin.port,
        priority: origin.priority,
        publish_mode: origin.publish_mode === "expanded" ? "expanded" : "direct",
        expanded_ip_priorities: { ...(origin.expanded_ip_priorities || {}) },
        preferred_agent_id: origin.preferred_agent_id || "",
        probe_mode: normalizeProbeMode(origin.probe_mode),
        remark: origin.remark || "",
        enabled: origin.enabled
      }
    }));
  }

  async function saveGlobalOriginEdit(originId: number) {
    const draft = globalOriginEdits[originId];
    if (!draft) return;
    const targetType = inferDraftTargetType(draft.target);
    await act(
      () =>
        apiFetch(`/api/groups/global-origins/${originId}`, token, {
          method: "PATCH",
          body: JSON.stringify({
            ...draft,
            target: draft.target.trim(),
            remark: draft.remark.trim() || null,
            publish_mode: targetType === "hostname" ? draft.publish_mode : "direct",
            preferred_agent_id: draft.preferred_agent_id === "" ? null : draft.preferred_agent_id,
            probe_mode: draft.probe_mode
          })
        }),
      "全局备用已同步更新",
      () => setEditingGlobalOriginId(null)
    );
  }

  function beginAddOrigin(group: FailoverGroup) {
    const maxPriority = group.origins.reduce((value, origin) => Math.max(value, origin.priority), 0);
    expandGroup(group.id);
    setAddingGroupId(group.id);
    setOriginAdd({
      target: "",
      port: 22,
      priority: maxPriority + 10,
      publish_mode: "direct",
      expanded_ip_priorities: {},
      preferred_agent_id: "",
      probe_mode: "default",
      remark: "",
      enabled: true
    });
  }

  function selectPoolItem(itemId: number) {
    const item = targetPool.find((poolItem) => poolItem.id === itemId);
    if (!item) return;
    setOriginAdd((current) => ({
      ...current,
      target: item.target,
      port: item.port || 22,
      publish_mode: "direct",
      expanded_ip_priorities: {},
      preferred_agent_id: current.preferred_agent_id,
      remark: item.remark || "",
      enabled: true
    }));
  }

  function selectGlobalPoolItem(itemId: number) {
    const item = targetPool.find((poolItem) => poolItem.id === itemId);
    if (!item) return;
    setGlobalOriginAdd((current) => ({
      ...current,
      target: item.target,
      port: item.port || 22,
      publish_mode: "direct",
      expanded_ip_priorities: {},
      preferred_agent_id: current.preferred_agent_id,
      remark: item.remark || "",
      enabled: true
    }));
  }

  async function createOrigin() {
    if (!addingGroup) return;
    await act(
      () => {
        if (!originAdd.target.trim()) {
          throw new Error("请填写备用目标");
        }
        return apiFetch(`/api/groups/${addingGroup.id}/origins`, token, {
          method: "POST",
          body: JSON.stringify({
            target: originAdd.target.trim(),
            port: originAdd.port,
            priority: originAdd.priority,
            publish_mode: addTargetType === "hostname" ? originAdd.publish_mode : "direct",
            expanded_ip_priorities: addTargetType === "hostname" ? originAdd.expanded_ip_priorities : {},
            preferred_agent_id: originAdd.preferred_agent_id === "" ? null : originAdd.preferred_agent_id,
            probe_mode: originAdd.probe_mode,
            remark: originAdd.remark.trim() || null,
            enabled: originAdd.enabled
          })
        });
      },
      "备用目标已添加",
      () => {
        setAddingGroupId(null);
        setOriginAdd(defaultOriginAddDraft);
      }
    );
  }

  function beginAddHostname(group: FailoverGroup) {
    expandGroup(group.id);
    setAddingHostnameGroupId(group.id);
    setHostnameAdd({ hostname: "", adopt_record_id: "" });
  }

  async function createHostname() {
    if (!addingHostnameGroup) return;
    await act(
      () => {
        if (!hostnameAdd.hostname.trim()) {
          throw new Error("请填写主域名");
        }
        return apiFetch(`/api/groups/${addingHostnameGroup.id}/hostnames`, token, {
          method: "POST",
          body: JSON.stringify({
            hostname: hostnameAdd.hostname.trim(),
            adopt_record_id: hostnameAdd.adopt_record_id.trim() || null
          })
        });
      },
      "主域名已添加并应用",
      () => {
        setAddingHostnameGroupId(null);
        setHostnameAdd({ hostname: "", adopt_record_id: "" });
      }
    );
  }

  async function deleteHostname(hostnameId: number, hostname: string) {
    if (!window.confirm(`确认取消接管主域名 ${hostname} 吗？\nCloudflare 上的 DNS 记录不会被删除。`)) {
      return;
    }
    await act(
      () => apiFetch(`/api/groups/hostnames/${hostnameId}`, token, { method: "DELETE" }),
      "主域名已取消接管"
    );
  }

  function beginEditGroup(group: FailoverGroup) {
    expandGroup(group.id);
    setEditingGroupId(group.id);
    setGroupEdits((current) => ({
      ...current,
      [group.id]: {
        ttl: group.ttl,
        min_switch_interval_seconds: group.min_switch_interval_seconds,
        enabled: group.enabled,
        collection_id: group.collection_id || ""
      }
    }));
  }

  async function saveGroupEdit(groupId: number) {
    const draft = groupEdits[groupId];
    if (!draft) return;
    await act(
      () =>
        apiFetch(`/api/groups/${groupId}`, token, {
          method: "PATCH",
          body: JSON.stringify({
            ...draft,
            collection_id: draft.collection_id === "" ? null : draft.collection_id
          })
        }),
      "切换组已更新并应用",
      () => setEditingGroupId(null)
    );
  }

  function beginEditOrigin(origin: Origin) {
    setEditingOriginId(origin.id);
    setOriginEdits((current) => ({
      ...current,
      [origin.id]: {
        target: origin.target,
        port: origin.port,
        priority: origin.priority,
        publish_mode: origin.publish_mode === "expanded" ? "expanded" : "direct",
        expanded_ip_priorities: { ...(origin.expanded_ip_priorities || {}) },
        preferred_agent_id: origin.preferred_agent_id || "",
        probe_mode: normalizeProbeMode(origin.probe_mode),
        remark: origin.remark || "",
        enabled: origin.enabled
      }
    }));
  }

  async function saveOriginEdit(originId: number) {
    const draft = originEdits[originId];
    if (!draft) return;
    const targetType = inferDraftTargetType(draft.target);
    const payload = {
      ...draft,
      publish_mode: targetType === "hostname" ? draft.publish_mode : "direct",
      preferred_agent_id: draft.preferred_agent_id === "" ? null : draft.preferred_agent_id,
      probe_mode: draft.probe_mode
    };
    await act(
      () =>
        apiFetch(`/api/groups/origins/${originId}`, token, {
          method: "PATCH",
          body: JSON.stringify(payload)
        }),
      "源站已更新并应用",
      () => setEditingOriginId(null)
    );
  }

  function selectExternalIpItem(itemId: number) {
    const item = externalIpItems.find((externalItem) => externalItem.id === itemId);
    if (!item) return;
    setOriginAdd((current) => ({
      ...current,
      target: item.target,
      port: item.port || 22,
      publish_mode: "direct",
      expanded_ip_priorities: {},
      preferred_agent_id: current.preferred_agent_id,
      remark: item.name || "",
      enabled: true
    }));
  }

  function selectGlobalExternalIpItem(itemId: number) {
    const item = externalIpItems.find((externalItem) => externalItem.id === itemId);
    if (!item) return;
    setGlobalOriginAdd((current) => ({
      ...current,
      target: item.target,
      port: item.port || 22,
      publish_mode: "direct",
      expanded_ip_priorities: {},
      preferred_agent_id: current.preferred_agent_id,
      remark: item.name || "",
      enabled: true
    }));
  }

  function expandGroup(groupId: number) {
    setCollapsedGroupIds((current) => {
      if (!current.has(groupId)) return current;
      const next = new Set(current);
      next.delete(groupId);
      return next;
    });
  }

  function toggleGroupCollapsed(groupId: number) {
    setCollapsedGroupIds((current) => {
      const next = new Set(current);
      if (next.has(groupId)) {
        next.delete(groupId);
      } else {
        next.add(groupId);
      }
      return next;
    });
  }

  function collectionCollapseKey(collection: FailoverCollection | null): string {
    return collection ? String(collection.id) : "ungrouped";
  }

  function toggleCollectionCollapsed(collection: FailoverCollection | null) {
    const key = collectionCollapseKey(collection);
    setCollapsedCollectionIds((current) => {
      const next = new Set(current);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  }

  function renderGlobalOrigin(origin: FailoverGlobalOrigin) {
    const preferredAgent = origin.preferred_agent_id ? agents.find((agent) => agent.id === origin.preferred_agent_id) : null;
    const draft = globalOriginEdits[origin.id] || {
      target: origin.target,
      port: origin.port,
      priority: origin.priority,
      publish_mode: origin.publish_mode === "expanded" ? "expanded" : "direct",
      expanded_ip_priorities: { ...(origin.expanded_ip_priorities || {}) },
      preferred_agent_id: origin.preferred_agent_id || "",
      probe_mode: normalizeProbeMode(origin.probe_mode),
      remark: origin.remark || "",
      enabled: origin.enabled
    };
    const editType = inferDraftTargetType(draft.target);
    if (editingGlobalOriginId === origin.id) {
      return (
        <div className="globalOriginItem globalOriginEditing" key={origin.id}>
          <label>
            目标
            <input value={draft.target} onChange={(event) => setGlobalOriginEdits((current) => ({ ...current, [origin.id]: { ...draft, target: event.target.value } }))} />
          </label>
          <label>
            端口
            <input type="number" min={1} max={65535} value={draft.port} onChange={(event) => setGlobalOriginEdits((current) => ({ ...current, [origin.id]: { ...draft, port: Number(event.target.value) } }))} />
          </label>
          <label>
            优先级
            <input type="number" min={0} value={draft.priority} onChange={(event) => setGlobalOriginEdits((current) => ({ ...current, [origin.id]: { ...draft, priority: Number(event.target.value) } }))} />
          </label>
          <label>
            指定探针
            <select
              value={draft.preferred_agent_id}
              onChange={(event) =>
                setGlobalOriginEdits((current) => ({
                  ...current,
                  [origin.id]: { ...draft, preferred_agent_id: event.target.value ? Number(event.target.value) : "" }
                }))
              }
            >
              <option value="">跟随默认探针</option>
              {agents.map((agent) => (
                <option value={agent.id} key={agent.id}>
                  {agentSelectLabel(agent)}
                </option>
              ))}
            </select>
          </label>
          <label>
            探针策略
            <select
              value={draft.probe_mode}
              onChange={(event) =>
                setGlobalOriginEdits((current) => ({
                  ...current,
                  [origin.id]: { ...draft, probe_mode: event.target.value as ProbeMode }
                }))
              }
            >
              {probeModeOptions.map((option) => (
                <option value={option.value} key={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            备注
            <input value={draft.remark} onChange={(event) => setGlobalOriginEdits((current) => ({ ...current, [origin.id]: { ...draft, remark: event.target.value } }))} />
          </label>
          <label className="inlineCheck">
            <input
              type="checkbox"
              disabled={editType !== "hostname"}
              checked={editType === "hostname" && draft.publish_mode === "expanded"}
              onChange={(event) => setGlobalOriginEdits((current) => ({ ...current, [origin.id]: { ...draft, publish_mode: event.target.checked ? "expanded" : "direct" } }))}
            />
            展开 IP 池
          </label>
          <label className="inlineCheck">
            <input type="checkbox" checked={draft.enabled} onChange={(event) => setGlobalOriginEdits((current) => ({ ...current, [origin.id]: { ...draft, enabled: event.target.checked } }))} />
            启用
          </label>
          <div className="rowActions">
            <button className="icon" title="保存并同步" onClick={() => saveGlobalOriginEdit(origin.id)}>
              <Save size={15} />
            </button>
            <button className="icon secondaryIcon" title="取消" onClick={() => setEditingGlobalOriginId(null)}>
              ×
            </button>
          </div>
        </div>
      );
    }
    return (
      <div className="globalOriginItem" key={origin.id}>
        <div>
          <strong title={`${origin.target}:${origin.port}`}>{displayTargetWithRemark(origin.target, origin.port, origin.remark)}</strong>
          <span>
            {targetTypeText(origin.target_type)} · 优先级 {origin.priority} · 发布为 {recordTypeForTargetType(origin.target_type, origin.publish_mode)} · {origin.enabled ? "已启用" : "已停用"}
            {preferredAgent ? ` · 指定探针 ${preferredAgent.name}` : ""}
            {normalizeProbeMode(origin.probe_mode) !== "default" ? ` · ${probeModeText(origin.probe_mode)}` : ""}
          </span>
        </div>
        <div className="rowActions">
          <button className="icon secondaryIcon" title="修改全局备用" onClick={() => beginEditGlobalOrigin(origin)}>
            <Pencil size={15} />
          </button>
          <button className="icon dangerBtn" title="删除全局备用" onClick={() => act(() => apiFetch(`/api/groups/global-origins/${origin.id}`, token, { method: "DELETE" }), "全局备用已删除并同步")}>
            <Trash2 size={15} />
          </button>
        </div>
      </div>
    );
  }

  function renderCollectionHeader(collection: FailoverCollection | null, groupCount: number, isCollapsed: boolean) {
    if (!collection) {
      return (
        <div className="collectionHead ungrouped">
          <button type="button" className="collectionTitleButton" onClick={() => toggleCollectionCollapsed(collection)}>
            {isCollapsed ? <ChevronRight size={16} /> : <ChevronDown size={16} />}
            <div>
              <strong>未分组</strong>
              <span>{groupCount} 个切换组 · 移入业务分组后可使用全局备用</span>
            </div>
          </button>
        </div>
      );
    }
    const draft = collectionEdits[collection.id] || { name: collection.name };
    return (
      <div className="collectionHead">
        <div className="collectionMain">
          {editingCollectionId === collection.id ? (
            <div className="collectionEditLine">
              <input value={draft.name} onChange={(event) => setCollectionEdits((current) => ({ ...current, [collection.id]: { name: event.target.value } }))} />
              <button className="icon" title="保存业务分组" onClick={() => saveCollectionEdit(collection.id)}>
                <Save size={15} />
              </button>
              <button className="icon secondaryIcon" title="取消" onClick={() => setEditingCollectionId(null)}>
                ×
              </button>
            </div>
          ) : (
            <button type="button" className="collectionTitleButton" onClick={() => toggleCollectionCollapsed(collection)}>
              {isCollapsed ? <ChevronRight size={16} /> : <ChevronDown size={16} />}
              <div>
                <strong>{collection.name}</strong>
                <span>{groupCount} 个切换组 · 全局备用 {collection.global_origins.length} 个</span>
              </div>
            </button>
          )}
          {!isCollapsed && collection.global_origins.length > 0 && <div className="globalOriginList">{[...collection.global_origins].sort((left, right) => left.priority - right.priority || left.id - right.id).map(renderGlobalOrigin)}</div>}
          {isCollapsed && collection.global_origins.length > 0 && (
            <div className="collectionCollapsedSummary">
              <span>已折叠</span>
              <strong>全局备用 {collection.global_origins.length} 个</strong>
              <span>切换组 {groupCount} 个</span>
            </div>
          )}
        </div>
        <div className="rowActions">
          <button className="icon secondaryIcon" title={isCollapsed ? "展开业务分组" : "折叠业务分组"} onClick={() => toggleCollectionCollapsed(collection)}>
            {isCollapsed ? <ChevronRight size={15} /> : <ChevronDown size={15} />}
          </button>
          <button className="secondary compactBtn" onClick={() => beginAddGlobalOrigin(collection)}>
            <Plus size={15} />
            <span>全局备用</span>
          </button>
          <button className="icon secondaryIcon" title="修改业务分组" onClick={() => beginEditCollection(collection)}>
            <Pencil size={15} />
          </button>
          <button className="icon dangerBtn" title="删除业务分组" onClick={() => act(() => apiFetch(`/api/groups/collections/${collection.id}`, token, { method: "DELETE" }), "业务分组已删除")}>
            <Trash2 size={15} />
          </button>
        </div>
      </div>
    );
  }

  return (
    <section className="stack">
      <div className="panelTitle groupsIntro">
        <h2>故障切换组</h2>
        <p>从解析记录页接管主用解析；业务分组里的全局备用会自动同步到该分组下所有切换组。</p>
      </div>
      <form className="collectionCreateBar" onSubmit={createCollection}>
        <label>
          新建业务分组
          <input placeholder="例如 香港线路、美国线路、游戏业务" value={collectionDraft.name} onChange={(event) => setCollectionDraft({ name: event.target.value })} />
        </label>
        <button type="submit">
          <Plus size={16} />
          <span>创建分组</span>
        </button>
      </form>
      <div className="groupGrid">
        {groupedSections.map((section) => (
          <div className={`failoverCollectionBlock ${collapsedCollectionIds.has(collectionCollapseKey(section.collection)) ? "collectionCollapsed" : ""}`} key={section.collection?.id || "ungrouped"}>
            {renderCollectionHeader(section.collection, section.groups.length, collapsedCollectionIds.has(collectionCollapseKey(section.collection)))}
            {!collapsedCollectionIds.has(collectionCollapseKey(section.collection)) && (
            <div className="collectionGroupGrid">
        {section.groups.map((group) => {
          const groupEdit = groupEdits[group.id] || {
            ttl: group.ttl,
            min_switch_interval_seconds: group.min_switch_interval_seconds,
            enabled: group.enabled,
            collection_id: group.collection_id || ""
          };
          const sortedOrigins = [...group.origins].sort((left, right) => left.priority - right.priority || left.id - right.id);
          const primaryPriority = sortedOrigins[0]?.priority;
          const currentOrigin = sortedOrigins.find((origin) => origin.id === group.current_origin_id);
          const currentTarget = currentOrigin ? displayTargetWithRemark(currentOrigin.target, currentOrigin.port, currentOrigin.remark) : "未发布";
          const groupHostnames = group.hostnames && group.hostnames.length > 0 ? [...group.hostnames].sort((left, right) => left.id - right.id) : [];
          const groupLastCheckedAt = sortedOrigins.reduce<string | null>((latest, origin) => {
            if (!origin.last_checked_at) return latest;
            if (!latest) return origin.last_checked_at;
            return new Date(origin.last_checked_at).getTime() > new Date(latest).getTime() ? origin.last_checked_at : latest;
          }, null);
          const isCollapsed = collapsedGroupIds.has(group.id);
          return (
            <article className="groupCard" key={group.id}>
              <div className="groupHead">
                <div>
                  <div className="groupTitleLine">
                    <h2 className="groupHostname">{group.hostname}</h2>
                    <span className="groupRoleBadge">主域名 {Math.max(groupHostnames.length, 1)} 个</span>
                  </div>
                  <span className="groupMetaLine">TTL {group.ttl} · 源站 {sortedOrigins.length} 个 · 当前 {currentTarget} · 最后检测 {fmtDate(groupLastCheckedAt)}</span>
                  <div className="hostnameChips">
                    {(groupHostnames.length > 0 ? groupHostnames : [{ id: 0, hostname: group.hostname, current_record_id: group.current_record_id }]).map((hostname) => (
                      <span className={`hostnameChip ${hostname.hostname === group.hostname ? "primary" : ""}`} key={hostname.id || hostname.hostname}>
                        {hostname.hostname}
                        {groupHostnames.length > 1 && hostname.id > 0 && (
                          <button
                            className="hostnameDeleteButton"
                            type="button"
                            aria-label={`取消接管主域名 ${hostname.hostname}`}
                            title="取消接管这个主域名"
                            onClick={() => deleteHostname(hostname.id, hostname.hostname)}
                          >
                            <Trash2 size={13} />
                          </button>
                        )}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="rowActions">
                  <Status value={group.last_error ? "error" : group.enabled ? "enabled" : "disabled"} />
                  <button className="icon secondaryIcon" title={isCollapsed ? "展开切换组" : "折叠切换组"} onClick={() => toggleGroupCollapsed(group.id)}>
                    {isCollapsed ? <ChevronRight size={15} /> : <ChevronDown size={15} />}
                  </button>
                  <button className="secondary compactBtn" title="手动检测该组全部目标" onClick={() => act(() => apiFetch(`/api/groups/${group.id}/run`, token, { method: "POST" }), "切换组检测已完成")}>
                    <Play size={15} />
                    <span>检测全部</span>
                  </button>
                  <button className="secondary" title="添加备用目标" onClick={() => beginAddOrigin(group)}>
                    <Plus size={15} />
                    <span>添加备用</span>
                  </button>
                  <button className="secondary" title="添加主域名" onClick={() => beginAddHostname(group)}>
                    <Plus size={15} />
                    <span>主域名</span>
                  </button>
                  <button className="icon secondaryIcon" title="修改切换组" onClick={() => beginEditGroup(group)}>
                    <Pencil size={15} />
                  </button>
                  <button className="icon dangerBtn" title="删除切换组" onClick={() => act(() => apiFetch(`/api/groups/${group.id}`, token, { method: "DELETE" }), "切换组已删除")}>
                    <Trash2 size={15} />
                  </button>
                </div>
              </div>
              {isCollapsed ? (
                <div className="groupCollapsedSummary">
                  <span>已折叠</span>
                  <strong>{currentTarget}</strong>
                  <span>当前使用 · {sortedOrigins.length} 个源站</span>
                </div>
              ) : (
                <>
                  {editingGroupId === group.id && (
                    <div className="groupSettingsEdit">
                      <label>
                        TTL（秒）
                        <input type="number" min={30} max={86400} value={groupEdit.ttl} onChange={(event) => setGroupEdits((current) => ({ ...current, [group.id]: { ...groupEdit, ttl: Number(event.target.value) } }))} />
                      </label>
                      <label>
                        最小切换间隔（秒）
                        <input type="number" min={0} max={86400} value={groupEdit.min_switch_interval_seconds} onChange={(event) => setGroupEdits((current) => ({ ...current, [group.id]: { ...groupEdit, min_switch_interval_seconds: Number(event.target.value) } }))} />
                      </label>
                      <label>
                        业务分组
                        <select value={groupEdit.collection_id} onChange={(event) => setGroupEdits((current) => ({ ...current, [group.id]: { ...groupEdit, collection_id: event.target.value ? Number(event.target.value) : "" } }))}>
                          <option value="">未分组</option>
                          {collections.map((collection) => (
                            <option value={collection.id} key={collection.id}>
                              {collection.name}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label className="inlineCheck">
                        <input type="checkbox" checked={groupEdit.enabled} onChange={(event) => setGroupEdits((current) => ({ ...current, [group.id]: { ...groupEdit, enabled: event.target.checked } }))} />
                        启用这个切换组
                      </label>
                      <div className="rowActions">
                        <button className="icon" title="保存并应用" onClick={() => saveGroupEdit(group.id)}>
                          <Save size={15} />
                        </button>
                        <button className="icon secondaryIcon" title="取消" onClick={() => setEditingGroupId(null)}>
                          ×
                        </button>
                      </div>
                    </div>
                  )}
                  {group.last_error && <div className="error">{group.last_error}</div>}
                  <div className="originList">
                    {sortedOrigins.map((origin) => {
                      const originEdit = originEdits[origin.id] || {
                        target: origin.target,
                        port: origin.port,
                        priority: origin.priority,
                        publish_mode: origin.publish_mode === "expanded" ? "expanded" : "direct",
                        expanded_ip_priorities: { ...(origin.expanded_ip_priorities || {}) },
                        preferred_agent_id: origin.preferred_agent_id || "",
                        probe_mode: normalizeProbeMode(origin.probe_mode),
                        remark: origin.remark || "",
                        enabled: origin.enabled
                      };
                      const editType = inferDraftTargetType(originEdit.target);
                      const isCurrentOrigin = group.current_origin_id === origin.id;
                      const isPrimaryOrigin = origin.priority === primaryPriority;
                      const preferredAgent = origin.preferred_agent_id ? agents.find((agent) => agent.id === origin.preferred_agent_id) : null;
                      const displayStatus = origin.enabled ? origin.status : "disabled";
                      const healthMeta = !origin.enabled ? "已停用，不参与检查" : `最后检测 ${fmtDate(origin.last_checked_at)}`;
                      const activeOriginProbeStates = activeProbeStates(origin.probe_states);
                      const visibleProbeStates = currentProbeStates(origin);
                      const hiddenProbeCount = activeOriginProbeStates.length - visibleProbeStates.length;
                      return (
                        <div
                          className={`origin ${editingOriginId === origin.id ? "originEditing" : ""} ${isCurrentOrigin ? "originCurrent" : ""} ${isPrimaryOrigin ? "originPrimary" : "originBackup"} ${origin.global_origin_id ? "originGlobal" : ""}`}
                          key={origin.id}
                        >
                          <Server size={18} />
                          {editingOriginId === origin.id ? (
                            <>
                              <div className="originEditGrid">
                                <label>
                                  目标 IP / IPv6 / 域名
                                  <input value={originEdit.target} onChange={(event) => setOriginEdits((current) => ({ ...current, [origin.id]: { ...originEdit, target: event.target.value } }))} />
                                </label>
                                <label>
                                  检查端口
                                  <input type="number" min={1} max={65535} value={originEdit.port} onChange={(event) => setOriginEdits((current) => ({ ...current, [origin.id]: { ...originEdit, port: Number(event.target.value) } }))} />
                                </label>
                                <label>
                                  优先级
                                  <input type="number" min={0} value={originEdit.priority} onChange={(event) => setOriginEdits((current) => ({ ...current, [origin.id]: { ...originEdit, priority: Number(event.target.value) } }))} />
                                </label>
                                <label>
                                  指定探针
                                  <select
                                    value={originEdit.preferred_agent_id}
                                    onChange={(event) =>
                                      setOriginEdits((current) => ({
                                        ...current,
                                        [origin.id]: { ...originEdit, preferred_agent_id: event.target.value ? Number(event.target.value) : "" }
                                      }))
                                    }
                                  >
                                    <option value="">跟随默认探针</option>
                                    {agents.map((agent) => (
                                      <option value={agent.id} key={agent.id}>
                                        {agentSelectLabel(agent)}
                                      </option>
                                    ))}
                                  </select>
                                </label>
                                <label>
                                  探针策略
                                  <select
                                    value={originEdit.probe_mode}
                                    onChange={(event) =>
                                      setOriginEdits((current) => ({
                                        ...current,
                                        [origin.id]: { ...originEdit, probe_mode: event.target.value as ProbeMode }
                                      }))
                                    }
                                  >
                                    {probeModeOptions.map((option) => (
                                      <option value={option.value} key={option.value}>
                                        {option.label}
                                      </option>
                                    ))}
                                  </select>
                                </label>
                                <label>
                                  备注
                                  <input placeholder="有备注时卡片优先显示备注" value={originEdit.remark} onChange={(event) => setOriginEdits((current) => ({ ...current, [origin.id]: { ...originEdit, remark: event.target.value } }))} />
                                </label>
                                <label className="inlineCheck">
                                  <input
                                    type="checkbox"
                                    disabled={editType !== "hostname"}
                                    checked={editType === "hostname" && originEdit.publish_mode === "expanded"}
                                    onChange={(event) =>
                                      setOriginEdits((current) => {
                                        const draft = current[origin.id] || originEdit;
                                        return { ...current, [origin.id]: { ...draft, publish_mode: event.target.checked ? "expanded" : "direct" } };
                                      })
                                    }
                                  />
                                  展开 IP 池
                                </label>
                                <label className="inlineCheck">
                                  <input type="checkbox" checked={originEdit.enabled} onChange={(event) => setOriginEdits((current) => ({ ...current, [origin.id]: { ...originEdit, enabled: event.target.checked } }))} />
                                  启用
                                </label>
                                <span className="originEditHint">当前会识别为 {targetTypeText(editType)}，发布为 {recordTypeForTargetType(editType, originEdit.publish_mode)}。</span>
                              </div>
                              {editType === "hostname" && originEdit.publish_mode === "expanded" && (
                                <ExpandedIpPriorityEditor
                                  origin={origin}
                                  draft={originEdit}
                                  onChange={(next) => setOriginEdits((current) => ({ ...current, [origin.id]: next }))}
                                />
                              )}
                              <div className="rowActions">
                                <button className="icon" title="保存并应用" onClick={() => saveOriginEdit(origin.id)}>
                                  <Save size={15} />
                                </button>
                                <button className="icon secondaryIcon" title="取消" onClick={() => setEditingOriginId(null)}>
                                  ×
                                </button>
                              </div>
                            </>
                          ) : (
                            <>
                              <div>
                                <div className="originTitleLine">
                                  <strong title={`${origin.target}:${origin.port}`}>{displayTargetWithRemark(origin.target, origin.port, origin.remark)}</strong>
                                  <div className="originBadges">
                                    {isCurrentOrigin && <span className="originBadge current">当前使用</span>}
                                    {origin.global_origin_id && <span className="originBadge global">全局备用</span>}
                                    <span className={`originBadge ${isPrimaryOrigin ? "primary" : "backup"}`}>{isPrimaryOrigin ? "主用" : "备用"}</span>
                                    <span className="originBadge record">{recordTypeForTargetType(origin.target_type, origin.publish_mode)}</span>
                                    {preferredAgent && <span className="originBadge record">指定探针 {preferredAgent.name}</span>}
                                    {normalizeProbeMode(origin.probe_mode) !== "default" && <span className="originBadge record">{probeModeText(origin.probe_mode)}</span>}
                                  </div>
                                </div>
                                <span>{targetTypeText(origin.target_type)} · 优先级 {origin.priority} · {origin.enabled ? "已启用" : "已停用"} · {healthMeta}</span>
                                {origin.enabled && origin.publish_mode === "expanded" && (
                                  <div className="expandedIpList">
                                    <IpList label="解析 IP" values={origin.resolved_ips} empty="尚未解析，点击手动检测或等待下个周期" />
                                    <IpList label="健康 IP" values={origin.healthy_ips} />
                                    <IpList label="已发布" values={origin.published_ips} empty="当前未发布该目标" />
                                    <ExpandedIpPrioritySummary origin={origin} />
                                  </div>
                                )}
                                {origin.enabled && origin.last_error && <small className="danger">{origin.last_error}</small>}
                                {(visibleProbeStates.length > 0 || hiddenProbeCount > 0) && (
                                  <div className="probeChips">
                                    {visibleProbeStates.map((probe) => (
                                      <span className={`probeChip ${probe.status}`} key={probe.id} title={probe.last_error || `最后检测 ${fmtDate(probe.last_checked_at)}`}>
                                        {probeSourceText(probe)}：{statusText(probe.status)} · {fmtTime(probe.last_checked_at)}
                                      </span>
                                    ))}
                                    {hiddenProbeCount > 0 && (
                                      <span className="probeChip muted" title="这些是已经不在当前解析 IP 列表里的历史探测状态">
                                        已隐藏历史 IP {hiddenProbeCount} 条
                                      </span>
                                    )}
                                  </div>
                                )}
                              </div>
                              <Status value={displayStatus} />
                              <button className="icon secondaryIcon" title="手动检测这个目标" onClick={() => act(() => apiFetch(`/api/groups/origins/${origin.id}/run`, token, { method: "POST" }), "目标检测已完成")}>
                                <Play size={15} />
                              </button>
                              {!origin.global_origin_id && (
                                <>
                                  <button className="icon secondaryIcon" title="修改源站" onClick={() => beginEditOrigin(origin)}>
                                    <Pencil size={15} />
                                  </button>
                                  <button className="icon dangerBtn" title="删除" onClick={() => act(() => apiFetch(`/api/groups/origins/${origin.id}`, token, { method: "DELETE" }), "源站已删除")}>
                                    <Trash2 size={15} />
                                  </button>
                                </>
                              )}
                            </>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </>
              )}
            </article>
          );
        })}
              {section.groups.length === 0 && section.collection && (
                <div className="panel emptyGroupPanel">
                  <h2>这个业务分组还没有切换组</h2>
                  <p>编辑切换组时选择这个业务分组后，全局备用会自动同步进去。</p>
                </div>
              )}
            </div>
            )}
          </div>
        ))}
        {groups.length === 0 && collections.length === 0 && (
          <div className="panel emptyGroupPanel">
            <h2>还没有故障切换组</h2>
            <p>请先到解析记录页，选择一条 DNS-only A/AAAA/CNAME 记录，点击管理并确认接管。</p>
          </div>
        )}
      </div>
      {addingGlobalCollection && (
        <div className="modalBackdrop" role="dialog" aria-modal="true">
          <div className="modalPanel">
            <div className="panelTitle">
              <h2>添加全局备用</h2>
              <p>{addingGlobalCollection.name} · 会同步到这个业务分组下所有切换组</p>
            </div>
            <label>
              从目标池选择
              <select value={selectedGlobalPoolItemId} onChange={(event) => selectGlobalPoolItem(Number(event.target.value))} disabled={enabledPoolItems.length === 0}>
                <option value="">{enabledPoolItems.length > 0 ? "选择一个池子目标，或在下方手动输入" : "目标池暂无可用目标"}</option>
                {enabledPoolItems.map((item) => (
                  <option value={item.id} key={item.id}>
                    {displayTargetWithRemark(item.target, item.port, item.remark)} · {targetTypeText(item.target_type)}
                  </option>
                ))}
              </select>
            </label>
            <label>
              从外部 IP 选择
              <select value={selectedGlobalExternalItemId} onChange={(event) => selectGlobalExternalIpItem(Number(event.target.value))} disabled={healthyExternalItems.length === 0}>
                <option value="">{healthyExternalItems.length > 0 ? "选择一个已同步 IP" : "暂无外部 IP"}</option>
                {healthyExternalItems.map((item) => (
                  <option value={item.id} key={item.id}>
                    {externalIpLabel(item)}
                  </option>
                ))}
              </select>
            </label>
            <label>
              全局备用 IP / IPv6 / 域名
              <input placeholder="例如 192.0.2.10 或 backup.example.com" value={globalOriginAdd.target} onChange={(event) => setGlobalOriginAdd((current) => ({ ...current, target: event.target.value }))} />
            </label>
            <label>
              备注
              <input placeholder="例如 全局香港备用、通用回源" value={globalOriginAdd.remark} onChange={(event) => setGlobalOriginAdd((current) => ({ ...current, remark: event.target.value }))} />
            </label>
            <div className="modalFormGrid">
              <label>
                检查端口
                <input type="number" min={1} max={65535} value={globalOriginAdd.port} onChange={(event) => setGlobalOriginAdd((current) => ({ ...current, port: Number(event.target.value) }))} />
              </label>
              <label>
                优先级
                <input type="number" min={0} value={globalOriginAdd.priority} onChange={(event) => setGlobalOriginAdd((current) => ({ ...current, priority: Number(event.target.value) }))} />
              </label>
              <label>
                指定探针
                <select value={globalOriginAdd.preferred_agent_id} onChange={(event) => setGlobalOriginAdd((current) => ({ ...current, preferred_agent_id: event.target.value ? Number(event.target.value) : "" }))}>
                  <option value="">跟随默认探针</option>
                  {agents.map((agent) => (
                    <option value={agent.id} key={agent.id}>
                      {agentSelectLabel(agent)}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                探针策略
                <select value={globalOriginAdd.probe_mode} onChange={(event) => setGlobalOriginAdd((current) => ({ ...current, probe_mode: event.target.value as ProbeMode }))}>
                  {probeModeOptions.map((option) => (
                    <option value={option.value} key={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <label className="inlineCheck">
              <input type="checkbox" checked={globalOriginAdd.enabled} onChange={(event) => setGlobalOriginAdd((current) => ({ ...current, enabled: event.target.checked }))} />
              启用这个全局备用
            </label>
            {globalAddTargetType === "hostname" && (
              <label className="inlineCheck">
                <input
                  type="checkbox"
                  checked={globalOriginAdd.publish_mode === "expanded"}
                  onChange={(event) => setGlobalOriginAdd((current) => ({ ...current, publish_mode: event.target.checked ? "expanded" : "direct" }))}
                />
                展开解析为 IP 池，只发布健康 A/AAAA
              </label>
            )}
            {globalOriginAdd.target.trim() && (
              <div className="originHint">
                当前输入识别为 {targetTypeText(globalAddTargetType)}，同步到各切换组后会发布为 {recordTypeForTargetType(globalAddTargetType, globalOriginAdd.publish_mode)}。
              </div>
            )}
            <div className="modalActions">
              <button type="button" className="secondary" onClick={() => setAddingGlobalCollectionId(null)}>取消</button>
              <button type="button" onClick={createGlobalOrigin}>
                <Plus size={16} />
                <span>添加全局备用</span>
              </button>
            </div>
          </div>
        </div>
      )}
      {addingHostnameGroup && (
        <div className="modalBackdrop" role="dialog" aria-modal="true">
          <div className="modalPanel">
            <div className="panelTitle">
              <h2>添加主域名</h2>
              <p>{addingHostnameGroup.hostname}</p>
            </div>
            <label>
              主域名
              <input placeholder="例如 b.example.com" value={hostnameAdd.hostname} onChange={(event) => setHostnameAdd((current) => ({ ...current, hostname: event.target.value }))} />
            </label>
            <label>
              接管记录 ID（可选）
              <input placeholder="不填则自动接管唯一 DNS-only 记录" value={hostnameAdd.adopt_record_id} onChange={(event) => setHostnameAdd((current) => ({ ...current, adopt_record_id: event.target.value }))} />
            </label>
            <div className="hintBox">添加后会和本组其他主域名共用同一套源站与切换策略。</div>
            <div className="modalActions">
              <button className="secondary" onClick={() => setAddingHostnameGroupId(null)}>取消</button>
              <button onClick={createHostname}>
                <Plus size={16} />
                <span>添加主域名</span>
              </button>
            </div>
          </div>
        </div>
      )}
      {addingGroup && (
        <div className="modalBackdrop" role="dialog" aria-modal="true">
          <div className="modalPanel">
            <div className="panelTitle">
              <h2>添加备用目标</h2>
              <p>{addingGroup.hostname}</p>
            </div>
            <label>
              从目标池选择
              <select value={selectedPoolItemId} onChange={(event) => selectPoolItem(Number(event.target.value))} disabled={enabledPoolItems.length === 0}>
                <option value="">{enabledPoolItems.length > 0 ? "选择一个池子目标，或在下方手动输入" : "目标池暂无可用目标"}</option>
                {enabledPoolItems.map((item) => (
                  <option value={item.id} key={item.id}>
                    {displayTargetWithRemark(item.target, item.port, item.remark)} · {targetTypeText(item.target_type)}
                  </option>
                ))}
              </select>
            </label>
            <label>
              从外部 IP 选择
              <select value={selectedExternalItemId} onChange={(event) => selectExternalIpItem(Number(event.target.value))} disabled={healthyExternalItems.length === 0}>
                <option value="">{healthyExternalItems.length > 0 ? "选择一个已同步 IP" : "暂无外部 IP"}</option>
                {healthyExternalItems.map((item) => (
                  <option value={item.id} key={item.id}>
                    {externalIpLabel(item)}
                  </option>
                ))}
              </select>
            </label>
            <label>
              备用 IP / IPv6 / 域名
              <input placeholder="例如 192.0.2.10 或 backup.example.com" value={originAdd.target} onChange={(event) => setOriginAdd((current) => ({ ...current, target: event.target.value }))} />
            </label>
            <label>
              备注
              <input placeholder="例如 香港备用、线路 1" value={originAdd.remark} onChange={(event) => setOriginAdd((current) => ({ ...current, remark: event.target.value }))} />
            </label>
            <div className="modalFormGrid">
              <label>
                检查端口
                <input type="number" min={1} max={65535} value={originAdd.port} onChange={(event) => setOriginAdd((current) => ({ ...current, port: Number(event.target.value) }))} />
              </label>
              <label>
                优先级
                <input type="number" min={0} value={originAdd.priority} onChange={(event) => setOriginAdd((current) => ({ ...current, priority: Number(event.target.value) }))} />
              </label>
              <label>
                指定探针
                <select value={originAdd.preferred_agent_id} onChange={(event) => setOriginAdd((current) => ({ ...current, preferred_agent_id: event.target.value ? Number(event.target.value) : "" }))}>
                  <option value="">跟随默认探针</option>
                  {agents.map((agent) => (
                    <option value={agent.id} key={agent.id}>
                      {agentSelectLabel(agent)}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                探针策略
                <select value={originAdd.probe_mode} onChange={(event) => setOriginAdd((current) => ({ ...current, probe_mode: event.target.value as ProbeMode }))}>
                  {probeModeOptions.map((option) => (
                    <option value={option.value} key={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <label className="inlineCheck">
              <input type="checkbox" checked={originAdd.enabled} onChange={(event) => setOriginAdd((current) => ({ ...current, enabled: event.target.checked }))} />
              启用这个备用目标
            </label>
            {addTargetType === "hostname" && (
              <label className="inlineCheck">
                <input
                  type="checkbox"
                  checked={originAdd.publish_mode === "expanded"}
                  onChange={(event) => setOriginAdd((current) => ({ ...current, publish_mode: event.target.checked ? "expanded" : "direct" }))}
                />
                展开解析为 IP 池，只发布健康 A/AAAA
              </label>
            )}
            {originAdd.target.trim() && (
              <div className="originHint">
                当前输入识别为 {targetTypeText(addTargetType)}，故障切换时会发布为 {recordTypeForTargetType(addTargetType, originAdd.publish_mode)}。
              </div>
            )}
            <div className="modalActions">
              <button type="button" className="secondary" onClick={() => setAddingGroupId(null)}>取消</button>
              <button type="button" onClick={createOrigin}>
                <Plus size={16} />
                <span>添加备用</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

function snippetCategoryText(value: string): string {
  const labels: Record<string, string> = {
    ssh: "SSH",
    command: "命令",
    address: "地址",
    note: "备注"
  };
  return labels[value] || value;
}

function sshCommandForSnippet(snippet: SavedSnippet | SnippetDraft): string {
  const address = (snippet.address || "").trim();
  if (!address) return "";
  const username = (snippet.username || "").trim();
  const portValue = typeof snippet.port === "number" ? snippet.port : Number(snippet.port || 22);
  const host = username ? `${username}@${address}` : address;
  return portValue && portValue !== 22 ? `ssh -p ${portValue} ${host}` : `ssh ${host}`;
}

function fencedCodeParts(value: string): { type: "text" | "code"; value: string; lang?: string }[] {
  const parts: { type: "text" | "code"; value: string; lang?: string }[] = [];
  const pattern = /```([\w-]*)\n?([\s\S]*?)```/g;
  let cursor = 0;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(value)) !== null) {
    if (match.index > cursor) {
      parts.push({ type: "text", value: value.slice(cursor, match.index) });
    }
    parts.push({ type: "code", lang: match[1] || undefined, value: match[2].trim() });
    cursor = match.index + match[0].length;
  }
  if (cursor < value.length) {
    parts.push({ type: "text", value: value.slice(cursor) });
  }
  return parts.filter((part) => part.value.trim());
}

function SnippetsPanel({ token, snippets, act }: { token: string; snippets: SavedSnippet[]; act: ActionRunner }) {
  const [draft, setDraft] = useState<SnippetDraft>(defaultSnippetDraft);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [query, setQuery] = useState("");
  const [copiedKey, setCopiedKey] = useState("");
  const filtered = useMemo(() => {
    const text = query.trim().toLowerCase();
    if (!text) return snippets;
    return snippets.filter((snippet) =>
      [
        snippet.title,
        snippet.category,
        snippet.address || "",
        snippet.username || "",
        snippet.tags || "",
        snippet.content || "",
        snippet.code || ""
      ]
        .join(" ")
        .toLowerCase()
        .includes(text)
    );
  }, [query, snippets]);

  function resetDraft() {
    setDraft(defaultSnippetDraft);
    setEditingId(null);
  }

  function beginEdit(snippet: SavedSnippet) {
    setEditingId(snippet.id);
    setDraft({
      title: snippet.title,
      category: snippet.category,
      address: snippet.address || "",
      username: snippet.username || "",
      port: String(snippet.port || 22),
      tags: snippet.tags || "",
      content: snippet.content || "",
      code: snippet.code || ""
    });
  }

  async function copyText(key: string, value: string) {
    await navigator.clipboard.writeText(value);
    setCopiedKey(key);
    window.setTimeout(() => setCopiedKey((current) => (current === key ? "" : current)), 1200);
  }

  function payloadFromDraft() {
    const portValue = Number(draft.port || 0);
    return {
      title: draft.title.trim(),
      category: draft.category,
      address: draft.address.trim() || null,
      username: draft.username.trim() || null,
      port: portValue > 0 ? portValue : null,
      tags: draft.tags.trim() || null,
      content: draft.content.trim() || null,
      code: draft.code.trim() || null
    };
  }

  async function saveSnippet(event: FormEvent) {
    event.preventDefault();
    await act(
      () => {
        if (!draft.title.trim()) throw new Error("请填写标题");
        const payload = payloadFromDraft();
        return apiFetch(editingId ? `/api/snippets/${editingId}` : "/api/snippets", token, {
          method: editingId ? "PATCH" : "POST",
          body: JSON.stringify(payload)
        });
      },
      editingId ? "资料已更新" : "资料已保存",
      resetDraft
    );
  }

  function renderCodeBlock(key: string, value: string, lang?: string) {
    return (
      <div className="snippetCodeBlock" key={key}>
        <div className="snippetCodeHead">
          <span>{lang || "代码块"}</span>
          <button className="icon secondaryIcon" title="复制代码块" onClick={() => copyText(key, value)}>
            <Copy size={14} />
          </button>
        </div>
        <pre><code>{value}</code></pre>
      </div>
    );
  }

  return (
    <section className="snippetPanel">
      <form className="panel snippetForm" onSubmit={saveSnippet}>
        <div className="panelTitle">
          <h2>{editingId ? "修改资料" : "保存命令 / 地址"}</h2>
          <p>用于保存 SSH 地址、常用命令和说明；不要在这里保存密码或私钥。</p>
        </div>
        <div className="snippetFormGrid">
          <label>
            标题
            <input value={draft.title} onChange={(event) => setDraft((current) => ({ ...current, title: event.target.value }))} placeholder="例如 香港服务器 SSH" />
          </label>
          <label>
            类型
            <select value={draft.category} onChange={(event) => setDraft((current) => ({ ...current, category: event.target.value }))}>
              <option value="command">命令</option>
              <option value="ssh">SSH</option>
              <option value="address">地址</option>
              <option value="note">备注</option>
            </select>
          </label>
          <label>
            地址 / 主机
            <input value={draft.address} onChange={(event) => setDraft((current) => ({ ...current, address: event.target.value }))} placeholder="例如 1.2.3.4 或 example.com" />
          </label>
          <label>
            用户名
            <input value={draft.username} onChange={(event) => setDraft((current) => ({ ...current, username: event.target.value }))} placeholder="例如 root" />
          </label>
          <label>
            端口
            <input type="number" min={1} max={65535} value={draft.port} onChange={(event) => setDraft((current) => ({ ...current, port: event.target.value }))} />
          </label>
          <label>
            标签
            <input value={draft.tags} onChange={(event) => setDraft((current) => ({ ...current, tags: event.target.value }))} placeholder="例如 香港, 宝塔, 生产" />
          </label>
        </div>
        <label>
          说明
          <textarea value={draft.content} onChange={(event) => setDraft((current) => ({ ...current, content: event.target.value }))} placeholder={"支持代码块，例如：\n```bash\nsystemctl status nginx\n```"} />
        </label>
        <label>
          代码块 / 常用命令
          <textarea value={draft.code} onChange={(event) => setDraft((current) => ({ ...current, code: event.target.value }))} placeholder="例如 ssh -p 22 root@1.2.3.4" />
        </label>
        {sshCommandForSnippet(draft) && (
          <div className="snippetPreviewCommand">
            <code>{sshCommandForSnippet(draft)}</code>
            <button type="button" className="icon secondaryIcon" title="复制 SSH 命令" onClick={() => copyText("draft-ssh", sshCommandForSnippet(draft))}>
              <Copy size={14} />
            </button>
          </div>
        )}
        <div className="modalActions">
          {editingId && <button type="button" className="secondary" onClick={resetDraft}>取消修改</button>}
          <button type="submit">
            <Save size={16} />
            <span>{editingId ? "保存修改" : "保存资料"}</span>
          </button>
        </div>
      </form>
      <div className="panel snippetListPanel">
        <div className="panelTitle">
          <h2>命令库</h2>
          <p>点击复制按钮即可复制地址、SSH 命令或代码块。</p>
        </div>
        <input className="searchInput" placeholder="搜索标题、标签、地址或内容" value={query} onChange={(event) => setQuery(event.target.value)} />
        <div className="snippetList">
          {filtered.map((snippet) => {
            const sshCommand = sshCommandForSnippet(snippet);
            return (
              <article className="snippetCard" key={snippet.id}>
                <div className="snippetHead">
                  <div>
                    <h3>{snippet.title}</h3>
                    <span>{snippetCategoryText(snippet.category)} · 更新 {fmtDate(snippet.updated_at)}</span>
                  </div>
                  <div className="rowActions">
                    <button className="icon secondaryIcon" title="修改" onClick={() => beginEdit(snippet)}>
                      <Pencil size={15} />
                    </button>
                    <button className="icon dangerBtn" title="删除" onClick={() => act(() => apiFetch(`/api/snippets/${snippet.id}`, token, { method: "DELETE" }), "资料已删除")}>
                      <Trash2 size={15} />
                    </button>
                  </div>
                </div>
                {snippet.tags && <div className="snippetTags">{snippet.tags.split(/[,\s，]+/).filter(Boolean).map((tag) => <span key={tag}>{tag}</span>)}</div>}
                {snippet.address && (
                  <div className="snippetCopyLine">
                    <span>地址</span>
                    <code>{snippet.address}</code>
                    <button className="icon secondaryIcon" title="复制地址" onClick={() => copyText(`address-${snippet.id}`, snippet.address || "")}>
                      <Copy size={14} />
                    </button>
                  </div>
                )}
                {sshCommand && (
                  <div className="snippetCopyLine">
                    <span>SSH</span>
                    <code>{sshCommand}</code>
                    <button className="icon secondaryIcon" title="复制 SSH 命令" onClick={() => copyText(`ssh-${snippet.id}`, sshCommand)}>
                      <Copy size={14} />
                    </button>
                  </div>
                )}
                {snippet.content && (
                  <div className="snippetContent">
                    {fencedCodeParts(snippet.content).map((part, index) =>
                      part.type === "code"
                        ? renderCodeBlock(`content-code-${snippet.id}-${index}`, part.value, part.lang)
                        : <p key={`content-text-${snippet.id}-${index}`}>{part.value.trim()}</p>
                    )}
                  </div>
                )}
                {snippet.code && renderCodeBlock(`code-${snippet.id}`, snippet.code)}
                {copiedKey && copiedKey.includes(String(snippet.id)) && <small className="successText">已复制</small>}
              </article>
            );
          })}
          {filtered.length === 0 && <div className="emptyGroupPanel"><h2>还没有保存资料</h2><p>左侧添加 SSH 地址、命令或代码块后会显示在这里。</p></div>}
        </div>
      </div>
    </section>
  );
}

function SshPanel({ token, settings, act }: { token: string; settings: SshSettings; act: ActionRunner }) {
  const [draft, setDraft] = useState<SshSettingsDraft>({
    enabled: settings.enabled,
    external_url: settings.external_url
  });
  const [copiedKey, setCopiedKey] = useState("");

  useEffect(() => {
    setDraft({
      enabled: settings.enabled,
      external_url: settings.external_url
    });
  }, [settings]);

  const dockerInstall = `mkdir -p /www/server/sshwifty
cat > /www/server/sshwifty/sshwifty.conf.json <<'JSON'
{
  "HostName": "",
  "SharedKey": "CHANGE_THIS_STRONG_PASSWORD",
  "DialTimeout": 10,
  "Servers": [
    {
      "ListenInterface": "127.0.0.1",
      "ListenPort": 8182,
      "InitialTimeout": 10,
      "ReadTimeout": 120,
      "WriteTimeout": 120,
      "HeartbeatTimeout": 10,
      "ReadDelay": 10,
      "WriteDelay": 10,
      "TLSCertificateFile": "",
      "TLSCertificateKeyFile": "",
      "ServerMessage": "SSH is available only through the Cloudflare DNS panel."
    }
  ]
}
JSON
docker rm -f sshwifty 2>/dev/null || true
docker run --detach \\
  --restart unless-stopped \\
  --publish 127.0.0.1:8182:8182 \\
  --volume /www/server/sshwifty/sshwifty.conf.json:/etc/sshwifty.conf.json:ro \\
  --env SSHWIFTY_CONFIG=/etc/sshwifty.conf.json \\
  --name sshwifty \\
  niruix/sshwifty:latest`;

  const nginxSnippet = `# 单独给 Sshwifty 建一个站点，例如 ssh.dns.jiyeai.com
# aaPanel 里建站并申请证书后，把下面 location 放进该站点配置。
location / {
    proxy_pass http://127.0.0.1:8182;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}`;

  async function copyText(key: string, value: string) {
    await navigator.clipboard.writeText(value);
    setCopiedKey(key);
    window.setTimeout(() => setCopiedKey((current) => (current === key ? "" : current)), 1200);
  }

  async function saveSettings(event: FormEvent) {
    event.preventDefault();
    await act(
      () =>
        apiFetch("/api/ssh/settings", token, {
          method: "PATCH",
          body: JSON.stringify({
            enabled: draft.enabled,
            external_url: draft.external_url.trim()
          })
        }),
      "SSH 设置已保存"
    );
  }

  function openSsh() {
    if (!settings.external_url) return;
    window.open(settings.external_url, "_blank", "noopener,noreferrer");
  }

  function renderCopyBlock(key: string, title: string, value: string) {
    return (
      <div className="sshCodeBlock">
        <div className="snippetCodeHead">
          <span>{title}</span>
          <button type="button" className="icon secondaryIcon" title="复制" onClick={() => copyText(key, value)}>
            <Copy size={14} />
          </button>
        </div>
        <pre><code>{value}</code></pre>
        {copiedKey === key && <small className="successText">已复制</small>}
      </div>
    );
  }

  return (
    <section className="sshPanel">
      <form className="panel sshSettingsPanel" onSubmit={saveSettings}>
        <div className="panelTitle">
          <h2>SSH 接入</h2>
          <p>把 Sshwifty 单独部署成 HTTPS 站点，本项目只保存入口地址并提供打开按钮。</p>
        </div>
        <div className="sshStatusLine">
          <span className={settings.enabled ? "pill healthy" : "pill muted"}>{settings.enabled ? "已启用" : "未启用"}</span>
          <span>入口：{settings.external_url || "未设置"}</span>
        </div>
        <div className="settingsGrid">
          <label className="checkboxLabel">
            <input type="checkbox" checked={draft.enabled} onChange={(event) => setDraft((current) => ({ ...current, enabled: event.target.checked }))} />
            启用 SSH 菜单入口
          </label>
          <label>
            Sshwifty HTTPS 入口
            <input value={draft.external_url} onChange={(event) => setDraft((current) => ({ ...current, external_url: event.target.value }))} placeholder="https://ssh.dns.jiyeai.com" />
            <span>必须是 HTTPS。建议用 Cloudflare Access 保护这个子域名。</span>
          </label>
        </div>
        <div className="formActions">
          <button>
            <Save size={16} />
            <span>保存 SSH 设置</span>
          </button>
        </div>
      </form>

      <div className="panel sshFramePanel">
        <div className="panelTitle">
          <h2>SSH 入口</h2>
          <p>点击后会打开你配置的 Sshwifty HTTPS 站点。连接和登录由 Sshwifty 自己处理。</p>
        </div>
        <div className="formActions">
          <button type="button" disabled={!settings.enabled || !settings.external_url} onClick={openSsh}>
            <SquareTerminal size={16} />
            <span>打开 SSH</span>
          </button>
        </div>
        {(!settings.enabled || !settings.external_url) && <div className="emptyGroupPanel"><h2>SSH 入口尚未可用</h2><p>先启用 SSH 菜单，并填写 Sshwifty 的 HTTPS 地址。</p></div>}
        {settings.enabled && settings.external_url && (
          <div className="sshPlaceholder">
            <strong>{settings.external_url}</strong>
            <span>推荐在 Cloudflare 上给这个子域名开启 Access，再把 8182 端口保持为仅本机监听。</span>
          </div>
        )}
      </div>

      <details className="panel sshGuidePanel">
        <summary>
          <span>部署 Sshwifty HTTPS 子站</span>
          <small>只在首次安装或排错时展开</small>
        </summary>
        <div className="sshGuideIntro">
          容器只绑定 <code>127.0.0.1:8182</code>，Nginx 单独建一个 HTTPS 子域名反代过去。不要把 8182 端口开放到公网。
        </div>
        <div className="sshGuideGrid">
          {renderCopyBlock("ssh-docker", "服务器安装命令", dockerInstall)}
          {renderCopyBlock("ssh-nginx", "Nginx WebSocket 反代补充", nginxSnippet)}
        </div>
      </details>
    </section>
  );
}

function ExternalIpsPanel({
  token,
  externalIpSources,
  externalIpItems,
  act
}: {
  token: string;
  externalIpSources: ExternalIpSource[];
  externalIpItems: ExternalIpItem[];
  act: ActionRunner;
}) {
  const [externalDraft, setExternalDraft] = useState<ExternalIpSourceDraft>(defaultExternalIpSourceDraft);
  const [editingSourceId, setEditingSourceId] = useState<number | null>(null);
  const [sourceEdits, setSourceEdits] = useState<Record<number, ExternalIpSourceDraft>>({});
  const healthyExternalItems = externalIpItems.filter((item) => item.status === "healthy");
  const externalMachines = useMemo(() => {
    const groups = new Map<
      string,
      { key: string; name: string; country: string | null; groupName: string | null; lastSeenAt: string | null; items: ExternalIpItem[] }
    >();
    for (const item of healthyExternalItems) {
      const key = item.machine_key || `${item.source_id}:${item.group_name || ""}:${item.name}:${item.port}`;
      const current = groups.get(key) || {
        key,
        name: item.name,
        country: item.country,
        groupName: item.group_name,
        lastSeenAt: item.last_seen_at,
        items: []
      };
      current.country = current.country || item.country;
      current.groupName = current.groupName || item.group_name;
      if (!current.lastSeenAt || (item.last_seen_at && new Date(item.last_seen_at).getTime() > new Date(current.lastSeenAt).getTime())) {
        current.lastSeenAt = item.last_seen_at;
      }
      current.items.push(item);
      groups.set(key, current);
    }
    return [...groups.values()]
      .map((group) => ({
        ...group,
        items: group.items.sort((left, right) => left.target_type.localeCompare(right.target_type) || left.target.localeCompare(right.target))
      }))
      .sort((left, right) => left.name.localeCompare(right.name));
  }, [healthyExternalItems]);

  async function createExternalIpSource(event: FormEvent) {
    event.preventDefault();
    await act(
      () =>
        apiFetch("/api/external-ips/sources", token, {
          method: "POST",
          body: JSON.stringify({
            name: externalDraft.name.trim(),
            base_url: externalDraft.base_url.trim(),
            token: externalDraft.token.trim(),
            default_port: externalDraft.default_port,
            sync_interval_seconds: externalDraft.sync_interval_seconds,
            enabled: externalDraft.enabled
          })
        }),
      "外部 IP 来源已添加",
      () => setExternalDraft(defaultExternalIpSourceDraft)
    );
  }

  function beginEditExternalIpSource(source: ExternalIpSource) {
    setEditingSourceId(source.id);
    setSourceEdits((current) => ({
      ...current,
      [source.id]: {
        name: source.name,
        base_url: source.base_url,
        token: "",
        default_port: source.default_port,
        sync_interval_seconds: source.sync_interval_seconds,
        enabled: source.enabled
      }
    }));
  }

  async function saveExternalIpSource(sourceId: number) {
    const draft = sourceEdits[sourceId];
    if (!draft) return;
    const payload: Record<string, string | number | boolean> = {
      name: draft.name.trim(),
      base_url: draft.base_url.trim(),
      default_port: draft.default_port,
      sync_interval_seconds: draft.sync_interval_seconds,
      enabled: draft.enabled
    };
    if (draft.token.trim()) {
      payload.token = draft.token.trim();
    }
    await act(
      () =>
        apiFetch(`/api/external-ips/sources/${sourceId}`, token, {
          method: "PATCH",
          body: JSON.stringify(payload)
        }),
      "外部 IP 来源已更新",
      () => setEditingSourceId(null)
    );
  }

  function externalItemToPoolPayload(item: ExternalIpItem) {
    return {
      target: item.target,
      port: item.port,
      remark: externalIpPoolRemark(item) || null,
      check_interval_seconds: 600,
      enabled: true
    };
  }

  async function addExternalIpToPool(item: ExternalIpItem) {
    await act(
      () =>
        apiFetch("/api/target-pool/bulk", token, {
          method: "POST",
          body: JSON.stringify({ items: [externalItemToPoolPayload(item)] })
        }),
      "已添加到 IP 池子"
    );
  }

  async function addMachineToPool(items: ExternalIpItem[]) {
    await act(
      () =>
        apiFetch("/api/target-pool/bulk", token, {
          method: "POST",
          body: JSON.stringify({ items: items.map(externalItemToPoolPayload) })
        }),
      "整台机器的 IP 已添加到池子"
    );
  }

  return (
    <section className="stack">
      <div className="panelTitle groupsIntro">
        <h2>外部 IP</h2>
        <p>从 Nyanpass 服务器状态页同步节点 IP，添加备用时可直接选择。</p>
      </div>
      <div className="externalIpPanel">
        <form className="panel externalSourceForm" onSubmit={createExternalIpSource}>
          <div className="panelTitle">
            <h2>添加来源</h2>
            <p>面板地址填 Nyanpass 根域名，Token 使用状态页 WebSocket 的 token。</p>
          </div>
          <div className="externalSourceGrid">
            <label>
              来源名称
              <input placeholder="例如 Nyanpass" value={externalDraft.name} onChange={(event) => setExternalDraft((current) => ({ ...current, name: event.target.value }))} required />
            </label>
            <label>
              面板地址
              <input placeholder="https://ny.example.com" value={externalDraft.base_url} onChange={(event) => setExternalDraft((current) => ({ ...current, base_url: event.target.value }))} required />
            </label>
            <label>
              Authorization / Token
              <input type="password" value={externalDraft.token} onChange={(event) => setExternalDraft((current) => ({ ...current, token: event.target.value }))} required />
            </label>
            <label>
              默认端口
              <input type="number" min={1} max={65535} value={externalDraft.default_port} onChange={(event) => setExternalDraft((current) => ({ ...current, default_port: Number(event.target.value) }))} />
            </label>
            <label>
              同步周期（秒）
              <input type="number" min={60} max={86400} value={externalDraft.sync_interval_seconds} onChange={(event) => setExternalDraft((current) => ({ ...current, sync_interval_seconds: Number(event.target.value) }))} />
            </label>
          </div>
          <button>
            <Plus size={16} />
            <span>添加来源</span>
          </button>
        </form>
        <div className="panel externalIpListPanel">
          <div className="panelTitle">
            <h2>来源与同步列表</h2>
            <p>显示外部来源返回的 IPv4 / IPv6。来源同步后会自动刷新。</p>
          </div>
          <div className="externalSourceList">
            {externalIpSources.map((source) => {
              const edit = sourceEdits[source.id] || {
                name: source.name,
                base_url: source.base_url,
                token: "",
                default_port: source.default_port,
                sync_interval_seconds: source.sync_interval_seconds,
                enabled: source.enabled
              };
              return (
                <div className="externalSourceItem" key={source.id}>
                  {editingSourceId === source.id ? (
                    <>
                      <div className="externalSourceEditGrid">
                        <label>
                          来源名称
                          <input value={edit.name} onChange={(event) => setSourceEdits((current) => ({ ...current, [source.id]: { ...edit, name: event.target.value } }))} />
                        </label>
                        <label>
                          面板地址
                          <input value={edit.base_url} onChange={(event) => setSourceEdits((current) => ({ ...current, [source.id]: { ...edit, base_url: event.target.value } }))} />
                        </label>
                        <label>
                          新 Token
                          <input type="password" placeholder="留空不修改" value={edit.token} onChange={(event) => setSourceEdits((current) => ({ ...current, [source.id]: { ...edit, token: event.target.value } }))} />
                        </label>
                        <label>
                          默认端口
                          <input type="number" min={1} max={65535} value={edit.default_port} onChange={(event) => setSourceEdits((current) => ({ ...current, [source.id]: { ...edit, default_port: Number(event.target.value) } }))} />
                        </label>
                        <label>
                          拉取周期（秒）
                          <input type="number" min={60} max={86400} value={edit.sync_interval_seconds} onChange={(event) => setSourceEdits((current) => ({ ...current, [source.id]: { ...edit, sync_interval_seconds: Number(event.target.value) } }))} />
                        </label>
                        <label className="inlineCheck">
                          <input type="checkbox" checked={edit.enabled} onChange={(event) => setSourceEdits((current) => ({ ...current, [source.id]: { ...edit, enabled: event.target.checked } }))} />
                          启用
                        </label>
                      </div>
                      <div className="rowActions">
                        <button className="icon" title="保存来源" onClick={() => saveExternalIpSource(source.id)}>
                          <Save size={15} />
                        </button>
                        <button className="icon secondaryIcon" title="取消" onClick={() => setEditingSourceId(null)}>
                          ×
                        </button>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="poolItemMain">
                        <strong>{source.name}</strong>
                        <span>{source.base_url} · 周期 {source.sync_interval_seconds}s · 默认端口 {source.default_port} · {fmtDate(source.last_synced_at)}</span>
                        {source.last_error && <small className="danger">{source.last_error}</small>}
                      </div>
                      <div className="rowActions">
                        <Status value={source.enabled ? source.status : "disabled"} />
                        <button className="icon secondaryIcon" title="立即同步" onClick={() => act(() => apiFetch(`/api/external-ips/sources/${source.id}/sync`, token, { method: "POST" }), "外部 IP 已同步")}>
                          <RefreshCw size={15} />
                        </button>
                        <button className="icon secondaryIcon" title="修改来源" onClick={() => beginEditExternalIpSource(source)}>
                          <Pencil size={15} />
                        </button>
                        <button className="icon dangerBtn" title="删除来源" onClick={() => act(() => apiFetch(`/api/external-ips/sources/${source.id}`, token, { method: "DELETE" }), "外部 IP 来源已删除")}>
                          <Trash2 size={15} />
                        </button>
                      </div>
                    </>
                  )}
                </div>
              );
            })}
            {externalIpSources.length === 0 && <div className="emptyCell">还没有外部 IP 来源</div>}
          </div>
          <div className="externalMachineList">
            {externalMachines.map((machine) => (
              <div className="externalMachineCard" key={machine.key}>
                <div className="externalMachineHead">
                  <div>
                    <strong>{machine.name}</strong>
                    <span>{machine.country || machine.groupName || "未知国家"} · {fmtDate(machine.lastSeenAt)}</span>
                  </div>
                  <button className="secondary compactBtn" title="把这台机器的全部 IPv4/IPv6 加入 IP 池子" onClick={() => addMachineToPool(machine.items)}>
                    <Plus size={14} />
                    <span>整机加入池子</span>
                  </button>
                </div>
                <div className="externalMachineIps">
                  {machine.items.map((item) => (
                    <div className="externalIpAddItem" key={item.id}>
                      <span className="externalIpChip" title={`${item.name} · ${fmtDate(item.last_seen_at)}`}>
                        {externalIpFamilyText(item)} {item.target}:{item.port}
                      </span>
                      <button className="externalIpAddBtn" title="加入 IP 池子" onClick={() => addExternalIpToPool(item)}>
                        <Plus size={12} />
                        <span>加入池子</span>
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            ))}
            {externalMachines.length === 0 && <span className="emptyInline">暂无外部 IP</span>}
          </div>
        </div>
      </div>
    </section>
  );
}

function AzPanelPanel({
  token,
  settings,
  resources,
  groups,
  jobs,
  act
}: {
  token: string;
  settings: AzPanelSettings;
  resources: AzPanelResource[];
  groups: FailoverGroup[];
  jobs: IpChangeJob[];
  act: ActionRunner;
}) {
  const [settingsDraft, setSettingsDraft] = useState<AzPanelSettingsDraft>({
    enabled: settings.enabled,
    base_url: settings.base_url,
    api_token: "",
    timeout_seconds: settings.timeout_seconds,
    default_cooldown_seconds: settings.default_cooldown_seconds
  });
  const [editingId, setEditingId] = useState<number | null>(null);
  const emptyDraft = (): AzPanelResourceDraft => ({
    name: "",
    provider: "azure",
    resource_id: "",
    account_id: "",
    region: "",
    ip_version: "ipv4",
    origin_id: "",
    current_ip: "",
    port: 22,
    enabled: true,
    auto_change_on_blocked: true,
    auto_update_origin: true,
    cooldown_seconds: settings.default_cooldown_seconds || 1800,
    remark: ""
  });
  const [resourceDraft, setResourceDraft] = useState<AzPanelResourceDraft>(emptyDraft);
  const origins = originOptions(groups);
  const [remoteProvider, setRemoteProvider] = useState("azure");
  const [remoteResources, setRemoteResources] = useState<AzPanelRemoteResource[]>([]);
  const [selectedRemoteKey, setSelectedRemoteKey] = useState("");

  useEffect(() => {
    setRemoteResources([]);
    setSelectedRemoteKey("");
  }, [remoteProvider]);

  useEffect(() => {
    setSettingsDraft({
      enabled: settings.enabled,
      base_url: settings.base_url,
      api_token: "",
      timeout_seconds: settings.timeout_seconds,
      default_cooldown_seconds: settings.default_cooldown_seconds
    });
  }, [settings]);

  function resourcePayload() {
    return {
      name: resourceDraft.name.trim(),
      provider: resourceDraft.provider,
      resource_id: resourceDraft.resource_id.trim(),
      account_id: resourceDraft.account_id.trim() || null,
      region: resourceDraft.region.trim() || null,
      ip_version: resourceDraft.ip_version,
      origin_id: resourceDraft.origin_id === "" ? null : Number(resourceDraft.origin_id),
      current_ip: resourceDraft.current_ip.trim() || null,
      port: resourceDraft.port,
      enabled: resourceDraft.enabled,
      auto_change_on_blocked: resourceDraft.auto_change_on_blocked,
      auto_update_origin: resourceDraft.auto_update_origin,
      cooldown_seconds: resourceDraft.cooldown_seconds,
      remark: resourceDraft.remark.trim() || null
    };
  }

  function remoteResourceLabel(resource: AzPanelRemoteResource): string {
    const ip = resource.current_ip ? ` · ${resource.current_ip}` : "";
    const region = resource.region ? ` · ${resource.region}` : "";
    const version = resource.ip_version === "ipv6" ? "IPv6" : "IPv4";
    const source = resource.cached ? ` · 本地缓存 ${fmtDate(resource.last_seen_at)}` : "";
    return `${resource.name}${region} · ${version}${ip}${source}`;
  }

  function applyRemoteResource(resource: AzPanelRemoteResource) {
    setSelectedRemoteKey(resource.key);
    setResourceDraft((current) => ({
      ...current,
      name: resource.name || current.name,
      provider: resource.provider,
      resource_id: resource.resource_id,
      account_id: resource.account_id || "",
      region: resource.region || "",
      ip_version: resource.ip_version,
      current_ip: resource.current_ip || "",
      port: resource.port || current.port || 22,
      remark: current.remark || resource.remark || resource.status || ""
    }));
  }

  async function refreshRemoteResources() {
    let fetched: AzPanelRemoteResource[] = [];
    const ok = await act(
      async () => {
        fetched = await apiFetch<AzPanelRemoteResource[]>(`/api/integrations/azpanel/remote-resources?provider=${encodeURIComponent(remoteProvider)}`, token);
      },
      "远端资源已刷新",
      () => {
        setRemoteResources(fetched);
        if (fetched.length > 0) {
          applyRemoteResource(fetched[0]);
        }
      }
    );
    if (!ok) {
      setRemoteResources([]);
      setSelectedRemoteKey("");
    }
  }

  async function saveSettings(event: FormEvent) {
    event.preventDefault();
    const payload: Record<string, string | number | boolean> = {
      enabled: settingsDraft.enabled,
      base_url: settingsDraft.base_url.trim(),
      timeout_seconds: settingsDraft.timeout_seconds,
      default_cooldown_seconds: settingsDraft.default_cooldown_seconds
    };
    if (settingsDraft.api_token.trim()) payload.api_token = settingsDraft.api_token.trim();
    await act(
      () => apiFetch("/api/integrations/azpanel/settings", token, { method: "PATCH", body: JSON.stringify(payload) }),
      "azpanel 设置已保存"
    );
  }

  async function saveResource(event: FormEvent) {
    event.preventDefault();
    if (!resourceDraft.resource_id.trim()) {
      await act(async () => {
        throw new Error("请先刷新并选择 azpanel 资源");
      });
      return;
    }
    const method = editingId ? "PATCH" : "POST";
    const path = editingId ? `/api/integrations/azpanel/resources/${editingId}` : "/api/integrations/azpanel/resources";
    await act(
      () => apiFetch(path, token, { method, body: JSON.stringify(resourcePayload()) }),
      editingId ? "资源已更新" : "资源已添加",
      () => {
        setEditingId(null);
        setResourceDraft(emptyDraft());
        setSelectedRemoteKey("");
      }
    );
  }

  function editResource(resource: AzPanelResource) {
    setEditingId(resource.id);
    setSelectedRemoteKey("");
    setRemoteProvider(resource.provider === "aws" ? "aws" : "azure");
    setResourceDraft({
      name: resource.name,
      provider: resource.provider,
      resource_id: resource.resource_id,
      account_id: resource.account_id || "",
      region: resource.region || "",
      ip_version: resource.ip_version,
      origin_id: resource.origin_id || "",
      current_ip: resource.current_ip || "",
      port: resource.port,
      enabled: resource.enabled,
      auto_change_on_blocked: resource.auto_change_on_blocked,
      auto_update_origin: resource.auto_update_origin,
      cooldown_seconds: resource.cooldown_seconds,
      remark: resource.remark || ""
    });
  }

  return (
    <section className="stack">
      <form className="panel" onSubmit={saveSettings}>
        <div className="panelTitle">
          <h2>azpanel 连接</h2>
          <p>需要 azpanel 提供内部接口：<code>/api/internal/cloudflare-dns/change-ip</code>。Token 会加密保存。</p>
        </div>
        <div className="settingsGrid">
          <label className="inlineCheck">
            <input type="checkbox" checked={settingsDraft.enabled} onChange={(event) => setSettingsDraft((current) => ({ ...current, enabled: event.target.checked }))} />
            启用自动换 IP
          </label>
          <label>
            azpanel 地址
            <input placeholder="https://az.example.com" value={settingsDraft.base_url} onChange={(event) => setSettingsDraft((current) => ({ ...current, base_url: event.target.value }))} />
          </label>
          <label>
            API Token
            <input type="password" placeholder={settings.api_token_configured ? "已保存，留空不修改" : "填写内部 API Token"} value={settingsDraft.api_token} onChange={(event) => setSettingsDraft((current) => ({ ...current, api_token: event.target.value }))} />
          </label>
          <label>
            请求超时（秒）
            <input type="number" min={5} max={300} value={settingsDraft.timeout_seconds} onChange={(event) => setSettingsDraft((current) => ({ ...current, timeout_seconds: Number(event.target.value) }))} />
          </label>
          <label>
            默认冷却（秒）
            <input type="number" min={60} max={86400} value={settingsDraft.default_cooldown_seconds} onChange={(event) => setSettingsDraft((current) => ({ ...current, default_cooldown_seconds: Number(event.target.value) }))} />
          </label>
        </div>
        <button>
          <Save size={16} />
          <span>保存 azpanel 设置</span>
        </button>
      </form>

      <form className="panel" onSubmit={saveResource}>
        <div className="panelTitle">
          <h2>{editingId ? "修改云资源" : "添加云资源"}</h2>
          <p>先从 azpanel 获取资源再选择，AWS 加载过的机器会保存到本地缓存。</p>
        </div>
        <div className="settingsGrid">
          <label>
            来源云厂商
            <select value={remoteProvider} onChange={(event) => setRemoteProvider(event.target.value)}>
              <option value="azure">Azure</option>
              <option value="aws">AWS</option>
            </select>
          </label>
          <div className="settingsGridActions">
            <button type="button" className="secondary" onClick={refreshRemoteResources}>
              <RefreshCw size={16} />
              <span>刷新资源</span>
            </button>
            <small>从 azpanel 拉取可用资源；拉取过的 AWS 机器会保留在本地表。</small>
          </div>
          <label className="wideField">
            azpanel 资源
            <select
              value={selectedRemoteKey}
              onChange={(event) => {
                const value = event.target.value;
                setSelectedRemoteKey(value);
                const resource = remoteResources.find((item) => item.key === value);
                if (resource) applyRemoteResource(resource);
              }}
            >
              <option value="">{remoteResources.length ? "请选择资源" : "先点击刷新资源"}</option>
              {remoteResources.map((resource) => (
                <option key={resource.key} value={resource.key}>{remoteResourceLabel(resource)}</option>
              ))}
            </select>
          </label>
          <label>
            名称
            <input value={resourceDraft.name} onChange={(event) => setResourceDraft((current) => ({ ...current, name: event.target.value }))} required />
          </label>
          <label>
            云厂商
            <input value={resourceDraft.provider ? resourceDraft.provider.toUpperCase() : ""} readOnly />
          </label>
          <label>
            资源 ID
            <input placeholder="从 azpanel 资源自动带入" value={resourceDraft.resource_id} readOnly required />
          </label>
          <label>
            账户 ID
            <input value={resourceDraft.account_id || "未提供"} readOnly />
          </label>
          <label>
            区域
            <input value={resourceDraft.region || "未提供"} readOnly />
          </label>
          <label>
            IP 类型
            <input value={resourceDraft.ip_version === "ipv6" ? "IPv6" : "IPv4"} readOnly />
          </label>
          <label>
            绑定源站
            <select value={resourceDraft.origin_id} onChange={(event) => setResourceDraft((current) => ({ ...current, origin_id: event.target.value ? Number(event.target.value) : "" }))}>
              <option value="">不绑定</option>
              {origins.map((origin) => <option key={origin.id} value={origin.id}>{origin.label}</option>)}
            </select>
          </label>
          <label>
            当前 IP
            <input value={resourceDraft.current_ip || "未记录"} readOnly />
          </label>
          <label>
            检查端口
            <input type="number" min={1} max={65535} value={resourceDraft.port} onChange={(event) => setResourceDraft((current) => ({ ...current, port: Number(event.target.value) }))} />
          </label>
          <label>
            冷却（秒）
            <input type="number" min={60} max={86400} value={resourceDraft.cooldown_seconds} onChange={(event) => setResourceDraft((current) => ({ ...current, cooldown_seconds: Number(event.target.value) }))} />
          </label>
          <label>
            备注
            <input value={resourceDraft.remark} onChange={(event) => setResourceDraft((current) => ({ ...current, remark: event.target.value }))} />
          </label>
          <label className="inlineCheck">
            <input type="checkbox" checked={resourceDraft.enabled} onChange={(event) => setResourceDraft((current) => ({ ...current, enabled: event.target.checked }))} />
            启用
          </label>
          <label className="inlineCheck">
            <input type="checkbox" checked={resourceDraft.auto_change_on_blocked} onChange={(event) => setResourceDraft((current) => ({ ...current, auto_change_on_blocked: event.target.checked }))} />
            源站故障自动换 IP
          </label>
          <label className="inlineCheck">
            <input type="checkbox" checked={resourceDraft.auto_update_origin} onChange={(event) => setResourceDraft((current) => ({ ...current, auto_update_origin: event.target.checked }))} />
            成功后更新源站
          </label>
        </div>
        <div className="rowActions">
          <button>
            <Save size={16} />
            <span>{editingId ? "保存资源" : "添加资源"}</span>
          </button>
          {editingId && <button type="button" className="secondary" onClick={() => { setEditingId(null); setResourceDraft(emptyDraft()); setSelectedRemoteKey(""); }}>取消编辑</button>}
        </div>
      </form>

      <div className="panel">
        <div className="panelTitle">
          <h2>云资源</h2>
          <p>手动换 IP 会立即调用 azpanel；自动换 IP 会在绑定的当前源站疑似被墙、机器挂了或本地不可达时触发。</p>
        </div>
        <div className="poolList">
          {resources.map((resource) => (
            <div className="poolItem" key={resource.id}>
              <div className="poolItemMain">
                <strong>{resource.name}</strong>
                <span>{resource.provider} · {resource.resource_id} · {resource.current_ip || "未记录 IP"}:{resource.port} · 尝试 {fmtDate(resource.last_attempt_at)} · 成功 {fmtDate(resource.last_change_at)}</span>
                {resource.last_error && <small className="danger">{resource.last_error}</small>}
              </div>
              <div className="rowActions">
                <Status value={resource.enabled ? "enabled" : "disabled"} />
                <button className="icon secondaryIcon" title="手动更换 IP" onClick={() => act(() => apiFetch(`/api/integrations/azpanel/resources/${resource.id}/change-ip`, token, { method: "POST", body: JSON.stringify({ reason: "manual from panel" }) }), "换 IP 任务已执行")}>
                  <RefreshCw size={15} />
                </button>
                <button className="icon secondaryIcon" title="编辑" onClick={() => editResource(resource)}>
                  <Pencil size={15} />
                </button>
                <button className="icon dangerBtn" title="删除" onClick={() => act(() => apiFetch(`/api/integrations/azpanel/resources/${resource.id}`, token, { method: "DELETE" }), "云资源已删除")}>
                  <Trash2 size={15} />
                </button>
              </div>
            </div>
          ))}
          {resources.length === 0 && <div className="emptyCell">还没有绑定云资源</div>}
        </div>
      </div>

      <IpChangeJobsPanel jobs={jobs} />
    </section>
  );
}

function XboardPanel({
  token,
  settings,
  nodes,
  resources,
  groups,
  jobs,
  act
}: {
  token: string;
  settings: XboardSettings;
  nodes: XboardNodeBinding[];
  resources: AzPanelResource[];
  groups: FailoverGroup[];
  jobs: IpChangeJob[];
  act: ActionRunner;
}) {
  const [settingsDraft, setSettingsDraft] = useState<XboardSettingsDraft>({
    enabled: settings.enabled,
    base_url: settings.base_url,
    api_token: "",
    timeout_seconds: settings.timeout_seconds
  });
  const emptyDraft = (): XboardNodeDraft => ({
    name: "",
    xboard_node_id: 1,
    node_type: "",
    host: "",
    port: "",
    origin_id: "",
    azpanel_resource_id: "",
    enabled: true,
    auto_update_after_change: true,
    remark: ""
  });
  const [nodeDraft, setNodeDraft] = useState<XboardNodeDraft>(emptyDraft);
  const [editingId, setEditingId] = useState<number | null>(null);
  const origins = originOptions(groups);

  useEffect(() => {
    setSettingsDraft({ enabled: settings.enabled, base_url: settings.base_url, api_token: "", timeout_seconds: settings.timeout_seconds });
  }, [settings]);

  async function saveSettings(event: FormEvent) {
    event.preventDefault();
    const payload: Record<string, string | number | boolean> = {
      enabled: settingsDraft.enabled,
      base_url: settingsDraft.base_url.trim(),
      timeout_seconds: settingsDraft.timeout_seconds
    };
    if (settingsDraft.api_token.trim()) payload.api_token = settingsDraft.api_token.trim();
    await act(
      () => apiFetch("/api/integrations/xboard/settings", token, { method: "PATCH", body: JSON.stringify(payload) }),
      "Xboard 设置已保存"
    );
  }

  function nodePayload() {
    return {
      name: nodeDraft.name.trim(),
      xboard_node_id: nodeDraft.xboard_node_id,
      node_type: nodeDraft.node_type.trim() || null,
      host: nodeDraft.host.trim() || null,
      port: nodeDraft.port === "" ? null : Number(nodeDraft.port),
      origin_id: nodeDraft.origin_id === "" ? null : Number(nodeDraft.origin_id),
      azpanel_resource_id: nodeDraft.azpanel_resource_id === "" ? null : Number(nodeDraft.azpanel_resource_id),
      enabled: nodeDraft.enabled,
      auto_update_after_change: nodeDraft.auto_update_after_change,
      remark: nodeDraft.remark.trim() || null
    };
  }

  async function saveNode(event: FormEvent) {
    event.preventDefault();
    const method = editingId ? "PATCH" : "POST";
    const path = editingId ? `/api/integrations/xboard/nodes/${editingId}` : "/api/integrations/xboard/nodes";
    await act(
      () => apiFetch(path, token, { method, body: JSON.stringify(nodePayload()) }),
      editingId ? "节点绑定已更新" : "节点绑定已添加",
      () => {
        setEditingId(null);
        setNodeDraft(emptyDraft());
      }
    );
  }

  function editNode(node: XboardNodeBinding) {
    setEditingId(node.id);
    setNodeDraft({
      name: node.name,
      xboard_node_id: node.xboard_node_id,
      node_type: node.node_type || "",
      host: node.host || "",
      port: node.port || "",
      origin_id: node.origin_id || "",
      azpanel_resource_id: node.azpanel_resource_id || "",
      enabled: node.enabled,
      auto_update_after_change: node.auto_update_after_change,
      remark: node.remark || ""
    });
  }

  return (
    <section className="stack">
      <form className="panel" onSubmit={saveSettings}>
        <div className="panelTitle">
          <h2>Xboard 联动</h2>
          <p>默认不需要改 Xboard。这里主要保存节点和云资源绑定；换 IP 后 Xboard 后端会自行上报并同步解析。</p>
        </div>
        <div className="settingsGrid">
          <label className="inlineCheck">
            <input type="checkbox" checked={settingsDraft.enabled} onChange={(event) => setSettingsDraft((current) => ({ ...current, enabled: event.target.checked }))} />
            主动通知 Xboard API
          </label>
          <label>
            Xboard 地址
            <input placeholder="https://xboard.example.com" value={settingsDraft.base_url} onChange={(event) => setSettingsDraft((current) => ({ ...current, base_url: event.target.value }))} />
          </label>
          <label>
            API Token
            <input type="password" placeholder={settings.api_token_configured ? "已保存，留空不修改" : "可选"} value={settingsDraft.api_token} onChange={(event) => setSettingsDraft((current) => ({ ...current, api_token: event.target.value }))} />
          </label>
          <label>
            请求超时（秒）
            <input type="number" min={5} max={120} value={settingsDraft.timeout_seconds} onChange={(event) => setSettingsDraft((current) => ({ ...current, timeout_seconds: Number(event.target.value) }))} />
          </label>
        </div>
        <button>
          <Save size={16} />
          <span>保存 Xboard 设置</span>
        </button>
      </form>

      <form className="panel" onSubmit={saveNode}>
        <div className="panelTitle">
          <h2>{editingId ? "修改节点绑定" : "添加节点绑定"}</h2>
          <p>把 Xboard 节点绑定到 azpanel 云资源，点击换 IP 时只触发 azpanel。</p>
        </div>
        <div className="settingsGrid">
          <label>
            节点名称
            <input value={nodeDraft.name} onChange={(event) => setNodeDraft((current) => ({ ...current, name: event.target.value }))} required />
          </label>
          <label>
            Xboard 节点 ID
            <input type="number" min={1} value={nodeDraft.xboard_node_id} onChange={(event) => setNodeDraft((current) => ({ ...current, xboard_node_id: Number(event.target.value) }))} />
          </label>
          <label>
            节点类型
            <input placeholder="vless / trojan / shadowsocks" value={nodeDraft.node_type} onChange={(event) => setNodeDraft((current) => ({ ...current, node_type: event.target.value }))} />
          </label>
          <label>
            当前 Host/IP
            <input value={nodeDraft.host} onChange={(event) => setNodeDraft((current) => ({ ...current, host: event.target.value }))} />
          </label>
          <label>
            节点端口
            <input type="number" min={1} max={65535} value={nodeDraft.port} onChange={(event) => setNodeDraft((current) => ({ ...current, port: event.target.value ? Number(event.target.value) : "" }))} />
          </label>
          <label>
            绑定 azpanel 资源
            <select value={nodeDraft.azpanel_resource_id} onChange={(event) => setNodeDraft((current) => ({ ...current, azpanel_resource_id: event.target.value ? Number(event.target.value) : "" }))}>
              <option value="">不绑定</option>
              {resources.map((resource) => <option key={resource.id} value={resource.id}>{resource.name} · {resource.current_ip || resource.resource_id}</option>)}
            </select>
          </label>
          <label>
            关联故障源站
            <select value={nodeDraft.origin_id} onChange={(event) => setNodeDraft((current) => ({ ...current, origin_id: event.target.value ? Number(event.target.value) : "" }))}>
              <option value="">不关联</option>
              {origins.map((origin) => <option key={origin.id} value={origin.id}>{origin.label}</option>)}
            </select>
          </label>
          <label>
            备注
            <input value={nodeDraft.remark} onChange={(event) => setNodeDraft((current) => ({ ...current, remark: event.target.value }))} />
          </label>
          <label className="inlineCheck">
            <input type="checkbox" checked={nodeDraft.enabled} onChange={(event) => setNodeDraft((current) => ({ ...current, enabled: event.target.checked }))} />
            启用
          </label>
          <label className="inlineCheck">
            <input type="checkbox" checked={nodeDraft.auto_update_after_change} onChange={(event) => setNodeDraft((current) => ({ ...current, auto_update_after_change: event.target.checked }))} />
            换 IP 后更新绑定记录
          </label>
        </div>
        <div className="rowActions">
          <button>
            <Save size={16} />
            <span>{editingId ? "保存节点" : "添加节点"}</span>
          </button>
          {editingId && <button type="button" className="secondary" onClick={() => { setEditingId(null); setNodeDraft(emptyDraft()); }}>取消编辑</button>}
        </div>
      </form>

      <div className="panel">
        <div className="panelTitle">
          <h2>节点列表</h2>
          <p>手动换 IP 会调用绑定的 azpanel 资源。Xboard 后端恢复上报后会自己同步解析。</p>
        </div>
        <div className="poolList">
          {nodes.map((node) => {
            const resource = resources.find((item) => item.id === node.azpanel_resource_id);
            return (
              <div className="poolItem" key={node.id}>
                <div className="poolItemMain">
                  <strong>{node.name}</strong>
                  <span>节点 {node.xboard_node_id} · {node.node_type || "未知类型"} · {node.host || "未记录 Host"}{node.port ? `:${node.port}` : ""}</span>
                  <small>{resource ? `绑定资源：${resource.name}` : "未绑定 azpanel 资源"} · 最近同步 {fmtDate(node.last_sync_at)}</small>
                  {node.last_error && <small className="danger">{node.last_error}</small>}
                </div>
                <div className="rowActions">
                  <Status value={node.enabled ? "enabled" : "disabled"} />
                  <button className="icon secondaryIcon" title="更换节点 IP" disabled={!node.azpanel_resource_id} onClick={() => act(() => apiFetch(`/api/integrations/xboard/nodes/${node.id}/change-ip`, token, { method: "POST", body: JSON.stringify({ reason: "Xboard node manual change" }) }), "节点换 IP 已执行")}>
                    <RefreshCw size={15} />
                  </button>
                  <button className="icon secondaryIcon" title="编辑" onClick={() => editNode(node)}>
                    <Pencil size={15} />
                  </button>
                  <button className="icon dangerBtn" title="删除" onClick={() => act(() => apiFetch(`/api/integrations/xboard/nodes/${node.id}`, token, { method: "DELETE" }), "节点绑定已删除")}>
                    <Trash2 size={15} />
                  </button>
                </div>
              </div>
            );
          })}
          {nodes.length === 0 && <div className="emptyCell">还没有 Xboard 节点绑定</div>}
        </div>
      </div>

      <IpChangeJobsPanel jobs={jobs} />
    </section>
  );
}

function IpChangeJobsPanel({ jobs }: { jobs: IpChangeJob[] }) {
  return (
    <div className="panel">
      <div className="panelTitle">
        <h2>最近换 IP 记录</h2>
        <p>用于判断自动换 IP 是否真的触发，以及 azpanel 返回了什么状态。</p>
      </div>
      <div className="eventList">
        {jobs.slice(0, 12).map((job) => (
          <div className="eventItem" key={job.id}>
            <div>
              <strong>#{job.id} · {statusText(job.status)}</strong>
              <p>{job.provider || "-"} · {job.old_ip || "-"} → {job.new_ip || "-"} · {job.trigger_type}</p>
              {job.error && <small className="danger">{job.error}</small>}
            </div>
            <time>{fmtDate(job.finished_at || job.started_at)}</time>
          </div>
        ))}
        {jobs.length === 0 && <div className="emptyCell">暂无换 IP 记录</div>}
      </div>
    </div>
  );
}

function AgentsPanel({ token, agents, agentToken, setAgentToken, act }: { token: string; agents: Agent[]; agentToken: string; setAgentToken: (value: string) => void; act: ActionRunner }) {
  const [name, setName] = useState("");
  const [region, setRegion] = useState<"china" | "foreign">("china");
  const [copied, setCopied] = useState(false);
  const [editingAgentId, setEditingAgentId] = useState<number | null>(null);
  const [agentEdits, setAgentEdits] = useState<Record<number, AgentEditDraft>>({});
  const panelUrl = window.location.origin;
  const installScriptUrl = `${panelUrl}/api/agent/install.sh`;
  const runInstallCommand = `CONTROL_URL=${shellQuote(panelUrl)} AGENT_TOKEN=${shellQuote(agentToken)} bash /tmp/cloudflare-dns-agent-install.sh`;
  const sudoInstallCommand = `sudo env CONTROL_URL=${shellQuote(panelUrl)} AGENT_TOKEN=${shellQuote(agentToken)} bash /tmp/cloudflare-dns-agent-install.sh`;
  const installCommand = `curl -fsSL ${shellQuote(installScriptUrl)} -o /tmp/cloudflare-dns-agent-install.sh && if [ "$(id -u)" -eq 0 ]; then ${runInstallCommand}; else ${sudoInstallCommand}; fi`;
  const isLocalPanelUrl = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/.test(panelUrl);

  async function copyInstallCommand() {
    await navigator.clipboard.writeText(installCommand);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  }

  async function createAgent(event: FormEvent) {
    event.preventDefault();
    setCopied(false);
    await act(async () => {
      const data = await apiFetch<{ token: string }>("/api/agents", token, {
        method: "POST",
        body: JSON.stringify({ name, region })
      });
      setAgentToken(data.token);
    }, "探针已创建");
    setName("");
    setRegion("china");
  }

  function beginEditAgent(agent: Agent) {
    setEditingAgentId(agent.id);
    setAgentEdits((current) => ({
      ...current,
      [agent.id]: { name: agent.name }
    }));
  }

  async function saveAgentEdit(agentId: number) {
    const draft = agentEdits[agentId];
    if (!draft) return;
    await act(
      () => {
        const nextName = draft.name.trim();
        if (!nextName) {
          throw new Error("探针名称不能为空");
        }
        return apiFetch(`/api/agents/${agentId}`, token, {
          method: "PATCH",
          body: JSON.stringify({ name: nextName })
        });
      },
      "探针名称已更新",
      () => setEditingAgentId(null)
    );
  }

  return (
    <section className="gridTwo">
      <form className="panel" onSubmit={createAgent}>
        <h2>新建探针</h2>
        <label>
          名称
          <input value={name} onChange={(event) => setName(event.target.value)} required />
        </label>
        <label>
          探针区域
          <select value={region} onChange={(event) => setRegion(event.target.value as "china" | "foreign")}>
            <option value="china">国内探针</option>
            <option value="foreign">国外探针</option>
          </select>
        </label>
        <button>
          <RadioTower size={16} />
          <span>创建</span>
        </button>
        {agentToken && (
          <div className="agentSecret">
            <h3>一键安装命令</h3>
            <p>复制下面整条命令到对应区域服务器的 root 终端执行。安装后会自动创建 <code>cloudflare-dns-agent</code> 服务，并持续从面板拉取探测任务。</p>
            {isLocalPanelUrl && <p className="warningText">当前面板地址是本地地址，复制到服务器前请把命令里的 <code>{panelUrl}</code> 改成你的面板公网 HTTPS 地址。</p>}
            <div className="commandHeader">
              <span>只显示这一次，创建后请立即保存或执行。</span>
              <button type="button" className="miniBtn" onClick={copyInstallCommand}>
                <Copy size={14} />
                <span>{copied ? "已复制" : "复制"}</span>
              </button>
            </div>
            <pre className="tokenBox commandBox">{installCommand}</pre>
            <h3>探针注册令牌</h3>
            <pre className="tokenBox">{agentToken}</pre>
          </div>
        )}
      </form>
      <div className="panel">
        <div className="panelTitle">
          <h2>探针服务器状态</h2>
          <p>设置默认探针后，所有源站优先使用默认探针；默认探针离线时，其他在线探针接力复检。未设置默认时，仍按同区域顺序接力。</p>
        </div>
        <div className="agentStatusGrid">
          {agents.map((agent) => {
            const edit = agentEdits[agent.id] || { name: agent.name };
            const isEditing = editingAgentId === agent.id;
            return (
              <div className="agentStatusCard" key={agent.id}>
                <div className="agentStatusHead">
                  {isEditing ? (
                    <label className="agentNameEdit">
                      探针名称
                      <input value={edit.name} onChange={(event) => setAgentEdits((current) => ({ ...current, [agent.id]: { name: event.target.value } }))} autoFocus />
                    </label>
                  ) : (
                    <strong>{agent.name}</strong>
                  )}
                  <div className="rowActions compactInline">
                    {agent.is_default && <span className="originBadge primary">默认</span>}
                    <Status value={agent.enabled ? agent.status : "disabled"} />
                  </div>
                </div>
                <span>区域：{agentRegionText(agent.region)}</span>
                <span>默认探针：{agent.is_default ? "是" : "否"}</span>
                <span>启用状态：{agent.enabled ? "已启用" : "已停用"}</span>
                <span>最后 IP：{agent.last_ip || "-"}</span>
                <span>最后上报：{fmtDate(agent.last_seen_at)}</span>
                <div className="rowActions">
                  {isEditing ? (
                    <>
                      <button className="icon" title="保存探针名称" onClick={() => saveAgentEdit(agent.id)}>
                        <Save size={15} />
                      </button>
                      <button className="icon secondaryIcon" title="取消改名" onClick={() => setEditingAgentId(null)}>
                        ×
                      </button>
                    </>
                  ) : (
                    <>
                      <button className="icon secondaryIcon" title="修改探针名称" onClick={() => beginEditAgent(agent)}>
                        <Pencil size={15} />
                      </button>
                      <button
                        className="secondary compactBtn"
                        title={agent.is_default ? "取消默认探针" : "设为默认探针"}
                        onClick={() =>
                          act(
                            () =>
                              apiFetch(`/api/agents/${agent.id}`, token, {
                                method: "PATCH",
                                body: JSON.stringify({ is_default: !agent.is_default })
                              }),
                            agent.is_default ? "已取消默认探针" : "默认探针已更新"
                          )
                        }
                      >
                        <RadioTower size={15} />
                        <span>{agent.is_default ? "取消默认" : "设为默认"}</span>
                      </button>
                      <button
                        className="icon secondaryIcon"
                        title={agent.enabled ? "停用探针" : "启用探针"}
                        onClick={() =>
                          act(
                            () => apiFetch(`/api/agents/${agent.id}/${agent.enabled ? "disable" : "enable"}`, token, { method: "PATCH" }),
                            agent.enabled ? "探针已停用" : "探针已启用"
                          )
                        }
                      >
                        {agent.enabled ? <PowerOff size={15} /> : <Power size={15} />}
                      </button>
                      <button className="icon dangerBtn" title="删除探针" onClick={() => act(() => apiFetch(`/api/agents/${agent.id}`, token, { method: "DELETE" }), "探针已删除")}>
                        <Trash2 size={15} />
                      </button>
                    </>
                  )}
                </div>
              </div>
            );
          })}
          {agents.length === 0 && <div className="emptyCell">还没有探针服务器</div>}
        </div>
      </div>
    </section>
  );
}

function SettingsPanel({ token, settings, act }: { token: string; settings: SystemSettings; act: ActionRunner }) {
  const [draft, setDraft] = useState<SystemSettingsDraft>(() => systemSettingsToDraft(settings));

  useEffect(() => {
    setDraft(systemSettingsToDraft(settings));
  }, [settings]);

  const sections: { title: string; description: string; fields: SystemSettingField[] }[] = [
    {
      title: "健康检查",
      description: "控制本地与探针的 TCP 检查频率、超时和连续判定阈值。",
      fields: [
        { key: "check_interval_seconds", label: "探针检查周期", min: 10, max: 3600, hint: "秒" },
        { key: "check_timeout_seconds", label: "TCP 超时", min: 1, max: 60, step: 0.1, hint: "秒" },
        { key: "fail_threshold", label: "连续失败判故障", min: 1, max: 20, hint: "次" },
        { key: "recovery_threshold", label: "连续成功判恢复", min: 1, max: 20, hint: "次" }
      ]
    },
    {
      title: "通知与外部来源",
      description: "控制无健康源站通知防抖，以及 Nyanpass 等外部 IP 来源的默认拉取周期。",
      fields: [
        { key: "no_healthy_notification_interval_seconds", label: "无健康源站通知间隔", min: 60, max: 86400, hint: "秒" },
        { key: "external_ip_sync_interval_seconds", label: "外部 IP 默认拉取周期", min: 60, max: 86400, hint: "秒" }
      ]
    },
    {
      title: "登录安全",
      description: "控制登录有效期、记住登录有效期和爆破保护锁定策略。",
      fields: [
        { key: "access_token_ttl_seconds", label: "普通登录有效期", min: 3600, max: 31536000, hint: "秒" },
        { key: "access_token_remember_ttl_seconds", label: "记住登录有效期", min: 3600, max: 31536000, hint: "秒" },
        { key: "login_lockout_enabled", label: "启用登录失败锁定", type: "toggle", hint: "连续失败后自动锁定登录" },
        { key: "login_max_failures", label: "最大失败次数", min: 1, max: 100, hint: "次" },
        { key: "login_failure_window_seconds", label: "失败统计窗口", min: 60, max: 86400, hint: "秒" },
        { key: "login_lockout_seconds", label: "锁定时间", min: 60, max: 86400, hint: "秒" },
        { key: "cloudflare_access_enabled", label: "启用 Cloudflare Access", type: "toggle", hint: "开启后必须先通过 Cloudflare Access 才能登录后台" }
      ]
    }
  ];

  function updateField(key: keyof SystemSettings, value: string) {
    setDraft((current) => ({ ...current, [key]: value }));
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const payload = Object.fromEntries(
      sections
        .flatMap((section) => section.fields)
        .map((field) => [
          field.key,
          field.type === "toggle" ? (draft[field.key] === "1" ? 1 : 0) : field.key === "check_timeout_seconds" ? Number.parseFloat(draft[field.key]) : Number.parseInt(draft[field.key], 10)
        ])
    );
    await act(
      () =>
        apiFetch("/api/settings", token, {
          method: "PATCH",
          body: JSON.stringify(payload)
        }),
      "设置已保存"
    );
  }

  return (
    <form className="panel settingsPanel" onSubmit={submit}>
      <div className="panelTitle">
        <h2>系统设置</h2>
        <p>这些参数保存在数据库里，保存后下一轮检查会自动生效，不需要登录服务器修改配置。</p>
      </div>
      <div className="settingsSections">
        {sections.map((section) => (
          <section className="settingsSection" key={section.title}>
            <div className="panelTitle">
              <h3>{section.title}</h3>
              <p>{section.description}</p>
            </div>
            <div className="settingsGrid">
              {section.fields.map((field) => (
                <label key={field.key}>
                  {field.label}
                  {field.type === "toggle" ? (
                    <span className="settingToggleLine">
                      <input
                        type="checkbox"
                        checked={draft[field.key] === "1"}
                        onChange={(event) => updateField(field.key, event.target.checked ? "1" : "0")}
                      />
                      <strong>{draft[field.key] === "1" ? "已开启" : "已关闭"}</strong>
                    </span>
                  ) : (
                    <input
                      type="number"
                      min={field.min}
                      max={field.max}
                      step={field.step || 1}
                      value={draft[field.key]}
                      onChange={(event) => updateField(field.key, event.target.value)}
                      required
                    />
                  )}
                  <span>{field.type === "toggle" ? field.hint : `${field.min} - ${field.max}${field.hint ? ` ${field.hint}` : ""}`}</span>
                </label>
              ))}
            </div>
          </section>
        ))}
      </div>
      <div className="formActions">
        <button>
          <Save size={16} />
          <span>保存设置</span>
        </button>
      </div>
    </form>
  );
}

function AccountPanel({ token, onPasswordChanged }: { token: string; onPasswordChanged: () => void }) {
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [username, setUsername] = useState("");
  const [usernamePassword, setUsernamePassword] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiFetch<UserProfile>("/api/auth/me", token)
      .then((user) => {
        setProfile(user);
        setUsername(user.username);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "无法读取账户信息"));
  }, [token]);

  async function submitUsername(event: FormEvent) {
    event.preventDefault();
    setMessage("");
    setError("");
    setBusy(true);
    try {
      const updated = await apiFetch<UserProfile>("/api/auth/username", token, {
        method: "PATCH",
        body: JSON.stringify({ username: username.trim(), current_password: usernamePassword })
      });
      setProfile(updated);
      setUsername(updated.username);
      setUsernamePassword("");
      setMessage("账户名已修改");
      try {
        localStorage.setItem(rememberedUsernameStorageKey, updated.username);
      } catch {
        // Ignore private browsing or storage-disabled environments.
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "账户名修改失败");
    } finally {
      setBusy(false);
    }
  }

  async function submitPassword(event: FormEvent) {
    event.preventDefault();
    setMessage("");
    setError("");
    if (newPassword !== confirmPassword) {
      setError("两次输入的新密码不一致");
      return;
    }
    setBusy(true);
    try {
      await apiFetch("/api/auth/password", token, {
        method: "PATCH",
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword })
      });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setMessage("密码已修改，请用新密码重新登录");
      window.setTimeout(onPasswordChanged, 900);
    } catch (err) {
      setError(err instanceof Error ? err.message : "密码修改失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel accountPanel">
      <div className="panelTitle">
        <h2>账户</h2>
        <p>当前账户：{profile ? profile.username : "读取中"}</p>
      </div>
      {message && <div className="notice success">{message}</div>}
      {error && <div className="error">{error}</div>}
      <form onSubmit={submitUsername}>
        <h3>修改账户名</h3>
        <label>
          新账户名
          <input minLength={3} maxLength={80} value={username} onChange={(event) => setUsername(event.target.value)} required />
        </label>
        <label>
          当前密码
          <input type="password" value={usernamePassword} onChange={(event) => setUsernamePassword(event.target.value)} required />
        </label>
        <button disabled={busy}>
          <Save size={16} />
          <span>{busy ? "保存中" : "保存账户名"}</span>
        </button>
      </form>
      <form onSubmit={submitPassword}>
        <h3>修改登录密码</h3>
        <label>
          当前密码
          <input type="password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} required />
        </label>
        <label>
          新密码
          <input type="password" minLength={8} value={newPassword} onChange={(event) => setNewPassword(event.target.value)} required />
        </label>
        <label>
          确认新密码
          <input type="password" minLength={8} value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} required />
        </label>
        <button disabled={busy}>
          <LockKeyhole size={16} />
          <span>{busy ? "保存中" : "保存新密码"}</span>
        </button>
      </form>
    </section>
  );
}

function NotificationsPanel({
  token,
  telegramNotifications,
  webhooks,
  act
}: {
  token: string;
  telegramNotifications: TelegramNotification[];
  webhooks: Webhook[];
  act: ActionRunner;
}) {
  const [telegramName, setTelegramName] = useState("");
  const [botToken, setBotToken] = useState("");
  const [chatId, setChatId] = useState("");
  const [telegramNotifyLevel, setTelegramNotifyLevel] = useState("important");
  const [editingTelegramId, setEditingTelegramId] = useState<number | null>(null);
  const [telegramEdit, setTelegramEdit] = useState<{ name: string; chat_id: string; bot_token: string; notify_level: string; enabled: boolean }>({
    name: "",
    chat_id: "",
    bot_token: "",
    notify_level: "important",
    enabled: true
  });
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");

  async function submitTelegram(event: FormEvent) {
    event.preventDefault();
    await act(
      () =>
        apiFetch("/api/telegram", token, {
          method: "POST",
          body: JSON.stringify({ name: telegramName, bot_token: botToken, chat_id: chatId, notify_level: telegramNotifyLevel, enabled: true })
        }),
      "Telegram 通知已保存"
    );
    setTelegramName("");
    setBotToken("");
    setChatId("");
    setTelegramNotifyLevel("important");
  }

  async function submitWebhook(event: FormEvent) {
    event.preventDefault();
    await act(
      () =>
        apiFetch("/api/webhooks", token, {
          method: "POST",
          body: JSON.stringify({ name, url, secret: secret || null, enabled: true })
        }),
      "Webhook 已保存"
    );
    setName("");
    setUrl("");
    setSecret("");
  }

  function beginEditTelegram(item: TelegramNotification) {
    setEditingTelegramId(item.id);
    setTelegramEdit({ name: item.name, chat_id: item.chat_id, bot_token: "", notify_level: item.notify_level || "important", enabled: item.enabled });
  }

  async function saveTelegramEdit(itemId: number) {
    const payload: Record<string, string | boolean> = {
      name: telegramEdit.name,
      chat_id: telegramEdit.chat_id,
      notify_level: telegramEdit.notify_level,
      enabled: telegramEdit.enabled
    };
    if (telegramEdit.bot_token.trim()) {
      payload.bot_token = telegramEdit.bot_token.trim();
    }
    await act(
      () =>
        apiFetch(`/api/telegram/${itemId}`, token, {
          method: "PATCH",
          body: JSON.stringify(payload)
        }),
      "Telegram 通知已更新",
      () => {
        setEditingTelegramId(null);
        setTelegramEdit({ name: "", chat_id: "", bot_token: "", notify_level: "important", enabled: true });
      }
    );
  }

  return (
    <section className="stack">
      <div className="gridTwo">
        <form className="panel" onSubmit={submitTelegram}>
          <h2>添加 Telegram</h2>
          <label>名称<input value={telegramName} onChange={(event) => setTelegramName(event.target.value)} required /></label>
          <label>Bot Token<input value={botToken} onChange={(event) => setBotToken(event.target.value)} required /></label>
          <label>Chat ID<input value={chatId} onChange={(event) => setChatId(event.target.value)} placeholder="例如 123456789 或 -100..." required /></label>
          <label>
            通知级别
            <select value={telegramNotifyLevel} onChange={(event) => setTelegramNotifyLevel(event.target.value)}>
              <option value="important">重要通知：DNS 切换、故障、探针离线</option>
              <option value="critical">故障和切换：DNS 切换、失败、无可用源站、探针离线</option>
              <option value="all">全部通知：包含源站健康/被墙变化</option>
            </select>
          </label>
          <button><RadioTower size={16} /><span>保存</span></button>
        </form>
        <div className="panel">
          <h2>Telegram 通知</h2>
          <div className="list">
            {telegramNotifications.map((item) => (
              <div className="row" key={item.id}>
                {editingTelegramId === item.id ? (
                  <>
                    <div className="editGrid">
                      <input value={telegramEdit.name} onChange={(event) => setTelegramEdit((current) => ({ ...current, name: event.target.value }))} placeholder="名称" />
                      <input value={telegramEdit.chat_id} onChange={(event) => setTelegramEdit((current) => ({ ...current, chat_id: event.target.value }))} placeholder="Chat ID" />
                      <input value={telegramEdit.bot_token} onChange={(event) => setTelegramEdit((current) => ({ ...current, bot_token: event.target.value }))} placeholder="新 Bot Token，留空不修改" />
                      <select value={telegramEdit.notify_level} onChange={(event) => setTelegramEdit((current) => ({ ...current, notify_level: event.target.value }))}>
                        <option value="important">重要通知</option>
                        <option value="critical">故障和切换</option>
                        <option value="all">全部通知</option>
                      </select>
                      <label className="inlineCheck">
                        <input type="checkbox" checked={telegramEdit.enabled} onChange={(event) => setTelegramEdit((current) => ({ ...current, enabled: event.target.checked }))} />
                        启用
                      </label>
                    </div>
                    <div className="rowActions">
                      <button className="icon" title="保存" onClick={() => saveTelegramEdit(item.id)}>
                        <Save size={15} />
                      </button>
                      <button className="icon secondaryIcon" title="取消" onClick={() => setEditingTelegramId(null)}>
                        ×
                      </button>
                    </div>
                  </>
                ) : (
                  <>
                    <div>
                      <strong>{item.name}</strong>
                      <span>{item.chat_id} · {telegramNotifyLevelText(item.notify_level || "important")} · {fmtDate(item.last_sent_at)}</span>
                      {item.last_error && <small className="danger">{item.last_error}</small>}
                    </div>
                    <div className="rowActions">
                      <Status value={item.enabled ? "enabled" : "disabled"} />
                      <button className="icon secondaryIcon" title="修改" onClick={() => beginEditTelegram(item)}>
                        ✎
                      </button>
                      <button className="icon" title="发送测试" onClick={() => act(() => apiFetch(`/api/telegram/${item.id}/test`, token, { method: "POST" }), "Telegram 测试通知已发送")}>
                        <Play size={15} />
                      </button>
                      <button className="icon dangerBtn" title="删除 Telegram" onClick={() => act(() => apiFetch(`/api/telegram/${item.id}`, token, { method: "DELETE" }), "Telegram 通知已删除")}>
                        <Trash2 size={15} />
                      </button>
                    </div>
                  </>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
      <div className="gridTwo">
        <form className="panel" onSubmit={submitWebhook}>
          <h2>添加 Webhook</h2>
          <label>名称<input value={name} onChange={(event) => setName(event.target.value)} required /></label>
          <label>URL<input value={url} onChange={(event) => setUrl(event.target.value)} required /></label>
          <label>签名密钥<input value={secret} onChange={(event) => setSecret(event.target.value)} /></label>
          <button><WebhookIcon size={16} /><span>保存</span></button>
        </form>
      <div className="panel">
        <h2>通知列表</h2>
        <div className="list">
          {webhooks.map((webhook) => (
            <div className="row" key={webhook.id}>
              <div>
                <strong>{webhook.name}</strong>
                <span>{webhook.url}</span>
                {webhook.last_error && <small className="danger">{webhook.last_error}</small>}
              </div>
              <div className="rowActions">
                <Status value={webhook.enabled ? "enabled" : "disabled"} />
                <button className="icon dangerBtn" title="删除 Webhook" onClick={() => act(() => apiFetch(`/api/webhooks/${webhook.id}`, token, { method: "DELETE" }), "Webhook 已删除")}>
                  <Trash2 size={15} />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
      </div>
    </section>
  );
}

function EventsPanel({ events, compact = false }: { events: EventItem[]; compact?: boolean }) {
  return (
    <section className={compact ? "panel" : "panel"}>
      <h2>{compact ? "最近事件" : "事件"}</h2>
      <div className="timeline">
        {events.map((event) => (
          <div className="event" key={event.id}>
            <Status value={event.severity} />
            <div>
              <strong>{event.message}</strong>
              <span>{eventTypeText(event.type)} · {fmtDate(event.created_at)}</span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function Badge({ value }: { value: string }) {
  return <span className="badge">{value}</span>;
}

function Status({ value }: { value: string }) {
  return <span className={`status ${value}`}>{statusText(value)}</span>;
}
