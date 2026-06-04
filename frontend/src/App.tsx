import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  ChevronDown,
  ChevronRight,
  Cloud,
  Copy,
  DatabaseZap,
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
  Trash2,
  Webhook as WebhookIcon
} from "lucide-react";
import { apiFetch, fmtDate, fmtTime } from "./api";
import type { Agent, Credential, DnsRecord, EventItem, ExternalIpItem, ExternalIpSource, FailoverGroup, Origin, Overview, ProbeState, SystemSettings, TargetPoolItem, TelegramNotification, Webhook, Zone } from "./types";

type Section = "overview" | "cloudflare" | "records" | "groups" | "targetPool" | "externalIps" | "agents" | "webhooks" | "settings" | "account" | "events";
type OriginAddDraft = { target: string; port: number; priority: number; publish_mode: string; remark: string; enabled: boolean };
type OriginEditDraft = { target: string; port: number; priority: number; publish_mode: string; remark: string; enabled: boolean };
type GroupEditDraft = { ttl: number; min_switch_interval_seconds: number; enabled: boolean };
type HostnameAddDraft = { hostname: string; adopt_record_id: string };
type TargetPoolDraft = { target: string; port: number; remark: string; check_interval_seconds: number; enabled: boolean };
type ExternalIpSourceDraft = { name: string; base_url: string; token: string; default_port: number; sync_interval_seconds: number; enabled: boolean };
type AgentEditDraft = { name: string };
type SystemSettingsDraft = { [K in keyof SystemSettings]: string };
type SystemSettingField = { key: keyof SystemSettings; label: string; min: number; max: number; step?: number; hint?: string };
type ToastTone = "info" | "success" | "error" | "loading";
type ActionRunner = <T>(fn: () => Promise<T>, done?: string, afterSuccess?: () => void) => Promise<boolean>;

const nav: { id: Section; label: string; icon: typeof Activity }[] = [
  { id: "overview", label: "总览", icon: Activity },
  { id: "cloudflare", label: "Cloudflare", icon: KeyRound },
  { id: "records", label: "解析记录", icon: Cloud },
  { id: "groups", label: "故障切换", icon: ListRestart },
  { id: "targetPool", label: "IP 池子", icon: Server },
  { id: "externalIps", label: "外部 IP", icon: Globe2 },
  { id: "agents", label: "探针", icon: RadioTower },
  { id: "webhooks", label: "通知", icon: WebhookIcon },
  { id: "settings", label: "设置", icon: SlidersHorizontal },
  { id: "account", label: "账户", icon: LockKeyhole },
  { id: "events", label: "事件", icon: DatabaseZap }
];

const sectionStorageKey = "cloudflareDnsActiveSection";

const statusLabels: Record<string, string> = {
  ok: "正常",
  error: "错误",
  unknown: "未知",
  standby: "备用待命",
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
  info: "信息"
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
  "telegram.test": "Telegram 测试"
};

const telegramNotifyLevelLabels: Record<string, string> = {
  important: "重要通知",
  critical: "故障和切换",
  all: "全部通知"
};

function statusText(value: string): string {
  return statusLabels[value] || value;
}

function originIsUnavailable(status: string): boolean {
  return ["unhealthy", "blocked", "machine_down", "regional_issue"].includes(status);
}

function targetTypeText(value: string): string {
  return targetTypeLabels[value] || value;
}

function agentRegionText(value: string): string {
  return value === "foreign" ? "国外探针" : "国内探针";
}

function telegramNotifyLevelText(value: string): string {
  return telegramNotifyLevelLabels[value] || value;
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

const defaultOriginAddDraft: OriginAddDraft = { target: "", port: 22, priority: 10, publish_mode: "direct", remark: "", enabled: true };
const defaultTargetPoolDraft: TargetPoolDraft = { target: "", port: 22, remark: "", check_interval_seconds: 600, enabled: true };
const defaultExternalIpSourceDraft: ExternalIpSourceDraft = { name: "", base_url: "", token: "", default_port: 22, sync_interval_seconds: 600, enabled: true };
const liveRefreshIntervalMs = 3000;
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
  const [groups, setGroups] = useState<FailoverGroup[]>([]);
  const [targetPool, setTargetPool] = useState<TargetPoolItem[]>([]);
  const [externalIpSources, setExternalIpSources] = useState<ExternalIpSource[]>([]);
  const [externalIpItems, setExternalIpItems] = useState<ExternalIpItem[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [telegramNotifications, setTelegramNotifications] = useState<TelegramNotification[]>([]);
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [systemSettings, setSystemSettings] = useState<SystemSettings | null>(null);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [agentToken, setAgentToken] = useState("");

  const selectedZone = useMemo(() => zones.find((zone) => zone.id === selectedZoneId), [selectedZoneId, zones]);

  async function loadSetup() {
    setBootError("");
    const data = await apiFetch<{ setup_required: boolean }>("/api/auth/setup-required");
    setSetupRequired(data.setup_required);
  }

  async function loadAll(activeToken = token) {
    if (!activeToken) return;
    const [nextOverview, nextCredentials, nextZones, nextGroups, nextTargetPool, nextExternalIpSources, nextExternalIpItems, nextAgents, nextTelegram, nextWebhooks, nextSystemSettings, nextEvents] = await Promise.all([
      apiFetch<Overview>("/api/overview", activeToken),
      apiFetch<Credential[]>("/api/credentials", activeToken),
      apiFetch<Zone[]>("/api/zones", activeToken),
      apiFetch<FailoverGroup[]>("/api/groups", activeToken),
      apiFetch<TargetPoolItem[]>("/api/target-pool", activeToken),
      apiFetch<ExternalIpSource[]>("/api/external-ips/sources", activeToken),
      apiFetch<ExternalIpItem[]>("/api/external-ips/items", activeToken),
      apiFetch<Agent[]>("/api/agents", activeToken),
      apiFetch<TelegramNotification[]>("/api/telegram", activeToken),
      apiFetch<Webhook[]>("/api/webhooks", activeToken),
      apiFetch<SystemSettings>("/api/settings", activeToken),
      apiFetch<EventItem[]>("/api/events?limit=100", activeToken)
    ]);
    setOverview(nextOverview);
    setCredentials(nextCredentials);
    setZones(nextZones);
    setGroups(nextGroups);
    setTargetPool(nextTargetPool);
    setExternalIpSources(nextExternalIpSources);
    setExternalIpItems(nextExternalIpItems);
    setAgents(nextAgents);
    setTelegramNotifications(nextTelegram);
    setWebhooks(nextWebhooks);
    setSystemSettings(nextSystemSettings);
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
    const [nextOverview, nextGroups, nextTargetPool, nextExternalIpSources, nextExternalIpItems, nextAgents, nextEvents] = await Promise.all([
      apiFetch<Overview>("/api/overview", activeToken),
      apiFetch<FailoverGroup[]>("/api/groups", activeToken),
      apiFetch<TargetPoolItem[]>("/api/target-pool", activeToken),
      apiFetch<ExternalIpSource[]>("/api/external-ips/sources", activeToken),
      apiFetch<ExternalIpItem[]>("/api/external-ips/items", activeToken),
      apiFetch<Agent[]>("/api/agents", activeToken),
      apiFetch<EventItem[]>("/api/events?limit=100", activeToken)
    ]);
    setOverview(nextOverview);
    setGroups(nextGroups);
    setTargetPool(nextTargetPool);
    setExternalIpSources(nextExternalIpSources);
    setExternalIpItems(nextExternalIpItems);
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
    );
  }

  if (!token) {
    return <AuthScreen setupRequired={setupRequired} onAuth={onAuth} />;
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <ShieldCheck size={28} />
          <div>
            <strong>DNS 故障切换</strong>
            <span>Cloudflare</span>
          </div>
        </div>
        <nav>
          {nav.map((item) => {
            const Icon = item.icon;
            return (
              <button key={item.id} className={section === item.id ? "active" : ""} onClick={() => setSection(item.id)}>
                <Icon size={18} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
        <button className="ghost logout" onClick={logout}>
          <LogOut size={18} />
          <span>退出登录</span>
        </button>
      </aside>

      <main>
        <header className="topbar">
          <div>
            <h1>{nav.find((item) => item.id === section)?.label}</h1>
            <p>
              {selectedZone ? selectedZone.name : "尚未选择域名区域"}
              <span className="liveRefreshText">
                实时更新{liveUpdatedAt ? ` · ${fmtTime(liveUpdatedAt)}` : ""}
              </span>
            </p>
          </div>
          <div className="actions">
            <button className="secondary" disabled={busy} onClick={() => act(() => loadAll(), "已刷新")}>
              <RefreshCw size={16} />
              <span>刷新</span>
            </button>
            <button disabled={busy} onClick={() => act(() => apiFetch("/api/groups/run", token, { method: "POST" }), "健康检查已完成")}>
              <Play size={16} />
              <span>立即检查</span>
            </button>
          </div>
        </header>

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
          <GroupsPanel token={token} groups={groups} targetPool={targetPool} externalIpItems={externalIpItems} act={act} />
        )}
        {section === "targetPool" && (
          <TargetPoolPanel token={token} targetPool={targetPool} groups={groups} act={act} />
        )}
        {section === "externalIps" && (
          <ExternalIpsPanel token={token} externalIpSources={externalIpSources} externalIpItems={externalIpItems} act={act} />
        )}
        {section === "agents" && (
          <AgentsPanel token={token} agents={agents} agentToken={agentToken} setAgentToken={setAgentToken} act={act} />
        )}
        {section === "webhooks" && <NotificationsPanel token={token} telegramNotifications={telegramNotifications} webhooks={webhooks} act={act} />}
        {section === "settings" && systemSettings && <SettingsPanel token={token} settings={systemSettings} act={act} />}
        {section === "account" && <AccountPanel token={token} onPasswordChanged={logout} />}
        {section === "events" && <EventsPanel events={events} />}
      </main>
    </div>
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
                <button className="icon" title="管理" disabled={record.proxied} onClick={() => openManageRecord(record)}>
                  <Link2 size={16} />
                </button>
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
              <label>
                健康检查周期（秒）
                <input type="number" min={60} max={86400} value={poolDraft.check_interval_seconds} onChange={(event) => setPoolDraft((current) => ({ ...current, check_interval_seconds: Number(event.target.value) }))} />
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
              <label>
                检查周期（秒）
                <input type="number" min={60} max={86400} value={batchInterval} onChange={(event) => setBatchInterval(Number(event.target.value))} />
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
                        <input type="number" min={60} max={86400} value={edit.check_interval_seconds} onChange={(event) => setPoolEdits((current) => ({ ...current, [item.id]: { ...edit, check_interval_seconds: Number(event.target.value) } }))} title="健康检查周期（秒）" />
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
                        <span>{targetTypeText(item.target_type)} · 发布为 {recordTypeForTargetType(item.target_type)} · 检测周期 {item.check_interval_seconds}s · 最后检测 {fmtDate(item.last_checked_at)}</span>
                        {item.last_error && <small className="danger">{item.last_error}</small>}
                        {activeProbeStates(item.probe_states).length > 0 && (
                          <div className="probeChips">
                            {activeProbeStates(item.probe_states).map((probe) => (
                              <span className={`probeChip ${probe.status}`} key={probe.id} title={probe.last_error || `最后检测 ${fmtDate(probe.last_checked_at)}`}>
                                {probeSourceText(probe)}：{statusText(probe.status)} · {fmtTime(probe.last_checked_at)}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                      <div className="rowActions">
                        <Status value={item.enabled ? item.status : "disabled"} />
                        <button className="icon secondaryIcon" title="手动检测目标池" onClick={() => act(() => apiFetch(`/api/target-pool/${item.id}/run`, token, { method: "POST" }), "目标池检测已完成")}>
                          <Play size={15} />
                        </button>
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
  groups,
  targetPool,
  externalIpItems,
  act
}: {
  token: string;
  groups: FailoverGroup[];
  targetPool: TargetPoolItem[];
  externalIpItems: ExternalIpItem[];
  act: ActionRunner;
}) {
  const [addingGroupId, setAddingGroupId] = useState<number | null>(null);
  const [originAdd, setOriginAdd] = useState<OriginAddDraft>(defaultOriginAddDraft);
  const [editingGroupId, setEditingGroupId] = useState<number | null>(null);
  const [groupEdits, setGroupEdits] = useState<Record<number, GroupEditDraft>>({});
  const [addingHostnameGroupId, setAddingHostnameGroupId] = useState<number | null>(null);
  const [hostnameAdd, setHostnameAdd] = useState<HostnameAddDraft>({ hostname: "", adopt_record_id: "" });
  const [editingOriginId, setEditingOriginId] = useState<number | null>(null);
  const [originEdits, setOriginEdits] = useState<Record<number, OriginEditDraft>>({});
  const [collapsedGroupIds, setCollapsedGroupIds] = useState<Set<number>>(new Set());
  const addingGroup = addingGroupId ? groups.find((group) => group.id === addingGroupId) : undefined;
  const addingHostnameGroup = addingHostnameGroupId ? groups.find((group) => group.id === addingHostnameGroupId) : undefined;
  const enabledPoolItems = targetPool.filter((item) => item.enabled);
  const healthyExternalItems = externalIpItems.filter((item) => item.status === "healthy");
  const addTargetType = inferDraftTargetType(originAdd.target);
  const selectedPoolItemId = enabledPoolItems.find((item) => item.target === originAdd.target && item.port === originAdd.port)?.id || "";
  const selectedExternalItemId = healthyExternalItems.find((item) => item.target === originAdd.target && item.port === originAdd.port)?.id || "";

  function beginAddOrigin(group: FailoverGroup) {
    const maxPriority = group.origins.reduce((value, origin) => Math.max(value, origin.priority), 0);
    expandGroup(group.id);
    setAddingGroupId(group.id);
    setOriginAdd({
      target: "",
      port: 22,
      priority: maxPriority + 10,
      publish_mode: "direct",
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

  async function deleteHostname(hostnameId: number) {
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
        enabled: group.enabled
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
          body: JSON.stringify(draft)
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
        remark: origin.remark || "",
        enabled: origin.enabled
      }
    }));
  }

  async function saveOriginEdit(originId: number) {
    const draft = originEdits[originId];
    if (!draft) return;
    const targetType = inferDraftTargetType(draft.target);
    const payload = { ...draft, publish_mode: targetType === "hostname" ? draft.publish_mode : "direct" };
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

  return (
    <section className="stack">
      <div className="panelTitle groupsIntro">
        <h2>故障切换组</h2>
        <p>从解析记录页点击管理即可接管主用解析；这里负责查看状态、修改源站和添加备用目标。</p>
      </div>
      <div className="groupGrid">
        {groups.map((group) => {
          const groupEdit = groupEdits[group.id] || {
            ttl: group.ttl,
            min_switch_interval_seconds: group.min_switch_interval_seconds,
            enabled: group.enabled
          };
          const sortedOrigins = [...group.origins].sort((left, right) => left.priority - right.priority || left.id - right.id);
          const primaryPriority = sortedOrigins[0]?.priority;
          const currentOrigin = sortedOrigins.find((origin) => origin.id === group.current_origin_id);
          const currentEnabledOrigin = currentOrigin?.enabled ? currentOrigin : undefined;
          const firstBackupOrigin = sortedOrigins.find((origin) => origin.enabled && origin.id !== currentEnabledOrigin?.id);
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
                          <button type="button" title="取消接管这个主域名" onClick={() => deleteHostname(hostname.id)}>
                            ×
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
                        remark: origin.remark || "",
                        enabled: origin.enabled
                      };
                      const editType = inferDraftTargetType(originEdit.target);
                      const isCurrentOrigin = group.current_origin_id === origin.id;
                      const isPrimaryOrigin = origin.priority === primaryPriority;
                      const shouldShowLiveHealth =
                        origin.enabled &&
                        (isCurrentOrigin ||
                          (currentEnabledOrigin ? originIsUnavailable(currentEnabledOrigin.status) && firstBackupOrigin?.id === origin.id : firstBackupOrigin?.id === origin.id));
                      const displayStatus = origin.enabled ? (shouldShowLiveHealth ? origin.status : "standby") : "disabled";
                      const healthMeta = !origin.enabled ? "已停用，不参与检查" : shouldShowLiveHealth ? `最后检测 ${fmtDate(origin.last_checked_at)}` : "备用待命，当前源站故障时检测";
                      const activeOriginProbeStates = activeProbeStates(origin.probe_states);
                      const visibleProbeStates = shouldShowLiveHealth ? currentProbeStates(origin) : [];
                      const hiddenProbeCount = shouldShowLiveHealth ? activeOriginProbeStates.length - visibleProbeStates.length : 0;
                      return (
                        <div
                          className={`origin ${editingOriginId === origin.id ? "originEditing" : ""} ${isCurrentOrigin ? "originCurrent" : ""} ${isPrimaryOrigin ? "originPrimary" : "originBackup"}`}
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
                                    <span className={`originBadge ${isPrimaryOrigin ? "primary" : "backup"}`}>{isPrimaryOrigin ? "主用" : "备用"}</span>
                                    <span className="originBadge record">{recordTypeForTargetType(origin.target_type, origin.publish_mode)}</span>
                                  </div>
                                </div>
                                <span>{targetTypeText(origin.target_type)} · 优先级 {origin.priority} · {origin.enabled ? "已启用" : "已停用"} · {healthMeta}</span>
                                {shouldShowLiveHealth && origin.publish_mode === "expanded" && (
                                  <div className="expandedIpList">
                                    <IpList label="解析 IP" values={origin.resolved_ips} empty="尚未解析，点击手动检测或等待下个周期" />
                                    <IpList label="健康 IP" values={origin.healthy_ips} />
                                    <IpList label="已发布" values={origin.published_ips} empty="当前未发布该目标" />
                                  </div>
                                )}
                                {shouldShowLiveHealth && origin.last_error && <small className="danger">{origin.last_error}</small>}
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
                              <button className="icon secondaryIcon" title="修改源站" onClick={() => beginEditOrigin(origin)}>
                                <Pencil size={15} />
                              </button>
                              <button className="icon dangerBtn" title="删除" onClick={() => act(() => apiFetch(`/api/groups/origins/${origin.id}`, token, { method: "DELETE" }), "源站已删除")}>
                                <Trash2 size={15} />
                              </button>
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
        {groups.length === 0 && (
          <div className="panel emptyGroupPanel">
            <h2>还没有故障切换组</h2>
            <p>请先到解析记录页，选择一条 DNS-only A/AAAA/CNAME 记录，点击管理并确认接管。</p>
          </div>
        )}
      </div>
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
          <p>同区域探针按列表顺序接力使用；主探针不可达时，下一个同区域探针才会复检。</p>
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
                  <Status value={agent.enabled ? agent.status : "disabled"} />
                </div>
                <span>区域：{agentRegionText(agent.region)}</span>
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
        { key: "login_max_failures", label: "最大失败次数", min: 1, max: 100, hint: "次" },
        { key: "login_failure_window_seconds", label: "失败统计窗口", min: 60, max: 86400, hint: "秒" },
        { key: "login_lockout_seconds", label: "锁定时间", min: 60, max: 86400, hint: "秒" }
      ]
    }
  ];

  function updateField(key: keyof SystemSettings, value: string) {
    setDraft((current) => ({ ...current, [key]: value }));
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const payload = Object.fromEntries(
      Object.entries(draft).map(([key, value]) => [key, key === "check_timeout_seconds" ? Number.parseFloat(value) : Number.parseInt(value, 10)])
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
                  <input
                    type="number"
                    min={field.min}
                    max={field.max}
                    step={field.step || 1}
                    value={draft[field.key]}
                    onChange={(event) => updateField(field.key, event.target.value)}
                    required
                  />
                  <span>{field.min} - {field.max}{field.hint ? ` ${field.hint}` : ""}</span>
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
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
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
        <h2>修改登录密码</h2>
        <p>输入当前密码和新密码。修改成功后会自动退出登录。</p>
      </div>
      {message && <div className="notice">{message}</div>}
      {error && <div className="error">{error}</div>}
      <form onSubmit={submit}>
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
