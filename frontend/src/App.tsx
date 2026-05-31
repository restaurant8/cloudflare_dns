import { DragEvent, FormEvent, useEffect, useMemo, useState } from "react";
import {
  Activity,
  Cloud,
  Copy,
  DatabaseZap,
  KeyRound,
  Link2,
  ListRestart,
  LockKeyhole,
  LogOut,
  Pencil,
  Play,
  Plus,
  RadioTower,
  RefreshCw,
  Save,
  Server,
  ShieldCheck,
  Trash2,
  Webhook as WebhookIcon
} from "lucide-react";
import { apiFetch, fmtDate } from "./api";
import type { Agent, Credential, DnsRecord, EventItem, FailoverGroup, Origin, Overview, TargetPoolItem, TelegramNotification, Webhook, Zone } from "./types";

type Section = "overview" | "cloudflare" | "records" | "groups" | "agents" | "webhooks" | "account" | "events";
type OriginAddDraft = { target: string; port: number; priority: number; publish_mode: string; enabled: boolean };
type OriginEditDraft = { target: string; port: number; priority: number; publish_mode: string; enabled: boolean };
type GroupEditDraft = { ttl: number; min_switch_interval_seconds: number; enabled: boolean };
type TargetPoolDraft = { target: string; port: number; remark: string; enabled: boolean };

const nav: { id: Section; label: string; icon: typeof Activity }[] = [
  { id: "overview", label: "总览", icon: Activity },
  { id: "cloudflare", label: "Cloudflare", icon: KeyRound },
  { id: "records", label: "解析记录", icon: Cloud },
  { id: "groups", label: "故障切换", icon: ListRestart },
  { id: "agents", label: "探针", icon: RadioTower },
  { id: "webhooks", label: "通知", icon: WebhookIcon },
  { id: "account", label: "账户", icon: LockKeyhole },
  { id: "events", label: "事件", icon: DatabaseZap }
];

const sectionStorageKey = "cloudflareDnsActiveSection";

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

function statusText(value: string): string {
  return statusLabels[value] || value;
}

function targetTypeText(value: string): string {
  return targetTypeLabels[value] || value;
}

function agentRegionText(value: string): string {
  return value === "foreign" ? "国外探针" : "国内探针";
}

function recordTypeForTargetType(value: string, publishMode = "direct"): string {
  if (value === "ipv4") return "A";
  if (value === "ipv6") return "AAAA";
  if (value === "hostname") return publishMode === "expanded" ? "A/AAAA IP池" : "CNAME";
  return "-";
}

function probeSourceText(value: string): string {
  const [source, ip] = value.split("|");
  if (source === "local") return ip ? `本地 ${ip}` : "本地";
  if (source.startsWith("agent:")) return ip ? `探针 ${source.slice(6)} ${ip}` : `探针 ${source.slice(6)}`;
  return value;
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

const defaultOriginAddDraft: OriginAddDraft = { target: "", port: 22, priority: 10, publish_mode: "direct", enabled: true };
const defaultTargetPoolDraft: TargetPoolDraft = { target: "", port: 22, remark: "", enabled: true };
const liveRefreshIntervalMs = 3000;

export default function App() {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("accessToken"));
  const [setupRequired, setSetupRequired] = useState<boolean | null>(null);
  const [bootError, setBootError] = useState("");
  const [section, setSection] = useState<Section>(() => initialSection());
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [liveUpdatedAt, setLiveUpdatedAt] = useState<string | null>(null);

  const [overview, setOverview] = useState<Overview>(emptyOverview);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [selectedZoneId, setSelectedZoneId] = useState<number | "">("");
  const [records, setRecords] = useState<DnsRecord[]>([]);
  const [groups, setGroups] = useState<FailoverGroup[]>([]);
  const [targetPool, setTargetPool] = useState<TargetPoolItem[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [telegramNotifications, setTelegramNotifications] = useState<TelegramNotification[]>([]);
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
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
    const [nextOverview, nextCredentials, nextZones, nextGroups, nextTargetPool, nextAgents, nextTelegram, nextWebhooks, nextEvents] = await Promise.all([
      apiFetch<Overview>("/api/overview", activeToken),
      apiFetch<Credential[]>("/api/credentials", activeToken),
      apiFetch<Zone[]>("/api/zones", activeToken),
      apiFetch<FailoverGroup[]>("/api/groups", activeToken),
      apiFetch<TargetPoolItem[]>("/api/target-pool", activeToken),
      apiFetch<Agent[]>("/api/agents", activeToken),
      apiFetch<TelegramNotification[]>("/api/telegram", activeToken),
      apiFetch<Webhook[]>("/api/webhooks", activeToken),
      apiFetch<EventItem[]>("/api/events?limit=100", activeToken)
    ]);
    setOverview(nextOverview);
    setCredentials(nextCredentials);
    setZones(nextZones);
    setGroups(nextGroups);
    setTargetPool(nextTargetPool);
    setAgents(nextAgents);
    setTelegramNotifications(nextTelegram);
    setWebhooks(nextWebhooks);
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
    const [nextOverview, nextGroups, nextTargetPool, nextAgents, nextEvents] = await Promise.all([
      apiFetch<Overview>("/api/overview", activeToken),
      apiFetch<FailoverGroup[]>("/api/groups", activeToken),
      apiFetch<TargetPoolItem[]>("/api/target-pool", activeToken),
      apiFetch<Agent[]>("/api/agents", activeToken),
      apiFetch<EventItem[]>("/api/events?limit=100", activeToken)
    ]);
    setOverview(nextOverview);
    setGroups(nextGroups);
    setTargetPool(nextTargetPool);
    setAgents(nextAgents);
    setEvents(nextEvents);
    setLiveUpdatedAt(new Date().toISOString());
  }

  async function act<T>(fn: () => Promise<T>, done = "已完成") {
    setBusy(true);
    setMessage("正在处理，请稍候...");
    try {
      await fn();
      setMessage(done);
      await loadAll();
      if (selectedZoneId) await loadRecords();
      return true;
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "请求失败");
      return false;
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    loadSetup().catch((error) => setBootError(error instanceof Error ? error.message : "无法连接后端 API"));
  }, []);

  useEffect(() => {
    function markClickedButton(event: MouseEvent) {
      const target = event.target;
      if (!(target instanceof Element)) return;
      const button = target.closest("button");
      if (!button || button.disabled) return;
      button.classList.remove("buttonClicked");
      void button.offsetWidth;
      button.classList.add("buttonClicked");
      window.setTimeout(() => button.classList.remove("buttonClicked"), 360);
    }

    document.addEventListener("click", markClickedButton, true);
    return () => document.removeEventListener("click", markClickedButton, true);
  }, []);

  useEffect(() => {
    if (token) {
      loadAll(token).catch((error) => setMessage(error.message));
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
      loadRecords(selectedZoneId).catch((error) => setMessage(error.message));
    }
  }, [selectedZoneId]);

  function onAuth(nextToken: string) {
    localStorage.setItem("accessToken", nextToken);
    setToken(nextToken);
    setSetupRequired(false);
  }

  function logout() {
    localStorage.removeItem("accessToken");
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
                实时更新{liveUpdatedAt ? ` · ${new Date(liveUpdatedAt).toLocaleTimeString()}` : ""}
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

        {message && <div className="notice" aria-live="polite">{message}</div>}

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
          <GroupsPanel token={token} groups={groups} targetPool={targetPool} act={act} />
        )}
        {section === "agents" && (
          <AgentsPanel token={token} agents={agents} agentToken={agentToken} setAgentToken={setAgentToken} act={act} />
        )}
        {section === "webhooks" && <NotificationsPanel token={token} telegramNotifications={telegramNotifications} webhooks={webhooks} act={act} />}
        {section === "account" && <AccountPanel token={token} onPasswordChanged={logout} />}
        {section === "events" && <EventsPanel events={events} />}
      </main>
    </div>
  );
}

function AuthScreen({ setupRequired, onAuth }: { setupRequired: boolean; onAuth: (token: string) => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
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
        body: JSON.stringify({ username, password })
      });
      onAuth(data.access_token);
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

function CloudflarePanel({ token, credentials, busy, act }: { token: string; credentials: Credential[]; busy: boolean; act: <T>(fn: () => Promise<T>, done?: string) => Promise<boolean> }) {
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
  act: <T>(fn: () => Promise<T>, done?: string) => Promise<boolean>;
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
    const ok = await act(
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
      "故障切换组已创建"
    );
    if (ok) {
      setManageRecord(null);
      setSection("groups");
    }
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

function GroupsPanel({
  token,
  groups,
  targetPool,
  act
}: {
  token: string;
  groups: FailoverGroup[];
  targetPool: TargetPoolItem[];
  act: <T>(fn: () => Promise<T>, done?: string) => Promise<boolean>;
}) {
  const [poolDraft, setPoolDraft] = useState<TargetPoolDraft>(defaultTargetPoolDraft);
  const [editingPoolId, setEditingPoolId] = useState<number | null>(null);
  const [poolEdits, setPoolEdits] = useState<Record<number, TargetPoolDraft>>({});
  const [addingGroupId, setAddingGroupId] = useState<number | null>(null);
  const [originAdd, setOriginAdd] = useState<OriginAddDraft>(defaultOriginAddDraft);
  const [editingGroupId, setEditingGroupId] = useState<number | null>(null);
  const [groupEdits, setGroupEdits] = useState<Record<number, GroupEditDraft>>({});
  const [editingOriginId, setEditingOriginId] = useState<number | null>(null);
  const [originEdits, setOriginEdits] = useState<Record<number, OriginEditDraft>>({});
  const addingGroup = addingGroupId ? groups.find((group) => group.id === addingGroupId) : undefined;
  const addTargetType = inferDraftTargetType(originAdd.target);

  async function createPoolItem(event: FormEvent) {
    event.preventDefault();
    const ok = await act(
      () =>
        apiFetch("/api/target-pool", token, {
          method: "POST",
          body: JSON.stringify({
            target: poolDraft.target.trim(),
            port: poolDraft.port,
            remark: poolDraft.remark.trim() || null,
            enabled: poolDraft.enabled
          })
        }),
      "目标已加入池子"
    );
    if (ok) {
      setPoolDraft(defaultTargetPoolDraft);
    }
  }

  function beginEditPoolItem(item: TargetPoolItem) {
    setEditingPoolId(item.id);
    setPoolEdits((current) => ({
      ...current,
      [item.id]: {
        target: item.target,
        port: item.port,
        remark: item.remark || "",
        enabled: item.enabled
      }
    }));
  }

  async function savePoolItem(itemId: number) {
    const draft = poolEdits[itemId];
    if (!draft) return;
    const ok = await act(
      () =>
        apiFetch(`/api/target-pool/${itemId}`, token, {
          method: "PATCH",
          body: JSON.stringify({
            target: draft.target.trim(),
            port: draft.port,
            remark: draft.remark.trim() || null,
            enabled: draft.enabled
          })
        }),
      "目标池已更新"
    );
    if (ok) {
      setEditingPoolId(null);
    }
  }

  function dragPoolItem(event: DragEvent, item: TargetPoolItem) {
    event.dataTransfer.setData("application/x-target-pool", JSON.stringify({ id: item.id, target: item.target, port: item.port }));
    event.dataTransfer.effectAllowed = "copy";
  }

  function allowPoolDrop(event: DragEvent) {
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
  }

  async function dropPoolItem(event: DragEvent, group: FailoverGroup) {
    event.preventDefault();
    const raw = event.dataTransfer.getData("application/x-target-pool");
    if (!raw) return;
    const item = JSON.parse(raw) as { target: string; port: number };
    const maxPriority = group.origins.reduce((value, origin) => Math.max(value, origin.priority), 0);
    await act(
      () =>
        apiFetch(`/api/groups/${group.id}/origins`, token, {
          method: "POST",
          body: JSON.stringify({
            target: item.target,
            port: item.port || 22,
            priority: maxPriority + 10,
            publish_mode: "direct",
            enabled: true
          })
        }),
      "已从目标池添加备用"
    );
  }

  function beginAddOrigin(group: FailoverGroup) {
    const maxPriority = group.origins.reduce((value, origin) => Math.max(value, origin.priority), 0);
    setAddingGroupId(group.id);
    setOriginAdd({
      target: "",
      port: 22,
      priority: maxPriority + 10,
      publish_mode: "direct",
      enabled: true
    });
  }

  async function createOrigin() {
    if (!addingGroup) return;
    const ok = await act(
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
            enabled: originAdd.enabled
          })
        });
      },
      "备用目标已添加"
    );
    if (ok) {
      setAddingGroupId(null);
      setOriginAdd(defaultOriginAddDraft);
    }
  }

  function beginEditGroup(group: FailoverGroup) {
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
      "切换组已更新并应用"
    );
    setEditingGroupId(null);
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
      "源站已更新并应用"
    );
    setEditingOriginId(null);
  }

  return (
    <section className="stack">
      <div className="panelTitle groupsIntro">
        <h2>故障切换组</h2>
        <p>从解析记录页点击管理即可接管主用解析；这里负责查看状态、修改源站和添加备用目标。</p>
      </div>
      <div className="targetPoolPanel">
        <form className="panel targetPoolForm" onSubmit={createPoolItem}>
          <div className="panelTitle">
            <h2>目标池</h2>
            <p>把常用 IP、IPv6 或域名先放进池子，拖到下面的故障组即可加入为备用目标。</p>
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
        <div className="panel poolListPanel">
          <div className="panelTitle">
            <h2>池子列表</h2>
            <p>按住目标拖到故障组卡片上，系统会按默认备用优先级添加。</p>
          </div>
          <div className="poolList">
            {targetPool.map((item) => {
              const edit = poolEdits[item.id] || {
                target: item.target,
                port: item.port,
                remark: item.remark || "",
                enabled: item.enabled
              };
              return (
                <div className="poolItem" key={item.id} draggable={editingPoolId !== item.id && item.enabled} onDragStart={(event) => dragPoolItem(event, item)}>
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
                        <strong>{item.target}:{item.port}</strong>
                        <span>{targetTypeText(item.target_type)} · 发布为 {recordTypeForTargetType(item.target_type)}{item.remark ? ` · ${item.remark}` : ""}</span>
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
      <div className="groupGrid">
        {groups.map((group) => {
          const groupEdit = groupEdits[group.id] || {
            ttl: group.ttl,
            min_switch_interval_seconds: group.min_switch_interval_seconds,
            enabled: group.enabled
          };
          const sortedOrigins = [...group.origins].sort((left, right) => left.priority - right.priority || left.id - right.id);
          const primaryPriority = sortedOrigins[0]?.priority;
          return (
            <article className="groupCard" key={group.id} onDragOver={allowPoolDrop} onDrop={(event) => dropPoolItem(event, group)}>
              <div className="groupHead">
                <div>
                  <h2>{group.hostname}</h2>
                  <span>TTL {group.ttl} · 记录 {group.current_record_id || "-"}</span>
                </div>
                <div className="rowActions">
                  <Status value={group.last_error ? "error" : group.enabled ? "enabled" : "disabled"} />
                  <button className="secondary compactBtn" title="手动检测该组全部目标" onClick={() => act(() => apiFetch(`/api/groups/${group.id}/run`, token, { method: "POST" }), "切换组检测已完成")}>
                    <Play size={15} />
                    <span>检测全部</span>
                  </button>
                  <button className="secondary" title="添加备用目标" onClick={() => beginAddOrigin(group)}>
                    <Plus size={15} />
                    <span>添加备用</span>
                  </button>
                  <button className="icon secondaryIcon" title="修改切换组" onClick={() => beginEditGroup(group)}>
                    <Pencil size={15} />
                  </button>
                  <button className="icon dangerBtn" title="删除切换组" onClick={() => act(() => apiFetch(`/api/groups/${group.id}`, token, { method: "DELETE" }), "切换组已删除")}>
                    <Trash2 size={15} />
                  </button>
                </div>
              </div>
              <div className="dropHint">把目标池里的 IP / 域名拖到这里，即可加入为备用目标。</div>
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
                    enabled: origin.enabled
                  };
                  const editType = inferDraftTargetType(originEdit.target);
                  const isCurrentOrigin = group.current_origin_id === origin.id;
                  const isPrimaryOrigin = origin.priority === primaryPriority;
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
                              <strong>{origin.target}:{origin.port}</strong>
                              <div className="originBadges">
                                {isCurrentOrigin && <span className="originBadge current">当前使用</span>}
                                <span className={`originBadge ${isPrimaryOrigin ? "primary" : "backup"}`}>{isPrimaryOrigin ? "主用" : "备用"}</span>
                                <span className="originBadge record">{recordTypeForTargetType(origin.target_type, origin.publish_mode)}</span>
                              </div>
                            </div>
                            <span>{targetTypeText(origin.target_type)} · 优先级 {origin.priority} · {origin.enabled ? "已启用" : "已停用"} · {fmtDate(origin.last_checked_at)}</span>
                            {origin.publish_mode === "expanded" && (
                              <div className="expandedIpList">
                                <IpList label="解析 IP" values={origin.resolved_ips} empty="尚未解析，点击手动检测或等待下个周期" />
                                <IpList label="健康 IP" values={origin.healthy_ips} />
                                <IpList label="已发布" values={origin.published_ips} empty="当前未发布该目标" />
                              </div>
                            )}
                            {origin.last_error && <small className="danger">{origin.last_error}</small>}
                            {origin.probe_states.length > 0 && (
                              <div className="probeChips">
                                {origin.probe_states.map((probe) => (
                                  <span className={`probeChip ${probe.status}`} key={probe.id} title={probe.last_error || ""}>
                                    {probeSourceText(probe.source_key)}：{statusText(probe.status)}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                          <Status value={origin.status} />
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
      {addingGroup && (
        <div className="modalBackdrop" role="dialog" aria-modal="true">
          <div className="modalPanel">
            <div className="panelTitle">
              <h2>添加备用目标</h2>
              <p>{addingGroup.hostname}</p>
            </div>
            <label>
              备用 IP / IPv6 / 域名
              <input placeholder="例如 192.0.2.10 或 backup.example.com" value={originAdd.target} onChange={(event) => setOriginAdd((current) => ({ ...current, target: event.target.value }))} />
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

function AgentsPanel({ token, agents, agentToken, setAgentToken, act }: { token: string; agents: Agent[]; agentToken: string; setAgentToken: (value: string) => void; act: <T>(fn: () => Promise<T>, done?: string) => Promise<boolean> }) {
  const [name, setName] = useState("");
  const [region, setRegion] = useState<"china" | "foreign">("china");
  const [copied, setCopied] = useState(false);
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
          <p>探针会主动拉取任务；超过约 3 个检查周期未上报会自动标记为离线并发送通知。</p>
        </div>
        <div className="agentStatusGrid">
          {agents.map((agent) => (
            <div className="agentStatusCard" key={agent.id}>
              <div className="agentStatusHead">
                <strong>{agent.name}</strong>
                <Status value={agent.status} />
              </div>
              <span>区域：{agentRegionText(agent.region)}</span>
              <span>最后 IP：{agent.last_ip || "-"}</span>
              <span>最后上报：{fmtDate(agent.last_seen_at)}</span>
              <button className="icon dangerBtn" title="删除探针" onClick={() => act(() => apiFetch(`/api/agents/${agent.id}`, token, { method: "DELETE" }), "探针已删除")}>
                <Trash2 size={15} />
              </button>
            </div>
          ))}
          {agents.length === 0 && <div className="emptyCell">还没有探针服务器</div>}
        </div>
      </div>
    </section>
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
  act: <T>(fn: () => Promise<T>, done?: string) => Promise<boolean>;
}) {
  const [telegramName, setTelegramName] = useState("");
  const [botToken, setBotToken] = useState("");
  const [chatId, setChatId] = useState("");
  const [editingTelegramId, setEditingTelegramId] = useState<number | null>(null);
  const [telegramEdit, setTelegramEdit] = useState<{ name: string; chat_id: string; bot_token: string; enabled: boolean }>({
    name: "",
    chat_id: "",
    bot_token: "",
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
          body: JSON.stringify({ name: telegramName, bot_token: botToken, chat_id: chatId, enabled: true })
        }),
      "Telegram 通知已保存"
    );
    setTelegramName("");
    setBotToken("");
    setChatId("");
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
    setTelegramEdit({ name: item.name, chat_id: item.chat_id, bot_token: "", enabled: item.enabled });
  }

  async function saveTelegramEdit(itemId: number) {
    const payload: Record<string, string | boolean> = {
      name: telegramEdit.name,
      chat_id: telegramEdit.chat_id,
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
      "Telegram 通知已更新"
    );
    setEditingTelegramId(null);
    setTelegramEdit({ name: "", chat_id: "", bot_token: "", enabled: true });
  }

  return (
    <section className="stack">
      <div className="gridTwo">
        <form className="panel" onSubmit={submitTelegram}>
          <h2>添加 Telegram</h2>
          <label>名称<input value={telegramName} onChange={(event) => setTelegramName(event.target.value)} required /></label>
          <label>Bot Token<input value={botToken} onChange={(event) => setBotToken(event.target.value)} required /></label>
          <label>Chat ID<input value={chatId} onChange={(event) => setChatId(event.target.value)} placeholder="例如 123456789 或 -100..." required /></label>
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
                      <span>{item.chat_id} · {fmtDate(item.last_sent_at)}</span>
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
