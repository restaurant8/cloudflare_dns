import { FormEvent, useEffect, useMemo, useState } from "react";
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
import type { Agent, Credential, DnsRecord, EventItem, FailoverGroup, Overview, TelegramNotification, Webhook, Zone } from "./types";

type Section = "overview" | "cloudflare" | "records" | "groups" | "agents" | "webhooks" | "account" | "events";
type OriginDraft = { targets: string; port: number; priority: number };

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

function recordTypeForTargetType(value: string): string {
  if (value === "ipv4") return "A";
  if (value === "ipv6") return "AAAA";
  if (value === "hostname") return "CNAME";
  return "-";
}

function probeSourceText(value: string): string {
  if (value === "local") return "本地";
  if (value.startsWith("agent:")) return `探针 ${value.slice(6)}`;
  return value;
}

function parseOriginDraft(draft: OriginDraft): Array<{ target: string; port: number; priority: number; weight: number }> {
  return draft.targets
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => {
      const parts = (line.includes(",") ? line.split(",") : line.split(/\s+/)).map((part) => part.trim()).filter(Boolean);
      return {
        target: parts[0],
        port: parts[1] ? Number(parts[1]) : draft.port,
        priority: parts[2] ? Number(parts[2]) : draft.priority,
        weight: 1
      };
    });
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

function comparableHostname(value: string): string {
  return value.trim().replace(/\.$/, "").toLowerCase();
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

const defaultOriginDraft: OriginDraft = { targets: "", port: 443, priority: 10 };

export default function App() {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("accessToken"));
  const [setupRequired, setSetupRequired] = useState<boolean | null>(null);
  const [bootError, setBootError] = useState("");
  const [section, setSection] = useState<Section>("overview");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  const [overview, setOverview] = useState<Overview>(emptyOverview);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [selectedZoneId, setSelectedZoneId] = useState<number | "">("");
  const [records, setRecords] = useState<DnsRecord[]>([]);
  const [groups, setGroups] = useState<FailoverGroup[]>([]);
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
    const [nextOverview, nextCredentials, nextZones, nextGroups, nextAgents, nextTelegram, nextWebhooks, nextEvents] = await Promise.all([
      apiFetch<Overview>("/api/overview", activeToken),
      apiFetch<Credential[]>("/api/credentials", activeToken),
      apiFetch<Zone[]>("/api/zones", activeToken),
      apiFetch<FailoverGroup[]>("/api/groups", activeToken),
      apiFetch<Agent[]>("/api/agents", activeToken),
      apiFetch<TelegramNotification[]>("/api/telegram", activeToken),
      apiFetch<Webhook[]>("/api/webhooks", activeToken),
      apiFetch<EventItem[]>("/api/events?limit=100", activeToken)
    ]);
    setOverview(nextOverview);
    setCredentials(nextCredentials);
    setZones(nextZones);
    setGroups(nextGroups);
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

  async function act<T>(fn: () => Promise<T>, done = "已完成") {
    setBusy(true);
    setMessage("");
    try {
      await fn();
      setMessage(done);
      await loadAll();
      if (selectedZoneId) await loadRecords();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "请求失败");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    loadSetup().catch((error) => setBootError(error instanceof Error ? error.message : "无法连接后端 API"));
  }, []);

  useEffect(() => {
    if (token) {
      loadAll(token).catch((error) => setMessage(error.message));
    }
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
            <p>{selectedZone ? selectedZone.name : "尚未选择域名区域"}</p>
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

        {message && <div className="notice">{message}</div>}

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
            seedGroup={(record) => {
              sessionStorage.setItem("seedGroup", JSON.stringify({ zone_id: record.zone_id, hostname: record.name, adopt_record_id: record.cf_record_id, record_type: record.type, content: record.content, ttl: record.ttl }));
              setSection("groups");
            }}
            act={act}
          />
        )}
        {section === "groups" && (
          <GroupsPanel token={token} zones={zones} groups={groups} act={act} />
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

function CloudflarePanel({ token, credentials, busy, act }: { token: string; credentials: Credential[]; busy: boolean; act: <T>(fn: () => Promise<T>, done?: string) => Promise<void> }) {
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
  seedGroup,
  act
}: {
  token: string;
  zones: Zone[];
  selectedZoneId: number | "";
  setSelectedZoneId: (value: number | "") => void;
  records: DnsRecord[];
  setSection: (section: Section) => void;
  seedGroup: (record: DnsRecord) => void;
  act: <T>(fn: () => Promise<T>, done?: string) => Promise<void>;
}) {
  const [query, setQuery] = useState("");
  const [zoneQuery, setZoneQuery] = useState("");
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
                <button className="icon" title="管理" disabled={record.proxied} onClick={() => seedGroup(record)}>
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
    </section>
  );
}

type GroupSeed = {
  zone_id: number;
  hostname: string;
  adopt_record_id: string;
  record_type?: string;
  content?: string;
  ttl?: number;
};

function GroupsPanel({ token, zones, groups, act }: { token: string; zones: Zone[]; groups: FailoverGroup[]; act: <T>(fn: () => Promise<T>, done?: string) => Promise<void> }) {
  const [seed] = useState<GroupSeed | null>(() => {
    const raw = sessionStorage.getItem("seedGroup");
    if (!raw) return null;
    sessionStorage.removeItem("seedGroup");
    try {
      return JSON.parse(raw) as GroupSeed;
    } catch {
      return null;
    }
  });
  const [zoneId, setZoneId] = useState<number | "">(seed?.zone_id || zones[0]?.id || "");
  const [hostname, setHostname] = useState(seed?.hostname || "");
  const [adoptRecordId, setAdoptRecordId] = useState(seed?.adopt_record_id || "");
  const [ttl, setTtl] = useState(seed?.ttl && seed.ttl >= 30 ? seed.ttl : 60);
  const [primaryPort, setPrimaryPort] = useState(443);
  const [zoneQuery, setZoneQuery] = useState("");
  const filteredZones = filteredZoneList(zones, zoneQuery, zoneId);
  const [originDrafts, setOriginDrafts] = useState<Record<number, OriginDraft>>({});
  const seedContextMatches = Boolean(seed && zoneId === seed.zone_id && comparableHostname(hostname) === comparableHostname(seed.hostname));
  const seededRecordMatches = Boolean(seed?.adopt_record_id && seedContextMatches && seed.adopt_record_id === adoptRecordId);
  const adoptRecordIdForSubmit = adoptRecordId && (!seed?.adopt_record_id || seededRecordMatches) ? adoptRecordId : "";

  function changeZone(nextZoneId: number | "") {
    setZoneId(nextZoneId);
    if (seed?.adopt_record_id && nextZoneId !== seed.zone_id) {
      setAdoptRecordId("");
    }
  }

  function changeHostname(value: string) {
    setHostname(value);
    if (seed?.adopt_record_id && comparableHostname(value) !== comparableHostname(seed.hostname)) {
      setAdoptRecordId("");
    }
  }

  async function createGroup(event: FormEvent) {
    event.preventDefault();
    await act(
      () =>
        apiFetch("/api/groups", token, {
          method: "POST",
          body: JSON.stringify({
            zone_id: zoneId,
            hostname,
            ttl,
            primary_port: primaryPort,
            enabled: true,
            min_switch_interval_seconds: 120,
            adopt_record_id: adoptRecordIdForSubmit || null
          })
        }),
      "切换组已创建"
    );
    setHostname("");
    setAdoptRecordId("");
  }

  async function createOrigin(groupId: number) {
    const draft = originDrafts[groupId] || defaultOriginDraft;
    await act(
      () => {
        const origins = parseOriginDraft(draft);
        if (origins.length === 0) {
          throw new Error("请填写至少一个备用目标");
        }
        return apiFetch(`/api/groups/${groupId}/origins/bulk`, token, {
          method: "POST",
          body: JSON.stringify({ origins })
        });
      },
      "备用目标已添加"
    );
    const group = groups.find((item) => item.id === groupId);
    setOriginDrafts((current) => ({ ...current, [groupId]: { ...defaultOriginDraft, port: group?.origins[0]?.port || draft.port } }));
  }

  return (
    <section className="stack">
      <form className="panel createGroupPanel" onSubmit={createGroup}>
        <div className="panelTitle">
          <h2>新建切换组</h2>
          <p>从解析记录进入时会自动识别当前 A/AAAA/CNAME 并加入为主目标，创建后只需要继续添加备用目标。</p>
        </div>
        <div className="groupCreateGrid">
          <label>
            搜索域名区域
            <input placeholder="输入域名筛选" value={zoneQuery} onChange={(event) => setZoneQuery(event.target.value)} />
          </label>
          <label>
            域名区域
            <select value={zoneId} onChange={(event) => changeZone(event.target.value ? Number(event.target.value) : "")} required>
              <option value="">请选择域名区域</option>
              {filteredZones.map((zone) => (
                <option key={zone.id} value={zone.id}>{zone.name}</option>
              ))}
            </select>
          </label>
          <label>
            主机名
            <input placeholder="例如 a.example.com" value={hostname} onChange={(event) => changeHostname(event.target.value)} required />
          </label>
          <label>
            接管记录 ID（可选）
            <input className="monoInput" placeholder="从解析记录点管理时自动填写" value={adoptRecordId} onChange={(event) => setAdoptRecordId(event.target.value)} />
          </label>
          <label>
            TTL（秒）
            <input type="number" min={30} max={86400} value={ttl} onChange={(event) => setTtl(Number(event.target.value))} />
          </label>
          <label>
            检查端口
            <input type="number" min={1} max={65535} value={primaryPort} onChange={(event) => setPrimaryPort(Number(event.target.value))} />
          </label>
        </div>
        {adoptRecordId && (
          <div className="recordIdNotice">
            <strong>{seededRecordMatches ? "已选择要接管的 Cloudflare 记录" : "Cloudflare 记录 ID"}</strong>
            {seededRecordMatches && <span>{seed?.record_type || "DNS"} {seed?.hostname} {seed?.content ? `-> ${seed.content}` : ""}</span>}
            {seededRecordMatches && <span>创建后会自动加入主目标，优先级 0，检查端口 {primaryPort}。</span>}
            {!seededRecordMatches && <span>手动输入主机名时可以留空；系统会自动接管同名唯一 DNS-only A/AAAA/CNAME 记录。</span>}
            <code>{adoptRecordId}</code>
          </div>
        )}
        {!adoptRecordId && (
          <div className="recordIdNotice">
            <strong>自动接管当前解析</strong>
            <span>如果这个主机名当前只有一条 DNS-only A/AAAA/CNAME 记录，创建时会自动识别并加入为主目标。</span>
          </div>
        )}
        <button className="createGroupButton">
          <Plus size={16} />
          <span>创建组</span>
        </button>
      </form>
      <div className="groupGrid">
        {groups.map((group) => {
          const groupDefaultDraft = { ...defaultOriginDraft, port: group.origins[0]?.port || defaultOriginDraft.port };
          const draft = originDrafts[group.id] || groupDefaultDraft;
          const parsedDraft = parseOriginDraft(draft);
          const singleDraftType = parsedDraft.length === 1 ? inferDraftTargetType(parsedDraft[0].target) : "";
          return (
            <article className="groupCard" key={group.id}>
              <div className="groupHead">
                <div>
                  <h2>{group.hostname}</h2>
                  <span>TTL {group.ttl} · 记录 {group.current_record_id || "-"}</span>
                </div>
                <div className="rowActions">
                  <Status value={group.last_error ? "error" : group.enabled ? "enabled" : "disabled"} />
                  <button className="icon dangerBtn" title="删除切换组" onClick={() => act(() => apiFetch(`/api/groups/${group.id}`, token, { method: "DELETE" }), "切换组已删除")}>
                    <Trash2 size={15} />
                  </button>
                </div>
              </div>
              {group.last_error && <div className="error">{group.last_error}</div>}
              <div className="originList">
                {group.origins.map((origin) => (
                  <div className="origin" key={origin.id}>
                    <Server size={18} />
                    <div>
                      <strong>{origin.target}:{origin.port}</strong>
                      <span>{targetTypeText(origin.target_type)} · 发布为 {recordTypeForTargetType(origin.target_type)} · 优先级 {origin.priority} · {fmtDate(origin.last_checked_at)}</span>
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
                    <button className="icon dangerBtn" title="删除" onClick={() => act(() => apiFetch(`/api/groups/origins/${origin.id}`, token, { method: "DELETE" }), "源站已删除")}>
                      <Trash2 size={15} />
                    </button>
                  </div>
                ))}
              </div>
              <div className="originFormHeader">
                <strong>添加备用目标</strong>
                <span>每行一个 IPv4、IPv6 或域名；IPv4 发布 A，IPv6 发布 AAAA，域名发布 CNAME。优先级数字越小越先使用。</span>
              </div>
              <div className="originBulkForm">
                <label>
                  备用目标
                  <textarea
                    rows={4}
                    placeholder={"每行一个目标，也可写：目标,端口,优先级\n192.0.2.10\n2001:db8::10\nbackup.example.com,443,20"}
                    value={draft.targets}
                    onChange={(event) => setOriginDrafts((current) => ({ ...current, [group.id]: { ...draft, targets: event.target.value } }))}
                  />
                </label>
                <div className="originBulkControls">
                  <label>
                    默认端口
                    <input title="TCP 检查端口" type="number" min={1} max={65535} value={draft.port} onChange={(event) => setOriginDrafts((current) => ({ ...current, [group.id]: { ...draft, port: Number(event.target.value) } }))} />
                  </label>
                  <label>
                    默认优先级
                    <input title="优先级，数字越小越优先" type="number" min={0} value={draft.priority} onChange={(event) => setOriginDrafts((current) => ({ ...current, [group.id]: { ...draft, priority: Number(event.target.value) } }))} />
                  </label>
                </div>
                <button type="button" className="secondary" onClick={() => createOrigin(group.id)}>
                  <Plus size={16} />
                  <span>批量添加</span>
                </button>
              </div>
              {singleDraftType && (
                <div className="originHint">
                  当前输入识别为 {targetTypeText(singleDraftType)}，故障切换时会发布为 {recordTypeForTargetType(singleDraftType)} 记录。
                </div>
              )}
              {parsedDraft.length > 1 && <div className="originHint">将添加 {parsedDraft.length} 个备用目标。</div>}
            </article>
          );
        })}
      </div>
    </section>
  );
}

function AgentsPanel({ token, agents, agentToken, setAgentToken, act }: { token: string; agents: Agent[]; agentToken: string; setAgentToken: (value: string) => void; act: <T>(fn: () => Promise<T>, done?: string) => Promise<void> }) {
  const [name, setName] = useState("");
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
        body: JSON.stringify({ name })
      });
      setAgentToken(data.token);
    }, "探针已创建");
    setName("");
  }

  return (
    <section className="gridTwo">
      <form className="panel" onSubmit={createAgent}>
        <h2>新建探针</h2>
        <label>
          名称
          <input value={name} onChange={(event) => setName(event.target.value)} required />
        </label>
        <button>
          <RadioTower size={16} />
          <span>创建</span>
        </button>
        {agentToken && (
          <div className="agentSecret">
            <h3>一键安装命令</h3>
            <p>复制下面整条命令到中国服务器的 root 终端执行。安装后会自动创建 <code>cloudflare-dns-agent</code> 服务，并持续从面板拉取探测任务。</p>
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
  act: <T>(fn: () => Promise<T>, done?: string) => Promise<void>;
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
