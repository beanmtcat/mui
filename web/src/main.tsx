import React, { lazy, memo, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  api,
  list,
  mutation,
  bytes,
  type Server,
  type Node,
  type NodeTemplate,
  type Certificate,
  type FirewallRule,
  type ForwardRule,
  type Subscription,
  type Customer,
  type SubscriptionAccess,
  type ConnectionIP,
  type Operation,
  type AuditEntry,
} from "./api";
import "./style.css";
// Heavy / rarely-used UI split out of the main bundle and lazy-loaded:
// TrafficChart (dashboard + traffic modals) and QRCode (TOTP setup only).
const TrafficChart = lazy(() => import("./components/TrafficChart"));
const QRCode = lazy(() => import("./components/QRCode"));
import { MemoSecretField as SecretField, MemoSecretTextarea as SecretTextarea, MemoMaskedValue as MaskedValue } from "./components/secrets";

type Tab =
  | "dashboard"
  | "servers"
  | "nodes"
  | "templates"
  | "certificates"
  | "firewall"
  | "forwards"
  | "subscriptions"
  | "customers"
  | "accesses"
  | "connections"
  | "operations"
  | "audit"
  | "settings";
// Pages that only exist as an entry of a sub-menu have no icon of their own.
type SubPage = "accesses" | "connections" | "audit";
type IconName = "refresh" | "sun" | "moon" | "generate" | "dice" | Exclude<Tab, SubPage> | "logout";
// An entry with children is a group: clicking it opens its first page, and its
// pages are listed beneath it while one of them is showing.
const tabs: { id: Exclude<Tab, SubPage>; label: string; icon: IconName; children?: { id: Tab; label: string }[] }[] = [
  { id: "dashboard", label: "总览", icon: "dashboard" },
  { id: "servers", label: "服务器", icon: "servers" },
  { id: "nodes", label: "节点", icon: "nodes" },
  { id: "templates", label: "节点模板", icon: "templates" },
  { id: "certificates", label: "证书", icon: "certificates" },
  { id: "firewall", label: "防火墙", icon: "firewall" },
  { id: "forwards", label: "端口转发", icon: "forwards" },
  { id: "subscriptions", label: "订阅", icon: "subscriptions" },
  {
    id: "customers", label: "客户端管理", icon: "customers",
    children: [
      { id: "customers", label: "客户" },
      { id: "accesses", label: "订阅访问记录" },
      { id: "connections", label: "节点连接 IP" },
    ],
  },
  {
    id: "operations", label: "操作记录", icon: "operations",
    children: [
      { id: "operations", label: "任务记录" },
      { id: "audit", label: "审计日志" },
    ],
  },
  { id: "settings", label: "设置", icon: "settings" },
];
const emptyServer: Partial<Server> = {
  name: "",
  purpose: "node",
  country: "SG",
  region: "",
  city: "",
  provider: "",
  tags: "",
  notes: "",
  ipv4: "",
  ipv6: "",
  domain: "",
};
const emptyNode: Partial<Node> = {
  serverId: "",
  name: "",
  protocol: "ss",
  port: 50000,
  listen: "0.0.0.0",
  publishAddress: "",
  method: "2022-blake3-aes-128-gcm",
  snellVersion: 5,
  obfs: "none",
  shadowTlsHost: "",
  tlsName: "",
  certificateId: "",
  firewallPolicy: "all",
  firewallSources: "",
  enabled: true,
};
const emptyTemplate: Partial<NodeTemplate> = {
  name: "",
  protocol: "ss",
  port: 50000,
  listen: "0.0.0.0",
  method: "2022-blake3-aes-128-gcm",
  snellVersion: 5,
  obfs: "none",
  shadowTlsHost: "",
  tlsName: "",
};
type TemplateForm = Partial<NodeTemplate> & { password?: string; shadowTlsPassword?: string };
type TrafficPoint = { at: string; uplink: number; downlink: number };
type Usage = { id: string; uplink: number; downlink: number };
type Notice = { tone: "bad" | "warn" | "info"; text: string; tab: Tab };
type ServerFilterField = "country" | "provider" | "region" | "city";
function serverFilterValues(servers: Server[], field: ServerFilterField) {
  return [...new Set(servers.map((server) => server[field]?.trim()).filter((value): value is string => !!value))]
    .sort((a, b) => a.localeCompare(b, "zh-Hans-CN"));
}
function subscriptionNodeEligible(format: string | undefined, node: Node) {
  if (node.protocol === "ss") {
    return node.method.startsWith("2022-blake3-") && (format !== "surge" || node.method !== "2022-blake3-chacha20-poly1305");
  }
  // Surge reaches Snell nodes through ShadowTLS; it has no AnyTLS support here.
  return format !== "surge" || (node.protocol === "snell" && !!node.shadowTlsHost);
}
type Confirmation = {
  title: string;
  message: string;
  confirmLabel: string;
  onConfirm: () => void;
};

// TrafficChart lives in ./components/TrafficChart.tsx (lazy-loaded).
function generatePassword(protocol: Node["protocol"], method = "") {
  const length = protocol === "ss" && method.startsWith("2022-")
    ? method.includes("128") ? 16 : 32
    : 32;
  const random = crypto.getRandomValues(new Uint8Array(length));
  const encoded = btoa(String.fromCharCode(...random));
  return protocol === "ss" && method.startsWith("2022-")
    ? encoded
    : encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function generatePort(excluded: ReadonlySet<number>) {
  const available: number[] = [];
  for (let port = 50000; port <= 60000; port++) {
    if (!excluded.has(port)) available.push(port);
  }
  if (!available.length) throw new Error("50000–60000 范围内没有可用端口");
  const span = available.length;
  const limit = Math.floor(0x100000000 / span) * span;
  const sample = new Uint32Array(1);
  do {
    crypto.getRandomValues(sample);
  } while (sample[0] >= limit);
  return available[sample[0] % span];
}

function trafficSummaryURL() {
  const now = new Date();
  const day = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const month = new Date(now.getFullYear(), now.getMonth(), 1).getTime();
  return `/api/traffic/summary?dayStart=${day}&monthStart=${month}`;
}

function trafficRankingURL() {
  const now = new Date();
  return `/api/traffic/ranking?since=${new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime()}`;
}

function Icon({ name }: { name: IconName }) {
  const paths = {
    refresh: <><path d="M20 11a8 8 0 1 0-2.2 6" /><path d="M20 4v7h-7" /></>,
    sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42" /></>,
    moon: <path d="M20.9 13a9 9 0 0 1-9.9-9.9A9 9 0 1 0 20.9 13Z" />,
    generate: <><path d="m12 3 1.7 5.3L19 10l-5.3 1.7L12 17l-1.7-5.3L5 10l5.3-1.7L12 3Z" /><path d="m19 16 .7 2.3L22 19l-2.3.7L19 22l-.7-2.3L16 19l2.3-.7L19 16Z" /></>,
    dice: <><rect x="3" y="3" width="18" height="18" rx="3" /><circle cx="8" cy="8" r="1" fill="currentColor" stroke="none" /><circle cx="16" cy="8" r="1" fill="currentColor" stroke="none" /><circle cx="12" cy="12" r="1" fill="currentColor" stroke="none" /><circle cx="8" cy="16" r="1" fill="currentColor" stroke="none" /><circle cx="16" cy="16" r="1" fill="currentColor" stroke="none" /></>,
    dashboard: <><rect x="3" y="3" width="8" height="8" rx="1" /><rect x="13" y="3" width="8" height="5" rx="1" /><rect x="13" y="10" width="8" height="11" rx="1" /><rect x="3" y="13" width="8" height="8" rx="1" /></>,
    servers: <><rect x="3" y="3" width="18" height="8" rx="2" /><rect x="3" y="13" width="18" height="8" rx="2" /><path d="M7 7h.01M7 17h.01M11 7h7M11 17h7" /></>,
    nodes: <><circle cx="5" cy="12" r="2" /><circle cx="19" cy="5" r="2" /><circle cx="19" cy="19" r="2" /><path d="m7 11 10-5M7 13l10 5" /></>,
    templates: <><rect x="5" y="3" width="14" height="18" rx="2" /><path d="M9 8h6M9 12h6M9 16h4" /></>,
    certificates: <><path d="M12 2 4 5v7c0 5 3.5 8 8 10 4.5-2 8-5 8-10V5l-8-3Z" /><path d="m9 12 2 2 4-4" /></>,
    firewall: <><path d="M4 3h16v18H4V3ZM4 9h16M4 15h16M9 3v6m6 0v6m-6 0v6" /></>,
    forwards: <><path d="M3 7h12m0 0-3-3m3 3-3 3M21 17H9m0 0 3-3m-3 3 3 3" /></>,
    subscriptions: <><path d="M4 7a13 13 0 0 1 13 13M4 12a8 8 0 0 1 8 8" /><circle cx="5" cy="19" r="1" fill="currentColor" stroke="none" /></>,
    customers: <><circle cx="9" cy="8" r="3" /><path d="M3 20v-2a6 6 0 0 1 12 0v2H3Z" /><circle cx="18" cy="9" r="2" /><path d="M17 15a5 5 0 0 1 4 5" /></>,
    operations: <><path d="M4 4v6h6M4.8 10a8 8 0 1 1-.2 5M12 7v5l3 2" /></>,
    settings: <><circle cx="12" cy="12" r="3" /><path d="M10 2h4l.6 2.2 2 .8 2-.9 2.8 2.8-.9 2 .8 2L23 11v4l-2.2.6-.8 2 .9 2-2.8 2.8-2-.9-2 .8L14 24h-4l-.6-2.2-2-.8-2 .9-2.8-2.8.9-2-.8-2L1 15v-4l2.2-.6.8-2-.9-2L6.9 3.6l2 .9 2-.8L10 2Z" transform="translate(0 -1) scale(1 .95)" /></>,
    logout: <><path d="M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h5M14 17l5-5-5-5M19 12H9" /></>,
  };
  return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}
const emptyRule: Partial<FirewallRule> = {
  serverId: "",
  portFrom: 443,
  portTo: 443,
  network: "tcp",
  source: "",
  action: "allow",
  comment: "",
};
// New forwards default to restricted: only the listed sources are allowed.
// Opening a forward to the whole internet requires an explicit choice below.
const emptyForward: Partial<ForwardRule> = {
  serverId: "", name: "", network: "tcp", listen: "0.0.0.0", port: 50000,
  targetHost: "", targetPort: 443, firewallPolicy: "restricted", firewallSources: "", enabled: true,
};

function App() {
  const templateRequest = useRef(0);
  // Guard against overlapping full refreshes (act() -> refresh() while a
  // poll is running, double clicks, ...). A refresh already in flight is
  // skipped instead of stacking duplicate requests.
  const refreshInFlight = useRef(false);
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    const stored = localStorage.getItem("mui-theme");
    return stored === "light" || stored === "dark"
      ? stored
      : matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });
  const [authed, setAuthed] = useState<boolean | null>(null),
    [totpEnabled, setTotpEnabled] = useState(false),
    [tab, setTab] = useState<Tab>("dashboard");
  const [opServer, setOpServer] = useState(""),
    [auditQuery, setAuditQuery] = useState(""),
    [auditInput, setAuditInput] = useState(""),
    [accessCustomer, setAccessCustomer] = useState(""),
    [connectionServer, setConnectionServer] = useState(""),
    [subQuery, setSubQuery] = useState(""),
    [customerQuery, setCustomerQuery] = useState("");
  const showLogError = (e: Error) => setError(e.message);
  const opLog = usePagedLog<Operation>(
    authed && tab === "operations" ? "/api/operations?serverId=" + encodeURIComponent(opServer) : null,
    (items) => "before=" + items[items.length - 1].id, showLogError);
  const auditLog = usePagedLog<AuditEntry>(
    authed && tab === "audit" ? "/api/audit?q=" + encodeURIComponent(auditQuery) : null,
    (items) => "before=" + items[items.length - 1].id, showLogError);
  const accessLog = usePagedLog<SubscriptionAccess>(
    authed && tab === "accesses" ? "/api/clients/accesses?customerId=" + encodeURIComponent(accessCustomer) : null,
    (items) => "before=" + items[items.length - 1].id, showLogError);
  const connectionLog = usePagedLog<ConnectionIP>(
    authed && tab === "connections" ? "/api/clients/connections?serverId=" + encodeURIComponent(connectionServer) : null,
    (items) => "before=" + encodeURIComponent(items[items.length - 1].cursor), showLogError);
  const [servers, setServers] = useState<Server[]>([]),
    [nodes, setNodes] = useState<Node[]>([]),
    [templates, setTemplates] = useState<NodeTemplate[]>([]),
    [certificates, setCertificates] = useState<Certificate[]>([]),
    [rules, setRules] = useState<FirewallRule[]>([]),
    [forwards, setForwards] = useState<ForwardRule[]>([]),
    [subs, setSubs] = useState<Subscription[]>([]),
    [customers, setCustomers] = useState<Customer[]>([]),
    [operations, setOperations] = useState<Operation[]>([]),
    [agentReleases, setAgentReleases] = useState<Record<string, string>>({}),
    [coreReleases, setCoreReleases] = useState<Record<string, string>>({});
  const [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [templateLoading, setTemplateLoading] = useState(false),
    [modal, setModal] = useState<
      "server" | "node" | "template" | "certificate" | "rule" | "forward" | "subscription" | "customer" | null
    >(null),
    [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [serverForm, setServerForm] = useState<Partial<Server>>(emptyServer),
    [nodeForm, setNodeForm] = useState<Partial<Node> & { password?: string; shadowTlsPassword?: string }>(
      emptyNode,
    ),
    [templateForm, setTemplateForm] = useState<TemplateForm>(emptyTemplate),
    [selectedTemplate, setSelectedTemplate] = useState(""),
    [certForm, setCertForm] = useState<Partial<Certificate>>({
      serverId: "",
      name: "",
      domain: "",
      pem: "",
      key: "",
    }),
    [ruleForm, setRuleForm] = useState<Partial<FirewallRule>>(emptyRule),
    [forwardForm, setForwardForm] = useState<Partial<ForwardRule>>(emptyForward),
    [subForm, setSubForm] = useState<Partial<Subscription>>({
      name: "",
      format: "sing-box",
      nodeIds: [],
      enabled: true,
    }),
    [customerForm, setCustomerForm] = useState<Partial<Customer>>({ name: "", notes: "" });
  const [installInfo, setInstallInfo] = useState<{ command: string; serverName: string } | null>(null),
    [issuedURL, setIssuedURL] = useState(""),
    [preview, setPreview] = useState<{
      content: string;
      excluded: string[];
    } | null>(null),
    [trafficNode, setTrafficNode] = useState<Node | null>(null),
    [traffic, setTraffic] = useState<
      { at: string; uplink: number; downlink: number }[]
    >([]),
    [trafficSub, setTrafficSub] = useState<Subscription | null>(null),
    [subTraffic, setSubTraffic] = useState<TrafficPoint[]>([]);
  const [firewallServer, setFirewallServer] = useState(""),
    [passwordForm, setPasswordForm] = useState({ current: "", next: "" }),
    [totpOff, setTotpOff] = useState({ password: "", code: "" });
  const [summary, setSummary] = useState<{
    today: { uplink: number; downlink: number };
    month: { uplink: number; downlink: number };
  }>({ today: { uplink: 0, downlink: 0 }, month: { uplink: 0, downlink: 0 } });
  const [dashSeries, setDashSeries] = useState<TrafficPoint[]>([]),
    [ranking, setRanking] = useState<{ nodes: Usage[]; subscriptions: Usage[] }>({ nodes: [], subscriptions: [] });
  const [nodeServerFilter, setNodeServerFilter] = useState(""),
    [nodeProtocolFilter, setNodeProtocolFilter] = useState("");
  const [serverFilters, setServerFilters] = useState<Record<ServerFilterField, string>>({
    country: "", provider: "", region: "", city: "",
  });
  const [password, setPassword] = useState(""),
    [code, setCode] = useState(""),
    [totpSetup, setTotpSetup] = useState<{
      secret: string;
      uri: string;
    } | null>(null);
  // Fetch a list through the server pagination protocol (?limit=&cursor=,
  // {items, nextCursor, total}), following cursors until the list is
  // complete. The tables still filter client-side (server/protocol/search
  // filters have no server-side params yet), so the working set must be
  // complete; a single-page UI pager is the follow-up once the server
  // accepts filter params. Logs keep their own cursor paging (usePagedLog).
  const loadAll = useCallback(async <T,>(path: string): Promise<T[]> => {
    const out: T[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 50; page++) {
      const res = await list<T>(path, { limit: 100, cursor });
      out.push(...res.items);
      if (!res.nextCursor) break;
      cursor = res.nextCursor;
    }
    return out;
  }, []);
  const refresh = useCallback(async () => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    try {
    // Each list loads on its own: one failing endpoint must not leave every
    // other part of the page showing stale data.
    const failures: string[] = [];
    const load = <T,>(path: string, apply: (value: T[]) => void) =>
      loadAll<T>(path).then(apply).catch((e) => { failures.push((e as Error).message); });
    await Promise.all([
      load<Server>("/api/servers", setServers),
      load<Node>("/api/nodes", (n) => {
        setNodes(n);
        setTrafficNode((current) => current ? n.find((item) => item.id === current.id) || current : null);
      }),
      load<NodeTemplate>("/api/node-templates", setTemplates),
      load<Certificate>("/api/certificates", setCertificates),
      load<FirewallRule>("/api/firewall", setRules),
      load<ForwardRule>("/api/forwards", setForwards),
      load<Subscription>("/api/subscriptions", (u) => {
        setSubs(u);
        setTrafficSub((current) => current ? u.find((item) => item.id === current.id) || null : null);
      }),
      load<Operation>("/api/operations", setOperations),
      // Not lists: these answer with a single document and are never paged.
      api<typeof summary>(trafficSummaryURL()).then(setSummary).catch((e) => { failures.push((e as Error).message); }),
      api<TrafficPoint[]>("/api/traffic/series?hours=24").then(setDashSeries).catch((e) => { failures.push((e as Error).message); }),
      api<typeof ranking>(trafficRankingURL()).then(setRanking).catch((e) => { failures.push((e as Error).message); }),
      load<Customer>("/api/customers", setCustomers),
      api<Record<string, string>>("/api/agent/release").then(setAgentReleases).catch(() => setAgentReleases({})),
      api<Record<string, string>>("/api/core/release").then(setCoreReleases).catch(() => setCoreReleases({})),
    ]);
    // The paged logs go back to their first page: whatever was just done is at the top.
    opLog.reload();
    auditLog.reload();
    accessLog.reload();
    connectionLog.reload();
    if (failures.length) setError(failures[0] + (failures.length > 1 ? `（另有 ${failures.length - 1} 项加载失败）` : ""));
    } finally {
      refreshInFlight.current = false;
    }
  }, [loadAll, opLog, auditLog, accessLog, connectionLog]);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("mui-theme", theme);
  }, [theme]);
  useEffect(() => {
    const expired = () => {
      setAuthed(false);
      setError("会话已过期，请重新登录");
    };
    window.addEventListener("mui:session-expired", expired);
    return () => window.removeEventListener("mui:session-expired", expired);
  }, []);
  useEffect(() => {
    api<{ authenticated: boolean; totpEnabled: boolean }>("/api/me")
      .then((v) => {
        setAuthed(true);
        setTotpEnabled(v.totpEnabled);
        refresh();
      })
      .catch(() => setAuthed(false));
  }, []);
  useEffect(() => {
    if (!authed) return;
    let inFlight = false;
    const poll = async () => {
      if (document.hidden || inFlight) return;
      inFlight = true;
      try {
        switch (tab) {
          case "dashboard": {
            const [s, n, o, summary, series, ranks, u] = await Promise.all([
              loadAll<Server>("/api/servers"),
              loadAll<Node>("/api/nodes"),
              loadAll<Operation>("/api/operations"),
              api<{ today: { uplink: number; downlink: number }; month: { uplink: number; downlink: number } }>(trafficSummaryURL()),
              api<TrafficPoint[]>("/api/traffic/series?hours=24"),
              api<{ nodes: Usage[]; subscriptions: Usage[] }>(trafficRankingURL()),
              loadAll<Subscription>("/api/subscriptions"),
            ]);
            setServers(s);
            setNodes(n);
            setOperations(o);
            setSummary(summary);
            setDashSeries(series);
            setRanking(ranks);
            setSubs(u);
            break;
          }
          case "servers":
            {
              const [s, o] = await Promise.all([
                loadAll<Server>("/api/servers"),
                loadAll<Operation>("/api/operations"),
              ]);
              setServers(s);
              setOperations(o);
            }
            break;
          case "nodes": {
            const n = await loadAll<Node>("/api/nodes");
            setNodes(n);
            setTrafficNode((current) => current ? n.find((item) => item.id === current.id) || current : null);
            break;
          }
          case "firewall": {
            const [s, f] = await Promise.all([
              loadAll<Server>("/api/servers"),
              loadAll<FirewallRule>("/api/firewall"),
            ]);
            setServers(s);
            setRules(f);
            break;
          }
          case "forwards": {
            const [s, f] = await Promise.all([loadAll<Server>("/api/servers"), loadAll<ForwardRule>("/api/forwards")]);
            setServers(s);
            setForwards(f);
            break;
          }
          case "operations":
            setOperations(await loadAll<Operation>("/api/operations"));
            // Leave a list alone once the reader has paged into older entries.
            if (!opLog.expanded) opLog.reload();
            break;
          case "audit":
            if (!auditLog.expanded) auditLog.reload();
            break;
          case "accesses":
            if (!accessLog.expanded) accessLog.reload();
            break;
          case "connections":
            if (!connectionLog.expanded) connectionLog.reload();
            break;
          case "subscriptions":
            setSubs(await loadAll<Subscription>("/api/subscriptions"));
            break;
        }
      } catch (e) {
        setError((e as Error).message);
      } finally {
        inFlight = false;
      }
    };
    const onVisible = () => { if (!document.hidden) void poll(); };
    const timer = setInterval(poll, 30000);
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [authed, tab]);
  useEffect(() => {
    if (!trafficNode) return;
    api<{ at: string; uplink: number; downlink: number }[]>(
      "/api/traffic/series?hours=24&nodeId=" + trafficNode.id,
    )
      .then(setTraffic)
      .catch((e) => setError(e.message));
  }, [trafficNode]);
  useEffect(() => {
    if (!trafficSub) return;
    api<TrafficPoint[]>("/api/subscriptions/" + trafficSub.id + "/traffic/series?hours=24")
      .then(setSubTraffic)
      .catch((e) => setError(e.message));
  }, [trafficSub?.id]);
  const activeNodes = useMemo(() => nodes.filter((n) => n.status === "active" && n.enabled), [nodes]);
  const onlineServers = useMemo(() => servers.filter((s) => s.status === "online"), [servers]);
  // What the agent saw that disagrees with what was entered for this server.
  const serverWarnings = useCallback((s: Server) => {
    const out: string[] = [];
    if (s.detectedIpv4 && s.ipv4 && s.detectedIpv4 !== s.ipv4)
      out.push(`Agent 检测到 IPv4 ${s.detectedIpv4}，与填写的不同`);
    if (s.detectedIpv6 && s.ipv6 && s.detectedIpv6 !== s.ipv6)
      out.push(`Agent 检测到 IPv6 ${s.detectedIpv6}，与填写的不同`);
    if (Math.abs(s.clockSkewSeconds || 0) > 60)
      out.push(`系统时间与面板相差 ${s.clockSkewSeconds} 秒，请检查时间同步`);
    if (s.firewallConflict)
      out.push(`${s.firewallConflict} 正在管理防火墙，面板已停止写入 UFW`);
    return out;
  }, []);
  const fwServer = useMemo(() => servers.find((s) => s.id === firewallServer) || servers[0], [servers, firewallServer]);
  const fwNodes = useMemo(() => nodes.filter(
    (n) => n.serverId === fwServer?.id && n.enabled && !n.deleting,
  ), [nodes, fwServer]);
  const fwRules = useMemo(() => rules.filter((r) => r.serverId === fwServer?.id), [rules, fwServer]);
  const nodeFirewallUnsupported = !!nodeForm.firewallPolicy && nodeForm.firewallPolicy !== "all" &&
    !servers.find((s) => s.id === nodeForm.serverId)?.nodeFirewallPolicies;
  const fwHistory = useMemo(() => operations
    .filter(
      (o) =>
        o.serverId === fwServer?.id &&
        (o.kind === "firewall.apply" || o.kind === "ufw.init"),
    )
    .slice(0, 8), [operations, fwServer]);
  const visibleNodes = useMemo(() => nodes.filter(
    (n) =>
      (!nodeServerFilter || n.serverId === nodeServerFilter) &&
      (!nodeProtocolFilter || n.protocol === nodeProtocolFilter),
  ), [nodes, nodeServerFilter, nodeProtocolFilter]);
  const visibleServers = useMemo(() => servers.filter((server) =>
    (Object.keys(serverFilters) as ServerFilterField[]).every(
      (field) => !serverFilters[field] || server[field]?.trim() === serverFilters[field],
    ),
  ), [servers, serverFilters]);
  const totalTraffic = useMemo(() => nodes.reduce((sum, n) => sum + n.uplink + n.downlink, 0), [nodes]);
  // Certificate expiry comes from the server (daysUntilExpiry / expiringSoon);
  // the frontend never computes it from expiresAt.
  const expiring = useMemo(() => certificates.filter(
    (c) => c.expiringSoon === true || (c.daysUntilExpiry !== undefined && c.daysUntilExpiry <= 30),
  ), [certificates]);
  const serverName = useCallback((id: string) =>
    servers.find((s) => s.id === id)?.name || id.slice(0, 8), [servers]);
  // Nodes of a subscription whose configuration is not live on their server yet.
  const pendingNodes = useCallback((sub: Subscription) =>
    (sub.pendingNodeIds || []).map((id) => nodes.find((item) => item.id === id)).filter((n): n is Node => !!n), [nodes]);
  const pendingSummary = useCallback((sub: Subscription) =>
    pendingNodes(sub).map((n) => {
      const server = servers.find((item) => item.id === n.serverId);
      return `${n.name}（${server?.name || "未知服务器"}${server && server.status !== "online" ? "，离线" : ""}）`;
    }).join("、"), [pendingNodes, servers]);
  // sing-box has to restart to add or remove a login, which drops the
  // connections of everyone on that server.
  const restartNotice = useCallback((nodeIds: string[]) => {
    const names = [...new Set(nodeIds.map((id) => nodes.find((n) => n.id === id)?.serverId).filter(Boolean))]
      .map((id) => serverName(id as string));
    return names.length
      ? `\n\n以下服务器的 sing-box 会重启，其上所有连接将中断数秒：${names.join("、")}`
      : "";
  }, [nodes, serverName]);
  const act = useCallback(async (
    fn: () => Promise<unknown>,
    success = "操作已提交",
  ): Promise<boolean> => {
    setError("");
    setNotice("");
    try {
      await fn();
      setNotice(success);
      await refresh();
      return true;
    } catch (e) {
      setError((e as Error).message);
      return false;
    }
  }, [refresh]);
  const copy = useCallback(async (text: string) => {
    // Clipboard API fails in non-secure contexts or when permission is
    // denied; fall back to execCommand, then to a manual-copy message.
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        setNotice("已复制到剪贴板");
        return;
      }
      throw new Error("clipboard unavailable");
    } catch {
      try {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand("copy");
        document.body.removeChild(ta);
        if (ok) {
          setNotice("已复制到剪贴板");
          return;
        }
      } catch {
        // Fall through to the manual message below.
      }
      setError("自动复制失败：浏览器未授予剪贴板权限，请手动选中复制。");
    }
  }, []);
  const openServer = (s?: Server) => {
    setServerForm(s ? { ...s } : { ...emptyServer });
    setModal("server");
  };
  const clearSelectedTemplate = () => {
    templateRequest.current++;
    setTemplateLoading(false);
    setSelectedTemplate("");
  };
  const openNode = (n?: Node) => {
    clearSelectedTemplate();
    setNodeForm(
      n
        ? { ...n, password: "", shadowTlsPassword: "" }
        : { ...emptyNode, serverId: servers[0]?.id || "" },
    );
    setModal("node");
  };
  const randomizeNodePort = () => {
    const server = servers.find((s) => s.id === nodeForm.serverId);
    const occupied = new Set([
      nodeForm.port || 0,
      ...nodes.filter((n) => n.serverId === nodeForm.serverId).map((n) => n.port),
      ...(server?.sshPorts || []),
    ]);
    try {
      setNodeForm({ ...nodeForm, port: generatePort(occupied) });
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const matchingCertificate = useCallback((serverId: string, tlsName: string) =>
    certificates.find(
      (c) =>
        c.serverId === serverId &&
        c.domain.toLowerCase() === tlsName.toLowerCase() &&
        new Date(c.expiresAt).getTime() > Date.now(),
    )?.id || "", [certificates]);
  const useTemplate = async (template: NodeTemplate, serverId = nodeForm.serverId || "") => {
    const request = ++templateRequest.current;
    setError("");
    setTemplateLoading(true);
    try {
      const detail = await api<NodeTemplate & { password: string; shadowTlsPassword: string }>(`/api/node-templates/${template.id}`);
      if (request !== templateRequest.current) return;
      const selectedServer = serverId || servers[0]?.id || "";
      setNodeForm({
        ...emptyNode,
        serverId: selectedServer,
        name: detail.name,
        protocol: detail.protocol,
        port: detail.port,
        listen: detail.listen,
        method: detail.method,
        snellVersion: detail.snellVersion,
        obfs: detail.obfs,
        shadowTlsHost: detail.shadowTlsHost,
        tlsName: detail.tlsName,
        certificateId:
          detail.protocol === "anytls"
            ? matchingCertificate(selectedServer, detail.tlsName)
            : "",
        password: detail.password || generatePassword(detail.protocol, detail.method),
        shadowTlsPassword: detail.protocol === "snell"
          ? detail.shadowTlsPassword || generatePassword("snell")
          : "",
      });
      setSelectedTemplate(detail.id);
      setTab("nodes");
      setModal("node");
    } catch (e) {
      if (request === templateRequest.current) setError((e as Error).message);
    } finally {
      if (request === templateRequest.current) setTemplateLoading(false);
    }
  };
  const openTemplate = async (source?: NodeTemplate | Node) => {
    clearSelectedTemplate();
    try {
      const secrets = source
        ? "serverId" in source
          ? await api<{ password: string; shadowTlsPassword: string }>(`/api/nodes/${source.id}/secret`)
          : await api<NodeTemplate & { password: string; shadowTlsPassword: string }>(`/api/node-templates/${source.id}`)
        : { password: "", shadowTlsPassword: "" };
      setTemplateForm(
        source
          ? {
            ...emptyTemplate,
            id: "serverId" in source ? undefined : source.id,
            name: source.name,
            protocol: source.protocol,
            port: source.port,
            listen: source.listen,
            method: source.method,
            snellVersion: source.snellVersion,
            obfs: source.obfs,
            shadowTlsHost: source.shadowTlsHost,
            tlsName: source.tlsName,
            password: secrets.password,
            shadowTlsPassword: secrets.shadowTlsPassword,
          }
          : { ...emptyTemplate, password: "", shadowTlsPassword: "" },
      );
      setModal("template");
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const close = () => {
    clearSelectedTemplate();
    setModal(null);
    setIssuedURL("");
  };
  const submitServer = async (e: React.FormEvent) => {
    e.preventDefault();
    const ok = await act(async () => {
      if (serverForm.id) {
        await mutation("/api/servers/" + serverForm.id, "PATCH", serverForm);
      } else {
        const result = await mutation<{ installCommand: string }>(
          "/api/servers",
          "POST",
          serverForm,
        );
        setModal(null);
        setInstallInfo({ command: result.installCommand, serverName: serverForm.name || "新服务器" });
        return;
      }
    }, "服务器已保存");
    if (ok && serverForm.id) close();
  };
  const submitNode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (
      await act(
        () =>
          mutation(
            "/api/nodes" + (nodeForm.id ? "/" + nodeForm.id : ""),
            nodeForm.id ? "PATCH" : "POST",
            nodeForm.id ? nodeForm : { ...nodeForm, templateId: selectedTemplate },
          ),
        nodeFirewallUnsupported
          ? "配置已保存，等待 Agent 更新后应用；原 UFW 规则仍会生效"
          : "配置已保存，等待 Agent 应用",
      )
    )
      close();
  };
  const submitTemplate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (
      await act(
        () =>
          mutation(
            "/api/node-templates" + (templateForm.id ? "/" + templateForm.id : ""),
            templateForm.id ? "PATCH" : "POST",
            templateForm,
          ),
        "节点模板已保存",
      )
    )
      close();
  };
  const submitCert = async (e: React.FormEvent) => {
    e.preventDefault();
    if (
      await act(
        () => mutation("/api/certificates", "POST", certForm),
        "证书已添加",
      )
    )
      close();
  };
  const submitRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (
      await act(
        () => mutation("/api/firewall", "POST", ruleForm),
        "UFW 规则已提交",
      )
    )
      close();
  };
  const doSubmitForward = async () => {
    const path = "/api/forwards" + (forwardForm.id ? "/" + forwardForm.id : "");
    if (await act(() => mutation(path, forwardForm.id ? "PATCH" : "POST", forwardForm), "转发配置已提交，等待 Agent 应用")) close();
  };
  const submitForward = async (e: React.FormEvent) => {
    e.preventDefault();
    // Opening a forward to the whole internet needs an explicit confirm.
    if (forwardForm.firewallPolicy === "all") {
      setConfirmation({
        title: "确认公开转发",
        message: `转发「${forwardForm.name || ""}」将放行所有来源，目标 ${forwardForm.targetHost || ""}:${forwardForm.targetPort || ""} 会暴露给全网。确定公开吗？如只需特定来源，请改用“仅放行指定 IP / CIDR”。`,
        confirmLabel: "确认公开",
        onConfirm: () => { void doSubmitForward(); },
      });
      return;
    }
    await doSubmitForward();
  };
  const submitSub = async (e: React.FormEvent) => {
    e.preventDefault();
    if (subForm.id) {
      if (
        await act(
          () => mutation("/api/subscriptions/" + subForm.id, "PATCH", subForm),
          "订阅已保存",
        )
      )
        close();
      return;
    }
    await act(async () => {
      const result = await mutation<Subscription>(
        "/api/subscriptions",
        "POST",
        subForm,
      );
      setIssuedURL(result.url || "");
    }, "订阅已创建");
  };
  const submitCustomer = async (e: React.FormEvent) => {
    e.preventDefault();
    const ok = await act(
      () => mutation(customerForm.id ? "/api/customers/" + customerForm.id : "/api/customers", customerForm.id ? "PATCH" : "POST", customerForm),
      customerForm.id ? "客户已保存" : "客户已创建",
    );
    if (ok) close();
  };
  const deleteItem = (path: string, label: string) => {
    setConfirmation({
      title: `删除${label}`,
      message: `确定删除${label}？此操作无法撤销。`,
      confirmLabel: "删除",
      onConfirm: () => { void act(() => mutation(path, "DELETE"), `${label}已删除`); },
    });
  };
  const deleteServer = (s: Server) => {
    const owned =
      nodes.some((n) => n.serverId === s.id) ||
      rules.some((r) => r.serverId === s.id) ||
      forwards.some((f) => f.serverId === s.id) ||
      certificates.some((c) => c.serverId === s.id);
    if (!owned || s.status === "online")
      return deleteItem("/api/servers/" + s.id, "服务器");
    setConfirmation({
      title: "强制删除服务器",
      message: `服务器「${s.name}」已离线，无法确认节点已停止。\n强制删除会同时移除它的节点、规则、证书和流量记录，且不可恢复。`,
      confirmLabel: "强制删除",
      onConfirm: () => {
        void act(
          () => mutation("/api/servers/" + s.id + "?force=1", "DELETE"),
          "服务器已强制删除",
        );
      },
    });
  };
  const matches = useCallback((query: string, ...fields: (string | undefined)[]) => {
    const q = query.trim().toLowerCase();
    return !q || fields.some((field) => (field || "").toLowerCase().includes(q));
  }, []);
  const visibleSubs = useMemo(() => subs.filter((sub) => matches(subQuery, sub.name, customers.find((c) => c.id === sub.customerId)?.name)), [subs, matches, subQuery, customers]);
  const visibleCustomers = useMemo(() => customers.filter((c) => matches(customerQuery, c.name, c.notes)), [customers, matches, customerQuery]);
  const auditTarget = useCallback((id: string) =>
    servers.find((x) => x.id === id)?.name || nodes.find((x) => x.id === id)?.name ||
    subs.find((x) => x.id === id)?.name || customers.find((x) => x.id === id)?.name ||
    (id.length > 12 ? id.slice(0, 8) + "…" : id), [servers, nodes, subs, customers]);
  const goTo = useCallback((target: Tab) => {
    setTab(target);
    setError("");
    setNotice("");
  }, []);
  const pageTitle = useMemo(() =>
    tabs.flatMap((t) => t.children || []).find((child) => child.id === tab)?.label ||
    tabs.find((t) => t.id === tab)?.label, [tab]);
  const liveSubs = useMemo(() => subs.filter((sub) => sub.enabled && (!sub.expiresAt || new Date(sub.expiresAt).getTime() > Date.now())), [subs]);
  const failedNodes = useMemo(() => nodes.filter((n) => n.status === "error"), [nodes]);
  const split = useCallback((v: { uplink: number; downlink: number }) => `↑ ${bytes(v.uplink)} · ↓ ${bytes(v.downlink)}`, []);
  const statCards = useMemo(() => [
    {
      label: "在线服务器",
      value: `${onlineServers.length} / ${servers.length}`,
      note: servers.length === onlineServers.length ? "全部在线" : `${servers.length - onlineServers.length} 台离线或未接入`,
    },
    {
      label: "运行中节点",
      value: `${activeNodes.length} / ${nodes.length}`,
      note: failedNodes.length ? `${failedNodes.length} 个应用失败` : `${nodes.filter((n) => !n.enabled).length} 个已停用`,
    },
    {
      label: "有效订阅",
      value: `${liveSubs.length} / ${subs.length}`,
      note: `${customers.length} 个客户`,
    },
    { label: "今日流量", value: bytes(summary.today.uplink + summary.today.downlink), note: split(summary.today) },
    { label: "本月流量", value: bytes(summary.month.uplink + summary.month.downlink), note: split(summary.month) },
    { label: "累计流量", value: bytes(totalTraffic), note: "全部节点" },
  ], [onlineServers, servers, activeNodes, nodes, failedNodes, liveSubs, subs, customers, summary, split, totalTraffic]);
  // Everything that wants the administrator's attention, worst first.
  const attention: Notice[] = useMemo(() => {
  const list: Notice[] = [];
  // Alias so the pushes below keep their original shape.
  const attention = list;
  for (const sv of servers) {
    if (sv.status === "offline")
      attention.push({ tone: "bad", tab: "servers", text: `服务器 ${sv.name} 离线，最后上报于 ${sv.lastSeen ? new Date(sv.lastSeen).toLocaleString() : "未知时间"}` });
    else if (sv.status === "pending")
      attention.push({ tone: "info", tab: "servers", text: `服务器 ${sv.name} 尚未接入 Agent` });
    else {
      if (sv.ufwStatus && sv.ufwStatus !== "active" && !sv.firewallConflict)
        attention.push({ tone: "warn", tab: "servers", text: `服务器 ${sv.name} 的 UFW 未启用，节点和规则无法应用` });
      if (sv.statsStatus === "unavailable")
        attention.push({ tone: "warn", tab: "servers", text: `服务器 ${sv.name} 的流量统计不可用` });
    }
    for (const warning of serverWarnings(sv))
      attention.push({ tone: "warn", tab: "servers", text: `${sv.name}：${warning}` });
  }
  for (const n of failedNodes)
    attention.push({ tone: "bad", tab: "nodes", text: `节点 ${n.name}（${serverName(n.serverId)}）应用失败${n.error ? "：" + n.error : ""}` });
  for (const sv of servers) {
    const latest = operations.find((o) => o.serverId === sv.id);
    if (latest?.status === "failed" && !failedNodes.some((n) => n.serverId === sv.id))
      attention.push({ tone: "bad", tab: "operations", text: `${sv.name} 最近一次任务失败（${kindLabel(latest.kind)}）${latest.error ? "：" + latest.error : ""}` });
  }
  for (const c of certificates) {
    // Expiry comes from the server (daysUntilExpiry / expiringSoon).
    const days = c.daysUntilExpiry;
    if (c.expiringSoon === true || (days !== undefined && days < 30)) {
      const text = days === undefined
        ? `证书 ${c.domain} 即将到期（30 天内）`
        : days < 0 ? `证书 ${c.domain} 已过期` : `证书 ${c.domain} 将在 ${days} 天后到期`;
      attention.push({ tone: days !== undefined && days < 7 ? "bad" : "warn", tab: "certificates", text });
    }
  }
  for (const sub of liveSubs) {
    const waiting = pendingNodes(sub);
    if (waiting.length)
      attention.push({ tone: "warn", tab: "subscriptions", text: `订阅 ${sub.name} 有 ${waiting.length} 个节点尚未生效：${pendingSummary(sub)}` });
    const days = sub.expiresAt ? Math.floor((new Date(sub.expiresAt).getTime() - Date.now()) / 86400000) : Infinity;
    if (days < 7)
      attention.push({ tone: "info", tab: "subscriptions", text: `订阅 ${sub.name} 将在 ${days < 1 ? "今天" : days + " 天后"}到期` });
  }
  const upgradable = servers.filter((sv) => sv.status === "online" && (
    (sv.agentSelfUpdate && agentReleases[sv.arch] && sv.agentBuild !== agentReleases[sv.arch]) ||
    (sv.coreSelfUpdate && !!sv.coreBuild && coreReleases[sv.arch] && sv.coreBuild !== coreReleases[sv.arch])));
  if (upgradable.length)
    attention.push({ tone: "info", tab: "servers", text: `${upgradable.length} 台服务器有可用的 Agent 或 sing-box 升级：${upgradable.map((sv) => sv.name).join("、")}` });
  const toneOrder = { bad: 0, warn: 1, info: 2 };
  attention.sort((x, y) => toneOrder[x.tone] - toneOrder[y.tone]);
  return list;
  }, [servers, failedNodes, operations, certificates, liveSubs, pendingNodes, pendingSummary, serverWarnings, serverName, agentReleases, coreReleases]);
  const total = useCallback((v: Usage) => v.uplink + v.downlink, []);
  const topNodes = useMemo(() => [...ranking.nodes].sort((x, y) => total(y) - total(x)).slice(0, 5), [ranking, total]);
  const topSubs = useMemo(() => [...ranking.subscriptions].sort((x, y) => total(y) - total(x)).slice(0, 5), [ranking, total]);
  const todayByServer = useCallback((id: string) =>
    ranking.nodes.filter((u) => nodes.find((n) => n.id === u.id)?.serverId === id).reduce((sum, u) => sum + total(u), 0), [ranking, nodes, total]);
  if (authed === null) return <div className="loading">正在加载面板…</div>;
  if (!authed)
    return (
      <div className="loginShell">
        <div className="loginCard">
          <h1>MUI 节点管理面板</h1>
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setError("");
              try {
                const result = await mutation<{ totpEnabled: boolean }>(
                  "/api/login",
                  "POST",
                  { password, code },
                );
                setTotpEnabled(result.totpEnabled);
                setAuthed(true);
                // Do not keep the password / TOTP code in React state.
                setPassword("");
                setCode("");
                await refresh();
              } catch (err) {
                setError((err as Error).message);
              }
            }}
          >
            <label>
              管理员密码
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoFocus
              />
            </label>
            <label>
              动态验证码（未启用请留空）
              <input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                maxLength={6}
              />
            </label>
            {error && <div className="error">{error}</div>}
            <button className="primary" type="submit">
              登录
            </button>
          </form>
        </div>
      </div>
    );
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">MUI 节点管理面板</div>
        <nav>
          {tabs.map((t) => {
            const open = !!t.children?.some((child) => child.id === tab);
            return (
              <React.Fragment key={t.id}>
                <button
                  className={t.children ? (open ? "open" : "") : tab === t.id ? "active" : ""}
                  aria-expanded={t.children ? open : undefined}
                  onClick={() => goTo(t.id)}
                >
                  <Icon name={t.icon} />
                  {t.label}
                </button>
                {open && t.children!.map((child) => (
                  <button key={child.id} className={"child" + (tab === child.id ? " active" : "")} onClick={() => goTo(child.id)}>
                    {child.label}
                  </button>
                ))}
              </React.Fragment>
            );
          })}
        </nav>
        <div className="sideBottom">
          <button
            onClick={async () => {
              try {
                await mutation("/api/logout", "POST");
                setAuthed(false);
                setError("");
                setNotice("");
              } catch (e) {
                setError((e as Error).message);
              }
            }}
          >
            <Icon name="logout" />
            退出登录
          </button>
        </div>
      </aside>
      <main>
        <header>
          <h1>{pageTitle}</h1>
          <div className="headerActions">
            <button className="iconButton" type="button" onClick={refresh} aria-label="刷新" title="刷新"><Icon name="refresh" /></button>
            <button className="iconButton" type="button" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label={theme === "dark" ? "切换浅色模式" : "切换深色模式"} title={theme === "dark" ? "切换浅色模式" : "切换深色模式"}><Icon name={theme === "dark" ? "sun" : "moon"} /></button>
          </div>
        </header>
        {error && (
          <div className="banner error">
            {error}
            <button onClick={() => setError("")}>×</button>
          </div>
        )}
        {notice && (
          <div className="banner success">
            {notice}
            <button onClick={() => setNotice("")}>×</button>
          </div>
        )}
        {expiring.length > 0 && (
          <div className="banner warning">
            {expiring.length} 张 TLS 证书已过期或将在 30 天内到期，请尽快更新。
          </div>
        )}
        {tab === "dashboard" && (
          <>
            <section className="panel">
              <div className="panelHead">
                <h2>需要关注</h2>
                <span className="hint">{attention.length ? `${attention.length} 项` : ""}</span>
              </div>
              {attention.length ? (
                attention.slice(0, 12).map((item, index) => (
                  <div className="listRow attention" key={index}>
                    <span className={"status " + (item.tone === "info" ? "idle" : item.tone)} aria-label={item.tone === "bad" ? "严重" : item.tone === "warn" ? "警告" : "提示"} />
                    <div className="grow">{item.text}</div>
                    <button className="textButton" onClick={() => goTo(item.tab)}>查看</button>
                  </div>
                ))
              ) : (
                <div className="listRow attention"><span className="status good" /><div className="grow">一切正常，没有需要处理的事项。</div></div>
              )}
              {attention.length > 12 && <div className="listRow attention"><div className="grow hint">另有 {attention.length - 12} 项未显示</div></div>}
            </section>
            <div className="statGrid">
              {statCards.map((c) => (
                <div className="statCard" key={c.label}>
                  <span>{c.label}</span>
                  <strong>{c.value}</strong>
                  <small>{c.note}</small>
                </div>
              ))}
            </div>
            <section className="panel">
              <div className="panelHead"><h2>全部节点流量</h2></div>
              {dashSeries.length ? <Suspense fallback={<div className="trafficChart"><Empty text="正在加载图表…" /></div>}><TrafficChart points={dashSeries} /></Suspense> : <div className="trafficChart"><Empty text="暂无流量样本" /></div>}
            </section>
            <div className="twoCol">
              <section className="panel">
                <div className="panelHead">
                  <h2>今日节点流量排行</h2>
                  <button className="textButton" onClick={() => goTo("nodes")}>全部节点 →</button>
                </div>
                {topNodes.length ? (
                  <table><tbody>
                    {topNodes.map((u, index) => {
                      const node = nodes.find((n) => n.id === u.id);
                      return (
                        <tr key={u.id}>
                          <td className="rank">{index + 1}</td>
                          <td><strong>{node?.name || "已删除的节点"}</strong><small>{node ? serverName(node.serverId) : "—"}</small></td>
                          <td className="num">{bytes(total(u))}<small>{split(u)}</small></td>
                        </tr>
                      );
                    })}
                  </tbody></table>
                ) : <Empty text="今天还没有流量" />}
              </section>
              <section className="panel">
                <div className="panelHead">
                  <h2>今日订阅流量排行</h2>
                  <button className="textButton" onClick={() => goTo("subscriptions")}>全部订阅 →</button>
                </div>
                {topSubs.length ? (
                  <table><tbody>
                    {topSubs.map((u, index) => {
                      const sub = subs.find((item) => item.id === u.id);
                      return (
                        <tr key={u.id}>
                          <td className="rank">{index + 1}</td>
                          <td><strong>{sub?.name || (u.id === "direct" ? "节点直连链接" : "已删除的订阅")}</strong><small>{customers.find((c) => c.id === sub?.customerId)?.name || "未关联客户"}</small></td>
                          <td className="num">{bytes(total(u))}<small>{split(u)}</small></td>
                        </tr>
                      );
                    })}
                  </tbody></table>
                ) : <Empty text="今天还没有订阅流量" />}
              </section>
            </div>
            <div className="twoCol">
              <section className="panel">
                <div className="panelHead">
                  <h2>服务器</h2>
                  <button className="textButton" onClick={() => goTo("servers")}>查看全部 →</button>
                </div>
                {servers.length ? (
                  <table>
                    <thead><tr><th>服务器</th><th>状态</th><th>节点</th><th className="num">今日流量</th></tr></thead>
                    <tbody>
                      {servers.slice(0, 8).map((sv) => (
                        <tr key={sv.id}>
                          <td><strong>{sv.name}</strong><small>{sv.country} · {sv.domain || sv.ipv4 || sv.ipv6}</small></td>
                          <td><Status value={sv.status} /></td>
                          <td>{nodes.filter((n) => n.serverId === sv.id && n.enabled && n.status === "active").length} / {nodes.filter((n) => n.serverId === sv.id).length}</td>
                          <td className="num">{bytes(todayByServer(sv.id))}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <Empty text="暂无服务器" />
                )}
              </section>
              <section className="panel">
                <div className="panelHead">
                  <h2>最近任务</h2>
                  <button className="textButton" onClick={() => goTo("operations")}>查看全部 →</button>
                </div>
                {operations.length ? (
                  operations.slice(0, 7).map((o) => (
                    <div className="listRow" key={o.id}>
                      <div className="grow">
                        <strong>{kindLabel(o.kind)}</strong>
                        <small>
                          {serverName(o.serverId)} ·{" "}
                          {new Date(o.createdAt).toLocaleString()}
                        </small>
                      </div>
                      <Status value={o.status} />
                    </div>
                  ))
                ) : (
                  <Empty text="暂无任务记录" />
                )}
              </section>
            </div>
          </>
        )}
        {tab === "servers" && (
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>服务器列表</h2>
                <p>管理服务器档案、Agent 与 UFW 状态</p>
              </div>
              <button className="primary" onClick={() => openServer()}>
                新建服务器
              </button>
            </div>
            <div className="filters serverFilters">
              {([
                ["country", "国家代码"],
                ["provider", "服务商"],
                ["region", "地区"],
                ["city", "城市"],
              ] as const).map(([field, label]) => (
                <select
                  key={field}
                  aria-label={`按${label}筛选服务器`}
                  value={serverFilters[field]}
                  onChange={(e) => setServerFilters({ ...serverFilters, [field]: e.target.value })}
                >
                  <option value="">全部{label}</option>
                  {serverFilterValues(servers, field).map((value) => (
                    <option key={value} value={value}>{value}</option>
                  ))}
                </select>
              ))}
            </div>
            <div className="tableWrap">
              <table>
                <thead>
                  <tr>
                    <th>服务器</th>
                    <th>国家 / 服务商 / 地区</th>
                    <th>公网地址</th>
                    <th>Agent</th>
                    <th>UFW</th>
                    <th>统计</th>
                    <th>网络流量</th>
                    <th>节点</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleServers.map((s) => (
                    <tr key={s.id}>
                      <td>
                        <strong>{s.name}</strong>
                        <small>
                          {s.os || "待接入"} · {s.arch}
                        </small>
                        {serverWarnings(s).map((w) => (
                          <small className="dangerText" key={w}>
                            {w}
                          </small>
                        ))}
                      </td>
                      <td>
                        {s.country}
                        <small>{s.provider || "—"}</small>
                        {(s.region || s.city) && <small>{[s.region, s.city].filter(Boolean).join(" · ")}</small>}
                      </td>
                      <td className="mono">{s.domain || s.ipv4 || s.ipv6}</td>
                      <td>
                        <Status value={s.status} />
                        <small>{s.agentVersion || "未接入"}</small>
                        {s.agentSelfUpdate && agentReleases[s.arch] && <small>{s.agentBuild === agentReleases[s.arch] ? "已是当前构建" : "有可用升级"}</small>}
                        {!s.agentSelfUpdate && !!s.agentVersion && <small>需先人工升级一次</small>}
                        {!!s.agentVersion && <small>{s.releaseKeyPinned ? "升级需发布签名" : "升级未启用签名校验"}</small>}
                        <small>{s.purpose === "relay" ? "仅转发" : "节点服务器"} · sing-box：{s.coreVersion || "未安装"}</small>
                        {s.coreSelfUpdate && coreReleases[s.arch] && <small>{s.coreBuild === coreReleases[s.arch] ? "核心已是当前构建" : "核心有可用升级"}</small>}
                        {!s.coreSelfUpdate && !!s.agentVersion && <small>升级 Agent 后可一键升级核心</small>}
                        {operations.some((o) => o.serverId === s.id && ["agent.upgrade", "core.upgrade"].includes(o.kind) && ["queued", "running", "activating"].includes(o.status)) && <small>程序升级进行中，详情见操作记录</small>}
                      </td>
                      <td>
                        <Status
                          value={s.firewallConflict ? "conflict" : s.ufwStatus}
                        />
                      </td>
                      <td>
                        <Status value={s.statsStatus} />
                      </td>
                      <td>
                        <small>
                          ↓ {bytes(s.networkRx || 0)}
                          <br />↑ {bytes(s.networkTx || 0)}
                        </small>
                      </td>
                      <td>{nodes.filter((n) => n.serverId === s.id).length}</td>
                      <td>
                        <div className="actions">
                          <button onClick={() => openServer(s)}>编辑</button>
                          <ActionMenu>
                          <button
                            disabled={!s.agentSelfUpdate || !agentReleases[s.arch] || s.agentBuild === agentReleases[s.arch] || operations.some((o) => o.serverId === s.id && ["agent.upgrade", "core.upgrade"].includes(o.kind) && ["queued", "running", "activating"].includes(o.status))}
                            title={!s.agentSelfUpdate ? "当前 Agent 不支持自更新；请先手动安装新版一次" : !agentReleases[s.arch] ? "面板缺少该架构的 Agent 构建文件" : "从面板下载并校验新版本，节点服务继续运行"}
                            onClick={() => act(() => mutation("/api/servers/" + s.id + "/agent/upgrade", "POST"), "Agent 升级已排队；重启上报新构建后才会显示成功")}
                          >
                            一键升级 Agent
                          </button>
                          <button
                            disabled={!s.coreSelfUpdate || !coreReleases[s.arch] || s.coreBuild === coreReleases[s.arch] || operations.some((o) => o.serverId === s.id && ["agent.upgrade", "core.upgrade"].includes(o.kind) && ["queued", "running", "activating"].includes(o.status))}
                            title={!s.coreSelfUpdate ? "请先将 Agent 升级到支持 sing-box 自更新的版本" : !coreReleases[s.arch] ? "面板缺少该架构的 sing-box 构建文件" : s.coreBuild ? "先验证新核心和现有配置，再重启核心；该服务器的节点连接会短暂中断，失败会恢复旧核心" : "从面板下载并验证 sing-box，然后安装到该服务器"}
                            onClick={() => {
                              const run = () => { void act(() => mutation("/api/servers/" + s.id + "/core/upgrade", "POST"), s.coreBuild ? "sing-box 升级已排队" : "sing-box 安装已排队"); };
                              if (!s.coreBuild) return run();
                              setConfirmation({
                                title: "升级 sing-box",
                                message: `升级「${s.name}」的 sing-box？\n升级时核心会重启，这台服务器上所有节点的连接将中断数秒。新核心无法启动时会自动恢复旧版本。`,
                                confirmLabel: "升级",
                                onConfirm: run,
                              });
                            }}
                          >
                            {s.coreBuild ? "一键升级 sing-box" : s.purpose === "relay" ? "转为节点机并安装 sing-box" : "安装 sing-box"}
                          </button>
                          <button
                            onClick={() =>
                              act(async () => {
                                const v = await mutation<{
                                  installCommand: string;
                                }>(
                                  "/api/servers/" + s.id + "/enrollment",
                                  "POST",
                                );
                                setInstallInfo({ command: v.installCommand, serverName: s.name });
                              }, "首次接入 / 手动修复命令已生成")
                            }
                          >
                            首次接入 / 手动修复
                          </button>
                          <button
                            disabled={s.ufwStatus === "active" || s.status !== "online"}
                            title={s.ufwStatus === "active" ? "UFW 已启用" : s.status !== "online" ? "服务器不在线" : ""}
                            onClick={() =>
                              setConfirmation({
                                title: "初始化 UFW",
                                message: `在「${s.name}」上启用 UFW？\n启用后默认拒绝 SSH 以外的所有入站连接：这台机器上的其他对外服务会立刻无法访问，直到为它们添加允许规则。\nSSH 端口会先被放行；如果 2 分钟内 Agent 无法向面板确认，UFW 会自动关闭。`,
                                confirmLabel: "启用 UFW",
                                onConfirm: () => {
                                  void act(() => mutation("/api/servers/" + s.id + "/ufw/init", "POST"), "UFW 初始化已排队");
                                },
                              })
                            }
                          >
                            初始化 UFW
                          </button>
                          <button
                            onClick={() => {
                              setConfirmation({
                                title: "吊销 Agent 凭据",
                                message: `吊销「${s.name}」的 Agent 凭据？该 Agent 将立即无法连接面板，需重新生成接入命令。`,
                                confirmLabel: "吊销凭据",
                                onConfirm: () => {
                                  void act(
                                    () =>
                                      mutation(
                                        "/api/servers/" + s.id + "/revoke",
                                        "POST",
                                      ),
                                    "Agent 凭据已吊销",
                                  );
                                },
                              });
                            }}
                          >
                            吊销 Agent
                          </button>
                          <button
                            className="dangerText"
                            onClick={() => deleteServer(s)}
                          >
                            删除
                          </button>
                          </ActionMenu>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!visibleServers.length && <Empty text={servers.length ? "没有符合筛选条件的服务器" : "还没有服务器，点击右上角添加"} />}
            </div>
          </section>
        )}
        {tab === "nodes" && (
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>节点列表</h2>
                <p>SS、Snell 与 AnyTLS 节点配置及流量</p>
              </div>
              <button className="primary" onClick={() => openNode()}>
                新建节点
              </button>
            </div>
            <div className="filters">
              <select
                value={nodeServerFilter}
                onChange={(e) => setNodeServerFilter(e.target.value)}
              >
                <option value="">全部服务器</option>
                {servers.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
              <select
                value={nodeProtocolFilter}
                onChange={(e) => setNodeProtocolFilter(e.target.value)}
              >
                <option value="">全部协议</option>
                <option value="ss">SS</option>
                <option value="snell">Snell</option>
                <option value="anytls">AnyTLS</option>
              </select>
            </div>
            <div className="tableWrap">
              <table>
                <thead>
                  <tr>
                    <th>节点</th>
                    <th>服务器</th>
                    <th>协议 / 端口</th>
                    <th>上行</th>
                    <th>下行</th>
                    <th>状态</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleNodes.map((n) => (
                    <tr key={n.id}>
                      <td>
                        <strong>{n.name}</strong>
                        <small className="mono">{n.id.slice(0, 8)}</small>
                      </td>
                      <td>{serverName(n.serverId)}</td>
                      <td>
                        <span className="chip">{n.protocol.toUpperCase()}</span>{" "}
                        <span className="mono">:{n.port}</span>
                        {n.protocol === "snell" && n.shadowTlsHost && <small>ShadowTLS v3 · {n.shadowTlsHost}</small>}
                        {n.protocol === "snell" && !n.shadowTlsHost && <small className="dangerText">旧节点未启用 ShadowTLS，请编辑节点升级</small>}
                      </td>
                      <td>{bytes(n.uplink)}</td>
                      <td>{bytes(n.downlink)}</td>
                      <td>
                        <Status value={n.deleting ? "deleting" : n.status} />
                        {n.error && (
                          <small className="dangerText">{n.error}</small>
                        )}
                      </td>
                      <td>
                        <div className="actions">
                          <button onClick={() => setTrafficNode(n)}>
                            流量
                          </button>
                          <button onClick={() => openNode(n)} disabled={!!n.deleting} title={n.deleting ? "节点正在删除" : ""}>编辑</button>
                          <ActionMenu>
                          <button onClick={() => openTemplate(n)}>存为模板</button>
                          {n.protocol === "snell" ? (
                            <button onClick={() => setTab("subscriptions")}>
                              通过订阅获取
                            </button>
                          ) : (
                            <button
                              onClick={() =>
                                act(async () => {
                                  const v = await api<{ uri: string }>(
                                    "/api/nodes/" + n.id + "/share",
                                  );
                                  await copy(v.uri);
                                }, "已复制节点链接")
                              }
                            >
                              复制链接
                            </button>
                          )}
                          <button
                            className="dangerText"
                            onClick={() =>
                              deleteItem("/api/nodes/" + n.id, "节点")
                            }
                          >
                            删除
                          </button>
                          </ActionMenu>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!visibleNodes.length && <Empty text="暂无符合条件的节点" />}
            </div>
          </section>
        )}
        {tab === "templates" && (
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>节点模板</h2>
                <p>保存常用配置，新建节点时选择模板即可带入</p>
              </div>
              <button className="primary" onClick={() => openTemplate()}>
                新建模板
              </button>
            </div>
            <div className="tableWrap">
              <table>
                <thead>
                  <tr>
                    <th>模板名称</th>
                    <th>协议</th>
                    <th>端口</th>
                    <th>主要设置</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {templates.map((t) => (
                    <tr key={t.id}>
                      <td><strong>{t.name}</strong></td>
                      <td><span className="chip">{t.protocol.toUpperCase()}</span></td>
                      <td className="mono">{t.port}</td>
                      <td className="mono">
                        {t.protocol === "ss" ? t.method : t.protocol === "snell" ? `ShadowTLS v3 · ${t.shadowTlsHost || "未配置"}` : t.tlsName}
                      </td>
                      <td>
                        <div className="actions">
                          <button onClick={() => void useTemplate(t, servers[0]?.id || "")} disabled={!servers.length || templateLoading}>使用模板</button>
                          <button onClick={() => openTemplate(t)}>编辑</button>
                          <button className="dangerText" onClick={() => deleteItem("/api/node-templates/" + t.id, "节点模板")}>删除</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!templates.length && <Empty text="还没有模板，可以新建模板或从现有节点保存" />}
            </div>
          </section>
        )}
        {tab === "certificates" && (
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>TLS 证书</h2>
                <p>用于 AnyTLS 节点，私钥加密保存</p>
              </div>
              <button
                className="primary"
                onClick={() => {
                  setCertForm({
                    serverId: servers[0]?.id || "",
                    name: "",
                    domain: "",
                    pem: "",
                    key: "",
                  });
                  setModal("certificate");
                }}
              >
                上传证书
              </button>
            </div>
            <div className="tableWrap">
              <table>
                <thead>
                  <tr>
                    <th>名称</th>
                    <th>服务器</th>
                    <th>域名</th>
                    <th>到期时间</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {certificates.map((c) => (
                    <tr key={c.id}>
                      <td>
                        <strong>{c.name || c.domain}</strong>
                      </td>
                      <td>{serverName(c.serverId)}</td>
                      <td className="mono">{c.domain}</td>
                      <td>{new Date(c.expiresAt).toLocaleDateString()}{c.expiringSoon && <span className="status bad">{c.daysUntilExpiry !== undefined && c.daysUntilExpiry < 0 ? "已过期" : c.daysUntilExpiry !== undefined ? `${c.daysUntilExpiry} 天后到期` : "即将到期"}</span>}</td>
                      <td>
                        <button
                          className="dangerText"
                          onClick={() =>
                            deleteItem("/api/certificates/" + c.id, "证书")
                          }
                        >
                          删除
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!certificates.length && <Empty text="暂无证书" />}
            </div>
          </section>
        )}
        {tab === "firewall" && (
          <>
            <div className="filters">
              <select
                value={fwServer?.id || ""}
                onChange={(e) => setFirewallServer(e.target.value)}
              >
                {servers.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
              {fwServer && (
                <Status
                  value={
                    fwServer.firewallConflict ? "conflict" : fwServer.ufwStatus
                  }
                />
              )}
            </div>
            {fwServer?.firewallConflict && (
              <div className="banner warning">
                {fwServer.firewallConflict}{" "}
                正在管理这台服务器的防火墙。为避免两套规则互相覆盖，面板不会写入
                UFW；请先停用它。
              </div>
            )}
            <section className="panel">
              <div className="panelHead">
                <div>
                  <h2>自定义规则</h2>
                  <p>拒绝规则排在允许规则之前；不能拒绝 SSH 端口</p>
                </div>
                <button
                  className="primary"
                  disabled={!fwServer}
                  onClick={() => {
                    setRuleForm({ ...emptyRule, serverId: fwServer?.id || "" });
                    setModal("rule");
                  }}
                >
                  新建规则
                </button>
              </div>
              <div className="tableWrap">
                <table>
                  <thead>
                    <tr>
                      <th>端口</th>
                      <th>协议</th>
                      <th>来源</th>
                      <th>动作</th>
                      <th>备注</th>
                      <th>状态</th>
                      <th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fwRules.map((r) => (
                      <tr key={r.id}>
                        <td className="mono">
                          {r.portFrom}
                          {r.portTo > r.portFrom ? `-${r.portTo}` : ""}
                        </td>
                        <td>{r.network.toUpperCase()}</td>
                        <td className="mono">{r.source || "任意"}</td>
                        <td>
                          <span
                            className={
                              "chip " + (r.action === "deny" ? "red" : "")
                            }
                          >
                            {r.action === "deny" ? "拒绝" : "允许"}
                          </span>
                        </td>
                        <td>{r.comment}</td>
                        <td>
                          <Status value={r.deleting ? "deleting" : r.status} />
                        </td>
                        <td>
                          <button
                            className="dangerText"
                            onClick={() =>
                              deleteItem("/api/firewall/" + r.id, "规则")
                            }
                          >
                            删除
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!fwRules.length && <Empty text="暂无自定义规则" />}
              </div>
            </section>
            <section className="panel">
              <div className="panelHead">
                <div>
                  <h2>节点自动规则</h2>
                  <p>按节点设置放行来源；手动管理的节点不创建自动规则</p>
                </div>
              </div>
              <div className="tableWrap">
                <table>
                  <thead>
                    <tr>
                      <th>节点</th>
                      <th>端口</th>
                      <th>协议</th>
                      <th>放行来源</th>
                      <th>状态</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fwNodes.map((n) => (
                      <tr key={n.id}>
                        <td>{n.name}</td>
                        <td className="mono">{n.port}</td>
                        <td>{n.protocol === "ss" ? "TCP + UDP" : "TCP"}</td>
                        <td className="mono">{n.firewallPolicy === "manual" ? "手动管理" : n.firewallPolicy === "restricted" ? n.firewallSources.split(",").join("、") : "任意来源"}</td>
                        <td>
                          <Status value={n.status} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!fwNodes.length && <Empty text="该服务器没有启用的节点" />}
              </div>
            </section>
            <section className="panel">
              <div className="panelHead">
                <div>
                  <h2>主机现有规则</h2>
                  <p>
                    Agent 读取的 <span className="mono">ufw status</span>
                    ，只读；面板只改动带 mui- 标记的规则
                    {fwServer?.sshPorts?.length
                      ? `；SSH 端口 ${fwServer.sshPorts.join("、")}`
                      : ""}
                  </p>
                </div>
              </div>
              {fwServer?.ufwRules?.length ? (
                <pre className="mono">{fwServer.ufwRules.join("\n")}</pre>
              ) : (
                <Empty text="Agent 尚未上报规则，或 UFW 未启用" />
              )}
            </section>
            <section className="panel">
              <div className="panelHead">
                <div>
                  <h2>变更历史</h2>
                  <p>最近的防火墙任务；节点变更引起的规则调整见操作记录</p>
                </div>
              </div>
              {fwHistory.length ? (
                fwHistory.map((o) => (
                  <div className="listRow" key={o.id}>
                    <div className="grow">
                      <strong>{kindLabel(o.kind)}</strong>
                      <small>
                        {new Date(o.createdAt).toLocaleString()}
                        {o.error ? " · " + o.error : ""}
                      </small>
                    </div>
                    <Status value={o.status} />
                  </div>
                ))
              ) : (
                <Empty text="暂无防火墙变更" />
              )}
            </section>
          </>
        )}
        {tab === "forwards" && (
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>端口转发</h2>
                <p>在所选服务器监听 TCP 或 UDP，并转发到目标地址；TCP 使用服务器新建的连接。</p>
              </div>
              <button className="primary" onClick={() => { setForwardForm({ ...emptyForward, serverId: servers[0]?.id || "" }); setModal("forward"); }} disabled={!servers.length}>新建转发</button>
            </div>
            {servers.some((s) => s.ufwStatus && s.ufwStatus !== "active") && (
              <div className="banner error">有服务器的 UFW 未启用，转发规则无法应用；请先在服务器列表执行“初始化 UFW”。</div>
            )}
            {servers.some((s) => !!s.firewallConflict) && (
              <div className="banner error">检测到其他防火墙工具正在管理防火墙，面板已停止写入 UFW；请先停用它。</div>
            )}
            <div className="tableWrap">
              <table>
                <thead><tr><th>名称</th><th>服务器</th><th>监听</th><th>目标</th><th>已转发</th><th>放行来源</th><th>状态</th><th>操作</th></tr></thead>
                <tbody>
                  {forwards.map((f) => (
                    <tr key={f.id}>
                      <td><strong>{f.name}</strong></td>
                      <td>{serverName(f.serverId)}</td>
                      <td className="mono">{f.network.toUpperCase()} {f.listen || "0.0.0.0"}:{f.port}</td>
                      <td className="mono">{f.targetHost}:{f.targetPort}</td>
                      <td>↑ {bytes(f.uplink || 0)} · ↓ {bytes(f.downlink || 0)}</td>
                      <td className="mono">{f.firewallPolicy === "manual" ? "手动管理" : f.firewallPolicy === "restricted" ? f.firewallSources.split(",").join("、") : "任意来源"}</td>
                      <td><Status value={f.deleting ? "deleting" : f.status} />{f.error && <small className="hint">{f.error}</small>}{!servers.find((s) => s.id === f.serverId)?.forwardSupport && <small className="hint">等待 Agent 更新</small>}</td>
                      <td><div className="actions">
                        <button disabled={f.deleting} onClick={() => { setForwardForm({ ...f }); setModal("forward"); }}>编辑</button>
                        <button disabled={f.deleting} onClick={() => void act(() => mutation("/api/forwards/" + f.id, "PATCH", { ...f, enabled: !f.enabled }), f.enabled ? "转发已停用" : "转发已启用")}>{f.enabled ? "停用" : "启用"}</button>
                        <button className="dangerText" onClick={() => deleteItem("/api/forwards/" + f.id, "转发")}>删除</button>
                      </div></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!forwards.length && <Empty text="暂无转发规则" />}
            </div>
          </section>
        )}
        {tab === "subscriptions" && (
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>订阅管理</h2>
                <p>每条订阅使用独立节点凭据并单独计量；令牌可随时轮换</p>
              </div>
              <button
                className="primary"
                onClick={() => {
                  setSubForm({
                    name: "",
                    format: "sing-box",
                    nodeIds: [],
                    enabled: true,
                  });
                  setIssuedURL("");
                  setModal("subscription");
                }}
              >
                新建订阅
              </button>
            </div>
            <div className="filters">
              <input type="search" value={subQuery} onChange={(e) => setSubQuery(e.target.value)} placeholder="搜索订阅名称或客户" aria-label="搜索订阅" />
              {subQuery && <span className="hint">{visibleSubs.length} / {subs.length}</span>}
            </div>
            <div className="tableWrap">
              <table>
                <thead>
                  <tr>
                    <th>名称</th>
                    <th>客户</th>
                    <th>格式</th>
                    <th>节点数</th>
                    <th>已用流量</th>
                    <th>状态</th>
                    <th>到期</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleSubs.map((s) => (
                    <tr key={s.id}>
                      <td>
                        <strong>{s.name}</strong>
                      </td>
                      <td>{customers.find((c) => c.id === s.customerId)?.name || "未关联"}</td>
                      <td>
                        <span className="chip">{s.format}</span>
                      </td>
                      <td>{s.nodeIds?.length || 0}</td>
                      <td>
                        <button className="textButton" onClick={() => { setSubTraffic([]); setTrafficSub(s); }}>
                          {bytes((s.uplink || 0) + (s.downlink || 0))}
                        </button>
                      </td>
                      <td>
                        <Status value={!s.enabled ? "disabled" : s.expiresAt && new Date(s.expiresAt).getTime() <= Date.now() ? "expired" : pendingNodes(s).length ? "partial" : "active"} />
                        {s.enabled && pendingNodes(s).length > 0 && <small className="hint">尚未生效，暂不下发：{pendingSummary(s)}。其余节点正常提供。</small>}
                      </td>
                      <td>
                        {s.expiresAt
                          ? new Date(s.expiresAt).toLocaleDateString()
                          : "不过期"}
                      </td>
                      <td>
                        <div className="actions">
                          <button
                            onClick={() =>
                              act(async () => {
                                setPreview(
                                  await api(
                                    "/api/subscriptions/" + s.id + "/preview",
                                  ),
                                );
                              }, "预览已生成")
                            }
                          >
                            预览
                          </button>
                          <button
                            onClick={() => {
                              setSubForm({ ...s });
                              setIssuedURL("");
                              setModal("subscription");
                            }}
                          >
                            编辑
                          </button>
                          <button
                            onClick={() =>
                              act(async () => {
                                const result = await api<{ url: string }>("/api/subscriptions/" + s.id + "/link");
                                setIssuedURL(result.url);
                              }, "订阅链接已显示在下方")
                            }
                          >
                            查看链接
                          </button>
                          <ActionMenu>
                          <button
                            onClick={() =>
                              setConfirmation({
                                title: s.enabled ? "停用订阅" : "启用订阅",
                                message: (s.enabled
                                  ? `停用「${s.name}」？该订阅的链接和已导入的节点会立即失效。`
                                  : `启用「${s.name}」？`) + restartNotice(s.nodeIds || []),
                                confirmLabel: s.enabled ? "停用" : "启用",
                                onConfirm: () => {
                                  void act(
                                    () => mutation("/api/subscriptions/" + s.id, "PATCH", { ...s, enabled: !s.enabled }),
                                    s.enabled ? "已停用" : "已启用",
                                  );
                                },
                              })
                            }
                          >
                            {s.enabled ? "停用" : "启用"}
                          </button>
                          <button
                            onClick={() =>
                              setConfirmation({
                                title: "轮换订阅链接",
                                message: `为「${s.name}」生成新链接？旧链接立即失效，客户需要用新链接重新导入。已导入的节点不受影响。`,
                                confirmLabel: "轮换",
                                onConfirm: () => {
                                  void act(async () => {
                                    const result = await mutation<{ url: string }>("/api/subscriptions/" + s.id + "/rotate", "POST");
                                    setIssuedURL(result.url);
                                  }, "订阅链接已轮换");
                                },
                              })
                            }
                          >
                            轮换链接
                          </button>
                          <button
                            className="dangerText"
                            onClick={() =>
                              setConfirmation({
                                title: "删除订阅",
                                message: `确定删除「${s.name}」？链接和已导入的节点会立即失效，此操作无法撤销。` + restartNotice(s.nodeIds || []),
                                confirmLabel: "删除",
                                onConfirm: () => { void act(() => mutation("/api/subscriptions/" + s.id, "DELETE"), "订阅已删除"); },
                              })
                            }
                          >
                            删除
                          </button>
                          </ActionMenu>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!visibleSubs.length && <Empty text={subQuery ? "没有匹配的订阅" : "暂无订阅"} />}
            </div>
            {preview && (
              <div className="commandBox">
                <div>
                  <strong>订阅预览</strong>
                  <span>
                    {preview.excluded.length
                      ? preview.excluded.join("；")
                      : "所有所选节点均已输出"}
                  </span>
                </div>
                <MaskedValue value={preview.content} pre />
              </div>
            )}
            {issuedURL && (
              <div className="commandBox">
                <div>
                  <strong>订阅链接</strong>
                  <span>可随时在订阅列表中再次查看</span>
                </div>
                <MaskedValue value={issuedURL}><button type="button" onClick={() => copy(issuedURL)}>复制</button></MaskedValue>
              </div>
            )}
          </section>
        )}
        {tab === "customers" && (
            <section className="panel">
              <div className="panelHead">
                <div><h2>客户端管理</h2><p>创建客户后，在订阅中关联客户；原有订阅可在订阅管理中编辑。</p></div>
                <button className="primary" onClick={() => { setCustomerForm({ name: "", notes: "" }); setModal("customer"); }}>新建客户</button>
              </div>
              <div className="filters">
                <input type="search" value={customerQuery} onChange={(e) => setCustomerQuery(e.target.value)} placeholder="搜索客户名称或备注" aria-label="搜索客户" />
                {customerQuery && <span className="hint">{visibleCustomers.length} / {customers.length}</span>}
              </div>
              <div className="tableWrap"><table><thead><tr><th>客户</th><th>备注</th><th>关联订阅</th><th>已用流量</th><th>操作</th></tr></thead><tbody>
                {visibleCustomers.map((c) => <tr key={c.id}>
                  <td><strong>{c.name}</strong></td><td>{c.notes || "—"}</td>
                  <td>{subs.filter((s) => s.customerId === c.id).map((s) => s.name).join("、") || "—"}</td>
                  <td>{bytes(subs.filter((s) => s.customerId === c.id).reduce((sum, s) => sum + (s.uplink || 0) + (s.downlink || 0), 0))}</td>
                  <td><div className="actions"><button onClick={() => { setCustomerForm({ ...c }); setModal("customer"); }}>编辑</button><button className="dangerText" onClick={() => deleteItem("/api/customers/" + c.id, "客户")}>删除</button></div></td>
                </tr>)}
              </tbody></table>{!visibleCustomers.length && <Empty text={customerQuery ? "没有匹配的客户" : "暂无客户，点击右上角新建"} />}</div>
            </section>
        )}
        {tab === "accesses" && (
            <section className="panel">
              <div className="panelHead"><div><h2>订阅访问记录</h2><p>成功下载订阅时记录来源 IP、客户与订阅。按数据保留设置清理。</p></div></div>
              <div className="filters">
                <select value={accessCustomer} onChange={(e) => setAccessCustomer(e.target.value)} aria-label="按客户筛选访问记录">
                  <option value="">全部客户</option>
                  {customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
              </div>
              <div className="tableWrap"><table><thead><tr><th>时间</th><th>客户</th><th>订阅</th><th>来源 IP</th></tr></thead><tbody>
                {accessLog.items.map((item) => <tr key={item.id}>
                  <td>{new Date(item.at).toLocaleString()}</td>
                  <td>{customers.find((c) => c.id === item.customerId)?.name || "未关联 / 已删除"}</td>
                  <td>{subs.find((s) => s.id === item.subscriptionId)?.name || "已删除"}</td>
                  <td><code>{item.ip}</code></td>
                </tr>)}
              </tbody></table>{accessLog.empty && <Empty text="暂无订阅访问记录" />}</div>
              <LoadMore log={accessLog} />
            </section>
        )}
        {tab === "connections" && (
            <section className="panel">
              <div className="panelHead"><div><h2>节点连接 IP</h2><p>Agent 从 sing-box 实时连接中采样，按首次发现顺序列出 IP，并显示最近连接时间。短连接可能未采到，经 ShadowTLS 接入的 Snell 节点目前采不到连接；订阅归属和流量请查看订阅统计。</p></div></div>
              <div className="filters">
                <select value={connectionServer} onChange={(e) => setConnectionServer(e.target.value)} aria-label="按服务器筛选连接 IP">
                  <option value="">全部服务器</option>
                  {servers.map((sv) => <option key={sv.id} value={sv.id}>{sv.name}</option>)}
                </select>
              </div>
              <div className="tableWrap"><table><thead><tr><th>最近连接</th><th>服务器</th><th>节点</th><th>来源 IP</th><th>订阅关联</th></tr></thead><tbody>
                {connectionLog.items.map((item) => {
                  const linked = subs.filter((s) => (s.nodeIds || []).includes(item.nodeId));
                  return <tr key={item.serverId + item.nodeId + item.ip}>
                    <td>{new Date(item.lastSeen).toLocaleString()}</td>
                    <td>{serverName(item.serverId)}</td>
                    <td>{nodes.find((n) => n.id === item.nodeId)?.name || "已删除"}</td>
                    <td><code>{item.ip}</code></td>
                    <td>{linked.length ? `可能关联：${linked.map((s) => s.name).join("、")}` : "无法归属"}</td>
                  </tr>;
                })}
              </tbody></table>{connectionLog.empty && <Empty text="暂无节点连接 IP；需更新 Agent 并等待实际连接" />}</div>
              <LoadMore log={connectionLog} />
            </section>
        )}
        {tab === "operations" && (
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>操作记录</h2>
                <p>查看配置下发、执行结果和失败原因</p>
              </div>
              <button className="ghost" onClick={refresh}>
                刷新
              </button>
            </div>
            <div className="filters">
              <select value={opServer} onChange={(e) => setOpServer(e.target.value)} aria-label="按服务器筛选操作记录">
                <option value="">全部服务器</option>
                {servers.map((sv) => <option key={sv.id} value={sv.id}>{sv.name}</option>)}
              </select>
            </div>
            <div className="tableWrap">
              <table>
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>服务器</th>
                    <th>操作</th>
                    <th>状态</th>
                    <th>错误</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {opLog.items.map((o) => (
                    <tr key={o.id}>
                      <td>{new Date(o.createdAt).toLocaleString()}</td>
                      <td>{serverName(o.serverId)}</td>
                      <td>{kindLabel(o.kind)}</td>
                      <td>
                        <Status value={o.status} />
                      </td>
                      <td className="errorCell">{o.error || "—"}</td>
                      <td>
                        {o.status === "failed" && (
                          <button
                            onClick={() =>
                              act(
                                () =>
                                  mutation(
                                    "/api/operations/" + o.id + "/retry",
                                    "POST",
                                  ),
                                "已重新排队",
                              )
                            }
                          >
                            重试
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {opLog.empty && <Empty text={opServer ? "该服务器暂无操作记录" : "暂无操作记录"} />}
            </div>
            <LoadMore log={opLog} />
          </section>
        )}
        {tab === "audit" && (
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>审计日志</h2>
                <p>管理员在面板上做过的改动</p>
              </div>
            </div>
            <form className="filters" onSubmit={(e) => { e.preventDefault(); setAuditQuery(auditInput.trim()); }}>
              <input value={auditInput} onChange={(e) => setAuditInput(e.target.value)} placeholder="搜索动作或说明，如 node.delete" aria-label="搜索审计日志" />
              <button className="ghost">搜索</button>
              {auditQuery && <button type="button" className="textButton" onClick={() => { setAuditInput(""); setAuditQuery(""); }}>清除</button>}
            </form>
            <div className="tableWrap">
              <table>
                <thead>
                  <tr><th>时间</th><th>动作</th><th>对象</th><th>说明</th></tr>
                </thead>
                <tbody>
                  {auditLog.items.map((entry) => (
                    <tr key={entry.id}>
                      <td>{new Date(entry.at).toLocaleString()}</td>
                      <td className="mono">{entry.action}</td>
                      <td>{auditTarget(entry.target)}</td>
                      <td>{entry.detail || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {auditLog.empty && <Empty text={auditQuery ? "没有匹配的审计记录" : "暂无审计记录"} />}
            </div>
            <LoadMore log={auditLog} />
          </section>
        )}
        {tab === "settings" && (
          <section className="panel settings">
            <h2>账户安全</h2>
            <p>建议启用动态验证码以保护管理面板。</p>
            {expiring.length > 0 && (
              <div className="banner warning" role="status">
                {expiring.length} 张 TLS 证书已过期或将在 30 天内到期（{expiring.map((c) => c.domain).join("、")}），请尽快更新证书。
              </div>
            )}
            <div className="settingRow">
              <div>
                <strong>TOTP 双因素认证</strong>
                <small>{totpEnabled ? "已启用" : "未启用"}</small>
              </div>
              {!totpEnabled && (
                <button
                  className="ghost"
                  onClick={() =>
                    act(async () => {
                      const v = await mutation<{ secret: string; uri: string }>(
                        "/api/totp/setup",
                        "POST",
                      );
                      setTotpSetup(v);
                    }, "请在验证器中添加密钥")
                  }
                >
                  设置
                </button>
              )}
            </div>
            {totpSetup && (
              <div className="totpBox">
                <p>用验证器应用扫描二维码，或手动添加下面的密钥：</p>
                <Suspense fallback={<div className="hint">正在加载二维码…</div>}><QRCode text={totpSetup.uri} /></Suspense>
                <MaskedValue value={totpSetup.secret}><button type="button" onClick={() => copy(totpSetup.secret)}>复制密钥</button></MaskedValue>
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    act(async () => {
                      await mutation("/api/totp/enable", "POST", { code });
                      setTotpEnabled(true);
                      setTotpSetup(null);
                    }, "双因素认证已启用");
                  }}
                >
                  <input
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    placeholder="输入 6 位验证码"
                    maxLength={6}
                  />
                  <button className="primary">启用</button>
                </form>
              </div>
            )}
            {totpEnabled && (
              <form
                className="totpBox"
                onSubmit={async (e) => {
                  e.preventDefault();
                  if (
                    await act(
                      () => mutation("/api/totp/disable", "POST", totpOff),
                      "双因素认证已关闭",
                    )
                  ) {
                    setTotpEnabled(false);
                    setTotpOff({ password: "", code: "" });
                  }
                }}
              >
                <p>关闭双因素认证需要当前密码和一个有效验证码：</p>
                <input
                  type="password"
                  required
                  autoComplete="current-password"
                  placeholder="当前密码"
                  value={totpOff.password}
                  onChange={(e) =>
                    setTotpOff({ ...totpOff, password: e.target.value })
                  }
                />
                <input
                  required
                  inputMode="numeric"
                  maxLength={6}
                  placeholder="6 位验证码"
                  value={totpOff.code}
                  onChange={(e) =>
                    setTotpOff({ ...totpOff, code: e.target.value })
                  }
                />
                <button className="ghost">关闭双因素认证</button>
              </form>
            )}
            <div className="settingRow">
              <div>
                <strong>管理员密码</strong>
                <small>修改后其他已登录的会话会失效</small>
              </div>
            </div>
            <form
              className="totpBox"
              onSubmit={async (e) => {
                e.preventDefault();
                if (
                  await act(
                    () =>
                      mutation("/api/password", "POST", {
                        current: passwordForm.current,
                        new: passwordForm.next,
                      }),
                    "密码已修改",
                  )
                )
                  setPasswordForm({ current: "", next: "" });
              }}
            >
              <input
                type="password"
                required
                autoComplete="current-password"
                placeholder="当前密码"
                value={passwordForm.current}
                onChange={(e) =>
                  setPasswordForm({ ...passwordForm, current: e.target.value })
                }
              />
              <input
                type="password"
                required
                minLength={12}
                maxLength={72}
                autoComplete="new-password"
                placeholder="新密码（至少 12 个字符）"
                value={passwordForm.next}
                onChange={(e) =>
                  setPasswordForm({ ...passwordForm, next: e.target.value })
                }
              />
              <button className="primary">修改密码</button>
            </form>
            <p className="hint">
              忘记密码或丢失验证器：按 README“忘记密码”一节的一次性命令重置（不要把 MUI_ADMIN_RESET 写进 .env 或 compose 文件）。
            </p>
          </section>
        )}
      </main>
      {installInfo && (
        <div
          className="overlay"
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) setInstallInfo(null);
          }}
          onKeyDown={(e) => {
            if (e.key === "Escape") setInstallInfo(null);
          }}
        >
          <div className="modal installModal" role="dialog" aria-modal="true" aria-labelledby="install-modal-title">
            <div className="modalHead">
              <h2 id="install-modal-title">首次接入 / 手动修复</h2>
              <button className="closeButton" aria-label="关闭" onClick={() => setInstallInfo(null)}>×</button>
            </div>
            <div className="commandBox">
              <strong>在「{installInfo.serverName}」服务器上运行以下命令</strong>
              <p className="hint">命令 10 分钟内有效。运行后会从面板下载并校验文件、接入 Agent；修复时 Agent 会重启，运行中的 sing-box 也可能重启。</p>
              <MaskedValue value={installInfo.command} pre><button className="primary" autoFocus type="button" onClick={() => copy(installInfo.command)}>复制命令</button></MaskedValue>
            </div>
          </div>
        </div>
      )}
      {modal && (
        <div
          className="overlay"
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) close();
          }}
        >
          <div className="modal">
            <div className="modalHead">
              <div>
                <h2>
                  {modal === "server"
                    ? serverForm.id
                      ? "编辑服务器"
                      : "新建服务器"
                    : modal === "node"
                      ? nodeForm.id
                        ? "编辑节点"
                        : "新建节点"
                      : modal === "template"
                        ? templateForm.id
                          ? "编辑节点模板"
                          : "新建节点模板"
                      : modal === "certificate"
                        ? "上传证书"
                        : modal === "customer"
                          ? customerForm.id ? "编辑客户" : "新建客户"
                        : modal === "rule"
                          ? "新建 UFW 规则"
                          : modal === "forward"
                            ? forwardForm.id ? "编辑端口转发" : "新建端口转发"
                          : subForm.id
                            ? "编辑订阅"
                            : "新建订阅"}
                </h2>
              </div>
              <button className="closeButton" aria-label="关闭" onClick={close}>
                ×
              </button>
            </div>
            {modal === "server" && (
              <form onSubmit={submitServer}>
                <div className="formGrid">
                  <Field label="服务器名 *">
                    <input
                      required
                      value={serverForm.name || ""}
                      onChange={(e) =>
                        setServerForm({ ...serverForm, name: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="用途">
                    <select value={serverForm.purpose || "node"} disabled={!!serverForm.id && !!serverForm.agentVersion} onChange={(e) => setServerForm({ ...serverForm, purpose: e.target.value as Server["purpose"] })}>
                      <option value="node">节点服务器（安装 sing-box）</option>
                      <option value="relay">仅转发服务器（只安装 Agent）</option>
                    </select>
                  </Field>
                  <Field label="国家代码 *">
                    <input
                      required
                      maxLength={2}
                      value={serverForm.country || ""}
                      onChange={(e) =>
                        setServerForm({
                          ...serverForm,
                          country: e.target.value.toUpperCase(),
                        })
                      }
                    />
                  </Field>
                  <Field label="公网 IPv4">
                    <input
                      value={serverForm.ipv4 || ""}
                      onChange={(e) =>
                        setServerForm({ ...serverForm, ipv4: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="公网 IPv6">
                    <input
                      value={serverForm.ipv6 || ""}
                      onChange={(e) =>
                        setServerForm({ ...serverForm, ipv6: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="订阅用域名">
                    <input
                      value={serverForm.domain || ""}
                      onChange={(e) =>
                        setServerForm({ ...serverForm, domain: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="服务商">
                    <input
                      value={serverForm.provider || ""}
                      onChange={(e) =>
                        setServerForm({
                          ...serverForm,
                          provider: e.target.value,
                        })
                      }
                    />
                  </Field>
                  <Field label="地区">
                    <input
                      value={serverForm.region || ""}
                      onChange={(e) =>
                        setServerForm({ ...serverForm, region: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="城市">
                    <input
                      value={serverForm.city || ""}
                      onChange={(e) =>
                        setServerForm({ ...serverForm, city: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="标签">
                    <input
                      value={serverForm.tags || ""}
                      onChange={(e) =>
                        setServerForm({ ...serverForm, tags: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="备注">
                    <input
                      value={serverForm.notes || ""}
                      onChange={(e) =>
                        setServerForm({ ...serverForm, notes: e.target.value })
                      }
                    />
                  </Field>
                </div>
                <p className="hint">至少填写一个公网 IP 或订阅用域名。仅转发服务器不会下载 sing-box；以后可在服务器列表一键安装并转为节点服务器。</p>
                <button className="primary submit">保存服务器</button>
              </form>
            )}
            {modal === "node" && (
              <form onSubmit={submitNode}>
                <div className="formGrid">
                  <Field label="服务器 *">
                    <select
                      required
                      value={nodeForm.serverId || ""}
                      disabled={!!nodeForm.id}
                      onChange={(e) => setNodeForm({
                        ...nodeForm,
                        serverId: e.target.value,
                        certificateId: nodeForm.protocol === "anytls"
                          ? matchingCertificate(e.target.value, nodeForm.tlsName || "")
                          : "",
                      })}
                    >
                      <option value="">选择服务器</option>
                      {servers.map((s) => (
                        <option key={s.id} value={s.id}>
                          {s.name}
                        </option>
                      ))}
                    </select>
                  </Field>
                  {!nodeForm.id && (
                    <Field label="节点模板">
                      <select
                        value={selectedTemplate}
                        disabled={templateLoading}
                        onChange={(e) => {
                          const template = templates.find((t) => t.id === e.target.value);
                          if (template) void useTemplate(template, nodeForm.serverId);
                          else clearSelectedTemplate();
                        }}
                      >
                        <option value="">手动填写</option>
                        {templates.map((t) => (
                          <option key={t.id} value={t.id}>
                            {t.name} · {t.protocol.toUpperCase()} :{t.port}
                          </option>
                        ))}
                      </select>
                    </Field>
                  )}
                  <Field label="节点名 *">
                    <input
                      required
                      value={nodeForm.name || ""}
                      onChange={(e) =>
                        setNodeForm({ ...nodeForm, name: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="协议">
                    <select
                      value={nodeForm.protocol}
                      onChange={(e) => {
                        clearSelectedTemplate();
                        setNodeForm({
                          ...nodeForm,
                          protocol: e.target.value as Node["protocol"],
                          password: "",
                          shadowTlsHost: "",
                          shadowTlsPassword: "",
                        });
                      }}
                    >
                      <option value="ss">Shadowsocks</option>
                      <option value="snell">Snell v5</option>
                      <option value="anytls">AnyTLS</option>
                    </select>
                  </Field>
                  <Field label="端口 *">
                    <div className="inputWithAction">
                      <input
                        required
                        type="number"
                        min={1}
                        max={65535}
                        value={nodeForm.port || ""}
                        onChange={(e) => setNodeForm({ ...nodeForm, port: Number(e.target.value) })}
                      />
                      <button className="iconButton" type="button" title="随机端口（50000–60000）" aria-label="随机端口（50000–60000）" onClick={randomizeNodePort}><Icon name="dice" /></button>
                    </div>
                  </Field>
                  <Field label="监听地址">
                    <input
                      value={nodeForm.listen || ""}
                      onChange={(e) =>
                        setNodeForm({ ...nodeForm, listen: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="发布地址覆盖">
                    <input
                      value={nodeForm.publishAddress || ""}
                      onChange={(e) =>
                        setNodeForm({
                          ...nodeForm,
                          publishAddress: e.target.value,
                        })
                      }
                    />
                  </Field>
                  <Field label="节点端口 UFW 规则">
                    <select
                      value={nodeForm.firewallPolicy || "all"}
                      onChange={(e) => setNodeForm({ ...nodeForm, firewallPolicy: e.target.value as Node["firewallPolicy"], firewallSources: "" })}
                    >
                      <option value="all">自动放行所有来源</option>
                      <option value="restricted">仅自动放行指定 IP / CIDR</option>
                      <option value="manual">不生成自动规则，手动管理</option>
                    </select>
                  </Field>
                  {nodeForm.firewallPolicy === "restricted" && (
                    <Field label="允许的来源 IP / CIDR *">
                      <textarea
                        required
                        rows={2}
                        placeholder="203.0.113.4, 2001:db8::/32"
                        value={nodeForm.firewallSources || ""}
                        onChange={(e) => setNodeForm({ ...nodeForm, firewallSources: e.target.value })}
                      />
                    </Field>
                  )}
                  {nodeForm.protocol === "ss" && (
                    <Field label="加密方式">
                      <select
                        value={nodeForm.method}
                        onChange={(e) => {
                          clearSelectedTemplate();
                          setNodeForm({ ...nodeForm, method: e.target.value, password: "" });
                        }}
                      >
                        {[
                          "2022-blake3-aes-128-gcm",
                          "2022-blake3-aes-256-gcm",
                          "2022-blake3-chacha20-poly1305",
                          "aes-128-gcm",
                          "aes-256-gcm",
                          "chacha20-ietf-poly1305",
                        ].map((v) => (
                          <option key={v}>{v}</option>
                        ))}
                      </select>
                    </Field>
                  )}
                  {nodeForm.protocol === "snell" && (
                    <>
                      <Field label="混淆模式">
                        <select value={nodeForm.obfs || "none"} onChange={(e) => setNodeForm({ ...nodeForm, obfs: e.target.value })}>
                          <option value="none">无</option>
                          <option value="http">HTTP</option>
                        </select>
                      </Field>
                      <Field label="ShadowTLS v3 SNI / 握手域名 *">
                        <input required placeholder="例如 www.example.com（TLS 站点）" value={nodeForm.shadowTlsHost || ""} onChange={(e) => { clearSelectedTemplate(); setNodeForm({ ...nodeForm, shadowTlsHost: e.target.value }); }} />
                      </Field>
                      <Field label={nodeForm.id ? "ShadowTLS v3 密码（留空不修改）" : selectedTemplate ? "ShadowTLS v3 密码（已填入，可修改）" : "ShadowTLS v3 密码（留空生成）"}>
                        <SecretField value={nodeForm.shadowTlsPassword || ""} onChange={(v) => setNodeForm({ ...nodeForm, shadowTlsPassword: v })} action={<button className="iconButton" type="button" title="生成 ShadowTLS 密码" aria-label="生成 ShadowTLS 密码" onClick={() => setNodeForm({ ...nodeForm, shadowTlsPassword: generatePassword("snell") })}><Icon name="generate" /></button>} />
                      </Field>
                    </>
                  )}
                  {nodeForm.protocol === "anytls" && (
                    <>
                      <Field label="TLS 域名 *">
                        <input
                          required
                          value={nodeForm.tlsName || ""}
                          onChange={(e) =>
                            setNodeForm({
                              ...nodeForm,
                              tlsName: e.target.value,
                              certificateId: matchingCertificate(nodeForm.serverId || "", e.target.value),
                            })
                          }
                        />
                      </Field>
                      <Field label="证书 *">
                        <select
                          required
                          value={nodeForm.certificateId || ""}
                          onChange={(e) =>
                            setNodeForm({
                              ...nodeForm,
                              certificateId: e.target.value,
                            })
                          }
                        >
                          <option value="">选择证书</option>
                          {certificates
                            .filter((c) => c.serverId === nodeForm.serverId)
                            .map((c) => (
                              <option key={c.id} value={c.id}>
                                {c.name || c.domain}
                              </option>
                            ))}
                        </select>
                      </Field>
                    </>
                  )}
                  <Field
                    label={
                      nodeForm.id
                        ? "新密码（留空不修改）"
                        : selectedTemplate ? "密码 / PSK（已填入，可修改）" : "密码 / PSK（留空生成）"
                    }
                  >
                    <SecretField value={nodeForm.password || ""} onChange={(v) => setNodeForm({ ...nodeForm, password: v })} action={<button className="iconButton" type="button" title="生成密码 / PSK" aria-label="生成密码 / PSK" onClick={() => setNodeForm({ ...nodeForm, password: generatePassword(nodeForm.protocol || "ss", nodeForm.method) })}><Icon name="generate" /></button>} />
                  </Field>
                  {nodeForm.id && (
                    <Field label="状态">
                      <label className="check">
                        <input
                          type="checkbox"
                          checked={nodeForm.enabled ?? true}
                          onChange={(e) =>
                            setNodeForm({
                              ...nodeForm,
                              enabled: e.target.checked,
                            })
                          }
                        />{" "}
                        启用节点
                      </label>
                    </Field>
                  )}
                </div>
                <p className="hint">
                  节点连接配置改变时会重启 sing-box；只修改 UFW 放行来源不会重启。
                </p>
                {nodeForm.firewallPolicy === "restricted" && <p className="hint">指定来源只约束节点自动规则；请检查主机上是否还有放行同一端口的其他规则。</p>}
                {nodeForm.firewallPolicy === "manual" && <p className="hint">手动管理模式不会开放节点端口，请先在自定义规则中添加需要的允许来源。</p>}
                {nodeFirewallUnsupported && <div className="banner warning" role="status">可以保存配置，但该服务器的 Agent 尚未上报支持新规则。更新 Agent 前不会应用此配置，现有 UFW 放行规则仍然生效。</div>}
                {templateLoading && <p className="hint">正在读取模板密码…</p>}
                <button className="primary submit" disabled={templateLoading}>提交配置</button>
              </form>
            )}
            {modal === "template" && (
              <form onSubmit={submitTemplate}>
                <div className="formGrid">
                  <Field label="模板名称 *">
                    <input
                      required
                      maxLength={100}
                      value={templateForm.name || ""}
                      onChange={(e) => setTemplateForm({ ...templateForm, name: e.target.value })}
                    />
                  </Field>
                  <Field label="协议">
                    <select
                      value={templateForm.protocol}
                      onChange={(e) => setTemplateForm({ ...templateForm, protocol: e.target.value as Node["protocol"], password: "", shadowTlsHost: "", shadowTlsPassword: "" })}
                    >
                      <option value="ss">Shadowsocks</option>
                      <option value="snell">Snell v5</option>
                      <option value="anytls">AnyTLS</option>
                    </select>
                  </Field>
                  <Field label="端口 *">
                    <div className="inputWithAction">
                      <input
                        required
                        type="number"
                        min={1}
                        max={65535}
                        value={templateForm.port || ""}
                        onChange={(e) => setTemplateForm({ ...templateForm, port: Number(e.target.value) })}
                      />
                      <button className="iconButton" type="button" title="随机端口（50000–60000）" aria-label="随机端口（50000–60000）" onClick={() => setTemplateForm({ ...templateForm, port: generatePort(new Set([templateForm.port || 0])) })}><Icon name="dice" /></button>
                    </div>
                  </Field>
                  <Field label="监听地址">
                    <input
                      value={templateForm.listen || ""}
                      onChange={(e) => setTemplateForm({ ...templateForm, listen: e.target.value })}
                    />
                  </Field>
                  {templateForm.protocol === "ss" && (
                    <Field label="加密方式">
                      <select
                        value={templateForm.method}
                        onChange={(e) => setTemplateForm({ ...templateForm, method: e.target.value, password: "" })}
                      >
                        {[
                          "2022-blake3-aes-128-gcm",
                          "2022-blake3-aes-256-gcm",
                          "2022-blake3-chacha20-poly1305",
                          "aes-128-gcm",
                          "aes-256-gcm",
                          "chacha20-ietf-poly1305",
                        ].map((v) => <option key={v}>{v}</option>)}
                      </select>
                    </Field>
                  )}
                  {templateForm.protocol === "snell" && (
                    <>
                      <Field label="混淆模式">
                        <select value={templateForm.obfs || "none"} onChange={(e) => setTemplateForm({ ...templateForm, obfs: e.target.value })}>
                          <option value="none">无</option>
                          <option value="http">HTTP</option>
                        </select>
                      </Field>
                      <Field label="ShadowTLS v3 SNI / 握手域名 *">
                        <input required placeholder="例如 www.example.com（TLS 站点）" value={templateForm.shadowTlsHost || ""} onChange={(e) => setTemplateForm({ ...templateForm, shadowTlsHost: e.target.value })} />
                      </Field>
                      <Field label="ShadowTLS v3 密码（留空时节点单独生成）">
                        <SecretField value={templateForm.shadowTlsPassword || ""} onChange={(v) => setTemplateForm({ ...templateForm, shadowTlsPassword: v })} action={<button className="iconButton" type="button" title="生成 ShadowTLS 密码" aria-label="生成 ShadowTLS 密码" onClick={() => setTemplateForm({ ...templateForm, shadowTlsPassword: generatePassword("snell") })}><Icon name="generate" /></button>} />
                      </Field>
                    </>
                  )}
                  {templateForm.protocol === "anytls" && (
                    <Field label="TLS 域名 *">
                      <input
                        required
                        value={templateForm.tlsName || ""}
                        onChange={(e) => setTemplateForm({ ...templateForm, tlsName: e.target.value })}
                      />
                    </Field>
                  )}
                  <Field label="密码 / PSK（留空时节点单独生成）">
                    <SecretField value={templateForm.password || ""} onChange={(v) => setTemplateForm({ ...templateForm, password: v })} action={<button className="iconButton" type="button" title="生成密码 / PSK" aria-label="生成密码 / PSK" onClick={() => setTemplateForm({ ...templateForm, password: generatePassword(templateForm.protocol || "ss", templateForm.method) })}><Icon name="generate" /></button>} />
                  </Field>
                </div>
                <p className="hint">SS 2022 密钥按加密方式生成 16 或 32 字节的 Base64。模板密码会加密保存，使用模板创建的节点共享该密码；留空则每个节点独立生成。Snell 的 ShadowTLS 域名应是服务器可访问的真实 TLS 站点（443 端口），ShadowTLS 密码与 Snell PSK 分开。AnyTLS 会尝试匹配所选服务器的证书。</p>
                <button className="primary submit">保存模板</button>
              </form>
            )}
            {modal === "certificate" && (
              <form onSubmit={submitCert}>
                <div className="formGrid">
                  <Field label="服务器 *">
                    <select
                      required
                      value={certForm.serverId || ""}
                      onChange={(e) =>
                        setCertForm({ ...certForm, serverId: e.target.value })
                      }
                    >
                      <option value="">选择服务器</option>
                      {servers.map((s) => (
                        <option key={s.id} value={s.id}>
                          {s.name}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label="名称">
                    <input
                      value={certForm.name || ""}
                      onChange={(e) =>
                        setCertForm({ ...certForm, name: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="域名 *">
                    <input
                      required
                      value={certForm.domain || ""}
                      onChange={(e) =>
                        setCertForm({ ...certForm, domain: e.target.value })
                      }
                    />
                  </Field>
                </div>
                <Field label="证书链 PEM *">
                  <textarea
                    required
                    rows={7}
                    value={certForm.pem || ""}
                    onChange={(e) =>
                      setCertForm({ ...certForm, pem: e.target.value })
                    }
                  />
                </Field>
                <Field label="私钥 PEM *">
                  <SecretTextarea
                    required
                    rows={7}
                    value={certForm.key || ""}
                    onChange={(v) => setCertForm({ ...certForm, key: v })}
                  />
                </Field>
                <button className="primary submit">保存证书</button>
              </form>
            )}
            {modal === "forward" && (
              <form onSubmit={submitForward}>
                <div className="formGrid">
                  <Field label="服务器 *"><select required value={forwardForm.serverId || ""} disabled={!!forwardForm.id} onChange={(e) => setForwardForm({ ...forwardForm, serverId: e.target.value })}><option value="">选择服务器</option>{servers.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></Field>
                  <Field label="名称 *"><input required maxLength={100} value={forwardForm.name || ""} onChange={(e) => setForwardForm({ ...forwardForm, name: e.target.value })} /></Field>
                  <Field label="协议"><select value={forwardForm.network || "tcp"} onChange={(e) => setForwardForm({ ...forwardForm, network: e.target.value as ForwardRule["network"] })}><option value="tcp">TCP</option><option value="udp">UDP</option></select></Field>
                  <Field label="监听 IP"><input required value={forwardForm.listen || ""} onChange={(e) => setForwardForm({ ...forwardForm, listen: e.target.value })} placeholder="0.0.0.0" /></Field>
                  <Field label="监听端口 *"><input required type="number" min={1024} max={65535} value={forwardForm.port || ""} onChange={(e) => setForwardForm({ ...forwardForm, port: Number(e.target.value) })} /></Field>
                  <Field label="目标地址 *"><input required value={forwardForm.targetHost || ""} onChange={(e) => setForwardForm({ ...forwardForm, targetHost: e.target.value })} placeholder="例如 203.0.113.10 或 example.com" /></Field>
                  <Field label="目标端口 *"><input required type="number" min={1} max={65535} value={forwardForm.targetPort || ""} onChange={(e) => setForwardForm({ ...forwardForm, targetPort: Number(e.target.value) })} /></Field>
                  <Field label="UFW 规则"><select value={forwardForm.firewallPolicy || "all"} onChange={(e) => setForwardForm({ ...forwardForm, firewallPolicy: e.target.value as ForwardRule["firewallPolicy"], firewallSources: e.target.value === "restricted" ? forwardForm.firewallSources : "" })}><option value="all">自动放行所有来源</option><option value="restricted">仅放行指定 IP / CIDR</option><option value="manual">手动管理</option></select></Field>
                  {forwardForm.firewallPolicy === "all" && <p className="hint">公开转发会把目标暴露给全网；如无必要请改用“仅放行指定 IP / CIDR”。提交时会再次确认。</p>}
                  {forwardForm.firewallPolicy === "restricted" && <Field label="允许的来源 IP / CIDR *"><textarea required value={forwardForm.firewallSources || ""} onChange={(e) => setForwardForm({ ...forwardForm, firewallSources: e.target.value })} placeholder="每行一个 IP 或 CIDR" /></Field>}
                  <Field label="状态"><label className="check"><input type="checkbox" checked={!!forwardForm.enabled} onChange={(e) => setForwardForm({ ...forwardForm, enabled: e.target.checked })} /> 启用转发</label></Field>
                </div>
                {forwardForm.serverId && !servers.find((s) => s.id === forwardForm.serverId)?.forwardSupport && <p className="hint">这台服务器的 Agent 尚未上报端口转发能力。规则可以先保存；升级 Agent 后会自动应用。</p>}
                <p className="hint">目标服务器需允许来自转发服务器的连接；UFW 规则只控制本机入口。</p>
                <p className="hint">目标可以填域名：转发进程每 30 秒重新解析一次，域名指向新地址后新连接会跟着走。修改或删除一条转发只影响它自己的连接。</p>
                <button className="primary submit" type="submit">提交配置</button>
              </form>
            )}
            {modal === "rule" && (
              <form onSubmit={submitRule}>
                <div className="formGrid">
                  <Field label="服务器 *">
                    <select
                      required
                      value={ruleForm.serverId || ""}
                      onChange={(e) =>
                        setRuleForm({ ...ruleForm, serverId: e.target.value })
                      }
                    >
                      <option value="">选择服务器</option>
                      {servers.map((s) => (
                        <option key={s.id} value={s.id}>
                          {s.name}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label="协议">
                    <select
                      value={ruleForm.network}
                      onChange={(e) =>
                        setRuleForm({ ...ruleForm, network: e.target.value })
                      }
                    >
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                    </select>
                  </Field>
                  <Field label="起始端口">
                    <input
                      required
                      type="number"
                      min={1}
                      max={65535}
                      value={ruleForm.portFrom || ""}
                      onChange={(e) =>
                        setRuleForm({
                          ...ruleForm,
                          portFrom: Number(e.target.value),
                        })
                      }
                    />
                  </Field>
                  <Field label="结束端口">
                    <input
                      required
                      type="number"
                      min={1}
                      max={65535}
                      value={ruleForm.portTo || ""}
                      onChange={(e) =>
                        setRuleForm({
                          ...ruleForm,
                          portTo: Number(e.target.value),
                        })
                      }
                    />
                  </Field>
                  <Field label="来源 IP / CIDR（留空任意）">
                    <input
                      value={ruleForm.source || ""}
                      onChange={(e) =>
                        setRuleForm({ ...ruleForm, source: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="动作">
                    <select
                      value={ruleForm.action}
                      onChange={(e) =>
                        setRuleForm({ ...ruleForm, action: e.target.value })
                      }
                    >
                      <option value="allow">允许</option>
                      <option value="deny">拒绝</option>
                    </select>
                  </Field>
                  <Field label="备注">
                    <input
                      value={ruleForm.comment || ""}
                      onChange={(e) =>
                        setRuleForm({ ...ruleForm, comment: e.target.value })
                      }
                    />
                  </Field>
                </div>
                <button className="primary submit">提交规则</button>
              </form>
            )}
            {modal === "customer" && (
              <form onSubmit={submitCustomer}>
                <div className="formGrid">
                  <Field label="客户名称 *"><input required maxLength={100} value={customerForm.name || ""} onChange={(e) => setCustomerForm({ ...customerForm, name: e.target.value })} /></Field>
                  <Field label="备注"><input maxLength={1000} value={customerForm.notes || ""} onChange={(e) => setCustomerForm({ ...customerForm, notes: e.target.value })} /></Field>
                </div>
                <button className="primary submit">{customerForm.id ? "保存客户" : "创建客户"}</button>
              </form>
            )}
            {modal === "subscription" && (
              <form onSubmit={submitSub}>
                <div className="formGrid">
                  <Field label="订阅名称 *">
                    <input
                      required
                      value={subForm.name || ""}
                      onChange={(e) =>
                        setSubForm({ ...subForm, name: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="关联客户">
                    <select value={subForm.customerId || ""} onChange={(e) => setSubForm({ ...subForm, customerId: e.target.value })}>
                      <option value="">未关联</option>
                      {customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                    </select>
                  </Field>
                  <Field label="客户端格式">
                    <select
                      value={subForm.format}
                      onChange={(e) =>
                        setSubForm({
                          ...subForm,
                          format: e.target.value,
                          nodeIds: (subForm.nodeIds || []).filter((id) => {
                            const node = nodes.find((item) => item.id === id);
                            return !!node && subscriptionNodeEligible(e.target.value, node);
                          }),
                        })
                      }
                    >
                      <option value="sing-box">sing-box JSON</option>
                      <option value="surge">Surge 代理片段</option>
                    </select>
                  </Field>
                  <Field label="到期日（留空不过期）">
                    <input
                      type="date"
                      value={
                        subForm.expiresAt
                          ? localDate(new Date(subForm.expiresAt))
                          : ""
                      }
                      onChange={(e) =>
                        setSubForm({
                          ...subForm,
                          // The link works through the end of the chosen day.
                          expiresAt: e.target.value
                            ? new Date(
                                e.target.value + "T23:59:59",
                              ).toISOString()
                            : undefined,
                        })
                      }
                    />
                  </Field>
                </div>
                <Field label="选择节点">
                  <div className="nodePicker">
                    {nodes
                      .filter(
                        (n) =>
                          (n.status === "active" && subscriptionNodeEligible(subForm.format, n)) ||
                          subForm.nodeIds?.includes(n.id),
                      )
                      .map((n) => (
                        <label className="check" key={n.id}>
                          <input
                            type="checkbox"
                            checked={subForm.nodeIds?.includes(n.id) || false}
                            onChange={(e) =>
                              setSubForm({
                                ...subForm,
                                nodeIds: e.target.checked
                                  ? [...(subForm.nodeIds || []), n.id]
                                  : (subForm.nodeIds || []).filter(
                                      (id) => id !== n.id,
                                    ),
                              })
                            }
                          />
                          {n.name}{" "}
                          <small>
                            {n.protocol.toUpperCase()} ·{" "}
                            {serverName(n.serverId)}
                          </small>
                        </label>
                      ))}
                    {nodes.filter((n) => n.status === "active" && subscriptionNodeEligible(subForm.format, n)).length ===
                      0 && <p className="hint">尚无已生效节点</p>}
                  </div>
                </Field>
                <p className="hint">Surge 格式支持 AES-GCM 的 SS 2022 节点和启用 ShadowTLS 的 Snell 节点；AnyTLS 请使用 sing-box 格式。</p>
                <p className="hint">保存后，所选节点所在服务器的 sing-box 会重启以更新登录凭据，其上所有连接将中断数秒。订阅到期时也会自动执行一次。</p>
                <button className="primary submit">
                  {subForm.id ? "保存订阅" : "创建订阅"}
                </button>
                {issuedURL && (
                  <div className="commandBox">
                    <strong>请保存订阅链接：</strong>
                    <span>新凭据需等待 Agent 应用配置后才能下载使用。</span>
                    <MaskedValue value={issuedURL}><button type="button" onClick={() => copy(issuedURL)}>复制</button></MaskedValue>
                  </div>
                )}
              </form>
            )}
          </div>
        </div>
      )}
      {trafficNode && (
        <div
          className="overlay"
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) setTrafficNode(null);
          }}
        >
          <div className="modal">
            <div className="modalHead">
              <div>
                <h2>{trafficNode.name} · 流量</h2>
              </div>
              <button
                className="closeButton" aria-label="关闭"
                onClick={() => setTrafficNode(null)}
              >
                ×
              </button>
            </div>
            <div className="trafficTotals">
              <div>
                累计上行<strong>{bytes(trafficNode.uplink)}</strong>
              </div>
              <div>
                累计下行<strong>{bytes(trafficNode.downlink)}</strong>
              </div>
            </div>
            {traffic.length ? <Suspense fallback={<div className="trafficChart"><Empty text="正在加载图表…" /></div>}><TrafficChart points={traffic} /></Suspense> : <div className="trafficChart"><Empty text="暂无流量样本" /></div>}
          </div>
        </div>
      )}
      {trafficSub && (
        <div className="overlay" onMouseDown={(e) => {
          if (e.target === e.currentTarget) setTrafficSub(null);
        }}>
          <div className="modal">
            <div className="modalHead">
              <h2>{trafficSub.name} · 订阅流量</h2>
              <button className="closeButton" aria-label="关闭" onClick={() => setTrafficSub(null)}>×</button>
            </div>
            <div className="trafficTotals">
              <div>累计上行<strong>{bytes(trafficSub.uplink || 0)}</strong></div>
              <div>累计下行<strong>{bytes(trafficSub.downlink || 0)}</strong></div>
            </div>
            {subTraffic.length ? <Suspense fallback={<div className="trafficChart"><Empty text="正在加载图表…" /></div>}><TrafficChart points={subTraffic} /></Suspense> : <div className="trafficChart"><Empty text="暂无流量样本" /></div>}
          </div>
        </div>
      )}
      {confirmation && (
        <ConfirmDialog
          confirmation={confirmation}
          onCancel={() => setConfirmation(null)}
          onConfirm={() => {
            setConfirmation(null);
            confirmation.onConfirm();
          }}
        />
      )}
    </div>
  );
}
function ConfirmDialog({
  confirmation,
  onCancel,
  onConfirm,
}: {
  confirmation: Confirmation;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const cancelButton = useRef<HTMLButtonElement>(null);
  const confirmButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    cancelButton.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onCancel();
      } else if (event.key === "Tab") {
        if (event.shiftKey && document.activeElement === cancelButton.current) {
          event.preventDefault();
          confirmButton.current?.focus();
        } else if (!event.shiftKey && document.activeElement === confirmButton.current) {
          event.preventDefault();
          cancelButton.current?.focus();
        }
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      previousFocus?.focus();
    };
  }, []);
  return (
    <div className="overlay confirmationOverlay" onMouseDown={(event) => {
      if (event.target === event.currentTarget) onCancel();
    }}>
      <div className="modal confirmModal" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-message">
        <div className="modalHead">
          <h2 id="confirm-title">{confirmation.title}</h2>
        </div>
        <p className="confirmMessage" id="confirm-message">{confirmation.message}</p>
        <div className="confirmActions">
          <button type="button" className="ghost" ref={cancelButton} onClick={onCancel}>取消</button>
          <button type="button" className="primary" ref={confirmButton} onClick={onConfirm}>{confirmation.confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}
const Field = memo(function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
    </label>
  );
});
const statusLabels: Record<string, [string, "good" | "bad" | "warn" | "idle"]> =
  {
    online: ["在线", "good"],
    active: ["正常", "good"],
    success: ["成功", "good"],
    offline: ["离线", "bad"],
    failed: ["失败", "bad"],
    error: ["出错", "bad"],
    unavailable: ["不可用", "bad"],
    conflict: ["冲突", "bad"],
    pending: ["等待中", "warn"],
    queued: ["排队中", "warn"],
    running: ["执行中", "warn"],
    activating: ["等待新版上线", "warn"],
    deleting: ["删除中", "warn"],
    inactive: ["未启用", "warn"],
    disabled: ["已停用", "idle"],
    expired: ["已到期", "idle"],
    partial: ["部分生效", "warn"],
    superseded: ["已被替代", "idle"],
    idle: ["空闲", "idle"],
    unsupported: ["不支持", "idle"],
    unknown: ["未知", "idle"],
  };
const Status = memo(function Status({ value }: { value: string }) {
  const [label, tone] = statusLabels[value] || [value || "未知", "idle"];
  return <span className={"status " + tone}>{label}</span>;
});
const kindLabels: Record<string, string> = {
  "agent.upgrade": "升级 Agent",
  "core.upgrade": "升级 sing-box",
  "nodes.apply": "应用节点配置",
  "subscriptions.apply": "应用订阅用户",
  "firewall.apply": "应用防火墙规则",
  "ufw.init": "初始化 UFW",
};
function kindLabel(kind: string) {
  return kindLabels[kind] || kind;
}
function localDate(d: Date) {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}
// QRCode lives in ./components/QRCode.tsx (lazy-loaded, only used by TOTP setup).
const LOG_PAGE = 50;
type PagedLog<T> = { items: T[]; more: boolean; busy: boolean; empty: boolean; expanded: boolean; reload: () => void; loadMore: () => void };

// usePagedLog shows a log one page at a time. `base` is the listing URL with its
// filters, or null while the list is not on screen; changing it starts over.
// `cursor` turns the rows already shown into the parameter that asks for the
// next page. One row more than a page is requested to learn whether more exist.
function usePagedLog<T>(base: string | null, cursor: (items: T[]) => string, onError: (e: Error) => void): PagedLog<T> {
  const [items, setItems] = useState<T[]>([]);
  const [more, setMore] = useState(false);
  const [busy, setBusy] = useState(false);
  // Known to be empty only once a page has actually come back.
  const [loaded, setLoaded] = useState(false);
  const request = useRef(0);
  const shown = useRef<T[]>([]);
  const load = (append: boolean) => {
    if (!base) return;
    const current = ++request.current;
    const previous = append ? shown.current : [];
    setBusy(true);
    api<unknown>(`${base}&limit=${LOG_PAGE + 1}${previous.length ? "&" + cursor(previous) : ""}`)
      .then((body) => {
        // Accept both the legacy bare array and the paged envelope.
        const page = Array.isArray(body) ? (body as T[]) : ((body as { items?: T[] }).items ?? []);
        // A newer request (another filter, a refresh) has taken over.
        if (current !== request.current) return;
        shown.current = [...previous, ...page.slice(0, LOG_PAGE)];
        setItems(shown.current);
        setMore(page.length > LOG_PAGE);
        setLoaded(true);
      })
      .catch((e) => { if (current === request.current) onError(e as Error); })
      .finally(() => { if (current === request.current) setBusy(false); });
  };
  useEffect(() => { load(false); }, [base]);
  return { items, more, busy, empty: loaded && !busy && !items.length, expanded: items.length > LOG_PAGE, reload: () => load(false), loadMore: () => load(true) };
}

function LoadMore<T>({ log }: { log: PagedLog<T> }) {
  if (!log.items.length) return null;
  return (
    <div className="loadMore">
      <span className="hint">已显示 {log.items.length} 条{log.more ? "" : "，没有更早的记录了"}</span>
      {log.more && <button className="ghost" disabled={log.busy} onClick={log.loadMore}>{log.busy ? "加载中…" : "加载更早的记录"}</button>}
    </div>
  );
}

// ActionMenu keeps a row's occasional and destructive actions one click away.
// The list is positioned against the viewport rather than the table, whose
// horizontal scroll container would clip an ordinary absolutely placed menu.
function ActionMenu({ children }: { children: React.ReactNode }) {
  const [place, setPlace] = useState<React.CSSProperties | null>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const items = () =>
    Array.from(list.current?.querySelectorAll<HTMLButtonElement>("button:not(:disabled)") || []);
  const close = (refocus = false) => {
    setPlace(null);
    if (refocus) trigger.current?.focus();
  };
  const toggle = () => {
    if (place) return close();
    const box = trigger.current!.getBoundingClientRect();
    const right = Math.max(8, window.innerWidth - box.right);
    // Open upwards when the row sits near the bottom of the window.
    setPlace(
      window.innerHeight - box.bottom < 260 && box.top > window.innerHeight - box.bottom
        ? { right, bottom: window.innerHeight - box.top + 4 }
        : { right, top: box.bottom + 4 },
    );
  };
  useEffect(() => {
    if (!place) return;
    // preventScroll: moving focus must not itself cause the scroll that dismisses the list.
    items()[0]?.focus({ preventScroll: true });
    const outside = (event: MouseEvent) => {
      const target = event.target as globalThis.Node;
      if (!list.current?.contains(target) && !trigger.current?.contains(target)) close();
    };
    const dismiss = (event: Event) => {
      if (event.target instanceof globalThis.Node && list.current?.contains(event.target)) return;
      close();
    };
    document.addEventListener("mousedown", outside);
    // A fixed list would otherwise stay put while its row scrolls away.
    window.addEventListener("scroll", dismiss, true);
    window.addEventListener("resize", dismiss);
    return () => {
      document.removeEventListener("mousedown", outside);
      window.removeEventListener("scroll", dismiss, true);
      window.removeEventListener("resize", dismiss);
    };
  }, [place]);
  const onKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "Escape") {
      event.stopPropagation();
      return close(true);
    }
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
    event.preventDefault();
    const all = items();
    const at = all.indexOf(document.activeElement as HTMLButtonElement);
    all[(at + (event.key === "ArrowDown" ? 1 : all.length - 1)) % all.length]?.focus();
  };
  return (
    <span className="actionMenu">
      <button type="button" ref={trigger} aria-haspopup="menu" aria-expanded={!!place} onClick={toggle}>
        更多
      </button>
      {place && (
        <div className="menuList" role="menu" ref={list} style={place} onClick={() => close()} onKeyDown={onKeyDown}>
          {children}
        </div>
      )}
    </span>
  );
}
const Empty = memo(function Empty({ text }: { text: string }) {
  return <div className="empty">{text}</div>;
});

createRoot(document.getElementById("root")!).render(<App />);
