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
  type Route,
  type RouteHop,
  type RouteSourceMode,
  type Role,
  type InstallGuide,
  roleLabels,
  canHostNodes,
} from "./api";
import "./style.css";
import OfflineManager from "./components/OfflineManager";
import AgentDownloads from "./components/AgentDownloads";
import ManagementMigration from "./components/ManagementMigration";
import CertificateFileField from "./components/CertificateFileField";
import { screenshotText, screenshotView } from "./components/screenshot";
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
  | "routes"
  | "subscriptions"
  | "customers"
  | "accesses"
  | "connections"
  | "operations"
  | "audit"
  | "settings";
// Pages that only exist as an entry of a sub-menu have no icon of their own.
type SubPage = "accesses" | "connections" | "audit";
type IconName = "privacy" | "refresh" | "sun" | "moon" | "generate" | "dice" | Exclude<Tab, SubPage> | "logout";
// An entry with children is a group: clicking it opens its first page, and its
// pages are listed beneath it while one of them is showing.
const tabs: { id: Exclude<Tab, SubPage>; label: string; icon: IconName; children?: { id: Tab; label: string }[] }[] = [
  { id: "dashboard", label: "总览", icon: "dashboard" },
  { id: "servers", label: "服务器", icon: "servers" },
  { id: "nodes", label: "节点", icon: "nodes" },
  { id: "templates", label: "节点模板", icon: "templates" },
  { id: "certificates", label: "证书", icon: "certificates" },
  { id: "firewall", label: "防火墙", icon: "firewall" },
  { id: "routes", label: "链路", icon: "routes" },
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
// The page lives in the URL hash (#servers, #routes, ...) so that a reload
// stays on it and the browser's back and forward buttons move between pages.
const tabIds = new Set<string>(tabs.flatMap((t) => [t.id, ...(t.children || []).map((c) => c.id)]));
function tabFromHash(): Tab {
  const id = decodeURIComponent(location.hash.slice(1));
  return tabIds.has(id) ? (id as Tab) : "dashboard";
}
const emptyServer: Partial<Server> = {
  managementMode: "online",
  agentProxyNodeId: "",
  agentProxyInternal: false,
  firewallMode: "ufw",
  name: "",
  roles: ["exit"],
  internalAddress: "",
  outboundInterface: "",
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
  outboundMode: "inherit",
  outboundInterface: "",
  method: "2022-blake3-aes-128-gcm",
  snellVersion: 6,
  snellPort: 20001,
  obfs: "none",
  shadowTlsHost: "",
  tlsName: "",
  certificateId: "",
  firewallPolicy: "all",
  firewallSources: "",
  direct: false,
  enabled: true,
};
const emptyTemplate: Partial<NodeTemplate> = {
  name: "",
  protocol: "ss",
  port: 50000,
  listen: "0.0.0.0",
  method: "2022-blake3-aes-128-gcm",
  snellVersion: 6,
  snellPort: 20001,
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
function subscriptionNodeIssue(format: string | undefined, node: Node): string {
  if (format === "v2rayn" && node.protocol !== "ss" && node.protocol !== "anytls" && node.protocol !== "socks5") return "v2rayN 订阅不支持 Snell / ShadowTLS";
  if (node.protocol === "ss") {
    if (format === "surge" && node.method === "2022-blake3-chacha20-poly1305") return "Surge 不支持 2022-blake3-chacha20-poly1305，请使用 AES 方式";
  }
  // Surge reaches Snell nodes through ShadowTLS; it has no AnyTLS support here.
  if (format === "surge" && node.protocol === "snell" && !node.shadowTlsHost) return "Surge 的 Snell 节点需要启用 ShadowTLS";
  if (format === "surge" && node.protocol === "anytls") return "Surge 订阅暂不支持 AnyTLS";
  return "";
}
function subscriptionNodeEligible(format: string | undefined, node: Node) {
  return !subscriptionNodeIssue(format, node);
}
function subscriptionDirectNodeIssue(format: string | undefined, node: Node): string {
  if (node.deleting) return "节点正在删除";
  if (!node.direct) return "未开启允许直连，请先编辑节点并保存";
  if (!node.enabled) return "节点已停用";
  return subscriptionNodeIssue(format, node);
}
function sharedSubscriptionPassword(node: Node) {
  return node.protocol === "ss" && !node.method.startsWith("2022-blake3-");
}
function manualFirewall(server?: Partial<Server>) { return server?.firewallMode === "manual"; }
function forwardDisplayStatus(forward: ForwardRule, server?: Server): string {
  if (server?.managementMode !== "offline") return forward.deleting ? "deleting" : forward.status;
  if (forward.deleting) return "offline-delete-pending";
  const exported = !!server.offlineExportedAt && server.offlineExportedRevision === server.revision;
  if (!exported || forward.status === "pending") return forward.enabled ? "offline-export-pending" : "offline-disable-export-pending";
  return forward.enabled ? "offline-exported" : "offline-disabled-exported";
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
    privacy: <><path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z" /><path d="m8 12 3 3 5-6" /></>,
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
    routes: <><circle cx="4" cy="12" r="2" /><circle cx="12" cy="12" r="2" /><circle cx="20" cy="12" r="2" /><path d="M6 12h4m4 0h4" /></>,
    subscriptions: <><path d="M4 7a13 13 0 0 1 13 13M4 12a8 8 0 0 1 8 8" /><circle cx="5" cy="19" r="1" fill="currentColor" stroke="none" /></>,
    customers: <><circle cx="9" cy="8" r="3" /><path d="M3 20v-2a6 6 0 0 1 12 0v2H3Z" /><circle cx="18" cy="9" r="2" /><path d="M17 15a5 5 0 0 1 4 5" /></>,
    operations: <><path d="M4 4v6h6M4.8 10a8 8 0 1 1-.2 5M12 7v5l3 2" /></>,
    settings: <><circle cx="12" cy="12" r="3" /><path d="M10 2h4l.6 2.2 2 .8 2-.9 2.8 2.8-.9 2 .8 2L23 11v4l-2.2.6-.8 2 .9 2-2.8 2.8-2-.9-2 .8L14 24h-4l-.6-2.2-2-.8-2 .9-2.8-2.8.9-2-.8-2L1 15v-4l2.2-.6.8-2-.9-2L6.9 3.6l2 .9 2-.8L10 2Z" transform="translate(0 -1) scale(1 .95)" /></>,
    logout: <><path d="M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h5M14 17l5-5-5-5M19 12H9" /></>,
  };
  return <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}
// One line of `ufw status numbered`, as the agent reports it.
type HostRule = {
  index: number;
  rule: string; // without the number: what the panel sends back to delete it
  tag: string; // "mui-..." / "panel-..." when the panel wrote it
  action: string;
  spec: string;
  source: string;
  portFrom: number;
  portTo: number;
  network: "tcp" | "udp" | ""; // "" covers both
  allPorts: boolean;
  app: boolean;
  v6: boolean; // the IPv6 line UFW lists separately for a rule
};
function parseHostRule(line: string): HostRule | null {
  const m = line.match(/^\[\s*(\d+)\]\s+(.*)$/);
  if (!m) return null;
  const rule = m[2].trim();
  const hash = rule.indexOf("#");
  const comment = hash >= 0 ? rule.slice(hash + 1).trim() : "";
  const fields = (hash >= 0 ? rule.slice(0, hash) : rule).replace(/ \(v6\)/g, "").trim().split(/\s+/);
  const at = fields.findIndex((f) => ["ALLOW", "DENY", "REJECT", "LIMIT"].includes(f));
  if (at < 1) return null;
  let from = at + 1;
  if (["IN", "OUT", "FWD"].includes(fields[from])) from++;
  const spec = fields.slice(0, at).join(" ");
  const out: HostRule = {
    index: Number(m[1]), rule, tag: /^(mui|panel)-/.test(comment) ? comment : "", action: fields[at], spec,
    source: fields.slice(from).join(" "), portFrom: 0, portTo: 0, network: "", allPorts: spec === "Anywhere", app: false,
    v6: rule.includes("(v6)"),
  };
  const ports = spec.match(/^(\d+)(?::(\d+))?(?:\/(tcp|udp))?$/);
  if (ports) {
    out.portFrom = Number(ports[1]);
    out.portTo = Number(ports[2] || ports[1]);
    out.network = (ports[3] || "") as HostRule["network"];
  } else if (!out.allPorts) {
    out.app = true;
  }
  return out;
}
// Mirrors the panel and agent check: a rule that may let SSH in stays.
function hostRuleAdmitsSSH(r: HostRule, sshPorts: number[]) {
  if (r.action !== "ALLOW" && r.action !== "LIMIT") return false;
  if (r.allPorts || r.app) return true;
  return r.network !== "udp" && sshPorts.some((p) => p >= r.portFrom && p <= r.portTo);
}
// A rule added on the host outside the panel that the panel may remove.
const hostRuleRemovable = (r: HostRule, sshPorts: number[]) => !r.tag && !hostRuleAdmitsSSH(r, sshPorts);
// What a custom rule can express: one port range, one protocol, allow/deny,
// one source.
const hostRuleConvertible = (r: HostRule) =>
  !r.allPorts && !r.app && r.network !== "" && (r.action === "ALLOW" || r.action === "DENY") && !/\s/.test(r.source);
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
  targets: [{ host: "", port: 443 }], balance: "failover", firewallPolicy: "restricted", firewallSources: "", enabled: true,
};
const emptyRoute: Partial<Route> = { name: "", entryServerId: "", hops: [], nodeId: "", nodeInternal: false, port: 0, enabled: true, notes: "" };
const roleOrder: Role[] = ["entry", "line", "transit", "exit"];
const rolesText = (roles: Role[] | undefined) => roleOrder.filter((r) => roles?.includes(r)).map((r) => roleLabels[r]).join(" / ") || "未设置";
// Forward targets are edited as one "host:port" per line; IPv6 hosts go in
// brackets.
const targetsText = (targets: ForwardRule["targets"] | undefined) =>
  (targets || []).map((t) => (t.host.includes(":") ? `[${t.host}]` : t.host) + (t.port ? ":" + t.port : "")).join("\n");
const parseTargets = (text: string): ForwardRule["targets"] =>
  text.split("\n").map((line) => line.trim()).filter(Boolean).map((line) => {
    const m = line.match(/^\[(.+)\]:(\d+)$/) || line.match(/^([^:]+):(\d+)$/);
    return m ? { host: m[1], port: Number(m[2]) } : { host: line, port: 0 };
  });

function App() {
  const templateRequest = useRef(0);
  // Guard against overlapping full refreshes (act() -> refresh() while a
  // poll is running, double clicks, ...). A refresh already in flight is
  // skipped instead of stacking duplicate requests.
  const refreshInFlight = useRef(false);
  const [refreshing, setRefreshing] = useState(false);
  const [screenshotMode, setScreenshotMode] = useState(() => localStorage.getItem("mui-screenshot-mode") === "true");
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    const stored = localStorage.getItem("mui-theme");
    return stored === "light" || stored === "dark"
      ? stored
      : matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });
  const [authed, setAuthed] = useState<boolean | null>(null),
    [totpEnabled, setTotpEnabled] = useState(false),
    [tab, setTab] = useState<Tab>(tabFromHash);
  const [opServer, setOpServer] = useState(""),
    [opKind, setOpKind] = useState(""),
    [auditQuery, setAuditQuery] = useState(""),
    [auditInput, setAuditInput] = useState(""),
    [accessCustomer, setAccessCustomer] = useState(""),
    [connectionServer, setConnectionServer] = useState(""),
    [subQuery, setSubQuery] = useState(""),
    [customerQuery, setCustomerQuery] = useState("");
  const showLogError = (e: Error) => setError(e.message);
  const [opRange, setOpRange] = useState<LogRange>(noRange),
    [auditRange, setAuditRange] = useState<LogRange>(noRange),
    [accessRange, setAccessRange] = useState<LogRange>(noRange),
    [connectionRange, setConnectionRange] = useState<LogRange>(noRange);
  const opLog = usePagedLog<Operation>(
    authed && tab === "operations" ? "/api/operations?serverId=" + encodeURIComponent(opServer) + "&kind=" + encodeURIComponent(opKind) : null, opRange, showLogError);
  const auditLog = usePagedLog<AuditEntry>(
    authed && tab === "audit" ? "/api/audit?q=" + encodeURIComponent(auditQuery) : null, auditRange, showLogError);
  const accessLog = usePagedLog<SubscriptionAccess>(
    authed && tab === "accesses" ? "/api/clients/accesses?customerId=" + encodeURIComponent(accessCustomer) : null, accessRange, showLogError);
  const connectionLog = usePagedLog<ConnectionIP>(
    authed && tab === "connections" ? "/api/clients/connections?serverId=" + encodeURIComponent(connectionServer) : null, connectionRange, showLogError);
  const [servers, setServers] = useState<Server[]>([]),
    [nodes, setNodes] = useState<Node[]>([]),
    [templates, setTemplates] = useState<NodeTemplate[]>([]),
    [certificates, setCertificates] = useState<Certificate[]>([]),
    [rules, setRules] = useState<FirewallRule[]>([]),
    [forwards, setForwards] = useState<ForwardRule[]>([]),
    [routes, setRoutes] = useState<Route[]>([]),
    [subs, setSubs] = useState<Subscription[]>([]),
    [customers, setCustomers] = useState<Customer[]>([]),
    [operations, setOperations] = useState<Operation[]>([]),
    [agentReleases, setAgentReleases] = useState<Record<string, string>>({}),
    [coreReleases, setCoreReleases] = useState<Record<string, string>>({});
  const [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [templateLoading, setTemplateLoading] = useState(false),
    [modal, setModal] = useState<
      "server" | "node" | "template" | "certificate" | "rule" | "forward" | "route" | "subscription" | "customer" | null
    >(null),
    [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [certFilesBusy, setCertFilesBusy] = useState({ pem: false, key: false });
  const [serverForm, setServerForm] = useState<Partial<Server>>(emptyServer),
    [nodeForm, setNodeForm] = useState<Partial<Node> & { password?: string; shadowTlsPassword?: string }>(
      emptyNode,
    ),
    [templateForm, setTemplateForm] = useState<TemplateForm>(emptyTemplate),
    [selectedTemplate, setSelectedTemplate] = useState(""),
    [certForm, setCertForm] = useState<Partial<Certificate>>({
      name: "",
      domain: "",
      pem: "",
      key: "",
    }),
    [ruleForm, setRuleForm] = useState<Partial<FirewallRule> & { replaceHostRule?: string }>(emptyRule),
    [forwardForm, setForwardForm] = useState<Partial<ForwardRule>>(emptyForward),
    [forwardTargets, setForwardTargets] = useState(""),
    [routeForm, setRouteForm] = useState<Partial<Route>>(emptyRoute),
    [subForm, setSubForm] = useState<Partial<Subscription>>({
      name: "",
      format: "sing-box",
      nodeIds: [],
      routeIds: [],
      enabled: true,
    }),
    [customerForm, setCustomerForm] = useState<Partial<Customer>>({ name: "", notes: "" });
  const [installInfo, setInstallInfo] = useState<(InstallGuide & { serverName: string }) | null>(null),
    [issuedURL, setIssuedURL] = useState(""),
    [issuedFormat, setIssuedFormat] = useState(""),
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
  const [agentDownloads, setAgentDownloads] = useState<{ arch: string } | null>(null);
  const [offlineServer, setOfflineServer] = useState<Server | null>(null);
  const [installMethod, setInstallMethod] = useState<"online" | "offline" | "standalone">("online");
  const [installArch, setInstallArch] = useState("amd64");
  const localInstallGuide = installMethod === "standalone" ? installInfo?.standaloneInstall : installInfo?.offlineInstall;
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
  const [forwardFilters, setForwardFilters] = useState({
    query: "", serverId: "", network: "", source: "", status: "",
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
  // accepts filter params. Logs page on the server (usePagedLog).
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
  const refresh = useCallback(async (manual = false) => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    setRefreshing(true);
    if (manual) { setError(""); setNotice("正在刷新…"); }
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
      load<Route>("/api/routes", setRoutes),
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
    if (failures.length) {
      setError(failures[0] + (failures.length > 1 ? `（另有 ${failures.length - 1} 项加载失败）` : ""));
      if (manual) setNotice("");
    } else if (manual) setNotice(`刷新完成 · ${new Date().toLocaleTimeString()}`);
    } finally {
      refreshInFlight.current = false;
      setRefreshing(false);
    }
  }, [loadAll, opLog, auditLog, accessLog, connectionLog]);
  useEffect(() => {
    if (tabFromHash() !== tab) history.pushState(null, "", "#" + tab);
  }, [tab]);
  useEffect(() => {
    const follow = () => setTab(tabFromHash());
    window.addEventListener("popstate", follow);
    window.addEventListener("hashchange", follow);
    return () => {
      window.removeEventListener("popstate", follow);
      window.removeEventListener("hashchange", follow);
    };
  }, []);
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
          case "routes": {
            const [s, n, f, r] = await Promise.all([loadAll<Server>("/api/servers"), loadAll<Node>("/api/nodes"), loadAll<ForwardRule>("/api/forwards"), loadAll<Route>("/api/routes")]);
            setServers(s);
            setNodes(n);
            setForwards(f);
            setRoutes(r);
            break;
          }
          case "operations":
            setOperations(await loadAll<Operation>("/api/operations"));
            // Leave a list alone once the reader has paged into older entries.
            if (opLog.page === 1) opLog.reload();
            break;
          case "audit":
            if (auditLog.page === 1) auditLog.reload();
            break;
          case "accesses":
            if (accessLog.page === 1) accessLog.reload();
            break;
          case "connections":
            if (connectionLog.page === 1) connectionLog.reload();
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
  const forwardServerIDs = useMemo(() => new Set(forwards.map((f) => f.serverId)), [forwards]);
  // What the agent saw that disagrees with what was entered for this server.
  const serverWarnings = useCallback((s: Server) => {
    const out: string[] = [];
    if (s.detectedIpv4 && s.ipv4 && s.detectedIpv4 !== s.ipv4)
      out.push(`Agent 检测到 IPv4 ${s.detectedIpv4}，与填写的不同`);
    if (s.detectedIpv6 && s.ipv6 && s.detectedIpv6 !== s.ipv6)
      out.push(`Agent 检测到 IPv6 ${s.detectedIpv6}，与填写的不同`);
    if (Math.abs(s.clockSkewSeconds || 0) > 60)
      out.push(`系统时间与面板相差 ${s.clockSkewSeconds} 秒，请检查时间同步`);
    if (s.firewallConflict && !manualFirewall(s))
      out.push(`${s.firewallConflict} 正在管理防火墙，面板已停止写入 UFW`);
    return out;
  }, []);
  const fwServer = useMemo(() => servers.find((s) => s.id === firewallServer) || servers[0], [servers, firewallServer]);
  const fwNodes = useMemo(() => nodes.filter(
    (n) => n.serverId === fwServer?.id && n.enabled && !n.deleting,
  ), [nodes, fwServer]);
  const fwRules = useMemo(() => rules.filter((r) => r.serverId === fwServer?.id), [rules, fwServer]);
  // Host rules ticked for a batch action, by rule text. Only rules still
  // reported and removable count, so a refreshed list drops stale picks.
  const [hostPicked, setHostPicked] = useState<string[]>([]);
  const fwHostRules = useMemo(
    () => (fwServer?.ufwRules || []).map((line) => ({ line, rule: parseHostRule(line) })),
    [fwServer],
  );
  const hostSelectable = useMemo(
    () => fwHostRules.flatMap(({ rule }) => (rule && hostRuleRemovable(rule, fwServer?.sshPorts || []) ? [rule] : [])),
    [fwHostRules, fwServer],
  );
  const hostSelected = useMemo(() => hostSelectable.filter((r) => hostPicked.includes(r.rule)), [hostSelectable, hostPicked]);
  useEffect(() => setHostPicked([]), [fwServer?.id]);
  const selectedNodeServer = servers.find((s) => s.id === nodeForm.serverId);
  const nodeCoreMissing = !!selectedNodeServer && canHostNodes(selectedNodeServer) && !selectedNodeServer.coreBuild &&
    (!!selectedNodeServer.agentVersion || !selectedNodeServer.roles?.includes("exit"));
  const selectedFormServer = servers.find((s) => s.id === serverForm.id);
  const serverManagementChanged = !!selectedFormServer && (selectedFormServer.managementMode === "offline") !== (serverForm.managementMode === "offline");
  const serverProxyEnabled = serverForm.managementMode !== "offline";
  const serverProxyOptions = nodes.filter((n) => n.protocol === "socks5").map((node) => {
    const host = servers.find((s) => s.id === node.serverId);
    const reason = node.serverId === serverForm.id ? "不能代理自身" : node.deleting ? "正在删除" : !node.enabled ? "已停用" :
      !host ? "服务器不存在" : host.managementMode === "offline" ? "代理服务器为离线管理" :
      manualFirewall(host) ? "代理服务器需 UFW 托管" : host.ufwStatus !== "active" ? "代理服务器未启用 UFW" :
      host.firewallConflict ? "代理服务器存在防火墙冲突" : node.firewallPolicy === "manual" ? "节点端口需由 UFW 管理" :
      node.status !== "active" ? "配置尚未成功应用" : "";
    return { node, host, reason };
  });
  const serverFormCoreMissing = !!serverForm.id && !!serverForm.agentVersion && canHostNodes(serverForm) && !selectedFormServer?.coreBuild;
  const serverFormCoreInstalling = operations.some((o) => o.serverId === serverForm.id &&
    ["agent.upgrade", "core.upgrade"].includes(o.kind) && ["queued", "running", "activating"].includes(o.status));
  const nodeCoreInstalling = operations.some((o) => o.serverId === nodeForm.serverId &&
    ["agent.upgrade", "core.upgrade"].includes(o.kind) && ["queued", "running", "activating"].includes(o.status));
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
  // What a node's port really admits: route-only nodes admit their routes'
  // last hops, direct ones what the administrator chose (plus route hops).
  const nodeAccessText = (n: Node) => {
    if (manualFirewall(servers.find((s) => s.id === n.serverId))) return "外部管理（来源限制自行配置）";
    const routeHops = (n.routeSources || "").split(",").filter(Boolean);
    const agentSources = (n.agentProxySources || "").split(",").filter(Boolean);
    if (!n.direct) return [routeHops.length ? "链路：" + routeHops.join("、") : "", agentSources.length ? "Agent：" + agentSources.join("、") : ""].filter(Boolean).join("；") || "不开放（无链路或 Agent 使用）";
    if (n.firewallPolicy === "manual") return "手动管理";
    if (n.firewallPolicy === "restricted") return [...new Set([...n.firewallSources.split(","), ...routeHops, ...agentSources])].filter(Boolean).join("、");
    return "任意来源";
  };
  const serverName = useCallback((id: string) =>
    servers.find((s) => s.id === id)?.name || id.slice(0, 8), [servers]);
  // Nodes and routes of a subscription whose configuration is not live yet.
  const pendingNodes = useCallback((sub: Subscription) => [
    ...(sub.pendingNodeIds || []).map((id) => nodes.find((item) => item.id === id)).filter((n): n is Node => !!n).map((n) => {
      const server = servers.find((item) => item.id === n.serverId);
      return `${n.name}（${server?.name || "未知服务器"}${server && server.status !== "online" ? "，离线" : ""}）`;
    }),
    ...(sub.pendingRouteIds || []).map((id) => routes.find((r) => r.id === id)).filter((r): r is Route => !!r).map((r) => `链路 ${r.name}`),
  ], [nodes, routes, servers]);
  const pendingSummary = useCallback((sub: Subscription) => pendingNodes(sub).join("、"), [pendingNodes]);
  // Every node a subscription has a login on: its direct nodes and the exit
  // nodes of its routes.
  const subNodeIds = useCallback((sub: Partial<Subscription>) => [
    ...(sub.nodeIds || []),
    ...(sub.routeIds || []).map((id) => routes.find((r) => r.id === id)?.nodeId || ""),
  ].filter(Boolean), [routes]);
  const subMemberNodes = (sub: Partial<Subscription>) => {
    const ids = new Set(subNodeIds(sub));
    return nodes.filter((n) => ids.has(n.id));
  };
  const sharedSubNodes = (sub: Partial<Subscription>) => subMemberNodes(sub).filter(sharedSubscriptionPassword);
  const onlySharedSubNodes = (sub: Partial<Subscription>) => {
    const members = subMemberNodes(sub);
    return members.length > 0 && members.every(sharedSubscriptionPassword);
  };
  const routePath = (r: Route) => {
    const node = nodes.find((n) => n.id === r.nodeId);
    return [
      serverName(r.entryServerId),
      ...r.hops.map((h) => h.serverIds.map(serverName).join(h.balance === "round-robin" ? " + " : " / ") + (h.internal ? "（内网）" : "")),
      (node ? `${node.name}@${serverName(node.serverId)}` : "已删除节点") + (r.nodeInternal ? "（内网）" : ""),
    ].join(" → ");
  };
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
    setError("");
    setNotice("");
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
        ? { ...n, snellPort: n.snellPort || 20000 + n.port % 10000, password: "", shadowTlsPassword: "" }
        : { ...emptyNode, serverId: servers.find((s) => canHostNodes(s))?.id || "" },
    );
    setModal("node");
  };
  const randomizeNodePort = () => {
    const server = servers.find((s) => s.id === nodeForm.serverId);
    const occupied = new Set([
      nodeForm.port || 0,
      nodeForm.protocol === "snell" ? nodeForm.snellPort || 0 : 0,
      ...nodes.filter((n) => n.serverId === nodeForm.serverId).flatMap((n) => [n.port, n.protocol === "snell" ? n.snellPort || 20000 + n.port % 10000 : 0]),
      ...forwards.filter((f) => f.serverId === nodeForm.serverId && f.enabled && !f.deleting).map((f) => f.port),
      ...(server?.sshPorts || []),
    ]);
    try {
      setNodeForm({ ...nodeForm, port: generatePort(occupied) });
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const matchingCertificate = useCallback((tlsName: string) =>
    certificates.find(
      (c) =>
        (c.dnsNames?.length ? c.dnsNames : [c.domain]).some((pattern) => {
          const name = tlsName.toLowerCase().replace(/\.$/, "");
          const domain = pattern.toLowerCase().replace(/\.$/, "");
          return domain === name || domain.startsWith("*.") && name.endsWith(domain.slice(1)) && name.split(".").length === domain.split(".").length;
        }) &&
        new Date(c.expiresAt).getTime() > Date.now(),
    )?.id || "", [certificates]);
  const useTemplate = async (template: NodeTemplate, serverId = nodeForm.serverId || "") => {
    const request = ++templateRequest.current;
    setError("");
    setTemplateLoading(true);
    try {
      const detail = await api<NodeTemplate & { password: string; shadowTlsPassword: string }>(`/api/node-templates/${template.id}`);
      if (request !== templateRequest.current) return;
      const selectedServer = serverId || servers.find((s) => canHostNodes(s))?.id || "";
      setNodeForm({
        ...emptyNode,
        serverId: selectedServer,
        name: detail.name,
        protocol: detail.protocol,
        username: detail.username || "",
        port: detail.port,
        listen: detail.listen,
        method: detail.method,
        snellVersion: detail.snellVersion,
        snellPort: detail.snellPort || 20000 + detail.port % 10000,
        obfs: detail.obfs,
        shadowTlsHost: detail.shadowTlsHost,
        tlsName: detail.tlsName,
        certificateId:
          detail.protocol === "anytls"
            ? matchingCertificate(detail.tlsName)
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
            username: source.username || "",
            port: source.port,
            listen: source.listen,
            method: source.method,
            snellVersion: source.snellVersion,
            snellPort: source.snellPort || 20000 + source.port % 10000,
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
    if (modal === "certificate") {
      setCertForm({ name: "", domain: "", pem: "", key: "" });
      setCertFilesBusy({ pem: false, key: false });
    }
    clearSelectedTemplate();
    setModal(null);
    setIssuedURL("");
  };
  const submitServer = async (e: React.FormEvent) => {
    e.preventDefault();
    const ok = await act(async () => {
      if (serverForm.id) {
        const saved = await mutation<Server>("/api/servers/" + serverForm.id, "PATCH", serverForm);
        if (serverManagementChanged) {
          setModal(null);
          if (saved.managementMode === "offline") { setOfflineServer(saved); return; }
          const guide = await mutation<InstallGuide>("/api/servers/" + saved.id + "/enrollment", "POST");
          setInstallMethod("offline");
          setInstallArch(saved.arch === "arm64" ? "arm64" : "amd64");
          setInstallInfo({ ...guide, serverName: saved.name });
        }
      } else {
        const result = await mutation<InstallGuide & { server: Server }>(
          "/api/servers",
          "POST",
          serverForm,
        );
        setModal(null);
        if (serverForm.managementMode === "offline") { setOfflineServer(result.server); return; }
        setInstallMethod("online");
        setInstallArch("amd64");
        setInstallInfo({ ...result, serverName: serverForm.name || "新服务器" });
        return;
      }
    }, serverManagementChanged ? "管理方式已保存；请按迁移指南在目标机完成切换" : serverFormCoreMissing ? "服务器类型已保存；尚未安装 sing-box，请在服务器列表安装后创建节点" : "服务器已保存");
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
            { ...nodeForm, ...(nodeForm.id ? {} : { templateId: selectedTemplate }), ...(manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) ? { firewallPolicy: "manual", firewallSources: "" } : {}) },
          ),
        nodeFirewallUnsupported || nodeForm.protocol === "snell" && !servers.find((s) => s.id === nodeForm.serverId)?.snellFixedPort
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
    if (!certForm.pem?.trim() || !certForm.key?.trim()) {
      setError("请选择证书 .pem 和私钥 .key 文件，或粘贴对应的 PEM 内容。");
      return;
    }
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
        () => mutation("/api/firewall" + (ruleForm.id ? "/" + ruleForm.id : ""), ruleForm.id ? "PATCH" : "POST", ruleForm),
        ruleForm.id ? "规则已修改，等待 Agent 应用" : ruleForm.replaceHostRule ? "已提交：先删除主机原规则，再由面板创建新规则" : "UFW 规则已提交",
      )
    )
      close();
  };
  const editHostRule = (server: Server, r: HostRule) => {
    setRuleForm({
      ...emptyRule, serverId: server.id, portFrom: r.portFrom, portTo: r.portTo, network: r.network || "tcp",
      source: r.source === "Anywhere" ? "" : r.source, action: r.action === "DENY" ? "deny" : "allow", comment: "", replaceHostRule: r.rule,
      family: r.v6 ? "ipv6" : "ipv4",
    });
    setModal("rule");
  };
  // One job for the whole batch: the agent removes every rule, each with its
  // IPv6 twin, or none of them if one is refused.
  const deleteHostRules = (server: Server, list: HostRule[]) => {
    setConfirmation({
      title: "删除主机规则",
      message: `确定从「${server.name}」删除以下 ${list.length} 条 UFW 规则？\n${list.map((r) => r.rule).join("\n")}\n每行单独删除：删除 IPv6 规则不影响同端口的 IPv4 规则，反之亦然。`,
      confirmLabel: "删除",
      onConfirm: () => {
        void act(async () => {
          await mutation("/api/servers/" + server.id + "/ufw/delete", "POST", { rules: list.map((r) => r.rule) });
          setHostPicked([]);
        }, "删除任务已排队，Agent 执行后列表会更新");
      },
    });
  };
  const adoptHostRules = (server: Server, list: HostRule[]) => {
    setConfirmation({
      title: "转为面板管理",
      message: `将以下 ${list.length} 条规则按原端口、协议、来源和动作转为自定义规则？\n${list.map((r) => r.rule).join("\n")}\n主机上的原规则会先删除，再由面板写回并在以后管理。`,
      confirmLabel: "转换",
      onConfirm: () => {
        void act(async () => {
          await mutation("/api/servers/" + server.id + "/ufw/adopt", "POST", { rules: list.map((r) => r.rule) });
          setHostPicked([]);
        }, "已提交：先删除主机原规则，再由面板写回");
      },
    });
  };
  const doSubmitForward = async () => {
    const path = "/api/forwards" + (forwardForm.id ? "/" + forwardForm.id : "");
    const body = { ...forwardForm, targets: parseTargets(forwardTargets), ...(manualFirewall(servers.find((s) => s.id === forwardForm.serverId)) ? { firewallPolicy: "manual", firewallSources: "" } : {}) };
    const server = servers.find((s) => s.id === forwardForm.serverId);
    const message = server?.managementMode === "offline" ? "转发已保存，请导出离线配置并在目标机应用" : body.network === "tcp+udp" && !server?.forwardTcpUdp ? "转发已保存，请先升级 Agent 至 0.6.7" : "转发配置已提交，等待 Agent 应用";
    if (await act(() => mutation(path, forwardForm.id ? "PATCH" : "POST", body), message)) close();
  };
  const openForward = (f?: ForwardRule) => {
    const form = f ? { ...f } : { ...emptyForward, serverId: servers[0]?.id || "" };
    setForwardForm(form);
    setForwardTargets(targetsText(form.targets));
    setModal("forward");
  };
  const openRoute = (r?: Route) => {
    setRouteForm(r ? { ...r, hops: r.hops.map((h) => ({ ...h, serverIds: [...h.serverIds] })) } : { ...emptyRoute });
    setModal("route");
  };
  const submitRoute = async (e: React.FormEvent) => {
    e.preventDefault();
    const path = "/api/routes" + (routeForm.id ? "/" + routeForm.id : "");
    if (await act(() => mutation(path, routeForm.id ? "PATCH" : "POST", routeForm), "链路已保存，各跳转发等待 Agent 应用")) close();
  };
  const submitForward = async (e: React.FormEvent) => {
    e.preventDefault();
    // Opening a forward to the whole internet needs an explicit confirm.
    if (forwardForm.firewallPolicy === "all" && !manualFirewall(servers.find((s) => s.id === forwardForm.serverId))) {
      setConfirmation({
        title: "确认公开转发",
        message: `转发「${forwardForm.name || ""}」将放行所有来源，目标 ${forwardTargets.split("\n").filter(Boolean).join("、")} 会暴露给全网。确定公开吗？如只需特定来源，请改用“仅放行指定 IP / CIDR”。`,
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
      setIssuedFormat(subForm.format || "");
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
  const deleteItem = (path: string, label: string, feedback?: { message: string; success: string }) => {
    setConfirmation({
      title: `删除${label}`,
      message: feedback?.message || `确定删除${label}？此操作无法撤销。`,
      confirmLabel: "删除",
      onConfirm: () => { void act(() => mutation(path, "DELETE"), feedback?.success || `${label}已删除`); },
    });
  };
  const deleteServer = (s: Server) => {
    const owned =
      nodes.some((n) => n.serverId === s.id) ||
      rules.some((r) => r.serverId === s.id) ||
      forwards.some((f) => f.serverId === s.id);
    if (!owned || s.status === "online")
      return deleteItem("/api/servers/" + s.id, "服务器");
    setConfirmation({
      title: "强制删除服务器",
      message: `服务器「${s.name}」已离线，无法确认节点已停止。\n强制删除会同时移除它的节点、转发、规则和流量记录，且不可恢复。`,
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
  const forwardServers = useMemo(() => new Map(servers.map((s) => [s.id, s])), [servers]);
  const forwardRoutes = useMemo(() => new Map(routes.map((r) => [r.id, r])), [routes]);
  const forwardStatuses = useMemo(() => [...new Set(forwards.map((f) =>
    forwardDisplayStatus(f, forwardServers.get(f.serverId)) || "unknown",
  ))].sort(), [forwards, forwardServers]);
  const forwardFiltersActive = Object.values(forwardFilters).some(Boolean);
  const visibleForwards = useMemo(() => forwards.filter((f) => {
    const server = forwardServers.get(f.serverId);
    return (!forwardFilters.serverId || f.serverId === forwardFilters.serverId) &&
      (!forwardFilters.network || f.network === forwardFilters.network) &&
      (!forwardFilters.source || (forwardFilters.source === "route" ? !!f.routeId : !f.routeId)) &&
      (!forwardFilters.status || (forwardDisplayStatus(f, server) || "unknown") === forwardFilters.status) &&
      matches(forwardFilters.query, f.name, server?.name, server?.ipv4, server?.ipv6,
        f.listen, String(f.port), forwardRoutes.get(f.routeId || "")?.name,
        ...f.targets.map((t) => `${t.host}:${t.port}`));
  }), [forwards, forwardFilters, forwardServers, forwardRoutes, matches]);
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
    if (sv.managementMode === "offline" && (!sv.offlineExportedAt || sv.offlineExportedRevision !== sv.revision))
      attention.push({ tone: "info", tab: "servers", text: `服务器 ${sv.name} 的离线配置待导出并在目标机应用` });
    else if (sv.status === "offline")
      attention.push({ tone: "bad", tab: "servers", text: `服务器 ${sv.name} 离线，最后上报于 ${sv.lastSeen ? new Date(sv.lastSeen).toLocaleString() : "未知时间"}` });
    else if (sv.status === "pending")
      attention.push({ tone: "info", tab: "servers", text: `服务器 ${sv.name} 尚未接入 Agent` });
    else {
      if (!manualFirewall(sv) && sv.ufwStatus && sv.ufwStatus !== "active" && !sv.firewallConflict)
        attention.push({ tone: "warn", tab: "servers", text: `服务器 ${sv.name} 的 UFW 未启用，请初始化 UFW 或选择手动管理防火墙` });
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
      attention.push({ tone: "warn", tab: "subscriptions", text: `订阅 ${sub.name} 有 ${waiting.length} 项尚未生效：${pendingSummary(sub)}` });
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
  const redactScreenshot = useMemo(() => {
    const entries: [string, string][] = [];
    const add = (value: string | undefined, label = "[已隐藏]") => { if (value) entries.push([value, label]); };
    for (const [records, label] of [[servers, "服务器"], [nodes, "节点"], [subs, "订阅"], [customers, "客户"], [routes, "链路"], [forwards, "转发"], [certificates, "证书"], [templates, "模板"]] as const) {
      [...records].sort((a, b) => a.id.localeCompare(b.id)).forEach((record, i) => { add(record.name, `${label} ${i + 1}`); add(record.id, "[标识已隐藏]"); add(record.id.slice(0, 8), "[标识已隐藏]"); });
    }
    for (const server of servers) for (const value of [server.ipv4, server.ipv6, server.detectedIpv4, server.detectedIpv6, server.domain, server.internalAddress, server.notes, server.tags]) add(value);
    for (const node of nodes) for (const value of [node.publishAddress, node.shadowTlsHost, node.tlsName, node.firewallSources, node.routeSources, node.agentProxySources, node.error]) add(value);
    for (const forward of forwards) { forward.targets?.forEach((target) => add(target.host)); add(forward.firewallSources); add(forward.error); }
    customers.forEach((customer) => add(customer.notes));
    routes.forEach((route) => add(route.notes));
    certificates.forEach((cert) => add(cert.domain));
    return screenshotText(entries);
  }, [servers, nodes, subs, customers, routes, forwards, certificates, templates]);
  const protectScreenshot = (tree: React.ReactNode) => screenshotMode
    ? screenshotView(tree, redactScreenshot, new Set([SecretField, SecretTextarea, MaskedValue, CertificateFileField])) : tree;
  const surgeImportHelp = (value: string) => {
    const line = `MUI = select, policy-path=${value}, update-interval=3600`;
    return <div className="surgeImportHelp">
      <p className="hint">导入 Surge 节点：编辑正在使用的配置，把下面这一行放进已有的 [Proxy Group] 段，保存并重新加载。然后把 MUI 加入现有规则所使用的代理组，即可从 MUI 组中选择节点。</p>
      <MaskedValue value={line} pre><button className="ghost" type="button" onClick={() => void copy(line)}>复制 Surge 代理组配置</button></MaskedValue>
      <p className="hint">本链接提供节点列表。通过 policy-path 引用会自动更新节点；不要把它当完整配置安装，否则会提示“规则必须以 FINAL 结尾”。已有配置的分流规则继续使用。</p>
    </div>;
  };
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
  return protectScreenshot(
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
            <span className="headerRefreshStatus" role="status" aria-live="polite">{refreshing ? "刷新中…" : ""}</span>
            <button className={"iconButton" + (refreshing ? " refreshing" : "")} type="button" disabled={refreshing} aria-busy={refreshing} onClick={() => void refresh(true)} aria-label={refreshing ? "刷新中" : "刷新"} title={refreshing ? "刷新中…" : "刷新"}><Icon name="refresh" /></button>
            <button className="iconButton" type="button" aria-pressed={screenshotMode} onClick={() => { const enabled = !screenshotMode; setScreenshotMode(enabled); localStorage.setItem("mui-screenshot-mode", String(enabled)); }} aria-label={screenshotMode ? "关闭截图脱敏" : "开启截图脱敏"} title={screenshotMode ? "关闭截图脱敏" : "开启截图脱敏"}><Icon name="privacy" /></button>
            <button className="iconButton" type="button" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label={theme === "dark" ? "切换浅色模式" : "切换深色模式"} title={theme === "dark" ? "切换浅色模式" : "切换深色模式"}><Icon name={theme === "dark" ? "sun" : "moon"} /></button>
          </div>
        </header>
        {screenshotMode && <div className="banner warning" role="status">截图脱敏已开启：名称、地址、凭据已隐藏，表单暂时只读。关闭后恢复显示。</div>}
        {error && !modal && (
          <div className="banner error" role="alert">
            {error}
            <button onClick={() => setError("")}>×</button>
          </div>
        )}
        {notice && !modal && (
          <div className="banner success" role="status">
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
              <div className="headerActions">
                <button className="ghost" onClick={() => setAgentDownloads({ arch: "amd64" })}>下载 Agent</button>
                <button className="primary" onClick={() => openServer()}>新建服务器</button>
              </div>
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
                    <th title="Agent 开始采样后的默认网卡累计收发量，包含系统流量、SSH、程序下载和 Agent 通信；不是节点或订阅用量。">整机累计流量</th>
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
                          {s.managementMode === "offline" ? "离线管理" : s.os || "待接入"}{s.arch && ` · ${s.arch}`}
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
                      <td className="mono">{s.domain || s.ipv4 || s.ipv6}{s.internalAddress && <small>内网 {s.internalAddress}</small>}</td>
                      <td>
                        <Status value={s.status} />
                        {s.managementMode === "offline" ? <>
                          <small>{s.offlineExportedAt ? `已导出版本 ${s.offlineExportedRevision}` : "尚未导出配置"}</small>
                          {(!s.offlineExportedAt || s.offlineExportedRevision !== s.revision) && <small className="dangerText">配置待导出 · 版本 {s.revision || 1}</small>}
                          <small>实时连通性未知</small>
                        </> : <>
                        <small>{s.agentVersion || "未接入"}</small>
                        {s.agentSelfUpdate && agentReleases[s.arch] && <small>{s.agentBuild === agentReleases[s.arch] ? "已是当前构建" : "有可用升级"}</small>}
                        {!s.agentSelfUpdate && !!s.agentVersion && <small>需先人工升级一次</small>}
                        {!!s.agentVersion && <small>{s.releaseKeyPinned ? "升级需发布签名" : "升级未启用签名校验"}</small>}
                        <small>{rolesText(s.roles)} · sing-box：{s.coreBuild ? s.coreVersion || "版本待上报" : "未安装"}</small>
                        {s.coreSelfUpdate && !!s.coreBuild && coreReleases[s.arch] && <small>{s.coreBuild === coreReleases[s.arch] ? "核心已是当前构建" : "核心有可用升级"}</small>}
                        {!s.coreSelfUpdate && !!s.agentVersion && <small>升级 Agent 后可一键升级核心</small>}
                        {operations.some((o) => o.serverId === s.id && ["agent.upgrade", "core.upgrade"].includes(o.kind) && ["queued", "running", "activating"].includes(o.status)) && <small>程序升级进行中，详情见操作记录</small>}
                        </>}
                      </td>
                      <td>
                        <Status
                          value={manualFirewall(s) ? "manual" : s.firewallConflict ? "conflict" : s.ufwStatus}
                        />
                      </td>
                      <td>
                        {s.managementMode === "offline" ? "不可远程获取" : <Status value={s.statsStatus} />}
                      </td>
                      <td title="↓ 网卡接收，↑ 网卡发送。包含本机所有经过默认网卡的流量。">
                        {s.managementMode === "offline" ? "—" : <small>
                          ↓ {bytes(s.networkRx || 0)}
                          <br />↑ {bytes(s.networkTx || 0)}
                        </small>}
                      </td>
                      <td>{nodes.filter((n) => n.serverId === s.id).length}</td>
                      <td>
                        <div className="actions">
                          <button onClick={() => openServer(s)}>编辑</button>
                          {s.managementMode === "offline" && <button onClick={() => setOfflineServer(s)}>离线配置</button>}
                          <ActionMenu>
                          {s.managementMode !== "offline" && <>
                          <button
                            disabled={!s.agentSelfUpdate || !agentReleases[s.arch] || s.agentBuild === agentReleases[s.arch] || operations.some((o) => o.serverId === s.id && ["agent.upgrade", "core.upgrade"].includes(o.kind) && ["queued", "running", "activating"].includes(o.status))}
                            title={!s.agentSelfUpdate ? "当前 Agent 不支持自更新；请先手动安装新版一次"
                              : !agentReleases[s.arch] ? "面板缺少该架构的 Agent 构建文件"
                              : s.agentBuild === agentReleases[s.arch] ? "已是面板上的最新构建；改了 Agent 代码后需先运行 deploy/build-agent.sh 重新构建，再用 publish.sh --with-agent 发布"
                              : operations.some((o) => o.serverId === s.id && ["agent.upgrade", "core.upgrade"].includes(o.kind) && ["queued", "running", "activating"].includes(o.status)) ? "已有升级任务在进行，详情见操作记录"
                              : "从面板下载并校验新版本，节点服务继续运行"}
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
                            {s.coreBuild ? "一键升级 sing-box" : canHostNodes(s) ? "安装 sing-box" : "安装 sing-box 并设为落地"}
                          </button>
                          <button
                            onClick={() =>
                              act(async () => {
                                const v = await mutation<InstallGuide>(
                                  "/api/servers/" + s.id + "/enrollment",
                                  "POST",
                                );
                                setInstallMethod("online");
                                setInstallArch(s.arch === "arm64" ? "arm64" : "amd64");
                                setInstallInfo({ ...v, serverName: s.name });
                              }, "首次接入 / 手动修复命令已生成")
                            }
                          >
                            首次接入 / 手动修复
                          </button>
                          <button
                            disabled={manualFirewall(s) || s.ufwStatus === "active" || s.status !== "online"}
                            title={manualFirewall(s) ? "手动管理模式不操作 UFW" : s.ufwStatus === "active" ? "UFW 已启用" : s.status !== "online" ? "服务器不在线" : ""}
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
                          </>}
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
                <p>SS、Snell、AnyTLS 与 SOCKS5 节点配置及流量</p>
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
                      <option value="socks5">SOCKS5</option>
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
                        <small>{n.direct ? "允许直连" : n.agentProxySources ? "链路 / Agent 访问" : "仅链路访问"}</small>
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
                        {t.protocol === "ss" ? t.method : t.protocol === "socks5" ? `用户名：${t.username || "未设置"}` : t.protocol === "snell" ? `ShadowTLS v3 · ${t.shadowTlsHost || "未配置"}` : t.tlsName}
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
                <p>统一证书库，可供多台服务器的 AnyTLS 节点复用，私钥加密保存</p>
              </div>
              <button
                className="primary"
                onClick={() => {
                  setCertForm({
                    name: "",
                    domain: "",
                    pem: "",
                    key: "",
                  });
                  setModal("certificate");
                  setCertFilesBusy({ pem: false, key: false });
                  setError(""); setNotice("");
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
                    <th>使用节点</th>
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
                      <td>{nodes.filter((n) => n.certificateId === c.id).length} 个节点</td>
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
                    manualFirewall(fwServer) ? "manual" : fwServer.firewallConflict ? "conflict" : fwServer.ufwStatus
                  }
                />
              )}
            </div>
            {manualFirewall(fwServer) && <div className="banner warning">该服务器为手动管理防火墙，此页规则仅供查看。面板不修改 UFW；节点及转发端口、指定来源和仅链路访问限制，请在宿主机、防火墙或安全组自行配置。</div>}
            {fwServer?.firewallConflict && !manualFirewall(fwServer) && (
              <div className="banner warning">
                {fwServer.firewallConflict}{" "}
                正在管理这台服务器的防火墙。为避免两套规则互相覆盖，面板不会写入
                UFW；请先停用它。
              </div>
            )}
            <fieldset className="firewallControls" disabled={manualFirewall(fwServer)}>
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
                      <th>地址族</th>
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
                        <td>{r.family === "ipv4" ? "IPv4" : r.family === "ipv6" ? "IPv6" : r.source ? (r.source.includes(":") ? "IPv6" : "IPv4") : "IPv4 + IPv6"}</td>
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
                          <div className="actions">
                            <button disabled={r.deleting} onClick={() => { setRuleForm({ ...r }); setModal("rule"); }}>修改</button>
                            <button
                              className="dangerText"
                              onClick={() =>
                                deleteItem("/api/firewall/" + r.id, "规则")
                              }
                            >
                              删除
                            </button>
                          </div>
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
                        <td className="mono">{nodeAccessText(n)}</td>
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
                    。主机上手动添加的规则可勾选后批量删除，或转为面板管理的自定义规则；面板生成的规则请在对应位置修改
                    {fwServer?.sshPorts?.length
                      ? `；SSH 端口 ${fwServer.sshPorts.join("、")}`
                      : ""}
                  </p>
                </div>
                {fwServer && hostSelectable.length > 0 && (
                  <div className="actions">
                    <button
                      disabled={!hostSelected.length || !hostSelected.every(hostRuleConvertible)}
                      title={hostSelected.every(hostRuleConvertible) ? "按原端口、协议、来源和动作转为自定义规则" : "所选规则中有同时放行 TCP 和 UDP、应用配置或 REJECT/LIMIT 规则，不能直接转换"}
                      onClick={() => adoptHostRules(fwServer, hostSelected)}
                    >转为面板管理{hostSelected.length ? `（${hostSelected.length}）` : ""}</button>
                    <button className="dangerText" disabled={!hostSelected.length} onClick={() => deleteHostRules(fwServer, hostSelected)}>
                      删除所选{hostSelected.length ? `（${hostSelected.length}）` : ""}
                    </button>
                  </div>
                )}
              </div>
              {fwServer?.ufwRules?.length ? (
                <div className="tableWrap">
                  <table>
                    <thead><tr>
                      <th>
                        <input
                          type="checkbox"
                          aria-label="全选可处理的规则"
                          disabled={!hostSelectable.length}
                          checked={hostSelectable.length > 0 && hostSelected.length === hostSelectable.length}
                          onChange={(e) => setHostPicked(e.target.checked ? hostSelectable.map((r) => r.rule) : [])}
                        />
                      </th>
                      <th>编号</th><th>规则</th><th>归属</th><th>操作</th>
                    </tr></thead>
                    <tbody>
                      {fwHostRules.map(({ line, rule: r }) => {
                        if (!r) return <tr key={line}><td /><td /><td className="mono" colSpan={3}>{line}</td></tr>;
                        const custom = r.tag.startsWith("mui-") ? fwRules.find((x) => "mui-" + x.id === r.tag) : undefined;
                        const node = r.tag.startsWith("mui-node-") ? nodes.find((n) => r.tag.startsWith("mui-node-" + n.id + "-")) : undefined;
                        const fwd = r.tag.startsWith("mui-forward-") ? forwards.find((f) => r.tag.startsWith("mui-forward-" + f.id + "-")) : undefined;
                        const owner = r.tag === "mui-ssh" ? "SSH（初始化 UFW 时创建）"
                          : custom ? "自定义规则"
                          : node ? `节点 ${node.name}`
                          : fwd ? `${fwd.routeId ? "链路转发" : "转发"} ${fwd.name}`
                          : r.tag.startsWith("mui-route-priority-") ? "节点 / 链路优先规则"
                          : r.tag.startsWith("panel-") ? "旧版面板规则，下次应用时清理"
                          : r.tag ? "面板规则（对象已删除，下次应用时清理）"
                          : "主机手动添加";
                        const ssh = !r.tag && hostRuleAdmitsSSH(r, fwServer.sshPorts || []);
                        const editable = hostRuleConvertible(r);
                        const removable = hostRuleRemovable(r, fwServer.sshPorts || []);
                        return (
                          <tr key={line}>
                            <td>
                              {removable && (
                                <input
                                  type="checkbox"
                                  aria-label={`选择规则 ${r.index}`}
                                  checked={hostPicked.includes(r.rule)}
                                  onChange={(e) => setHostPicked(e.target.checked ? [...hostPicked, r.rule] : hostPicked.filter((x) => x !== r.rule))}
                                />
                              )}
                            </td>
                            <td className="mono">{r.index}</td>
                            <td className="mono">{r.rule.replace(/\s*#.*$/, "")}</td>
                            <td>{owner}</td>
                            <td>
                              {custom ? (
                                <div className="actions">
                                  <button disabled={custom.deleting} onClick={() => { setRuleForm({ ...custom }); setModal("rule"); }}>修改</button>
                                  <button className="dangerText" onClick={() => deleteItem("/api/firewall/" + custom.id, "规则")}>删除</button>
                                </div>
                              ) : r.tag ? (
                                <span className="hint">—</span>
                              ) : ssh ? (
                                <span className="hint" title="可能放行 SSH 端口，为防止失联请登录服务器手动调整">受保护</span>
                              ) : (
                                <div className="actions">
                                  <button
                                    disabled={!editable}
                                    title={editable ? "改为面板管理的自定义规则，原规则会被删除" : "该规则同时放行 TCP 和 UDP、是应用配置或动作为 REJECT/LIMIT，请删除后在自定义规则中新建"}
                                    onClick={() => editHostRule(fwServer, r)}
                                  >修改</button>
                                  <button className="dangerText" onClick={() => deleteHostRules(fwServer, [r])}>删除</button>
                                </div>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
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
            </fieldset>
          </>
        )}
        {tab === "routes" && (
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>链路</h2>
                <p>入口或线路 → 中转（每跳可多台负载均衡）→ 落地节点。面板在每一跳自动生成转发，整条链路使用同一个端口。</p>
              </div>
              <button className="primary" onClick={() => openRoute()} disabled={!nodes.length}>新建链路</button>
            </div>
            <div className="tableWrap">
              <table>
                <thead><tr><th>名称</th><th>路径</th><th>端口</th><th>落地节点</th><th>状态</th><th>操作</th></tr></thead>
                <tbody>
                  {routes.map((r) => {
                    const node = nodes.find((n) => n.id === r.nodeId);
                    return (
                      <tr key={r.id}>
                        <td><strong>{r.name}</strong>{r.notes && <small>{r.notes}</small>}</td>
                        <td>{routePath(r)}</td>
                        <td className="mono">{r.port}</td>
                        <td>{node ? node.name : "已删除"}{node && <small>{node.protocol.toUpperCase()} · {serverName(node.serverId)}</small>}</td>
                        <td><Status value={r.status || "pending"} /></td>
                        <td><div className="actions">
                          <button onClick={() => openRoute(r)}>编辑</button>
                          <ActionMenu>
                            <button onClick={() => void act(() => mutation("/api/routes/" + r.id, "PATCH", { ...r, enabled: !r.enabled }), r.enabled ? "链路已停用" : "链路已启用")}>{r.enabled ? "停用" : "启用"}</button>
                            <button className="dangerText" onClick={() => deleteItem("/api/routes/" + r.id, "链路")}>删除</button>
                          </ActionMenu>
                        </div></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {!routes.length && <Empty text="暂无链路" />}
            </div>
          </section>
        )}
        {tab === "forwards" && (
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>端口转发</h2>
                <p>支持 TCP、UDP 或 TCP + UDP；双协议共用监听端口与目标，流量合并统计。</p>
              </div>
              <div className="headerActions">
                <button className="ghost" onClick={() => setAgentDownloads({ arch: "amd64" })}>下载 Agent</button>
                <button className="primary" onClick={() => openForward()} disabled={!servers.length}>新建转发</button>
              </div>
            </div>
            {servers.some((s) => forwardServerIDs.has(s.id) && s.managementMode !== "offline" && !manualFirewall(s) && s.ufwStatus && s.ufwStatus !== "active") && (
              <div className="banner warning">有 UFW 托管服务器尚未启用 UFW；请初始化 UFW，或将对应服务器设置为手动管理防火墙。</div>
            )}
            {servers.some((s) => forwardServerIDs.has(s.id) && s.managementMode !== "offline" && !manualFirewall(s) && !!s.firewallConflict) && (
              <div className="banner error">检测到其他防火墙工具正在管理防火墙，面板已停止写入 UFW；请先停用它。</div>
            )}
            <div className="filters forwardFilters">
              <input type="search" value={forwardFilters.query} onChange={(e) => setForwardFilters({ ...forwardFilters, query: e.target.value })} placeholder="搜索名称、IP、端口或链路" aria-label="搜索端口转发" />
              <select aria-label="按服务器筛选转发" value={forwardFilters.serverId} onChange={(e) => setForwardFilters({ ...forwardFilters, serverId: e.target.value })}>
                <option value="">全部服务器</option>
                {servers.map((s) => <option key={s.id} value={s.id}>{s.name}{s.managementMode === "offline" ? "（离线管理）" : ""}</option>)}
              </select>
              <select aria-label="按协议筛选转发" value={forwardFilters.network} onChange={(e) => setForwardFilters({ ...forwardFilters, network: e.target.value })}>
                <option value="">全部协议</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="tcp+udp">TCP + UDP</option>
              </select>
              <select aria-label="按规则来源筛选转发" value={forwardFilters.source} onChange={(e) => setForwardFilters({ ...forwardFilters, source: e.target.value })}>
                <option value="">全部规则来源</option>
                <option value="manual">手动创建</option>
                <option value="route">链路自动生成</option>
              </select>
              <select aria-label="按状态筛选转发" value={forwardFilters.status} onChange={(e) => setForwardFilters({ ...forwardFilters, status: e.target.value })}>
                <option value="">全部状态</option>
                {[...new Set([...forwardStatuses, ...(forwardFilters.status ? [forwardFilters.status] : [])])].map((status) => <option key={status} value={status}>{statusLabels[status]?.[0] || status}</option>)}
              </select>
              {forwardFiltersActive && <button type="button" className="ghost" onClick={() => setForwardFilters({ query: "", serverId: "", network: "", source: "", status: "" })}>清空筛选</button>}
              <span className="hint" role="status">显示 {visibleForwards.length} / {forwards.length} 条</span>
            </div>
            <div className="tableWrap">
              <table>
                <thead><tr><th>名称</th><th>服务器</th><th>监听</th><th>目标</th><th>已转发</th><th>放行来源</th><th>状态</th><th>操作</th></tr></thead>
                <tbody>
                  {visibleForwards.map((f) => {
                    const server = servers.find((s) => s.id === f.serverId);
                    const offline = server?.managementMode === "offline";
                    return (
                      <tr key={f.id}>
                        <td><strong>{f.name}</strong>{f.routeId && <small>链路自动生成</small>}</td>
                        <td>{serverName(f.serverId)}{offline && <small>离线管理</small>}</td>
                        <td className="mono">{f.network.toUpperCase().replace("+", " + ")} {f.listen || "0.0.0.0"}:{f.port}</td>
                        <td className="mono">{f.targets.map((t) => `${t.host}:${t.port}`).join("、")}{f.targets.length > 1 && <small>{f.balance === "round-robin" ? "轮询" : "主备"}</small>}</td>
                        <td>{offline ? <small title="离线机器不向面板回传转发流量">无法远程获取</small> : <>↑ {bytes(f.uplink || 0)} · ↓ {bytes(f.downlink || 0)}</>}</td>
                        <td className="mono">{manualFirewall(server) ? "外部管理" : f.firewallPolicy === "closed" ? "不开放" : f.firewallPolicy === "manual" ? "手动管理" : f.firewallPolicy === "restricted" ? f.firewallSources.split(",").join("、") : "任意来源"}</td>
                        <td title={offline ? "离线配置需手动在目标机应用；面板无法确认应用结果或实时连通性" : undefined}>
                          <Status value={forwardDisplayStatus(f, server)} />
                          {offline ? <small><button className="textButton" onClick={() => setOfflineServer(server)}>离线配置</button></small> : <>
                            {f.error && <small className="hint">{f.error}</small>}
                            {f.network === "tcp+udp" && !server?.forwardTcpUdp && <small className="hint">需升级 Agent 至 0.6.7</small>}
                            {!server?.forwardSupport && <small className="hint">等待 Agent 更新</small>}
                          </>}
                        </td>
                        <td>{f.routeId ? <button className="textButton" style={{ whiteSpace: "nowrap" }} onClick={() => setTab("routes")}>在链路中管理</button> : <div className="actions">
                          <button disabled={f.deleting} onClick={() => openForward(f)}>编辑</button>
                          <button disabled={f.deleting} onClick={() => void act(() => mutation("/api/forwards/" + f.id, "PATCH", { ...f, enabled: !f.enabled }), offline ? "转发配置已保存，请重新导出并在离线目标机应用" : f.enabled ? "转发已停用" : "转发已启用")}>{f.enabled ? "停用" : "启用"}</button>
                          <button className="dangerText" onClick={() => deleteItem("/api/forwards/" + f.id, "转发", offline ? { message: "确定删除这条离线转发？保存后还需导出完整配置并在目标机应用，才会停止该机上的转发。", success: "删除配置已保存，请重新导出并在离线目标机应用" } : undefined)}>删除</button>
                        </div>}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {!visibleForwards.length && <Empty text={forwardFiltersActive ? "没有匹配的转发规则，请调整或清空筛选" : "暂无转发规则"} />}
            </div>
          </section>
        )}
        {tab === "subscriptions" && (
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>订阅管理</h2>
                <p>分发节点和链路；支持独立凭据统计及传统 SS 共享密码</p>
              </div>
              <button
                className="primary"
                onClick={() => {
                  setSubForm({
                    name: "",
                    format: "sing-box",
                    nodeIds: [],
                    routeIds: [],
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
                    <th>内容</th>
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
                        <span className="chip">{s.format === "v2rayn" ? "v2rayN" : s.format}</span>
                      </td>
                      <td>{s.routeIds?.length || 0} 条链路<small>{s.nodeIds?.length || 0} 个直连节点</small></td>
                      <td>
                        {onlySharedSubNodes(s) ? <span className="hint">无法按订阅统计</span> : <button className="textButton" onClick={() => { setSubTraffic([]); setTrafficSub(s); }}>
                          {bytes((s.uplink || 0) + (s.downlink || 0))}
                        </button>}
                        {sharedSubNodes(s).length > 0 && <small>共享密码节点的流量请在节点中查看{onlySharedSubNodes(s) ? "" : "；此处仅统计独立凭据节点"}</small>}
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
                                setIssuedFormat(s.format);
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
                                  ? `停用「${s.name}」？订阅下载链接立即失效。独立用户凭据在 Agent 应用配置后失效。${sharedSubNodes(s).length ? "共享密码的 SS 节点仍可访问，撤销访问需更换节点密码。" : ""}`
                                  : `启用「${s.name}」？`) + restartNotice(subNodeIds(s)),
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
                                    setIssuedFormat(s.format);
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
                                message: `确定删除「${s.name}」？下载链接立即失效，独立用户凭据在 Agent 应用配置后失效。${sharedSubNodes(s).length ? "共享密码的 SS 节点仍可访问，撤销访问需更换节点密码。" : ""}此操作无法撤销。` + restartNotice(subNodeIds(s)),
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
                {issuedFormat === "surge" && surgeImportHelp(issuedURL)}
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
                {visibleCustomers.map((c) => {
                  const memberships = subs.filter((s) => s.customerId === c.id);
                  const shared = memberships.some((s) => sharedSubNodes(s).length > 0);
                  const onlyShared = memberships.length > 0 && memberships.every(onlySharedSubNodes);
                  return <tr key={c.id}>
                  <td><strong>{c.name}</strong></td><td>{c.notes || "—"}</td>
                  <td>{memberships.map((s) => s.name).join("、") || "—"}</td>
                  <td>{onlyShared ? "无法按客户统计" : bytes(memberships.reduce((sum, s) => sum + (s.uplink || 0) + (s.downlink || 0), 0))}{shared && <small>共享密码节点的流量请在节点中查看{onlyShared ? "" : "；此处仅统计独立凭据节点"}</small>}</td>
                  <td><div className="actions"><button onClick={() => { setCustomerForm({ ...c }); setModal("customer"); }}>编辑</button><button className="dangerText" onClick={() => deleteItem("/api/customers/" + c.id, "客户")}>删除</button></div></td>
                </tr>; })}
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
                <DateRange value={accessRange} onChange={setAccessRange} />
              </div>
              <div className="tableWrap"><table><thead><tr><th>时间</th><th>客户</th><th>订阅</th><th>来源 IP</th></tr></thead><tbody>
                {accessLog.items.map((item) => <tr key={item.id}>
                  <td>{new Date(item.at).toLocaleString()}</td>
                  <td>{customers.find((c) => c.id === item.customerId)?.name || "未关联 / 已删除"}</td>
                  <td>{subs.find((s) => s.id === item.subscriptionId)?.name || "已删除"}</td>
                  <td><code>{item.ip}</code></td>
                </tr>)}
              </tbody></table>{accessLog.empty && <Empty text="暂无订阅访问记录" />}</div>
              <Pager log={accessLog} />
            </section>
        )}
        {tab === "connections" && (
            <section className="panel">
              <div className="panelHead"><div><h2>节点连接 IP</h2><p>链路客户端 IP 从入口转发采集（TCP / UDP，需入口 Agent 0.6.13+）；直连节点从 sing-box 采样。中转和 Agent 的对端地址单独标注，不作为客户端 IP。离线入口无法上报，历史记录无法还原；连接来源不代表已通过节点认证，也不能据此确定订阅归属。</p></div></div>
              <div className="filters">
                <select value={connectionServer} onChange={(e) => setConnectionServer(e.target.value)} aria-label="按采集服务器筛选连接 IP">
                  <option value="">全部服务器</option>
                  {servers.map((sv) => <option key={sv.id} value={sv.id}>{sv.name}</option>)}
                </select>
                <DateRange value={connectionRange} onChange={setConnectionRange} label="最近连接" />
              </div>
              <div className="tableWrap"><table><thead><tr><th>最近连接</th><th>采集服务器</th><th>节点 / 链路</th><th>客户端 IP</th><th>采集方式 / 对端地址</th><th>订阅关联</th></tr></thead><tbody>
                {connectionLog.items.map((item) => {
                  const linked = item.sourceKind === "entry"
                    ? subs.filter((s) => !!item.routeId && s.routeIds?.includes(item.routeId))
                    : item.sourceKind === "direct" ? subs.filter((s) => s.nodeIds?.includes(item.nodeId)) : [];
                  const sourceLabel = ({ entry: "入口转发采集", direct: "节点直连采样", relay: "中转 / 服务器对端", agent: "Agent 代理连接", unknown: "仅有落地对端，无法确认客户端" } as Record<string, string>)[item.sourceKind || "unknown"];
                  return <tr key={item.serverId + item.nodeId + item.ip + (item.routeId || "")}>
                    <td>{new Date(item.lastSeen).toLocaleString()}</td>
                    <td>{serverName(item.serverId)}</td>
                    <td>{nodes.find((n) => n.id === item.nodeId)?.name || "已删除"}{item.routeId && <small>{routes.find((r) => r.id === item.routeId)?.name || "历史链路（已删除）"}</small>}</td>
                    <td>{item.clientIp ? <code>{item.clientIp}</code> : <span className="hint">无法获取</span>}</td>
                    <td>{sourceLabel}{item.peerIp && <small>对端：<code>{item.peerIp}</code></small>}</td>
                    <td>{linked.length ? `可能关联：${linked.map((s) => s.name).join("、")}` : "无法归属"}</td>
                  </tr>;
                })}
              </tbody></table>{connectionLog.empty && <Empty text="暂无连接来源记录；链路请升级入口 Agent 至 0.6.13，离线入口无法上报" />}</div>
              <Pager log={connectionLog} />
            </section>
        )}
        {tab === "operations" && (
          <section className="panel">
            <div className="panelHead">
              <div>
                <h2>操作记录</h2>
                <p>查看配置下发、执行结果和失败原因</p>
              </div>
              <button className="ghost" onClick={() => void refresh(true)}>
                刷新
              </button>
            </div>
            <div className="filters">
              <select value={opServer} onChange={(e) => setOpServer(e.target.value)} aria-label="按服务器筛选操作记录">
                <option value="">全部服务器</option>
                {servers.map((sv) => <option key={sv.id} value={sv.id}>{sv.name}</option>)}
              </select>
              <select value={opKind} onChange={(e) => setOpKind(e.target.value)} aria-label="按操作筛选操作记录">
                <option value="">全部操作</option>
                {Object.entries(kindLabels).map(([kind, label]) => <option key={kind} value={kind}>{label}</option>)}
              </select>
              <DateRange value={opRange} onChange={setOpRange} />
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
              {opLog.empty && <Empty text={opServer || opKind || opRange.from || opRange.to ? "没有符合筛选条件的操作记录" : "暂无操作记录"} />}
            </div>
            <Pager log={opLog} />
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
              <DateRange value={auditRange} onChange={setAuditRange} />
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
            <Pager log={auditLog} />
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
      {offlineServer && <OfflineManager server={servers.find((s) => s.id === offlineServer.id) || offlineServer} onClose={() => setOfflineServer(null)} onExported={() => refresh()} onCopy={(v) => void copy(v)} onDownloadAgent={() => setAgentDownloads({ arch: offlineServer.arch || "amd64" })} screenshotMode={screenshotMode} redact={redactScreenshot} />}
      {agentDownloads && <AgentDownloads initialArch={agentDownloads.arch} onClose={() => setAgentDownloads(null)} onCopy={(v) => void copy(v)} screenshotMode={screenshotMode} redact={redactScreenshot} />}
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
            <div className="installMethods" role="group" aria-label="安装方式">
              <button type="button" aria-pressed={installMethod === "online"} onClick={() => setInstallMethod("online")}>在线安装</button>
              <button type="button" disabled={!installInfo.offlineInstall} title={!installInfo.offlineInstall ? "请更新后端后重新生成接入命令" : ""} aria-pressed={installMethod === "offline"} onClick={() => setInstallMethod("offline")}>手工安装</button>
              <button type="button" disabled={!installInfo.standaloneInstall} title={!installInfo.standaloneInstall ? "请更新后端后重新生成接入命令" : ""} aria-pressed={installMethod === "standalone"} onClick={() => setInstallMethod("standalone")}>完全离线转发</button>
            </div>
            {installMethod !== "standalone" && installInfo.offlineInstall?.proxyNotice && <p className="hint commandBox">{installInfo.offlineInstall.proxyNotice}</p>}
            {installMethod !== "standalone" && <ManagementMigration command={installInfo.offlineInstall?.migrationCommand} onCopy={(v) => void copy(v)} />}
            {installMethod === "online" ? <div className="commandBox">
              <strong>在「{installInfo.serverName}」服务器上运行以下命令</strong>
              <p className="hint">命令 10 分钟内有效。运行后会从面板下载并校验文件、接入 Agent；修复时 Agent 会重启，运行中的 sing-box 也可能重启。</p>
              <MaskedValue value={installInfo.installCommand} pre><button className="primary" autoFocus type="button" onClick={() => copy(installInfo.installCommand)}>复制命令</button></MaskedValue>
            </div> : <div className="offlineInstall">
              <p className="hint">{installMethod === "standalone" ? "完全离线转发使用 Agent 0.6.7 的本地模式，无需接入令牌和面板连接，仅安装 mui-forward 服务。此标签用于独立手写配置。需要面板编排链路和订阅时，请将服务器设为“离线管理”，使用列表中的“离线配置”。" : `先在本机下载，再上传到「${installInfo.serverName}」。目标机不下载二进制，但仍需访问面板完成接入和心跳。`}</p>
              <section className="installStep">
                <h3>1. 在本机下载文件</h3>
                <Field label="目标服务器架构">
                  <select value={installArch} onChange={(e) => setInstallArch(e.target.value)}>
                    <option value="amd64">amd64（x86_64 / Intel / AMD）</option>
                    <option value="arm64">arm64（aarch64 / ARM）</option>
                  </select>
                </Field>
                <p className="hint">按目标服务器选择，和本机架构无关。可在目标机执行 <code>uname -m</code> 确认。</p>
                <div className="installDownloads">
                  {localInstallGuide?.downloads.find((d) => d.arch === installArch)?.files.map((file) => <a key={file.name} href={file.url} download={file.name}>{file.name}</a>)}
                </div>
                <button className="ghost" type="button" onClick={() => copy(localInstallGuide!.downloads.find((d) => d.arch === installArch)!.command)}>复制本机下载命令（macOS / Linux）</button>
                <p className="hint">本机下载命令统一保存到 <code>~/mui-install/</code>。</p>
              </section>
              <section className="installStep">
                <h3>2. 上传到目标服务器{installMethod === "standalone" ? "并配置转发" : ""}</h3>
                <p className="hint">通过 SFTP / SCP 将以上文件上传到目标机的 <code>~/mui-install/</code>，全部放在同一目录并保留原文件名。{installMethod === "standalone" ? "离线转发不需要 sing-box，也不操作 UFW。" : "落地服务器包含 sing-box，其他类型只安装 Agent。"}</p>
                <button className="ghost" type="button" onClick={() => copy("mkdir -p ~/mui-install")}>复制目标机建目录命令</button>
                {installMethod === "standalone" && <>
                  <p className="hint">将下面 JSON 保存为 <code>~/mui-install/forwards.json</code>，把 <code>10.0.0.2</code> 改为入口机能访问的下一跳地址，并调整端口。示例使用一条规则同时转发 TCP 和 UDP。</p>
                  <div className="commandBox">
                    <pre>{localInstallGuide?.exampleConfig}</pre>
                    <button className="ghost" type="button" onClick={() => copy(localInstallGuide?.exampleConfig || "")}>复制转发配置示例</button>
                  </div>
                </>}
              </section>
              <section className="installStep">
                <h3>3. 在目标服务器安装</h3>
                <p className="hint">用上传文件的同一用户执行，自动识别 root / sudo。{localInstallGuide?.signed ? "校验摘要及发布签名后安装服务" : "校验摘要后安装服务（面板未配置发布签名）"}；{installMethod === "standalone" ? "重复安装会重启转发服务，现有连接会中断。修改规则请用 offline apply 命令。" : "修复会重启 Agent，运行中的 sing-box 也可能重启。"}</p>
                {installMethod !== "standalone" && <p className="hint">接入令牌 10 分钟有效。若已过期，关闭后重新生成命令；同一发布版本的文件无需重复下载。</p>}
                <div className="commandBox">
                  <MaskedValue value={localInstallGuide?.command || ""} pre><button className="primary" type="button" onClick={() => copy(localInstallGuide!.command)}>{installMethod === "standalone" ? "复制离线安装命令" : "复制手工安装命令"}</button></MaskedValue>
                </div>
                {installMethod === "standalone" && <p className="hint">之后修改配置：<code>mui-agent offline apply ~/mui-install/forwards.json</code>。首次安装和应用以 root 执行；端口放行与下一跳来源白名单需自行配置。</p>}
              </section>
            </div>}
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
          <div className="modal" role="dialog" aria-modal="true" aria-labelledby="edit-modal-title">
            <div className="modalHead">
              <div>
                <h2 id="edit-modal-title">
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
                          ? ruleForm.id ? "修改 UFW 规则" : ruleForm.replaceHostRule ? "接管主机规则" : "新建 UFW 规则"
                          : modal === "route"
                            ? routeForm.id ? "编辑链路" : "新建链路"
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
            {(error || notice) && <div className={"banner modalFeedback " + (error ? "error" : "success")} role={error ? "alert" : "status"}>
              <span>{error ? error.replace(/^\/api\/[^\s:]+:\s*/, "") : notice}</span>
              <button type="button" aria-label={error ? "关闭错误提示" : "关闭操作提示"} onClick={() => error ? setError("") : setNotice("")}>×</button>
            </div>}
            {modal === "server" && (
              <form className="serverForm" onSubmit={submitServer}>
                <section className="serverFormSection" aria-labelledby="server-basic-title">
                  <h3 id="server-basic-title">基本信息</h3>
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
                    <div className="serverFormWide">
                      <Field label="管理方式">
                        <select aria-label="管理方式" value={serverForm.managementMode || "online"} onChange={(e) => {
                          const offline = e.target.value === "offline";
                          const roles = (serverForm.roles || []).filter((r) => r !== "exit");
                          setServerForm({
                            ...serverForm,
                            managementMode: offline ? "offline" : "online",
                            agentProxyNodeId: offline ? "" : serverForm.agentProxyNodeId,
                            agentProxyInternal: offline ? false : serverForm.agentProxyInternal,
                            firewallMode: offline ? "manual" : serverForm.firewallMode,
                            roles: offline ? (roles.length ? roles : ["entry"]) : serverForm.roles,
                          });
                        }}>
                          <option value="online">在线 Agent（连接面板）</option>
                          <option value="offline">离线管理（导出配置 / 本地应用）</option>
                        </select>
                      </Field>
                      <p className="serverFieldHelp">在线 Agent 可直接或通过 SOCKS5 连接面板；离线管理通过导出配置在本机应用，仅支持入口、线路、中转。</p>
                      {serverManagementChanged && <p className="banner warning" role="status">保存后旧 Agent 凭据失效，页面会打开迁移指南。需在目标机停用旧服务并重新安装；保留服务器档案、链路和转发，安装期间会中断转发。已有节点须先删除才能改为离线管理。</p>}
                    </div>
                    <div className="serverFormWide">
                      <fieldset className="serverRoles">
                        <legend>类型（可多选） *</legend>
                        <div className="checkRow">
                          {roleOrder.map((role) => (
                            <label className="check" key={role}>
                              <input
                                type="checkbox"
                                disabled={serverForm.managementMode === "offline" && role === "exit"}
                                checked={serverForm.roles?.includes(role) || false}
                                onChange={(e) => setServerForm({
                                  ...serverForm,
                                  roles: e.target.checked ? [...(serverForm.roles || []), role] : (serverForm.roles || []).filter((r) => r !== role),
                                })}
                              />
                              {roleLabels[role]}
                            </label>
                          ))}
                        </div>
                      </fieldset>
                      <p className="serverFieldHelp">入口、线路可作为首跳；中转、线路可作为中间跳；在线中转和落地都可搭建节点。</p>
                      <p className="serverFieldHelp">中转服务器建节点前需在列表安装 sing-box，安装后保留中转类型。</p>
                      {serverFormCoreMissing && <div className="banner warning serverCoreHint" role="status">
                        <div>
                          <p>可以保存服务器类型。该服务器尚未安装 sing-box，建节点前需先安装。</p>
                          <button type="button" className="ghost" disabled={!selectedFormServer?.coreSelfUpdate || !coreReleases[selectedFormServer?.arch || ""] || serverFormCoreInstalling}
                            onClick={() => act(() => mutation("/api/servers/" + serverForm.id + "/core/upgrade", "POST"), "sing-box 安装已排队，完成后点击刷新安装状态")}>{serverFormCoreInstalling ? "核心安装或升级进行中" : "安装 sing-box"}</button>
                          <button type="button" className="ghost" disabled={refreshing} onClick={() => void refresh(true)}>{refreshing ? "刷新中…" : "刷新安装状态"}</button>
                          {!selectedFormServer?.coreSelfUpdate && <p>请先接入支持核心安装的 Agent。</p>}
                          {!!selectedFormServer?.coreSelfUpdate && !coreReleases[selectedFormServer?.arch || ""] && <p>面板缺少该架构的 sing-box 发布文件。</p>}
                        </div>
                      </div>}

                    </div>
                    <div className="serverFormWide">
                      <Field label="Agent 连接面板的 SOCKS5 节点">
                        <select aria-label="Agent 连接面板的 SOCKS5 节点" disabled={!serverProxyEnabled} value={serverForm.agentProxyNodeId || ""} onChange={(e) => setServerForm({ ...serverForm, agentProxyNodeId: e.target.value, agentProxyInternal: false })}>
                          <option value="">直接连接面板（不使用代理）</option>
                          {serverProxyOptions.map(({ node, host, reason }) => <option value={node.id} key={node.id} disabled={!!reason}>{node.name} · {host?.name || "未知服务器"} :{node.port}{reason ? `（${reason}）` : ""}</option>)}
                        </select>
                      </Field>
                      {!serverProxyEnabled && <p className="serverFieldHelp">离线管理不连接面板；切换为在线 Agent 后即可使用 SOCKS5，与服务器类型无关。</p>}
                      {!serverProxyOptions.length && <p className="serverFieldHelp">暂无 SOCKS5 节点。请先在已启用 UFW 的在线中转或落地服务器创建 SOCKS5 节点。</p>}
                      {!!serverProxyOptions.length && !serverProxyOptions.some((o) => !o.reason) && <p className="serverFieldHelp">当前 SOCKS5 节点均不可用，请按各选项后的原因修复，再点击右上角刷新。</p>}
                      {serverForm.agentProxyNodeId && <Field label="本机连接 SOCKS5 的地址">
                        <select aria-label="本机连接 SOCKS5 的地址" value={serverForm.agentProxyInternal ? "internal" : "public"} onChange={(e) => setServerForm({ ...serverForm, agentProxyInternal: e.target.value === "internal" })}>
                          <option value="public">SOCKS5 节点发布地址（公网 / 域名）</option>
                          <option value="internal" disabled={!servers.find((s) => s.id === nodes.find((n) => n.id === serverForm.agentProxyNodeId)?.serverId)?.internalAddress}>SOCKS5 所在服务器的内网地址</option>
                        </select>
                      </Field>}
                      {serverForm.agentProxyNodeId && <Field label="SOCKS5 防火墙放行来源">
                        <select aria-label="SOCKS5 防火墙放行来源" value={serverForm.agentProxySourceMode || "auto"} onChange={(e) => setServerForm({ ...serverForm, agentProxySourceMode: e.target.value as Server["agentProxySourceMode"] })}>
                          <option value="auto">跟随连接地址类型</option>
                          <option value="public">本机公网 IP</option>
                          <option value="internal">本机内网 IP</option>
                        </select>
                        <p className="serverFieldHelp">这是 SOCKS5 服务器实际看到的入口来源 IP，可独立于上方连接地址选择。选择内网来源时，请在下方填写这台服务器的内网 IP。仅改来源规则无需重装或重启本机 Agent。</p>
                      </Field>}
                      <p className="serverFieldHelp">代理用于 Agent 接入、心跳、任务与下载，与节点“允许直连”无关。候选节点须已启用、配置已生效，且其服务器已启用 UFW、没有防火墙冲突。面板按所选本机来源 IP 自动放行；经过 NAT 时请填写实际出口 IP。所有在线服务器均可使用代理，需 Agent 0.6.10 或更高版本。</p>
                    </div>
                  </div>
                </section>
                <section className="serverFormSection" aria-labelledby="server-network-title">
                  <h3 id="server-network-title">网络与防火墙</h3>
                  <div className="formGrid">
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
                    <Field label="内网地址">
                      <input
                        value={serverForm.internalAddress || ""}
                        placeholder="内网 / 专线互通时填写，如 10.0.0.2"
                        onChange={(e) =>
                          setServerForm({ ...serverForm, internalAddress: e.target.value })
                        }
                      />
                    </Field>
                    {serverForm.managementMode !== "offline" && <div className="serverFormWide">
                      <Field label="节点默认出口网卡">
                        <input maxLength={15} placeholder="留空使用系统路由，例如 ppp0" value={serverForm.outboundInterface || ""} onChange={(e) => setServerForm({ ...serverForm, outboundInterface: e.target.value })} />
                      </Field>
                      <p className="serverFieldHelp">仅控制这台服务器上 sing-box 节点的出口，节点可单独覆盖。修改后会重新应用配置并重启 sing-box；指定网卡不存在或未启用时，保留原配置并报错。</p>
                      {!!serverForm.outboundInterface?.trim() && !!serverForm.agentVersion && !serverForm.outboundBindingSupport && <p className="serverFieldHelp dangerText">配置可保存；请先升级 Agent 至 0.6.12 后应用出口网卡设置。</p>}
                    </div>}
                    <div className="serverFormWide">
                      <Field label="防火墙管理">
                        <select disabled={serverForm.managementMode === "offline"} value={serverForm.firewallMode || "ufw"} onChange={(e) => setServerForm({ ...serverForm, firewallMode: e.target.value as "ufw" | "manual" })}>
                          <option value="ufw">UFW 托管</option>
                          <option value="manual" disabled={!!serverForm.agentVersion && !serverForm.manualFirewallSupport && !manualFirewall(serverForm)}>手动管理（宿主机 / 安全组 / 其他防火墙）</option>
                        </select>
                      </Field>
                      <div className="serverFieldHelp" aria-live="polite">
                        <p>{manualFirewall(serverForm) ? "节点和转发可正常部署。面板不修改现有防火墙，端口放行及来源限制需自行配置。" : "由面板管理 UFW 规则，部署节点和转发前需初始化 UFW。"}</p>
                        {!!serverForm.agentVersion && !serverForm.manualFirewallSupport && <p>启用手动管理前，请先升级 Agent 至 0.6.4。</p>}
                      </div>
                    </div>
                  </div>
                  <p className="serverFieldHelp">公网 IP 或订阅用域名至少填写一项。</p>
                </section>
                <section className="serverFormSection" aria-labelledby="server-details-title">
                  <h3 id="server-details-title">其他信息</h3>
                  <div className="formGrid">
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
                    <div className="serverFormWide">
                      <Field label="备注">
                        <textarea
                          rows={2}
                          value={serverForm.notes || ""}
                          onChange={(e) =>
                            setServerForm({ ...serverForm, notes: e.target.value })
                          }
                        />
                      </Field>
                    </div>
                  </div>
                </section>
                <div className="serverFormActions">
                  <button className="primary">保存服务器</button>
                </div>
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
                          ? nodeForm.certificateId || matchingCertificate(nodeForm.tlsName || "")
                          : "",
                      })}
                    >
                      <option value="">选择中转或落地服务器</option>
                      {servers.filter((s) => canHostNodes(s) || s.id === nodeForm.serverId).map((s) => (
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
                          snellVersion: e.target.value === "snell" ? 6 : 0,
                          password: "",
                          shadowTlsHost: "",
                          shadowTlsPassword: "",
                        });
                      }}
                    >
                      <option value="ss">Shadowsocks</option>
                      <option value="snell">Snell</option>
                      <option value="anytls">AnyTLS</option>
                      <option value="socks5">SOCKS5</option>
                    </select>
                  </Field>
                  <Field label="端口 *（1–65535）">
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
                  <Field label="节点出口">
                    <select aria-label="节点出口" value={nodeForm.outboundMode || "inherit"} onChange={(e) => setNodeForm({ ...nodeForm, outboundMode: e.target.value as Node["outboundMode"], outboundInterface: "" })}>
                      <option value="inherit">继承服务器（{servers.find((s) => s.id === nodeForm.serverId)?.outboundInterface || "系统路由"}）</option>
                      <option value="system">使用系统路由</option>
                      <option value="interface">指定出口网卡</option>
                    </select>
                    <small>仅影响此节点的 sing-box 流量及 ShadowTLS 握手，不改变 Agent 或端口转发的出口。</small>
                  </Field>
                  {nodeForm.outboundMode === "interface" && <Field label="出口网卡 *">
                    <input required maxLength={15} placeholder="例如 ppp0、eth0" value={nodeForm.outboundInterface || ""} onChange={(e) => setNodeForm({ ...nodeForm, outboundInterface: e.target.value })} />
                    <small>须为目标服务器已启用的网卡；不可用时应用失败，不自动改用其他出口。</small>
                  </Field>}
                  {(nodeForm.outboundMode === "interface" || ((nodeForm.outboundMode || "inherit") === "inherit" && !!servers.find((s) => s.id === nodeForm.serverId)?.outboundInterface)) && !servers.find((s) => s.id === nodeForm.serverId)?.outboundBindingSupport && <p className="hint dangerText">配置可保存；需升级 Agent 至 0.6.12 后应用出口网卡设置。</p>}
                  <Field label="访问方式">
                    <label className="check">
                      <input type="checkbox" checked={!!nodeForm.direct} onChange={(e) => setNodeForm({ ...nodeForm, direct: e.target.checked })} />
                      允许直连（可直接加入订阅）
                    </label>
                  </Field>
                  {nodeForm.direct && <Field label="节点端口 UFW 规则">
                    <select
                      value={manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) ? "manual" : nodeForm.firewallPolicy || "all"}
                      disabled={manualFirewall(servers.find((s) => s.id === nodeForm.serverId))}
                      onChange={(e) => setNodeForm({ ...nodeForm, firewallPolicy: e.target.value as Node["firewallPolicy"], firewallSources: "" })}
                    >
                      <option value="all">自动放行所有来源</option>
                      <option value="restricted">仅自动放行指定 IP / CIDR</option>
                      <option value="manual" disabled={nodeForm.protocol === "socks5"}>不生成自动规则，手动管理</option>
                    </select>
                  </Field>}
                  {!manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) && !nodeForm.direct && <p className="hint">未开启客户端直连：仅放行链路最后一跳和使用此 SOCKS5 的 Agent。{nodeForm.routeSources ? `链路来源：${nodeForm.routeSources.split(",").join("、")}。` : ""}{nodeForm.agentProxySources ? `Agent 来源：${nodeForm.agentProxySources.split(",").join("、")}。` : ""}{!nodeForm.routeSources && !nodeForm.agentProxySources ? "未被链路或 Agent 使用时，端口不对外开放。" : ""}</p>}
                  {!manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) && nodeForm.direct && nodeForm.firewallPolicy === "restricted" && (
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
                  {nodeForm.protocol === "socks5" && <>
                    <Field label="SOCKS5 用户名 *"><input required autoComplete="off" maxLength={255} value={nodeForm.username || ""} onChange={(e) => setNodeForm({ ...nodeForm, username: e.target.value })} /></Field>
                  </>}
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
                      <Field label="Snell 版本">
                        <select value={nodeForm.snellVersion || 5} onChange={(e) => setNodeForm({ ...nodeForm, snellVersion: Number(e.target.value), obfs: "none" })}>
                          <option value={6}>v6</option><option value={5}>v5</option>
                        </select>
                        {(nodeForm.snellVersion || 5) === 6 && <small>PSK 需要 12–255 字节；使用默认流量整形，不使用 HTTP 混淆。</small>}
                        {(nodeForm.snellVersion || 5) === 6 && nodeForm.serverId && !servers.find((s) => s.id === nodeForm.serverId)?.snellV6 && <small className="dangerText">需升级 Agent 至 0.6.11 后应用 v6 配置。</small>}
                      </Field>
                      <Field label="Snell 内层端口 *">
                        <input required type="number" min={1} max={65535} value={nodeForm.snellPort || ""} onChange={(e) => setNodeForm({ ...nodeForm, snellPort: Number(e.target.value) })} />
                        <small>固定监听 127.0.0.1，不对公网开放；须与其他监听端口不同。</small>
                        {nodeForm.serverId && !servers.find((s) => s.id === nodeForm.serverId)?.snellFixedPort && <small className="dangerText">配置可保存；需升级 Agent 至 0.6.2 或更高版本后才会应用固定内层端口。</small>}
                      </Field>
                      {(nodeForm.snellVersion || 5) === 5 && <Field label="混淆模式">
                        <select value={nodeForm.obfs || "none"} onChange={(e) => setNodeForm({ ...nodeForm, obfs: e.target.value })}>
                          <option value="none">无</option>
                          <option value="http">HTTP</option>
                        </select>
                      </Field>}
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
                              certificateId: matchingCertificate(e.target.value),
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
                            .map((c) => (
                              <option key={c.id} value={c.id}>
                                {c.name ? `${c.name} · ${c.domain}` : c.domain}{new Date(c.expiresAt).getTime() <= Date.now() ? "（已过期）" : ""}
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
                {!manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) && nodeForm.firewallPolicy === "restricted" && <p className="hint">Agent 0.6.14 起，节点来源限制优先于主机已有的同端口 UFW 规则；其他来源会被拒绝。</p>}
                {!manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) && nodeForm.firewallPolicy === "manual" && <p className="hint">手动管理模式不会开放节点端口，请先在自定义规则中添加需要的允许来源。</p>}
                {manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) && <p className="hint">该服务器的防火墙由外部管理。允许直连开关仅决定能否加入直连订阅；实际端口放行、来源白名单和仅链路访问限制请自行配置。</p>}
                {nodeForm.protocol === "socks5" && !!servers.find((s) => s.id === nodeForm.serverId)?.agentVersion && !servers.find((s) => s.id === nodeForm.serverId)?.agentProxySupport && <div className="banner warning" role="status">配置可以保存；请先将服务器 Agent 升级至 0.6.10，之后才会应用 SOCKS5 节点。</div>}
                {nodeFirewallUnsupported && <div className="banner warning" role="status">可以保存配置，但该服务器的 Agent 尚未上报支持新规则。更新 Agent 前不会应用此配置，现有 UFW 放行规则仍然生效。</div>}
                {nodeCoreMissing && <div className="banner warning" role="status">
                  <p>该服务器需要先安装 sing-box，安装成功后即可创建节点。</p>
                  <button type="button" className="ghost" disabled={!selectedNodeServer?.coreSelfUpdate || !coreReleases[selectedNodeServer?.arch || ""] || nodeCoreInstalling}
                    onClick={() => act(() => mutation("/api/servers/" + nodeForm.serverId + "/core/upgrade", "POST"), "sing-box 安装已排队；点击刷新安装状态，完成后提交节点")}>{nodeCoreInstalling ? "sing-box 安装或升级进行中" : "安装 sing-box"}</button>
                  <button type="button" className="ghost" disabled={refreshing} onClick={() => void refresh(true)}>{refreshing ? "刷新中…" : "刷新安装状态"}</button>
                  {!selectedNodeServer?.coreSelfUpdate && <p>请先接入支持核心安装的 Agent。</p>}
                  {!!selectedNodeServer?.coreSelfUpdate && !coreReleases[selectedNodeServer?.arch || ""] && <p>面板缺少该架构的 sing-box 发布文件。</p>}
                </div>}
                {nodeForm.protocol === "socks5" && <p className="hint">SOCKS5 支持 TCP，强制用户名密码认证，服务器必须启用 UFW。所有在线服务器的 Agent 均可独立使用此节点，无需打开“允许直连”，面板会为它的来源 IP 自动添加放行规则。仅在可信网络中使用，SOCKS5 本身不加密。</p>}
                {nodeForm.protocol === "socks5" && (manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) || servers.find((s) => s.id === nodeForm.serverId)?.ufwStatus !== "active") && <div className="banner warning" role="status">请先将该服务器设置为 UFW 托管，并在服务器列表安全初始化防火墙，再提交 SOCKS5 节点。</div>}
                {templateLoading && <p className="hint">正在读取模板密码…</p>}
                <button className="primary submit" disabled={templateLoading || nodeCoreMissing || (nodeForm.protocol === "socks5" && (manualFirewall(servers.find((s) => s.id === nodeForm.serverId)) || servers.find((s) => s.id === nodeForm.serverId)?.ufwStatus !== "active"))}>提交配置</button>
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
                      onChange={(e) => setTemplateForm({ ...templateForm, protocol: e.target.value as Node["protocol"], snellVersion: e.target.value === "snell" ? 6 : 0, password: "", shadowTlsHost: "", shadowTlsPassword: "" })}
                    >
                      <option value="ss">Shadowsocks</option>
                      <option value="snell">Snell</option>
                      <option value="anytls">AnyTLS</option>
                      <option value="socks5">SOCKS5</option>
                    </select>
                  </Field>
                  <Field label="端口 *（1–65535）">
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
                  {templateForm.protocol === "socks5" && <Field label="SOCKS5 用户名 *"><input required autoComplete="off" maxLength={255} value={templateForm.username || ""} onChange={(e) => setTemplateForm({ ...templateForm, username: e.target.value })} /></Field>}
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
                      <Field label="Snell 版本">
                        <select value={templateForm.snellVersion || 5} onChange={(e) => setTemplateForm({ ...templateForm, snellVersion: Number(e.target.value), obfs: "none" })}>
                          <option value={6}>v6</option><option value={5}>v5</option>
                        </select>
                        {(templateForm.snellVersion || 5) === 6 && <small>PSK 需要 12–255 字节；使用默认流量整形，不使用 HTTP 混淆。</small>}
                      </Field>
                      <Field label="Snell 内层端口 *">
                        <input required type="number" min={1} max={65535} value={templateForm.snellPort || ""} onChange={(e) => setTemplateForm({ ...templateForm, snellPort: Number(e.target.value) })} />
                        <small>仅监听 127.0.0.1；同一服务器上的节点不能共用。</small>
                      </Field>
                      {(templateForm.snellVersion || 5) === 5 && <Field label="混淆模式">
                        <select value={templateForm.obfs || "none"} onChange={(e) => setTemplateForm({ ...templateForm, obfs: e.target.value })}>
                          <option value="none">无</option>
                          <option value="http">HTTP</option>
                        </select>
                      </Field>}
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
                <p className="hint">SS 2022 密钥按加密方式生成 16 或 32 字节的 Base64。模板密码会加密保存，使用模板创建的节点共享该密码；留空则每个节点独立生成。Snell 的 ShadowTLS 域名应是服务器可访问的真实 TLS 站点（443 端口），ShadowTLS 密码与 Snell PSK 分开。AnyTLS 会按 TLS 域名从统一证书库匹配证书。</p>
                <button className="primary submit">保存模板</button>
              </form>
            )}
            {modal === "certificate" && (
              <form className="certificateForm" onSubmit={submitCert}>
                <p className="hint">和 Nginx 一样，选择证书文件和对应私钥文件即可，无需转换格式或选择服务器。</p>
                <CertificateFileField kind="certificate" value={certForm.pem || ""} onChange={(pem) => setCertForm((f) => ({ ...f, pem }))} onBusy={(busy) => setCertFilesBusy((s) => ({ ...s, pem: busy }))} />
                <CertificateFileField kind="key" value={certForm.key || ""} onChange={(key) => setCertForm((f) => ({ ...f, key }))} onBusy={(busy) => setCertFilesBusy((s) => ({ ...s, key: busy }))} />
                <div className="formGrid">
                  <Field label="名称">
                    <input
                      value={certForm.name || ""}
                      onChange={(e) =>
                        setCertForm({ ...certForm, name: e.target.value })
                      }
                    />
                  </Field>
                  <Field label="域名（留空从证书读取）">
                    <input
                      value={certForm.domain || ""}
                      onChange={(e) =>
                        setCertForm({ ...certForm, domain: e.target.value })
                      }
                    />
                  </Field>
                </div>
                <p className="hint">证书可供多台服务器复用。创建 AnyTLS 节点时选择证书，面板会将证书和私钥下发到该节点所在服务器；TLS 域名须被证书覆盖。</p>
                <button className="primary submit" disabled={certFilesBusy.pem || certFilesBusy.key || !certForm.pem?.trim() || !certForm.key?.trim()}>{certFilesBusy.pem || certFilesBusy.key ? "正在读取文件…" : "保存证书"}</button>
              </form>
            )}
            {modal === "route" && (() => {
              const hops = routeForm.hops || [];
              const node = nodes.find((n) => n.id === routeForm.nodeId);
              const setHop = (i: number, patch: Partial<RouteHop>) =>
                setRouteForm({ ...routeForm, hops: hops.map((h, j) => (j === i ? { ...h, ...patch } : h)) });
              // A server appears once per route, and the exit is never a hop.
              const taken = (i: number) => new Set([
                routeForm.entryServerId || "",
                node?.serverId || "",
                ...hops.flatMap((h, j) => (j === i ? [] : h.serverIds)),
              ]);
              const connectionSettings = (
                senderIds: string[], receiverIds: string[], internal: boolean, sourceMode: RouteSourceMode | undefined,
                setInternal: (value: boolean) => void, setSource: (value: RouteSourceMode) => void,
              ) => {
                const senders = servers.filter((s) => senderIds.includes(s.id));
                const receivers = servers.filter((s) => receiverIds.includes(s.id));
                const sourceInternal = sourceMode === "internal" || (!sourceMode || sourceMode === "auto") && internal;
                const targetAddress = (s: Server) => internal ? s.internalAddress : s.ipv4 || s.ipv6 || s.domain;
                const targets = receivers.map(targetAddress);
                const useV4 = targets.some((v) => !v || !v.includes(":"));
                const useV6 = targets.some((v) => !v || v.includes(":") || !/^\d+\.\d+\.\d+\.\d+$/.test(v));
                const sourceAddresses = (s: Server) => sourceInternal ? s.internalAddress || "未填写内网 IP" :
                  [...new Set([...(useV4 ? [s.ipv4, s.detectedIpv4] : []), ...(useV6 ? [s.ipv6, s.detectedIpv6] : [])].filter(Boolean))].join("、") || "未填写可用的公网 IP";
                const managed = !receivers.length || receivers.some((s) => !manualFirewall(s));
                return (
                  <fieldset className="routeConnection">
                    <legend>{senders.map((s) => s.name).join(" / ") || "请选择发送方"} → {receivers.map((s) => s.name).join(" / ") || "请选择接收方"}</legend>
                    <div className="formGrid">
                      <Field label="连接地址：接收方的哪个地址？">
                        <select value={internal ? "internal" : "public"} onChange={(e) => setInternal(e.target.value === "internal")}>
                          <option value="public">接收方公网地址</option>
                          <option value="internal">接收方内网地址</option>
                        </select>
                        {receivers.map((s) => <small className="connectionAddress" key={s.id}>{s.name}：{targetAddress(s) || "未填写该地址"}</small>)}
                      </Field>
                      <Field label="防火墙来源：放行发送方的哪个 IP？">
                        <select disabled={!managed} value={sourceMode || "auto"} onChange={(e) => setSource(e.target.value as RouteSourceMode)}>
                          <option value="auto">自动（{internal ? "发送方内网 IP" : "发送方公网 IP"}）</option>
                          <option value="public">发送方公网 IP</option>
                          <option value="internal">发送方内网 IP</option>
                        </select>
                        {managed ? senders.map((s) => <small className="connectionAddress" key={s.id}>{s.name}：{sourceAddresses(s)}</small>) : <small className="connectionAddress">接收方防火墙为手动管理，请自行放行。</small>}
                      </Field>
                    </div>
                    {managed && <p className="hint">按接收方实际看到的来源 IP 选择；此设置只生成放行规则，不改变发送方的出口或路由。</p>}
                  </fieldset>
                );
              };
              return (
                <form onSubmit={submitRoute}>
                  <div className="formGrid">
                    <Field label="名称 *"><input required maxLength={100} value={routeForm.name || ""} onChange={(e) => setRouteForm({ ...routeForm, name: e.target.value })} /></Field>
                    <Field label="首跳（入口 / 线路） *">
                      <select required value={routeForm.entryServerId || ""} onChange={(e) => setRouteForm({ ...routeForm, entryServerId: e.target.value })}>
                        <option value="">选择服务器</option>
                        {servers.filter((s) => s.roles?.some((r) => r === "entry" || r === "line")).map((s) => <option key={s.id} value={s.id}>{s.name}（{rolesText(s.roles)}）</option>)}
                      </select>
                    </Field>
                    <Field label="落地节点 *">
                      <select required value={routeForm.nodeId || ""} onChange={(e) => setRouteForm({ ...routeForm, nodeId: e.target.value })}>
                        <option value="">选择节点</option>
                        {nodes.filter((n) => !n.deleting).map((n) => <option key={n.id} value={n.id}>{n.name}（{n.protocol.toUpperCase()} · {serverName(n.serverId)}）</option>)}
                      </select>
                    </Field>
                    <Field label="端口（留空自动）"><input type="number" min={1024} max={65535} value={routeForm.port || ""} placeholder="优先使用落地节点端口" onChange={(e) => setRouteForm({ ...routeForm, port: Number(e.target.value) || 0 })} /></Field>
                    <Field label="备注"><input maxLength={200} value={routeForm.notes || ""} onChange={(e) => setRouteForm({ ...routeForm, notes: e.target.value })} /></Field>
                    <Field label="状态"><label className="check"><input type="checkbox" checked={!!routeForm.enabled} onChange={(e) => setRouteForm({ ...routeForm, enabled: e.target.checked })} /> 启用链路</label></Field>
                  </div>
                  <div className="field">
                    <span>中间跳（按顺序，可为空）</span>
                    <div className="hopList">
                      {hops.map((hop, i) => (
                        <div className="hop" key={i}>
                          <div className="hopHead">
                            <strong>第 {i + 1} 个中转</strong>
                            <select aria-label={`第 ${i + 1} 跳的模式`} value={hop.balance} onChange={(e) => setHop(i, { balance: e.target.value as RouteHop["balance"] })}>
                              <option value="failover">主备</option>
                              <option value="round-robin">轮询</option>
                            </select>
                            <button type="button" onClick={() => setRouteForm({ ...routeForm, hops: hops.filter((_, j) => j !== i) })}>移除</button>
                          </div>
                          <div className="nodePicker">
                            {servers.filter((s) => s.roles?.some((r) => r === "transit" || r === "line") && (!taken(i).has(s.id) || hop.serverIds.includes(s.id))).map((s) => (
                              <label className="check" key={s.id}>
                                <input
                                  type="checkbox"
                                  checked={hop.serverIds.includes(s.id)}
                                  onChange={(e) => setHop(i, { serverIds: e.target.checked ? [...hop.serverIds, s.id] : hop.serverIds.filter((id) => id !== s.id) })}
                                />
                                {s.name} <small>{rolesText(s.roles)}{s.internalAddress ? ` · 内网 ${s.internalAddress}` : ""}</small>
                              </label>
                            ))}
                          </div>
                          {connectionSettings(i === 0 ? [routeForm.entryServerId || ""] : hops[i - 1].serverIds, hop.serverIds,
                            !!hop.internal, hop.sourceMode, (internal) => setHop(i, { internal }), (sourceMode) => setHop(i, { sourceMode }))}
                        </div>
                      ))}
                      <button type="button" onClick={() => setRouteForm({ ...routeForm, hops: [...hops, { serverIds: [], balance: "failover", internal: false }] })}>添加一跳</button>
                    </div>
                  </div>
                  <h3 className="routeExitTitle">连接落地</h3>
                  {connectionSettings(hops.length ? hops[hops.length - 1].serverIds : [routeForm.entryServerId || ""], node ? [node.serverId] : [],
                    !!routeForm.nodeInternal, routeForm.nodeSourceMode,
                    (nodeInternal) => setRouteForm({ ...routeForm, nodeInternal }), (nodeSourceMode) => setRouteForm({ ...routeForm, nodeSourceMode }))}
                  <p className="hint">一跳选多台服务器即为负载均衡组：主备优先用第一台可用的，轮询把新连接轮流分配；故障服务器自动停用，恢复后自动启用。</p>
                  <p className="hint">例如入口通过专线访问中转的公网地址：连接地址选“接收方公网地址”，防火墙来源选“发送方内网 IP”。普通公网互连保留“接收方公网地址 + 自动”即可。</p>
                  <button className="primary submit">保存链路</button>
                </form>
              );
            })()}
            {modal === "forward" && (
              <form onSubmit={submitForward}>
                <div className="formGrid">
                  <Field label="服务器 *"><select required value={forwardForm.serverId || ""} disabled={!!forwardForm.id} onChange={(e) => setForwardForm({ ...forwardForm, serverId: e.target.value })}><option value="">选择服务器</option>{servers.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></Field>
                  <Field label="名称 *"><input required maxLength={100} value={forwardForm.name || ""} onChange={(e) => setForwardForm({ ...forwardForm, name: e.target.value })} /></Field>
                  <Field label="协议"><select value={forwardForm.network || "tcp"} onChange={(e) => setForwardForm({ ...forwardForm, network: e.target.value as ForwardRule["network"], healthCheck: "" })}><option value="tcp">TCP</option><option value="udp">UDP</option><option value="tcp+udp">TCP + UDP</option></select></Field>
                  <Field label="监听 IP"><input required value={forwardForm.listen || ""} onChange={(e) => setForwardForm({ ...forwardForm, listen: e.target.value })} placeholder="0.0.0.0" /></Field>
                  <Field label="监听端口 *"><input required type="number" min={1024} max={65535} value={forwardForm.port || ""} onChange={(e) => setForwardForm({ ...forwardForm, port: Number(e.target.value) })} /></Field>
                  <Field label="目标（每行一个 地址:端口） *"><textarea required rows={3} value={forwardTargets} onChange={(e) => setForwardTargets(e.target.value)} placeholder={"203.0.113.10:443\nexample.com:443\n[2001:db8::1]:443"} /></Field>
                  {parseTargets(forwardTargets).length > 1 && <Field label="多目标模式"><select value={forwardForm.balance || "failover"} onChange={(e) => setForwardForm({ ...forwardForm, balance: e.target.value as ForwardRule["balance"] })}><option value="failover">主备：优先第一个可用目标</option><option value="round-robin">轮询：新连接轮流分配</option></select></Field>}
                  {(forwardForm.network === "udp" || forwardForm.network === "tcp+udp") && parseTargets(forwardTargets).length > 1 && <Field label="健康检查">
                    <select value={forwardForm.healthCheck || ""} onChange={(e) => setForwardForm({ ...forwardForm, healthCheck: e.target.value as "tcp" | "none" | "" })}>
                      <option value="">{forwardForm.network === "tcp+udp" ? "按协议默认：TCP 主动探测 / UDP 被动检查" : "默认：被动检查（纯 UDP 服务）"}</option>
                      <option value="none">不主动探测（通过连接 / 套接字错误切换）</option>
                      <option value="tcp">TCP 探测（目标须有同端口 TCP 服务）</option>
                    </select>
                  </Field>}
                  <Field label="UFW 规则"><select disabled={manualFirewall(servers.find((s) => s.id === forwardForm.serverId))} value={manualFirewall(servers.find((s) => s.id === forwardForm.serverId)) ? "manual" : forwardForm.firewallPolicy || "all"} onChange={(e) => setForwardForm({ ...forwardForm, firewallPolicy: e.target.value as ForwardRule["firewallPolicy"], firewallSources: e.target.value === "restricted" ? forwardForm.firewallSources : "" })}><option value="all">自动放行所有来源</option><option value="restricted">仅放行指定 IP / CIDR</option><option value="manual">手动管理</option></select></Field>
                  {!manualFirewall(servers.find((s) => s.id === forwardForm.serverId)) && forwardForm.firewallPolicy === "all" && <p className="hint">公开转发会把目标暴露给全网；如无必要请改用“仅放行指定 IP / CIDR”。提交时会再次确认。</p>}
                  {!manualFirewall(servers.find((s) => s.id === forwardForm.serverId)) && forwardForm.firewallPolicy === "restricted" && <Field label="允许的来源 IP / CIDR *"><textarea required value={forwardForm.firewallSources || ""} onChange={(e) => setForwardForm({ ...forwardForm, firewallSources: e.target.value })} placeholder="每行一个 IP 或 CIDR" /></Field>}
                  <Field label="状态"><label className="check"><input type="checkbox" checked={!!forwardForm.enabled} onChange={(e) => setForwardForm({ ...forwardForm, enabled: e.target.checked })} /> 启用转发</label></Field>
                </div>
                {forwardForm.network === "tcp+udp" && <p className="hint">TCP 和 UDP 使用同一监听端口、目标及防火墙来源，一起启停和删除，用量合并统计。需要 Agent 0.6.7 或更高版本。</p>}
                {forwardForm.network === "tcp+udp" && servers.find((s) => s.id === forwardForm.serverId)?.managementMode !== "offline" && !servers.find((s) => s.id === forwardForm.serverId)?.forwardTcpUdp && <p className="hint">服务器尚未上报双协议转发能力。配置可先保存，请升级 Agent 后再应用。</p>}
                {forwardForm.serverId && !servers.find((s) => s.id === forwardForm.serverId)?.forwardSupport && servers.find((s) => s.id === forwardForm.serverId)?.managementMode !== "offline" && <p className="hint">这台服务器的 Agent 尚未上报端口转发能力。规则可以先保存；升级 Agent 后会自动应用。</p>}
                {servers.find((s) => s.id === forwardForm.serverId)?.managementMode === "offline" && <p className="hint">此机离线管理：保存后到服务器列表导出完整配置，再在目标机应用。</p>}
                {manualFirewall(servers.find((s) => s.id === forwardForm.serverId)) && <p className="hint">该服务器为手动管理防火墙，面板只部署转发进程，入口端口与来源限制请自行配置。</p>}
                <p className="hint">目标服务器需允许来自转发服务器的连接；UFW 规则只控制本机入口。</p>
                <p className="hint">目标可以填域名：转发进程每 30 秒重新解析一次，域名指向新地址后新连接会跟着走。修改或删除一条转发只影响它自己的连接。</p>
                <p className="hint">多目标 TCP 或已选择 TCP 探测的 UDP 规则，每 5 秒探测一次，连续 2 次失败停用、2 次成功恢复。纯 UDP 默认通过套接字错误切换目标，10 秒后允许重试；仅无响应无法判断故障。</p>
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
                      disabled={!!ruleForm.id || !!ruleForm.replaceHostRule}
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
                  <Field label="地址族">
                    <select
                      value={ruleForm.family || ""}
                      onChange={(e) => setRuleForm({ ...ruleForm, family: e.target.value as FirewallRule["family"] })}
                    >
                      <option value="">IPv4 + IPv6</option>
                      <option value="ipv4">仅 IPv4</option>
                      <option value="ipv6">仅 IPv6</option>
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
                <p className="hint">填写来源 IP / CIDR 时，规则只作用于该来源所属的地址族，所选地址族须与来源一致。</p>
                {ruleForm.replaceHostRule && <p className="hint">保存后先删除主机上的这一条原规则（同端口的另一地址族规则不受影响）：<span className="mono">{ruleForm.replaceHostRule}</span>，再由面板创建上面的规则并在以后管理它。</p>}
                <button className="primary submit">{ruleForm.id ? "保存修改" : "提交规则"}</button>
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
                          routeIds: (subForm.routeIds || []).filter((id) => {
                            const node = nodes.find((item) => item.id === routes.find((r) => r.id === id)?.nodeId);
                            return !!node && subscriptionNodeEligible(e.target.value, node);
                          }),
                        })
                      }
                    >
                      <option value="sing-box">sing-box JSON</option>
                      <option value="surge">Surge 节点订阅（代理组）</option>
                      <option value="v2rayn">v2rayN 订阅</option>
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
                <Field label="选择链路">
                  <div className="nodePicker">
                    {routes.map((r) => {
                      const node = nodes.find((n) => n.id === r.nodeId);
                      const selected = subForm.routeIds?.includes(r.id) || false;
                      const issue = !r.enabled ? "链路已停用" : !node ? "落地节点已删除" : subscriptionNodeIssue(subForm.format, node);
                      return <label className="check subscriptionRouteChoice" key={r.id}>
                          <input
                            type="checkbox"
                            checked={selected}
                            disabled={!!issue && !selected}
                            onChange={(e) =>
                              setSubForm({
                                ...subForm,
                                routeIds: e.target.checked
                                  ? [...(subForm.routeIds || []), r.id]
                                  : (subForm.routeIds || []).filter((id) => id !== r.id),
                              })
                            }
                          />
                          <span className="subscriptionRouteDetails">
                            <span>{r.name}</span>
                            <small>{routePath(r)}</small>
                            {issue && <small className="routeChoiceIssue">{issue}{selected ? "；请取消选择或调整落地配置" : ""}</small>}
                            {node && sharedSubscriptionPassword(node) && <small>共享节点密码 · 无法按订阅统计流量</small>}
                          </span>
                        </label>;
                    })}
                    {!routes.length && <p className="hint">暂无链路，请先在“链路”中创建并选择落地节点。“端口转发”里的手动规则不会自动成为订阅链路。</p>}
                  </div>
                </Field>
                <Field label="直连节点（需在节点中开启“允许直连”）">
                  <div className="nodePicker">
                    {nodes.map((n) => {
                      const selected = subForm.nodeIds?.includes(n.id) || false;
                      const issue = subscriptionDirectNodeIssue(subForm.format, n);
                      return <label className="check subscriptionRouteChoice" key={n.id}>
                          <input
                            type="checkbox"
                            checked={selected}
                            disabled={!!issue && !selected}
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
                          <span className="subscriptionRouteDetails">
                            <span>{n.name}</span>
                            <small>{n.protocol.toUpperCase()} · {serverName(n.serverId)}</small>
                            {issue && <small className="routeChoiceIssue">{issue}{selected ? "；请取消选择或调整节点配置" : ""}</small>}
                            {!issue && n.status !== "active" && <small>{n.status === "error" ? "配置应用失败，请检查操作记录；可先加入订阅，生效后下发" : "配置待应用；可先加入订阅，生效后下发"}</small>}
                          </span>
                        </label>;
                    })}
                    {!nodes.length && <p className="hint">暂无节点，请先创建节点并开启“允许直连”。</p>}
                  </div>
                  <p className="hint">待应用的节点可以先选入订阅，配置在服务器上生效后才会出现在订阅下载中。不兼容当前客户端格式的节点会显示具体原因。</p>
                </Field>
                {subForm.format === "surge" && <p className="hint">Surge 格式输出节点列表，支持传统 SS（如 aes-256-gcm）、AES-GCM 的 SS 2022 和 ShadowTLS Snell。请通过代理组的 policy-path 引用链接；把此链接当完整配置安装会报“规则必须以 FINAL 结尾”。创建后或在列表“查看链接”中可复制代理组配置。AnyTLS 请使用 sing-box 或 v2rayN 格式。</p>}
                {subForm.format === "v2rayn" && <p className="hint">v2rayN 格式支持 SS 和 AnyTLS 节点及其链路。复制订阅链接，在 v2rayN 中添加订阅分组并更新订阅；AnyTLS 请使用支持该协议的新版 v2rayN，并选择 sing-box 内核。v2rayN 不支持 Snell / ShadowTLS。</p>}
                {sharedSubNodes(subForm).length > 0 && <p className="hint">以下 SS 节点沿用节点密码：{sharedSubNodes(subForm).map((n) => n.name).join("、")}。流量只能按节点统计，无法单独撤销某条订阅的节点访问；禁用、到期或轮换订阅链接仅影响订阅下载，撤销已导入客户端的访问需更换节点密码。</p>}
                <p className="hint">链路的订阅地址是首跳服务器的地址和链路端口，协议与登录凭据来自落地节点。</p>
                <p className="hint">保存后，所选节点（含链路的落地节点）所在服务器的 sing-box 会重启以更新登录凭据，其上所有连接将中断数秒。订阅到期时也会自动执行一次。</p>
                <button className="primary submit">
                  {subForm.id ? "保存订阅" : "创建订阅"}
                </button>
                {issuedURL && (
                  <div className="commandBox">
                    <strong>请保存订阅链接：</strong>
                    <span>新凭据需等待 Agent 应用配置后才能下载使用。</span>
                    <MaskedValue value={issuedURL}><button type="button" onClick={() => copy(issuedURL)}>复制</button></MaskedValue>
                    {issuedFormat === "surge" && surgeImportHelp(issuedURL)}
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
            {sharedSubNodes(trafficSub).length > 0 && <p className="hint">共享密码节点无法按订阅统计，以下数据只包含独立凭据节点。共享节点总流量请在节点列表查看。</p>}
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
    "offline-managed": ["离线管理", "idle"],
    "offline-export-pending": ["配置待导出", "warn"],
    "offline-disable-export-pending": ["停用待导出", "warn"],
    "offline-delete-pending": ["删除待导出", "warn"],
    "offline-exported": ["配置已导出", "idle"],
    "offline-disabled-exported": ["停用已导出", "idle"],
    exported: ["离线配置已导出", "idle"],
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
    manual: ["手动管理", "idle"],
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
  "forwards.apply": "应用转发规则",
  "firewall.apply": "应用防火墙规则",
  "ufw.init": "初始化 UFW",
  "ufw.delete": "删除主机规则",
};
function kindLabel(kind: string) {
  return kindLabels[kind] || kind;
}
function localDate(d: Date) {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}
// QRCode lives in ./components/QRCode.tsx (lazy-loaded, only used by TOTP setup).
type LogRange = { from: string; to: string }; // dates as YYYY-MM-DD, "" for open
const noRange: LogRange = { from: "", to: "" };
// Whole local days: from the start of the first to the end of the last.
function rangeQuery(range: LogRange) {
  let q = "";
  if (range.from) q += "&fromMs=" + new Date(range.from + "T00:00:00").getTime();
  if (range.to) q += "&toMs=" + new Date(range.to + "T23:59:59.999").getTime();
  return q;
}
type PagedLog<T> = {
  items: T[]; total: number; page: number; pageSize: number; busy: boolean; empty: boolean;
  setPage: (page: number) => void; setPageSize: (size: number) => void; reload: () => void;
};

// usePagedLog shows a log one numbered page at a time, counted on the server.
// `base` is the listing URL with its filters, or null while the list is not on
// screen; changing it or the date range goes back to the first page.
function usePagedLog<T>(base: string | null, range: LogRange, onError: (e: Error) => void): PagedLog<T> {
  const [items, setItems] = useState<T[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [busy, setBusy] = useState(false);
  // Known to be empty only once a page has actually come back.
  const [loaded, setLoaded] = useState(false);
  const request = useRef(0);
  const filters = base === null ? null : base + rangeQuery(range);
  const url = filters === null ? null : `${filters}&page=${page}&pageSize=${pageSize}`;
  const load = () => {
    if (!url) return;
    const current = ++request.current;
    setBusy(true);
    api<{ items?: T[]; total?: number }>(url)
      .then((body) => {
        // A newer request (another page, filter or refresh) has taken over.
        if (current !== request.current) return;
        setItems(body.items ?? []);
        setTotal(body.total ?? 0);
        setLoaded(true);
      })
      .catch((e) => { if (current === request.current) onError(e as Error); })
      .finally(() => { if (current === request.current) setBusy(false); });
  };
  useEffect(() => { setPage(1); }, [filters]);
  useEffect(() => { load(); }, [url]);
  return {
    items, total, page, pageSize, busy, empty: loaded && !busy && !items.length,
    setPage, setPageSize: (size) => { setPageSize(size); setPage(1); }, reload: load,
  };
}

// Pager: total, numbered pages around the current one, and the page size.
function Pager<T>({ log }: { log: PagedLog<T> }) {
  if (!log.total) return null;
  const pages = Math.max(1, Math.ceil(log.total / log.pageSize));
  const shown = [...new Set([1, log.page - 2, log.page - 1, log.page, log.page + 1, log.page + 2, pages])]
    .filter((p) => p >= 1 && p <= pages)
    .sort((a, b) => a - b);
  return (
    <div className="pager">
      <span className="hint">共 {log.total} 条，第 {log.page} / {pages} 页</span>
      <div className="pages">
        <button className="ghost" disabled={log.busy || log.page <= 1} onClick={() => log.setPage(log.page - 1)}>上一页</button>
        {shown.map((p, i) => (
          <React.Fragment key={p}>
            {i > 0 && p - shown[i - 1] > 1 && <span className="hint">…</span>}
            <button className={p === log.page ? "primary" : "ghost"} disabled={log.busy} aria-current={p === log.page ? "page" : undefined} onClick={() => log.setPage(p)}>{p}</button>
          </React.Fragment>
        ))}
        <button className="ghost" disabled={log.busy || log.page >= pages} onClick={() => log.setPage(log.page + 1)}>下一页</button>
        <select value={log.pageSize} onChange={(e) => log.setPageSize(Number(e.target.value))} aria-label="每页条数">
          {[20, 50, 100, 200].map((n) => <option key={n} value={n}>{n} 条/页</option>)}
        </select>
      </div>
    </div>
  );
}

// DateRange filters a log by whole days; either end may stay open.
function DateRange({ value, onChange, label = "日期" }: { value: LogRange; onChange: (v: LogRange) => void; label?: string }) {
  return (
    <span className="dateRange">
      <input type="date" aria-label={`${label}起`} value={value.from} max={value.to || undefined} onChange={(e) => onChange({ ...value, from: e.target.value })} />
      <span className="hint">至</span>
      <input type="date" aria-label={`${label}止`} value={value.to} min={value.from || undefined} onChange={(e) => onChange({ ...value, to: e.target.value })} />
      {(value.from || value.to) && <button type="button" className="textButton" onClick={() => onChange(noRange)}>清除日期</button>}
    </span>
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
