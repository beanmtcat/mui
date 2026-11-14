// Online transit and exit servers may host nodes. Entry and line servers
// can be the first hop of a route; transit and line servers a middle hop.
export type Role = "entry" | "line" | "transit" | "exit";
export type OfflineInstallGuide = {
    migrationCommand?: string;
    proxyNotice?: string;
    command: string;
    signed: boolean;
    exampleConfig?: string;
    downloads: { arch: string; command: string; files: { name: string; url: string }[] }[];
};
export type InstallGuide = {
  installCommand: string;
  offlineInstall: OfflineInstallGuide;
  standaloneInstall: OfflineInstallGuide;
};
export const roleLabels: Record<Role, string> = { entry: "入口", line: "线路", transit: "中转", exit: "落地" };
export type BillingCycle = "" | "month" | "quarter" | "halfyear" | "year" | "2year" | "3year" | "days";
export type TrafficLimitType = "sum" | "up" | "down" | "max" | "min";
export type CycleTrafficSummary = {
  startAt: string;
  resetAt: string;
  rx: number;
  tx: number;
  used: number;
  limit: number;
  type: TrafficLimitType;
};
export type Server = {
  managementMode?: "online" | "offline" | "external";
  managementMigrationFrom?: "online" | "offline";
  offlineExportedRevision?: number;
  offlineExportedAt?: string;
  id: string;
  name: string;
  roles: Role[];
  internalAddress: string;
  outboundInterface?: string;
  outboundBindingSupport?: boolean;
  nodeDomainBlock?: boolean;
  nodeSocksOutbound?: boolean;
  firewallMode?: "ufw" | "manual";
  agentProxyNodeId?: string;
  agentProxyInternal?: boolean;
  agentProxySourceMode?: "" | "auto" | "public" | "internal";
  agentProxySupport?: boolean;
  manualFirewallSupport?: boolean;
  country: string;
  region: string;
  city: string;
  provider: string;
  tags: string;
  notes: string;
  ipv4: string;
  ipv6: string;
  autoSyncPublicIp?: boolean;
  domain: string;
  expiresAt?: string;
  price?: number;
  currency?: string;
  billingCycle?: BillingCycle;
  billingCycleDays?: number;
  autoRenew?: boolean;
  trafficLimit?: number;
  trafficLimitType?: TrafficLimitType;
  trafficResetDay?: number;
  group?: string;
  sortWeight?: number;
  alertMuted?: boolean;
  cycleTraffic?: CycleTrafficSummary;
  publicNote?: string;
  publicVisible?: boolean;
  publicName?: string;
  status: string;
  os: string;
  arch: string;
  agentVersion: string;
  agentBuild: string;
  agentSelfUpdate: boolean;
  nodeFirewallPolicies: boolean;
  multiUserStats: boolean;
  forwardSupport: boolean;
  forwardTcpUdp?: boolean;
  shadowTlsAuth?: boolean;
  snellFixedPort?: boolean;
  snellV6?: boolean;
  hostMonitor?: boolean;
  releaseKeyPinned?: boolean;
  appliedRevision: number;
  coreVersion: string;
  coreBuild: string;
  coreSelfUpdate: boolean;
  ufwStatus: string;
  statsStatus: string;
  networkRx: number;
  networkTx: number;
  lastSeen?: string;
  revision: number;
  detectedIpv4?: string;
  detectedIpv6?: string;
  clockSkewSeconds?: number;
  sshPorts?: number[] | null;
  firewallConflict?: string;
  ufwRules?: string[] | null;
};
export const canHostNodes = (server: Partial<Server>) =>
  (server.managementMode === "external" && !!server.roles?.includes("exit") ||
    server.managementMode !== "offline" && server.managementMode !== "external" && !!server.roles?.some((r) => r === "exit" || r === "transit"));

export type Node = {
  id: string;
  serverId: string;
  name: string;
  protocol: "ss" | "snell" | "anytls" | "socks5";
  singleUser?: boolean;
  username?: string;
  port: number;
  listen: string;
  publishAddress: string;
  outboundMode?: "inherit" | "system" | "interface" | "socks5" | "";
  outboundInterface?: string;
  outboundNodeId?: string;
  blockedDomains?: string[];
  method: string;
  snellVersion: number;
  snellPort?: number;
  obfs: string;
  shadowTlsHost: string;
  tlsName: string;
  certificateId: string;
  firewallPolicy: "all" | "restricted" | "manual";
  firewallSources: string;
  // Off: ordinary clients use routes. Assigned Agents get independent
  // source rules, regardless of client subscription visibility.
  direct: boolean;
  routeSources?: string;
  agentProxySources?: string;
  enabled: boolean;
  deleting?: boolean;
  status: string;
  error: string;
  uplink: number;
  downlink: number;
  createdAt: string;
};
export type NodeTemplate = {
  id: string;
  name: string;
  protocol: Node["protocol"];
  username?: string;
  port: number;
  listen: string;
  method: string;
  snellVersion: number;
  snellPort?: number;
  obfs: string;
  shadowTlsHost: string;
  tlsName: string;
};
export type Certificate = {
  id: string;
  name: string;
  domain: string;
  pendingServers?: string[];
  dnsNames?: string[];
  pem: string;
  key?: string;
  expiresAt: string;
  // Served by the backend: days until expiry and the <=30 day alert flag.
  // The frontend never computes expiry itself; missing fields mean "not expiring".
  daysUntilExpiry?: number;
  expiringSoon?: boolean;
};
export type FirewallRule = {
  id: string;
  serverId: string;
  portFrom: number;
  portTo: number;
  network: string;
  source: string;
  // Empty applies to IPv4 and IPv6; with a source, the source decides.
  family?: "" | "ipv4" | "ipv6";
  action: string;
  comment: string;
  owner: string;
  deleting?: boolean;
  status: string;
};
export type ForwardRule = {
  id: string;
  serverId: string;
  name: string;
  network: "tcp" | "udp" | "tcp+udp";
  listen: string;
  port: number;
  targets: { host: string; port: number }[];
  balance: "failover" | "round-robin" | "";
  healthCheck?: "tcp" | "none" | "";
  // Set on forwards the panel generated for a route; edit the route instead.
  routeId?: string;
  routeIds?: string[];
  firewallPolicy: "all" | "restricted" | "manual" | "closed";
  firewallSources: string;
  enabled: boolean;
  deleting: boolean;
  status: string;
  error: string;
  uplink: number;
  downlink: number;
};
export type Subscription = {
  id: string;
  name: string;
  customerId?: string;
  format: string;
  surgeTemplateId?: string;
  nodeIds: string[];
  routeIds: string[];
  enabled: boolean;
  expiresAt?: string;
  url?: string;
  uplink: number;
  downlink: number;
  pendingNodeIds?: string[];
  pendingRouteIds?: string[];
  linkAvailable?: boolean;
};
export type SurgeTemplate = { id: string; name: string; template: string; custom?: boolean };
export type RouteSourceMode = "auto" | "public" | "internal";
export type RouteSourceFamily = "ipv4" | "ipv6" | "both";
export type RouteHop = { serverIds: string[]; balance: "failover" | "round-robin"; internal: boolean; addressModes?: Record<string, "public" | "internal">; sourceMode?: RouteSourceMode; sourceFamily?: RouteSourceFamily };
export type Route = {
  id: string;
  name: string;
  entryServerId: string;
  entryFirewallPolicy?: "all" | "restricted";
  entryFirewallSources?: string;
  hops: RouteHop[];
  nodeId: string;
  nodeInternal: boolean;
  nodeSourceMode?: RouteSourceMode;
  nodeSourceFamily?: RouteSourceFamily;
  port: number;
  enabled: boolean;
  notes: string;
  status?: string;
  error?: string;
  edgeLatencies?: { fromServerId: string; toServerId: string; tcpMs: number; ok: boolean; at: string }[];
};
export type AuditEntry = { id: string; at: string; action: string; target: string; detail: string; ip: string };
export type TelegramEvents = {
  serverOffline: { enabled: boolean; offlineMinutes: number };
  applyFailed: { enabled: boolean };
  certExpiring: { enabled: boolean };
  subscriptionExpiring: { enabled: boolean };
  serverExpiring: { enabled: boolean };
  serverRenewed: { enabled: boolean };
  resource: { enabled: boolean; minutes: number; threshold: number };
  trafficLimit: { enabled: boolean; threshold: number };
  trafficReport: { daily: boolean; weekly: boolean; monthly: boolean };
  security: { enabled: boolean };
};
export type TelegramSettings = {
  enabled: boolean;
  botTokenSet: boolean;
  chatId: string;
  threadId: number;
  apiBase: string;
  events: TelegramEvents;
};
export type Customer = { id: string; name: string; notes: string; createdAt: string };
export type SubscriptionAccess = { id: string; subscriptionId: string; customerId: string; ip: string; at: string; userAgent?: string; client?: string };
export type ConnectionIP = { serverId: string; nodeId: string; ip: string; clientIp?: string; peerIp?: string; routeId?: string; sourceKind?: "entry" | "direct" | "relay" | "agent" | "unknown"; lastSeen: string; cursor: string };
export type ClientActivity = { accesses: SubscriptionAccess[]; connections: ConnectionIP[] };
export type Operation = {
  id: string;
  serverId: string;
  kind: string;
  status: string;
  error: string;
  targetBuild?: string;
  createdAt: string;
  updatedAt: string;
};
export type MonitorSample = {
  at: string;
  cpu: number;
  load1: number;
  load5: number;
  load15: number;
  ramUsed: number;
  ramTotal: number;
  swapUsed: number;
  swapTotal: number;
  diskUsed: number;
  diskTotal: number;
  netUp: number;
  netDown: number;
  netTotalUp: number;
  netTotalDown: number;
  tcp: number;
  udp: number;
  process: number;
  uptime: number;
};
export type MonitorHost = {
  cpuName: string;
  cpuCores: number;
  cpuPhysicalCores: number;
  arch: string;
  os: string;
  kernel: string;
  virtualization: string;
  memTotal: number;
  swapTotal: number;
  diskTotal: number;
};
export type MonitorOverviewItem = {
  serverId: string;
  online: boolean;
  hostMonitor: boolean;
  sample?: MonitorSample;
  host?: MonitorHost;
  cycleTraffic?: CycleTrafficSummary;
};
export type MonitorRecord = {
  at: string;
  cpu: number;
  load1: number;
  ramUsed: number;
  ramTotal: number;
  swapUsed: number;
  diskUsed: number;
  diskTotal: number;
  netUp: number;
  netDown: number;
  netUpPeak: number;
  netDownPeak: number;
  totalUp: number;
  totalDown: number;
  tcp: number;
  udp: number;
  process: number;
};
export type PingTask = {
  id: string;
  name: string;
  target: string;
  intervalSeconds: number;
  serverIds: string[];
};
export type PingMinuteRecord = {
  serverId: string;
  at: string;
  msAvg: number;
  msMax: number;
  sent: number;
  lost: number;
};
export async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  // Spread options first: its own headers must be merged, not replace these.
  const res = await fetch(path, {
    ...options,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...options.headers },
  });
  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => ({ error: "服务器响应无效" }));
  if (!res.ok) {
    if (res.status === 401 && path !== "/api/login" && path !== "/api/me") {
      window.dispatchEvent(new Event("mui:session-expired"));
    }
    const detail = body.error === "服务器响应无效" ? `HTTP ${res.status}` : body.error || `HTTP ${res.status}`;
    throw new Error(`${path}: ${detail}`);
  }
  return body as T;
}
export function mutation<T>(path: string, method: string, data?: unknown) {
  return api<T>(path, {
    method,
    // Custom CSRF header: non-simple request, so a cross-site form cannot
    // forge it. Pairs with the server's Origin check on state-changing calls.
    headers: { "X-Requested-With": "XMLHttpRequest" },
    body: data === undefined ? undefined : JSON.stringify(data),
  });
}
// Paged list envelope from the server: { items, nextCursor, total }.
// Older endpoints still return a bare array; list() normalises both.
export type Paged<T> = { items: T[]; nextCursor: string | null; total: number | null };
export async function list<T>(
  path: string,
  opts: { limit?: number; cursor?: string } = {},
): Promise<Paged<T>> {
  const limit = Math.min(Math.max(opts.limit ?? 100, 1), 500);
  const sep = path.includes("?") ? "&" : "?";
  const url = `${path}${sep}limit=${limit}` + (opts.cursor ? `&cursor=${encodeURIComponent(opts.cursor)}` : "");
  const body = await api<unknown>(url);
  if (Array.isArray(body)) return { items: body as T[], nextCursor: null, total: body.length };
  const page = body as { items?: T[]; nextCursor?: string | null; total?: number };
  return {
    items: Array.isArray(page.items) ? page.items : [],
    nextCursor: page.nextCursor ?? null,
    total: typeof page.total === "number" ? page.total : null,
  };
}
export function bytes(v: number) {
  if (!Number.isFinite(v)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}
