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
export type Server = {
  managementMode?: "online" | "offline";
  managementMigrationFrom?: "online" | "offline";
  offlineExportedRevision?: number;
  offlineExportedAt?: string;
  id: string;
  name: string;
  roles: Role[];
  internalAddress: string;
  outboundInterface?: string;
  outboundBindingSupport?: boolean;
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
	komariTokenSet?: boolean;
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
  server.managementMode !== "offline" && !!server.roles?.some((r) => r === "exit" || r === "transit");

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
  outboundMode?: "inherit" | "system" | "interface" | "";
  outboundInterface?: string;
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
export type RouteSourceMode = "auto" | "public" | "internal";
export type RouteHop = { serverIds: string[]; balance: "failover" | "round-robin"; internal: boolean; sourceMode?: RouteSourceMode };
export type Route = {
  id: string;
  name: string;
  entryServerId: string;
  hops: RouteHop[];
  nodeId: string;
  nodeInternal: boolean;
  nodeSourceMode?: RouteSourceMode;
  port: number;
  enabled: boolean;
  notes: string;
  status?: string;
};
export type AuditEntry = { id: string; at: string; action: string; target: string; detail: string; ip: string };
export type Customer = { id: string; name: string; notes: string; createdAt: string };
export type SubscriptionAccess = { id: string; subscriptionId: string; customerId: string; ip: string; at: string };
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
export async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
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
