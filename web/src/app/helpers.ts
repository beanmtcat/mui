import {
  type BillingCycle, type Certificate, type FirewallRule, type ForwardRule, type Node, type NodeTemplate,
  type Role, type Route, type Server, type TrafficLimitType, roleLabels,
} from "../api";

export type Tab =
  | "dashboard" | "servers" | "monitor" | "globe" | "nodes" | "templates" | "certificates" | "firewall" | "forwards" | "routes"
  | "subscriptions" | "surge-templates" | "customers" | "accesses" | "connections" | "operations" | "audit" | "help" | "settings";
export type TemplateForm = Partial<NodeTemplate> & { password?: string; shadowTlsPassword?: string };
export type ServerForm = Partial<Server>;
export type NodeForm = Partial<Node> & { password?: string; shadowTlsPassword?: string };
export type RuleForm = Partial<FirewallRule> & { replaceHostRule?: string };
export type CertificateForm = Partial<Certificate>;

export const emptyServer: Partial<Server> = {
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
  autoSyncPublicIp: false,
  domain: "",
  price: 0,
  currency: "$",
  billingCycle: "",
  billingCycleDays: 0,
  autoRenew: false,
  trafficLimit: 0,
  trafficLimitType: "sum",
  trafficResetDay: 0,
  group: "",
  sortWeight: 0,
  alertMuted: false,
  publicVisible: false,
  publicName: "",
  publicNote: "",
};
export const googleBlockedDomains = [
  "google.com", "google.co.jp", "google.com.hk", "google.cn", "googleapis.com", "gstatic.com", "googleusercontent.com",
  "googlevideo.com", "youtube.com", "youtu.be", "ytimg.com", "ggpht.com", "gmail.com", "googlemail.com",
  "googleadservices.com", "googlesyndication.com", "doubleclick.net", "googletagmanager.com", "googletagservices.com",
  "google-analytics.com", "googleoptimize.com", "gvt1.com", "gvt2.com", "1e100.net", "blogspot.com", "blogger.com", "recaptcha.net",
];

export const emptyNode: Partial<Node> = {
  serverId: "",
  name: "",
  protocol: "ss",
  singleUser: false,
  port: 50000,
  listen: "0.0.0.0",
  publishAddress: "",
  outboundMode: "inherit",
  outboundInterface: "",
  method: "2022-blake3-aes-128-gcm",
  snellVersion: 5,
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
export const emptyTemplate: Partial<NodeTemplate> = {
  name: "",
  protocol: "ss",
  port: 50000,
  listen: "0.0.0.0",
  method: "2022-blake3-aes-128-gcm",
  snellVersion: 5,
  snellPort: 20001,
  obfs: "none",
  shadowTlsHost: "",
  tlsName: "",
};
export type TrafficPoint = { at: string; uplink: number; downlink: number };
export type Usage = { id: string; uplink: number; downlink: number };
export type ServerFilterField = "country" | "provider" | "region" | "city";
export function serverFilterValues(servers: Server[], field: ServerFilterField) {
  return [...new Set(servers.map((server) => server[field]?.trim()).filter((value): value is string => !!value))]
    .sort((a, b) => a.localeCompare(b, "zh-Hans-CN"));
}
export function countryFlag(country: string) {
  const code = country.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return "";
  return String.fromCodePoint(...Array.from(code, (letter) => 0x1f1e6 + letter.charCodeAt(0) - 65));
}
export function subscriptionNodeIssue(format: string | undefined, node: Node): string {
  if (format === "v2rayn" && node.protocol !== "ss" && node.protocol !== "anytls" && node.protocol !== "socks5") return "v2rayN 订阅不支持 Snell / ShadowTLS";
  if (node.protocol === "ss") {
    if (format === "surge" && node.method === "2022-blake3-chacha20-poly1305") return "Surge 不支持 2022-blake3-chacha20-poly1305，请使用 AES 方式";
  }
  if (format === "surge" && node.protocol === "snell" && !node.shadowTlsHost && !node.singleUser) return "托管 Snell 节点的 Surge 订阅需要 ShadowTLS";
  return "";
}
export function subscriptionNodeEligible(format: string | undefined, node: Node) {
  return !subscriptionNodeIssue(format, node);
}
export function subscriptionDirectNodeIssue(format: string | undefined, node: Node): string {
  if (node.deleting) return "节点正在删除";
  if (!node.direct) return "未开启允许直连，请先编辑节点并保存";
  if (!node.enabled) return "节点已停用";
  return subscriptionNodeIssue(format, node);
}
export function sharedSubscriptionPassword(node: Node) {
  return !!node.singleUser || node.protocol === "ss" && !node.method.startsWith("2022-blake3-");
}
export function manualFirewall(server?: Partial<Server>) { return server?.firewallMode === "manual"; }
export function forwardDisplayStatus(forward: ForwardRule, server?: Server): string {
  if (server?.managementMode !== "offline") return forward.deleting ? "deleting" : forward.status;
  if (forward.deleting) return "offline-delete-pending";
  const exported = !!server.offlineExportedAt && server.offlineExportedRevision === server.revision;
  if (!exported || forward.status === "pending") return forward.enabled ? "offline-export-pending" : "offline-disable-export-pending";
  return forward.enabled ? "offline-exported" : "offline-disabled-exported";
}

export type Confirmation = {
  title: string;
  message: string;
  confirmLabel: string;
  onConfirm: () => void;
};

export function generatePassword(protocol: Node["protocol"], method = "") {
  const length = protocol === "ss" && method.startsWith("2022-")
    ? method.includes("128") ? 16 : 32
    : 32;
  const random = crypto.getRandomValues(new Uint8Array(length));
  const encoded = btoa(String.fromCharCode(...random));
  return protocol === "ss" && method.startsWith("2022-")
    ? encoded
    : encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function generatePort(excluded: ReadonlySet<number>) {
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

export function trafficSummaryURL() {
  const now = new Date();
  const day = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const month = new Date(now.getFullYear(), now.getMonth(), 1).getTime();
  return `/api/traffic/summary?dayStart=${day}&monthStart=${month}`;
}

export function trafficRankingURL() {
  const now = new Date();
  return `/api/traffic/ranking?since=${new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime()}`;
}
// One line of `ufw status numbered`, as the agent reports it.
export type HostRule = {
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
export function parseHostRule(line: string): HostRule | null {
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
export function hostRuleAdmitsSSH(r: HostRule, sshPorts: number[]) {
  if (r.action !== "ALLOW" && r.action !== "LIMIT") return false;
  if (r.allPorts || r.app) return true;
  return r.network !== "udp" && sshPorts.some((p) => p >= r.portFrom && p <= r.portTo);
}
// A rule added on the host outside the panel that the panel may remove.
export const hostRuleRemovable = (r: HostRule, sshPorts: number[]) => !r.tag && !hostRuleAdmitsSSH(r, sshPorts);
// A host rule without /tcp or /udp becomes two panel rules on adoption.
export const hostRuleConvertible = (r: HostRule) =>
  !r.allPorts && !r.app && (r.action === "ALLOW" || r.action === "DENY") && !/\s/.test(r.source);
export const emptyRule: Partial<FirewallRule> = {
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
export const emptyForward: Partial<ForwardRule> = {
  serverId: "", name: "", network: "tcp", listen: "0.0.0.0", port: 50000,
  targets: [{ host: "", port: 443 }], balance: "failover", firewallPolicy: "restricted", firewallSources: "", enabled: true,
};
export const emptyRoute: Partial<Route> = { name: "", entryServerId: "", hops: [], nodeId: "", nodeInternal: false, nodeSourceFamily: "ipv4", port: 0, enabled: true, notes: "" };
export const roleOrder: Role[] = ["entry", "line", "transit", "exit"];
export const rolesText = (roles: Role[] | undefined) => roleOrder.filter((r) => roles?.includes(r)).map((r) => roleLabels[r]).join(" / ") || "未设置";
export const supportsGitHubUpgrade = (version: string) => {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (!match) return false;
  const [major, minor, patch] = match.slice(1).map(Number);
  return major > 0 || minor > 6 || (minor === 6 && patch >= 19);
};
// Forward targets are edited as one "host:port" per line; IPv6 hosts go in
// brackets.
export const targetsText = (targets: ForwardRule["targets"] | undefined) =>
  (targets || []).map((t) => (t.host.includes(":") ? `[${t.host}]` : t.host) + (t.port ? ":" + t.port : "")).join("\n");
export const parseTargets = (text: string): ForwardRule["targets"] =>
  text.split("\n").map((line) => line.trim()).filter(Boolean).map((line) => {
    const m = line.match(/^\[(.+)\]:(\d+)$/) || line.match(/^([^:]+):(\d+)$/);
    return m ? { host: m[1], port: Number(m[2]) } : { host: line, port: 0 };
  });

const zhCollator = new Intl.Collator("zh-Hans-CN", { numeric: true, sensitivity: "base" });

export const UNGROUPED_LABEL = "未分组";
export const UNGROUPED_FILTER = "__ungrouped__";

export const billingCycleLabels: Record<Exclude<BillingCycle, "">, string> = {
  month: "月付",
  quarter: "季付",
  halfyear: "半年付",
  year: "年付",
  "2year": "两年付",
  "3year": "三年付",
  days: "按天自定义",
};

export const trafficLimitTypeLabels: Record<TrafficLimitType, string> = {
  sum: "双向合计（上行 + 下行）",
  up: "仅上行",
  down: "仅下行",
  max: "双向取大者",
  min: "双向取小者",
};

export const trafficLimitTypeShortLabels: Record<TrafficLimitType, string> = {
  sum: "上行+下行",
  up: "仅上行",
  down: "仅下行",
  max: "较大方向",
  min: "较小方向",
};

export function formatBillingCycle(server: Pick<Server, "billingCycle" | "billingCycleDays">): string {
  const c = server.billingCycle || "";
  if (!c) return "";
  if (c === "days") return server.billingCycleDays ? `每 ${server.billingCycleDays} 天` : "按天";
  return billingCycleLabels[c] || c;
}

export function serverGroupName(server: Pick<Server, "group">): string {
  return server.group?.trim() || UNGROUPED_LABEL;
}

export function serverGroupFilterOptions(servers: Server[]): { value: string; label: string }[] {
  const named = new Set<string>();
  let hasUngrouped = false;
  for (const s of servers) {
    const g = s.group?.trim() || "";
    if (!g || g === UNGROUPED_LABEL) {
      hasUngrouped = true;
    } else {
      named.add(g);
    }
  }
  const out = [...named].sort((a, b) => zhCollator.compare(a, b)).map((g) => ({ value: g, label: g }));
  if (hasUngrouped) {
    out.push({ value: UNGROUPED_FILTER, label: UNGROUPED_LABEL });
  }
  return out;
}

export function matchesServerGroupFilter(server: Pick<Server, "group">, filter: string): boolean {
  if (!filter) return true;
  const g = server.group?.trim() || "";
  if (filter === UNGROUPED_FILTER) return !g || g === UNGROUPED_LABEL;
  return g === filter;
}

export function compareServerDefault(a: Server, b: Server): number {
  const wa = a.sortWeight ?? 0;
  const wb = b.sortWeight ?? 0;
  if (wb !== wa) return wb - wa;
  return zhCollator.compare(a.name || "", b.name || "");
}

export function groupAndSortServers(
  servers: Server[],
  customSort?: (rows: Server[]) => Server[],
): { group: string; items: Server[] }[] {
  const map = new Map<string, Server[]>();
  for (const s of servers) {
    const g = serverGroupName(s);
    const list = map.get(g);
    if (list) list.push(s);
    else map.set(g, [s]);
  }
  const groups = [...map.keys()].sort((a, b) => {
    if (a === UNGROUPED_LABEL) return b === UNGROUPED_LABEL ? 0 : 1;
    if (b === UNGROUPED_LABEL) return -1;
    return zhCollator.compare(a, b);
  });
  return groups.map((group) => {
    const raw = map.get(group) || [];
    const items = customSort ? customSort(raw) : [...raw].sort(compareServerDefault);
    return { group, items };
  });
}

export function formatServerExpiry(expiresAt: string | undefined): {
  dateStr: string;
  remainText: string;
  fullText: string;
  tone: "neutral" | "warn" | "bad";
} | null {
  if (!expiresAt) return null;
  const exp = new Date(expiresAt);
  if (Number.isNaN(exp.getTime())) return null;
  const dateStr = expiresAt.slice(0, 10);
  const diffMs = exp.getTime() - Date.now();
  if (diffMs <= 0) {
    const daysAgo = Math.floor(-diffMs / 86400000);
    const remainText = daysAgo > 0 ? `已过期 ${daysAgo} 天` : "已过期";
    return {
      dateStr,
      remainText,
      fullText: `${dateStr} · ${remainText}`,
      tone: "bad",
    };
  }
  const remainDays = Math.max(1, Math.ceil(diffMs / 86400000));
  const remainText = `剩 ${remainDays} 天`;
  return {
    dateStr,
    remainText,
    fullText: `到期 ${dateStr} · ${remainText}`,
    tone: diffMs <= 7 * 86400000 ? "warn" : "neutral",
  };
}

export function cycleTrafficTone(used: number, limit: number, threshold?: number): "" | "warning" | "danger" {
  if (limit <= 0) return "";
  const pct = (used / limit) * 100;
  if (pct >= 100) return "danger";
  const effectiveThreshold = typeof threshold === "number" && threshold >= 50 && threshold <= 100 ? threshold : 80;
  if (pct >= effectiveThreshold) return "warning";
  return "";
}

export function formatMonthlyCostSummary(servers: Server[]): string {
  const totals = new Map<string, number>();
  for (const s of servers) {
    if (s.status === "revoked") continue;
    const price = s.price ?? 0;
    if (!(price > 0) || !s.billingCycle) continue;
    let monthly = 0;
    switch (s.billingCycle) {
      case "month":
        monthly = price;
        break;
      case "quarter":
        monthly = price / 3;
        break;
      case "halfyear":
        monthly = price / 6;
        break;
      case "year":
        monthly = price / 12;
        break;
      case "2year":
        monthly = price / 24;
        break;
      case "3year":
        monthly = price / 36;
        break;
      case "days": {
        const d = s.billingCycleDays ?? 0;
        if (d > 0) monthly = (price * 30) / d;
        break;
      }
    }
    if (monthly > 0) {
      const cur = (s.currency || "$").trim() || "$";
      totals.set(cur, (totals.get(cur) || 0) + monthly);
    }
  }
  if (totals.size === 0) return "";
  const parts = [...totals.entries()].map(([cur, amount]) => {
    const sep = /^[A-Za-z]+$/.test(cur) ? " " : "";
    return `${cur}${sep}${amount.toFixed(2)}`;
  });
  return `每月约 ${parts.join(" · ")}`;
}
