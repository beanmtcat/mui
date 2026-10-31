import {
  type Certificate, type FirewallRule, type ForwardRule, type Node, type NodeTemplate,
  type Role, type Route, type Server, roleLabels,
} from "../api";

export type Tab =
  | "dashboard" | "servers" | "nodes" | "templates" | "certificates" | "firewall" | "forwards" | "routes"
  | "subscriptions" | "customers" | "accesses" | "connections" | "operations" | "audit" | "help" | "settings";
export type TemplateForm = Partial<NodeTemplate> & { password?: string; shadowTlsPassword?: string };
export type ServerForm = Partial<Server> & { komariToken?: string };
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
};
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
export const emptyTemplate: Partial<NodeTemplate> = {
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
