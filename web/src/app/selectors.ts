import type { Certificate, Customer, ForwardRule, Node, NodeTemplate, Route, Server, Subscription } from "../api";
import { screenshotText } from "../components/screenshot";
import { manualFirewall } from "./helpers";

// What a node's port really admits: route-only nodes admit their routes'
// last hops, direct ones what the administrator chose (plus route hops).
export function formatNodeAccess(servers: Server[], n: Node): string {
  if (manualFirewall(servers.find((s) => s.id === n.serverId))) return "外部管理（来源限制自行配置）";
  const routeHops = (n.routeSources || "").split(",").filter(Boolean);
  const agentSources = (n.agentProxySources || "").split(",").filter(Boolean);
  if (!n.direct) return [routeHops.length ? "链路：" + routeHops.join("、") : "", agentSources.length ? "Agent：" + agentSources.join("、") : ""].filter(Boolean).join("；") || "不开放（无链路或 Agent 使用）";
  if (n.firewallPolicy === "manual") return "手动管理";
  if (n.firewallPolicy === "restricted") return [...new Set([...n.firewallSources.split(","), ...routeHops, ...agentSources])].filter(Boolean).join("、");
  return "任意来源";
}

export function formatRoutePath(nodes: Node[], serverName: (id: string) => string, r: Route): string {
  const node = nodes.find((n) => n.id === r.nodeId);
  return [
    serverName(r.entryServerId),
    ...r.hops.map((h) => {
      const internal = h.serverIds.map((id) => h.addressModes?.[id] === "internal" || (h.addressModes?.[id] !== "public" && h.internal));
      const allInternal = internal.length > 0 && internal.every(Boolean);
      return h.serverIds.map((id, i) => serverName(id) + (!allInternal && internal[i] ? "（内网）" : ""))
        .join(h.balance === "round-robin" ? " + " : " / ") + (allInternal ? "（内网）" : "");
    }),
    (node ? `${node.name}@${serverName(node.serverId)}` : "已删除节点") + (r.nodeInternal ? "（内网）" : ""),
  ].join(" → ");
}

export function matchValidCertificate(certificates: Certificate[], tlsName: string): string {
  return certificates.find(
    (c) =>
      (c.dnsNames?.length ? c.dnsNames : [c.domain]).some((pattern) => {
        const name = tlsName.toLowerCase().replace(/\.$/, "");
        const domain = pattern.toLowerCase().replace(/\.$/, "");
        return domain === name || domain.startsWith("*.") && name.endsWith(domain.slice(1)) && name.split(".").length === domain.split(".").length;
      }) &&
      new Date(c.expiresAt).getTime() > Date.now(),
  )?.id || "";
}

export function buildScreenshotRedactor({
  servers,
  nodes,
  subs,
  customers,
  routes,
  forwards,
  certificates,
  templates,
}: {
  servers: Server[];
  nodes: Node[];
  subs: Subscription[];
  customers: Customer[];
  routes: Route[];
  forwards: ForwardRule[];
  certificates: Certificate[];
  templates: NodeTemplate[];
}) {
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
}

