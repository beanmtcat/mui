import { useCallback, useEffect, useMemo, useState } from "react";
import type { Certificate, Node, Operation, Server, Subscription } from "../api";
import { manualFirewall, type Tab } from "./helpers";
import { kindLabel } from "./ui";

// `key` names the problem, not its wording: "expires in 12 days" must stay read
// tomorrow. The tone is part of it, so a problem that gets worse comes back.
export type Notice = { key: string; tone: "bad" | "warn" | "info"; text: string; tab: Tab; server?: string; q?: string };

// Issues needing attention; ordinary traffic sampling states are not alerts.
export function getServerWarnings(s: Server): string[] {
  const out: string[] = [];
  if (s.detectedIpv4 && s.ipv4 && s.detectedIpv4 !== s.ipv4)
    out.push(`Agent 检测到 IPv4 ${s.detectedIpv4}，与填写的不同`);
  if (s.detectedIpv6 && s.ipv6 && s.detectedIpv6 !== s.ipv6)
    out.push(`Agent 检测到 IPv6 ${s.detectedIpv6}，与填写的不同`);
  if (Math.abs(s.clockSkewSeconds || 0) > 60)
    out.push(`系统时间与面板相差 ${s.clockSkewSeconds} 秒，请检查时间同步`);
  if (s.firewallConflict && !manualFirewall(s))
    out.push(`${s.firewallConflict} 正在管理防火墙，面板已停止写入 UFW`);
  if (s.status === "online" && s.statsStatus === "unavailable")
    out.push("节点流量采样不可用，请检查 Agent 和 sing-box");
  return out;
}

export function useAttention({
  servers,
  failedNodes,
  operations,
  certificates,
  liveSubs,
  pendingNodes,
  pendingSummary,
  serverName,
  agentReleases,
  coreReleases,
  refreshTick,
}: {
  servers: Server[];
  failedNodes: Node[];
  operations: Operation[];
  certificates: Certificate[];
  liveSubs: Subscription[];
  pendingNodes: (sub: Subscription) => string[];
  pendingSummary: (sub: Subscription) => string;
  serverName: (id: string) => string;
  agentReleases: Record<string, string>;
  coreReleases: Record<string, string>;
  refreshTick: number;
}) {
  const serverWarnings = useCallback((s: Server) => getServerWarnings(s), []);

  // Everything that wants the administrator's attention, worst first.
  const attention: Notice[] = useMemo(() => {
    const list: Notice[] = [];
    for (const sv of servers) {
      if (sv.managementMode === "offline" && (!sv.offlineExportedAt || sv.offlineExportedRevision !== sv.revision))
        list.push({ key: `export:${sv.id}`, tone: "info", tab: "servers", q: sv.name, text: `服务器 ${sv.name} 的离线配置待导出并在目标机应用` });
      else if (sv.status === "offline")
        list.push({ key: `offline:${sv.id}`, tone: "bad", tab: "servers", q: sv.name, text: `服务器 ${sv.name} 离线，最后上报于 ${sv.lastSeen ? new Date(sv.lastSeen).toLocaleString() : "未知时间"}` });
      else if (sv.status === "pending")
        list.push({ key: `pending:${sv.id}`, tone: "info", tab: "servers", q: sv.name, text: `服务器 ${sv.name} 尚未接入 Agent` });
      else {
        if (!manualFirewall(sv) && sv.ufwStatus && sv.ufwStatus !== "active" && !sv.firewallConflict)
          list.push({ key: `ufw:${sv.id}`, tone: "warn", tab: "servers", q: sv.name, text: `服务器 ${sv.name} 的 UFW 未启用，请初始化 UFW 或选择手动管理防火墙` });
        if (sv.statsStatus === "unavailable")
          list.push({ key: `stats:${sv.id}`, tone: "warn", tab: "servers", q: sv.name, text: `服务器 ${sv.name} 的流量统计不可用` });
      }
      for (const warning of serverWarnings(sv))
        list.push({ key: `warning:${sv.id}:${warning.replace(/[\d.:a-f-]+/gi, "")}`, tone: "warn", tab: "servers", q: sv.name, text: `${sv.name}：${warning}` });
    }
    for (const n of failedNodes)
      list.push({ key: `node:${n.id}`, tone: "bad", tab: "nodes", server: n.serverId, q: n.name, text: `节点 ${n.name}（${serverName(n.serverId)}）应用失败${n.error ? "：" + n.error : ""}` });
    for (const sv of servers) {
      const latest = operations.find((o) => o.serverId === sv.id);
      if (latest?.status === "failed" && !failedNodes.some((n) => n.serverId === sv.id))
        list.push({ key: `task:${latest.id}`, tone: "bad", tab: "operations", server: sv.id, text: `${sv.name} 最近一次任务失败（${kindLabel(latest.kind)}）${latest.error ? "：" + latest.error : ""}` });
    }
    for (const c of certificates) {
      // Expiry comes from the server (daysUntilExpiry / expiringSoon).
      const days = c.daysUntilExpiry;
      if (c.expiringSoon === true || (days !== undefined && days < 30)) {
        const text = days === undefined
          ? `证书 ${c.domain} 即将到期（30 天内）`
          : days < 0 ? `证书 ${c.domain} 已过期` : `证书 ${c.domain} 将在 ${days} 天后到期`;
        list.push({ key: `certificate:${c.id}`, tone: days !== undefined && days < 7 ? "bad" : "warn", tab: "certificates", q: c.domain, text });
      }
    }
    for (const sub of liveSubs) {
      const waiting = pendingNodes(sub);
      if (waiting.length)
        list.push({ key: `sub-pending:${sub.id}`, tone: "warn", tab: "subscriptions", q: sub.name, text: `订阅 ${sub.name} 有 ${waiting.length} 项尚未生效：${pendingSummary(sub)}` });
      const days = sub.expiresAt ? Math.floor((new Date(sub.expiresAt).getTime() - Date.now()) / 86400000) : Infinity;
      if (days < 7)
        list.push({ key: `sub-expiry:${sub.id}`, tone: "info", tab: "subscriptions", q: sub.name, text: `订阅 ${sub.name} 将在 ${days < 1 ? "今天" : days + " 天后"}到期` });
    }
    const upgradable = servers.filter((sv) => sv.status === "online" && (
      (sv.agentSelfUpdate && agentReleases[sv.arch] && sv.agentBuild !== agentReleases[sv.arch]) ||
      (sv.coreSelfUpdate && !!sv.coreBuild && coreReleases[sv.arch] && sv.coreBuild !== coreReleases[sv.arch])));
    if (upgradable.length)
      list.push({ key: `upgrades:${upgradable.map((sv) => sv.id).join()}`, tone: "info", tab: "servers", text: `${upgradable.length} 台服务器有可用的 Agent 或 sing-box 升级：${upgradable.map((sv) => sv.name).join("、")}` });
    const toneOrder = { bad: 0, warn: 1, info: 2 };
    list.sort((x, y) => toneOrder[x.tone] - toneOrder[y.tone]);
    for (const item of list) item.key = `${item.tone}:${item.key}`;
    return list;
  }, [servers, failedNodes, operations, certificates, liveSubs, pendingNodes, pendingSummary, serverWarnings, serverName, agentReleases, coreReleases]);

  // Read marks live in this browser. Only problems still present keep theirs,
  // so one that clears up and later returns is announced again.
  const [readAttention, setReadAttention] = useState<string[]>(() => {
    try {
      const stored: unknown = JSON.parse(localStorage.getItem("mui-attention-read") || "[]");
      return Array.isArray(stored) ? stored.filter((key): key is string => typeof key === "string") : [];
    } catch {
      return [];
    }
  });
  const saveRead = useCallback((update: (keys: string[]) => string[]) => setReadAttention((current) => {
    const next = update(current);
    try { localStorage.setItem("mui-attention-read", JSON.stringify(next)); } catch { /* Marks then last until reload. */ }
    return next;
  }), []);
  const markRead = useCallback((keys: string[]) => saveRead((current) => [...new Set([...current, ...keys])]), [saveRead]);
  const markUnread = useCallback((key: string) => saveRead((current) => current.filter((item) => item !== key)), [saveRead]);
  useEffect(() => {
    // Lists are empty until the first full refresh; that says nothing yet.
    if (!refreshTick) return;
    const present = new Set(attention.map((item) => item.key));
    if (readAttention.some((key) => !present.has(key))) saveRead((current) => current.filter((key) => present.has(key)));
  }, [attention, refreshTick, readAttention, saveRead]);
  const unreadAttention = useMemo(() => attention.filter((item) => !readAttention.includes(item.key)), [attention, readAttention]);
  const readItems = useMemo(() => attention.filter((item) => readAttention.includes(item.key)), [attention, readAttention]);

  return { serverWarnings, attention, unreadAttention, readItems, markRead, markUnread };
}

