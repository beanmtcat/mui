import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api, list, mutation, bytes, canHostNodes,
  type Certificate, type ConnectionIP, type Customer, type FirewallRule, type ForwardRule, type InstallGuide,
  type Node, type NodeTemplate, type Operation, type Route, type Server, type Subscription,
} from "../api";
import { MemoSecretField as SecretField, MemoSecretTextarea as SecretTextarea, MemoMaskedValue as MaskedValue } from "../components/secrets";
import CertificateFileField from "../components/CertificateFileField";
import { screenshotText, screenshotView } from "../components/screenshot";
import { clearFeedback, setError, setNotice } from "./feedback";
import {
  emptyForward, emptyNode, emptyRoute, emptyServer, emptyTemplate, generatePassword, manualFirewall,
  sharedSubscriptionPassword, targetsText, trafficRankingURL, trafficSummaryURL,
  type CertificateForm, type Confirmation, type NodeForm, type RuleForm, type ServerForm, type Tab, type TemplateForm, type TrafficPoint, type Usage,
} from "./helpers";
import { collator, kindLabel } from "./ui";
import { navigate, parseHash, useServerParam, useTab } from "./url";

// `key` names the problem, not its wording: "expires in 12 days" must stay read
// tomorrow. The tone is part of it, so a problem that gets worse comes back.
export type Notice = { key: string; tone: "bad" | "warn" | "info"; text: string; tab: Tab; server?: string; q?: string };
export type ModalSpec =
  | { kind: "server"; form: ServerForm }
  | { kind: "node"; form: NodeForm; templateId: string }
  | { kind: "template"; form: TemplateForm }
  | { kind: "certificate"; form: CertificateForm }
  | { kind: "rule"; form: RuleForm }
  | { kind: "forward"; form: Partial<ForwardRule>; targets: string }
  | { kind: "route"; form: Partial<Route> }
  | { kind: "subscription"; form: Partial<Subscription> }
  | { kind: "customer"; form: Partial<Customer> };
export type BatchRun = { title: string; total: number; done: number; failures: string[]; finished: boolean };
export type { ConnectionIP };

const taskRunning = (o: Operation) => ["queued", "running", "activating"].includes(o.status);
const FAST_POLL = 4000, SLOW_POLL = 30000;

export function useAppState() {
  // A refresh that arrives during another one runs right after it, so what a
  // save just changed is never left waiting for the next poll.
  const refreshInFlight = useRef(false);
  const refreshAgain = useRef(false);
  const [refreshing, setRefreshing] = useState(false);
  const [screenshotMode, setScreenshotMode] = useState(() => localStorage.getItem("mui-screenshot-mode") === "true");
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    const stored = localStorage.getItem("mui-theme");
    return stored === "light" || stored === "dark"
      ? stored
      : matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });
  const [authed, setAuthed] = useState<boolean | null>(null),
    [totpEnabled, setTotpEnabled] = useState(false);
  const tab = useTab();
  const [currentServerId] = useServerParam();
  const [serverRecords, setServers] = useState<Server[]>([]),
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
    [coreReleases, setCoreReleases] = useState<Record<string, string>>({}),
    [komariEndpoint, setKomariEndpoint] = useState("");
  // Every list and picker of servers shows them by name, so "-2" comes before "-10".
  const servers = useMemo(() => [...serverRecords].sort((a, b) => collator.compare(a.name, b.name)), [serverRecords]);
  const [refreshTick, setRefreshTick] = useState(0),
    [pollTick, setPollTick] = useState(0);
  const [modal, setModal] = useState<ModalSpec | null>(null),
    [confirmation, setConfirmation] = useState<Confirmation | null>(null),
    [batch, setBatch] = useState<BatchRun | null>(null);
  const [installInfo, setInstallInfo] = useState<(InstallGuide & { serverName: string }) | null>(null),
    [installMethod, setInstallMethod] = useState<"online" | "offline" | "standalone">("online"),
    [installArch, setInstallArch] = useState("amd64"),
    [issued, setIssued] = useState<{ url: string; format: string } | null>(null),
    [preview, setPreview] = useState<{ content: string; excluded: string[] } | null>(null),
    [trafficNode, setTrafficNode] = useState<Node | null>(null),
    [trafficSub, setTrafficSub] = useState<Subscription | null>(null),
    [agentDownloads, setAgentDownloads] = useState<{ arch: string } | null>(null),
    [offlineServer, setOfflineServer] = useState<Server | null>(null);
  const [summary, setSummary] = useState<{
    today: { uplink: number; downlink: number };
    month: { uplink: number; downlink: number };
  }>({ today: { uplink: 0, downlink: 0 }, month: { uplink: 0, downlink: 0 } });
  const [dashSeries, setDashSeries] = useState<TrafficPoint[]>([]),
    [ranking, setRanking] = useState<{ nodes: Usage[]; subscriptions: Usage[] }>({ nodes: [], subscriptions: [] });

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
    if (refreshInFlight.current) {
      refreshAgain.current = true;
      return;
    }
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
      api<{ endpoint: string }>("/api/settings/komari").then((value) => setKomariEndpoint(value.endpoint)).catch((e) => { failures.push((e as Error).message); }),
    ]);
    setRefreshTick((tick) => tick + 1);
    if (failures.length) {
      setError(failures[0] + (failures.length > 1 ? `（另有 ${failures.length - 1} 项加载失败）` : ""));
      if (manual) setNotice("");
    } else if (manual) setNotice(`刷新完成 · ${new Date().toLocaleTimeString()}`);
    } finally {
      refreshInFlight.current = false;
      setRefreshing(false);
      if (refreshAgain.current) {
        refreshAgain.current = false;
        void refreshRef.current();
      }
    }
  }, [loadAll]);
  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;
  const serversRef = useRef(servers);
  serversRef.current = servers;
  // Set by a change the administrator just made: its result is worth watching
  // closely even before the agent has picked the task up.
  const watchUntil = useRef(0);

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
        void refresh();
      })
      .catch(() => setAuthed(false));
  }, []);
  useEffect(() => {
    if (!authed) return;
    let stopped = false, timer: ReturnType<typeof setTimeout> | undefined, polling = false, wasWorking = false;
    const pollPage = async () => {
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
          break;
        case "certificates": {
          const [n, c] = await Promise.all([loadAll<Node>("/api/nodes"), loadAll<Certificate>("/api/certificates")]);
          setNodes(n);
          setCertificates(c);
          break;
        }
        case "subscriptions":
          setSubs(await loadAll<Subscription>("/api/subscriptions"));
          break;
      }
      setPollTick((value) => value + 1);
    };
    // Tasks a live agent is working through. One queued for an offline server
    // can wait for days and must not keep the page polling at full speed.
    const stillWorking = async () => {
      const recent = (await list<Operation>("/api/operations", { limit: 30 })).items;
      setOperations((current) => {
        const known = new Set(recent.map((o) => o.id));
        return [...recent, ...current.filter((o) => !known.has(o.id))];
      });
      const online = new Set(serversRef.current.filter((s) => s.status === "online").map((s) => s.id));
      return recent.some((o) => taskRunning(o) && online.has(o.serverId));
    };
    const poll = async () => {
      if (polling || document.hidden) return;
      polling = true;
      try {
        await pollPage();
        const working = await stillWorking();
        // Everything a finished task touched, not only this page's lists.
        if (wasWorking && !working) void refreshRef.current();
        wasWorking = working;
      } catch (e) {
        setError((e as Error).message);
      } finally {
        polling = false;
      }
    };
    const schedule = () => {
      if (stopped) return;
      clearTimeout(timer);
      timer = setTimeout(() => void poll().then(schedule), wasWorking || Date.now() < watchUntil.current ? FAST_POLL : SLOW_POLL);
    };
    const onVisible = () => { if (!document.hidden) void poll(); };
    const onWatch = () => { clearTimeout(timer); schedule(); };
    schedule();
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("mui:watch", onWatch);
    return () => {
      stopped = true;
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("mui:watch", onWatch);
    };
  }, [authed, tab]);

  const activeNodes = useMemo(() => nodes.filter((n) => n.status === "active" && n.enabled), [nodes]);
  const onlineServers = useMemo(() => servers.filter((s) => s.status === "online"), [servers]);
  const agentServers = useMemo(() => servers.filter((s) => s.managementMode !== "offline" && s.managementMode !== "external"), [servers]);
  const upgradingAgentIDs = useMemo(() => new Set(operations
    .filter((o) => o.kind === "agent.upgrade" && ["queued", "running", "activating"].includes(o.status))
    .map((o) => o.serverId)), [operations]);
  const updatingAgentIDs = useMemo(() => new Set(operations
    .filter((o) => o.kind === "nodes.apply" && ["queued", "running"].includes(o.status))
    .map((o) => o.serverId)), [operations]);
  const forwardServerIDs = useMemo(() => new Set(forwards.map((f) => f.serverId)), [forwards]);
  // Issues needing attention; ordinary traffic sampling states are not alerts.
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
    if (s.status === "online" && s.statsStatus === "unavailable")
      out.push("节点流量采样不可用，请检查 Agent 和 sing-box");
    return out;
  }, []);
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
    const names = [...new Set(nodeIds.map((id) => nodes.find((n) => n.id === id)).filter((n): n is Node => !!n && !sharedSubscriptionPassword(n)).map((n) => n.serverId))]
      .map((id) => serverName(id as string));
    return names.length
      ? `\n\n以下服务器的 sing-box 会重启，其上所有连接将中断数秒：${names.join("、")}`
      : "";
  }, [nodes, serverName]);
  // Resolves as soon as the change is accepted. The lists refresh behind the
  // scenes, so a dialog closes at once instead of waiting for every list.
  const act = useCallback(async (
    fn: () => Promise<unknown>,
    success = "操作已提交",
  ): Promise<boolean> => {
    clearFeedback();
    try {
      await fn();
      setNotice(success);
      watchUntil.current = Date.now() + 60000;
      window.dispatchEvent(new Event("mui:watch"));
      void refresh();
      return true;
    } catch (e) {
      setError((e as Error).message);
      return false;
    }
  }, [refresh]);
  // Runs one action over many rows, a few at a time, and reports each failure
  // by name: one refused row must not hide what happened to the others.
  const runBatch = useCallback(async <T,>(title: string, rows: T[], label: (row: T) => string, task: (row: T) => Promise<unknown>) => {
    const failures: string[] = [];
    let done = 0;
    setBatch({ title, total: rows.length, done, failures, finished: false });
    const queue = [...rows];
    await Promise.all(Array.from({ length: Math.min(4, rows.length) }, async () => {
      for (let row = queue.shift(); row !== undefined; row = queue.shift()) {
        try {
          await task(row);
        } catch (e) {
          failures.push(`${label(row)}：${(e as Error).message.replace(/^\/api\/[^\s:]+:\s*/, "")}`);
        }
        done++;
        setBatch({ title, total: rows.length, done, failures: [...failures], finished: false });
      }
    }));
    setBatch({ title, total: rows.length, done, failures: [...failures], finished: true });
    watchUntil.current = Date.now() + 60000;
    window.dispatchEvent(new Event("mui:watch"));
    void refresh();
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
  const goTo = useCallback((target: Tab, serverId?: string, filters?: Record<string, string>) => {
    const current = parseHash().params.get("server") || "";
    const selected = serverId ?? current;
    navigate(target, selected || (target === "firewall" ? serversRef.current[0]?.id || "" : ""), filters);
    clearFeedback();
  }, []);
  const openModal = useCallback((spec: ModalSpec) => {
    clearFeedback();
    setModal(spec);
  }, []);
  const closeModal = useCallback(() => setModal(null), []);
  const openServer = (s?: Server) => openModal({ kind: "server", form: s ? { ...s } : { ...emptyServer } });
  const openNode = (n?: Node) => {
    const newServerId = servers.find((s) => s.id === currentServerId && canHostNodes(s))?.id || servers.find((s) => canHostNodes(s))?.id || "";
    const sellerNode = servers.find((s) => s.id === newServerId)?.managementMode === "external";
    openModal({
      kind: "node", templateId: "",
      form: n
        ? { ...n, snellPort: n.snellPort || 20000 + n.port % 10000, password: "", shadowTlsPassword: "" }
        : { ...emptyNode, serverId: newServerId, singleUser: sellerNode, direct: sellerNode, firewallPolicy: sellerNode ? "manual" : "all" },
    });
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
  // The form a template fills in, its stored passwords included.
  const templateNodeForm = async (template: NodeTemplate, serverId: string): Promise<NodeForm> => {
    const detail = await api<NodeTemplate & { password: string; shadowTlsPassword: string }>(`/api/node-templates/${template.id}`);
    return {
      ...emptyNode,
      serverId: serverId || servers.find((s) => canHostNodes(s))?.id || "",
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
    };
  };
  const useTemplate = async (template: NodeTemplate) => {
    try {
      const form = await templateNodeForm(template, currentServerId);
      goTo("nodes");
      openModal({ kind: "node", form, templateId: template.id });
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const openTemplate = async (source?: NodeTemplate | Node) => {
    try {
      const secrets = source
        ? "serverId" in source
          ? await api<{ password: string; shadowTlsPassword: string }>(`/api/nodes/${source.id}/secret`)
          : await api<NodeTemplate & { password: string; shadowTlsPassword: string }>(`/api/node-templates/${source.id}`)
        : { password: "", shadowTlsPassword: "" };
      openModal({
        kind: "template",
        form: source
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
      });
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const openForward = (f?: ForwardRule) => {
    const form = f ? { ...f } : { ...emptyForward, serverId: servers.find((s) => s.id === currentServerId && s.managementMode !== "external")?.id || servers.find((s) => s.managementMode !== "external")?.id || "" };
    openModal({ kind: "forward", form, targets: targetsText(form.targets) });
  };
  const openRoute = (r?: Route) => openModal({ kind: "route", form: r ? { ...r, hops: r.hops.map((h) => ({ ...h, serverIds: [...h.serverIds] })) } : { ...emptyRoute } });
  const openSubscription = (s?: Subscription) => {
    setIssued(null);
    openModal({ kind: "subscription", form: s ? { ...s } : { name: "", format: "sing-box", nodeIds: [], routeIds: [], enabled: true } });
  };
  const showInstall = (guide: InstallGuide, serverName: string, method: "online" | "offline", arch: string) => {
    setInstallMethod(method);
    setInstallArch(arch === "arm64" ? "arm64" : "amd64");
    setInstallInfo({ ...guide, serverName });
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
      message: s.managementMode === "external" ? `删除「${s.name}」的面板档案及其节点和订阅引用？不会触及卖家服务器。` : `服务器「${s.name}」已离线，无法确认节点已停止。\n强制删除会同时移除它的节点、转发、规则和流量记录，且不可恢复。`,
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
  const auditTarget = useCallback((id: string) =>
    servers.find((x) => x.id === id)?.name || nodes.find((x) => x.id === id)?.name ||
    subs.find((x) => x.id === id)?.name || customers.find((x) => x.id === id)?.name ||
    (id.length > 12 ? id.slice(0, 8) + "…" : id), [servers, nodes, subs, customers]);

  const liveSubs = useMemo(() => subs.filter((sub) => sub.enabled && (!sub.expiresAt || new Date(sub.expiresAt).getTime() > Date.now())), [subs]);
  const failedNodes = useMemo(() => nodes.filter((n) => n.status === "error"), [nodes]);
  const split = useCallback((v: { uplink: number; downlink: number }) => `↑ ${bytes(v.uplink)} · ↓ ${bytes(v.downlink)}`, []);
  // Everything that wants the administrator's attention, worst first.
  const attention: Notice[] = useMemo(() => {
  const list: Notice[] = [];
  // Alias so the pushes below keep their original shape.
  const attention = list;
  for (const sv of servers) {
    if (sv.managementMode === "offline" && (!sv.offlineExportedAt || sv.offlineExportedRevision !== sv.revision))
      attention.push({ key: `export:${sv.id}`, tone: "info", tab: "servers", q: sv.name, text: `服务器 ${sv.name} 的离线配置待导出并在目标机应用` });
    else if (sv.status === "offline")
      attention.push({ key: `offline:${sv.id}`, tone: "bad", tab: "servers", q: sv.name, text: `服务器 ${sv.name} 离线，最后上报于 ${sv.lastSeen ? new Date(sv.lastSeen).toLocaleString() : "未知时间"}` });
    else if (sv.status === "pending")
      attention.push({ key: `pending:${sv.id}`, tone: "info", tab: "servers", q: sv.name, text: `服务器 ${sv.name} 尚未接入 Agent` });
    else {
      if (!manualFirewall(sv) && sv.ufwStatus && sv.ufwStatus !== "active" && !sv.firewallConflict)
        attention.push({ key: `ufw:${sv.id}`, tone: "warn", tab: "servers", q: sv.name, text: `服务器 ${sv.name} 的 UFW 未启用，请初始化 UFW 或选择手动管理防火墙` });
      if (sv.statsStatus === "unavailable")
        attention.push({ key: `stats:${sv.id}`, tone: "warn", tab: "servers", q: sv.name, text: `服务器 ${sv.name} 的流量统计不可用` });
    }
    for (const warning of serverWarnings(sv))
      attention.push({ key: `warning:${sv.id}:${warning.replace(/[\d.:a-f-]+/gi, "")}`, tone: "warn", tab: "servers", q: sv.name, text: `${sv.name}：${warning}` });
  }
  for (const n of failedNodes)
    attention.push({ key: `node:${n.id}`, tone: "bad", tab: "nodes", server: n.serverId, q: n.name, text: `节点 ${n.name}（${serverName(n.serverId)}）应用失败${n.error ? "：" + n.error : ""}` });
  for (const sv of servers) {
    const latest = operations.find((o) => o.serverId === sv.id);
    if (latest?.status === "failed" && !failedNodes.some((n) => n.serverId === sv.id))
      attention.push({ key: `task:${latest.id}`, tone: "bad", tab: "operations", server: sv.id, text: `${sv.name} 最近一次任务失败（${kindLabel(latest.kind)}）${latest.error ? "：" + latest.error : ""}` });
  }
  for (const c of certificates) {
    // Expiry comes from the server (daysUntilExpiry / expiringSoon).
    const days = c.daysUntilExpiry;
    if (c.expiringSoon === true || (days !== undefined && days < 30)) {
      const text = days === undefined
        ? `证书 ${c.domain} 即将到期（30 天内）`
        : days < 0 ? `证书 ${c.domain} 已过期` : `证书 ${c.domain} 将在 ${days} 天后到期`;
      attention.push({ key: `certificate:${c.id}`, tone: days !== undefined && days < 7 ? "bad" : "warn", tab: "certificates", q: c.domain, text });
    }
  }
  for (const sub of liveSubs) {
    const waiting = pendingNodes(sub);
    if (waiting.length)
      attention.push({ key: `sub-pending:${sub.id}`, tone: "warn", tab: "subscriptions", q: sub.name, text: `订阅 ${sub.name} 有 ${waiting.length} 项尚未生效：${pendingSummary(sub)}` });
    const days = sub.expiresAt ? Math.floor((new Date(sub.expiresAt).getTime() - Date.now()) / 86400000) : Infinity;
    if (days < 7)
      attention.push({ key: `sub-expiry:${sub.id}`, tone: "info", tab: "subscriptions", q: sub.name, text: `订阅 ${sub.name} 将在 ${days < 1 ? "今天" : days + " 天后"}到期` });
  }
  const upgradable = servers.filter((sv) => sv.status === "online" && (
    (sv.agentSelfUpdate && agentReleases[sv.arch] && sv.agentBuild !== agentReleases[sv.arch]) ||
    (sv.coreSelfUpdate && !!sv.coreBuild && coreReleases[sv.arch] && sv.coreBuild !== coreReleases[sv.arch])));
  if (upgradable.length)
    attention.push({ key: `upgrades:${upgradable.map((sv) => sv.id).join()}`, tone: "info", tab: "servers", text: `${upgradable.length} 台服务器有可用的 Agent 或 sing-box 升级：${upgradable.map((sv) => sv.name).join("、")}` });
  const toneOrder = { bad: 0, warn: 1, info: 2 };
  attention.sort((x, y) => toneOrder[x.tone] - toneOrder[y.tone]);
  for (const item of list) item.key = `${item.tone}:${item.key}`;
  return list;
  }, [servers, failedNodes, operations, certificates, liveSubs, pendingNodes, pendingSummary, serverWarnings, serverName, agentReleases, coreReleases]);
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
  const surgeImportHelp = (value: string) => {
    const line = `MUI = select, policy-path=${value}, update-interval=3600`;
    return <div className="surgeImportHelp">
      <p className="hint">导入 Surge 节点：编辑正在使用的配置，把下面这一行放进已有的 [Proxy Group] 段，保存并重新加载。然后把 MUI 加入现有规则所使用的代理组，即可从 MUI 组中选择节点。</p>
      <MaskedValue value={line} pre><button className="ghost" type="button" onClick={() => void copy(line)}>复制 Surge 代理组配置</button></MaskedValue>
      <p className="hint">本链接提供节点列表。通过 policy-path 引用会自动更新节点；不要把它当完整配置安装，否则会提示“规则必须以 FINAL 结尾”。已有配置的分流规则继续使用。</p>
    </div>;
  };
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
  }, [attention, refreshTick]);
  const unreadAttention = useMemo(() => attention.filter((item) => !readAttention.includes(item.key)), [attention, readAttention]);
  const readItems = useMemo(() => attention.filter((item) => readAttention.includes(item.key)), [attention, readAttention]);
  const protect = useCallback((tree: React.ReactNode) => screenshotMode
    ? screenshotView(tree, redactScreenshot, new Set([SecretField, SecretTextarea, MaskedValue, CertificateFileField])) : tree, [screenshotMode, redactScreenshot]);
  const expiring = useMemo(() => certificates.filter(
    (c) => c.expiringSoon === true || (c.daysUntilExpiry !== undefined && c.daysUntilExpiry <= 30),
  ), [certificates]);
  return {
    refreshing, screenshotMode, setScreenshotMode, theme, setTheme, authed, setAuthed, totpEnabled, setTotpEnabled, tab, currentServerId,
    servers, nodes, templates, certificates, rules, forwards, routes, subs, customers, operations, agentReleases, coreReleases,
    komariEndpoint, setKomariEndpoint, refreshTick, pollTick, modal, confirmation, setConfirmation, batch, setBatch,
    installInfo, setInstallInfo, installMethod, setInstallMethod, installArch, setInstallArch, issued, setIssued, preview, setPreview,
    trafficNode, setTrafficNode, trafficSub, setTrafficSub, agentDownloads, setAgentDownloads, offlineServer, setOfflineServer,
    summary, dashSeries, ranking, refresh, act, runBatch, copy, goTo, openModal, closeModal, openServer, openNode, openForward, openRoute,
    openSubscription, openTemplate, useTemplate, templateNodeForm, matchingCertificate, showInstall, deleteItem, deleteServer, matches,
    auditTarget, attention, unreadAttention, readItems, markRead, markUnread, liveSubs, failedNodes, split, activeNodes, onlineServers, agentServers, upgradingAgentIDs, updatingAgentIDs,
    forwardServerIDs, serverWarnings, nodeAccessText, serverName, pendingNodes, pendingSummary, subNodeIds, subMemberNodes, sharedSubNodes,
    onlySharedSubNodes, routePath, restartNotice, surgeImportHelp, protect, redactScreenshot, expiring,
  };
}

export type App = ReturnType<typeof useAppState>;
