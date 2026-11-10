import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api, list, mutation, bytes, canHostNodes,
  type Certificate, type ConnectionIP, type Customer, type FirewallRule, type ForwardRule, type InstallGuide,
  type Node, type NodeTemplate, type Operation, type Route, type Server, type Subscription, type SurgeTemplate,
} from "../api";
import { MemoSecretField as SecretField, MemoSecretTextarea as SecretTextarea, MemoMaskedValue as MaskedValue } from "../components/secrets";
import CertificateFileField from "../components/CertificateFileField";
import { screenshotView } from "../components/screenshot";
import { useAttention, type Notice } from "./attention";
import { clearFeedback, setError, setNotice } from "./feedback";
import {
  emptyForward, emptyNode, emptyRoute, emptyServer, emptyTemplate, generatePassword,
  sharedSubscriptionPassword, targetsText, trafficRankingURL, trafficSummaryURL,
  type CertificateForm, type Confirmation, type NodeForm, type RuleForm, type ServerForm, type Tab, type TemplateForm, type TrafficPoint, type Usage,
} from "./helpers";
import { buildScreenshotRedactor, formatNodeAccess, formatRoutePath, matchValidCertificate } from "./selectors";
import { collator } from "./ui";
import { navigate, parseHash, useServerParam, useTab } from "./url";

export type { Notice };
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
const secretComponents = new Set<unknown>([SecretField, SecretTextarea, MaskedValue, CertificateFileField]);

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
  const tabRef = useRef(tab);
  tabRef.current = tab;
  const [currentServerId] = useServerParam();
  const [serverRecords, setServers] = useState<Server[]>([]),
    [nodes, setNodes] = useState<Node[]>([]),
    [templates, setTemplates] = useState<NodeTemplate[]>([]),
    [certificates, setCertificates] = useState<Certificate[]>([]),
    [rules, setRules] = useState<FirewallRule[]>([]),
    [forwards, setForwards] = useState<ForwardRule[]>([]),
    [routes, setRoutes] = useState<Route[]>([]),
    [subs, setSubs] = useState<Subscription[]>([]),
    [surgeTemplates, setSurgeTemplates] = useState<SurgeTemplate[]>([]),
    [surgeTemplatesStatus, setSurgeTemplatesStatus] = useState<"loading" | "ready" | "error">("loading"),
    [customers, setCustomers] = useState<Customer[]>([]),
    [operations, setOperations] = useState<Operation[]>([]),
    [agentReleases, setAgentReleases] = useState<Record<string, string>>({}),
    [coreReleases, setCoreReleases] = useState<Record<string, string>>({});
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
  // complete. Uses the server's maximum page size (500) to minimise round-trips.
  const loadAll = useCallback(async <T,>(path: string): Promise<T[]> => {
    const out: T[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 20; page++) {
      const res = await list<T>(path, { limit: 500, cursor });
      out.push(...res.items);
      if (!res.nextCursor) break;
      cursor = res.nextCursor;
    }
    return out;
  }, []);

  const loadDashboardTraffic = useCallback(async (onFailure?: (msg: string) => void) => {
    const fail = (e: unknown) => { if (onFailure) onFailure((e as Error).message); };
    await Promise.all([
      api<{ today: { uplink: number; downlink: number }; month: { uplink: number; downlink: number } }>(trafficSummaryURL()).then(setSummary).catch(fail),
      api<TrafficPoint[]>("/api/traffic/series?hours=24").then(setDashSeries).catch(fail),
      api<{ nodes: Usage[]; subscriptions: Usage[] }>(trafficRankingURL()).then(setRanking).catch(fail),
    ]);
  }, []);

  const refresh = useCallback(async (manual = false) => {
    if (refreshInFlight.current) {
      refreshAgain.current = true;
      return;
    }
    refreshInFlight.current = true;
    setRefreshing(true);
    setSurgeTemplatesStatus("loading");
    if (manual) { setError(""); setNotice("正在刷新…"); }
    try {
      // Each list loads on its own: one failing endpoint must not leave every
      // other part of the page showing stale data.
      const failures: string[] = [];
      const recordFailure = (msg: string) => { failures.push(msg); };
      const load = <T,>(path: string, apply: (value: T[]) => void) =>
        loadAll<T>(path).then(apply).catch((e) => recordFailure((e as Error).message));
      const withTraffic = tabRef.current === "dashboard";
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
        api<SurgeTemplate[]>("/api/surge-templates")
          .then((items) => { setSurgeTemplates(items); setSurgeTemplatesStatus("ready"); })
          .catch((e) => { setSurgeTemplatesStatus("error"); recordFailure((e as Error).message); }),
        list<Operation>("/api/operations", { limit: 200 }).then((res) => setOperations(res.items)).catch((e) => recordFailure((e as Error).message)),
        load<Customer>("/api/customers", setCustomers),
        api<Record<string, string>>("/api/agent/release").then(setAgentReleases).catch(() => setAgentReleases({})),
        api<Record<string, string>>("/api/core/release").then(setCoreReleases).catch(() => setCoreReleases({})),
        ...(withTraffic ? [loadDashboardTraffic(recordFailure)] : []),
      ]);
      if (!withTraffic && tabRef.current === "dashboard") {
        await loadDashboardTraffic(recordFailure);
      }
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
  }, [loadAll, loadDashboardTraffic]);

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
  }, [refresh]);
  useEffect(() => {
    if (authed && tab === "dashboard" && !refreshInFlight.current) {
      void loadDashboardTraffic((msg) => setError(msg));
    }
  }, [authed, tab, loadDashboardTraffic]);
  useEffect(() => {
    if (!authed) return;
    let stopped = false, timer: ReturnType<typeof setTimeout> | undefined, polling = false, wasWorking = false;
    const pollPage = async () => {
      switch (tab) {
        case "dashboard": {
          const [s, n, u] = await Promise.all([
            loadAll<Server>("/api/servers"),
            loadAll<Node>("/api/nodes"),
            loadAll<Subscription>("/api/subscriptions"),
            loadDashboardTraffic((msg) => setError(msg)),
          ]);
          setServers(s);
          setNodes(n);
          setSubs(u);
          break;
        }
        case "servers":
          setServers(await loadAll<Server>("/api/servers"));
          break;
        case "globe": {
          const [s, n, r] = await Promise.all([loadAll<Server>("/api/servers"), loadAll<Node>("/api/nodes"), loadAll<Route>("/api/routes")]);
          setServers(s);
          setNodes(n);
          setRoutes(r);
          break;
        }
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
      const recent = (await list<Operation>("/api/operations", { limit: 50 })).items;
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
  }, [authed, tab, loadAll, loadDashboardTraffic]);

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
  const liveSubs = useMemo(() => subs.filter((sub) => sub.enabled && (!sub.expiresAt || new Date(sub.expiresAt).getTime() > Date.now())), [subs]);
  const failedNodes = useMemo(() => nodes.filter((n) => n.status === "error"), [nodes]);
  const expiring = useMemo(() => certificates.filter(
    (c) => c.expiringSoon === true || (c.daysUntilExpiry !== undefined && c.daysUntilExpiry <= 30),
  ), [certificates]);

  const nodeAccessText = useCallback((n: Node) => formatNodeAccess(servers, n), [servers]);
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
  const subMemberNodes = useCallback((sub: Partial<Subscription>) => {
    const ids = new Set(subNodeIds(sub));
    return nodes.filter((n) => ids.has(n.id));
  }, [nodes, subNodeIds]);
  const sharedSubNodes = useCallback((sub: Partial<Subscription>) => subMemberNodes(sub).filter(sharedSubscriptionPassword), [subMemberNodes]);
  const onlySharedSubNodes = useCallback((sub: Partial<Subscription>) => {
    const members = subMemberNodes(sub);
    return members.length > 0 && members.every(sharedSubscriptionPassword);
  }, [subMemberNodes]);
  const routePath = useCallback((r: Route) => formatRoutePath(nodes, serverName, r), [nodes, serverName]);
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
  const openServer = useCallback((s?: Server) => openModal({ kind: "server", form: s ? { ...s } : { ...emptyServer } }), [openModal]);
  const openNode = useCallback((n?: Node) => {
    const newServerId = servers.find((s) => s.id === currentServerId && canHostNodes(s))?.id || servers.find((s) => canHostNodes(s))?.id || "";
    const sellerNode = servers.find((s) => s.id === newServerId)?.managementMode === "external";
    openModal({
      kind: "node", templateId: "",
      form: n
        ? { ...n, snellPort: n.snellPort || 20000 + n.port % 10000, password: "", shadowTlsPassword: "" }
        : { ...emptyNode, serverId: newServerId, singleUser: sellerNode, direct: sellerNode, firewallPolicy: sellerNode ? "manual" : "all" },
    });
  }, [servers, currentServerId, openModal]);
  const matchingCertificate = useCallback((tlsName: string) => matchValidCertificate(certificates, tlsName), [certificates]);
  // The form a template fills in, its stored passwords included.
  const templateNodeForm = useCallback(async (template: NodeTemplate, serverId: string): Promise<NodeForm> => {
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
      certificateId: detail.protocol === "anytls" ? matchingCertificate(detail.tlsName) : "",
      password: detail.password || generatePassword(detail.protocol, detail.method),
      shadowTlsPassword: detail.protocol === "snell" ? detail.shadowTlsPassword || generatePassword("snell") : "",
    };
  }, [servers, matchingCertificate]);
  const useTemplate = useCallback(async (template: NodeTemplate) => {
    try {
      const form = await templateNodeForm(template, currentServerId);
      goTo("nodes");
      openModal({ kind: "node", form, templateId: template.id });
    } catch (e) {
      setError((e as Error).message);
    }
  }, [templateNodeForm, currentServerId, goTo, openModal]);
  const openTemplate = useCallback(async (source?: NodeTemplate | Node) => {
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
            snellVersion: "serverId" in source && source.protocol === "snell" && source.snellVersion === 6 ? 5 : source.snellVersion,
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
  }, [openModal]);
  const openForward = useCallback((f?: ForwardRule) => {
    const form = f ? { ...f } : { ...emptyForward, serverId: servers.find((s) => s.id === currentServerId && s.managementMode !== "external")?.id || servers.find((s) => s.managementMode !== "external")?.id || "" };
    openModal({ kind: "forward", form, targets: targetsText(form.targets) });
  }, [servers, currentServerId, openModal]);
  const openRoute = useCallback((r?: Route) => openModal({ kind: "route", form: r ? { ...r, hops: r.hops.map((h) => ({ ...h, serverIds: [...h.serverIds] })) } : { ...emptyRoute } }), [openModal]);
  const openSubscription = useCallback((s?: Subscription) => {
    setIssued(null);
    openModal({ kind: "subscription", form: s ? { ...s } : { name: "", format: "sing-box", nodeIds: [], routeIds: [], enabled: true } });
  }, [openModal]);
  const showInstall = useCallback((guide: InstallGuide, serverNameText: string, method: "online" | "offline", arch: string) => {
    setInstallMethod(method);
    setInstallArch(arch === "arm64" ? "arm64" : "amd64");
    setInstallInfo({ ...guide, serverName: serverNameText });
  }, []);
  const deleteItem = useCallback((path: string, label: string, feedback?: { message: string; success: string }) => {
    setConfirmation({
      title: `删除${label}`,
      message: feedback?.message || `确定删除${label}？此操作无法撤销。`,
      confirmLabel: "删除",
      onConfirm: () => { void act(() => mutation(path, "DELETE"), feedback?.success || `${label}已删除`); },
    });
  }, [act]);
  const deleteServer = useCallback((s: Server) => {
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
  }, [nodes, rules, forwards, deleteItem, act]);
  const matches = useCallback((query: string, ...fields: (string | undefined)[]) => {
    const q = query.trim().toLowerCase();
    return !q || fields.some((field) => (field || "").toLowerCase().includes(q));
  }, []);
  const auditTarget = useCallback((id: string) =>
    servers.find((x) => x.id === id)?.name || nodes.find((x) => x.id === id)?.name ||
    subs.find((x) => x.id === id)?.name || customers.find((x) => x.id === id)?.name ||
    surgeTemplates.find((x) => x.id === id)?.name || (id === "default" ? "默认模板" : "") ||
    (id.length > 12 ? id.slice(0, 8) + "…" : id), [servers, nodes, subs, customers, surgeTemplates]);
  const split = useCallback((v: { uplink: number; downlink: number }) => `↑ ${bytes(v.uplink)} · ↓ ${bytes(v.downlink)}`, []);

  const { serverWarnings, attention, unreadAttention, readItems, markRead, markUnread } = useAttention({
    servers, failedNodes, operations, certificates, liveSubs,
    pendingNodes, pendingSummary, serverName, agentReleases, coreReleases, refreshTick,
  });

  const redactScreenshot = useMemo(() => buildScreenshotRedactor({
    servers, nodes, subs, customers, routes, forwards, certificates, templates, surgeTemplates,
  }), [servers, nodes, subs, customers, routes, forwards, certificates, templates, surgeTemplates]);

  const surgeImportHelp = useCallback((value: string) => {
    const line = `MUI = select, policy-path=${value}, update-interval=3600`;
    const profile = `${value}?profile=1`;
    return <div className="surgeImportHelp">
      <p className="hint">没有现成配置：在 Surge 中选“从 URL 安装配置”，粘贴下面的完整配置链接。它按该订阅选择的“Surge 模板”生成；默认模板包含节点选择、自动测速、故障转移和常用分流。Surge 每 12 小时自动更新；在 Surge 里手动修改会在更新时被覆盖。</p>
      <MaskedValue value={profile}><button className="ghost" type="button" onClick={() => void copy(profile)}>复制完整配置链接</button></MaskedValue>
      <p className="hint">已有自己的配置：编辑正在使用的配置，把下面这一行放进已有的 [Proxy Group] 段，保存并重新加载。然后把 MUI 加入现有规则所使用的代理组，即可从 MUI 组中选择节点，原有分流规则继续使用。</p>
      <MaskedValue value={line} pre><button className="ghost" type="button" onClick={() => void copy(line)}>复制 Surge 代理组配置</button></MaskedValue>
    </div>;
  }, [copy]);

  const protect = useCallback((tree: React.ReactNode) => screenshotMode
    ? screenshotView(tree, redactScreenshot, secretComponents) : tree, [screenshotMode, redactScreenshot]);

  return useMemo(() => ({
    refreshing, screenshotMode, setScreenshotMode, theme, setTheme, authed, setAuthed, totpEnabled, setTotpEnabled, tab, currentServerId,
    servers, nodes, templates, certificates, rules, forwards, routes, subs, surgeTemplates, surgeTemplatesStatus, customers, operations, agentReleases, coreReleases,
    refreshTick, pollTick, modal, confirmation, setConfirmation, batch, setBatch,
    installInfo, setInstallInfo, installMethod, setInstallMethod, installArch, setInstallArch, issued, setIssued, preview, setPreview,
    trafficNode, setTrafficNode, trafficSub, setTrafficSub, agentDownloads, setAgentDownloads, offlineServer, setOfflineServer,
    summary, dashSeries, ranking, refresh, act, runBatch, copy, goTo, openModal, closeModal, openServer, openNode, openForward, openRoute,
    openSubscription, openTemplate, useTemplate, templateNodeForm, matchingCertificate, showInstall, deleteItem, deleteServer, matches,
    auditTarget, attention, unreadAttention, readItems, markRead, markUnread, liveSubs, failedNodes, split, activeNodes, onlineServers, agentServers, upgradingAgentIDs, updatingAgentIDs,
    forwardServerIDs, serverWarnings, nodeAccessText, serverName, pendingNodes, pendingSummary, subNodeIds, subMemberNodes, sharedSubNodes,
    onlySharedSubNodes, routePath, restartNotice, surgeImportHelp, protect, redactScreenshot, expiring,
  }), [
    refreshing, screenshotMode, theme, authed, totpEnabled, tab, currentServerId,
    servers, nodes, templates, certificates, rules, forwards, routes, subs, surgeTemplates, surgeTemplatesStatus, customers, operations, agentReleases, coreReleases,
    refreshTick, pollTick, modal, confirmation, batch,
    installInfo, installMethod, installArch, issued, preview,
    trafficNode, trafficSub, agentDownloads, offlineServer,
    summary, dashSeries, ranking, refresh, act, runBatch, copy, goTo, openModal, closeModal, openServer, openNode, openForward, openRoute,
    openSubscription, openTemplate, useTemplate, templateNodeForm, matchingCertificate, showInstall, deleteItem, deleteServer, matches,
    auditTarget, attention, unreadAttention, readItems, markRead, markUnread, liveSubs, failedNodes, split, activeNodes, onlineServers, agentServers, upgradingAgentIDs, updatingAgentIDs,
    forwardServerIDs, serverWarnings, nodeAccessText, serverName, pendingNodes, pendingSummary, subNodeIds, subMemberNodes, sharedSubNodes,
    onlySharedSubNodes, routePath, restartNotice, surgeImportHelp, protect, redactScreenshot, expiring,
  ]);
}

export type App = ReturnType<typeof useAppState>;
