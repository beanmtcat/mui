import { useCallback, useEffect, useMemo, useState } from "react";
import {
  countryFlag,
  formatBytes,
  UNGROUPED_FILTER,
  UNGROUPED_LABEL,
} from "./monitor/format";
import { MonitorMetricsCharts, PingTaskChart } from "./monitor/MonitorCharts";
import { MonitorServerCard } from "./monitor/MonitorServerCard";
import type {
  MonitorCardSample,
  MonitorCardViewModel,
  MonitorRange,
  SharedMonitorRecord,
  SharedPingPoint,
  SharedTrafficLimitType,
} from "./monitor/types";
import { applyStatusTheme, readInitialStatusTheme, type StatusTheme } from "./theme";

const PUBLIC_RANGES: { id: MonitorRange; label: string }[] = [
  { id: "1h", label: "1 小时" },
  { id: "6h", label: "6 小时" },
  { id: "24h", label: "24 小时" },
  { id: "7d", label: "7 天" },
];

type PublicCycleTraffic = {
  startAt: string;
  resetAt: string;
  used: number;
  limit: number;
  type: SharedTrafficLimitType;
};

type PublicServerItem = {
  id: string;
  name: string;
  group: string;
  country: string;
  region?: string;
  city?: string;
  online: boolean;
  hostMonitor: boolean;
  os?: string;
  arch?: string;
  virtualization?: string;
  cpuName?: string;
  cpuCores?: number;
  memTotal?: number;
  swapTotal?: number;
  diskTotal?: number;
  sample?: MonitorCardSample;
  cycleTraffic?: PublicCycleTraffic;
  expiresAt?: string;
  publicNote?: string;
};

type PublicStatusResponse = {
  title: string;
  description: string;
  showTraffic: boolean;
  showPing: boolean;
  generatedAt: string;
  servers: PublicServerItem[];
};

type PublicPingTaskSeries = {
  id: string;
  name: string;
  intervalSeconds: number;
  records: SharedPingPoint[];
};

const zhCollator = new Intl.Collator("zh-Hans-CN", { numeric: true, sensitivity: "base" });

function SunIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  );
}

function toPublicCardViewModel(srv: PublicServerItem, showTraffic: boolean): MonitorCardViewModel {
  const loc = [srv.region, srv.city].filter(Boolean).join(" · ") || srv.country;
  const hostLine = [
    srv.cpuName,
    srv.cpuCores ? `${srv.cpuCores} 核` : "",
    srv.os,
    srv.virtualization,
  ]
    .filter(Boolean)
    .join(" · ");

  return {
    id: srv.id,
    name: srv.name,
    country: srv.country,
    locationText: loc,
    online: srv.online,
    supported: srv.hostMonitor,
    unsupportedMessage: "暂未启用实时采集。",
    hostLine: hostLine || undefined,
    cpuCores: srv.cpuCores,
    sample: srv.sample,
    showTraffic,
    cycleTraffic: showTraffic && srv.cycleTraffic ? srv.cycleTraffic : undefined,
    expiresAt: srv.expiresAt,
    publicNote: srv.publicNote,
  };
}

export function StatusApp() {
  const [theme, setTheme] = useState<StatusTheme>(() => readInitialStatusTheme());
  const [pageState, setPageState] = useState<"loading" | "disabled" | "ready">("loading");
  const [data, setData] = useState<PublicStatusResponse | null>(null);
  const [disconnected, setDisconnected] = useState(false);

  const [groupFilter, setGroupFilter] = useState("");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState("");
  const [range, setRange] = useState<MonitorRange>("24h");

  const [records, setRecords] = useState<SharedMonitorRecord[]>([]);
  const [pings, setPings] = useState<PublicPingTaskSeries[]>([]);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => {
      const next: StatusTheme = prev === "dark" ? "light" : "dark";
      applyStatusTheme(next);
      return next;
    });
  }, []);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/public/status", {
        method: "GET",
        credentials: "omit",
        headers: { Accept: "application/json" },
      });
      if (res.status === 404) {
        setData(null);
        setDisconnected(false);
        setSelectedId("");
        setPageState("disabled");
        document.title = "状态页未开启";
        return;
      }
      if (!res.ok) {
        setDisconnected(true);
        setPageState((prev) => (prev === "loading" ? "ready" : prev));
        return;
      }
      const next = (await res.json()) as PublicStatusResponse;
      setData(next);
      setDisconnected(false);
      setPageState("ready");
      document.title = next.title || "服务状态";
    } catch {
      setDisconnected(true);
      setPageState((prev) => (prev === "loading" ? "ready" : prev));
    }
  }, []);

  useEffect(() => {
    void fetchStatus();
    const id = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        void fetchStatus();
      }
    }, 5000);
    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        void fetchStatus();
      }
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.clearInterval(id);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [fetchStatus]);

  const servers = useMemo(() => data?.servers ?? [], [data]);

  const selectedServer = useMemo(
    () => (selectedId ? servers.find((s) => s.id === selectedId) : undefined),
    [selectedId, servers],
  );

  const loadDetailHistory = useCallback(async () => {
    if (!selectedServer || pageState !== "ready") {
      setRecords([]);
      setPings([]);
      return;
    }
    setLoadingDetail(true);
    try {
      const recPromise = fetch(
        `/api/public/servers/${encodeURIComponent(selectedServer.id)}/records?range=${range}`,
        { method: "GET", credentials: "omit", headers: { Accept: "application/json" } },
      );
      const pingPromise = data?.showPing
        ? fetch(
            `/api/public/servers/${encodeURIComponent(selectedServer.id)}/pings?range=${range}`,
            { method: "GET", credentials: "omit", headers: { Accept: "application/json" } },
          )
        : Promise.resolve(null);

      const [recRes, pingRes] = await Promise.all([recPromise, pingPromise]);
      if (recRes.ok) {
        setRecords((await recRes.json()) as SharedMonitorRecord[]);
      }
      if (pingRes && pingRes.ok) {
        setPings((await pingRes.json()) as PublicPingTaskSeries[]);
      } else {
        setPings([]);
      }
    } catch {
      // Keep last loaded history points if transient failure occurs.
    } finally {
      setLoadingDetail(false);
    }
  }, [selectedServer, pageState, range, data?.showPing]);

  useEffect(() => {
    setRecords([]);
    setPings([]);
    void loadDetailHistory();
    if (!selectedServer || pageState !== "ready") return;
    const id = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        void loadDetailHistory();
      }
    }, 30_000);
    return () => window.clearInterval(id);
  }, [loadDetailHistory, selectedServer, pageState]);

  const groupOptions = useMemo(() => {
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
    const opts = [...named]
      .sort((a, b) => zhCollator.compare(a, b))
      .map((g) => ({ value: g, label: g }));
    if (hasUngrouped) {
      opts.push({ value: UNGROUPED_FILTER, label: UNGROUPED_LABEL });
    }
    return opts;
  }, [servers]);

  useEffect(() => {
    if (!groupFilter) return;
    if (!groupOptions.some((o) => o.value === groupFilter)) {
      setGroupFilter("");
    }
  }, [groupFilter, groupOptions]);

  const filteredServers = useMemo(() => {
    const q = search.trim().toLowerCase();
    return servers.filter((s) => {
      if (groupFilter) {
        const g = s.group?.trim() || "";
        const matchGroup =
          groupFilter === UNGROUPED_FILTER ? !g || g === UNGROUPED_LABEL : g === groupFilter;
        if (!matchGroup) return false;
      }
      if (!q) return true;
      const haystack = [s.name, s.group, s.country, s.region, s.city, s.publicNote]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [servers, groupFilter, search]);

  // Preserve exact backend sortWeight order within each group.
  const groupedServers = useMemo(() => {
    const map = new Map<string, PublicServerItem[]>();
    for (const s of filteredServers) {
      const g = s.group?.trim() || UNGROUPED_LABEL;
      const list = map.get(g);
      if (list) list.push(s);
      else map.set(g, [s]);
    }
    const groups = [...map.keys()].sort((a, b) => {
      if (a === UNGROUPED_LABEL) return b === UNGROUPED_LABEL ? 0 : 1;
      if (b === UNGROUPED_LABEL) return -1;
      return zhCollator.compare(a, b);
    });
    return groups.map((group) => ({ group, items: map.get(group) || [] }));
  }, [filteredServers]);

  const onlineCount = useMemo(() => servers.filter((s) => s.online).length, [servers]);

  if (pageState === "disabled") {
    return (
      <div className="statusPage monScope">
        <div className="statusShell statusCentered">
          <div className="statusThemeFloat">
            <button
              type="button"
              className="statusIconBtn"
              onClick={toggleTheme}
              aria-label={theme === "dark" ? "切换为浅色外观" : "切换为深色外观"}
              title={theme === "dark" ? "浅色外观" : "深色外观"}
            >
              {theme === "dark" ? <SunIcon /> : <MoonIcon />}
            </button>
          </div>
          <section className="statusDisabledCard" role="status">
            <h1>状态页未开启</h1>
          </section>
        </div>
      </div>
    );
  }

  return (
    <div className="statusPage monScope">
      <div className="statusShell">
        <header className="statusHeader">
          <div className="statusTitleBlock">
            <h1>{data?.title || "服务状态"}</h1>
            {data?.description && <p className="statusDescription">{data.description}</p>}
          </div>

          <div className="statusHeaderActions">
            {data && (
              <div className="statusOnlineBadge monTabular" aria-label="在线与总节点数">
                <span
                  className={`monStatusDot${onlineCount > 0 ? " is-online" : ""}`}
                  aria-hidden="true"
                />
                <span>
                  在线 <strong>{onlineCount}</strong> / {servers.length}
                </span>
              </div>
            )}
            <button
              type="button"
              className="statusIconBtn"
              onClick={toggleTheme}
              aria-label={theme === "dark" ? "切换为浅色外观" : "切换为深色外观"}
              title={theme === "dark" ? "浅色外观" : "深色外观"}
            >
              {theme === "dark" ? <SunIcon /> : <MoonIcon />}
              <span>{theme === "dark" ? "浅色" : "深色"}</span>
            </button>
          </div>
        </header>

        {disconnected && (
          <div className="statusBanner" role="alert">
            <strong>连接中断</strong>
            <span>
              {data ? "暂时无法刷新最新状态，当前展示上一份数据。" : "暂时无法连接状态服务，正在自动重试…"}
            </span>
          </div>
        )}

        {pageState === "loading" && !data ? (
          <section className="statusSurface statusEmpty">正在加载状态数据…</section>
        ) : !data ? null : (
          <>
            {servers.length > 0 && (
              <div className="statusToolbar">
                {groupOptions.length > 1 && (
                  <select
                    className="statusSelect"
                    aria-label="按分组筛选"
                    value={groupFilter}
                    onChange={(e) => setGroupFilter(e.target.value)}
                  >
                    <option value="">全部分组（{servers.length}）</option>
                    {groupOptions.map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                )}
                <input
                  type="search"
                  className="statusSearch"
                  placeholder="搜索名称、分组或地区…"
                  aria-label="搜索节点"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>
            )}

            <section className="statusSurface statusBody">
              {servers.length === 0 ? (
                <p className="statusHint">暂无公开展示的服务器。</p>
              ) : groupedServers.length === 0 ? (
                <p className="statusHint">没有符合筛选条件的服务器。</p>
              ) : (
                groupedServers.map(({ group, items }) => (
                  <div className="monitorGroupSection" key={group}>
                    <div className="monitorGroupHead">
                      <strong>{group}</strong>
                      <span className="monTabular">{items.length} 台</span>
                    </div>
                    <div className="monitorGrid">
                      {items.map((srv) => (
                        <MonitorServerCard
                          key={srv.id}
                          card={toPublicCardViewModel(srv, data.showTraffic)}
                          active={selectedServer?.id === srv.id}
                          onSelect={setSelectedId}
                        />
                      ))}
                    </div>
                  </div>
                ))
              )}
            </section>

            {selectedServer && (
              <section className="statusSurface statusDetailPanel">
                <div className="statusDetailHead">
                  <div className="statusDetailTitle">
                    <h2>
                      {countryFlag(selectedServer.country)} {selectedServer.name} · 历史曲线
                    </h2>
                    <p className="statusDetailMeta">
                      {[
                        selectedServer.cpuName &&
                          `${selectedServer.cpuName}${selectedServer.cpuCores ? `（${selectedServer.cpuCores} 核）` : ""}`,
                        selectedServer.os &&
                          `${selectedServer.os}${selectedServer.arch ? ` (${selectedServer.arch})` : ""}`,
                        selectedServer.virtualization && `虚拟化 ${selectedServer.virtualization}`,
                        selectedServer.memTotal ? `内存 ${formatBytes(selectedServer.memTotal)}` : "",
                        selectedServer.diskTotal ? `磁盘 ${formatBytes(selectedServer.diskTotal)}` : "",
                      ]
                        .filter(Boolean)
                        .join(" · ")}
                    </p>
                  </div>

                  <div className="statusDetailControls">
                    <div className="monitorRangeTabs" role="tablist" aria-label="监控时间范围">
                      {PUBLIC_RANGES.map((r) => (
                        <button
                          key={r.id}
                          type="button"
                          role="tab"
                          aria-selected={range === r.id}
                          className={range === r.id ? "active" : ""}
                          onClick={() => setRange(r.id)}
                        >
                          {r.label}
                        </button>
                      ))}
                    </div>
                    <button
                      type="button"
                      className="statusCloseBtn"
                      onClick={() => setSelectedId("")}
                    >
                      收起详情
                    </button>
                  </div>
                </div>

                <div className="statusDetailBody">
                  {loadingDetail && records.length === 0 ? (
                    <p className="statusHint">正在加载历史记录…</p>
                  ) : (
                    <>
                      <MonitorMetricsCharts records={records} range={range} />
                      {data.showPing && pings.length > 0 && (
                        <div className="monitorPingChartsSection">
                          <h3>延迟监测曲线</h3>
                          <div className="monitorChartsGrid">
                            {pings.map((task) => (
                              <PingTaskChart
                                key={task.id}
                                title={task.name}
                                records={task.records}
                                range={range}
                              />
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              </section>
            )}
          </>
        )}
      </div>
    </div>
  );
}
