import { useCallback, useEffect, useMemo, useState } from "react";
import { StatusDetailPanel } from "./components/StatusDetailPanel";
import { MoonIcon, SunIcon } from "./components/ThemeIcons";
import { usePublicHistory } from "./hooks/usePublicHistory";
import { usePublicStatus } from "./hooks/usePublicStatus";
import { UNGROUPED_FILTER, UNGROUPED_LABEL } from "./monitor/format";
import { MonitorServerCard } from "./monitor/MonitorServerCard";
import { toPublicCardViewModel, type PublicServerItem } from "./monitor/publicCard";
import type { MonitorRange } from "./monitor/types";
import { applyStatusTheme, readInitialStatusTheme, type StatusTheme } from "./theme";

const zhCollator = new Intl.Collator("zh-Hans-CN", { numeric: true, sensitivity: "base" });

export function StatusApp() {
  const [theme, setTheme] = useState<StatusTheme>(() => readInitialStatusTheme());

  const [groupFilter, setGroupFilter] = useState("");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState("");
  const [range, setRange] = useState<MonitorRange>("24h");

  const handleDisabled = useCallback(() => setSelectedId(""), []);
  const { pageState, data, disconnected } = usePublicStatus(handleDisabled);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => {
      const next: StatusTheme = prev === "dark" ? "light" : "dark";
      applyStatusTheme(next);
      return next;
    });
  }, []);

  const servers = useMemo(() => data?.servers ?? [], [data]);

  const selectedServer = useMemo(
    () => (selectedId ? servers.find((s) => s.id === selectedId) : undefined),
    [selectedId, servers],
  );

  const { records, pings, loadingDetail } = usePublicHistory(
    selectedServer,
    pageState,
    range,
    data?.showPing,
  );

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
              <StatusDetailPanel
                server={selectedServer}
                range={range}
                onRangeChange={setRange}
                onClose={() => setSelectedId("")}
                loadingDetail={loadingDetail}
                records={records}
                showPing={data.showPing}
                pings={pings}
              />
            )}
          </>
        )}
      </div>
    </div>
  );
}
