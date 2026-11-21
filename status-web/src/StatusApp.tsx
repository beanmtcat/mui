import { useCallback, useEffect, useMemo, useState } from "react";
import { StatusCockpit } from "./components/StatusCockpit";
import { StatusDetailModal } from "./components/StatusDetailModal";
import { StatusFilters, type GroupFilterOption, type RegionFilterOption } from "./components/StatusFilters";
import { StatusShell } from "./components/StatusShell";
import { MoonIcon, SunIcon } from "./components/ThemeIcons";
import { usePublicHistory } from "./hooks/usePublicHistory";
import { usePublicStatus } from "./hooks/usePublicStatus";
import { UNGROUPED_FILTER, UNGROUPED_LABEL } from "./monitor/format";
import { MonitorServerCard } from "./monitor/MonitorServerCard";
import { toPublicCardViewModel } from "./monitor/publicCard";
import type { MonitorRange } from "./monitor/types";
import { applyStatusTheme, readInitialStatusTheme, type StatusTheme } from "./theme";

const zhCollator = new Intl.Collator("zh-Hans-CN", { numeric: true, sensitivity: "base" });

export function StatusApp() {
  const [theme, setTheme] = useState<StatusTheme>(() => readInitialStatusTheme());

  const [groupFilter, setGroupFilter] = useState("");
  const [countryFilter, setCountryFilter] = useState("");
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
    selectedServer ? selectedServer.id : "",
    pageState,
    range,
    data?.showPing,
  );

  const groupOptions = useMemo<GroupFilterOption[]>(() => {
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

  const groupFilteredServers = useMemo(() => {
    if (!groupFilter) return servers;
    return servers.filter((s) => {
      const g = s.group?.trim() || "";
      return groupFilter === UNGROUPED_FILTER ? !g || g === UNGROUPED_LABEL : g === groupFilter;
    });
  }, [servers, groupFilter]);

  const regionOptions = useMemo<RegionFilterOption[]>(() => {
    const counts = new Map<string, number>();
    for (const s of groupFilteredServers) {
      const code = (s.country || "").trim().toUpperCase();
      if (!code) continue;
      counts.set(code, (counts.get(code) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => (b[1] !== a[1] ? b[1] - a[1] : a[0].localeCompare(b[0])))
      .map(([code, count]) => ({ code, count }));
  }, [groupFilteredServers]);

  useEffect(() => {
    if (!countryFilter) return;
    if (!regionOptions.some((r) => r.code === countryFilter)) {
      setCountryFilter("");
    }
  }, [countryFilter, regionOptions]);

  const filteredServers = useMemo(() => {
    const q = search.trim().toLowerCase();
    return groupFilteredServers.filter((s) => {
      if (countryFilter) {
        const code = (s.country || "").trim().toUpperCase();
        if (code !== countryFilter) return false;
      }
      if (!q) return true;
      const haystack = [s.name, s.group, s.country, s.region, s.city, s.os, s.publicNote]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [groupFilteredServers, countryFilter, search]);

  if (pageState === "disabled") {
    return (
      <div className="statusPage monScope">
        <div className="statusShell statusCentered">
          <div className="statusThemeFloat">
            <button
              type="button"
              className="statusThemeToggle"
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
    <StatusShell
      title={data?.title || "服务状态"}
      description={data?.description}
      theme={theme}
      onToggleTheme={toggleTheme}
      disconnected={disconnected}
      hasData={Boolean(data)}
      background={data?.background}
    >
      {pageState === "loading" && !data ? (
        <section className="statusEmpty">正在加载状态数据…</section>
      ) : !data ? null : (
        <>
          <StatusCockpit
            servers={servers}
            generatedAt={data.generatedAt}
            showTraffic={data.showTraffic}
            disconnected={disconnected}
            controls={
              servers.length > 0 ? (
                <StatusFilters
                  groupOptions={groupOptions}
                  groupFilter={groupFilter}
                  onGroupChange={setGroupFilter}
                  regionOptions={regionOptions}
                  countryFilter={countryFilter}
                  onCountryChange={setCountryFilter}
                  search={search}
                  onSearchChange={setSearch}
                />
              ) : undefined
            }
          />

          {servers.length === 0 ? (
            <p className="statusEmpty">暂无公开展示的服务器。</p>
          ) : filteredServers.length === 0 ? (
            <p className="statusEmpty">没有符合筛选条件的服务器。</p>
          ) : (
            <div className="monitorGridFrame">
              <section className="monitorGrid" aria-label="服务器实时状态列表">
                {filteredServers.map((srv) => (
                  <MonitorServerCard
                    key={srv.id}
                    card={toPublicCardViewModel(srv, data.showTraffic, data.showPing)}
                    active={selectedServer?.id === srv.id}
                    onSelect={setSelectedId}
                  />
                ))}
              </section>
            </div>
          )}

          {selectedServer && (
            <StatusDetailModal
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
    </StatusShell>
  );
}
