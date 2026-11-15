import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  mutation,
  type MonitorOverviewItem,
  type MonitorRecord,
  type PingMinuteRecord,
  type PingTask,
  type Server,
} from "../api";
import { useApp } from "../app/context";
import { setError } from "../app/feedback";
import {
  countryFlag,
  formatBillingCycle,
  formatMonthlyCostSummary,
  groupAndSortServers,
  matchesServerGroupFilter,
  serverGroupFilterOptions,
} from "../app/helpers";
import { ModalShell } from "../app/ui";
import { useUrlParam } from "../app/url";
import {
  MonitorMetricsCharts,
  PingCombinedChart,
  type MonitorRange,
} from "../monitor/MonitorCharts";
import { MonitorServerCard } from "../monitor/MonitorServerCard";
import { resolveExpireVisual, type ExpireVisual } from "../monitor/monitorTone";
import { buildAdminMonitorCard } from "../monitor/adminCard";
import {
  PingTaskDialog,
  emptyPingDraft,
  type PingTaskDraft,
} from "../forms/PingTaskDialog";

const RANGES: { id: MonitorRange; label: string }[] = [
  { id: "1h", label: "1 小时" },
  { id: "6h", label: "6 小时" },
  { id: "24h", label: "24 小时" },
  { id: "7d", label: "7 天" },
  { id: "30d", label: "30 天" },
];

export default function Monitor() {
  const { servers, trafficLimitThreshold, ensureTrafficLimitThreshold, refreshTick, act, setConfirmation, redactScreenshot, protect } = useApp();
  useEffect(() => {
    ensureTrafficLimitThreshold();
  }, [ensureTrafficLimitThreshold]);
  const [selectedId, setSelectedId] = useUrlParam("server");
  const [rangeParam, setRangeParam] = useUrlParam("range");
  const [groupFilter, setGroupFilter] = useUrlParam("group");
  const range: MonitorRange = RANGES.some((r) => r.id === rangeParam)
    ? (rangeParam as MonitorRange)
    : "24h";

  const [overview, setOverview] = useState<MonitorOverviewItem[]>([]);
  const [loadingOverview, setLoadingOverview] = useState(true);
  const [pingTasks, setPingTasks] = useState<PingTask[]>([]);
  const [pingDialog, setPingDialog] = useState<PingTaskDraft | null>(null);

  const [records, setRecords] = useState<MonitorRecord[]>([]);
  const [loadingRecords, setLoadingRecords] = useState(false);
  const [pingRecordsMap, setPingRecordsMap] = useState<Record<string, PingMinuteRecord[]>>({});

  const onlineManagedServers = useMemo(
    () =>
      servers.filter(
        (s) => s.managementMode !== "offline" && s.managementMode !== "external",
      ),
    [servers],
  );

  const groupOptions = useMemo(
    () => serverGroupFilterOptions(onlineManagedServers),
    [onlineManagedServers],
  );

  const filteredServers = useMemo(
    () => onlineManagedServers.filter((s) => matchesServerGroupFilter(s, groupFilter)),
    [onlineManagedServers, groupFilter],
  );

  const groupedServers = useMemo(
    () => groupAndSortServers(filteredServers),
    [filteredServers],
  );

  const monthlyCostSummary = useMemo(
    () => formatMonthlyCostSummary(servers),
    [servers],
  );

  const overviewByServer = useMemo(() => {
    const map = new Map<string, MonitorOverviewItem>();
    for (const item of overview) map.set(item.serverId, item);
    return map;
  }, [overview]);

  const fetchOverview = useCallback(async () => {
    try {
      const data = await api<MonitorOverviewItem[]>("/api/monitor");
      setOverview(data);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoadingOverview(false);
    }
  }, []);

  const fetchPingTasks = useCallback(async () => {
    try {
      const data = await api<PingTask[]>("/api/ping-tasks");
      setPingTasks(data);
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

  const confirmRenew = useCallback(
    (srv: Server) => {
      const cycleText = formatBillingCycle(srv);
      setConfirmation({
        title: "续期服务器",
        message: `确认将「${srv.name}」的到期日顺延一个周期${cycleText ? `（${cycleText}）` : ""}吗？`,
        confirmLabel: "确认续期",
        onConfirm: () => {
          void act(async () => {
            await mutation<Server>(`/api/servers/${encodeURIComponent(srv.id)}/renew`, "POST");
            await fetchOverview();
          }, "服务器已续期一个周期");
        },
      });
    },
    [act, fetchOverview, setConfirmation],
  );

  // Poll /api/monitor every 5s ONLY while Monitor tab is mounted AND page is visible.
  useEffect(() => {
    void fetchOverview();
    void fetchPingTasks();

    const id = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        void fetchOverview();
      }
    }, 5000);

    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        void fetchOverview();
      }
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.clearInterval(id);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [fetchOverview, fetchPingTasks]);

  const selectedServer = useMemo(
    () => onlineManagedServers.find((s) => s.id === selectedId) || null,
    [onlineManagedServers, selectedId],
  );
  const activeServerId = selectedServer ? selectedServer.id : "";

  const serverPingTasks = useMemo(() => {
    if (!activeServerId) return [];
    return pingTasks.filter(
      (t) => t.serverIds.length === 0 || t.serverIds.includes(activeServerId),
    );
  }, [pingTasks, activeServerId]);

  const pingTaskIdsKey = useMemo(
    () => serverPingTasks.map((t) => t.id).join(","),
    [serverPingTasks],
  );

  const historyControllerRef = useRef<AbortController | null>(null);
  const historyReqSeqRef = useRef(0);
  const prevHistoryTargetRef = useRef("");
  const hasLoadedHistoryRef = useRef(false);

  const loadDetailHistory = useCallback(
    async (isBackground = false) => {
      if (!activeServerId) return;
      historyControllerRef.current?.abort();
      const controller = new AbortController();
      historyControllerRef.current = controller;
      const seq = ++historyReqSeqRef.current;

      if (!isBackground && !hasLoadedHistoryRef.current) {
        setLoadingRecords(true);
      }
      try {
        const pingRange = range === "30d" ? "7d" : range;
        const taskIds = pingTaskIdsKey ? pingTaskIdsKey.split(",") : [];
        const [hist, ...pingLists] = await Promise.all([
          api<MonitorRecord[]>(
            `/api/monitor/${encodeURIComponent(activeServerId)}/records?range=${range}`,
            { signal: controller.signal },
          ),
          ...taskIds.map((taskId) =>
            api<PingMinuteRecord[]>(
              `/api/ping-tasks/${encodeURIComponent(taskId)}/records?serverId=${encodeURIComponent(activeServerId)}&range=${pingRange}`,
              { signal: controller.signal },
            ),
          ),
        ]);
        if (controller.signal.aborted || seq !== historyReqSeqRef.current) {
          return;
        }
        hasLoadedHistoryRef.current = true;
        setRecords(hist);
        const nextMap: Record<string, PingMinuteRecord[]> = {};
        taskIds.forEach((taskId, i) => {
          nextMap[taskId] = pingLists[i] || [];
        });
        setPingRecordsMap(nextMap);
      } catch (e) {
        if (controller.signal.aborted || seq !== historyReqSeqRef.current) {
          return;
        }
        setError((e as Error).message);
      } finally {
        if (!controller.signal.aborted && seq === historyReqSeqRef.current) {
          setLoadingRecords(false);
        }
      }
    },
    [activeServerId, range, pingTaskIdsKey],
  );

  useEffect(() => {
    if (!activeServerId) {
      historyControllerRef.current?.abort();
      historyControllerRef.current = null;
      historyReqSeqRef.current += 1;
      prevHistoryTargetRef.current = "";
      hasLoadedHistoryRef.current = false;
      setRecords([]);
      setPingRecordsMap({});
      setLoadingRecords(false);
      return;
    }
    const targetKey = `${activeServerId}\n${range}`;
    const targetChanged = prevHistoryTargetRef.current !== targetKey;
    if (targetChanged) {
      prevHistoryTargetRef.current = targetKey;
      hasLoadedHistoryRef.current = false;
      setRecords([]);
      setPingRecordsMap({});
      setLoadingRecords(true);
    }
    void loadDetailHistory(!targetChanged && hasLoadedHistoryRef.current);

    const id = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        void loadDetailHistory(true);
      }
    }, 30_000);
    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        void loadDetailHistory(true);
      }
    };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      historyControllerRef.current?.abort();
      historyControllerRef.current = null;
      window.clearInterval(id);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [activeServerId, range, pingTaskIdsKey, loadDetailHistory]);

  // The header refresh button reloads this page's own data too, so one button covers everything.
  const seenRefreshTick = useRef(refreshTick);
  useEffect(() => {
    if (seenRefreshTick.current === refreshTick) return;
    seenRefreshTick.current = refreshTick;
    void fetchOverview();
    void fetchPingTasks();
    if (activeServerId) void loadDetailHistory(true);
  }, [refreshTick, fetchOverview, fetchPingTasks, activeServerId, loadDetailHistory]);

  const onlineCount = onlineManagedServers.filter(
    (s) => overviewByServer.get(s.id)?.online ?? s.status === "online",
  ).length;

  const { billedCount, autoRenewCount, expiringItems } = useMemo(() => {
    let billed = 0;
    let autoRenew = 0;
    const expiring: { srv: Server; visual: ExpireVisual; canSelect: boolean }[] = [];
    for (const srv of servers) {
      if (srv.status === "revoked") continue;
      if (srv.billingCycle && srv.price && srv.price > 0) billed += 1;
      if (srv.autoRenew && srv.billingCycle) autoRenew += 1;
      const vis = resolveExpireVisual(srv.expiresAt, srv.autoRenew && !!srv.billingCycle);
      if (vis && vis.daysRemaining <= 7) {
        expiring.push({
          srv,
          visual: vis,
          canSelect: srv.managementMode !== "offline" && srv.managementMode !== "external",
        });
      }
    }
    expiring.sort((a, b) => a.visual.daysRemaining - b.visual.daysRemaining);
    return { billedCount: billed, autoRenewCount: autoRenew, expiringItems: expiring };
  }, [servers]);

  return protect(
    <div className="monitorPage">
      {(monthlyCostSummary || expiringItems.length > 0 || billedCount > 0) && (
        <section className="monSummaryHero" aria-label="监控与费用概览">
          <div className="monSummaryMain">
            <span className="monSummaryEyebrow">月度费用汇总</span>
            {monthlyCostSummary ? (
              <div className="monSummaryValue monTabular">{monthlyCostSummary}</div>
            ) : (
              <div className="monSummaryValue is-muted">暂未填写计费金额</div>
            )}
            {expiringItems.length > 0 && (
              <div className="monRenewalInlineList" aria-label="近期到期提醒">
                {expiringItems.map(({ srv, visual, canSelect }) =>
                  canSelect ? (
                    <button
                      key={srv.id}
                      type="button"
                      className="monRenewalChip monTabular"
                      data-tone={visual.tone}
                      onClick={() => setSelectedId(srv.id)}
                      title={`点击查看「${redactScreenshot(srv.name)}」监控曲线`}
                    >
                      <span>{countryFlag(srv.country)}</span>
                      <span className="monRenewalName">{redactScreenshot(srv.name)}</span>
                      <strong>{visual.badgeText}</strong>
                    </button>
                  ) : (
                    <span
                      key={srv.id}
                      className="monRenewalChip monTabular"
                      data-tone={visual.tone}
                    >
                      <span>{countryFlag(srv.country)}</span>
                      <span className="monRenewalName">{redactScreenshot(srv.name)}</span>
                      <strong>{visual.badgeText}</strong>
                    </span>
                  ),
                )}
              </div>
            )}
          </div>

          <div className="monSummaryLedger">
            <div className="monSummaryLedgerRow">
              <span>在线服务器</span>
              <strong className="monTabular monLedgerOnline">
                <span className="monStatusDot is-online" aria-hidden="true" />
                {onlineCount} / {onlineManagedServers.length} 台
              </strong>
            </div>
            <div className="monSummaryLedgerRow">
              <span>计费与续期</span>
              <strong className="monTabular">
                {billedCount} 台计费 · {autoRenewCount} 台自动续期
              </strong>
            </div>
            <div className="monSummaryLedgerRow">
              <span>采样与延迟</span>
              <strong className="monTabular">
                每 5 秒刷新 · {pingTasks.length} 项任务
              </strong>
            </div>
          </div>
        </section>
      )}

      <section className="panel monitorMainPanel">
        <div className="panelHead">
          <div>
            <h2>主机实时监控</h2>
            <p className="hint monTabular">
              共 {onlineManagedServers.length} 台在线管理服务器，当前在线 {onlineCount} 台 · 每 5 秒自动刷新
            </p>
          </div>
          <div className="toolbarActions monitorToolbar">
            <select
              aria-label="按分组筛选监控服务器"
              value={groupFilter}
              onChange={(e) => setGroupFilter(e.target.value)}
            >
              <option value="">全部分组</option>
              {groupOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            {groupFilter && (
              <button type="button" className="ghost" onClick={() => setGroupFilter("")}>
                清空分组
              </button>
            )}
            <button
              type="button"
              className="primary"
              disabled={pingTasks.length >= 32}
              onClick={() => setPingDialog({ ...emptyPingDraft })}
            >
              新建延迟任务
            </button>
          </div>
        </div>

        <div className="monitorPanelBody">
          {loadingOverview && onlineManagedServers.length === 0 ? (
            <p className="hint">正在加载监控数据…</p>
          ) : onlineManagedServers.length === 0 ? (
            <p className="hint">暂无在线 Agent 管理的服务器。</p>
          ) : groupedServers.length === 0 ? (
            <p className="hint">当前分组下没有符合条件的服务器。</p>
          ) : (
            groupedServers.map(({ group, items }) => (
              <div className="monitorGroupSection" key={group}>
                <div className="monitorGroupHead">
                  <strong>{redactScreenshot(group)}</strong>
                  <span className="monTabular">{items.length} 台</span>
                </div>
                <div className="monitorGrid">
                  {items.map((srv) => {
                    const card = buildAdminMonitorCard(
                      srv,
                      overviewByServer.get(srv.id),
                      trafficLimitThreshold,
                      redactScreenshot,
                    );
                    const hasBadges = Boolean(srv.alertMuted || (srv.autoRenew && srv.billingCycle));
                    return (
                      <MonitorServerCard
                        key={srv.id}
                        card={card}
                        active={selectedServer?.id === srv.id}
                        onSelect={setSelectedId}
                        headerBadgesSlot={
                          hasBadges ? (
                            <>
                              {srv.alertMuted && (
                                <span
                                  className="monTagChip"
                                  data-tone="gray"
                                  title="已静音离线与资源高占用告警"
                                >
                                  静音
                                </span>
                              )}
                              {srv.autoRenew && srv.billingCycle && (
                                <span className="monTagChip" data-tone="blue">
                                  自动续期
                                </span>
                              )}
                            </>
                          ) : undefined
                        }
                        footerActionSlot={
                          srv.billingCycle ? (
                            <button
                              type="button"
                              className="ghost monitorRenewBtn"
                              disabled={!srv.expiresAt || srv.status === "revoked"}
                              title={
                                !srv.expiresAt
                                  ? "请先在服务器设置中填写到期日"
                                  : srv.status === "revoked"
                                    ? "凭据已吊销，无法续期"
                                    : undefined
                              }
                              onClick={(e) => {
                                e.stopPropagation();
                                confirmRenew(srv);
                              }}
                            >
                              续期一个周期
                            </button>
                          ) : undefined
                        }
                      />
                    );
                  })}
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      {selectedServer && (
        <ModalShell
          title={`${countryFlag(selectedServer.country)} ${redactScreenshot(selectedServer.name)} · 历史曲线`}
          labelledBy="monitor-detail-title"
          dirty={false}
          onClose={() => setSelectedId("")}
          onConfirm={setConfirmation}
        >
          <div className="monitorDetailHead">
            <div>
              {(() => {
                const h = overviewByServer.get(selectedServer.id)?.host;
                const s = overviewByServer.get(selectedServer.id)?.sample;
                if (!h && !s) return null;
                return (
                  <p className="hint">
                    {[
                      h?.cpuName &&
                        `${h.cpuName}（${h.cpuCores} 逻辑核${h.cpuPhysicalCores ? ` / ${h.cpuPhysicalCores} 物理核` : ""}）`,
                      h?.os && `${h.os} (${h.arch})`,
                      h?.kernel && `内核 ${h.kernel}`,
                      h?.virtualization && `虚拟化 ${h.virtualization}`,
                      s && `TCP ${s.tcp} / UDP ${s.udp} / 进程 ${s.process}`,
                    ]
                      .filter(Boolean)
                      .join(" · ")}
                  </p>
                );
              })()}
            </div>
            <div className="monitorDetailTools">
              <div className="monitorRangeTabs" role="tablist" aria-label="监控时间范围">
                {RANGES.map((r) => (
                  <button
                    key={r.id}
                    type="button"
                    role="tab"
                    aria-selected={range === r.id}
                    className={range === r.id ? "active" : ""}
                    onClick={() => setRangeParam(r.id === "24h" ? "" : r.id)}
                  >
                    {r.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="monitorDetailBody">
            {loadingRecords && records.length === 0 ? (
              <p className="hint">正在加载历史记录…</p>
            ) : (
              <>
                <MonitorMetricsCharts records={records} range={range} />
                {serverPingTasks.length > 0 && (
                  <div className="monitorPingChartsSection">
                    <h3>TCP 延迟监测曲线</h3>
                    <div className="monitorChartsGrid">
                      <PingCombinedChart
                        tasks={serverPingTasks.map((task) => ({
                          id: task.id,
                          name: redactScreenshot(task.name),
                          records: pingRecordsMap[task.id] || [],
                        }))}
                        range={range}
                      />
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </ModalShell>
      )}

      <section className="panel">
        <div className="panelHead">
          <div>
            <h2>TCP 延迟监测任务（{pingTasks.length} / 32）</h2>
            <p className="hint">
              由各在线服务器按设定间隔发起公网 TCP 握手测速，自动拒绝私网与保留地址。
            </p>
          </div>
          <button
            type="button"
            className="primary"
            disabled={pingTasks.length >= 32}
            onClick={() => setPingDialog({ ...emptyPingDraft })}
          >
            新建任务
          </button>
        </div>

        {pingTasks.length === 0 ? (
          <p className="hint">暂未配置延迟监测任务。</p>
        ) : (
          <div className="tableWrap">
            <table>
              <thead>
                <tr>
                  <th>名称</th>
                  <th>目标地址</th>
                  <th>检测间隔</th>
                  <th>执行服务器</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {pingTasks.map((t) => (
                  <tr key={t.id}>
                    <td>
                      <strong>{redactScreenshot(t.name)}</strong>
                    </td>
                    <td>
                      <code>{redactScreenshot(t.target)}</code>
                    </td>
                    <td>{t.intervalSeconds} 秒</td>
                    <td>
                      {t.serverIds.length === 0
                        ? "全部支持监控的服务器"
                        : t.serverIds
                            .map((id) => {
                              const s = servers.find((srv) => srv.id === id);
                              return s ? redactScreenshot(s.name) : id;
                            })
                            .join("、")}
                    </td>
                    <td className="actions">
                      <button
                        type="button"
                        className="ghost"
                        onClick={() =>
                          setPingDialog({
                            id: t.id,
                            name: t.name,
                            target: t.target,
                            intervalDraft: String(t.intervalSeconds),
                            serverIds: [...t.serverIds],
                          })
                        }
                      >
                        编辑
                      </button>
                      <button
                        type="button"
                        className="danger"
                        onClick={() =>
                          setConfirmation({
                            title: "删除延迟监测任务",
                            message: `确认删除任务“${t.name}”及其历史延迟记录吗？`,
                            confirmLabel: "删除",
                            onConfirm: () => {
                              void act(async () => {
                                await mutation(`/api/ping-tasks/${t.id}`, "DELETE");
                                await fetchPingTasks();
                              }, "监测任务已删除");
                            },
                          })
                        }
                      >
                        删除
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {pingDialog && (
        <PingTaskDialog
          initial={pingDialog}
          onlineServers={onlineManagedServers}
          redact={redactScreenshot}
          onClose={() => setPingDialog(null)}
          onSaved={async () => {
            await fetchPingTasks();
            if (activeServerId) await loadDetailHistory(true);
          }}
        />
      )}
    </div>,
  );
}
