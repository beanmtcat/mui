import { useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  bytes,
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
  cycleTrafficTone,
  formatBillingCycle,
  formatMonthlyCostSummary,
  formatServerExpiry,
  groupAndSortServers,
  matchesServerGroupFilter,
  serverGroupFilterOptions,
  trafficLimitTypeShortLabels,
} from "../app/helpers";
import { Field, SubmitButton, useBusy } from "../app/ui";
import { useUrlParam } from "../app/url";
import {
  MonitorMetricsCharts,
  PingTaskChart,
  type MonitorRange,
} from "../components/MonitorCharts";
import { Dialog } from "../forms/Dialog";

const RANGES: { id: MonitorRange; label: string }[] = [
  { id: "1h", label: "1 小时" },
  { id: "6h", label: "6 小时" },
  { id: "24h", label: "24 小时" },
  { id: "7d", label: "7 天" },
  { id: "30d", label: "30 天" },
];

type PingTaskDraft = {
  id?: string;
  name: string;
  target: string;
  intervalDraft: string;
  serverIds: string[];
};

const emptyPingDraft: PingTaskDraft = {
  name: "",
  target: "",
  intervalDraft: "60",
  serverIds: [],
};

function formatUptime(seconds: number | undefined) {
  if (!seconds || seconds <= 0) return "—";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days} 天 ${hours} 小时`;
  if (hours > 0) return `${hours} 小时 ${mins} 分钟`;
  return `${Math.max(1, mins)} 分钟`;
}

function usagePercent(used: number, total: number) {
  if (total <= 0) return 0;
  return Math.max(0, Math.min(100, (used / total) * 100));
}

function barTone(pct: number) {
  if (pct >= 90) return "danger";
  if (pct >= 75) return "warning";
  return "";
}

function PingTaskDialog({
  initial,
  onlineServers,
  redact,
  onClose,
  onSaved,
}: {
  initial: PingTaskDraft;
  onlineServers: Server[];
  redact: (v: string) => string;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const { act } = useApp();
  const [draft, setDraft] = useState<PingTaskDraft>(initial);
  const { busy, run } = useBusy();

  return (
    <Dialog
      title={draft.id ? "编辑 TCP 延迟任务" : "新建 TCP 延迟任务"}
      value={draft}
      initial={initial}
      busy={busy}
      onClose={onClose}
    >
      <form
        className="serverForm"
        onSubmit={(e) => {
          e.preventDefault();
          const interval = Number.parseInt(draft.intervalDraft.trim(), 10);
          if (!Number.isInteger(interval) || interval < 30 || interval > 3600) {
            setError("检测间隔请填写 30–3600 之间的整数秒");
            return;
          }
          void run(async () => {
            const payload = {
              name: draft.name.trim(),
              target: draft.target.trim(),
              intervalSeconds: interval,
              serverIds: draft.serverIds,
            };
            const ok = await act(async () => {
              if (draft.id) {
                await mutation<PingTask>(`/api/ping-tasks/${draft.id}`, "PATCH", payload);
              } else {
                await mutation<PingTask>("/api/ping-tasks", "POST", payload);
              }
              await onSaved();
            }, draft.id ? "监测任务已更新" : "监测任务已创建");
            if (ok) onClose();
          });
        }}
      >
        <div className="formGrid">
          <Field label="任务名称 *">
            <input
              required
              maxLength={80}
              placeholder="例如：电信广州 / Cloudflare"
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            />
          </Field>
          <Field label="检测间隔（秒，30–3600） *">
            <input
              required
              inputMode="numeric"
              value={draft.intervalDraft}
              onChange={(e) => setDraft({ ...draft, intervalDraft: e.target.value })}
            />
          </Field>
          <div className="serverFormWide">
            <Field
              label="目标地址（host:port） *"
              help="仅支持 TCP 连接检测，且只允许公网 IP 或解析为公网地址的域名；内网、回环、链路本地及 CGNAT 地址会被拒绝。"
            >
              <input
                required
                placeholder="例如：1.1.1.1:443 或 example.com:443"
                value={draft.target}
                onChange={(e) => setDraft({ ...draft, target: e.target.value })}
              />
            </Field>
          </div>
          <div className="serverFormWide">
            <fieldset className="serverRoles">
              <legend>
                执行服务器（不勾选表示全部支持监控的在线服务器）
              </legend>
              {onlineServers.length === 0 ? (
                <p className="hint">暂无在线 Agent 管理的服务器。</p>
              ) : (
                <div className="checkRow">
                  {onlineServers.map((srv) => {
                    const checked = draft.serverIds.includes(srv.id);
                    return (
                      <label className="check" key={srv.id}>
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={(e) =>
                            setDraft({
                              ...draft,
                              serverIds: e.target.checked
                                ? [...draft.serverIds, srv.id]
                                : draft.serverIds.filter((id) => id !== srv.id),
                            })
                          }
                        />
                        {countryFlag(srv.country)} {redact(srv.name)}
                      </label>
                    );
                  })}
                </div>
              )}
            </fieldset>
          </div>
        </div>
        <div className="serverFormActions">
          <button type="button" className="ghost" disabled={busy} onClick={onClose}>
            取消
          </button>
          <SubmitButton busy={busy} label="保存任务" className="primary" />
        </div>
      </form>
    </Dialog>
  );
}

export default function Monitor() {
  const { servers, trafficLimitThreshold, act, setConfirmation, redactScreenshot, protect } = useApp();
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

  const serverPingTasks = useMemo(() => {
    if (!selectedServer) return [];
    return pingTasks.filter(
      (t) => t.serverIds.length === 0 || t.serverIds.includes(selectedServer.id),
    );
  }, [pingTasks, selectedServer]);

  const loadDetailHistory = useCallback(async () => {
    if (!selectedServer) return;
    setLoadingRecords(true);
    try {
      const pingRange = range === "30d" ? "7d" : range;
      const [hist, ...pingLists] = await Promise.all([
        api<MonitorRecord[]>(
          `/api/monitor/${encodeURIComponent(selectedServer.id)}/records?range=${range}`,
        ),
        ...serverPingTasks.map((t) =>
          api<PingMinuteRecord[]>(
            `/api/ping-tasks/${encodeURIComponent(t.id)}/records?serverId=${encodeURIComponent(selectedServer.id)}&range=${pingRange}`,
          ),
        ),
      ]);
      setRecords(hist);
      const nextMap: Record<string, PingMinuteRecord[]> = {};
      serverPingTasks.forEach((t, i) => {
        nextMap[t.id] = pingLists[i] || [];
      });
      setPingRecordsMap(nextMap);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoadingRecords(false);
    }
  }, [selectedServer, range, serverPingTasks]);

  useEffect(() => {
    if (!selectedServer) {
      setRecords([]);
      setPingRecordsMap({});
      return;
    }
    void loadDetailHistory();
  }, [loadDetailHistory, selectedServer]);

  const onlineCount = onlineManagedServers.filter(
    (s) => overviewByServer.get(s.id)?.online ?? s.status === "online",
  ).length;

  return protect(
    <div className="monitorPage">
      <section className="panel">
        <div className="panelHead">
          <div>
            <h2>主机实时监控</h2>
            <p className="hint">
              共 {onlineManagedServers.length} 台在线管理服务器，当前在线 {onlineCount} 台 · 每 5 秒自动刷新
            </p>
            {monthlyCostSummary && (
              <p className="monitorCostSummary">{monthlyCostSummary}</p>
            )}
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
              className="ghost"
              onClick={() => {
                void fetchOverview();
                if (selectedServer) void loadDetailHistory();
              }}
            >
              立即刷新
            </button>
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
                  <span>{items.length} 台</span>
                </div>
                <div className="monitorGrid">
                  {items.map((srv) => {
                    const item = overviewByServer.get(srv.id);
                    const online = item?.online ?? srv.status === "online";
                    const supported = item?.hostMonitor ?? !!srv.hostMonitor;
                    const sample = item?.sample;
                    const host = item?.host;
                    const active = selectedServer?.id === srv.id;

                    const cpuPct = sample ? Math.max(0, Math.min(100, sample.cpu)) : 0;
                    const ramPct = sample ? usagePercent(sample.ramUsed, sample.ramTotal) : 0;
                    const diskPct = sample ? usagePercent(sample.diskUsed, sample.diskTotal) : 0;
                    const loc = [srv.region, srv.city].filter(Boolean).join(" · ") || srv.country;
                    const expiry = formatServerExpiry(srv.expiresAt);

                    const ct = item?.cycleTraffic ?? srv.cycleTraffic;
                    const cycleLimit = ct?.limit ?? srv.trafficLimit ?? 0;
                    const cycleUsed = ct?.used ?? 0;
                    const cycleRx = ct?.rx ?? 0;
                    const cycleTx = ct?.tx ?? 0;
                    const cycleType = ct?.type ?? srv.trafficLimitType ?? "sum";
                    const cyclePctRaw = cycleLimit > 0 ? (cycleUsed / cycleLimit) * 100 : 0;
                    const cyclePctWidth = Math.max(0, Math.min(100, cyclePctRaw));
                    const cycleTone = cycleTrafficTone(cycleUsed, cycleLimit, trafficLimitThreshold);
                    const cycleRangeTitle = ct
                      ? `本周期：${ct.startAt.slice(0, 10)} 至 ${ct.resetAt.slice(0, 10)}`
                      : undefined;

                    return (
                      <article
                        key={srv.id}
                        className={`monitorCard${active ? " active" : ""}${!online ? " offline" : ""}`}
                        onClick={() => setSelectedId(active ? "" : srv.id)}
                      >
                        <div className="monitorCardHead">
                          <div className="monitorCardTitle">
                            <span className="monitorFlag" aria-hidden="true">
                              {countryFlag(srv.country)}
                            </span>
                            <div>
                              <strong>{redactScreenshot(srv.name)}</strong>
                              <small>{redactScreenshot(loc)}</small>
                            </div>
                          </div>
                          <div className="monitorBadges">
                            {srv.alertMuted && (
                              <span className="pill neutral" title="已静音离线与资源高占用告警">
                                静音
                              </span>
                            )}
                            {srv.autoRenew && srv.billingCycle && (
                              <span className="pill accent">自动续期</span>
                            )}
                            {expiry && (
                              <span className={`pill ${expiry.tone}`}>{expiry.fullText}</span>
                            )}
                            <span className={`pill ${online ? "good" : "bad"}`}>
                              {online ? "在线" : "离线"}
                            </span>
                          </div>
                        </div>

                        {!supported ? (
                          <div className="monitorUpgradeNotice">
                            <span className="pill warn">需升级 Agent</span>
                            <p>升级至 Agent 0.6.31 或更高版本后自动上报主机监控指标。</p>
                          </div>
                        ) : !sample ? (
                          <div className="monitorUpgradeNotice">
                            <p className="hint">
                              {online ? "等待首次采样上报…" : "服务器当前离线，暂无内存实时样本"}
                            </p>
                            {host && (
                              <small className="hint">
                                {[host.cpuName, host.cpuCores ? `${host.cpuCores} 核` : "", host.os]
                                  .filter(Boolean)
                                  .join(" · ")}
                              </small>
                            )}
                          </div>
                        ) : (
                          <>
                            {host && (
                              <div className="monitorHostMeta">
                                {[
                                  host.cpuName,
                                  host.cpuCores ? `${host.cpuCores} 核` : "",
                                  host.os,
                                  host.virtualization,
                                ]
                                  .filter(Boolean)
                                  .join(" · ")}
                              </div>
                            )}

                            <div className="monitorBars">
                              <div className="monitorBarRow">
                                <div className="monitorBarLabel">
                                  <span>CPU</span>
                                  <strong>{cpuPct.toFixed(1)}%</strong>
                                </div>
                                <div className="monitorProgress">
                                  <div
                                    className={`monitorProgressFill ${barTone(cpuPct)}`}
                                    style={{ width: `${cpuPct}%` }}
                                  />
                                </div>
                              </div>

                              <div className="monitorBarRow">
                                <div className="monitorBarLabel">
                                  <span>内存</span>
                                  <strong>
                                    {bytes(sample.ramUsed)} / {bytes(sample.ramTotal)} ({ramPct.toFixed(0)}%)
                                  </strong>
                                </div>
                                <div className="monitorProgress">
                                  <div
                                    className={`monitorProgressFill ${barTone(ramPct)}`}
                                    style={{ width: `${ramPct}%` }}
                                  />
                                </div>
                              </div>

                              <div className="monitorBarRow">
                                <div className="monitorBarLabel">
                                  <span>磁盘</span>
                                  <strong>
                                    {bytes(sample.diskUsed)} / {bytes(sample.diskTotal)} ({diskPct.toFixed(0)}%)
                                  </strong>
                                </div>
                                <div className="monitorProgress">
                                  <div
                                    className={`monitorProgressFill ${barTone(diskPct)}`}
                                    style={{ width: `${diskPct}%` }}
                                  />
                                </div>
                              </div>
                            </div>

                            <div className="monitorStatsGrid">
                              <div>
                                <span>实时速率</span>
                                <strong>
                                  ↑ {bytes(sample.netUp)}/s · ↓ {bytes(sample.netDown)}/s
                                </strong>
                              </div>
                              <div>
                                <span>累计流量</span>
                                <strong>
                                  ↑ {bytes(sample.netTotalUp)} · ↓ {bytes(sample.netTotalDown)}
                                </strong>
                              </div>
                              <div>
                                <span>负载 (1/5/15)</span>
                                <strong>
                                  {sample.load1.toFixed(2)} / {sample.load5.toFixed(2)} / {sample.load15.toFixed(2)}
                                </strong>
                              </div>
                              <div>
                                <span>开机时长</span>
                                <strong>{formatUptime(sample.uptime)}</strong>
                              </div>
                            </div>
                          </>
                        )}

                        <div className="monitorCycleSection" title={cycleRangeTitle}>
                          {cycleLimit > 0 ? (
                            <div className="monitorBarRow">
                              <div className="monitorBarLabel">
                                <span>本周期流量（{trafficLimitTypeShortLabels[cycleType]}）</span>
                                <strong className={cycleTone === "danger" ? "dangerText" : ""}>
                                  {bytes(cycleUsed)} / {bytes(cycleLimit)} ({cyclePctRaw.toFixed(0)}%)
                                </strong>
                              </div>
                              <div className="monitorProgress">
                                <div
                                  className={`monitorProgressFill ${cycleTone}`}
                                  style={{ width: `${cyclePctWidth}%` }}
                                />
                              </div>
                            </div>
                          ) : (
                            <div className="monitorCyclePlain">
                              <span>本周期用量</span>
                              <strong>
                                {bytes(cycleRx + cycleTx)}（↑ {bytes(cycleTx)} · ↓ {bytes(cycleRx)}）
                              </strong>
                            </div>
                          )}
                        </div>

                        {!!srv.billingCycle && (
                          <div className="monitorCardFooter">
                            <small className="monitorBillingMeta">
                              {[
                                srv.price && srv.price > 0
                                  ? `${(srv.currency || "$").trim() || "$"}${/^[A-Za-z]+$/.test((srv.currency || "$").trim()) ? " " : ""}${srv.price.toFixed(2)}`
                                  : "",
                                formatBillingCycle(srv),
                              ]
                                .filter(Boolean)
                                .join(" / ")}
                            </small>
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
                          </div>
                        )}
                      </article>
                    );
                  })}
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      {selectedServer && (
        <section className="panel monitorDetailPanel">
          <div className="panelHead">
            <div>
              <h2>
                {countryFlag(selectedServer.country)}{" "}
                {redactScreenshot(selectedServer.name)} · 历史曲线
              </h2>
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
            <div className="toolbarActions">
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
              <button type="button" className="ghost" onClick={() => setSelectedId("")}>
                收起详情
              </button>
            </div>
          </div>

          {loadingRecords && records.length === 0 ? (
            <p className="hint">正在加载历史记录…</p>
          ) : (
            <>
              <MonitorMetricsCharts records={records} range={range} />
              {serverPingTasks.length > 0 && (
                <div className="monitorPingChartsSection">
                  <h3>TCP 延迟监测曲线</h3>
                  <div className="monitorChartsGrid">
                    {serverPingTasks.map((task) => (
                      <PingTaskChart
                        key={task.id}
                        title={redactScreenshot(task.name)}
                        target={redactScreenshot(task.target)}
                        records={pingRecordsMap[task.id] || []}
                        range={range}
                      />
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </section>
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
            if (selectedServer) await loadDetailHistory();
          }}
        />
      )}
    </div>,
  );
}
