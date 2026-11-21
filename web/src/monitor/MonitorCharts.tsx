// Counterpart in status-web/src/monitor/MonitorCharts.tsx — keep chart layout & styles in sync.

import { memo, useState, type CSSProperties } from "react";
import { formatBytes } from "./format";
import { latencyHeatColor } from "./monitorTone";
import type { MonitorRange, SharedMonitorRecord, SharedPingPoint } from "./types";

export type { MonitorRange };

type SeriesTone =
  | "cpu"
  | "memory"
  | "swap"
  | "up"
  | "down"
  | "network"
  | "load"
  | "latency"
  | "latencyMax";

type SeriesDef<T> = {
  key: string;
  label: string;
  tone: SeriesTone;
  dashed?: boolean;
  value: (point: T) => number | null;
};

function formatChartTime(at: string, range: MonitorRange) {
  const d = new Date(at);
  if (range === "7d" || range === "30d") {
    return d.toLocaleString("zh-CN", {
      month: "numeric",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }
  return d.toLocaleTimeString("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function niceCeiling(peak: number, fixedMax?: number) {
  if (fixedMax && fixedMax > 0 && peak <= fixedMax) return fixedMax;
  if (peak <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(peak));
  return ([1, 2, 5, 10].find((step) => step * magnitude >= peak) || 10) * magnitude;
}

function findNearestXIndex(
  svgX: number,
  count: number,
  xAt: (index: number) => number,
): number {
  let best = 0;
  let bestDist = Math.abs(xAt(0) - svgX);
  for (let i = 1; i < count; i++) {
    const dist = Math.abs(xAt(i) - svgX);
    if (dist < bestDist) {
      best = i;
      bestDist = dist;
    }
  }
  return best;
}

function resolveVisibleKeys(
  hidden: Readonly<Record<string, boolean>>,
  keys: readonly string[],
): Set<string> {
  const visible = new Set<string>();
  for (const k of keys) {
    if (!hidden[k]) visible.add(k);
  }
  if (visible.size === 0) {
    for (const k of keys) visible.add(k);
  }
  return visible;
}

function toggleSeriesVisibility(
  prev: Readonly<Record<string, boolean>>,
  keys: readonly string[],
  key: string,
): Record<string, boolean> {
  if (keys.length <= 1) return {};
  const visible = resolveVisibleKeys(prev, keys);
  const isCurrentlyVisible = visible.has(key);
  // Clicking the sole remaining visible series restores all series.
  if (isCurrentlyVisible && visible.size <= 1) {
    return {};
  }
  const next: Record<string, boolean> = {};
  for (const k of keys) {
    const nextVisible = k === key ? !isCurrentlyVisible : visible.has(k);
    if (!nextVisible) {
      next[k] = true;
    }
  }
  return next;
}

export function MonitorSeriesChart<T extends { at: string }>({
  title,
  subtitle,
  accent,
  latencyColor,
  points,
  series,
  range,
  fixedCeiling,
  formatAxis,
  formatValue,
  emptyLabel = "暂无采样数据",
  extraReadout,
  hiddenKeys,
  onToggleSeries,
}: {
  title: string;
  subtitle?: string;
  accent?: string;
  latencyColor?: string;
  points: T[];
  series: SeriesDef<T>[];
  range: MonitorRange;
  fixedCeiling?: number;
  formatAxis: (v: number) => string;
  formatValue: (v: number) => string;
  emptyLabel?: string;
  extraReadout?: (point: T, visibleKeys: ReadonlySet<string>) => string | null;
  hiddenKeys?: Readonly<Record<string, boolean>>;
  onToggleSeries?: (key: string) => void;
}) {
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);
  const [internalHidden, setInternalHidden] = useState<Record<string, boolean>>({});
  const effectiveHidden = hiddenKeys ?? internalHidden;
  const seriesKeys = series.map((s) => s.key);
  const visibleSet = resolveVisibleKeys(effectiveHidden, seriesKeys);
  const visibleSeries = series.filter((s) => visibleSet.has(s.key));
  const canToggle = series.length > 1;
  const handleToggle = (key: string) => {
    if (!canToggle) return;
    if (onToggleSeries) {
      onToggleSeries(key);
      return;
    }
    setInternalHidden((prev) => toggleSeriesVisibility(prev, seriesKeys, key));
  };

  const width = 720;
  const height = 180;

  let peak = 0;
  for (const p of points) {
    for (const s of visibleSeries) {
      const v = s.value(p);
      if (v !== null && Number.isFinite(v) && v > peak) peak = v;
    }
  }
  const effectiveCeiling = visibleSeries.length === series.length ? fixedCeiling : undefined;
  const ceiling = niceCeiling(peak, effectiveCeiling);
  const pointTimes = points.map((p) => new Date(p.at).getTime());
  const firstTime = pointTimes.length > 0 ? pointTimes[0] : NaN;
  const lastTime = pointTimes.length > 0 ? pointTimes[pointTimes.length - 1] : NaN;
  const timeSpan = lastTime - firstTime;
  const hasTimeScale =
    points.length > 1 && pointTimes.every((t) => Number.isFinite(t)) && timeSpan > 0;
  const x = (index: number) => {
    if (points.length <= 1) return width / 2;
    if (hasTimeScale) {
      return 6 + ((pointTimes[index] - firstTime) / timeSpan) * (width - 12);
    }
    return 6 + (index / (points.length - 1)) * (width - 12);
  };
  const y = (value: number) =>
    height - 6 - (Math.max(0, Math.min(ceiling, value)) / ceiling) * (height - 12);

  const buildPath = (s: SeriesDef<T>) => {
    const cmds: string[] = [];
    let penDown = false;
    points.forEach((p, idx) => {
      const v = s.value(p);
      if (v === null || !Number.isFinite(v)) {
        penDown = false;
        return;
      }
      cmds.push(`${penDown ? "L" : "M"}${x(idx).toFixed(1)},${y(v).toFixed(1)}`);
      penDown = true;
    });
    return cmds.join(" ");
  };

  const selectedIndex =
    points.length === 0
      ? -1
      : hoverIndex === null
        ? points.length - 1
        : Math.min(hoverIndex, points.length - 1);
  const selected = selectedIndex >= 0 ? points[selectedIndex] : undefined;

  const xTicks: { key: string; label: string; optional: boolean }[] = (() => {
    if (points.length === 0) return [];
    if (points.length === 1) {
      return [{ key: "0", label: formatChartTime(points[0].at, range), optional: false }];
    }
    if (hasTimeScale) {
      const fractions =
        timeSpan >= 4 * 60_000
          ? [0, 0.25, 0.5, 0.75, 1]
          : timeSpan >= 2 * 60_000
            ? [0, 0.5, 1]
            : [0, 1];
      return fractions.map((f, pos) => ({
        key: String(pos),
        label: formatChartTime(new Date(firstTime + timeSpan * f).toISOString(), range),
        optional: fractions.length === 5 && (pos === 1 || pos === 3),
      }));
    }
    const tickIndices = [
      0,
      Math.floor((points.length - 1) * 0.25),
      Math.floor((points.length - 1) * 0.5),
      Math.floor((points.length - 1) * 0.75),
      points.length - 1,
    ].filter((idx, pos, arr) => idx >= 0 && idx < points.length && arr.indexOf(idx) === pos);
    return tickIndices.map((idx, pos) => ({
      key: String(idx),
      label: formatChartTime(points[idx].at, range),
      optional: pos === 1 || pos === 3,
    }));
  })();

  const cardStyle = {
    ...(accent ? { "--mon-chart-accent": accent } : {}),
    ...(latencyColor ? { "--mon-chart-latency": latencyColor } : {}),
  } as CSSProperties;

  return (
    <div className="trafficChart monitorChartCard monTabular" style={cardStyle}>
      <div className="trafficChartHead monitorChartHead">
        <div className="monitorChartHeadText">
          <strong className="monitorChartTitle">{title}</strong>
          {subtitle && <span className="monitorChartSub">{subtitle}</span>}
        </div>
        <div className="trafficLegend monitorLegend">
          {series.map((s) => {
            const isHidden = !visibleSet.has(s.key);
            if (!canToggle) {
              return (
                <span
                  key={s.key}
                  className={`monSeries-${s.tone}${s.dashed ? " is-dashed" : ""}`}
                >
                  {s.label}
                </span>
              );
            }
            const titleText = isHidden
              ? `点击显示「${s.label}」`
              : visibleSeries.length <= 1
                ? "点击恢复全部指标"
                : `点击隐藏「${s.label}」`;
            return (
              <button
                key={s.key}
                type="button"
                className={`monitorLegendBtn monSeries-${s.tone}${s.dashed ? " is-dashed" : ""}${isHidden ? " is-hidden" : ""}`}
                aria-pressed={!isHidden}
                title={titleText}
                onClick={() => handleToggle(s.key)}
              >
                {s.label}
              </button>
            );
          })}
        </div>
      </div>
      <div className="trafficPlotRow">
        <div className="trafficYAxis">
          <span>{points.length ? formatAxis(ceiling) : ""}</span>
          <span>{points.length ? formatAxis(ceiling / 2) : ""}</span>
          <span>{formatAxis(0)}</span>
        </div>
        <div className="trafficPlot">
          <svg
            viewBox={`0 0 ${width} ${height}`}
            preserveAspectRatio="none"
            role="img"
            aria-label={title}
            onMouseMove={(event) => {
              if (!points.length) return;
              const bounds = event.currentTarget.getBoundingClientRect();
              const ratio = Math.max(
                0,
                Math.min(1, (event.clientX - bounds.left) / Math.max(1, bounds.width)),
              );
              setHoverIndex(findNearestXIndex(ratio * width, points.length, x));
            }}
            onMouseLeave={() => setHoverIndex(null)}
          >
            {[6, height / 2, height - 6].map((atY) => (
              <line key={atY} className="trafficGridLine" x1="0" x2={width} y1={atY} y2={atY} />
            ))}
            {visibleSeries.map((s) => {
              const d = buildPath(s);
              return d ? (
                <path
                  key={s.key}
                  className={`trafficLine monSeries-${s.tone}${s.dashed ? " is-dashed" : ""}`}
                  d={d}
                />
              ) : null;
            })}
            {points.length === 1 &&
              visibleSeries.map((s) => {
                const v = s.value(points[0]);
                return v !== null ? (
                  <circle
                    key={s.key}
                    className={`trafficDot monSeries-${s.tone}`}
                    cx={x(0)}
                    cy={y(v)}
                    r="4.5"
                  />
                ) : null;
              })}
            {hoverIndex !== null && selected && (
              <>
                <line
                  className="trafficCursor"
                  x1={x(selectedIndex)}
                  x2={x(selectedIndex)}
                  y1="6"
                  y2={height - 6}
                />
                {visibleSeries.map((s) => {
                  const v = s.value(selected);
                  return v !== null ? (
                    <circle
                      key={s.key}
                      className={`trafficDot monSeries-${s.tone}`}
                      cx={x(selectedIndex)}
                      cy={y(v)}
                      r="4.5"
                    />
                  ) : null;
                })}
              </>
            )}
          </svg>
          {points.length === 0 && <div className="trafficZero">{emptyLabel}</div>}
        </div>
      </div>
      {xTicks.length > 0 && (
        <div className="trafficXAxis">
          {xTicks.map((tick) => (
            <span className={tick.optional ? "optional" : ""} key={tick.key}>
              {tick.label}
            </span>
          ))}
        </div>
      )}
      {selected && (
        <div className="trafficReadout monitorReadout">
          <strong>{formatChartTime(selected.at, range)}</strong>
          {visibleSeries.map((s) => {
            const v = s.value(selected);
            return (
              <span key={s.key}>
                {s.label}：{v === null ? "—" : formatValue(v)}
              </span>
            );
          })}
          {(() => {
            const extraText = extraReadout ? extraReadout(selected, visibleSet) : null;
            return extraText ? <span>{extraText}</span> : null;
          })()}
        </div>
      )}
    </div>
  );
}

export const MonitorMetricsCharts = memo(function MonitorMetricsCharts({
  records,
  range,
}: {
  records: SharedMonitorRecord[];
  range: MonitorRange;
}) {
  const lastRamTotal = records.length ? records[records.length - 1].ramTotal : 0;
  return (
    <div className="monitorChartsGrid">
      <MonitorSeriesChart
        title="CPU 使用率"
        subtitle={range === "7d" || range === "30d" ? "按小时均值" : "按分钟均值"}
        accent="var(--mon-progress-cpu)"
        points={records}
        range={range}
        fixedCeiling={100}
        series={[{ key: "cpu", label: "CPU", tone: "cpu", value: (p) => p.cpu }]}
        formatAxis={(v) => `${Math.round(v)}%`}
        formatValue={(v) => `${v.toFixed(1)}%`}
        extraReadout={(p) => `1 分钟负载：${p.load1.toFixed(2)}`}
      />
      <MonitorSeriesChart
        title="内存与交换分区"
        subtitle={lastRamTotal > 0 ? `物理内存总量 ${formatBytes(lastRamTotal)}` : undefined}
        accent="var(--mon-progress-memory)"
        points={records}
        range={range}
        fixedCeiling={lastRamTotal > 0 ? lastRamTotal : undefined}
        series={[
          { key: "ram", label: "内存已用", tone: "memory", value: (p) => p.ramUsed },
          { key: "swap", label: "Swap 已用", tone: "swap", dashed: true, value: (p) => p.swapUsed },
        ]}
        formatAxis={(v) => formatBytes(v)}
        formatValue={(v) => formatBytes(v)}
        extraReadout={(p, visibleKeys) =>
          visibleKeys.has("ram") && p.ramTotal > 0
            ? `占比 ${((p.ramUsed / p.ramTotal) * 100).toFixed(1)}%`
            : null
        }
      />
      <MonitorSeriesChart
        title="网络速率"
        subtitle="均值与峰值"
        accent="var(--mon-progress-network)"
        points={records}
        range={range}
        series={[
          { key: "up", label: "上行速率", tone: "up", value: (p) => p.netUp },
          { key: "down", label: "下行速率", tone: "down", dashed: true, value: (p) => p.netDown },
        ]}
        formatAxis={(v) => `${formatBytes(v)}/s`}
        formatValue={(v) => `${formatBytes(v)}/s`}
        extraReadout={(p, visibleKeys) => {
          const parts: string[] = [];
          if (visibleKeys.has("up")) parts.push(`↑ ${formatBytes(p.netUpPeak)}/s`);
          if (visibleKeys.has("down")) parts.push(`↓ ${formatBytes(p.netDownPeak)}/s`);
          return parts.length > 0 ? `峰值 ${parts.join(" · ")}` : null;
        }}
      />
      <MonitorSeriesChart
        title="连接数与进程数"
        accent="var(--mon-progress-load)"
        points={records}
        range={range}
        series={[
          { key: "tcp", label: "TCP", tone: "cpu", value: (p) => p.tcp },
          { key: "udp", label: "UDP", tone: "network", dashed: true, value: (p) => p.udp },
          { key: "proc", label: "进程", tone: "load", value: (p) => p.process },
        ]}
        formatAxis={(v) => `${Math.round(v)}`}
        formatValue={(v) => `${Math.round(v)}`}
      />
    </div>
  );
});

// One chart for every probe task of a server: a line per task, aligned on time.
const PING_SERIES_TONES: SeriesTone[] = ["cpu", "memory", "network", "load", "down", "swap"];

type CombinedPingPoint = {
  at: string;
  ms: (number | null)[];
  sent: number[];
  lost: number[];
};

export const PingCombinedChart = memo(function PingCombinedChart({
  tasks,
  range,
}: {
  tasks: { id: string; name: string; records: SharedPingPoint[] }[];
  range: MonitorRange;
}) {
  const [hiddenKeys, setHiddenKeys] = useState<Record<string, boolean>>({});
  const taskKeys = tasks.map((t) => t.id);
  const visibleTaskSet = resolveVisibleKeys(hiddenKeys, taskKeys);
  const visibleTaskCount = visibleTaskSet.size;

  const byTime = new Map<number, CombinedPingPoint>();
  let totalSent = 0;
  let totalLost = 0;
  let okCount = 0;
  let weightedMs = 0;
  tasks.forEach((task, taskIndex) => {
    if (!visibleTaskSet.has(task.id)) return;
    for (const r of task.records) {
      const key = new Date(r.at).getTime();
      if (!Number.isFinite(key)) continue;
      let point = byTime.get(key);
      if (!point) {
        point = {
          at: r.at,
          ms: tasks.map(() => null),
          sent: tasks.map(() => 0),
          lost: tasks.map(() => 0),
        };
        byTime.set(key, point);
      }
      const ok = r.sent - r.lost;
      point.ms[taskIndex] = ok > 0 ? r.msAvg : null;
      point.sent[taskIndex] = r.sent;
      point.lost[taskIndex] = r.lost;
      totalSent += r.sent;
      totalLost += r.lost;
      if (ok > 0) {
        okCount += ok;
        weightedMs += r.msAvg * ok;
      }
    }
  });
  const points = [...byTime.entries()].sort((a, b) => a[0] - b[0]).map(([, point]) => point);

  const avgMs = okCount > 0 ? weightedMs / okCount : null;
  const latColor = avgMs !== null ? latencyHeatColor(avgMs) : "var(--mon-latency-excellent)";
  const subParts: string[] = [
    visibleTaskCount === tasks.length
      ? `${tasks.length} 个任务`
      : `已选 ${visibleTaskCount}/${tasks.length} 个任务`,
  ];
  if (avgMs !== null) subParts.push(`均值 ${avgMs.toFixed(0)} ms`);
  if (totalSent > 0) {
    subParts.push(`丢包率 ${((totalLost / totalSent) * 100).toFixed(1)}%（${totalLost}/${totalSent}）`);
  }

  return (
    <div className="monitorChartWide">
      <MonitorSeriesChart
        title="延迟"
        subtitle={subParts.join(" · ")}
        accent={latColor}
        latencyColor={latColor}
        points={points}
        range={range}
        hiddenKeys={hiddenKeys}
        onToggleSeries={(key) =>
          setHiddenKeys((prev) => toggleSeriesVisibility(prev, taskKeys, key))
        }
        series={tasks.map((task, taskIndex) => ({
          key: task.id,
          label: task.name,
          tone: PING_SERIES_TONES[taskIndex % PING_SERIES_TONES.length],
          dashed: taskIndex >= PING_SERIES_TONES.length,
          value: (p: CombinedPingPoint) => p.ms[taskIndex],
        }))}
        formatAxis={(v) => `${Math.round(v)} ms`}
        formatValue={(v) => `${Math.round(v)} ms`}
        emptyLabel="暂无 TCP 延迟记录"
        extraReadout={(p, visibleKeys) => {
          const parts = tasks
            .map((task, taskIndex) =>
              visibleKeys.has(task.id) && p.sent[taskIndex] > 0 && p.lost[taskIndex] > 0
                ? `${task.name} ${((p.lost[taskIndex] / p.sent[taskIndex]) * 100).toFixed(0)}%`
                : null,
            )
            .filter(Boolean);
          return parts.length > 0 ? `丢包 ${parts.join("、")}` : null;
        }}
      />
    </div>
  );
});
