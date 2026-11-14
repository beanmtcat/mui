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
  extraReadout?: (point: T) => string | null;
}) {
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);
  const width = 720;
  const height = 180;

  let peak = 0;
  for (const p of points) {
    for (const s of series) {
      const v = s.value(p);
      if (v !== null && Number.isFinite(v) && v > peak) peak = v;
    }
  }
  const ceiling = niceCeiling(peak, fixedCeiling);
  const x = (index: number) =>
    points.length <= 1
      ? width / 2
      : 6 + (index / (points.length - 1)) * (width - 12);
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

  const tickIndices =
    points.length === 0
      ? []
      : [
          0,
          Math.floor((points.length - 1) * 0.25),
          Math.floor((points.length - 1) * 0.5),
          Math.floor((points.length - 1) * 0.75),
          points.length - 1,
        ].filter((idx, pos, arr) => idx >= 0 && idx < points.length && arr.indexOf(idx) === pos);

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
          {series.map((s) => (
            <span
              key={s.key}
              className={`monSeries-${s.tone}${s.dashed ? " is-dashed" : ""}`}
            >
              {s.label}
            </span>
          ))}
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
              const ratio = (event.clientX - bounds.left) / Math.max(1, bounds.width);
              setHoverIndex(
                Math.max(0, Math.min(points.length - 1, Math.round(ratio * (points.length - 1)))),
              );
            }}
            onMouseLeave={() => setHoverIndex(null)}
          >
            {[6, height / 2, height - 6].map((atY) => (
              <line key={atY} className="trafficGridLine" x1="0" x2={width} y1={atY} y2={atY} />
            ))}
            {series.map((s) => {
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
              series.map((s) => {
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
                {series.map((s) => {
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
      {tickIndices.length > 0 && (
        <div className="trafficXAxis">
          {tickIndices.map((idx, pos) => (
            <span className={pos === 1 || pos === 3 ? "optional" : ""} key={idx}>
              {formatChartTime(points[idx].at, range)}
            </span>
          ))}
        </div>
      )}
      {selected && (
        <div className="trafficReadout monitorReadout">
          <strong>{formatChartTime(selected.at, range)}</strong>
          {series.map((s) => {
            const v = s.value(selected);
            return (
              <span key={s.key}>
                {s.label}：{v === null ? "—" : formatValue(v)}
              </span>
            );
          })}
          {extraReadout && extraReadout(selected) && <span>{extraReadout(selected)}</span>}
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
        extraReadout={(p) =>
          p.ramTotal > 0 ? `占比 ${((p.ramUsed / p.ramTotal) * 100).toFixed(1)}%` : null
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
        extraReadout={(p) => `峰值 ↑ ${formatBytes(p.netUpPeak)}/s · ↓ ${formatBytes(p.netDownPeak)}/s`}
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

export const PingTaskChart = memo(function PingTaskChart({
  title,
  target,
  records,
  range,
}: {
  title: string;
  target?: string;
  records: SharedPingPoint[];
  range: MonitorRange;
}) {
  let totalSent = 0;
  let totalLost = 0;
  let okCount = 0;
  let weightedMs = 0;
  for (const r of records) {
    totalSent += r.sent;
    totalLost += r.lost;
    const ok = r.sent - r.lost;
    if (ok > 0) {
      okCount += ok;
      weightedMs += r.msAvg * ok;
    }
  }
  const lossPct = totalSent > 0 ? (totalLost / totalSent) * 100 : 0;
  const avgMs = okCount > 0 ? weightedMs / okCount : null;
  const latColor = avgMs !== null ? latencyHeatColor(avgMs) : "var(--mon-latency-excellent)";
  const subParts: string[] = [];
  if (target) subParts.push(target);
  if (avgMs !== null) subParts.push(`均值 ${avgMs.toFixed(0)} ms`);
  if (totalSent > 0) subParts.push(`丢包率 ${lossPct.toFixed(1)}%（${totalLost}/${totalSent}）`);
  if (range === "30d") subParts.push("延迟记录保留 7 天");

  return (
    <MonitorSeriesChart
      title={title}
      subtitle={subParts.length > 0 ? subParts.join(" · ") : undefined}
      accent={latColor}
      latencyColor={latColor}
      points={records}
      range={range}
      series={[
        {
          key: "avg",
          label: "平均延迟",
          tone: "latency",
          value: (p) => (p.sent > p.lost ? p.msAvg : null),
        },
        {
          key: "max",
          label: "最大延迟",
          tone: "latencyMax",
          dashed: true,
          value: (p) => (p.sent > p.lost ? p.msMax : null),
        },
      ]}
      formatAxis={(v) => `${Math.round(v)} ms`}
      formatValue={(v) => `${Math.round(v)} ms`}
      emptyLabel="暂无 TCP 延迟记录"
      extraReadout={(p) =>
        p.sent > 0
          ? `丢包 ${p.lost}/${p.sent}（${((p.lost / p.sent) * 100).toFixed(0)}%）`
          : null
      }
    />
  );
});
