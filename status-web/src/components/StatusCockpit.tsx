import { memo, useId, useMemo, type CSSProperties, type ReactNode } from "react";
import {
  useAnimatedMetricValue,
  useAnimatedTelemetryGeometry,
  usePrefersReducedMotion,
  useStableDialCeiling,
  useTelemetryHistory,
} from "../hooks/useCockpitMotion";
import { formatBytes } from "../monitor/format";
import { clamp, formatByteRate } from "../monitor/monitorTone";
import type { PublicServerItem } from "../monitor/publicCard";
import {
  buildDialScaleMarks,
  buildRingMarkers,
  COCKPIT_DEFAULT_DIAL_CEILING,
  getCockpitNodeStates,
  summarizeCockpitResources,
} from "./cockpitMath";

function CockpitDial({
  direction,
  label,
  rawRate,
  ceiling,
  totalBytes,
  showTotal,
  totalLabel,
  reducedMotion,
}: {
  direction: "up" | "down";
  label: string;
  rawRate: number;
  ceiling: number;
  totalBytes: number;
  showTotal: boolean;
  totalLabel: string;
  reducedMotion: boolean;
}) {
  const { value: animatedRate, animating } = useAnimatedMetricValue(rawRate, 680, reducedMotion);
  const display = formatByteRate(animatedRate);
  const ratio = ceiling > 0 ? clamp(animatedRate / ceiling, 0, 1) : 0;
  const angleDeg = 132 + ratio * 276;
  const progressDeg = ratio * 276;
  const scaleMarks = useMemo(() => buildDialScaleMarks(ceiling), [ceiling]);

  const style = {
    "--cockpit-angle": `${angleDeg.toFixed(1)}deg`,
    "--cockpit-progress": `${progressDeg.toFixed(1)}deg`,
  } as CSSProperties;

  return (
    <div className="home-cockpit-dial-panel" data-dial={direction}>
      <div className="home-cockpit-dial" style={style}>
        <div className="home-cockpit-dial-arc" aria-hidden="true" />
        <div className="home-cockpit-dial-scan" aria-hidden="true" />
        <div className="home-cockpit-dial-orbit" aria-hidden="true" />
        <div className="home-cockpit-dial-needle" aria-hidden="true" />
        <div className="home-cockpit-dial-hub" aria-hidden="true" />

        {scaleMarks.map((mark) => {
          const cls =
            mark.position === "start"
              ? "home-cockpit-scale-start"
              : mark.position === "end"
                ? "home-cockpit-scale-end"
                : "home-cockpit-scale-mark";
          return (
            <span key={mark.position} className={cls} data-position={mark.position} aria-hidden="true">
              {mark.label}
            </span>
          );
        })}

        <div className="home-cockpit-dial-content">
          <span className="home-cockpit-dial-label">{label}</span>
          <div
            className="home-cockpit-dial-value monTabular"
            data-animating={animating ? "true" : "false"}
          >
            {display.value}
            <span>{display.unit}</span>
          </div>
          {showTotal && (
            <div className="home-cockpit-dial-detail monTabular" title={`${totalLabel} ${formatBytes(totalBytes)}`}>
              {totalLabel} {formatBytes(totalBytes)}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function CockpitTelemetryWing({
  direction,
  title,
  samples,
  reducedMotion,
}: {
  direction: "upload" | "download";
  title: string;
  samples: number[];
  reducedMotion: boolean;
}) {
  const gradId = useId();
  const clipId = useId();
  const width = 180;
  const height = 64;
  const geo = useAnimatedTelemetryGeometry(samples, width, height, reducedMotion);
  const meanRate = formatByteRate(geo.mean);
  const peakRate = formatByteRate(geo.peak);
  const clipWidth = Math.max(0, Math.min(width, geo.revealProgress * width));

  return (
    <div
      className="home-cockpit-telemetry"
      data-direction={direction}
      data-animating={geo.transitioning ? "true" : "false"}
    >
      <header>
        <span>{title}</span>
        <i>{direction === "upload" ? "↑" : "↓"}</i>
      </header>

      <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" aria-hidden="true">
        <defs>
          <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="currentColor" stopOpacity="0.34" />
            <stop offset="100%" stopColor="currentColor" stopOpacity="0.02" />
          </linearGradient>
          <clipPath id={clipId}>
            <rect x="0" y="-6" width={clipWidth.toFixed(1)} height={height + 12} />
          </clipPath>
        </defs>
        <line className="home-cockpit-telemetry-grid" x1="0" y1={height * 0.25} x2={width} y2={height * 0.25} />
        <line className="home-cockpit-telemetry-grid" x1="0" y1={height * 0.5} x2={width} y2={height * 0.5} />
        <line className="home-cockpit-telemetry-grid" x1="0" y1={height * 0.75} x2={width} y2={height * 0.75} />
        <g transform={`translate(${width} 0) scale(-1 1)`}>
          <g clipPath={`url(#${clipId})`}>
            <path className="home-cockpit-telemetry-area" fill={`url(#${gradId})`} d={geo.areaPath} />
            <path className="home-cockpit-telemetry-line" d={geo.linePath} />
            <path className="home-cockpit-telemetry-pulse" d={geo.linePath} />
          </g>
          <circle className="home-cockpit-telemetry-end-ring" cx={geo.endX} cy={geo.endY} r="4.2" />
          <circle className="home-cockpit-telemetry-end-dot" cx={geo.endX} cy={geo.endY} r="2.2" />
        </g>
      </svg>

      <div className="home-cockpit-telemetry-stats monTabular">
        <span>
          均值
          <strong>
            {meanRate.value} {meanRate.unit}
          </strong>
        </span>
        <span>
          峰值
          <strong>
            {peakRate.value} {peakRate.unit}
          </strong>
        </span>
      </div>
    </div>
  );
}

function CockpitNodeStatusRing({
  totalNodes,
  onlineNodes,
  offlineNodes,
  reducedMotion,
}: {
  totalNodes: number;
  onlineNodes: number;
  offlineNodes: number;
  reducedMotion: boolean;
}) {
  const { value: animOnline } = useAnimatedMetricValue(onlineNodes, 560, reducedMotion);
  const states = useMemo(
    () => getCockpitNodeStates(totalNodes, onlineNodes, offlineNodes),
    [totalNodes, onlineNodes, offlineNodes],
  );
  const markers = useMemo(() => buildRingMarkers(states), [states]);

  return (
    <div
      className="home-cockpit-node-cluster"
      aria-label={`在线 ${onlineNodes} 个，共 ${totalNodes} 个节点，离线 ${offlineNodes} 个`}
    >
      <svg viewBox="0 0 280 128" aria-hidden="true">
        <path className="home-cockpit-node-ring-guide" d="M77.6 119 A72 72 0 1 1 202.4 119" />
        <path className="home-cockpit-node-ring-sweep" d="M77.6 119 A72 72 0 1 1 202.4 119" />
        {markers.map((marker, idx) => (
          <circle
            key={idx}
            className="home-cockpit-node-marker"
            data-state={marker.state}
            cx={marker.x}
            cy={marker.y}
            r={marker.r}
            style={{ animationDelay: `${marker.delayMs}ms` }}
          />
        ))}
      </svg>
      <div className="home-cockpit-online">
        <p className="monTabular">
          {Math.round(animOnline)}
          <span>/ {totalNodes}</span>
        </p>
        <span>在线节点</span>
      </div>
    </div>
  );
}

export const StatusCockpit = memo(function StatusCockpit({
  servers,
  generatedAt,
  showTraffic,
  disconnected,
  controls,
}: {
  servers: PublicServerItem[];
  generatedAt: string;
  showTraffic: boolean;
  disconnected: boolean;
  controls?: ReactNode;
}) {
  const reducedMotion = usePrefersReducedMotion();
  const summary = useMemo(
    () => summarizeCockpitResources(servers, showTraffic),
    [servers, showTraffic],
  );

  const upCeiling = useStableDialCeiling(summary.netUp, COCKPIT_DEFAULT_DIAL_CEILING);
  const downCeiling = useStableDialCeiling(summary.netDown, COCKPIT_DEFAULT_DIAL_CEILING);
  const { upSamples, downSamples } = useTelemetryHistory(
    summary.netUp,
    summary.netDown,
    generatedAt,
    servers.length > 0,
  );

  const cpuAnim = useAnimatedMetricValue(summary.cpuPct, 620, reducedMotion).value;
  const ramPct = summary.ramTotal > 0 ? clamp((summary.ramUsed / summary.ramTotal) * 100, 0, 100) : 0;
  const diskPct =
    summary.diskTotal > 0 ? clamp((summary.diskUsed / summary.diskTotal) * 100, 0, 100) : 0;
  const ramAnim = useAnimatedMetricValue(ramPct, 620, reducedMotion).value;
  const diskAnim = useAnimatedMetricValue(diskPct, 620, reducedMotion).value;

  return (
    <section
      className="home-cockpit-overview"
      data-has-traffic={showTraffic && summary.hasTrafficTotals ? "true" : "false"}
      data-has-toolbar={controls ? "true" : "false"}
      aria-label="实时总览仪表盘"
    >
      <CockpitDial
        direction="up"
        label="实时上行"
        rawRate={summary.netUp}
        ceiling={upCeiling}
        totalBytes={summary.totalUp}
        showTotal={showTraffic && summary.hasTrafficTotals}
        totalLabel="出站"
        reducedMotion={reducedMotion}
      />

      <CockpitTelemetryWing
        direction="upload"
        title="上行趋势"
        samples={upSamples}
        reducedMotion={reducedMotion}
      />

      <div className="home-cockpit-center-panel">
        <div className="home-cockpit-center-topline">
          <span className="home-cockpit-ready" data-disconnected={disconnected ? "true" : "false"}>
            <i aria-hidden="true" />
            {disconnected ? "OFFLINE" : "READY"}
          </span>
          <span className="home-cockpit-live-tag">
            {disconnected ? "DATA · RETRY" : "DATA · LIVE"}
          </span>
        </div>

        <div className="home-cockpit-center-stage">
          {showTraffic && summary.hasTrafficTotals && (
            <div className="home-cockpit-side-summary home-cockpit-traffic-left monTabular">
              <span className="home-cockpit-summary-label">累计出站</span>
              <strong>{formatBytes(summary.totalUp)}</strong>
            </div>
          )}

          <CockpitNodeStatusRing
            totalNodes={summary.totalNodes}
            onlineNodes={summary.onlineNodes}
            offlineNodes={summary.offlineNodes}
            reducedMotion={reducedMotion}
          />

          {showTraffic && summary.hasTrafficTotals && (
            <div className="home-cockpit-side-summary home-cockpit-traffic-summary monTabular">
              <span className="home-cockpit-summary-label">累计入站</span>
              <strong>{formatBytes(summary.totalDown)}</strong>
            </div>
          )}
        </div>
      </div>

      <div className="home-cockpit-resource-strip">
        <div className="home-cockpit-resource-item" data-resource="cpu">
          <div className="home-cockpit-resource-head">
            <small>CPU</small>
            <strong className="monTabular">{cpuAnim.toFixed(1)}%</strong>
          </div>
          <span
            className="home-cockpit-resource-track"
            style={{ "--cockpit-resource-progress": `${clamp(cpuAnim, 0, 100).toFixed(1)}%` } as CSSProperties}
          >
            <i />
          </span>
          <div className="home-cockpit-resource-detail monTabular">
            {summary.cpuCores > 0 ? `${summary.cpuCores} 核在线均值` : "在线节点均值"}
          </div>
        </div>

        <div className="home-cockpit-resource-item" data-resource="memory">
          <div className="home-cockpit-resource-head">
            <small>内存</small>
            <strong className="monTabular">{ramAnim.toFixed(0)}%</strong>
          </div>
          <span
            className="home-cockpit-resource-track"
            style={{ "--cockpit-resource-progress": `${clamp(ramAnim, 0, 100).toFixed(1)}%` } as CSSProperties}
          >
            <i />
          </span>
          <div className="home-cockpit-resource-detail monTabular">
            {summary.ramTotal > 0
              ? `${formatBytes(summary.ramUsed)} / ${formatBytes(summary.ramTotal)}`
              : "—"}
          </div>
        </div>

        <div className="home-cockpit-resource-item" data-resource="disk">
          <div className="home-cockpit-resource-head">
            <small>磁盘</small>
            <strong className="monTabular">{diskAnim.toFixed(0)}%</strong>
          </div>
          <span
            className="home-cockpit-resource-track"
            style={{ "--cockpit-resource-progress": `${clamp(diskAnim, 0, 100).toFixed(1)}%` } as CSSProperties}
          >
            <i />
          </span>
          <div className="home-cockpit-resource-detail monTabular">
            {summary.diskTotal > 0
              ? `${formatBytes(summary.diskUsed)} / ${formatBytes(summary.diskTotal)}`
              : "—"}
          </div>
        </div>
      </div>

      <CockpitTelemetryWing
        direction="download"
        title="下行趋势"
        samples={downSamples}
        reducedMotion={reducedMotion}
      />

      <CockpitDial
        direction="down"
        label="实时下行"
        rawRate={summary.netDown}
        ceiling={downCeiling}
        totalBytes={summary.totalDown}
        showTotal={showTraffic && summary.hasTrafficTotals}
        totalLabel="入站"
        reducedMotion={reducedMotion}
      />

      {controls ? <div className="home-cockpit-toolbar">{controls}</div> : null}
    </section>
  );
});
