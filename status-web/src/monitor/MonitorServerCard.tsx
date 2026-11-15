// Public status page server card — compact density aligned with LuminaPlus CompactNodeCard.

import { memo, type CSSProperties, type ReactNode } from "react";
import { IpStackBadges } from "../components/IpStackBadges";
import { OsLogo } from "../components/OsLogo";
import { PingHealthStrip } from "../components/PingHealthStrip";
import {
  countryFlag,
  cycleTrafficTone,
  formatBytes,
  formatServerExpiry,
  trafficLimitTypeShortLabels,
} from "./format";
import {
  clamp,
  formatByteRate,
  loadGaugeColor,
  metricGaugeColor,
  resolveExpireVisual,
  speedRateColor,
  TRAFFIC_QUOTA_SEGMENT_COLORS,
  trafficQuotaLitCount,
  TRAFFIC_SLIVER_RATIO,
} from "./monitorTone";
import type { MonitorCardViewModel } from "./types";

function usagePercent(used: number, total: number) {
  if (total <= 0) return 0;
  return clamp((used / total) * 100, 0, 100);
}

function CpuIcon() {
  return (
    <svg width="12.5" height="12.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="4" y="4" width="16" height="16" rx="2" />
      <rect x="9" y="9" width="6" height="6" rx="1" />
      <path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3" />
    </svg>
  );
}

function MemoryIcon() {
  return (
    <svg width="12.5" height="12.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="2" y="6" width="20" height="10" rx="2" />
      <path d="M6 10v2M10 10v2M14 10v2M18 10v2M6 16v3M10 16v3M14 16v3M18 16v3" />
    </svg>
  );
}

function DiskIcon() {
  return (
    <svg width="12.5" height="12.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="2" y="5" width="20" height="14" rx="2.5" />
      <path d="M2 13h20" />
      <circle cx="6.5" cy="16" r="1" fill="currentColor" />
      <circle cx="10.5" cy="16" r="1" fill="currentColor" />
    </svg>
  );
}

function LoadIcon() {
  return (
    <svg width="12.5" height="12.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 14l4-4" />
      <path d="M3.34 19a10 10 0 1 1 17.32 0" />
    </svg>
  );
}

function ArrowIcon({ up }: { up: boolean }) {
  return (
    <svg width="11.5" height="11.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {up ? <path d="M12 19V5M5 12l7-7 7 7" /> : <path d="M12 5v14M19 12l-7 7-7-7" />}
    </svg>
  );
}

function DatabaseIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <ellipse cx="12" cy="5" rx="9" ry="3" />
      <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
      <path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3" />
    </svg>
  );
}

function CalendarIcon() {
  return (
    <svg width="11.5" height="11.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.1" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="3" y="4" width="18" height="18" rx="2" />
      <path d="M16 2v4M8 2v4M3 10h18" />
    </svg>
  );
}

function SegmentedGauge({
  icon,
  label,
  valueText,
  unit,
  detailText,
  fraction,
  color,
}: {
  icon: ReactNode;
  label: string;
  valueText: string;
  unit?: string;
  detailText?: string;
  fraction: number;
  color: string;
}) {
  const clamped = clamp(fraction, 0, 1);
  const fillPct = clamped > 0 ? Math.max(clamped * 100, (TRAFFIC_SLIVER_RATIO / 18) * 100) : 0;
  const style = {
    "--mon-gauge-color": color,
    "--mon-gauge-fill": `${fillPct}%`,
  } as CSSProperties;

  return (
    <div
      className="monMetricItem"
      style={style}
      title={detailText ? `${label} ${valueText}${unit ?? ""} · ${detailText}` : `${label} ${valueText}${unit ?? ""}`}
    >
      <div className="monMetricHead">
        <span className="monMetricLabel">
          {icon}
          <span>{label}</span>
        </span>
        <span className="monMetricValue monTabular">
          <strong>{valueText}</strong>
          {unit && <small>{unit}</small>}
        </span>
      </div>
      <div className="monGaugeTrack" aria-hidden="true" />
    </div>
  );
}

export const MonitorServerCard = memo(function MonitorServerCard({
  card,
  active,
  onSelect,
}: {
  card: MonitorCardViewModel;
  active: boolean;
  onSelect: (id: string) => void;
}) {
  const { online, supported, sample } = card;
  const showTraffic = card.showTraffic !== false;

  const cpuPct = sample ? clamp(sample.cpu, 0, 100) : 0;
  const ramPct = sample ? usagePercent(sample.ramUsed, sample.ramTotal) : 0;
  const diskPct = sample ? usagePercent(sample.diskUsed, sample.diskTotal) : 0;
  const loadBaseline = card.cpuCores && card.cpuCores > 0 ? card.cpuCores : 4;
  const loadFraction = sample ? clamp(sample.load1 / loadBaseline, 0, 1) : 0;

  const expiry = formatServerExpiry(card.expiresAt);
  const expireVisual = resolveExpireVisual(card.expiresAt);

  const ct = showTraffic ? card.cycleTraffic : undefined;
  const cycleLimit = ct?.limit ?? 0;
  const cycleUsed = ct?.used ?? 0;
  const cycleType = ct?.type ?? "sum";
  const cycleFraction = cycleLimit > 0 ? clamp(cycleUsed / cycleLimit, 0, 1) : 0;
  const cyclePctRaw = cycleLimit > 0 ? (cycleUsed / cycleLimit) * 100 : 0;
  const cycleTone = cycleTrafficTone(cycleUsed, cycleLimit);
  const litCount = cycleLimit > 0 ? trafficQuotaLitCount(cycleFraction) : 0;
  const cycleRemain = cycleLimit > 0 ? Math.max(0, cycleLimit - cycleUsed) : 0;
  const cycleTypeLabel = trafficLimitTypeShortLabels[cycleType] || "上行+下行";
  const cycleRangeTitle = ct
    ? [
        `本周期（${cycleTypeLabel}）：${ct.startAt.slice(0, 10)} 至 ${ct.resetAt.slice(0, 10)}`,
        cycleLimit > 0
          ? `已用 ${cyclePctRaw.toFixed(0)}%，剩 ${formatBytes(cycleRemain)}`
          : "不限流量",
      ].join(" · ")
    : undefined;

  const subtitleText = [card.group, card.locationText].filter(Boolean).join(" · ");
  const expireBadge = expireVisual
    ? expireVisual.badgeText.replace(/^剩 (\d+) 天$/, "余 $1天")
    : "";
  const uptimeSeconds = online && sample ? sample.uptime : 0;
  const uptimeText =
    uptimeSeconds >= 86_400
      ? `${Math.floor(uptimeSeconds / 86_400)}天`
      : uptimeSeconds >= 3_600
        ? `${Math.floor(uptimeSeconds / 3_600)}小时`
        : uptimeSeconds > 0
          ? `${Math.max(1, Math.floor(uptimeSeconds / 60))}分钟`
          : "";

  const upRate = formatByteRate(sample?.netUp);
  const downRate = formatByteRate(sample?.netDown);
  const upSpeedColor = online ? speedRateColor(upRate.unit) : "var(--mon-text-tertiary)";
  const downSpeedColor = online ? speedRateColor(downRate.unit) : "var(--mon-text-tertiary)";

  return (
    <article
      className={`monitorCard${active ? " active" : ""}${!online ? " offline" : ""}`}
      onClick={() => onSelect(active ? "" : card.id)}
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.target !== e.currentTarget) return;
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect(active ? "" : card.id);
        }
      }}
    >
      <div className="monitorCardHead">
        <div className="monTitleBlock">
          <div className="monTitleRow">
            <span className="monitorFlag" aria-hidden="true">
              {countryFlag(card.country)}
            </span>
            <strong className="monServerName" title={card.name}>
              {card.name}
            </strong>
          </div>
          {(card.ipv4 || card.ipv6 || subtitleText || card.publicNote) && (
            <div className="monSubtitleRow">
              <IpStackBadges ipv4={card.ipv4} ipv6={card.ipv6} />
              {subtitleText && (
                <span className="monSubtitleChip" title={subtitleText}>
                  {subtitleText}
                </span>
              )}
              {card.publicNote && (
                <span className="monTagChip" title={card.publicNote}>
                  {card.publicNote}
                </span>
              )}
            </div>
          )}
        </div>

        <div className="monitorBadges">
          <OsLogo value={card.os} size={17} />
        </div>
      </div>

      {!supported ? (
        <div className="monitorUpgradeNotice">
          <p>{card.unsupportedMessage || "暂未启用实时主机监控。"}</p>
          {expiry && expireVisual && (
            <small className="monTabular" style={{ color: expireVisual.color }}>
              {expiry.fullText}
            </small>
          )}
        </div>
      ) : !sample ? (
        <div className="monitorUpgradeNotice">
          <p>{online ? "等待首次采样上报…" : "服务器当前离线，暂无内存实时样本"}</p>
          {expiry && expireVisual && (
            <small className="monTabular" style={{ color: expireVisual.color }}>
              {expiry.fullText}
            </small>
          )}
        </div>
      ) : (
        <div className="monCardStack">
          <div className="monMetricGrid">
            <SegmentedGauge
              icon={<CpuIcon />}
              label="CPU"
              valueText={cpuPct.toFixed(1)}
              unit="%"
              detailText={card.cpuCores ? `${card.cpuCores} 核` : `进程 ${sample.process}`}
              fraction={cpuPct / 100}
              color={metricGaugeColor("var(--mon-progress-cpu)", cpuPct)}
            />
            <SegmentedGauge
              icon={<MemoryIcon />}
              label="内存"
              valueText={ramPct.toFixed(0)}
              unit="%"
              detailText={`${formatBytes(sample.ramUsed)} / ${formatBytes(sample.ramTotal)}`}
              fraction={ramPct / 100}
              color={metricGaugeColor("var(--mon-progress-memory)", ramPct)}
            />
            <SegmentedGauge
              icon={<DiskIcon />}
              label="磁盘"
              valueText={diskPct.toFixed(0)}
              unit="%"
              detailText={`${formatBytes(sample.diskUsed)} / ${formatBytes(sample.diskTotal)}`}
              fraction={diskPct / 100}
              color={metricGaugeColor("var(--mon-progress-disk)", diskPct)}
            />
            <SegmentedGauge
              icon={<LoadIcon />}
              label="负载"
              valueText={sample.load1.toFixed(2)}
              detailText={`${sample.load5.toFixed(2)} / ${sample.load15.toFixed(2)}`}
              fraction={loadFraction}
              color={loadGaugeColor(sample.load1 / loadBaseline)}
            />
          </div>

          <div
            className="monInfoStrip"
            style={{ "--mon-info-cols": showTraffic ? 3 : 2 } as CSSProperties}
          >
            <div className="monInfoTile" title={`实时上行 ${upRate.value} ${upRate.unit} · 实时下行 ${downRate.value} ${downRate.unit}`}>
              <div className="monInfoRow">
                <span className="monInfoRowIcon monInfoUp">
                  <ArrowIcon up />
                </span>
                <strong className="monInfoRowValue monTabular" style={{ color: upSpeedColor }}>
                  {upRate.value}
                  <small>{upRate.unit}</small>
                </strong>
              </div>
              <div className="monInfoRow">
                <span className="monInfoRowIcon monInfoDown">
                  <ArrowIcon up={false} />
                </span>
                <strong className="monInfoRowValue monTabular" style={{ color: downSpeedColor }}>
                  {downRate.value}
                  <small>{downRate.unit}</small>
                </strong>
              </div>
            </div>

            {showTraffic && (
              <div
                className="monInfoTile"
                title={`出站累计 ${formatBytes(sample.netTotalUp)} · 入站累计 ${formatBytes(sample.netTotalDown)}`}
              >
                <div className="monInfoRow">
                  <span className="monInfoRowIcon monInfoUp">
                    <ArrowIcon up />
                  </span>
                  <strong className="monInfoRowValue monTabular">
                    {formatBytes(sample.netTotalUp)}
                  </strong>
                </div>
                <div className="monInfoRow">
                  <span className="monInfoRowIcon monInfoDown">
                    <ArrowIcon up={false} />
                  </span>
                  <strong className="monInfoRowValue monTabular">
                    {formatBytes(sample.netTotalDown)}
                  </strong>
                </div>
              </div>
            )}

            <div
              className="monInfoTile"
              title={expiry ? expiry.fullText : "未设置到期时间"}
            >
              <div className="monInfoRow">
                <span
                  className="monInfoRowIcon"
                  style={expireVisual ? { color: expireVisual.color } : undefined}
                >
                  <CalendarIcon />
                </span>
                <strong
                  className="monInfoRowValue monTabular"
                  data-muted={!expireVisual ? "true" : "false"}
                  style={expireVisual ? { color: expireVisual.color } : undefined}
                >
                  {expireVisual ? expireBadge : "长期"}
                </strong>
              </div>
              <div className="monInfoRow">
                <span className="monInfoRowLabel">到期</span>
                <span className="monInfoRowSub monTabular">
                  {expiry ? expiry.dateStr : "未设"}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {showTraffic && ct && (
        <div
          className={`monTraffic${uptimeText ? " has-uptime" : ""}`}
          data-tone={cycleTone || "normal"}
          title={cycleRangeTitle}
        >
          <span className="monTrafficLabel">
            <DatabaseIcon />
            <span>流量</span>
          </span>
          <div className="monQuotaTrack" aria-hidden="true">
            {TRAFFIC_QUOTA_SEGMENT_COLORS.map((segColor, i) => {
              const activeColor =
                cycleTone === "danger"
                  ? "var(--mon-status-error)"
                  : cycleTone === "warning"
                    ? "var(--mon-status-warning)"
                    : segColor;
              const bg =
                cycleLimit <= 0
                  ? "var(--mon-progress-bg)"
                  : litCount === -1 && i === 0
                    ? `linear-gradient(to right, ${activeColor} 0, ${activeColor} ${TRAFFIC_SLIVER_RATIO * 100}%, var(--mon-progress-bg) ${TRAFFIC_SLIVER_RATIO * 100}%, var(--mon-progress-bg) 100%)`
                    : cycleTone === "danger" || i < litCount
                      ? activeColor
                      : "var(--mon-progress-bg)";
              return <span key={i} className="monQuotaSegment" style={{ background: bg }} />;
            })}
          </div>
          {uptimeText && <span className="monTrafficUptime monTabular">在线：{uptimeText}</span>}
          <span
            className={`monTrafficValue monTabular${cycleTone === "danger" ? " is-danger" : cycleTone === "warning" ? " is-warning" : ""}`}
          >
            {formatBytes(cycleUsed)} / {cycleLimit > 0 ? formatBytes(cycleLimit) : "不限"}
          </span>
        </div>
      )}

      <PingHealthStrip buckets={card.ping} lines={card.pingLines} showPing={card.showPing} />
    </article>
  );
});
