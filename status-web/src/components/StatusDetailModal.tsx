import { useEffect } from "react";
import { countryFlag, formatBytes, formatMonitorUptime, formatServerExpiry } from "../monitor/format";
import { resolveExpireVisual } from "../monitor/monitorTone";
import { MonitorMetricsCharts, PingCombinedChart } from "../monitor/MonitorCharts";
import type { PublicPingTaskSeries, PublicServerItem } from "../monitor/publicCard";
import type { MonitorRange, SharedMonitorRecord } from "../monitor/types";

const PUBLIC_RANGES: { id: MonitorRange; label: string }[] = [
  { id: "1h", label: "1 小时" },
  { id: "6h", label: "6 小时" },
  { id: "24h", label: "24 小时" },
  { id: "7d", label: "7 天" },
];

export function StatusDetailModal({
  server,
  range,
  onRangeChange,
  onClose,
  loadingDetail,
  records,
  showPing,
  pings,
}: {
  server: PublicServerItem;
  range: MonitorRange;
  onRangeChange: (next: MonitorRange) => void;
  onClose: () => void;
  loadingDetail: boolean;
  records: SharedMonitorRecord[];
  showPing: boolean;
  pings: PublicPingTaskSeries[];
}) {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
      }
    };
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = prevOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [onClose]);

  const hardwareSummary = [
    server.cpuName && `${server.cpuName}${server.cpuCores ? ` · ${server.cpuCores} 核` : ""}`,
    !server.cpuName && server.cpuCores ? `${server.cpuCores} 核` : "",
    server.os && `${server.os}${server.arch ? ` (${server.arch})` : ""}`,
    server.virtualization || "",
    server.memTotal ? `内存 ${formatBytes(server.memTotal)}` : "",
    server.swapTotal ? `Swap ${formatBytes(server.swapTotal)}` : "",
    server.diskTotal ? `磁盘 ${formatBytes(server.diskTotal)}` : "",
  ]
    .filter(Boolean)
    .join(" · ");

  const expiry = formatServerExpiry(server.expiresAt);
  const expireVisual = resolveExpireVisual(server.expiresAt);
  const sample = server.sample;

  return (
    <div
      className="statusModalBackdrop"
      role="presentation"
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          onClose();
        }
      }}
    >
      <section
        className="statusModalPanel"
        role="dialog"
        aria-modal="true"
        aria-label={`${server.name} 历史监控曲线`}
      >
        <header className="statusModalHead">
          <div className="statusModalTitle">
            <h2>
              {countryFlag(server.country)} {server.name} · 历史曲线
            </h2>
            {hardwareSummary && <p className="statusModalMeta">{hardwareSummary}</p>}
            {(sample || expiry || server.publicNote) && (
              <div className="statusModalRuntime monTabular">
                {sample && (
                  <>
                    <span className="statusModalPill" data-tone={server.online ? "online" : "muted"}>
                      开机时长 {formatMonitorUptime(sample.uptime)}
                    </span>
                    <span className="statusModalPill">
                      活跃连接 {sample.tcp} TCP / {sample.udp} UDP
                    </span>
                    <span className="statusModalPill">进程 {sample.process}</span>
                  </>
                )}
                {expiry && expireVisual && (
                  <span
                    className="statusModalPill"
                    style={{ color: expireVisual.color }}
                    title={expiry.fullText}
                  >
                    {expiry.fullText}
                  </span>
                )}
                {server.publicNote && (
                  <span className="statusModalPill" title={server.publicNote}>
                    {server.publicNote}
                  </span>
                )}
              </div>
            )}
          </div>

          <div className="statusModalControls">
            <div className="monitorRangeTabs" role="tablist" aria-label="监控时间范围">
              {PUBLIC_RANGES.map((r) => (
                <button
                  key={r.id}
                  type="button"
                  role="tab"
                  aria-selected={range === r.id}
                  className={range === r.id ? "active" : ""}
                  onClick={() => onRangeChange(r.id)}
                >
                  {r.label}
                </button>
              ))}
            </div>
            <button
              type="button"
              className="statusModalClose"
              onClick={onClose}
              aria-label="关闭详情"
              title="关闭 (Esc)"
            >
              ×
            </button>
          </div>
        </header>

        <div className="statusModalBody">
          {loadingDetail && records.length === 0 ? (
            <p className="statusEmpty">正在加载历史记录…</p>
          ) : (
            <>
              <MonitorMetricsCharts records={records} range={range} />
              {showPing && pings.length > 0 && (
                <div className="monitorPingChartsSection">
                  <h3>延迟监测曲线</h3>
                  <div className="monitorChartsGrid">
                    <PingCombinedChart tasks={pings} range={range} />
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </section>
    </div>
  );
}
