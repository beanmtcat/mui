import { countryFlag, formatBytes } from "../monitor/format";
import { MonitorMetricsCharts, PingTaskChart } from "../monitor/MonitorCharts";
import type { PublicPingTaskSeries, PublicServerItem } from "../monitor/publicCard";
import type { MonitorRange, SharedMonitorRecord } from "../monitor/types";

const PUBLIC_RANGES: { id: MonitorRange; label: string }[] = [
  { id: "1h", label: "1 小时" },
  { id: "6h", label: "6 小时" },
  { id: "24h", label: "24 小时" },
  { id: "7d", label: "7 天" },
];

export function StatusDetailPanel({
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
  return (
    <section className="statusSurface statusDetailPanel">
      <div className="statusDetailHead">
        <div className="statusDetailTitle">
          <h2>
            {countryFlag(server.country)} {server.name} · 历史曲线
          </h2>
          <p className="statusDetailMeta">
            {[
              server.cpuName &&
                `${server.cpuName}${server.cpuCores ? `（${server.cpuCores} 核）` : ""}`,
              server.os &&
                `${server.os}${server.arch ? ` (${server.arch})` : ""}`,
              server.virtualization && `虚拟化 ${server.virtualization}`,
              server.memTotal ? `内存 ${formatBytes(server.memTotal)}` : "",
              server.diskTotal ? `磁盘 ${formatBytes(server.diskTotal)}` : "",
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
                onClick={() => onRangeChange(r.id)}
              >
                {r.label}
              </button>
            ))}
          </div>
          <button
            type="button"
            className="statusCloseBtn"
            onClick={onClose}
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
            {showPing && pings.length > 0 && (
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
  );
}
