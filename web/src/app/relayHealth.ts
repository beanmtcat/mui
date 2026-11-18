import type { RelayAutoState, RelayReport } from "../api";

export const relayStatusLabels: Record<RelayAutoState, string> = { normal: "正常", degraded: "降级", down: "故障", probation: "试跑" };

export const relayReasons: Record<RelayReport["reason"], string> = {
  healthy: "TCP 建连正常",
  probe_failed: "TCP 探测失败",
  dial_failed: "实际建连失败",
  manual: "已应用手动覆盖",
  slow_handshake: "TCP 建连变慢",
  probe_loss: "探测失败偏多",
  blackhole: "上游多次未响应",
  recovering: "观察期结束",
  downstream_down: "下游不可用",
};

export function relayAutoDescription(report: RelayReport) {
  const reason = report.autoReason || report.reason;
  return relayStatusLabels[report.autoState] + (reason === "manual" ? "" : ` · ${relayReasons[reason]}`);
}

export function relayStatsDescription(report: RelayReport) {
  const stats = report.stats;
  if (!stats) return "";
  return [
    `最近 1 分钟探测成功 ${stats.probeSuccesses} 次`,
    `建连中位数 ${stats.probeSuccesses ? stats.medianMs + " ms" : "暂无"}，基线 ${stats.baselineMs ? stats.baselineMs + " ms" : "暂无"}`,
    `被动观测 ${stats.passiveSamples} 个来源${stats.passiveSamples ? `，失败比例 ${stats.passiveBadPercent}%` : ""}`,
  ].join(" · ");
}

export const relaySeverity: Record<RelayAutoState, number> = { normal: 0, probation: 1, degraded: 2, down: 3 };
