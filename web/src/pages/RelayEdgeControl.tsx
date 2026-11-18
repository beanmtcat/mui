import type { RelayEdge, RelayAutoState } from "../api";
import { useApp } from "../app/context";
import { relayAutoDescription, relayStatsDescription, relayStatusLabels } from "../app/relayHealth";

export const relayTones: Record<RelayAutoState, string> = { normal: "good", degraded: "warn", down: "bad", probation: "warn" };

export default function RelayEdgeControl({ edge, from, to, routeId, latency, style, tone }: {
  edge?: RelayEdge; from: string; to: string; routeId: string; latency: string; style: React.CSSProperties; tone: string;
}) {
  const { openModal, protect, serverName } = useApp();
  const override = edge?.override, reported = edge?.reported;
  const availability = edge?.availability === "upgrade" ? "需升级到 0.6.32 才生效" : edge?.availability === "offline" ? "上一跳为离线管理" : "";
  const applied = override && reported?.source === "manual" && reported.state === override.state;
  const automaticDown = override?.state === "normal" && reported?.autoState === "down";
  const pending = Boolean(override && !applied && !automaticDown);
  let state = reported ? relayStatusLabels[reported.state] : "";
  if (reported?.source === "manual") state = "手动" + state;
  if (applied) state += override.until
    ? ` · 至 ${new Date(override.until).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", hour12: false })}`
    : " · 永久";
  const shown = pending && override ? `手动${relayStatusLabels[override.state]}（待应用）`
    : !reported || reported.source === "auto" && reported.state === "normal" ? latency : state;
  const label = [
    `${serverName(from)} → ${serverName(to)}`, `延迟 ${latency}`,
    reported ? `生效 ${state}，自动 ${relayAutoDescription(reported)}` : "状态待上报",
    override && `${override.fromServerId ? "线路" : "服务器"}设置 ${relayStatusLabels[override.state]} · ${override.until ? new Date(override.until).toLocaleString() + " 到期" : "永久"}`,
    override && !applied && (automaticDown ? "自动故障仍生效" : "手动设置待应用"),
    !override && reported?.source === "manual" && "手动设置待清除", override?.note, availability,
    edge?.downstreamFlapping && "状态抖动，暂时保持当前状态",
    reported && relayStatsDescription(reported),
  ].filter(Boolean).join("\n");
  return protect(<button type="button" className={`routeFanLabel relayEdgeButton tone-${reported ? relayTones[reported.state] : tone}${pending ? " relayEdgePending" : ""}`} style={style}
    title={label} aria-label={label} onClick={() => openModal({ kind: "relay", from, to, routeId })}>
    {shown}{edge?.downstreamFlapping && <span className="relayEdgeFlapping" aria-hidden="true"> · 抖动</span>}
  </button>);
}
