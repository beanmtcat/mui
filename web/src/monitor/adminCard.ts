import type { MonitorOverviewItem, Server } from "../api";
import { formatBillingCycle } from "../app/helpers";
import type { MonitorCardViewModel } from "./types";

export function buildAdminMonitorCard(
  srv: Server,
  item: MonitorOverviewItem | undefined,
  trafficLimitThreshold: number,
  redact: (v: string) => string,
): MonitorCardViewModel {
  const online = item?.online ?? srv.status === "online";
  const supported = item?.hostMonitor ?? !!srv.hostMonitor;
  const sample = item?.sample;
  const host = item?.host;
  const loc = [srv.region, srv.city].filter(Boolean).join(" · ") || srv.country;
  const stackLabel =
    srv.ipv4 && srv.ipv6 ? "双栈" : srv.ipv6 ? "IPv6" : srv.ipv4 ? "IPv4" : undefined;
  const hostLine = host
    ? [host.cpuName, host.cpuCores ? `${host.cpuCores} 核` : "", host.os, host.virtualization]
        .filter(Boolean)
        .join(" · ")
    : "";
  const priceLabel = [
    srv.price && srv.price > 0
      ? `${(srv.currency || "$").trim() || "$"}${/^[A-Za-z]+$/.test((srv.currency || "$").trim()) ? " " : ""}${srv.price.toFixed(2)}`
      : "",
    formatBillingCycle(srv),
  ]
    .filter(Boolean)
    .join(" / ");
  const ct = item?.cycleTraffic ?? srv.cycleTraffic;
  return {
    id: srv.id,
    name: redact(srv.name),
    country: srv.country,
    locationText: loc ? redact(loc) : "",
    stackLabel,
    online,
    supported,
    unsupportedBadge: "需升级 Agent",
    unsupportedMessage: "升级至 Agent 0.6.31 或更高版本后自动上报主机监控指标。",
    hostLine: hostLine || undefined,
    cpuCores: host?.cpuCores,
    sample,
    showTraffic: true,
    cycleTraffic: {
      startAt: ct?.startAt ?? "",
      resetAt: ct?.resetAt ?? "",
      used: ct?.used ?? 0,
      limit: ct?.limit ?? srv.trafficLimit ?? 0,
      type: ct?.type ?? srv.trafficLimitType ?? "sum",
      rx: ct?.rx ?? 0,
      tx: ct?.tx ?? 0,
    },
    trafficLimitThreshold,
    expiresAt: srv.expiresAt,
    expireAutoRenewHint: Boolean(srv.autoRenew && srv.billingCycle),
    priceLabel: priceLabel || undefined,
  };
}
