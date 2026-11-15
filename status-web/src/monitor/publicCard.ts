import type {
  MonitorCardSample,
  MonitorCardViewModel,
  PublicPingBucket,
  PublicPingLine,
  SharedPingPoint,
  SharedTrafficLimitType,
} from "./types";

export type PublicCycleTraffic = {
  startAt: string;
  resetAt: string;
  used: number;
  limit: number;
  type: SharedTrafficLimitType;
};

export type PublicServerItem = {
  id: string;
  name: string;
  group: string;
  country: string;
  region?: string;
  city?: string;
  online: boolean;
  hostMonitor: boolean;
  ipv4: boolean;
  ipv6: boolean;
  os?: string;
  arch?: string;
  virtualization?: string;
  cpuName?: string;
  cpuCores?: number;
  memTotal?: number;
  swapTotal?: number;
  diskTotal?: number;
  sample?: MonitorCardSample;
  cycleTraffic?: PublicCycleTraffic;
  ping?: PublicPingBucket[];
  pingLines?: PublicPingLine[];
  expiresAt?: string;
  publicNote?: string;
};

export type PublicStatusResponse = {
  title: string;
  description: string;
  showTraffic: boolean;
  showPing: boolean;
  generatedAt: string;
  servers: PublicServerItem[];
};

export type PublicPingTaskSeries = {
  id: string;
  name: string;
  intervalSeconds: number;
  records: SharedPingPoint[];
};

export function toPublicCardViewModel(
  srv: PublicServerItem,
  showTraffic: boolean,
  showPing = true,
): MonitorCardViewModel {
  const loc = [srv.region, srv.city].filter(Boolean).join(" · ") || srv.country;
  const hostLine = [
    srv.cpuName,
    srv.cpuCores ? `${srv.cpuCores} 核` : "",
    srv.os,
    srv.virtualization,
  ]
    .filter(Boolean)
    .join(" · ");

  return {
    id: srv.id,
    name: srv.name,
    group: srv.group?.trim() || undefined,
    country: srv.country,
    locationText: loc,
    online: srv.online,
    supported: srv.hostMonitor,
    unsupportedMessage: "暂未启用实时采集。",
    hostLine: hostLine || undefined,
    os: srv.os,
    ipv4: srv.ipv4,
    ipv6: srv.ipv6,
    cpuCores: srv.cpuCores,
    sample: srv.sample,
    showTraffic,
    showPing,
    cycleTraffic: showTraffic && srv.cycleTraffic ? srv.cycleTraffic : undefined,
    ping: showPing && srv.ping && srv.ping.length > 0 ? srv.ping : undefined,
    pingLines:
      showPing && Array.isArray(srv.pingLines) && srv.pingLines.length > 1
        ? srv.pingLines.filter((line) => line && Array.isArray(line.buckets))
        : undefined,
    expiresAt: srv.expiresAt,
    publicNote: srv.publicNote,
  };
}
