// Counterpart in web/src/monitor/types.ts — keep monitor view types in sync (admin-only fields omitted here).

export type MonitorRange = "1h" | "6h" | "24h" | "7d";

export type SharedTrafficLimitType = "sum" | "up" | "down" | "max" | "min";

export type MonitorCardSample = {
  at: string;
  cpu: number;
  load1: number;
  load5: number;
  load15: number;
  ramUsed: number;
  ramTotal: number;
  swapUsed: number;
  swapTotal: number;
  diskUsed: number;
  diskTotal: number;
  netUp: number;
  netDown: number;
  netTotalUp?: number;
  netTotalDown?: number;
  tcp: number;
  udp: number;
  process: number;
  uptime: number;
};

export type MonitorCardCycleTraffic = {
  startAt: string;
  resetAt: string;
  used: number;
  limit: number;
  type: SharedTrafficLimitType;
};

export type PublicPingBucket = {
  at: string;
  ms: number;
  loss: number;
};

export type MonitorCardViewModel = {
  id: string;
  name: string;
  group?: string;
  country: string;
  locationText: string;
  online: boolean;
  supported: boolean;
  unsupportedMessage?: string;
  hostLine?: string;
  os?: string;
  ipv4?: boolean;
  ipv6?: boolean;
  cpuCores?: number;
  sample?: MonitorCardSample;
  showTraffic?: boolean;
  showPing?: boolean;
  cycleTraffic?: MonitorCardCycleTraffic;
  ping?: PublicPingBucket[];
  expiresAt?: string;
  publicNote?: string;
};

export type SharedMonitorRecord = {
  at: string;
  cpu: number;
  load1: number;
  ramUsed: number;
  ramTotal: number;
  swapUsed: number;
  diskUsed: number;
  diskTotal: number;
  netUp: number;
  netDown: number;
  netUpPeak: number;
  netDownPeak: number;
  totalUp?: number;
  totalDown?: number;
  tcp: number;
  udp: number;
  process: number;
};

export type SharedPingPoint = {
  at: string;
  msAvg: number;
  msMax: number;
  sent: number;
  lost: number;
};
