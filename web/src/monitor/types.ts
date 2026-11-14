// Counterpart in status-web/src/monitor/types.ts — keep shared monitor view types in sync.

export type MonitorRange = "1h" | "6h" | "24h" | "7d" | "30d";

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
  rx?: number;
  tx?: number;
};

export type MonitorCardViewModel = {
  id: string;
  name: string;
  country: string;
  locationText: string;
  stackLabel?: string;
  online: boolean;
  supported: boolean;
  unsupportedBadge?: string;
  unsupportedMessage?: string;
  hostLine?: string;
  cpuCores?: number;
  sample?: MonitorCardSample;
  showTraffic?: boolean;
  cycleTraffic?: MonitorCardCycleTraffic;
  trafficLimitThreshold?: number;
  expiresAt?: string;
  expireAutoRenewHint?: boolean;
  priceLabel?: string;
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
