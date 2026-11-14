// Counterpart in status-web/src/monitor/monitorTone.ts — keep shared tone & gauge helpers in sync.
// Adapted from Komari-Theme-LuminaPlus (Misaka Drive, src/utils/metricTone.ts,
// src/utils/expireStatus.ts, src/components/node/nodeCardShared.ts), Apache-2.0.

export const TRAFFIC_QUOTA_SEGMENTS = 18;
export const TRAFFIC_SLIVER_RATIO = 0.12;

export function clamp(value: number, min: number, max: number) {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, value));
}

function toHsl(h: number, s: number, l: number) {
  return `hsl(${h.toFixed(1)} ${s.toFixed(1)}% ${l.toFixed(1)}%)`;
}

// High-occupancy metric tone ramp: keeps each metric's signature color below 75%,
// shifts to amber/orange across 75%-90%, and turns critical red at >= 90%.
export function metricGaugeColor(baseToken: string, pct: number): string {
  const p = clamp(pct, 0, 100);
  if (p >= 90) return "var(--mon-status-error)";
  if (p >= 75) {
    const t = clamp((p - 75) / 15, 0, 1);
    return toHsl(38 - 26 * t, 84 + 2 * t, 50 - 3 * t);
  }
  return baseToken;
}

export function loadGaugeColor(fraction: number): string {
  const f = clamp(fraction, 0, 2);
  if (f >= 1) return "var(--mon-status-error)";
  if (f >= 0.8) return "var(--mon-status-warning)";
  return "var(--mon-progress-load)";
}

export type ByteRateDisplay = {
  value: string;
  unit: "B/s" | "KB/s" | "MB/s" | "GB/s" | "TB/s";
};

const RATE_UNITS: ByteRateDisplay["unit"][] = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];

export function formatByteRate(bytesPerSec: number | undefined): ByteRateDisplay {
  const safe = bytesPerSec && Number.isFinite(bytesPerSec) && bytesPerSec > 0 ? bytesPerSec : 0;
  if (safe < 1024) {
    return { value: Math.round(safe).toString(), unit: "B/s" };
  }
  let val = safe;
  let idx = 0;
  while (val >= 1024 && idx < RATE_UNITS.length - 1) {
    val /= 1024;
    idx += 1;
  }
  const decimals = val >= 100 ? 0 : val >= 10 ? 1 : 2;
  return { value: val.toFixed(decimals), unit: RATE_UNITS[idx] };
}

export function speedRateColor(unit: ByteRateDisplay["unit"] | string): string {
  switch (unit) {
    case "B/s":
      return "var(--mon-speed-idle)";
    case "KB/s":
      return "var(--mon-speed-low)";
    case "MB/s":
      return "var(--mon-speed-high)";
    case "GB/s":
    case "TB/s":
      return "var(--mon-speed-max)";
    default:
      return "var(--mon-text-tertiary)";
  }
}

export function latencyHeatColor(ms: number | null | undefined): string {
  if (ms == null || !Number.isFinite(ms) || ms < 0) {
    return "var(--mon-text-tertiary)";
  }
  if (ms <= 60) return "var(--mon-latency-excellent)";
  if (ms <= 100) return "var(--mon-latency-good)";
  if (ms <= 160) return "var(--mon-latency-moderate)";
  if (ms <= 200) return "var(--mon-latency-elevated)";
  return "var(--mon-latency-critical)";
}

const TRAFFIC_QUOTA_STOPS = [
  { pos: 0, h: 150, s: 58, l: 45 },
  { pos: 0.1, h: 150, s: 58, l: 45 },
  { pos: 0.28, h: 98, s: 64, l: 47 },
  { pos: 0.44, h: 66, s: 74, l: 47 },
  { pos: 0.58, h: 45, s: 84, l: 50 },
  { pos: 0.72, h: 30, s: 84, l: 52 },
  { pos: 0.86, h: 16, s: 82, l: 51 },
  { pos: 1, h: 4, s: 78, l: 50 },
];

export function trafficQuotaSegmentColor(pos: number): string {
  const p = clamp(pos, 0, 1);
  for (let i = 0; i < TRAFFIC_QUOTA_STOPS.length - 1; i += 1) {
    const a = TRAFFIC_QUOTA_STOPS[i];
    const b = TRAFFIC_QUOTA_STOPS[i + 1];
    if (p >= a.pos && p <= b.pos) {
      const t = b.pos === a.pos ? 0 : (p - a.pos) / (b.pos - a.pos);
      return toHsl(a.h + (b.h - a.h) * t, a.s + (b.s - a.s) * t, a.l + (b.l - a.l) * t);
    }
  }
  return toHsl(4, 78, 50);
}

export const TRAFFIC_QUOTA_SEGMENT_COLORS = Array.from(
  { length: TRAFFIC_QUOTA_SEGMENTS },
  (_, i) => trafficQuotaSegmentColor((i + 0.5) / TRAFFIC_QUOTA_SEGMENTS),
);

export function trafficQuotaLitCount(fraction: number): number {
  const f = clamp(fraction, 0, 1);
  let count = 0;
  for (let i = 0; i < TRAFFIC_QUOTA_SEGMENTS; i += 1) {
    if ((i + 0.5) / TRAFFIC_QUOTA_SEGMENTS <= f) count += 1;
    else break;
  }
  if (count === 0 && f > 0) return -1;
  return count;
}

export type ExpireVisual = {
  daysRemaining: number;
  tone: "critical" | "warning" | "normal";
  color: string;
  badgeText: string;
};

export function resolveExpireVisual(expiresAt: string | undefined, autoRenew?: boolean): ExpireVisual | null {
  if (!expiresAt) return null;
  const exp = new Date(expiresAt);
  if (Number.isNaN(exp.getTime())) return null;
  const diffMs = exp.getTime() - Date.now();
  if (diffMs <= 0) {
    const daysAgo = Math.floor(-diffMs / 86_400_000);
    return {
      daysRemaining: -daysAgo,
      tone: "critical",
      color: "var(--mon-ink-error)",
      badgeText: daysAgo > 0 ? `已过期 ${daysAgo} 天` : "已过期",
    };
  }
  const days = Math.max(1, Math.ceil(diffMs / 86_400_000));
  if (days <= 3) {
    return {
      daysRemaining: days,
      tone: "critical",
      color: "var(--mon-ink-error)",
      badgeText: `剩 ${days} 天`,
    };
  }
  if (days <= 7) {
    return {
      daysRemaining: days,
      tone: "warning",
      color: "var(--mon-ink-warning)",
      badgeText: autoRenew ? `剩 ${days} 天 · 待续期` : `剩 ${days} 天`,
    };
  }
  if (days <= 30) {
    return {
      daysRemaining: days,
      tone: "normal",
      color: "color-mix(in srgb, var(--mon-ink-warning) 62%, var(--mon-ink-success) 38%)",
      badgeText: `剩 ${days} 天`,
    };
  }
  return {
    daysRemaining: days,
    tone: "normal",
    color: "var(--mon-ink-success)",
    badgeText: `剩 ${days} 天`,
  };
}
