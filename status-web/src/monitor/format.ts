// Counterpart in web/src/monitor/format.ts — keep formatting helpers in sync.

import type { SharedTrafficLimitType } from "./types";

export const UNGROUPED_LABEL = "未分组";
export const UNGROUPED_FILTER = "__ungrouped__";

export const trafficLimitTypeShortLabels: Record<SharedTrafficLimitType, string> = {
  sum: "上行+下行",
  up: "仅上行",
  down: "仅下行",
  max: "较大方向",
  min: "较小方向",
};

export function formatBytes(v: number | undefined): string {
  if (v === undefined || !Number.isFinite(v)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let val = Math.max(0, v);
  let i = 0;
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024;
    i += 1;
  }
  return `${val.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function formatMonitorUptime(seconds: number | undefined): string {
  if (!seconds || seconds <= 0) return "—";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days} 天 ${hours} 小时`;
  if (hours > 0) return `${hours} 小时 ${mins} 分钟`;
  return `${Math.max(1, mins)} 分钟`;
}

export function countryFlag(country: string): string {
  const code = (country || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return "";
  return String.fromCodePoint(
    ...Array.from(code, (letter) => 0x1f1e6 + letter.charCodeAt(0) - 65),
  );
}

export function formatServerExpiry(expiresAt: string | undefined): {
  dateStr: string;
  remainText: string;
  fullText: string;
  tone: "neutral" | "warn" | "bad";
} | null {
  if (!expiresAt) return null;
  const exp = new Date(expiresAt);
  if (Number.isNaN(exp.getTime())) return null;
  const dateStr = expiresAt.slice(0, 10);
  const diffMs = exp.getTime() - Date.now();
  if (diffMs <= 0) {
    const daysAgo = Math.floor(-diffMs / 86400000);
    const remainText = daysAgo > 0 ? `已过期 ${daysAgo} 天` : "已过期";
    return {
      dateStr,
      remainText,
      fullText: `${dateStr} · ${remainText}`,
      tone: "bad",
    };
  }
  const remainDays = Math.max(1, Math.ceil(diffMs / 86400000));
  const remainText = `剩 ${remainDays} 天`;
  return {
    dateStr,
    remainText,
    fullText: `到期 ${dateStr} · ${remainText}`,
    tone: diffMs <= 7 * 86400000 ? "warn" : "neutral",
  };
}

export function cycleTrafficTone(used: number, limit: number): "" | "warning" | "danger" {
  if (limit <= 0) return "";
  const pct = (used / limit) * 100;
  if (pct >= 100) return "danger";
  if (pct >= 80) return "warning";
  return "";
}
