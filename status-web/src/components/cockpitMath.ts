import type { PublicServerItem } from "../monitor/publicCard";
import { clamp } from "../monitor/monitorTone";

export const COCKPIT_DEFAULT_DIAL_CEILING = 10 * 1024 * 1024; // 10 MB/s baseline ceiling
export const COCKPIT_WING_POINTS = 60;

export type CockpitNodeState = "online" | "offline" | "unknown";

export type CockpitScaleMark = {
  position: "start" | "one-sixth" | "one-third" | "half" | "two-thirds" | "five-sixths" | "end";
  label: string;
};

const SCALE_STOPS: { position: CockpitScaleMark["position"]; ratio: number }[] = [
  { position: "start", ratio: 0 },
  { position: "one-sixth", ratio: 1 / 6 },
  { position: "one-third", ratio: 1 / 3 },
  { position: "half", ratio: 0.5 },
  { position: "two-thirds", ratio: 2 / 3 },
  { position: "five-sixths", ratio: 5 / 6 },
  { position: "end", ratio: 1 },
];

export function getAdaptiveDialCeiling(value: number, fallback: number): number {
  if (!Number.isFinite(value) || value <= 0) return fallback;
  const unitExponent = Math.max(0, Math.floor(Math.log(value) / Math.log(1024)));
  const unit = 1024 ** unitExponent;
  const target = value / unit / 0.85;
  const magnitude = 10 ** Math.floor(Math.log10(target));
  const normalized = target / magnitude;
  const multiplier =
    normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 2.5 ? 2.5 : normalized <= 5 ? 5 : 10;
  return Math.max(fallback, multiplier * magnitude * unit);
}

export function formatDialTick(bytesPerSec: number): string {
  if (!Number.isFinite(bytesPerSec) || bytesPerSec <= 0) return "0";
  const units = ["B", "K", "M", "G", "T"];
  let val = bytesPerSec;
  let idx = 0;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx += 1;
  }
  const rounded = val >= 10 || Number.isInteger(val) ? Math.round(val).toString() : val.toFixed(1);
  return `${rounded}${units[idx]}`;
}

export function buildDialScaleMarks(ceiling: number): CockpitScaleMark[] {
  return SCALE_STOPS.map(({ position, ratio }) => ({
    position,
    label: formatDialTick(ceiling * ratio),
  }));
}

export function getCockpitNodeStates(
  totalNodes: number,
  onlineNodes: number,
  offlineNodes: number,
): CockpitNodeState[] {
  const total = Math.max(0, totalNodes);
  if (total === 0) return [];
  const slots = total <= 30 ? total : 36;
  const onlineSlots =
    total <= 30
      ? Math.min(slots, onlineNodes)
      : Math.min(slots, Math.round((onlineNodes / total) * slots));
  const offlineSlots =
    total <= 30
      ? Math.min(slots - onlineSlots, offlineNodes)
      : Math.min(slots - onlineSlots, Math.round((offlineNodes / total) * slots));

  return Array.from({ length: slots }, (_, index) => {
    if (index < onlineSlots) return "online";
    if (index >= slots - offlineSlots) return "offline";
    return "unknown";
  });
}

export type CockpitRingMarker = {
  x: number;
  y: number;
  r: number;
  state: CockpitNodeState;
  delayMs: number;
};

export function buildRingMarkers(
  states: CockpitNodeState[],
  cx = 140,
  cy = 83,
  radius = 72,
): CockpitRingMarker[] {
  if (states.length === 0) return [];
  const startAngle = 150;
  const sweepAngle = 240;
  const count = states.length;
  const markerRadius = count <= 12 ? 3.5 : count <= 30 ? 2.5 : 2.1;
  return states.map((state, index) => {
    const progress = count === 1 ? 0.5 : index / (count - 1);
    const angle = ((startAngle + progress * sweepAngle) * Math.PI) / 180;
    return {
      x: cx + Math.cos(angle) * radius,
      y: cy + Math.sin(angle) * radius,
      r: markerRadius,
      state,
      delayMs: Math.min(index * 18, 420),
    };
  });
}

export type TelemetryGeometry = {
  linePath: string;
  areaPath: string;
  endX: number;
  endY: number;
  mean: number;
  peak: number;
};

export function resampleTelemetryY(
  rawValues: number[],
  height: number,
  count = COCKPIT_WING_POINTS,
): { ys: number[]; mean: number; peak: number } {
  const values =
    rawValues.length === 0 ? [0, 0] : rawValues.length === 1 ? [rawValues[0], rawValues[0]] : rawValues;

  let sum = 0;
  let peak = 0;
  const safeValues: number[] = new Array(values.length);
  for (let i = 0; i < values.length; i += 1) {
    const v = values[i];
    const safe = Number.isFinite(v) && v > 0 ? v : 0;
    safeValues[i] = safe;
    sum += safe;
    if (safe > peak) peak = safe;
  }
  const mean = sum / safeValues.length;

  const topPad = 4;
  const bottomPad = 3;
  const usableHeight = Math.max(4, height - topPad - bottomPad);
  const scaleMax = peak > 0 ? peak * 1.12 : 1;
  const n = Math.max(2, count);

  const sampled: number[] = new Array(n);
  for (let i = 0; i < n; i += 1) {
    const pos = (i / (n - 1)) * (safeValues.length - 1);
    const lo = Math.floor(pos);
    const hi = Math.min(safeValues.length - 1, Math.ceil(pos));
    const frac = pos - lo;
    sampled[i] = safeValues[lo] + (safeValues[hi] - safeValues[lo]) * frac;
  }

  // Snap each original sample onto its nearest grid slot with max-envelope so
  // single-point spikes are never attenuated when history is shorter than n.
  if (safeValues.length !== n) {
    for (let k = 0; k < safeValues.length; k += 1) {
      const slot = Math.round((k / (safeValues.length - 1)) * (n - 1));
      if (safeValues[k] > sampled[slot]) {
        sampled[slot] = safeValues[k];
      }
    }
  }

  const ys: number[] = new Array(n);
  for (let i = 0; i < n; i += 1) {
    const ratio = peak > 0 ? clamp(sampled[i] / scaleMax, 0, 1) : 0;
    ys[i] = height - bottomPad - ratio * usableHeight;
  }

  return { ys, mean, peak };
}

export function buildTelemetryPathsFromY(
  ys: number[],
  width: number,
  height: number,
): Pick<TelemetryGeometry, "linePath" | "areaPath" | "endX" | "endY"> {
  const safeYs = ys.length >= 2 ? ys : [height - 3, height - 3];
  const n = safeYs.length;
  const dx = width / (n - 1);
  const points = safeYs.map((y, idx) => ({
    x: idx * dx,
    y,
  }));

  // Fritsch-Butland monotone cubic Hermite tangents: the SVG curve passes
  // through every sample (including extrema) while staying within each
  // segment's [min(y_i, y_{i+1}), max(y_i, y_{i+1})] envelope.
  const secants: number[] = new Array(n - 1);
  for (let i = 0; i < n - 1; i += 1) {
    secants[i] = (points[i + 1].y - points[i].y) / dx;
  }
  const tangents: number[] = new Array(n);
  tangents[0] = secants[0];
  tangents[n - 1] = secants[n - 2];
  for (let i = 1; i < n - 1; i += 1) {
    const prevSlope = secants[i - 1];
    const nextSlope = secants[i];
    if (prevSlope * nextSlope <= 0) {
      tangents[i] = 0;
    } else {
      tangents[i] = (2 * prevSlope * nextSlope) / (prevSlope + nextSlope);
    }
  }

  let linePath = `M ${points[0].x.toFixed(1)},${points[0].y.toFixed(1)}`;
  for (let i = 0; i < n - 1; i += 1) {
    const p0 = points[i];
    const p1 = points[i + 1];
    const c1x = p0.x + dx / 3;
    const c1y = p0.y + (tangents[i] * dx) / 3;
    const c2x = p1.x - dx / 3;
    const c2y = p1.y - (tangents[i + 1] * dx) / 3;
    linePath += ` C ${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${p1.x.toFixed(1)},${p1.y.toFixed(1)}`;
  }

  const last = points[n - 1];
  const areaPath = `${linePath} L ${last.x.toFixed(1)},${height} L ${points[0].x.toFixed(1)},${height} Z`;

  return {
    linePath,
    areaPath,
    endX: last.x,
    endY: last.y,
  };
}

export function sampleTelemetryYAtProgress(
  ys: number[],
  progress: number,
  fallbackY: number,
): number {
  if (ys.length === 0) return fallbackY;
  if (ys.length === 1) return ys[0];
  const clamped = clamp(progress, 0, 1);
  const pos = clamped * (ys.length - 1);
  const lo = Math.floor(pos);
  const hi = Math.min(ys.length - 1, Math.ceil(pos));
  const frac = pos - lo;
  return ys[lo] + (ys[hi] - ys[lo]) * frac;
}

export function buildTelemetryPaths(
  rawValues: number[],
  width: number,
  height: number,
): TelemetryGeometry {
  const { ys, mean, peak } = resampleTelemetryY(rawValues, height);
  const paths = buildTelemetryPathsFromY(ys, width, height);
  return {
    ...paths,
    mean,
    peak,
  };
}

export type CockpitSummary = {
  totalNodes: number;
  onlineNodes: number;
  offlineNodes: number;
  netUp: number;
  netDown: number;
  totalUp: number;
  totalDown: number;
  hasTrafficTotals: boolean;
  cpuPct: number;
  cpuCores: number;
  ramUsed: number;
  ramTotal: number;
  diskUsed: number;
  diskTotal: number;
};

function finitePositive(n: number | undefined): number {
  return n !== undefined && Number.isFinite(n) && n > 0 ? n : 0;
}

export function summarizeCockpitResources(
  servers: PublicServerItem[],
  showTraffic: boolean,
): CockpitSummary {
  let onlineNodes = 0;
  let netUp = 0;
  let netDown = 0;
  let totalUp = 0;
  let totalDown = 0;
  let hasTrafficTotals = false;
  let cpuSum = 0;
  let cpuSamples = 0;
  let cpuCores = 0;
  let ramUsed = 0;
  let ramTotal = 0;
  let diskUsed = 0;
  let diskTotal = 0;

  for (const srv of servers) {
    const s = srv.sample;
    if (showTraffic && s && s.netTotalUp !== undefined && s.netTotalDown !== undefined) {
      totalUp += finitePositive(s.netTotalUp);
      totalDown += finitePositive(s.netTotalDown);
      hasTrafficTotals = true;
    }

    if (!srv.online) continue;
    onlineNodes += 1;
    cpuCores += finitePositive(srv.cpuCores);

    if (s) {
      netUp += finitePositive(s.netUp);
      netDown += finitePositive(s.netDown);
      cpuSum += clamp(s.cpu, 0, 100);
      cpuSamples += 1;
    }

    const rTotal = finitePositive(s?.ramTotal) || finitePositive(srv.memTotal);
    if (rTotal > 0) {
      ramTotal += rTotal;
      ramUsed += Math.min(rTotal, finitePositive(s?.ramUsed));
    }

    const dTotal = finitePositive(s?.diskTotal) || finitePositive(srv.diskTotal);
    if (dTotal > 0) {
      diskTotal += dTotal;
      diskUsed += Math.min(dTotal, finitePositive(s?.diskUsed));
    }
  }

  return {
    totalNodes: servers.length,
    onlineNodes,
    offlineNodes: Math.max(0, servers.length - onlineNodes),
    netUp,
    netDown,
    totalUp,
    totalDown,
    hasTrafficTotals,
    cpuPct: cpuSamples > 0 ? cpuSum / cpuSamples : 0,
    cpuCores,
    ramUsed,
    ramTotal,
    diskUsed,
    diskTotal,
  };
}
