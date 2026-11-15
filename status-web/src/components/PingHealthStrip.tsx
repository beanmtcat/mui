import { memo, useMemo, useState } from "react";
import { latencyHeatColor, lossHeatColor } from "../monitor/monitorTone";
import type { PublicPingBucket } from "../monitor/types";

// The reference theme shows 18 bars; the API may send up to 30 minute buckets.
const PING_SLOT_COUNT = 18;

function formatBucketTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "--:--";
  const hh = date.getHours().toString().padStart(2, "0");
  const mm = date.getMinutes().toString().padStart(2, "0");
  return `${hh}:${mm}`;
}

function formatLossPercent(loss: number): string {
  if (!Number.isFinite(loss) || loss <= 0) return "0%";
  if (loss >= 10) return `${Math.round(loss)}%`;
  const rounded = Math.round(loss * 10) / 10;
  return `${Number.isInteger(rounded) ? rounded.toFixed(0) : rounded.toFixed(1)}%`;
}

function LatencyClockIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.1"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </svg>
  );
}

function LossUnplugIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.1"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M19 5 5 19" />
      <path d="M12 22v-3" />
      <path d="M9 8V2" />
      <path d="M15 8V2" />
      <path d="M18 11v-1a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v1a5 5 0 0 0 10 0" />
    </svg>
  );
}

type HoverTarget = {
  side: "latency" | "loss";
  slotIndex: number;
};

export const PingHealthStrip = memo(function PingHealthStrip({
  buckets,
  showPing,
}: {
  buckets?: PublicPingBucket[];
  showPing?: boolean;
}) {
  const [hover, setHover] = useState<HoverTarget | null>(null);

  const model = useMemo(() => {
    if (!buckets || buckets.length === 0) return null;
    const recent = buckets.slice(-PING_SLOT_COUNT);
    const emptyLead = PING_SLOT_COUNT - recent.length;
    const slots: (PublicPingBucket | null)[] = Array.from(
      { length: PING_SLOT_COUNT },
      (_, idx) => (idx < emptyLead ? null : recent[idx - emptyLead]),
    );
    const latest = recent[recent.length - 1];
    const latestLoss = Math.max(0, Math.min(100, latest.loss));
    return {
      slots,
      latencyText: latest.ms >= 0 ? `${Math.round(latest.ms)} ms` : "超时",
      latencyColor:
        latest.ms >= 0 ? latencyHeatColor(latest.ms) : "var(--mon-latency-critical)",
      lossText: formatLossPercent(latestLoss),
      lossColor: lossHeatColor(latestLoss),
    };
  }, [buckets]);

  if (!showPing) {
    return null;
  }

  // No probe data yet: keep the row with empty bars so cards stay the same height.
  if (!model) {
    const emptyBars = Array.from({ length: PING_SLOT_COUNT }, (_, idx) => (
      <span key={idx} className="monPingBar" data-state="empty" aria-hidden="true" />
    ));
    return (
      <div className="monPingStrip">
        <div className="monPingBlock">
          <div className="monPingHead">
            <span className="monPingLabel">
              <LatencyClockIcon />
              <span>延迟</span>
            </span>
            <strong className="monPingValue monTabular" data-empty="true">—</strong>
          </div>
          <div className="monPingBars">{emptyBars}</div>
        </div>
        <div className="monPingBlock">
          <div className="monPingHead">
            <span className="monPingLabel">
              <LossUnplugIcon />
              <span>丢包</span>
            </span>
            <strong className="monPingValue monTabular" data-empty="true">—</strong>
          </div>
          <div className="monPingBars">{emptyBars}</div>
        </div>
      </div>
    );
  }

  const renderTooltip = (side: "latency" | "loss") => {
    if (!hover || hover.side !== side) return null;
    const bucket = model.slots[hover.slotIndex];
    if (!bucket) return null;
    const text = `${formatBucketTime(bucket.at)} · ${
      bucket.ms >= 0 ? `${Math.round(bucket.ms)} ms` : "超时"
    } · 丢包 ${formatLossPercent(bucket.loss)}`;
    const left = `clamp(58px, ${((hover.slotIndex + 0.5) / PING_SLOT_COUNT) * 100}%, calc(100% - 58px))`;
    return (
      <div className="monPingTooltip monTabular" role="status" style={{ left }}>
        {text}
      </div>
    );
  };

  return (
    <div className="monPingStrip" onMouseLeave={() => setHover(null)}>
      <div className="monPingBlock">
        {renderTooltip("latency")}
        <div className="monPingHead">
          <span className="monPingLabel">
            <LatencyClockIcon />
            <span>延迟</span>
          </span>
          <strong className="monPingValue monTabular" style={{ color: model.latencyColor }}>
            {model.latencyText}
          </strong>
        </div>
        <div className="monPingBars" aria-label="最近 18 分钟延迟">
          {model.slots.map((bucket, idx) => {
            if (!bucket) {
              return (
                <span
                  key={`lat-empty-${idx}`}
                  className="monPingBar"
                  data-state="empty"
                  aria-hidden="true"
                />
              );
            }
            const failed = bucket.ms < 0;
            const color = failed ? "var(--mon-latency-critical)" : latencyHeatColor(bucket.ms);
            const isHovered = hover?.slotIndex === idx;
            const isDimmed = hover !== null && !isHovered;
            return (
              <span
                key={`lat-${bucket.at}`}
                className="monPingBar"
                data-state={failed ? "failed" : "ok"}
                data-hovered={isHovered ? "true" : "false"}
                data-dimmed={isDimmed ? "true" : "false"}
                style={{ backgroundColor: color }}
                onMouseEnter={() => setHover({ side: "latency", slotIndex: idx })}
              />
            );
          })}
        </div>
      </div>

      <div className="monPingBlock">
        {renderTooltip("loss")}
        <div className="monPingHead">
          <span className="monPingLabel">
            <LossUnplugIcon />
            <span>丢包</span>
          </span>
          <strong className="monPingValue monTabular" style={{ color: model.lossColor }}>
            {model.lossText}
          </strong>
        </div>
        <div className="monPingBars" aria-label="最近 18 分钟丢包">
          {model.slots.map((bucket, idx) => {
            if (!bucket) {
              return (
                <span
                  key={`loss-empty-${idx}`}
                  className="monPingBar"
                  data-state="empty"
                  aria-hidden="true"
                />
              );
            }
            const failed = bucket.ms < 0;
            const color = failed ? "var(--mon-latency-critical)" : lossHeatColor(bucket.loss);
            const isHovered = hover?.slotIndex === idx;
            const isDimmed = hover !== null && !isHovered;
            return (
              <span
                key={`loss-${bucket.at}`}
                className="monPingBar"
                data-state={failed ? "failed" : "ok"}
                data-hovered={isHovered ? "true" : "false"}
                data-dimmed={isDimmed ? "true" : "false"}
                style={{ backgroundColor: color }}
                onMouseEnter={() => setHover({ side: "loss", slotIndex: idx })}
              />
            );
          })}
        </div>
      </div>
    </div>
  );
});
