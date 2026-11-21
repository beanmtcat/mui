import { useEffect, useMemo, useRef, useState } from "react";
import {
  buildTelemetryPathsFromY,
  COCKPIT_WING_POINTS,
  getAdaptiveDialCeiling,
  resampleTelemetryY,
  sampleTelemetryYAtProgress,
  type TelemetryGeometry,
} from "../components/cockpitMath";

export function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() =>
    typeof window !== "undefined" && typeof window.matchMedia === "function"
      ? window.matchMedia("(prefers-reduced-motion: reduce)").matches
      : false,
  );

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReduced(mq.matches);
    update();
    mq.addEventListener("change", update);
    return () => mq.removeEventListener("change", update);
  }, []);

  return reduced;
}

export function useAnimatedMetricValue(
  target: number,
  durationMs = 680,
  reducedMotion = false,
): { value: number; animating: boolean } {
  const [display, setDisplay] = useState(target);
  const [animating, setAnimating] = useState(false);
  const currentRef = useRef(target);

  useEffect(() => {
    if (!Number.isFinite(target)) return;
    if (reducedMotion || durationMs <= 0) {
      currentRef.current = target;
      setDisplay(target);
      setAnimating(false);
      return;
    }

    const startVal = currentRef.current;
    if (Math.abs(target - startVal) < 0.01) {
      currentRef.current = target;
      setDisplay(target);
      setAnimating(false);
      return;
    }

    let rafId = 0;
    const startTime = performance.now();
    setAnimating(true);

    const step = (now: number) => {
      const elapsed = now - startTime;
      const t = Math.min(1, elapsed / durationMs);
      const eased = 1 - (1 - t) ** 3;
      const next = startVal + (target - startVal) * eased;
      currentRef.current = next;
      setDisplay(next);
      if (t < 1) {
        rafId = window.requestAnimationFrame(step);
      } else {
        currentRef.current = target;
        setDisplay(target);
        setAnimating(false);
      }
    };

    rafId = window.requestAnimationFrame(step);
    return () => window.cancelAnimationFrame(rafId);
  }, [target, durationMs, reducedMotion]);

  return { value: display, animating };
}

const DIAL_DOWNSHIFT_HOLD_MS = 60_000;

export function useStableDialCeiling(rawValue: number, fallback: number): number {
  const [ceiling, setCeiling] = useState(() => getAdaptiveDialCeiling(rawValue, fallback));
  const belowSinceRef = useRef<number | null>(null);

  useEffect(() => {
    const candidate = getAdaptiveDialCeiling(rawValue, fallback);
    if (candidate > ceiling) {
      belowSinceRef.current = null;
      setCeiling(candidate);
      return;
    }
    if (candidate < ceiling) {
      const now = Date.now();
      if (belowSinceRef.current === null) {
        belowSinceRef.current = now;
        return;
      }
      if (now - belowSinceRef.current >= DIAL_DOWNSHIFT_HOLD_MS) {
        belowSinceRef.current = null;
        setCeiling(candidate);
      }
      return;
    }
    belowSinceRef.current = null;
  }, [rawValue, fallback, ceiling]);

  return ceiling;
}

export function useTelemetryHistory(
  upRate: number,
  downRate: number,
  sampleKey: string,
  hasData: boolean,
): { upSamples: number[]; downSamples: number[] } {
  const [series, setSeries] = useState<{ up: number[]; down: number[] }>({
    up: [],
    down: [],
  });
  const lastKeyRef = useRef("");

  useEffect(() => {
    if (!hasData || !sampleKey) return;
    if (lastKeyRef.current === sampleKey) return;
    lastKeyRef.current = sampleKey;

    const safeUp = Number.isFinite(upRate) && upRate > 0 ? upRate : 0;
    const safeDown = Number.isFinite(downRate) && downRate > 0 ? downRate : 0;

    setSeries((prev) => {
      const nextUp =
        prev.up.length === 0 ? [safeUp, safeUp] : [...prev.up, safeUp].slice(-COCKPIT_WING_POINTS);
      const nextDown =
        prev.down.length === 0
          ? [safeDown, safeDown]
          : [...prev.down, safeDown].slice(-COCKPIT_WING_POINTS);
      return { up: nextUp, down: nextDown };
    });
  }, [upRate, downRate, sampleKey, hasData]);

  return { upSamples: series.up, downSamples: series.down };
}

export type AnimatedTelemetryGeometry = TelemetryGeometry & {
  revealProgress: number;
  transitioning: boolean;
};

const TELEMETRY_REVEAL_MS = 620;
const TELEMETRY_MORPH_MS = 540;

function maxArrayDelta(a: readonly number[], b: readonly number[] | null): number {
  if (!b || a.length !== b.length) return Number.POSITIVE_INFINITY;
  let maxDelta = 0;
  for (let i = 0; i < a.length; i += 1) {
    const d = Math.abs(a[i] - b[i]);
    if (d > maxDelta) maxDelta = d;
  }
  return maxDelta;
}

export function useAnimatedTelemetryGeometry(
  samples: number[],
  width: number,
  height: number,
  reducedMotion: boolean,
): AnimatedTelemetryGeometry {
  const baselineY = height - 3;
  const hasData = samples.length > 0;
  const target = useMemo(() => resampleTelemetryY(samples, height), [samples, height]);

  const hasRevealedRef = useRef(false);
  const currentYsRef = useRef<number[]>(
    Array.from({ length: COCKPIT_WING_POINTS }, () => baselineY),
  );
  const lastTargetYsRef = useRef<number[] | null>(null);
  const revealRef = useRef(reducedMotion ? 1 : 0);

  const [frame, setFrame] = useState<{
    ys: number[];
    reveal: number;
    transitioning: boolean;
  }>(() => ({
    ys: reducedMotion && hasData ? target.ys : currentYsRef.current,
    reveal: reducedMotion ? 1 : hasData ? 0 : 1,
    transitioning: false,
  }));

  useEffect(() => {
    if (!hasData) {
      return;
    }

    if (reducedMotion) {
      hasRevealedRef.current = true;
      currentYsRef.current = target.ys;
      lastTargetYsRef.current = target.ys;
      revealRef.current = 1;
      setFrame({ ys: target.ys, reveal: 1, transitioning: false });
      return;
    }

    // Initial data arrival: smoothly unfold the curve left-to-right once.
    if (!hasRevealedRef.current) {
      hasRevealedRef.current = true;
      currentYsRef.current = target.ys;
      lastTargetYsRef.current = target.ys;
      revealRef.current = 0;

      let rafId = 0;
      const startTime = performance.now();
      const startReveal = 0.04;
      setFrame({ ys: target.ys, reveal: startReveal, transitioning: true });

      const step = (now: number) => {
        const t = Math.min(1, (now - startTime) / TELEMETRY_REVEAL_MS);
        const eased = 1 - (1 - t) ** 3;
        const nextReveal = startReveal + (1 - startReveal) * eased;
        revealRef.current = nextReveal;
        setFrame({ ys: target.ys, reveal: nextReveal, transitioning: t < 1 });
        if (t < 1) {
          rafId = window.requestAnimationFrame(step);
        }
      };

      rafId = window.requestAnimationFrame(step);
      return () => window.cancelAnimationFrame(rafId);
    }

    // Subsequent updates: ignore unchanged geometry to prevent replay or flicker.
    if (maxArrayDelta(target.ys, lastTargetYsRef.current) < 0.05 && revealRef.current >= 1) {
      return;
    }

    const fromYs = currentYsRef.current.slice();
    const fromReveal = revealRef.current;
    lastTargetYsRef.current = target.ys;

    let rafId = 0;
    const startTime = performance.now();
    setFrame({ ys: fromYs, reveal: fromReveal, transitioning: true });

    const step = (now: number) => {
      const t = Math.min(1, (now - startTime) / TELEMETRY_MORPH_MS);
      const eased = 1 - (1 - t) ** 3;
      const nextYs = fromYs.map((y0, idx) => y0 + (target.ys[idx] - y0) * eased);
      const nextReveal = fromReveal + (1 - fromReveal) * eased;
      currentYsRef.current = nextYs;
      revealRef.current = nextReveal;
      setFrame({ ys: nextYs, reveal: nextReveal, transitioning: t < 1 });
      if (t < 1) {
        rafId = window.requestAnimationFrame(step);
      } else {
        currentYsRef.current = target.ys;
        revealRef.current = 1;
        setFrame({ ys: target.ys, reveal: 1, transitioning: false });
      }
    };

    rafId = window.requestAnimationFrame(step);
    return () => window.cancelAnimationFrame(rafId);
  }, [target.ys, hasData, reducedMotion]);

  return useMemo(() => {
    const paths = buildTelemetryPathsFromY(frame.ys, width, height);
    const reveal = hasData ? frame.reveal : 1;
    const endX = reveal < 1 ? reveal * width : paths.endX;
    const endY = reveal < 1 ? sampleTelemetryYAtProgress(frame.ys, reveal, baselineY) : paths.endY;
    return {
      ...paths,
      endX,
      endY,
      revealProgress: reveal,
      transitioning: frame.transitioning,
      mean: target.mean,
      peak: target.peak,
    };
  }, [frame, width, height, hasData, baselineY, target.mean, target.peak]);
}
