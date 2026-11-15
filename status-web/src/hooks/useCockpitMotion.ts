import { useEffect, useRef, useState } from "react";
import { COCKPIT_WING_POINTS, getAdaptiveDialCeiling } from "../components/cockpitMath";

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
