import { useCallback, useEffect, useRef, useState } from "react";
import type { PublicPingTaskSeries } from "../monitor/publicCard";
import type { MonitorRange, SharedMonitorRecord } from "../monitor/types";
import type { PublicPageState } from "./usePublicStatus";

export function usePublicHistory(
  serverId: string,
  pageState: PublicPageState,
  range: MonitorRange,
  showPing: boolean | undefined,
) {
  const [records, setRecords] = useState<SharedMonitorRecord[]>([]);
  const [pings, setPings] = useState<PublicPingTaskSeries[]>([]);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const activeControllerRef = useRef<AbortController | null>(null);
  const prevTargetRef = useRef("");
  const hasLoadedTargetRef = useRef(false);

  const loadDetailHistory = useCallback(
    async (isBackground = false) => {
      if (!serverId || pageState !== "ready") return;

      activeControllerRef.current?.abort();
      const controller = new AbortController();
      activeControllerRef.current = controller;

      if (!isBackground && !hasLoadedTargetRef.current) {
        setLoadingDetail(true);
      }

      try {
        const recPromise = fetch(
          `/api/public/servers/${encodeURIComponent(serverId)}/records?range=${range}`,
          {
            method: "GET",
            credentials: "omit",
            headers: { Accept: "application/json" },
            signal: controller.signal,
          },
        );
        const pingPromise = showPing
          ? fetch(
              `/api/public/servers/${encodeURIComponent(serverId)}/pings?range=${range}`,
              {
                method: "GET",
                credentials: "omit",
                headers: { Accept: "application/json" },
                signal: controller.signal,
              },
            )
          : Promise.resolve(null);

        const [recRes, pingRes] = await Promise.all([recPromise, pingPromise]);
        const nextRecords = recRes.ok
          ? ((await recRes.json()) as SharedMonitorRecord[])
          : null;
        const nextPings =
          showPing && pingRes && pingRes.ok
            ? ((await pingRes.json()) as PublicPingTaskSeries[])
            : null;

        if (controller.signal.aborted || activeControllerRef.current !== controller) {
          return;
        }

        if (nextRecords !== null) {
          hasLoadedTargetRef.current = true;
          setRecords(nextRecords);
        }
        if (!showPing) {
          setPings([]);
        } else if (nextPings !== null) {
          setPings(nextPings);
        }
      } catch {
        if (controller.signal.aborted || activeControllerRef.current !== controller) {
          return;
        }
        // Keep last loaded history points if transient failure occurs.
      } finally {
        if (!controller.signal.aborted && activeControllerRef.current === controller) {
          setLoadingDetail(false);
        }
      }
    },
    [serverId, pageState, range, showPing],
  );

  useEffect(() => {
    if (!serverId || pageState !== "ready") {
      activeControllerRef.current?.abort();
      activeControllerRef.current = null;
      prevTargetRef.current = "";
      hasLoadedTargetRef.current = false;
      setRecords([]);
      setPings([]);
      setLoadingDetail(false);
      return;
    }

    const targetKey = `${serverId}\n${range}`;
    const targetChanged = prevTargetRef.current !== targetKey;
    if (targetChanged) {
      prevTargetRef.current = targetKey;
      hasLoadedTargetRef.current = false;
      setRecords([]);
      setPings([]);
      setLoadingDetail(true);
    }

    void loadDetailHistory(!targetChanged && hasLoadedTargetRef.current);

    const id = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        void loadDetailHistory(true);
      }
    }, 30_000);
    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        void loadDetailHistory(true);
      }
    };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      activeControllerRef.current?.abort();
      activeControllerRef.current = null;
      window.clearInterval(id);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [serverId, pageState, range, showPing]);

  return { records, pings, loadingDetail };
}
