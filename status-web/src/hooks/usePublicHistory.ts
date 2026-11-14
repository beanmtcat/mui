import { useCallback, useEffect, useState } from "react";
import type { PublicPingTaskSeries, PublicServerItem } from "../monitor/publicCard";
import type { MonitorRange, SharedMonitorRecord } from "../monitor/types";
import type { PublicPageState } from "./usePublicStatus";

export function usePublicHistory(
  selectedServer: PublicServerItem | undefined,
  pageState: PublicPageState,
  range: MonitorRange,
  showPing: boolean | undefined,
) {
  const [records, setRecords] = useState<SharedMonitorRecord[]>([]);
  const [pings, setPings] = useState<PublicPingTaskSeries[]>([]);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const loadDetailHistory = useCallback(async () => {
    if (!selectedServer || pageState !== "ready") {
      setRecords([]);
      setPings([]);
      return;
    }
    setLoadingDetail(true);
    try {
      const recPromise = fetch(
        `/api/public/servers/${encodeURIComponent(selectedServer.id)}/records?range=${range}`,
        { method: "GET", credentials: "omit", headers: { Accept: "application/json" } },
      );
      const pingPromise = showPing
        ? fetch(
            `/api/public/servers/${encodeURIComponent(selectedServer.id)}/pings?range=${range}`,
            { method: "GET", credentials: "omit", headers: { Accept: "application/json" } },
          )
        : Promise.resolve(null);

      const [recRes, pingRes] = await Promise.all([recPromise, pingPromise]);
      if (recRes.ok) {
        setRecords((await recRes.json()) as SharedMonitorRecord[]);
      }
      if (pingRes && pingRes.ok) {
        setPings((await pingRes.json()) as PublicPingTaskSeries[]);
      } else {
        setPings([]);
      }
    } catch {
      // Keep last loaded history points if transient failure occurs.
    } finally {
      setLoadingDetail(false);
    }
  }, [selectedServer, pageState, range, showPing]);

  useEffect(() => {
    setRecords([]);
    setPings([]);
    void loadDetailHistory();
    if (!selectedServer || pageState !== "ready") return;
    const id = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        void loadDetailHistory();
      }
    }, 30_000);
    return () => window.clearInterval(id);
  }, [loadDetailHistory, selectedServer, pageState]);

  return { records, pings, loadingDetail };
}
