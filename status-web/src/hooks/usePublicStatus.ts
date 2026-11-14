import { useCallback, useEffect, useState } from "react";
import type { PublicStatusResponse } from "../monitor/publicCard";

export type PublicPageState = "loading" | "disabled" | "ready";

export function usePublicStatus(onDisabled: () => void) {
  const [pageState, setPageState] = useState<PublicPageState>("loading");
  const [data, setData] = useState<PublicStatusResponse | null>(null);
  const [disconnected, setDisconnected] = useState(false);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/public/status", {
        method: "GET",
        credentials: "omit",
        headers: { Accept: "application/json" },
      });
      if (res.status === 404) {
        setData(null);
        setDisconnected(false);
        onDisabled();
        setPageState("disabled");
        document.title = "状态页未开启";
        return;
      }
      if (!res.ok) {
        setDisconnected(true);
        setPageState((prev) => (prev === "loading" ? "ready" : prev));
        return;
      }
      const next = (await res.json()) as PublicStatusResponse;
      setData(next);
      setDisconnected(false);
      setPageState("ready");
      document.title = next.title || "服务状态";
    } catch {
      setDisconnected(true);
      setPageState((prev) => (prev === "loading" ? "ready" : prev));
    }
  }, [onDisabled]);

  useEffect(() => {
    void fetchStatus();
    const id = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        void fetchStatus();
      }
    }, 5000);
    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        void fetchStatus();
      }
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.clearInterval(id);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [fetchStatus]);

  return { pageState, data, disconnected, fetchStatus };
}
