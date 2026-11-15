import { useEffect, useRef, useState } from "react";
import type { PublicStatusBackground } from "../monitor/publicCard";

export function StatusBackgroundLayer({
  background,
  onActiveChange,
}: {
  background?: PublicStatusBackground;
  onActiveChange: (active: boolean) => void;
}) {
  const version = background?.version?.trim() ?? "";
  const imgRef = useRef<HTMLImageElement | null>(null);
  const [loadedVersion, setLoadedVersion] = useState("");
  const [failedVersion, setFailedVersion] = useState("");

  const isFailed = Boolean(version && failedVersion === version);
  const isLoaded = Boolean(version && !isFailed && loadedVersion === version);

  useEffect(() => {
    if (!version || isFailed) {
      onActiveChange(false);
      return;
    }
    const img = imgRef.current;
    if (img && img.complete && img.naturalWidth > 0) {
      setLoadedVersion(version);
      onActiveChange(true);
      return;
    }
    onActiveChange(loadedVersion === version);
  }, [version, isFailed, loadedVersion, onActiveChange]);

  useEffect(() => {
    return () => onActiveChange(false);
  }, [onActiveChange]);

  if (!version || isFailed) {
    return null;
  }

  return (
    <div className="statusBgLayer" aria-hidden="true">
      <img
        ref={imgRef}
        key={version}
        className="statusBgImage"
        data-loaded={isLoaded ? "true" : "false"}
        src={`/api/public/background?v=${encodeURIComponent(version)}`}
        alt=""
        decoding="async"
        onLoad={() => {
          setLoadedVersion(version);
          onActiveChange(true);
        }}
        onError={() => {
          setFailedVersion(version);
          onActiveChange(false);
        }}
      />
      <div className="statusBgScrim" data-loaded={isLoaded ? "true" : "false"} />
    </div>
  );
}
