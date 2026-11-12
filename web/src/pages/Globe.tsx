import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { geoDistance, geoEquirectangular, geoGraticule10, geoInterpolate, geoOrthographic, geoPath, type GeoProjection } from "d3-geo";
import type { FeatureCollection, LineString } from "geojson";
import type { Server } from "../api";
import { useApp } from "../app/context";
import { clusterScreenPoints, routeSegments, serverPlace, type Point, type ScreenCluster, type ScreenPoint } from "../app/geo";
import { Status } from "../app/ui";
import world from "../globe-data/world-110m.json";

const land = world as unknown as FeatureCollection;
const graticule = geoGraticule10();
const FLAT_LON = 150;
const MIN_ZOOM = 0.75;
const MAX_ZOOM = 32;
const FIT_MAX_ZOOM = 8;
const FOCUS_MIN_ZOOM = 4;
const CLUSTER_RADIUS = 26;
const DRAG_THRESHOLD = 5;
const DEFAULT_CENTER: Point = [110, 24];
const DEFAULT_FLAT_CENTER: Point = [0, 0];
const INITIAL_SIZE: CanvasSize = { width: 800, height: 520 };

type ViewMode = "globe" | "flat";
type CanvasSize = { width: number; height: number };
type ClusterStatus = "online" | "partial" | "offline";
type ViewState = { mode: ViewMode; center: Point; flatCenter: Point; zoom: number; size: CanvasSize };
type DragStart = { pointerId: number; pointerType: string; x: number; y: number; center: Point; zoom: number; mode: ViewMode; size: CanvasSize; moved: boolean };
type LabelBox = { x: number; y: number; w: number; h: number; text: string };
type MapCluster = ScreenCluster<Server> & { status: ClusterStatus; label: LabelBox };

const wrapLongitude = (value: number) => ((((value + 180) % 360) + 360) % 360) - 180;
const clampLatitude = (value: number) => Math.max(-82, Math.min(82, value));
const clampZoom = (value: number, max = MAX_ZOOM) => Math.max(MIN_ZOOM, Math.min(max, value));
const globeScale = (size: CanvasSize) => Math.min(size.width, size.height) * 0.465;
const flatScale = (size: CanvasSize) => size.width / (2 * Math.PI);

// Pan limit for one axis: locked to the middle while the map is not larger than
// the canvas, then widening so up to ~30% of the canvas may show empty space,
// which lets places near the map seam (around 30°W) still be centred.
function flatPanLimit(full: number, half: number): number {
  const base = Math.max(0, full - half);
  const t = Math.min(1, base / (full / 2));
  return Math.min(full, base + 0.6 * Math.min(half, full) * t);
}

function clampFlatCenter(point: Point, zoom: number, size: CanvasSize): Point {
  const scale = flatScale(size) * zoom;
  const lonLimit = flatPanLimit(180, size.width / (2 * scale) * 180 / Math.PI);
  const latLimit = Math.min(85, flatPanLimit(90, size.height / (2 * scale) * 180 / Math.PI));
  return [Math.max(-lonLimit, Math.min(lonLimit, point[0])), Math.max(-latLimit, Math.min(latLimit, point[1]))];
}

function toFlatCenter(point: Point, zoom: number, size: CanvasSize): Point {
  return clampFlatCenter([wrapLongitude(point[0] - FLAT_LON), point[1]], zoom, size);
}

function buildProjection(mode: ViewMode, center: Point, flatCenter: Point, zoom: number, size: CanvasSize): GeoProjection {
  return mode === "globe"
    ? geoOrthographic().translate([size.width / 2, size.height / 2]).scale(globeScale(size) * zoom).rotate([-center[0], -center[1]]).clipAngle(90).clipExtent([[0, 0], [size.width, size.height]])
    : geoEquirectangular().translate([size.width / 2, size.height / 2]).rotate([-FLAT_LON, 0]).center(flatCenter).scale(flatScale(size) * zoom).clipExtent([[0, 0], [size.width, size.height]]);
}

function clientToViewBox(svg: SVGSVGElement, clientX: number, clientY: number, size: CanvasSize): Point {
  const rect = svg.getBoundingClientRect();
  if (!rect.width || !rect.height) return [size.width / 2, size.height / 2];
  return [((clientX - rect.left) / rect.width) * size.width, ((clientY - rect.top) / rect.height) * size.height];
}

function applyAnchoredZoom(view: ViewState, fromScreen: Point, toScreen: Point, targetZoom: number): ViewState {
  const { size } = view;
  const nextZoom = clampZoom(targetZoom);
  if (view.mode === "flat") {
    const oldProj = buildProjection("flat", view.center, view.flatCenter, view.zoom, size);
    const anchor = oldProj.invert?.(fromScreen) as Point | null | undefined;
    if (!anchor || Number.isNaN(anchor[0]) || Number.isNaN(anchor[1])) {
      return { ...view, zoom: nextZoom, flatCenter: clampFlatCenter(view.flatCenter, nextZoom, size) };
    }
    const newScale = flatScale(size) * nextZoom;
    const nextFlat = clampFlatCenter([
      wrapLongitude(anchor[0] - FLAT_LON) - ((toScreen[0] - size.width / 2) / newScale) * (180 / Math.PI),
      anchor[1] + ((toScreen[1] - size.height / 2) / newScale) * (180 / Math.PI),
    ], nextZoom, size);
    return {
      ...view,
      zoom: nextZoom,
      flatCenter: nextFlat,
      center: [wrapLongitude(nextFlat[0] + FLAT_LON), clampLatitude(nextFlat[1])],
    };
  }

  const oldScale = globeScale(size) * view.zoom;
  if (Math.hypot(fromScreen[0] - size.width / 2, fromScreen[1] - size.height / 2) >= oldScale * 0.998) {
    return { ...view, zoom: nextZoom, flatCenter: clampFlatCenter(view.flatCenter, nextZoom, size) };
  }
  const oldProj = buildProjection("globe", view.center, view.flatCenter, view.zoom, size);
  const anchor = oldProj.invert?.(fromScreen) as Point | null | undefined;
  if (!anchor || Number.isNaN(anchor[0]) || Number.isNaN(anchor[1])) {
    return { ...view, zoom: nextZoom, flatCenter: clampFlatCenter(view.flatCenter, nextZoom, size) };
  }
  const newScale = globeScale(size) * nextZoom;
  let nx = (toScreen[0] - size.width / 2) / newScale;
  let ny = (size.height / 2 - toScreen[1]) / newScale;
  const norm = Math.hypot(nx, ny);
  if (norm > 0.995) {
    nx = (nx / norm) * 0.995;
    ny = (ny / norm) * 0.995;
  }
  const phiA = anchor[1] * Math.PI / 180;
  const cosPhiA = Math.max(1e-6, Math.cos(phiA));
  const sinLambda = Math.max(-1, Math.min(1, nx / cosPhiA));
  const asinDeg = Math.asin(sinLambda) * 180 / Math.PI;
  const cand1 = wrapLongitude(anchor[0] - asinDeg);
  const cand2 = wrapLongitude(anchor[0] - (180 - asinDeg));
  const lon0 = Math.abs(wrapLongitude(cand1 - view.center[0])) <= Math.abs(wrapLongitude(cand2 - view.center[0])) ? cand1 : cand2;
  const dLambda = wrapLongitude(anchor[0] - lon0) * Math.PI / 180;
  const k = Math.cos(phiA) * Math.cos(dLambda);
  const r = Math.max(1e-6, Math.hypot(Math.sin(phiA), k));
  const alpha = Math.atan2(Math.sin(phiA), k);
  const beta = Math.asin(Math.max(-1, Math.min(1, ny / r)));
  const lat0 = clampLatitude((alpha - beta) * 180 / Math.PI);
  const nextCenter: Point = [lon0, lat0];
  return {
    ...view,
    zoom: nextZoom,
    center: nextCenter,
    flatCenter: toFlatCenter(nextCenter, nextZoom, size),
  };
}

function smallestArcCenterLon(points: readonly Point[]): number {
  const lons = [...new Set(points.map((p) => wrapLongitude(p[0])))].sort((a, b) => a - b);
  if (lons.length <= 1) return lons[0] ?? DEFAULT_CENTER[0];
  let maxGap = -1, startLon = lons[0];
  for (let i = 0; i < lons.length; i++) {
    const current = lons[i];
    const next = i + 1 < lons.length ? lons[i + 1] : lons[0] + 360;
    const gap = next - current;
    if (gap > maxGap) { maxGap = gap; startLon = wrapLongitude(next); }
  }
  return wrapLongitude(startLon + Math.max(0, 360 - maxGap) / 2);
}

function computeFitAllView(points: readonly Point[], mode: ViewMode, size: CanvasSize): ViewState {
  if (points.length === 0) {
    return { mode, center: DEFAULT_CENTER, flatCenter: DEFAULT_FLAT_CENTER, zoom: 1, size };
  }
  const halfW = size.width * 0.38, halfH = size.height * 0.38;
  const lats = points.map((p) => p[1]);
  const minLat = Math.min(...lats), maxLat = Math.max(...lats);
  const globeCenter: Point = [smallestArcCenterLon(points), clampLatitude((minLat + maxLat) / 2)];
  const gScale = globeScale(size), fScale = flatScale(size);

  let globeZoom = 1;
  const maxAngle = Math.max(...points.map((p) => geoDistance(p, globeCenter)));
  if (maxAngle < Math.PI / 2 - 0.03) {
    const unitProj = geoOrthographic().translate([0, 0]).scale(gScale).rotate([-globeCenter[0], -globeCenter[1]]);
    let maxAbsX = 0, maxAbsY = 0;
    for (const point of points) {
      const projected = unitProj(point);
      if (!projected) continue;
      maxAbsX = Math.max(maxAbsX, Math.abs(projected[0]));
      maxAbsY = Math.max(maxAbsY, Math.abs(projected[1]));
    }
    const zX = maxAbsX > 1e-3 ? halfW / maxAbsX : FIT_MAX_ZOOM;
    const zY = maxAbsY > 1e-3 ? halfH / maxAbsY : FIT_MAX_ZOOM;
    globeZoom = clampZoom(Math.min(zX, zY, FIT_MAX_ZOOM), FIT_MAX_ZOOM);
  }

  const relLons = points.map((p) => wrapLongitude(p[0] - FLAT_LON));
  const minRelLon = Math.min(...relLons), maxRelLon = Math.max(...relLons);
  const dLon = maxRelLon - minRelLon, dLat = maxLat - minLat;
  const rawFlatCenter: Point = [(minRelLon + maxRelLon) / 2, (minLat + maxLat) / 2];
  const zLon = dLon > 1e-3 ? (halfW * 2) / (fScale * (dLon * Math.PI / 180)) : FIT_MAX_ZOOM;
  const zLat = dLat > 1e-3 ? (halfH * 2) / (fScale * (dLat * Math.PI / 180)) : FIT_MAX_ZOOM;
  const flatZoom = clampZoom(Math.min(zLon, zLat, FIT_MAX_ZOOM), FIT_MAX_ZOOM);

  const nextZoom = mode === "globe" ? globeZoom : flatZoom;
  return { mode, center: globeCenter, flatCenter: clampFlatCenter(rawFlatCenter, nextZoom, size), zoom: nextZoom, size };
}

function estimateLabelWidth(text: string): number {
  let width = 12;
  for (const ch of text) {
    const code = ch.codePointAt(0) || 0;
    if (code > 0x024f) width += 11.2;
    else if ("ilI1.,:;|!/'\"` ".includes(ch)) width += 4.2;
    else if (ch >= "A" && ch <= "Z") width += 7.2;
    else width += 6.4;
  }
  return Math.ceil(width);
}

function computeLabelBox(screen: Point, count: number, text: string, size: CanvasSize): LabelBox {
  const haloR = count > 1 ? 15 : 9, gap = 4, w = estimateLabelWidth(text), h = 18;
  let x = screen[0] + haloR + gap;
  if (x + w > size.width - 4) x = screen[0] - haloR - gap - w;
  return { x, y: screen[1] - h / 2, w, h, text };
}

const boxesOverlap = (a: LabelBox, b: LabelBox) =>
  a.x < b.x + b.w + 2 && a.x + a.w + 2 > b.x && a.y < b.y + b.h + 2 && a.y + a.h + 2 > b.y;

function boxHitsCircle(box: LabelBox, cx: number, cy: number, radius: number): boolean {
  const nx = Math.max(box.x, Math.min(cx, box.x + box.w));
  const ny = Math.max(box.y, Math.min(cy, box.y + box.h));
  return Math.hypot(cx - nx, cy - ny) < radius;
}

export default function Globe() {
  const { servers, nodes, routes, serverName, goTo, currentServerId, protect } = useApp();
  const [mode, setMode] = useState<ViewMode>("globe");
  const [center, setCenter] = useState<Point>(DEFAULT_CENTER);
  const [flatCenter, setFlatCenter] = useState<Point>(DEFAULT_FLAT_CENTER);
  const [zoom, setZoom] = useState(1);
  const [size, setSize] = useState<CanvasSize>(INITIAL_SIZE);
  const [sizeReady, setSizeReady] = useState(false);
  const [routeId, setRouteId] = useState("");
  const [includeDisabled, setIncludeDisabled] = useState(false);
  const [activeMarkerKey, setActiveMarkerKey] = useState("");
  const [hoveredServerId, setHoveredServerId] = useState("");

  const selectedServerId = currentServerId;
  const canvasRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const viewRef = useRef<ViewState>({ mode: "globe", center: DEFAULT_CENTER, flatCenter: DEFAULT_FLAT_CENTER, zoom: 1, size: INITIAL_SIZE });
  const rafRef = useRef(0);
  const dragging = useRef<DragStart | null>(null);
  const activePointers = useRef(new Map<number, { x: number; y: number; pointerType: string }>());
  const pinching = useRef<{ dist: number; mid: Point } | null>(null);
  const suppressClick = useRef(false);
  const didAutoFit = useRef(false);
  const skipFocusZoomRef = useRef(false);

  viewRef.current = { mode, center, flatCenter, zoom, size };

  const applyViewImmediate = useCallback((next: ViewState) => {
    if (rafRef.current) { cancelAnimationFrame(rafRef.current); rafRef.current = 0; }
    viewRef.current = { ...next, size: viewRef.current.size };
    setMode(next.mode);
    setCenter(next.center);
    setFlatCenter(next.flatCenter);
    setZoom(next.zoom);
  }, []);

  const scheduleFlush = useCallback(() => {
    if (rafRef.current) return;
    rafRef.current = requestAnimationFrame(() => {
      rafRef.current = 0;
      const current = viewRef.current;
      setCenter(current.center);
      setFlatCenter(current.flatCenter);
      setZoom(current.zoom);
    });
  }, []);

  useEffect(() => () => { if (rafRef.current) cancelAnimationFrame(rafRef.current); }, []);

  // Track .globeCanvas pixel size so 1 viewBox unit = 1 CSS pixel; preserve center and zoom on resize.
  useEffect(() => {
    const el = canvasRef.current;
    if (!el) return;
    const updateSize = (w: number, h: number) => {
      if (w <= 0 || h <= 0) return;
      const nextSize = { width: Math.round(w), height: Math.round(h) };
      viewRef.current = { ...viewRef.current, size: nextSize };
      setSize((prev) => (prev.width === nextSize.width && prev.height === nextSize.height ? prev : nextSize));
      setSizeReady(true);
    };
    updateSize(el.clientWidth, el.clientHeight);
    const observer = new ResizeObserver((entries) => {
      const rect = entries[0]?.contentRect;
      if (rect) updateSize(rect.width, rect.height);
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const locations = useMemo(() => new Map(servers.map((server) => [server.id, serverPlace(server)])), [servers]);
  const { placedPoints, missing } = useMemo(() => {
    const pts: Point[] = [], unplaced: Server[] = [];
    for (const server of servers) {
      const place = locations.get(server.id);
      if (place) pts.push(place.point);
      else unplaced.push(server);
    }
    return { placedPoints: pts, missing: unplaced };
  }, [servers, locations]);

  const segments = useMemo(() => routeSegments(routes, nodes, includeDisabled, routeId)
    .filter((segment) => Boolean(locations.get(segment.from) && locations.get(segment.to))),
  [routes, nodes, includeDisabled, routeId, locations]);

  const selected = servers.find((server) => server.id === selectedServerId);
  const selectedPlace = selected ? locations.get(selected.id) ?? null : null;

  // Initial auto-fit when entering page with no selected server.
  useEffect(() => {
    if (!sizeReady || didAutoFit.current) return;
    if (selectedServerId) {
      didAutoFit.current = true;
      return;
    }
    if (placedPoints.length > 0) {
      didAutoFit.current = true;
      applyViewImmediate(computeFitAllView(placedPoints, viewRef.current.mode, viewRef.current.size));
    }
  }, [sizeReady, selectedServerId, placedPoints, applyViewImmediate]);

  // Center on externally-selected server (URL navigation or location edit).
  const selectedLon = selectedPlace?.point[0];
  const selectedLat = selectedPlace?.point[1];
  useEffect(() => {
    if (!sizeReady || selectedLon === undefined || selectedLat === undefined) return;
    if (skipFocusZoomRef.current) {
      skipFocusZoomRef.current = false;
      return;
    }
    const current = viewRef.current;
    const nextZoom = Math.max(current.zoom, FOCUS_MIN_ZOOM);
    const point: Point = [selectedLon, selectedLat];
    applyViewImmediate({
      ...current,
      center: [point[0], clampLatitude(point[1])],
      flatCenter: toFlatCenter(point, nextZoom, current.size),
      zoom: nextZoom,
    });
  }, [sizeReady, selected?.id, selectedLon, selectedLat, applyViewImmediate]);

  // Non-passive wheel & multi-touch gesture listeners.
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      let dy = event.deltaY;
      if (event.deltaMode === 1) dy *= 16;
      else if (event.deltaMode === 2) dy *= 100;
      const sensitivity = event.ctrlKey ? 0.012 : 0.0025;
      const factor = Math.min(1.25, Math.max(0.8, Math.exp(-dy * sensitivity)));
      const current = viewRef.current;
      const cursor = clientToViewBox(svg, event.clientX, event.clientY, current.size);
      viewRef.current = applyAnchoredZoom(current, cursor, cursor, current.zoom * factor);
      scheduleFlush();
    };
    const onTouchMove = (event: TouchEvent) => {
      if (event.touches.length >= 2) event.preventDefault();
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    svg.addEventListener("touchmove", onTouchMove, { passive: false });
    return () => {
      svg.removeEventListener("wheel", onWheel);
      svg.removeEventListener("touchmove", onTouchMove);
    };
  }, [scheduleFlush]);

  const projection = useMemo(() => buildProjection(mode, center, flatCenter, zoom, size), [mode, center, flatCenter, zoom, size]);
  const path = useMemo(() => geoPath(projection), [projection]);
  const { sphere, grid, landPaths } = useMemo(() => ({
    sphere: path({ type: "Sphere" }) || "",
    grid: path(graticule) || "",
    landPaths: land.features.map((feature) => path(feature) || ""),
  }), [path]);

  const linkItems = useMemo(() => {
    const items: { key: string; d: string; active: boolean; title: string }[] = [];
    for (const segment of segments) {
      const from = locations.get(segment.from)?.point, to = locations.get(segment.to)?.point;
      if (!from || !to) continue;
      let d = "";
      if (from[0] === to[0] && from[1] === to[1]) {
        if (mode === "globe" && geoDistance(from, center) >= Math.PI / 2 - 0.005) continue;
        const projected = projection(from);
        if (!projected) continue;
        const [x, y] = projected;
        if (x < -40 || x > size.width + 40 || y < -40 || y > size.height + 40) continue;
        d = `M${x - 4},${y - 4} C${x - 24},${y - 30} ${x + 24},${y - 30} ${x + 4},${y - 4}`;
      } else {
        const between = geoInterpolate(from, to);
        const line: LineString = { type: "LineString", coordinates: Array.from({ length: 33 }, (_, i) => between(i / 32)) };
        d = path(line) || "";
      }
      if (d) items.push({ key: `${segment.from}:${segment.to}`, d, active: segment.active, title: `${serverName(segment.from)} → ${serverName(segment.to)} · ${segment.routeNames.join("、")}` });
    }
    return items;
  }, [segments, locations, mode, center, size, projection, path, serverName]);

  const clusters = useMemo<MapCluster[]>(() => {
    const entries: ScreenPoint<Server>[] = [];
    for (const server of servers) {
      const place = locations.get(server.id);
      if (!place || (mode === "globe" && geoDistance(place.point, center) >= Math.PI / 2 - 0.005)) continue;
      const projected = projection(place.point);
      if (!projected) continue;
      if (projected[0] < -CLUSTER_RADIUS * 2 || projected[0] > size.width + CLUSTER_RADIUS * 2 || projected[1] < -CLUSTER_RADIUS * 2 || projected[1] > size.height + CLUSTER_RADIUS * 2) continue;
      entries.push({ id: server.id, point: place.point, screen: [projected[0], projected[1]], item: server });
    }
    return clusterScreenPoints(entries, CLUSTER_RADIUS)
      .filter((c) => c.screen[0] >= -18 && c.screen[0] <= size.width + 18 && c.screen[1] >= -18 && c.screen[1] <= size.height + 18)
      .map((cluster) => {
        const onlineCount = cluster.items.filter((server) => server.status === "online").length;
        const status: ClusterStatus = onlineCount === cluster.items.length ? "online" : onlineCount === 0 ? "offline" : "partial";
        const text = cluster.items.length > 1 ? `${cluster.items.length} 台` : cluster.items[0].name;
        return { ...cluster, status, label: computeLabelBox(cluster.screen, cluster.items.length, text, size) };
      });
  }, [servers, locations, mode, center, flatCenter, zoom, size, projection]);

  const shownLabelKeys = useMemo(() => {
    const ordered = [...clusters].sort((a, b) => {
      const aSelected = a.items.some((s) => s.id === selectedServerId);
      const bSelected = b.items.some((s) => s.id === selectedServerId);
      if (aSelected !== bSelected) return aSelected ? -1 : 1;
      const rank = (status: ClusterStatus) => status === "online" ? 0 : status === "partial" ? 1 : 2;
      return rank(a.status) - rank(b.status);
    });
    const shown = new Set<string>();
    const placed: LabelBox[] = [];
    for (const cluster of ordered) {
      const isSelected = cluster.items.some((s) => s.id === selectedServerId);
      const box = cluster.label;
      if (isSelected) {
        shown.add(cluster.key);
        placed.push(box);
        continue;
      }
      if (box.x < 2 || box.x + box.w > size.width - 2 || box.y < 2 || box.y + box.h > size.height - 2) continue;
      if (placed.some((existing) => boxesOverlap(box, existing))) continue;
      const hitsMarker = clusters.some((other) => (
        other.key !== cluster.key &&
        boxHitsCircle(box, other.screen[0], other.screen[1], other.items.length > 1 ? 14 : 8)
      ));
      if (hitsMarker) continue;
      shown.add(cluster.key);
      placed.push(box);
    }
    return shown;
  }, [clusters, selectedServerId, size]);

  const selectedCluster = useMemo(
    () => clusters.find((cluster) => cluster.items.some((server) => server.id === selectedServerId)),
    [clusters, selectedServerId],
  );
  const hoveredClusterKey = useMemo(() => {
    if (!hoveredServerId) return "";
    return clusters.find((cluster) => cluster.items.some((server) => server.id === hoveredServerId))?.key || "";
  }, [clusters, hoveredServerId]);

  const samePlaceServers = useMemo(() => {
    if (!selectedPlace) return [];
    return servers.filter((server) => {
      const place = locations.get(server.id);
      return Boolean(place && place.point[0] === selectedPlace.point[0] && place.point[1] === selectedPlace.point[1]);
    });
  }, [servers, locations, selectedPlace]);

  const selectionPeers = useMemo(() => {
    if (selectedCluster && selectedCluster.items.length > 1 && (selectedCluster.coLocated || zoom >= MAX_ZOOM)) {
      return selectedCluster.items;
    }
    return samePlaceServers.length > 1 ? samePlaceServers : [];
  }, [selectedCluster, samePlaceServers, zoom]);

  const selectedRoutes = useMemo(() => selected ? routes.filter((route) => routeSegments([route], nodes, true, "")
    .some((segment) => segment.from === selected.id || segment.to === selected.id)) : [], [selected, routes, nodes]);

  const highlightedIds = useMemo(
    () => routeId ? new Set(segments.flatMap((segment) => [segment.from, segment.to])) : null,
    [routeId, segments],
  );

  // Preserve pixels-per-degree and center coordinates when toggling between globe and flat projections.
  const switchMode = (nextMode: ViewMode) => {
    if (nextMode === mode) return;
    const current = viewRef.current;
    const gScale = globeScale(current.size), fScale = flatScale(current.size);
    if (nextMode === "flat") {
      const flatZoom = clampZoom(current.zoom * gScale / fScale);
      applyViewImmediate({ ...current, mode: "flat", zoom: flatZoom, flatCenter: toFlatCenter(current.center, flatZoom, current.size) });
    } else {
      const globeZoom = clampZoom(current.zoom * fScale / gScale);
      const nextCenter: Point = [wrapLongitude(current.flatCenter[0] + FLAT_LON), clampLatitude(current.flatCenter[1])];
      applyViewImmediate({ ...current, mode: "globe", zoom: globeZoom, center: nextCenter });
    }
  };

  const fitAll = () => {
    if (placedPoints.length > 0) applyViewImmediate(computeFitAllView(placedPoints, viewRef.current.mode, viewRef.current.size));
  };
  const resetView = () => applyViewImmediate({ mode: viewRef.current.mode, center: DEFAULT_CENTER, flatCenter: DEFAULT_FLAT_CENTER, zoom: 1, size: viewRef.current.size });
  const stepZoom = (multiplier: number) => {
    const current = viewRef.current;
    const nextZoom = clampZoom(current.zoom * multiplier);
    applyViewImmediate({ ...current, zoom: nextZoom, flatCenter: clampFlatCenter(current.flatCenter, nextZoom, current.size) });
  };

  const focusServer = (server: Server, keepZoom = false) => {
    const place = locations.get(server.id);
    const current = viewRef.current;
    const nextZoom = keepZoom ? current.zoom : Math.max(current.zoom, FOCUS_MIN_ZOOM);
    if (selectedServerId !== server.id) skipFocusZoomRef.current = true;
    goTo("globe", server.id);
    if (place) {
      applyViewImmediate({
        ...current,
        center: [place.point[0], clampLatitude(place.point[1])],
        flatCenter: toFlatCenter(place.point, nextZoom, current.size),
        zoom: nextZoom,
      });
    }
  };

  const handleClusterActivate = (cluster: MapCluster) => {
    if (cluster.items.length === 1) {
      focusServer(cluster.items[0]);
      return;
    }
    const current = viewRef.current;
    if (cluster.coLocated || current.zoom >= MAX_ZOOM - 1e-6) {
      if (selectedServerId !== cluster.items[0].id) skipFocusZoomRef.current = true;
      goTo("globe", cluster.items[0].id);
      applyViewImmediate({
        ...current,
        center: [cluster.point[0], clampLatitude(cluster.point[1])],
        flatCenter: toFlatCenter(cluster.point, current.zoom, current.size),
      });
      return;
    }
    const uniquePoints = new Map<string, Point>();
    for (const pt of cluster.points) uniquePoints.set(`${pt[0]}:${pt[1]}`, pt);
    const distinct = [...uniquePoints.values()];
    const relLons = distinct.map((pt) => wrapLongitude(pt[0] - cluster.point[0]));
    const lats = distinct.map((pt) => pt[1]);
    const dLon = Math.max(...relLons) - Math.min(...relLons);
    const dLat = Math.max(...lats) - Math.min(...lats);
    const baseScale = current.mode === "globe" ? globeScale(current.size) : flatScale(current.size);
    const lonFactor = current.mode === "globe" ? Math.max(0.2, Math.cos(cluster.point[1] * Math.PI / 180)) : 1;
    const spanAtUnitZoom = Math.hypot(dLon * lonFactor, dLat) * (Math.PI / 180) * baseScale;
    const targetSpan = Math.min(Math.min(current.size.width, current.size.height) * 0.45, 34 * Math.max(1, distinct.length - 1));
    const neededZoom = spanAtUnitZoom > 1e-4 ? targetSpan / spanAtUnitZoom : MAX_ZOOM;
    const nextZoom = clampZoom(Math.max(current.zoom * 2, neededZoom));
    applyViewImmediate({
      ...current,
      center: [cluster.point[0], clampLatitude(cluster.point[1])],
      flatCenter: toFlatCenter(cluster.point, nextZoom, current.size),
      zoom: nextZoom,
    });
  };

  const renderServerButton = (server: Server, keepZoomOnClick = false) => {
    const place = locations.get(server.id);
    return (
      <button key={server.id} type="button" className={selectedServerId === server.id ? "selected" : ""}
        onClick={() => focusServer(server, keepZoomOnClick)}
        onPointerEnter={() => setHoveredServerId(server.id)}
        onPointerLeave={() => setHoveredServerId((id) => (id === server.id ? "" : id))}
        onFocus={() => setHoveredServerId(server.id)}
        onBlur={() => setHoveredServerId((id) => (id === server.id ? "" : id))}>
        <span className={`globeServerDot ${server.status === "online" ? "online" : ""}`} />
        <span className="globeServerInfo">
          <strong>{server.name}</strong>
          <small>{[server.country, server.city || server.region].filter(Boolean).join(" · ") || "位置未填写"}{place?.precision === "country" ? " · 国家位置" : ""}</small>
        </span>
        {!place && <span className="globeUnplaced">未定位</span>}
      </button>
    );
  };

  const finishPointer = (svg: SVGSVGElement, pointerId: number) => {
    activePointers.current.delete(pointerId);
    if (activePointers.current.size < 2) pinching.current = null;
    if (dragging.current?.pointerId === pointerId) {
      if (dragging.current.moved) suppressClick.current = true;
      dragging.current = null;
    }
    if (svg.hasPointerCapture(pointerId)) {
      try { svg.releasePointerCapture(pointerId); } catch { /* ignore */ }
    }
  };

  return protect(<section className="panel globePage">
    <div className="panelHead">
      <div>
        <h2>全球网络</h2>
        <p>按服务器档案的位置展示；连线依次经过入口、中转和落地。球面可拖动旋转，平面可拖动平移，支持滚轮与双指缩放。</p>
      </div>
      <div className="globeCounts"><strong>{servers.length}</strong> 台服务器 <span>·</span> <strong>{routes.length}</strong> 条链路</div>
    </div>
    <div className="globeToolbar">
      <div className="globeMode" role="group" aria-label="地图视图">
        <button type="button" className={mode === "globe" ? "active" : ""} aria-pressed={mode === "globe"} onClick={() => switchMode("globe")}>球面</button>
        <button type="button" className={mode === "flat" ? "active" : ""} aria-pressed={mode === "flat"} onClick={() => switchMode("flat")}>平面</button>
      </div>
      <select aria-label="按链路筛选地图" value={routeId} onChange={(event) => {
        const id = event.target.value;
        setRouteId(id);
        if (routes.find((route) => route.id === id)?.enabled === false) setIncludeDisabled(true);
      }}>
        <option value="">全部链路</option>
        {routes.map((route) => <option key={route.id} value={route.id}>{route.name}{route.enabled ? "" : "（停用）"}</option>)}
      </select>
      <label className="check"><input type="checkbox" checked={includeDisabled} onChange={(event) => setIncludeDisabled(event.target.checked)} />包含停用链路</label>
      <div className="globeZoom" role="group" aria-label="缩放与视图控制">
        <button type="button" className="globeZoomText" aria-label="适配全部服务器" disabled={placedPoints.length === 0} onClick={fitAll}>全部</button>
        <button type="button" className="globeZoomText" aria-label="重置地图视图" onClick={resetView}>重置</button>
        <button type="button" aria-label="缩小" disabled={zoom <= MIN_ZOOM + 1e-6} onClick={() => stepZoom(1 / 1.5)}>−</button>
        <button type="button" aria-label="放大" disabled={zoom >= MAX_ZOOM - 1e-6} onClick={() => stepZoom(1.5)}>+</button>
      </div>
    </div>
    <div className="globeLayout">
      <div className="globeMapStage">
        <div ref={canvasRef} className={`globeCanvas ${mode}`}>
          <svg ref={svgRef} viewBox={`0 0 ${size.width} ${size.height}`} role="group" aria-label="服务器与链路地图"
            onDoubleClick={(event) => {
              if ((event.target as Element | null)?.closest?.(".globeMarker")) return;
              event.preventDefault();
              const current = viewRef.current;
              const anchorScreen = clientToViewBox(event.currentTarget, event.clientX, event.clientY, current.size);
              applyViewImmediate(applyAnchoredZoom(current, anchorScreen, anchorScreen, current.zoom * 2));
            }}
            onPointerDown={(event) => {
              if (event.pointerType === "mouse" && event.button !== 0) return;
              activePointers.current.set(event.pointerId, { x: event.clientX, y: event.clientY, pointerType: event.pointerType });
              if (activePointers.current.size >= 2) {
                if (dragging.current && event.currentTarget.hasPointerCapture(dragging.current.pointerId)) {
                  try { event.currentTarget.releasePointerCapture(dragging.current.pointerId); } catch { /* ignore */ }
                }
                dragging.current = null;
                suppressClick.current = true;
                const [p1, p2] = [...activePointers.current.values()];
                const dist = Math.hypot(p2.x - p1.x, p2.y - p1.y);
                const mid: Point = [(p1.x + p2.x) / 2, (p1.y + p2.y) / 2];
                pinching.current = dist > 4 ? { dist, mid } : null;
                try { event.currentTarget.setPointerCapture(event.pointerId); } catch { /* ignore */ }
                return;
              }
              suppressClick.current = false;
              // Let the browser handle single-finger touch scrolling in the flat view.
              if (viewRef.current.mode === "flat" && event.pointerType === "touch") return;
              const current = viewRef.current;
              dragging.current = {
                pointerId: event.pointerId, pointerType: event.pointerType,
                x: event.clientX, y: event.clientY,
                center: current.mode === "globe" ? current.center : current.flatCenter,
                zoom: current.zoom, mode: current.mode, size: current.size, moved: false,
              };
            }}
            onPointerMove={(event) => {
              if (activePointers.current.has(event.pointerId)) {
                activePointers.current.set(event.pointerId, { x: event.clientX, y: event.clientY, pointerType: event.pointerType });
              }
              if (activePointers.current.size >= 2) {
                const [p1, p2] = [...activePointers.current.values()];
                const newDist = Math.hypot(p2.x - p1.x, p2.y - p1.y);
                const newMid: Point = [(p1.x + p2.x) / 2, (p1.y + p2.y) / 2];
                if (pinching.current && pinching.current.dist > 4 && newDist > 4) {
                  const current = viewRef.current;
                  const factor = Math.min(1.5, Math.max(0.67, newDist / pinching.current.dist));
                  const fromScreen = clientToViewBox(event.currentTarget, pinching.current.mid[0], pinching.current.mid[1], current.size);
                  const toScreen = clientToViewBox(event.currentTarget, newMid[0], newMid[1], current.size);
                  viewRef.current = applyAnchoredZoom(current, fromScreen, toScreen, current.zoom * factor);
                  scheduleFlush();
                }
                pinching.current = newDist > 4 ? { dist: newDist, mid: newMid } : null;
                return;
              }
              const start = dragging.current;
              if (!start || start.pointerId !== event.pointerId) return;
              const dx = event.clientX - start.x, dy = event.clientY - start.y;
              if (!start.moved) {
                if (Math.hypot(dx, dy) < DRAG_THRESHOLD) return;
                // A vertical touch swipe belongs to the page, not the globe.
                if (start.pointerType === "touch" && Math.abs(dy) > Math.abs(dx)) {
                  dragging.current = null;
                  activePointers.current.delete(event.pointerId);
                  return;
                }
                start.moved = true;
                try { event.currentTarget.setPointerCapture(event.pointerId); } catch { /* ignore */ }
              }
              if (start.mode === "globe") {
                const step = 180 / Math.PI / (globeScale(start.size) * start.zoom);
                const nextCenter: Point = [wrapLongitude(start.center[0] - dx * step), clampLatitude(start.center[1] + dy * step)];
                viewRef.current = { ...viewRef.current, center: nextCenter, flatCenter: toFlatCenter(nextCenter, start.zoom, start.size) };
                scheduleFlush();
              } else {
                const rect = event.currentTarget.getBoundingClientRect();
                const degreesPerPx = 180 / Math.PI / (flatScale(start.size) * start.zoom);
                const rx = rect.width ? start.size.width / rect.width : 1;
                const ry = rect.height ? start.size.height / rect.height : 1;
                const nextFlat = clampFlatCenter([start.center[0] - dx * rx * degreesPerPx, start.center[1] + dy * ry * degreesPerPx], start.zoom, start.size);
                viewRef.current = { ...viewRef.current, flatCenter: nextFlat, center: [wrapLongitude(nextFlat[0] + FLAT_LON), clampLatitude(nextFlat[1])] };
                scheduleFlush();
              }
            }}
            onPointerUp={(event) => finishPointer(event.currentTarget, event.pointerId)}
            onPointerCancel={(event) => finishPointer(event.currentTarget, event.pointerId)}
            onClickCapture={(event) => {
              if (!suppressClick.current) return;
              suppressClick.current = false;
              event.preventDefault();
              event.stopPropagation();
            }}>
            <defs>
              <radialGradient id="globeOcean" cx="38%" cy="30%" r="78%"><stop offset="0%" stopColor="#285a75" /><stop offset="100%" stopColor="#0a253b" /></radialGradient>
              <linearGradient id="globeLine" x1="0" y1="0" x2="1" y2="1"><stop stopColor="#39d6db" /><stop offset="100%" stopColor="#9ac8ff" /></linearGradient>
            </defs>
            <path className="globeSphere" d={sphere} />
            <path className="globeGraticule" d={grid} />
            <g className="globeLand">{landPaths.map((d, index) => <path key={index} d={d} />)}</g>
            <g className="globeLinks">{linkItems.map((link) => (
              <path key={link.key} d={link.d} className={link.active ? "globeLinkActive" : "globeLinkDisabled"}>
                <title>{link.title}</title>
              </path>
            ))}</g>
            <g className="globeMarkers">{clusters.map((cluster) => {
              const [x, y] = cluster.screen, count = cluster.items.length;
              const isSelected = selectedCluster?.key === cluster.key, isHovered = hoveredClusterKey === cluster.key;
              const dimmed = Boolean(highlightedIds && !cluster.items.some((server) => highlightedIds.has(server.id)));
              const statusClass = cluster.status === "online" ? " online" : cluster.status === "partial" ? " partial" : "";
              return (
                <g key={cluster.key} transform={`translate(${x},${y})`} role="button" tabIndex={0}
                  className={`globeMarker${isSelected ? " selected" : ""}${isHovered ? " hovered" : ""}${dimmed ? " dimmed" : ""}${statusClass}`}
                  aria-label={`${cluster.items.map((server) => server.name).join("、")}，${count} 台服务器`}
                  onClick={() => handleClusterActivate(cluster)}
                  onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); handleClusterActivate(cluster); } }}
                  onPointerEnter={() => setActiveMarkerKey(cluster.key)}
                  onPointerLeave={() => setActiveMarkerKey((key) => (key === cluster.key ? "" : key))}
                  onFocus={() => setActiveMarkerKey(cluster.key)}
                  onBlur={() => setActiveMarkerKey((key) => (key === cluster.key ? "" : key))}>
                  <circle className="globeMarkerHalo" r={count > 1 ? 15 : 9} />
                  <circle className="globeMarkerCore" r={count > 1 ? 10 : 5} />
                  {count > 1 && <text textAnchor="middle" dominantBaseline="central">{count}</text>}
                  <title>{cluster.items.map((server) => server.name).join("、")}</title>
                </g>
              );
            })}</g>
            <g className="globeLabels">{(() => {
              const activeCluster = clusters.find((c) => c.key === activeMarkerKey || c.key === hoveredClusterKey);
              const activeClampedBox = activeCluster ? {
                ...activeCluster.label,
                x: Math.max(4, Math.min(size.width - 4 - activeCluster.label.w, activeCluster.label.x)),
                y: Math.max(4, Math.min(size.height - 4 - activeCluster.label.h, activeCluster.label.y)),
              } : null;
              const visibleLabels = clusters.filter((cluster) => {
                const isSelected = selectedCluster?.key === cluster.key;
                const isActive = activeMarkerKey === cluster.key || hoveredClusterKey === cluster.key;
                if (isSelected || isActive) return true;
                if (!shownLabelKeys.has(cluster.key)) return false;
                if (activeClampedBox && boxesOverlap(cluster.label, activeClampedBox)) return false;
                return true;
              }).sort((a, b) => {
                const aForced = Number(selectedCluster?.key === a.key || activeMarkerKey === a.key || hoveredClusterKey === a.key);
                const bForced = Number(selectedCluster?.key === b.key || activeMarkerKey === b.key || hoveredClusterKey === b.key);
                return aForced - bForced;
              });
              return visibleLabels.map((cluster) => {
                const isSelected = selectedCluster?.key === cluster.key;
                const isActive = activeMarkerKey === cluster.key || hoveredClusterKey === cluster.key;
                const forced = isSelected || isActive;
                const dimmed = !forced && Boolean(highlightedIds && !cluster.items.some((server) => highlightedIds.has(server.id)));
                const box = cluster.label;
                const x = forced ? Math.max(4, Math.min(size.width - 4 - box.w, box.x)) : box.x;
                const y = forced ? Math.max(4, Math.min(size.height - 4 - box.h, box.y)) : box.y;
                return (
                  <g key={cluster.key} className={`globeLabel${forced ? " active" : ""}${dimmed ? " dimmed" : ""}`} transform={`translate(${x},${y})`}>
                    <rect width={box.w} height={box.h} rx={4} />
                    <text x={box.w / 2} y={box.h / 2} textAnchor="middle" dominantBaseline="central">{box.text}</text>
                  </g>
                );
              });
            })()}</g>
          </svg>
        </div>
        <div className="globeLegend">
          <span><i className="globeLegendDot online" />在线服务器</span>
          <span><i className="globeLegendDot partial" />部分在线</span>
          <span><i className="globeLegendDot offline" />离线服务器</span>
          <span><i className="globeLegendLine" />启用链路</span>
          <span><i className="globeLegendLine disabled" />停用链路</span>
        </div>
      </div>
      <aside className="globeSidebar">
        {selected && <div className="globeSelection">
          <div className="globeSelectionHead"><strong>{selected.name}</strong><Status value={selected.status || "pending"} /></div>
          <p>{[selected.country, selected.region, selected.city].filter(Boolean).join(" · ") || "未填写位置"} · {selectedPlace?.precision === "city" ? "按城市定位" : selectedPlace ? "按国家定位" : "未定位"}</p>
          <div className="globeSelectionActions"><button type="button" onClick={() => goTo("servers", "", { q: selected.name })}>查看服务器</button></div>
          {selectionPeers.length > 1 && <div className="globeSelectionPeers">
            <span className="globeSelectionPeersHead">
              {selectedCluster && !selectedCluster.coLocated ? `当前聚合点（${selectionPeers.length} 台）` : `同一位置（${selectionPeers.length} 台）`}
            </span>
            <div className="globeServerList">{selectionPeers.map((peer) => renderServerButton(peer, true))}</div>
          </div>}
          {selectedRoutes.length > 0 && <div className="globeRelated"><span>经过此服务器的链路</span>{selectedRoutes.map((route) => <button type="button" key={route.id} onClick={() => goTo("routes", "", { q: route.name })}>{route.name}</button>)}</div>}
        </div>}
        <div className="globeListHead"><h3>服务器</h3><span>{servers.length} 台</span></div>
        <div className="globeServerList">{servers.map((server) => renderServerButton(server, false))}</div>
        {missing.length > 0 && <p className="globeFootnote">{missing.length} 台服务器的国家代码无坐标，已在列表中显示。</p>}
      </aside>
    </div>
    <p className="globeFootnote">地图位置为城市或国家级估算，不代表服务器 IP 的实际定位。数据随页面打包，浏览时不请求第三方地图服务。</p>
  </section>);
}
