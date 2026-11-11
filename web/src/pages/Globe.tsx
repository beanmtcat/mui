import { useEffect, useMemo, useRef, useState } from "react";
import { geoDistance, geoEquirectangular, geoGraticule10, geoInterpolate, geoOrthographic, geoPath } from "d3-geo";
import type { FeatureCollection, LineString } from "geojson";
import type { Server } from "../api";
import { useApp } from "../app/context";
import { routeSegments, serverPlace, type Point, type ServerPlace } from "../app/geo";
import { Status } from "../app/ui";
import world from "../globe-data/world-110m.json";

const land = world as unknown as FeatureCollection;
const graticule = geoGraticule10();
const WIDTH = 960, HEIGHT = 600;
const FLAT_SCALE = 148;
const FLAT_LON = 150;
const DRAG_THRESHOLD = 5;
type ViewMode = "globe" | "flat";
type LocationGroup = { key: string; point: Point; servers: Server[]; precision: "city" | "country" };
type DragStart = { pointerId: number; pointerType: string; x: number; y: number; center: Point; mode: ViewMode; moved: boolean };

function locationGroups(servers: Server[], locations: Map<string, ServerPlace | null>) {
  const groups = new Map<string, LocationGroup>();
  const missing: Server[] = [];
  for (const server of servers) {
    const place = locations.get(server.id);
    if (!place) { missing.push(server); continue; }
    const key = place.point.join(":");
    const group = groups.get(key) || { key, point: place.point, servers: [], precision: place.precision };
    group.servers.push(server);
    groups.set(key, group);
  }
  return { groups: [...groups.values()], missing };
}

function wrapLongitude(value: number) {
  return ((((value + 180) % 360) + 360) % 360) - 180;
}

function clampFlatCenter(point: Point, zoom: number): Point {
  const scale = FLAT_SCALE * zoom;
  const lonLimit = Math.max(0, 180 - WIDTH / (2 * scale) * 180 / Math.PI);
  const latLimit = Math.max(0, 90 - HEIGHT / (2 * scale) * 180 / Math.PI);
  return [Math.max(-lonLimit, Math.min(lonLimit, point[0])), Math.max(-latLimit, Math.min(latLimit, point[1]))];
}

function toFlatCenter(point: Point, zoom: number): Point {
  return clampFlatCenter([wrapLongitude(point[0] - FLAT_LON), point[1]], zoom);
}

export default function Globe() {
  const { servers, nodes, routes, serverName, goTo, currentServerId, protect } = useApp();
  const [mode, setMode] = useState<ViewMode>("globe");
  const [center, setCenter] = useState<Point>([110, 24]);
  const [flatCenter, setFlatCenter] = useState<Point>([0, 0]);
  const [zoom, setZoom] = useState(1);
  const [routeId, setRouteId] = useState("");
  const [includeDisabled, setIncludeDisabled] = useState(false);
  const selectedServerId = currentServerId;
  const dragging = useRef<DragStart | null>(null);
  const suppressClick = useRef(false);
  const locations = useMemo(() => new Map(servers.map((server) => [server.id, serverPlace(server)])), [servers]);
  const { groups, missing } = useMemo(() => locationGroups(servers, locations), [servers, locations]);
  const segments = useMemo(() => routeSegments(routes, nodes, includeDisabled, routeId)
    .filter((segment) => Boolean(locations.get(segment.from) && locations.get(segment.to))),
  [routes, nodes, includeDisabled, routeId, locations]);
  const selected = servers.find((server) => server.id === selectedServerId);
  const selectedPlace = selected ? locations.get(selected.id) ?? null : null;
  useEffect(() => {
    if (selectedPlace) setCenter(selectedPlace.point);
  }, [selected?.id, selected?.country, selected?.region, selected?.city]);
  useEffect(() => {
    if (mode !== "flat") return;
    setFlatCenter((current) => selectedPlace ? toFlatCenter(selectedPlace.point, zoom) : clampFlatCenter(current, zoom));
  }, [mode, zoom, selected?.id, selected?.country, selected?.region, selected?.city]);
  const selectedGroup = groups.find((group) => group.servers.some((server) => server.id === selectedServerId));
  const selectedRoutes = selected ? routes.filter((route) => routeSegments([route], nodes, true, "")
    .some((segment) => segment.from === selected.id || segment.to === selected.id)) : [];
  const highlightedIds = routeId ? new Set(segments.flatMap((segment) => [segment.from, segment.to])) : null;

  const projection = mode === "globe"
    ? geoOrthographic().translate([WIDTH / 2, HEIGHT / 2]).scale(279 * zoom).rotate([-center[0], -center[1]]).clipAngle(90)
    : geoEquirectangular().translate([WIDTH / 2, HEIGHT / 2]).rotate([-FLAT_LON, 0]).center(flatCenter).scale(FLAT_SCALE * zoom).clipExtent([[0, 0], [WIDTH, HEIGHT]]);
  const path = geoPath(projection);
  const sphere = path({ type: "Sphere" }) || "";
  const grid = path(graticule) || "";
  const visible = (point: Point) => mode === "flat" || geoDistance(point, center) < Math.PI / 2 - 0.005;
  const focus = (server: Server) => {
    goTo("globe", server.id);
    const place = locations.get(server.id);
    if (place) {
      setCenter(place.point);
      setFlatCenter(toFlatCenter(place.point, zoom));
    }
  };
  const arc = (from: Point, to: Point) => {
    if (from[0] === to[0] && from[1] === to[1]) {
      if (!visible(from)) return "";
      const projected = projection(from);
      if (!projected) return "";
      const [x, y] = projected;
      return `M${x - 4},${y - 4} C${x - 24},${y - 30} ${x + 24},${y - 30} ${x + 4},${y - 4}`;
    }
    const between = geoInterpolate(from, to);
    const line: LineString = { type: "LineString", coordinates: Array.from({ length: 33 }, (_, i) => between(i / 32)) };
    return path(line) || "";
  };

  return protect(<section className="panel globePage">
    <div className="panelHead">
      <div>
        <h2>全球网络</h2>
        <p>按服务器档案的位置展示；连线依次经过入口、中转和落地。球面可拖动旋转，平面可拖动平移。</p>
      </div>
      <div className="globeCounts"><strong>{servers.length}</strong> 台服务器 <span>·</span> <strong>{routes.length}</strong> 条链路</div>
    </div>
    <div className="globeToolbar">
      <div className="globeMode" role="group" aria-label="地图视图">
        <button type="button" className={mode === "globe" ? "active" : ""} aria-pressed={mode === "globe"} onClick={() => setMode("globe")}>球面</button>
        <button type="button" className={mode === "flat" ? "active" : ""} aria-pressed={mode === "flat"} onClick={() => setMode("flat")}>平面</button>
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
      <div className="globeZoom" role="group" aria-label="缩放地图">
        <button type="button" aria-label="缩小" disabled={zoom <= 0.75} onClick={() => setZoom((value) => Math.max(0.75, +(value - 0.15).toFixed(2)))}>−</button>
        <button type="button" aria-label="放大" disabled={zoom >= 1.55} onClick={() => setZoom((value) => Math.min(1.55, +(value + 0.15).toFixed(2)))}>+</button>
      </div>
    </div>
    <div className="globeLayout">
      <div className={`globeCanvas ${mode}`}>
        <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} role="group" aria-label="服务器与链路地图"
          onPointerDown={(event) => {
            suppressClick.current = false;
            // Let the browser handle touch scrolling in the flat view.
            if (event.button !== 0 || (mode === "flat" && event.pointerType === "touch")) return;
            dragging.current = { pointerId: event.pointerId, pointerType: event.pointerType,
              x: event.clientX, y: event.clientY, center: mode === "globe" ? center : flatCenter, mode, moved: false };
          }}
          onPointerMove={(event) => {
            const start = dragging.current;
            if (!start || start.pointerId !== event.pointerId) return;
            const dx = event.clientX - start.x, dy = event.clientY - start.y;
            if (!start.moved) {
              if (Math.hypot(dx, dy) < DRAG_THRESHOLD) return;
              // A vertical touch swipe belongs to the page, not the globe.
              if (start.pointerType === "touch" && Math.abs(dy) > Math.abs(dx)) { dragging.current = null; return; }
              start.moved = true;
              event.currentTarget.setPointerCapture(event.pointerId);
            }
            if (start.mode === "globe") {
              setCenter([wrapLongitude(start.center[0] - dx * 0.32), Math.max(-82, Math.min(82, start.center[1] + dy * 0.32))]);
            } else {
              const rect = event.currentTarget.getBoundingClientRect();
              const degreesPerPixel = 180 / Math.PI / (FLAT_SCALE * zoom);
              setFlatCenter(clampFlatCenter([
                start.center[0] - dx * WIDTH / rect.width * degreesPerPixel,
                start.center[1] + dy * HEIGHT / rect.height * degreesPerPixel,
              ], zoom));
            }
          }}
          onPointerUp={(event) => {
            if (dragging.current?.pointerId === event.pointerId && dragging.current.moved) suppressClick.current = true;
            dragging.current = null;
            if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
          }}
          onPointerCancel={() => { dragging.current = null; }}
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
          <g className="globeLand">{land.features.map((feature, index) => <path key={index} d={path(feature) || ""} />)}</g>
          <g className="globeLinks">{segments.map((segment) => {
            const from = locations.get(segment.from)?.point, to = locations.get(segment.to)?.point;
            if (!from || !to) return null;
            const shape = arc(from, to);
            return shape && <path key={`${segment.from}:${segment.to}`} d={shape} className={segment.active ? "globeLinkActive" : "globeLinkDisabled"}>
              <title>{`${serverName(segment.from)} → ${serverName(segment.to)} · ${segment.routeNames.join("、")}`}</title>
            </path>;
          })}</g>
          <g className="globeMarkers">{groups.map((group) => {
            if (!visible(group.point)) return null;
            const projected = projection(group.point);
            if (!projected) return null;
            const [x, y] = projected;
            const isSelected = selectedGroup?.key === group.key;
            const dimmed = highlightedIds && !group.servers.some((server) => highlightedIds.has(server.id));
            const online = group.servers.some((server) => server.status === "online");
            return <g key={group.key} className={`globeMarker${isSelected ? " selected" : ""}${dimmed ? " dimmed" : ""}${online ? " online" : ""}`}
              transform={`translate(${x},${y})`} role="button" tabIndex={0}
              aria-label={`${group.servers.map((server) => server.name).join("、")}，${group.servers.length} 台服务器`}
              onClick={() => focus(group.servers[0])}
              onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); focus(group.servers[0]); } }}>
              <circle className="globeMarkerHalo" r={group.servers.length > 1 ? 16 : 12} />
              <circle className="globeMarkerCore" r={group.servers.length > 1 ? 10 : 7} />
              {group.servers.length > 1 && <text textAnchor="middle" dominantBaseline="central">{group.servers.length}</text>}
              <title>{group.servers.map((server) => server.name).join("、")}</title>
            </g>;
          })}</g>
        </svg>
        <div className="globeLegend"><span><i className="globeLegendDot online" />在线服务器</span><span><i className="globeLegendDot offline" />离线服务器</span><span><i className="globeLegendLine" />启用链路</span><span><i className="globeLegendLine disabled" />停用链路</span></div>
      </div>
      <aside className="globeSidebar">
        {selected && <div className="globeSelection">
          <div className="globeSelectionHead"><strong>{selected.name}</strong><Status value={selected.status || "pending"} /></div>
          <p>{[selected.country, selected.region, selected.city].filter(Boolean).join(" · ") || "未填写位置"} · {selectedPlace?.precision === "city" ? "按城市定位" : selectedPlace ? "按国家定位" : "未定位"}</p>
          {selectedGroup && selectedGroup.servers.length > 1 && <p>同一位置还有 {selectedGroup.servers.length - 1} 台服务器，可在下方列表选择。</p>}
          <div className="globeSelectionActions"><button type="button" onClick={() => goTo("servers", "", { q: selected.name })}>查看服务器</button></div>
          {selectedRoutes.length > 0 && <div className="globeRelated"><span>经过此服务器的链路</span>{selectedRoutes.map((route) => <button type="button" key={route.id} onClick={() => goTo("routes", "", { q: route.name })}>{route.name}</button>)}</div>}
        </div>}
        <div className="globeListHead"><h3>服务器</h3><span>{servers.length} 台</span></div>
        <div className="globeServerList">{servers.map((server) => {
          const place = locations.get(server.id);
          return <button key={server.id} type="button" className={selectedServerId === server.id ? "selected" : ""} onClick={() => focus(server)}>
            <span className={`globeServerDot ${server.status === "online" ? "online" : ""}`} />
            <span className="globeServerInfo"><strong>{server.name}</strong><small>{[server.country, server.city || server.region].filter(Boolean).join(" · ") || "位置未填写"}{place?.precision === "country" ? " · 国家位置" : ""}</small></span>
            {!place && <span className="globeUnplaced">未定位</span>}
          </button>;
        })}</div>
        {missing.length > 0 && <p className="globeFootnote">{missing.length} 台服务器的国家代码无坐标，已在列表中显示。</p>}
      </aside>
    </div>
    <p className="globeFootnote">地图位置为城市或国家级估算，不代表服务器 IP 的实际定位。数据随页面打包，浏览时不请求第三方地图服务。</p>
  </section>);
}
