import { useLayoutEffect, useMemo, useRef, useState } from "react";
import type { Node, Route, RouteHop, Server } from "../api";
import { useApp } from "../app/context";

export type RoutePoint = NonNullable<Route["edgeLatencies"]>[number];
export type LinkTone = "good" | "bad" | "pending" | "off";

const nodeWidth = 172, nodeHeight = 36, rowHeight = 48, padX = 16, padY = 34, minGap = 76;

export function routeKeys(route: Route): string[][] {
  return [[`s:${route.entryServerId}`], ...route.hops.map((hop) => hop.serverIds.map((id) => `s:${id}`)), [`n:${route.nodeId}`]];
}

export function hopUsesInternal(hop: RouteHop, serverId: string) {
  return hop.addressModes?.[serverId] === "internal" || (hop.addressModes?.[serverId] !== "public" && hop.internal);
}

// Mirrors hopAddress on the panel: the address the previous hop connects to.
export function routeAddress(server: Server | undefined, internal: boolean) {
  if (!server) return "";
  if (internal) return server.internalAddress;
  return (server.autoSyncPublicIp && server.domain) || server.ipv4 || server.ipv6 || server.domain;
}

export function linkTone(points: (RoutePoint | undefined)[], enabled: boolean): LinkTone {
  if (!enabled) return "off";
  if (points.some((point) => point && !point.ok)) return "bad";
  return points.length && points.every((point) => point?.ok) ? "good" : "pending";
}

type MapNode = { key: string; label: string; meta: string; col: number; x: number; y: number; entry: boolean };
type MapEdge = { id: string; from: string; to: string; routes: string[]; tone: LinkTone; label: string; path: string; midX: number; midY: number; width: number };

// Layered graph: a server sits right of everything that sends to it, so
// routes that meet at a shared transit visibly converge on one box.
function layout(routes: Route[], nodes: Node[], servers: Server[], serverName: (id: string) => string, width: number) {
  const known = routes.filter((route) => nodes.some((n) => n.id === route.nodeId));
  const paths = known.map(routeKeys);
  const pairs = paths.flatMap((stages) => stages.slice(1).flatMap((stage, i) => stage.flatMap((to) => stages[i].map((from) => [from, to] as [string, string]))));
  const next = new Map<string, string[]>();
  for (const [from, to] of pairs) next.set(from, [...(next.get(from) || []), to]);
  // Routes may run in opposite directions, so A → B and B → A can coexist.
  // Layer on the graph without its back edges; those are still drawn.
  const state = new Map<string, "open" | "done">();
  const forward: [string, string][] = [];
  const visit = (key: string) => {
    state.set(key, "open");
    for (const to of next.get(key) || []) {
      if (state.get(to) === "open") continue;
      forward.push([key, to]);
      if (!state.has(to)) visit(to);
    }
    state.set(key, "done");
  };
  for (const stages of paths) if (!state.has(stages[0][0])) visit(stages[0][0]);
  const col = new Map<string, number>([...state.keys()].map((key) => [key, 0]));
  for (let pass = 0; pass < state.size; pass++) {
    for (const [from, to] of forward) col.set(to, Math.max(col.get(to)!, col.get(from)! + 1));
  }
  const last = Math.max(0, ...col.values());
  for (const key of col.keys()) if (key.startsWith("n:")) col.set(key, last);
  const used = [...new Set(col.values())].sort((a, b) => a - b);
  const columns: string[][] = used.map(() => []);
  for (const stages of paths) for (const stage of stages) for (const key of stage) {
    const list = columns[used.indexOf(col.get(key)!)];
    if (!list.includes(key)) list.push(key);
  }
  // Barycentre sweeps keep connected boxes level and reduce crossings.
  for (let sweep = 0; sweep < 6; sweep++) {
    const position = new Map(columns.flatMap((list) => list.map((key, i) => [key, i - (list.length - 1) / 2] as [string, number])));
    const leftToRight = sweep % 2 === 0;
    columns.forEach((list) => {
      const weight = new Map(list.map((key) => {
        const near = pairs.filter(([from, to]) => (leftToRight ? to : from) === key).map(([from, to]) => position.get(leftToRight ? from : to)!);
        return [key, near.length ? near.reduce((sum, value) => sum + value, 0) / near.length : position.get(key)!] as [string, number];
      }));
      list.sort((a, b) => weight.get(a)! - weight.get(b)!);
    });
  }
  const tallest = Math.max(1, ...columns.map((list) => list.length));
  const count = Math.max(columns.length, 1);
  const gap = count > 1 ? Math.max(minGap, (width - padX * 2 - count * nodeWidth) / (count - 1)) : 0;
  const entries = new Set(known.map((route) => `s:${route.entryServerId}`));
  const placed = new Map<string, MapNode>();
  columns.forEach((list, c) => list.forEach((key, i) => {
    const node = key.startsWith("n:") ? nodes.find((n) => n.id === key.slice(2)) : undefined;
    const serverId = node ? node.serverId : key.slice(2);
    const server = servers.find((s) => s.id === serverId);
    // One box per server, but routes may reach it at different addresses.
    const reached = node
      ? known.filter((route) => route.nodeId === node.id).map((route) => route.nodeInternal)
      : known.flatMap((route) => route.hops).filter((hop) => hop.serverIds.includes(serverId)).map((hop) => hopUsesInternal(hop, serverId));
    const address = [...new Set((reached.length ? reached : [false]).map((internal) => routeAddress(server, !!internal)))].filter(Boolean).join(" / ");
    placed.set(key, {
      key, col: c, entry: entries.has(key), label: node ? node.name : serverName(key.slice(2)),
      meta: node ? `${address} · ${serverName(node.serverId)}` : address,
      x: padX + c * (nodeWidth + gap), y: padY + (tallest - list.length) * rowHeight / 2 + i * rowHeight,
    });
  }));
  const grouped = new Map<string, { from: string; to: string; routes: Route[]; points: (RoutePoint | undefined)[] }>();
  known.forEach((route, r) => paths[r].slice(1).forEach((stage, i) => stage.forEach((to) => paths[r][i].forEach((from) => {
    const id = `${from}>${to}`;
    const item = grouped.get(id) || { from, to, routes: [], points: [] };
    if (!item.routes.includes(route)) item.routes.push(route);
    const target = to.startsWith("n:") ? nodes.find((n) => n.id === to.slice(2))?.serverId : to.slice(2);
    if (route.enabled) item.points.push(route.edgeLatencies?.find((point) => point.fromServerId === from.slice(2) && point.toServerId === target));
    grouped.set(id, item);
  }))));
  const edges: MapEdge[] = [...grouped.entries()].map(([id, item]) => {
    const a = placed.get(item.from)!, b = placed.get(item.to)!;
    const x1 = a.x + nodeWidth, y1 = a.y + nodeHeight / 2, x2 = b.x, y2 = b.y + nodeHeight / 2;
    const bend = Math.max(36, Math.abs(x2 - x1) / 2);
    const measured = item.points.filter((point): point is RoutePoint => !!point?.ok).map((point) => point.tcpMs);
    const enabled = item.routes.some((route) => route.enabled);
    const tone = linkTone(item.points, enabled);
    return {
      id, from: item.from, to: item.to, routes: item.routes.map((route) => route.id), tone,
      label: tone === "bad" ? "失败" : measured.length ? `${Math.min(...measured)} ms` : "",
      path: `M${x1} ${y1} C${x1 + bend} ${y1} ${x2 - bend} ${y2} ${x2} ${y2}`,
      midX: (x1 + x2) / 2, midY: (y1 + y2) / 2, width: 1.5 + Math.min(item.routes.length - 1, 3) * .75,
    };
  });
  const columnLabels = columns.map((_, c) => c === 0 ? "入口" : c === count - 1 ? "落地" : `中转 ${c}`);
  return {
    placed: [...placed.values()], edges, columnLabels,
    columnX: columns.map((_, c) => padX + c * (nodeWidth + gap) + nodeWidth / 2),
    width: padX * 2 + count * nodeWidth + (count - 1) * gap,
    height: padY + tallest * rowHeight + 2,
  };
}

export function RouteMap({ routes, focus, onFocus }: {
  routes: Route[];
  focus: string;
  onFocus: (key: string) => void;
}) {
  const { nodes, servers, serverName, protect } = useApp();
  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  const [hover, setHover] = useState("");
  useLayoutEffect(() => {
    if (!box.current) return;
    const observer = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width));
    observer.observe(box.current);
    return () => observer.disconnect();
  }, []);
  const map = useMemo(() => layout(routes, nodes, servers, serverName, width), [routes, nodes, servers, serverName, width]);
  const lit = useMemo(() => {
    const key = hover || focus;
    if (!key) return null;
    return new Set(routes.filter((route) => routeKeys(route).flat().includes(key)).map((route) => route.id));
  }, [routes, hover, focus]);
  const edgeLit = (edge: MapEdge) => !lit || edge.routes.some((id) => lit.has(id));
  const nodeLit = (key: string) => !lit || routes.some((route) => lit.has(route.id) && routeKeys(route).flat().includes(key));
  return protect(<div className="routeMap" ref={box}>
    <div className="routeMapCanvas" style={{ width: map.width, height: map.height }}>
      {map.columnLabels.map((label, i) => <span key={label} className="routeMapColumn" style={{ left: map.columnX[i] }}>{label}</span>)}
      <svg width={map.width} height={map.height} aria-hidden="true">
        {map.edges.map((edge) => <path key={edge.id} d={edge.path} strokeWidth={edge.width} className={`routeMapEdge tone-${edge.tone}${edgeLit(edge) ? "" : " dim"}${lit && edgeLit(edge) ? " flowing" : ""}`} />)}
      </svg>
      {lit && map.edges.filter((edge) => edgeLit(edge) && edge.label).map((edge) => <span key={edge.id} className={`routeMapLabel tone-${edge.tone}`} style={{ left: edge.midX, top: edge.midY }}>{edge.label}</span>)}
      {map.placed.map((item) => <button key={item.key} type="button" aria-pressed={focus === item.key}
        className={`routeMapNode${item.entry ? " entry" : ""}${item.key.startsWith("n:") ? " exit" : ""}${focus === item.key ? " selected" : ""}${nodeLit(item.key) ? "" : " dim"}`}
        style={{ left: item.x, top: item.y, width: nodeWidth, height: nodeHeight }} title={item.meta ? `${item.label}（${item.meta}）` : item.label}
        onClick={() => onFocus(focus === item.key ? "" : item.key)} onMouseEnter={() => setHover(item.key)} onMouseLeave={() => setHover("")}>
        <span className="routeMapNodeName">{item.label}</span>
        {item.meta && <span className="routeMapNodeMeta">{item.meta}</span>}
      </button>)}
    </div>
  </div>);
}
