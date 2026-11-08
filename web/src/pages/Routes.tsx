import { Fragment, useMemo, useState } from "react";
import { mutation, type Node, type Route } from "../api";
import { useApp } from "../app/context";
import { manualFirewall } from "../app/helpers";
import { ActionMenu, Empty, HelpTip, ModalShell, parseSort, sortRows, Status, statusLabels } from "../app/ui";
import { useUrlParam } from "../app/url";
import { hopUsesInternal, linkTone, routeAddress, RouteMap, routeKeys, type RoutePoint } from "./RouteMap";

type Edge = { from: string; to: string; point?: RoutePoint };

const hostHeight = 44, hostGap = 6, trackPad = 16;

function latencyLabel(point: Edge["point"]) {
  return point ? point.ok ? `${point.tcpMs} ms` : "失败" : "待测";
}

function hostCenter(index: number, count: number, height: number) {
  return height / 2 + (index - (count - 1) / 2) * (hostHeight + hostGap);
}

function RouteLine({ route, node, onServer, onNode }: {
  route: Route;
  node?: Node;
  onServer: (id: string) => void;
  onNode: () => void;
}) {
  const { protect, servers, serverName } = useApp();
  const address = (id: string, internal: boolean) => routeAddress(servers.find((s) => s.id === id), internal);
  const stages = [
    { kind: "entry", members: [route.entryServerId], tag: "" },
    ...route.hops.map((hop) => ({ kind: "transit", members: hop.serverIds, tag: hop.serverIds.length > 1 ? hop.balance === "round-robin" ? "轮询" : "主备" : "" })),
    { kind: "exit", members: node ? [node.serverId] : [], tag: "" },
  ];
  const connections = stages.slice(0, -1).map((stage, i) => stage.members.flatMap((from) => stages[i + 1].members.map((to) => ({
    from, to, point: route.edgeLatencies?.find((point) => point.fromServerId === from && point.toServerId === to),
  }))));
  const tallest = Math.max(...stages.map((stage) => stage.members.length), 1);
  const height = tallest * hostHeight + (tallest - 1) * hostGap + trackPad * 2;
  return protect(<div className="routeTrackViewport">
    <div className="routeTrack" role="group" style={{ height }} aria-label={`链路路径：${stages.map((stage) => stage.members.map(serverName).join(" / ") || "已删除节点").join(" → ")}`}>
      {stages.map((stage, i) => <Fragment key={`${stage.kind}-${i}`}>
        {i > 0 && <div className="routeFan" style={{ minWidth: connections[i - 1].length > 1 ? 104 : 76 }}>
          <svg viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" aria-hidden="true">
            {connections[i - 1].map(({ from, to, point }) => {
              const y1 = hostCenter(stages[i - 1].members.indexOf(from), stages[i - 1].members.length, height);
              const y2 = hostCenter(stage.members.indexOf(to), stage.members.length, height);
              return <path key={`${from}-${to}`} d={`M0 ${y1} C50 ${y1} 50 ${y2} 100 ${y2}`} vectorEffect="non-scaling-stroke" className={`routeFanLine tone-${linkTone([point], route.enabled)}`} />;
            })}
          </svg>
          {route.enabled && connections[i - 1].map(({ from, to, point }, n, list) => {
            const y1 = hostCenter(stages[i - 1].members.indexOf(from), stages[i - 1].members.length, height);
            const y2 = hostCenter(stage.members.indexOf(to), stage.members.length, height);
            // Lines from one host part near the far end, lines into one near the
            // start. Crossing lines spread their labels along the curves instead.
            const t = list.length < 2 ? .5 : stages[i - 1].members.length === 1 ? .72 : stage.members.length === 1 ? .28 : .3 + .4 * n / (list.length - 1);
            return <span key={`${from}-${to}`} className={`routeFanLabel tone-${linkTone([point], true)}`} style={{ left: `${t * 100}%`, top: y1 + (y2 - y1) * (3 * t * t - 2 * t * t * t) }}
              title={point ? `${serverName(from)} → ${serverName(to)}，测量于 ${new Date(point.at).toLocaleString()}` : `${serverName(from)} → ${serverName(to)}，尚无有效测量数据`}>
              <span className="routeFanPair">{serverName(from)} → {serverName(to)}</span> <strong>{latencyLabel(point)}</strong>
            </span>;
          })}
        </div>}
        <div className={`routeStage ${stage.kind}`}>
          {stage.kind === "exit" ? node ? <button type="button" className="routeHost" onClick={onNode} title={`${node.name}（${node.protocol.toUpperCase()} · ${serverName(node.serverId)} ${address(node.serverId, route.nodeInternal)}）`}>
            <span className="routeHostName">{node.name}</span>
            <span className="routeHostAddress">{address(node.serverId, route.nodeInternal)} · {serverName(node.serverId)}</span>
          </button> : <span className="routeStopMissing">节点已删除</span> : stage.members.map((id) => {
            const hop = stage.kind === "transit" ? route.hops[i - 1] : undefined;
            const internal = !!hop && hopUsesInternal(hop, id);
            return <button key={id} type="button" className="routeHost" onClick={() => onServer(id)} title={`${serverName(id)} ${address(id, internal)}`}>
              <span className="routeHostName"><span>{serverName(id)}</span>{internal && <small>内网</small>}</span>
              <span className="routeHostAddress">{address(id, internal)}</span>
            </button>;
          })}
          {stage.tag && <span className="routeStageTag" style={{ top: `calc(50% + ${(stage.members.length * hostHeight + (stage.members.length - 1) * hostGap) / 2}px)` }}>{stage.tag}</span>}
        </div>
      </Fragment>)}
    </div>
  </div>);
}

export default function Routes() {
  const { nodes, routes, servers, serverName, routePath, act, goTo, openRoute, deleteItem, matches, protect, setConfirmation } = useApp();
  const [q, setQ] = useUrlParam("q"), [status, setStatus] = useUrlParam("status");
  const [entry, setEntry] = useUrlParam("entry"), [exit, setExit] = useUrlParam("exit"), [sortValue, setSort] = useUrlParam("sort");
  const [focus, setFocus] = useState(""), [mapOpen, setMapOpen] = useState(false);
  const sort = parseSort(sortValue, setSort);
  const filtered = !!(q || status || entry || exit || focus);
  const exitByNode = useMemo(() => new Map(nodes.map((n) => [n.id, n.serverId])), [nodes]);
  const entryOptions = useMemo(() => [...new Set([...routes.map((r) => r.entryServerId), entry].filter(Boolean))]
    .sort((a, b) => serverName(a).localeCompare(serverName(b))), [routes, entry, serverName]);
  const exitOptions = useMemo(() => [...new Set([...routes.map((r) => exitByNode.get(r.nodeId) || ""), exit].filter(Boolean))]
    .sort((a, b) => serverName(a).localeCompare(serverName(b))), [routes, exit, exitByNode, serverName]);
  const matching = useMemo(() => sortRows(routes.filter((r) =>
    (!status || (r.status || "pending") === status) && (!entry || r.entryServerId === entry) &&
    (!exit || exitByNode.get(r.nodeId) === exit) && matches(q, r.name, r.notes, String(r.port), routePath(r)),
  ), sort, {
    name: (r) => r.name, port: (r) => r.port, status: (r) => r.status || "pending", node: (r) => nodes.find((n) => n.id === r.nodeId)?.name || "",
  }), [routes, nodes, q, status, entry, exit, exitByNode, sort.key, sort.descending, matches, routePath]);
  const visible = useMemo(() => focus ? matching.filter((r) => routeKeys(r).flat().includes(focus)) : matching, [matching, focus]);
  const focusName = focus.startsWith("n:") ? nodes.find((n) => n.id === focus.slice(2))?.name : focus && serverName(focus.slice(2));
  const tally = useMemo(() => {
    const count = { good: 0, bad: 0, warn: 0, idle: 0 };
    for (const r of routes) count[statusLabels[r.status || "pending"]?.[1] || "idle"]++;
    return count;
  }, [routes]);
  return protect(<section className="panel routePage">
    <div className="panelHead">
      <div>
        <h2>链路</h2>
        <p className="routeTally">
          <span>{routes.length} 条</span>
          {tally.good > 0 && <span className="good">{tally.good} 正常</span>}
          {tally.bad > 0 && <span className="bad">{tally.bad} 异常</span>}
          {tally.warn > 0 && <span className="warn">{tally.warn} 待应用</span>}
          {tally.idle > 0 && <span>{tally.idle} 未运行</span>}
          <HelpTip label="链路延迟" text="每个数值由上一跳 Agent 每分钟测量到下一跳 TCP 端口的建连时间。它不是整条链路或代理协议的往返延迟；无新数据时显示待测。" />
        </p>
      </div>
      <div className="headerActions">
        <button className="ghost" onClick={() => setMapOpen(true)} disabled={!routes.length}>拓扑图</button>
        <button className="primary" onClick={() => openRoute()} disabled={!nodes.length}>新建链路</button>
      </div>
    </div>
    <div className="filters routeFilters">
      <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="搜索链路名称、端口、服务器或备注" aria-label="搜索链路" />
      <select aria-label="按入口服务器筛选链路" value={entry} onChange={(e) => setEntry(e.target.value)}>
        <option value="">全部入口服务器</option>
        {entryOptions.map((id) => <option key={id} value={id}>{serverName(id)}</option>)}
      </select>
      <select aria-label="按落地服务器筛选链路" value={exit} onChange={(e) => setExit(e.target.value)}>
        <option value="">全部落地服务器</option>
        {exitOptions.map((id) => <option key={id} value={id}>{serverName(id)}</option>)}
      </select>
      <select aria-label="按状态筛选链路" value={status} onChange={(e) => setStatus(e.target.value)}>
        <option value="">全部状态</option>
        {[...new Set(routes.map((item) => item.status || "pending"))].sort().map((value) => <option key={value} value={value}>{statusLabels[value]?.[0] || value}</option>)}
      </select>
      <select aria-label="链路排序" value={sortValue} onChange={(e) => setSort(e.target.value)}>
        <option value="">默认排序</option>
        <option value="name">名称 A–Z</option><option value="-name">名称 Z–A</option>
        <option value="port">端口升序</option><option value="-port">端口降序</option>
        <option value="node">落地节点</option><option value="-node">落地节点倒序</option>
        <option value="status">状态</option><option value="-status">状态倒序</option>
      </select>
      {filtered && <button type="button" className="ghost" onClick={() => { setQ(""); setStatus(""); setEntry(""); setExit(""); setFocus(""); }}>清空筛选</button>}
      {filtered && <span className="hint" role="status">{focusName && `经过 ${focusName} · `}{q && `已定位：${q} · `}显示 {visible.length} / {routes.length} 条</span>}
    </div>
    <div className="routeRows">
      {visible.map((r) => {
        const node = nodes.find((n) => n.id === r.nodeId);
        const entryRestricted = r.entryFirewallPolicy === "restricted";
        const entryManual = manualFirewall(servers.find((s) => s.id === r.entryServerId));
        const entrySourceCount = r.entryFirewallSources?.split(",").filter((source) => source.trim()).length || 0;
        return <article className={`routeRow${r.enabled ? "" : " disabled"}`} key={r.id}>
          <div className="routeRowIdentity">
            <div className="routeRowTitle"><h3>{r.name}</h3><Status value={r.status || "pending"} /></div>
            <div className="routeRowMeta"><span className="mono">:{r.port}</span><span>{r.hops.length ? `${r.hops.length} 跳中转` : "直连落地"}</span></div>
            {entryRestricted && <span className="routeEntryAccess" title={entryManual ? undefined : r.entryFirewallSources}>{entryManual ? "入口限制需手动配置" : `入口限制 ${entrySourceCount} 个来源`}</span>}
            {r.notes && <p className="routeRowNotes">{r.notes}</p>}
            <div className="actions routeRowActions">
              <button onClick={() => openRoute(r)}>编辑</button>
              <ActionMenu>
                <button onClick={() => void act(() => mutation("/api/routes/" + r.id, "PATCH", { ...r, enabled: !r.enabled }), r.enabled ? "链路已停用" : "链路已启用")}>{r.enabled ? "停用" : "启用"}</button>
                <button className="dangerText" onClick={() => deleteItem("/api/routes/" + r.id, "链路")}>删除</button>
              </ActionMenu>
            </div>
          </div>
          <RouteLine route={r} node={node}
            onServer={(id) => goTo("servers", "", { q: serverName(id) })}
            onNode={() => node && goTo("nodes", node.serverId, { q: node.name })} />
          {r.error && <p className="routeRowError" role="alert">{r.error}</p>}
        </article>;
      })}
      {!visible.length && <Empty text={filtered ? "没有符合筛选条件的链路" : "暂无链路，点击右上角新建"} />}
    </div>
    {mapOpen && <ModalShell title="链路拓扑" labelledBy="route-map-title" dirty={false} onClose={() => setMapOpen(false)} onConfirm={setConfirmation}>
      <RouteMap routes={matching} focus={focus} onFocus={setFocus} />
      <p className="routeMapHint hint" role="status">{focusName ? `已筛选经过 ${focusName} 的 ${visible.length} 条链路，关闭后在列表中查看` : "点击服务器或节点可高亮路径，并筛选列表"}</p>
    </ModalShell>}
  </section>);
}
