import { useEffect, useMemo, useState } from "react";
import { api, mutation, type Operation, type Server } from "../api";
import { useApp } from "../app/context";
import { emptyRule, hostRuleAdmitsSSH, hostRuleConvertible, hostRuleRemovable, manualFirewall, parseHostRule, type HostRule } from "../app/helpers";
import { Empty, HelpTip, kindLabel, Status, TableWrap } from "../app/ui";
import { useServerParam } from "../app/url";

export default function Firewall() {
  const { servers, nodes, rules, forwards, refreshTick, pollTick, act, setConfirmation, openModal, deleteItem, nodeAccessText, protect } = useApp();
  const [firewallServer, setServer] = useServerParam();
  const [fwHistory, setFwHistory] = useState<Operation[]>([]),
    [fwHistoryServerId, setFwHistoryServerId] = useState(""),
    [fwHistoryError, setFwHistoryError] = useState("");
  const fwServer = useMemo(() => servers.find((s) => s.id === firewallServer) || servers[0], [servers, firewallServer]);
  useEffect(() => {
    if (!fwServer?.id) return;
    const serverId = fwServer.id;
    let active = true;
    setFwHistoryServerId((current) => current === serverId ? current : "");
    setFwHistoryError("");
    Promise.all(["firewall.apply", "ufw.init", "ufw.delete"].map((kind) =>
      api<Operation[]>(`/api/operations?serverId=${encodeURIComponent(serverId)}&kind=${kind}&limit=8`),
    )).then((groups) => {
      if (!active) return;
      setFwHistory(groups.flat().sort((a, b) => b.id.localeCompare(a.id)).slice(0, 8));
      setFwHistoryServerId(serverId);
    }).catch((e) => {
      if (!active) return;
      setFwHistoryError((e as Error).message);
      setFwHistoryServerId(serverId);
    });
    return () => { active = false; };
  }, [fwServer?.id, refreshTick, pollTick]);
  const fwNodes = useMemo(() => nodes.filter(
    (n) => n.serverId === fwServer?.id && n.enabled && !n.deleting,
  ), [nodes, fwServer]);
  const fwRules = useMemo(() => rules.filter((r) => r.serverId === fwServer?.id), [rules, fwServer]);
  // Host rules ticked for a batch action, by rule text. Only rules still
  // reported and removable count, so a refreshed list drops stale picks.
  const [hostPicked, setHostPicked] = useState<string[]>([]);
  const fwHostRules = useMemo(
    () => (fwServer?.ufwRules || []).map((line) => ({ line, rule: parseHostRule(line) })),
    [fwServer],
  );
  const hostSelectable = useMemo(
    () => fwHostRules.flatMap(({ rule }) => (rule && hostRuleRemovable(rule, fwServer?.sshPorts || []) ? [rule] : [])),
    [fwHostRules, fwServer],
  );
  const hostSelected = useMemo(() => hostSelectable.filter((r) => hostPicked.includes(r.rule)), [hostSelectable, hostPicked]);
  useEffect(() => setHostPicked([]), [fwServer?.id]);
  const editHostRule = (server: Server, r: HostRule) => {
    openModal({ kind: "rule", form: {
      ...emptyRule, serverId: server.id, portFrom: r.portFrom, portTo: r.portTo, network: r.network || "tcp+udp",
      source: r.source === "Anywhere" ? "" : r.source, action: r.action === "DENY" ? "deny" : "allow", comment: "", replaceHostRule: r.rule,
      family: r.v6 ? "ipv6" : "ipv4",
    } });
  };
  // One job for the whole batch: the agent removes every rule, each with its
  // IPv6 twin, or none of them if one is refused.
  const deleteHostRules = (server: Server, list: HostRule[]) => {
    setConfirmation({
      title: "删除主机规则",
      message: `确定从「${server.name}」删除以下 ${list.length} 条 UFW 规则？\n${list.map((r) => r.rule).join("\n")}\n每行单独删除：删除 IPv6 规则不影响同端口的 IPv4 规则，反之亦然。`,
      confirmLabel: "删除",
      onConfirm: () => {
        void act(async () => {
          await mutation("/api/servers/" + server.id + "/ufw/delete", "POST", { rules: list.map((r) => r.rule) });
          setHostPicked([]);
        }, "删除任务已排队，Agent 执行后列表会更新");
      },
    });
  };
  const adoptHostRules = (server: Server, list: HostRule[]) => {
    setConfirmation({
      title: "转为面板管理",
      message: `将以下 ${list.length} 条规则按原端口、协议、来源和动作转为自定义规则？\n${list.map((r) => r.rule).join("\n")}\n主机上的原规则会先删除，再由面板写回并在以后管理。`,
      confirmLabel: "转换",
      onConfirm: () => {
        void act(async () => {
          await mutation("/api/servers/" + server.id + "/ufw/adopt", "POST", { rules: list.map((r) => r.rule) });
          setHostPicked([]);
        }, "已提交：先删除主机原规则，再由面板写回");
      },
    });
  };
  return protect(<>
          <>
            <div className="filters">
              <select
                value={fwServer?.id || ""}
                aria-label="选择服务器" onChange={(e) => setServer(e.target.value)}
              >
                {servers.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
              {fwServer && (
                <Status
                  value={
                    manualFirewall(fwServer) ? "manual" : fwServer.firewallConflict ? "conflict" : fwServer.ufwStatus
                  }
                />
              )}
            </div>
            {manualFirewall(fwServer) && <div className="banner warning">该服务器为手动管理防火墙，此页规则仅供查看。面板不修改 UFW；节点及转发端口、指定来源和仅链路访问限制，请在宿主机、防火墙或安全组自行配置。</div>}
            {fwServer?.firewallConflict && !manualFirewall(fwServer) && (
              <div className="banner warning">
                {fwServer.firewallConflict}{" "}
                正在管理这台服务器的防火墙。为避免两套规则互相覆盖，面板不会写入
                UFW；请先停用它。
              </div>
            )}
            <fieldset className="firewallControls" disabled={manualFirewall(fwServer)}>
            <section className="panel">
              <div className="panelHead">
                <div>
                  <h2>自定义规则</h2>
                  <p>拒绝规则排在允许规则之前；不能拒绝 SSH 端口</p>
                </div>
                <button
                  className="primary"
                  disabled={!fwServer}
                  onClick={() => openModal({ kind: "rule", form: { ...emptyRule, serverId: fwServer?.id || "" } })}
                >
                  新建规则
                </button>
              </div>
              <TableWrap>
                <table>
                  <thead>
                    <tr>
                      <th>端口</th>
                      <th>协议</th>
                      <th>地址族</th>
                      <th>来源</th>
                      <th>动作</th>
                      <th>备注</th>
                      <th>状态</th>
                      <th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fwRules.map((r) => (
                      <tr key={r.id}>
                        <td className="mono">
                          {r.portFrom}
                          {r.portTo > r.portFrom ? `-${r.portTo}` : ""}
                        </td>
                        <td>{r.network.toUpperCase()}</td>
                        <td>{r.family === "ipv4" ? "IPv4" : r.family === "ipv6" ? "IPv6" : r.source ? (r.source.includes(":") ? "IPv6" : "IPv4") : "IPv4 + IPv6"}</td>
                        <td className="mono">{r.source || "任意"}</td>
                        <td>
                          <span
                            className={
                              "chip " + (r.action === "deny" ? "red" : "")
                            }
                          >
                            {r.action === "deny" ? "拒绝" : "允许"}
                          </span>
                        </td>
                        <td>{r.comment}</td>
                        <td>
                          <Status value={r.deleting ? "deleting" : r.status} />
                        </td>
                        <td>
                          <div className="actions">
                            <button disabled={r.deleting} onClick={() => openModal({ kind: "rule", form: { ...r } })}>修改</button>
                            <button
                              className="dangerText"
                              onClick={() =>
                                deleteItem("/api/firewall/" + r.id, "规则")
                              }
                            >
                              删除
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!fwRules.length && <Empty text="暂无自定义规则" />}
              </TableWrap>
            </section>
            <section className="panel">
              <div className="panelHead">
                <div>
                  <h2>节点自动规则</h2>
                  <p>按节点设置放行来源；手动管理的节点不创建自动规则</p>
                </div>
              </div>
              <TableWrap>
                <table>
                  <thead>
                    <tr>
                      <th>节点</th>
                      <th>端口</th>
                      <th>协议</th>
                      <th>放行来源</th>
                      <th>状态</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fwNodes.map((n) => (
                      <tr key={n.id}>
                        <td>{n.name}</td>
                        <td className="mono">{n.port}</td>
                        <td>{n.protocol === "ss" ? "TCP + UDP" : "TCP"}</td>
                        <td className="mono">{nodeAccessText(n)}</td>
                        <td>
                          <Status value={n.status} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!fwNodes.length && <Empty text="该服务器没有启用的节点" />}
              </TableWrap>
            </section>
            <section className="panel">
              <div className="panelHead">
                <div>
                  <h2>主机现有规则</h2>
                  <p>
                    Agent 读取的 <span className="mono">ufw status</span>
                    。主机上手动添加的规则可勾选后批量删除，或转为面板管理的自定义规则；面板生成的规则请在对应位置修改
                    {fwServer?.sshPorts?.length
                      ? `；SSH 端口 ${fwServer.sshPorts.join("、")}`
                      : ""}
                  </p>
                </div>
                {fwServer && hostSelectable.length > 0 && (
                  <div className="actions">
                    <button
                      disabled={!hostSelected.length || !hostSelected.every(hostRuleConvertible)}
                      title={hostSelected.every(hostRuleConvertible) ? "按原端口、协议、来源和动作转为自定义规则；TCP + UDP 会拆成两条" : "所选规则中有无端口、应用配置或 REJECT/LIMIT 规则，不能直接转换"}
                      onClick={() => adoptHostRules(fwServer, hostSelected)}
                    >转为面板管理{hostSelected.length ? `（${hostSelected.length}）` : ""}</button>
                    <button className="dangerText" disabled={!hostSelected.length} onClick={() => deleteHostRules(fwServer, hostSelected)}>
                      删除所选{hostSelected.length ? `（${hostSelected.length}）` : ""}
                    </button>
                  </div>
                )}
              </div>
              {fwServer?.ufwRules?.length ? (
                <TableWrap>
                  <table>
                    <thead><tr>
                      <th>
                        <input
                          type="checkbox"
                          aria-label="全选可处理的规则"
                          disabled={!hostSelectable.length}
                          checked={hostSelectable.length > 0 && hostSelected.length === hostSelectable.length}
                          onChange={(e) => setHostPicked(e.target.checked ? hostSelectable.map((r) => r.rule) : [])}
                        />
                      </th>
                      <th>编号</th><th>规则</th><th>归属</th><th>操作</th>
                    </tr></thead>
                    <tbody>
                      {fwHostRules.map(({ line, rule: r }) => {
                        if (!r) return <tr key={line}><td /><td /><td className="mono" colSpan={3}>{line}</td></tr>;
                        const custom = r.tag.startsWith("mui-") ? fwRules.find((x) => "mui-" + x.id === r.tag) : undefined;
                        const node = r.tag.startsWith("mui-node-") ? nodes.find((n) => r.tag.startsWith("mui-node-" + n.id + "-")) : undefined;
                        const fwd = r.tag.startsWith("mui-forward-") ? forwards.find((f) => r.tag.startsWith("mui-forward-" + f.id + "-")) : undefined;
                        const owner = r.tag === "mui-ssh" ? "SSH（初始化 UFW 时创建）"
                          : custom ? "自定义规则"
                          : node ? `节点 ${node.name}`
                          : fwd ? `${fwd.routeId ? "链路转发" : "转发"} ${fwd.name}`
                          : r.tag.startsWith("mui-route-priority-") ? "节点 / 链路优先规则"
                          : r.tag.startsWith("panel-") ? "旧版面板规则，下次应用时清理"
                          : r.tag ? "面板规则（对象已删除，下次应用时清理）"
                          : "主机手动添加";
                        const ssh = !r.tag && hostRuleAdmitsSSH(r, fwServer.sshPorts || []);
                        const editable = hostRuleConvertible(r);
                        const removable = hostRuleRemovable(r, fwServer.sshPorts || []);
                        return (
                          <tr key={line}>
                            <td>
                              {removable && (
                                <input
                                  type="checkbox"
                                  aria-label={`选择规则 ${r.index}`}
                                  checked={hostPicked.includes(r.rule)}
                                  onChange={(e) => setHostPicked(e.target.checked ? [...hostPicked, r.rule] : hostPicked.filter((x) => x !== r.rule))}
                                />
                              )}
                            </td>
                            <td className="mono">{r.index}</td>
                            <td className="mono">{r.rule.replace(/\s*#.*$/, "")}</td>
                            <td>{owner}</td>
                            <td>
                              {custom ? (
                                <div className="actions">
                                  <button disabled={custom.deleting} onClick={() => openModal({ kind: "rule", form: { ...custom } })}>修改</button>
                                  <button className="dangerText" onClick={() => deleteItem("/api/firewall/" + custom.id, "规则")}>删除</button>
                                </div>
                              ) : r.tag ? (
                                <span className="hint">—</span>
                              ) : ssh ? (
                                <span className="actions"><span className="hint">SSH 保护</span><HelpTip label={`规则 ${r.index} 的 SSH 保护`} text="这条规则可能放行 SSH 端口。为防止远程失联，面板禁止修改和删除；请登录服务器用 UFW 手动调整。" /></span>
                              ) : (
                                <div className="actions">
                                  {editable ? <button
                                    title={r.network ? "改为面板管理的自定义规则，原规则会被删除" : "接管后拆成 TCP 和 UDP 两条面板规则，原规则会被删除"}
                                    onClick={() => editHostRule(fwServer, r)}
                                  >修改</button> : <span className="actions"><span className="hint">需在主机修改</span><HelpTip label={`规则 ${r.index} 不能接管`} text="无端口、应用配置或 REJECT/LIMIT 规则不能转为面板自定义规则；可登录服务器用 UFW 修改。" /></span>}
                                  <button className="dangerText" onClick={() => deleteHostRules(fwServer, [r])}>删除</button>
                                </div>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </TableWrap>
              ) : (
                <Empty text="Agent 尚未上报规则，或 UFW 未启用" />
              )}
            </section>
            <section className="panel">
              <div className="panelHead">
                <div>
                  <h2>变更历史</h2>
                  <p>最近的防火墙任务；节点变更引起的规则调整见操作记录</p>
                </div>
              </div>
              {fwHistoryServerId !== fwServer?.id ? (
                <Empty text="正在读取防火墙变更…" />
              ) : fwHistoryError ? (
                <div className="banner error" role="alert">读取变更历史失败：{fwHistoryError}</div>
              ) : fwHistory.length ? (
                fwHistory.map((o) => (
                  <div className="listRow" key={o.id}>
                    <div className="grow">
                      <strong>{kindLabel(o.kind)}</strong>
                      <small>
                        {new Date(o.createdAt).toLocaleString()}
                        {o.error ? " · " + o.error : ""}
                      </small>
                    </div>
                    <Status value={o.status} />
                  </div>
                ))
              ) : (
                <Empty text="暂无防火墙变更" />
              )}
            </section>
            </fieldset>
          </>
  </>);
}
