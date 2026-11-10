import { useState } from "react";
import { mutation, type SurgeTemplate } from "../api";
import { useApp } from "../app/context";
import { Empty, TableWrap } from "../app/ui";

export default function SurgeTemplates() {
  const { subs, surgeTemplates, surgeTemplatesStatus, act, protect, setConfirmation } = useApp();
  const [editing, setEditing] = useState<SurgeTemplate | null>(null);
  const [name, setName] = useState("");
  const [content, setContent] = useState("");
  const edit = (item?: SurgeTemplate) => {
    const builtin = surgeTemplates.find((x) => x.id === "default");
    if (!item && !builtin) return;
    setEditing(item || { id: "", name: "", template: builtin?.template || "" });
    setName(item?.name || "");
    setContent(item?.template || builtin?.template || "");
  };
  const save = () => void act(async () => {
    const path = editing?.id ? `/api/surge-templates/${editing.id}` : "/api/surge-templates";
    await mutation(path, editing?.id ? "PATCH" : "POST", { name, template: content });
    setEditing(null);
  }, "Surge 模板已保存");
  return protect(<section className="panel">
    <div className="panelHead">
      <div><h2>Surge 完整配置模板</h2><p>每条 Surge 订阅可选择一份模板，完整配置链接会随模板更新。</p></div>
      <button className="primary" type="button" disabled={!surgeTemplates.length} onClick={() => edit()}>新建模板</button>
    </div>
    <TableWrap><table><thead><tr><th>模板名称</th><th>使用中的订阅</th><th>操作</th></tr></thead><tbody>
      {surgeTemplates.map((item) => {
        const used = subs.filter((sub) => sub.format === "surge" && (sub.surgeTemplateId || "default") === item.id);
        return <tr key={item.id}>
          <td><strong>{item.name}</strong>{item.id === "default" && <small>{item.custom ? "已自定义；可恢复内置内容" : "内置默认；随面板版本更新"}</small>}</td>
          <td>{used.length} 条{used.length > 0 && <small>{used.map((sub) => sub.name).join("、")}</small>}</td>
          <td><div className="actions">
            <button type="button" onClick={() => edit(item)}>编辑</button>
            {item.id !== "default" && <button type="button" className="dangerText" onClick={() => setConfirmation({
              title: "删除 Surge 模板", message: `删除「${item.name}」？使用中的订阅需要先选择其他模板。`, confirmLabel: "删除",
              onConfirm: () => { void act(async () => { await mutation(`/api/surge-templates/${item.id}`, "DELETE"); if (editing?.id === item.id) setEditing(null); }, "Surge 模板已删除"); },
            })}>删除</button>}
          </div></td>
        </tr>;
      })}
    </tbody></table>{!surgeTemplates.length && <Empty text={surgeTemplatesStatus === "loading" ? "正在读取模板…" : surgeTemplatesStatus === "error" ? "模板加载失败，请点击刷新重试" : "暂无模板"} />}</TableWrap>
    {editing && <form className="surgeProfileForm" onSubmit={(e) => { e.preventDefault(); save(); }}>
      <h3>{editing.id ? `编辑「${editing.name}」` : "新建 Surge 模板"}</h3>
      <label htmlFor="surge-template-name">模板名称</label>
      <input id="surge-template-name" required maxLength={80} value={name} disabled={editing.id === "default"} onChange={(e) => setName(e.target.value)} />
      <label htmlFor="surge-template-content">完整配置内容</label>
      <textarea id="surge-template-content" required spellCheck={false} rows={22} value={content} onChange={(e) => setContent(e.target.value)} />
      <small>{"{{PROXIES}}"} 放节点行，{"{{PROXY_NAMES}}"} 放节点名；[Rule] 段须以 FINAL 结尾。#!MANAGED-CONFIG 由面板添加。保存后，使用该模板的订阅在下次更新时生效。</small>
      <div className="surgeProfileActions">
        <button className="primary" type="submit">保存模板</button>
        {editing.id === "default" && editing.custom && <button className="ghost" type="button" onClick={() => void act(async () => { await mutation("/api/surge-templates/default", "PATCH", { name: "默认模板", template: "" }); setEditing(null); }, "已恢复内置默认模板")}>恢复内置默认</button>}
        <button className="ghost" type="button" onClick={() => setEditing(null)}>取消</button>
      </div>
    </form>}
  </section>);
}
