import { useState } from "react";
import { mutation, type PingTask, type Server } from "../api";
import { useApp } from "../app/context";
import { setError } from "../app/feedback";
import { countryFlag } from "../app/helpers";
import { Field, SubmitButton, useBusy } from "../app/ui";
import { Dialog } from "./Dialog";

export type PingTaskDraft = {
  id?: string;
  name: string;
  target: string;
  intervalDraft: string;
  serverIds: string[];
};

export const emptyPingDraft: PingTaskDraft = {
  name: "",
  target: "",
  intervalDraft: "60",
  serverIds: [],
};

export function PingTaskDialog({
  initial,
  onlineServers,
  redact,
  onClose,
  onSaved,
}: {
  initial: PingTaskDraft;
  onlineServers: Server[];
  redact: (v: string) => string;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const { act } = useApp();
  const [draft, setDraft] = useState<PingTaskDraft>(initial);
  const { busy, run } = useBusy();

  return (
    <Dialog
      title={draft.id ? "编辑 TCP 延迟任务" : "新建 TCP 延迟任务"}
      value={draft}
      initial={initial}
      busy={busy}
      onClose={onClose}
    >
      <form
        className="serverForm"
        onSubmit={(e) => {
          e.preventDefault();
          const interval = Number.parseInt(draft.intervalDraft.trim(), 10);
          if (!Number.isInteger(interval) || interval < 30 || interval > 3600) {
            setError("检测间隔请填写 30–3600 之间的整数秒");
            return;
          }
          void run(async () => {
            const payload = {
              name: draft.name.trim(),
              target: draft.target.trim(),
              intervalSeconds: interval,
              serverIds: draft.serverIds,
            };
            const ok = await act(async () => {
              if (draft.id) {
                await mutation<PingTask>(`/api/ping-tasks/${draft.id}`, "PATCH", payload);
              } else {
                await mutation<PingTask>("/api/ping-tasks", "POST", payload);
              }
              await onSaved();
            }, draft.id ? "监测任务已更新" : "监测任务已创建");
            if (ok) onClose();
          });
        }}
      >
        <div className="formGrid">
          <Field label="任务名称 *">
            <input
              required
              maxLength={80}
              placeholder="例如：电信广州 / Cloudflare"
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            />
          </Field>
          <Field label="检测间隔（秒，30–3600） *">
            <input
              required
              inputMode="numeric"
              value={draft.intervalDraft}
              onChange={(e) => setDraft({ ...draft, intervalDraft: e.target.value })}
            />
          </Field>
          <div className="serverFormWide">
            <Field
              label="目标地址（host:port） *"
              help="仅支持 TCP 连接检测，且只允许公网 IP 或解析为公网地址的域名；内网、回环、链路本地及 CGNAT 地址会被拒绝。"
            >
              <input
                required
                placeholder="例如：1.1.1.1:443 或 example.com:443"
                value={draft.target}
                onChange={(e) => setDraft({ ...draft, target: e.target.value })}
              />
            </Field>
          </div>
          <div className="serverFormWide">
            <fieldset className="serverRoles">
              <legend>
                执行服务器（不勾选表示全部支持监控的在线服务器）
              </legend>
              {onlineServers.length === 0 ? (
                <p className="hint">暂无在线 Agent 管理的服务器。</p>
              ) : (
                <div className="checkRow">
                  {onlineServers.map((srv) => {
                    const checked = draft.serverIds.includes(srv.id);
                    return (
                      <label className="check" key={srv.id}>
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={(e) =>
                            setDraft({
                              ...draft,
                              serverIds: e.target.checked
                                ? [...draft.serverIds, srv.id]
                                : draft.serverIds.filter((id) => id !== srv.id),
                            })
                          }
                        />
                        {countryFlag(srv.country)} {redact(srv.name)}
                      </label>
                    );
                  })}
                </div>
              )}
            </fieldset>
          </div>
        </div>
        <div className="serverFormActions">
          <button type="button" className="ghost" disabled={busy} onClick={onClose}>
            取消
          </button>
          <SubmitButton busy={busy} label="保存任务" className="primary" />
        </div>
      </form>
    </Dialog>
  );
}
