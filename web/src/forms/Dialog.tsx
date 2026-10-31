import { useApp } from "../app/context";
import { setError, setNotice, useFeedback } from "../app/feedback";
import { ModalShell } from "../app/ui";

// Messages inside a dialog, right above the form they are about. Input stays
// in place, and only an error needs a click to go away.
export function ModalFeedback() {
  const { protect } = useApp();
  const { error, notice } = useFeedback();
  if (!error && !notice) return null;
  return protect(<div className={"banner modalFeedback " + (error ? "error" : "success")} role={error ? "alert" : "status"}>
    <span>{error ? error.replace(/^\/api\/[^\s:]+:\s*/, "") : notice}</span>
    <button type="button" aria-label={error ? "关闭错误提示" : "关闭操作提示"} onClick={() => error ? setError("") : setNotice("")}>×</button>
  </div>);
}

export function Dialog({ title, value, initial, busy, children }: { title: string; value: unknown; initial: unknown; busy: boolean; children: React.ReactNode }) {
  const { closeModal, setConfirmation, protect } = useApp();
  return protect(<ModalShell title={title} dirty={JSON.stringify(value) !== JSON.stringify(initial)} busy={busy} onClose={closeModal} onConfirm={setConfirmation} feedback={<ModalFeedback />}>
    {children}
  </ModalShell>);
}
