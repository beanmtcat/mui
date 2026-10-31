import { useSyncExternalStore } from "react";

// Feedback lives outside React state so that showing a message re-renders the
// message alone, not the page behind it.
type Feedback = { error: string; notice: string };
let state: Feedback = { error: "", notice: "" };
let timer: ReturnType<typeof setTimeout> | undefined;
const listeners = new Set<() => void>();

function update(next: Partial<Feedback>) {
  state = { ...state, ...next };
  listeners.forEach((listener) => listener());
}

// Errors stay until dismissed: they must be read. Confirmations fade away.
export const setError = (error: string) => update({ error });
export function setNotice(notice: string) {
  clearTimeout(timer);
  update({ notice });
  if (notice) timer = setTimeout(() => update({ notice: "" }), 3000);
}
export function clearFeedback() {
  clearTimeout(timer);
  update({ error: "", notice: "" });
}
export function useFeedback() {
  return useSyncExternalStore((listener) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  }, () => state);
}
