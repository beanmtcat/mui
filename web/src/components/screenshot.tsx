import React from "react";

// A presentation-only copy of the React tree. Source records, form state,
// request bodies and clipboard handlers keep their original values.
export function screenshotText(entries: [string, string][]) {
  const replacements = new Map(entries.filter(([value]) => !!value));
  const words = [...replacements.keys()].filter((value) => value.length >= 2).sort((a, b) => b.length - a.length);
  const pattern = words.length ? new RegExp(words.map((value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"), "g") : null;
  return (text: string): string => {
    if (replacements.has(text)) return replacements.get(text)!;
    return (pattern ? text.replace(pattern, (value) => replacements.get(value)!) : text)
      .replace(/https?:\/\/[^\s<>"']+/g, "[链接已隐藏]")
      .replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g, "[IP 已隐藏]")
      .replace(/(?<![\w:])(?:[a-f\d]{0,4}:){2,}[a-f\d:.]*(?:%[\w.-]+)?(?:\/\d{1,3})?/gi, (ip) => ip.includes("::") || (ip.match(/:/g)?.length || 0) >= 3 ? "[IP 已隐藏]" : ip)
      .replace(/\b[a-f\d]{32,64}\b/gi, "[标识已隐藏]")
      .replace(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/gi, "[邮箱已隐藏]");
  };
}

export function screenshotView(tree: React.ReactNode, text: (value: string) => string, secrets: ReadonlySet<unknown>): React.ReactNode {
  if (typeof tree === "string") return text(tree);
  if (Array.isArray(tree)) return React.Children.map(tree, (child) => screenshotView(child, text, secrets));
  if (!React.isValidElement<Record<string, unknown>>(tree)) return tree;
  const props = tree.props;
  const patch: Record<string, unknown> = {};
  for (const name of ["title", "aria-label", "label", "text", "message", "placeholder"]) {
    if (typeof props[name] === "string") patch[name] = text(props[name]);
  }
  if (props.confirmation && typeof props.confirmation === "object") {
    const confirmation = props.confirmation as Record<string, unknown>;
    patch.confirmation = { ...confirmation, title: text(String(confirmation.title)), message: text(String(confirmation.message)) };
  }
  if (typeof tree.type === "string" && ["input", "textarea", "select"].includes(tree.type)) {
    patch.disabled = true;
    if (tree.type === "textarea" || tree.type === "input" && !["checkbox", "radio", "number", "date"].includes(String(props.type))) {
      patch.value = props.value ? "••••••••" : "";
      patch.type = tree.type === "input" ? "password" : undefined;
    }
  }
  if (secrets.has(tree.type)) {
    patch.value = "[敏感内容已隐藏]";
    patch.onChange = () => {};
    patch.action = undefined;
  }
  // Raw configurations, user agents, audit payloads and install commands can
  // contain secrets not present in the current list of records.
  if (tree.type === "pre" || tree.type === "code") patch.children = "[敏感内容已隐藏]";
  else if (props.children !== undefined) patch.children = screenshotView(props.children as React.ReactNode, text, secrets);
  return React.cloneElement(tree, patch);
}
