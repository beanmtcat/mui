import React, { memo, useState } from "react";

// SecretField: password input with a show/hide toggle. The value stays in the
// parent form state (unchanged behaviour); only the input type toggles.
// `action` is an optional extra button (e.g. "generate") rendered beside it.
function SecretField({
  value, onChange, action, placeholder, autoComplete,
}: {
  value: string;
  onChange: (value: string) => void;
  action?: React.ReactNode;
  placeholder?: string;
  autoComplete?: string;
}) {
  const [shown, setShown] = useState(false);
  return (
    <div className="inputWithAction">
      <input
        type={shown ? "text" : "password"}
        autoComplete={autoComplete || "off"}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      <button
        className="iconButton" type="button"
        title={shown ? "隐藏" : "显示"} aria-label={shown ? "隐藏密钥" : "显示密钥"}
        onClick={() => setShown(!shown)}
      >
        {shown ? "隐藏" : "显示"}
      </button>
      {action}
    </div>
  );
}

// SecretTextarea: same idea for multi-line secrets (certificate private key).
// While hidden it renders a disabled, masked copy so the real value never
// appears in the DOM as readable text.
function SecretTextarea({
  value, onChange, rows, required, placeholder,
}: {
  value: string;
  onChange: (value: string) => void;
  rows?: number;
  required?: boolean;
  placeholder?: string;
}) {
  const [shown, setShown] = useState(false);
  const masked = value.split("\n").map((line) => (line ? "••••••••" : "")).join("\n");
  return (
    <div>
      {shown ? (
        <textarea required={required} rows={rows} placeholder={placeholder} value={value} onChange={(e) => onChange(e.target.value)} />
      ) : (
        <textarea rows={rows} placeholder={placeholder} value={masked} disabled aria-label="已遮蔽的密钥，点击显示后编辑" />
      )}
      <button className="textButton" type="button" onClick={() => setShown(!shown)}>
        {shown ? "隐藏密钥" : "显示密钥"}
      </button>
    </div>
  );
}

// MaskedValue: for values that must be shown on demand (subscription preview,
// subscription URL, TOTP secret, install command). Default is masked;
// clicking reveals the real value. Children are the "copy" button etc.
function MaskedValue({
  value, children, pre,
}: {
  value: string;
  children?: React.ReactNode;
  pre?: boolean;
}) {
  const [shown, setShown] = useState(false);
  return (
    <div>
      {shown
        ? (pre ? <pre>{value}</pre> : <code>{value}</code>)
        : <code>••••••••（点击显示）</code>}
      <div className="actions">
        <button type="button" onClick={() => setShown(!shown)}>
          {shown ? "隐藏" : "点击显示"}
        </button>
        {children}
      </div>
    </div>
  );
}

export const MemoSecretField = memo(SecretField);
export const MemoSecretTextarea = memo(SecretTextarea);
export const MemoMaskedValue = memo(MaskedValue);
