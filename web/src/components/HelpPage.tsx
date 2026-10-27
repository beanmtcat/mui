import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { api, mutation } from "../api";

type HelpArticle = {
  id: string;
  question: string;
  answer: string;
  position: number;
  updatedAt: number;
};
type HelpForm = Pick<HelpArticle, "question" | "answer" | "position"> & { id?: string };

function inlineCode(value: string): ReactNode[] {
  return value.split(/(`[^`\n]+`)/g).map((part, index) =>
    part.startsWith("`") && part.endsWith("`")
      ? <code key={index}>{part.slice(1, -1)}</code>
      : part,
  );
}

function HelpAnswer({ value, onCopy }: { value: string; onCopy: (text: string) => void }) {
  const lines = value.replace(/\r\n/g, "\n").split("\n");
  const sections: { kind: "text" | "code"; value: string; language?: string }[] = [];
  let kind: "text" | "code" = "text";
  let language = "";
  let current: string[] = [];
  const flush = () => {
    if (current.length) sections.push({ kind, value: current.join("\n"), language });
    current = [];
  };
  for (const line of lines) {
    if (kind === "text") {
      const opening = line.match(/^```([\w+.-]*)\s*$/);
      if (opening) {
        flush();
        kind = "code";
        language = opening[1];
        continue;
      }
    } else if (/^```\s*$/.test(line)) {
      flush();
      kind = "text";
      language = "";
      continue;
    }
    current.push(line);
  }
  flush();
  return <div className="helpAnswer">{sections.map((section, index) => section.kind === "code" ? (
    <div className="helpCode" key={index}>
      <div className="helpCodeHead"><span>{section.language || "代码"}</span><button type="button" onClick={() => onCopy(section.value)}>复制代码</button></div>
      <pre><code>{section.value}</code></pre>
    </div>
  ) : section.value.trim().split(/\n\s*\n/).filter(Boolean).map((paragraph, pIndex) => (
    <p key={`${index}-${pIndex}`}>{paragraph.split("\n").map((line, lIndex) => <span key={lIndex}>{lIndex > 0 && <br />}{inlineCode(line)}</span>)}</p>
  )))}</div>;
}

export default function HelpPage({ onCopy }: { onCopy: (text: string) => void }) {
  const [articles, setArticles] = useState<HelpArticle[]>([]);
  const [query, setQuery] = useState("");
  const [form, setForm] = useState<HelpForm | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const editorRef = useRef<HTMLFormElement>(null);
  const answerRef = useRef<HTMLTextAreaElement>(null);

  const reload = async () => {
    const items = await api<HelpArticle[]>("/api/help");
    setArticles(items);
  };
  useEffect(() => {
    void reload().catch((e: Error) => setError(e.message)).finally(() => setLoading(false));
  }, []);
  useEffect(() => {
    if (form) editorRef.current?.scrollIntoView({ block: "start", behavior: "smooth" });
  }, [form !== null, form?.id]);
  const visible = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return !needle ? articles : articles.filter((item) => `${item.question}\n${item.answer}`.toLocaleLowerCase().includes(needle));
  }, [articles, query]);

  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!form || saving) return;
    setSaving(true);
    setError("");
    try {
      await mutation(form.id ? `/api/help/${form.id}` : "/api/help", form.id ? "PATCH" : "POST", {
        question: form.question, answer: form.answer, position: form.position,
      });
      await reload();
      setForm(null);
      setNotice("帮助条目已保存");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };
  const remove = async (article: HelpArticle) => {
    if (!window.confirm(`删除「${article.question}」？`)) return;
    setError("");
    try {
      await mutation(`/api/help/${article.id}`, "DELETE");
      await reload();
      setNotice("帮助条目已删除");
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const insertCode = () => {
    if (!form) return;
    const field = answerRef.current;
    const start = field?.selectionStart ?? form.answer.length;
    const end = field?.selectionEnd ?? start;
    const prefix = start > 0 && !form.answer.slice(0, start).endsWith("\n\n") ? "\n\n" : "";
    const snippet = "```sh\n\n```";
    setForm({ ...form, answer: form.answer.slice(0, start) + prefix + snippet + form.answer.slice(end) });
    requestAnimationFrame(() => {
      field?.focus();
      const caret = start + prefix.length + "```sh\n".length;
      field?.setSelectionRange(caret, caret);
    });
  };

  return <section className="panel helpPage">
    <div className="panelHead">
      <div><h2>常见问题</h2><p>查找使用说明和排查步骤。</p></div>
      <button type="button" className="primary" onClick={() => { setForm({ question: "", answer: "", position: (articles.at(-1)?.position || 0) + 10 }); setError(""); }}>新增问题</button>
    </div>
    {error && <div className="banner error" role="alert">{error}<button type="button" onClick={() => setError("")}>×</button></div>}
    {notice && <div className="banner success" role="status">{notice}<button type="button" onClick={() => setNotice("")}>×</button></div>}
    {form && <form ref={editorRef} className="helpEditor" onSubmit={(event) => void save(event)}>
      <h3>{form.id ? "编辑问题" : "新增问题"}</h3>
      <label>问题<input required maxLength={200} value={form.question} onChange={(event) => setForm({ ...form, question: event.target.value })} placeholder="例如：Agent 升级按钮为什么是灰色的？" /></label>
      <label>答案<textarea ref={answerRef} required maxLength={50000} rows={10} value={form.answer} onChange={(event) => setForm({ ...form, answer: event.target.value })} placeholder={'输入说明。行内代码用 `命令`；多行代码用 ```sh 和 ``` 包裹。'} /></label>
      <div className="helpEditorTools"><button type="button" className="ghost" onClick={insertCode}>插入代码块</button><label>排序<input type="number" min={0} max={9999} step={1} value={form.position} onChange={(event) => setForm({ ...form, position: Number(event.target.value) })} /></label></div>
      {form.answer.trim() && <div className="helpPreview"><strong>预览</strong><HelpAnswer value={form.answer} onCopy={onCopy} /></div>}
      <div className="actions"><button className="primary" type="submit" disabled={saving}>{saving ? "保存中…" : "保存"}</button><button type="button" onClick={() => setForm(null)}>取消</button></div>
    </form>}
    <div className="helpSearch"><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索问题或答案" aria-label="搜索帮助" /></div>
    {loading ? <p className="helpEmpty">正在加载…</p> : visible.length ? <div className="helpList">{visible.map((article) => <details key={article.id} className="helpItem">
      <summary>{article.question}</summary>
      <HelpAnswer value={article.answer} onCopy={onCopy} />
      <div className="helpItemActions"><button type="button" onClick={() => { setForm({ ...article }); setNotice(""); }}>编辑</button><button type="button" className="dangerText" onClick={() => void remove(article)}>删除</button></div>
    </details>)}</div> : <p className="helpEmpty">{query ? "没有匹配的帮助内容" : "暂无帮助内容，点击“新增问题”开始录入"}</p>}
  </section>;
}
