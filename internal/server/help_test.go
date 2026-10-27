package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHelpArticleLifecycle(t *testing.T) {
	p := newTestMui(t)
	get := func(cookie *http.Cookie) (int, []helpArticle) {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/help", nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		p.handler.ServeHTTP(rec, req)
		var items []helpArticle
		if rec.Code == 200 {
			if err := json.Unmarshal(rec.Body.Bytes(), &items); err != nil {
				t.Fatal(err)
			}
		}
		return rec.Code, items
	}
	if code, _ := get(nil); code != 401 {
		t.Fatalf("unauthenticated help status = %d", code)
	}
	code, items := get(p.cookie)
	if code != 200 || len(items) != 3 {
		t.Fatalf("seeded help: status=%d count=%d", code, len(items))
	}
	answer := "运行：\n\n```sh\nprintf '<script>hello</script>'\n```"
	code, created, _ := p.do("POST", "/api/help", map[string]any{"question": "  怎么检查？  ", "answer": answer, "position": 5}, nil)
	if code != 201 || created["question"] != "怎么检查？" || created["answer"] != answer {
		t.Fatalf("create help: %d %#v", code, created)
	}
	id := created["id"].(string)
	code, items = get(p.cookie)
	if code != 200 || len(items) != 4 || items[0].ID != id || items[0].Answer != answer {
		t.Fatalf("stored help: status=%d items=%#v", code, items)
	}
	code, _, _ = p.do("POST", "/api/help", map[string]any{"question": "", "answer": answer, "position": 1}, nil)
	if code != 400 {
		t.Fatalf("invalid article status = %d", code)
	}
	code, updated, _ := p.do("PATCH", "/api/help/"+id, map[string]any{"question": "更新后", "answer": "新答案", "position": 99}, nil)
	if code != 200 || updated["question"] != "更新后" || updated["answer"] != "新答案" {
		t.Fatalf("update help: %d %#v", code, updated)
	}
	code, _, _ = p.do("DELETE", "/api/help/"+id, nil, nil)
	if code != 200 {
		t.Fatalf("delete help: %d", code)
	}
	code, items = get(p.cookie)
	if code != 200 || len(items) != 3 {
		t.Fatalf("deleted help: status=%d count=%d", code, len(items))
	}
	code, out, _ := p.do("PATCH", "/api/help/"+id, map[string]any{"question": "x", "answer": "y", "position": 0}, nil)
	if code != 404 || !strings.Contains(out["error"].(string), "不存在") {
		t.Fatalf("missing help: %d %#v", code, out)
	}
}
