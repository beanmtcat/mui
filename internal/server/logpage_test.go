package server

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestLogsPageWithTotalAndDateRange(t *testing.T) {
	p := newTestMui(t)
	id, _ := p.enroll("logs")
	for i := range 5 {
		if code, out, _ := p.do("POST", "/api/firewall", map[string]any{"serverId": id, "portFrom": 9000 + i, "portTo": 9000 + i, "network": "tcp", "action": "allow"}, nil); code != 201 {
			t.Fatalf("rule: %d %v", code, out)
		}
	}
	now := time.Now().UnixMilli()
	page := func(path string) (items []map[string]any, total int) {
		t.Helper()
		code, body := rawDo(t, p, "GET", path, nil, nil)
		if code != 200 {
			t.Fatalf("%s: %d %s", path, code, body)
		}
		var env struct {
			Items []map[string]any `json:"items"`
			Total int              `json:"total"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("%s: %v %s", path, err, body)
		}
		return env.Items, env.Total
	}
	for _, base := range []string{"/api/operations?serverId=" + id, "/api/audit?q=firewall"} {
		first, total := page(base + "&page=1&pageSize=2")
		if total < 5 || len(first) != 2 {
			t.Fatalf("%s page 1: %d items, total %d", base, len(first), total)
		}
		pages := (total + 1) / 2
		last, _ := page(fmt.Sprintf("%s&page=%d&pageSize=2", base, pages))
		if want := total - 2*(pages-1); len(last) != want {
			t.Fatalf("%s last page: %d items, want %d of %d", base, len(last), want, total)
		}
		if first[0]["id"] == last[0]["id"] {
			t.Fatalf("%s: pages overlap", base)
		}
		if _, n := page(fmt.Sprintf("%s&page=1&pageSize=2&fromMs=%d", base, now+60_000)); n != 0 {
			t.Fatalf("%s: a range in the future matched %d", base, n)
		}
		if _, n := page(fmt.Sprintf("%s&page=1&pageSize=2&fromMs=%d&toMs=%d", base, now-60_000, now+60_000)); n != total {
			t.Fatalf("%s: a range around now matched %d of %d", base, n, total)
		}
		if _, n := page(fmt.Sprintf("%s&page=1&pageSize=2&toMs=%d", base, now-60_000)); n != 0 {
			t.Fatalf("%s: a range in the past matched %d", base, n)
		}
	}
	if code, _ := rawDo(t, p, "GET", "/api/audit?page=0", nil, nil); code != 400 {
		t.Fatalf("page 0: %d", code)
	}
	if code, _ := rawDo(t, p, "GET", "/api/audit?page=1&fromMs=x", nil, nil); code != 400 {
		t.Fatalf("bad date: %d", code)
	}
	// Without page the cursor form still answers with a bare array.
	code, body := rawDo(t, p, "GET", "/api/audit?limit=2", nil, nil)
	var bare []map[string]any
	if code != 200 || json.Unmarshal(body, &bare) != nil || len(bare) != 2 {
		t.Fatalf("cursor form: %d %s", code, body)
	}
}

func TestOperationsFilterByKind(t *testing.T) {
	p := newTestMui(t)
	id, _ := p.enroll("kinds")
	if code, out, _ := p.do("POST", "/api/firewall", map[string]any{"serverId": id, "portFrom": 9100, "portTo": 9100, "network": "tcp", "action": "allow"}, nil); code != 201 {
		t.Fatalf("rule: %d %v", code, out)
	}
	if code, out, _ := p.do("POST", "/api/servers/"+id+"/ufw/init", nil, nil); code >= 300 {
		t.Fatalf("ufw init: %d %v", code, out)
	}
	for kind, want := range map[string]int{"firewall.apply": 1, "ufw.init": 1, "core.upgrade": 0} {
		code, body := rawDo(t, p, "GET", "/api/operations?page=1&pageSize=50&kind="+kind, nil, nil)
		var env struct {
			Items []map[string]any `json:"items"`
			Total int              `json:"total"`
		}
		if code != 200 || json.Unmarshal(body, &env) != nil || env.Total != want {
			t.Fatalf("%s: %d %s", kind, code, body)
		}
		for _, item := range env.Items {
			if item["kind"] != kind {
				t.Fatalf("%s matched %v", kind, item["kind"])
			}
		}
	}
	if code, _ := rawDo(t, p, "GET", "/api/operations?kind=%25", nil, nil); code != 400 {
		t.Fatalf("unknown kind: %d", code)
	}
}
