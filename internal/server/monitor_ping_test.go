package server

import (
	"fmt"
	"testing"
)

func TestPingTasksValidationAndMaxLimit(t *testing.T) {
	p := newTestMui(t)
	for _, bad := range []string{
		"",
		"1.1.1.1",
		"127.0.0.1:80",
		"[::1]:443",
		"10.0.0.1:443",
		"172.16.0.1:80",
		"192.168.1.1:80",
		"100.64.0.1:443",
		"169.254.169.254:80",
		"localhost:443",
		"svc.local:443",
	} {
		if code, _, _ := p.do("POST", "/api/ping-tasks", map[string]any{
			"name":   "bad",
			"target": bad,
		}, nil); code != 400 {
			t.Fatalf("expected target %q to be rejected with 400, got %d", bad, code)
		}
	}

	var firstID string
	for i := 0; i < 32; i++ {
		code, out, _ := p.do("POST", "/api/ping-tasks", map[string]any{
			"name":            fmt.Sprintf("task-%02d", i),
			"target":          fmt.Sprintf("example-%d.com:443", i),
			"intervalSeconds": 60,
		}, nil)
		if code != 201 {
			t.Fatalf("create task %d: %d %v", i, code, out)
		}
		if i == 0 {
			firstID = out["id"].(string)
		}
	}
	if code, _, _ := p.do("POST", "/api/ping-tasks", map[string]any{
		"name":   "task-33",
		"target": "1.1.1.1:443",
	}, nil); code != 400 {
		t.Fatalf("expected 33rd ping task to be rejected with 400, got %d", code)
	}
	if code, out, _ := p.do("PATCH", "/api/ping-tasks/"+firstID, map[string]any{
		"name":            "Updated-Task",
		"intervalSeconds": 120,
	}, nil); code != 200 || out["name"] != "Updated-Task" {
		t.Fatalf("PATCH ping task failed: %d %v", code, out)
	}
	if code, _, _ := p.do("DELETE", "/api/ping-tasks/"+firstID, nil, nil); code != 200 {
		t.Fatalf("DELETE ping task failed: %d", code)
	}
}
