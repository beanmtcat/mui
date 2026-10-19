package server

import (
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"mui/internal/shared"
)

func TestV2rayNSubscriptionDownloadAndPreview(t *testing.T) {
	l := newRouteLab(t)
	code, route := l.route(map[string]any{"name": "入口 SS", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatalf("route: %d %v", code, route)
	}
	code, node, _ := l.p.do("POST", "/api/nodes", map[string]any{
		"serverId": l.exit, "name": "直连 SS", "protocol": "ss", "method": "2022-blake3-aes-256-gcm", "port": 50011, "direct": true,
	}, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	create := map[string]any{"name": "v2rayN", "format": "v2rayn", "enabled": true,
		"routeIds": []string{route["id"].(string)}, "nodeIds": []string{node["id"].(string)}}
	code, sub, _ := l.p.do("POST", "/api/subscriptions", create, nil)
	if code != 201 {
		t.Fatalf("subscription create: %d %v", code, sub)
	}
	path := strings.TrimPrefix(sub["url"].(string), "https://mui.example.test")
	if code, body := l.p.fetch(path); code != 503 {
		t.Fatalf("credentials not installed yet: %d %s", code, body)
	}
	l.applyAll()
	create["name"] = "v2rayN edited"
	if code, body, _ := l.p.do("PATCH", "/api/subscriptions/"+sub["id"].(string), create, nil); code != 200 {
		t.Fatalf("subscription edit: %d %v", code, body)
	}
	l.applyAll()
	rec := httptest.NewRecorder()
	l.p.handler.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("download: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	body, err := base64.StdEncoding.DecodeString(rec.Body.String())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(body), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected a direct node and a route: %s", body)
	}
	for i, line := range lines {
		u, err := url.Parse(line)
		if err != nil || u.Scheme != "ss" {
			t.Fatalf("invalid share URI: %s (%v)", line, err)
		}
		credentials, err := base64.RawURLEncoding.DecodeString(u.User.Username())
		parts := strings.Split(string(credentials), ":")
		if err != nil || len(parts) != 3 {
			t.Fatalf("SS 2022 server and subscription keys missing: %s", credentials)
		}
		key, err := base64.StdEncoding.DecodeString(parts[2])
		wantHost, wantSize := "198.51.100.4:50011", 32
		if i == 1 {
			wantHost, wantSize = "entry.example.com:50010", 16
		}
		if u.Host != wantHost || err != nil || len(key) != wantSize {
			t.Fatalf("wrong published address or user key: %s (%v)", line, err)
		}
	}
	code, preview, _ := l.p.do("GET", "/api/subscriptions/"+sub["id"].(string)+"/preview", nil, nil)
	if code != 200 || preview["content"] != rec.Body.String() || len(preview["excluded"].([]any)) != 0 {
		t.Fatalf("preview differs from download: %d %v", code, preview)
	}
}

func TestV2rayNRejectsSnellMembers(t *testing.T) {
	l := newRouteLab(t)
	node, err := l.p.store.Node(l.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	node.Protocol, node.Method, node.ShadowTLSHost = "snell", "", "tls.example.com"
	node.Direct = true
	if err := l.p.store.PutNodeWithShadowTLS(node, "snell-password", "shadowtls-password"); err != nil {
		t.Fatal(err)
	}
	code, route := l.route(map[string]any{"name": "Snell route", "entryServerId": l.entry, "nodeId": l.nodeID, "enabled": true})
	if code != 201 {
		t.Fatalf("route: %d %v", code, route)
	}
	for _, members := range []map[string]any{
		{"nodeIds": []string{node.ID}}, {"routeIds": []string{route["id"].(string)}},
	} {
		members["name"], members["format"] = "unsupported", "v2rayn"
		code, body, _ := l.p.do("POST", "/api/subscriptions", members, nil)
		if code != 400 || !strings.Contains(body["error"].(string), "Snell") {
			t.Fatalf("unsupported member accepted: %d %v", code, body)
		}
	}
	if err := validateSubscriptionNode("v2rayn", shared.Node{Protocol: "anytls"}); err != nil {
		t.Fatalf("AnyTLS must be supported: %v", err)
	}
}
