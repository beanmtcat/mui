package server

import (
	"strings"
	"testing"
)

func TestSubscriptionEditAcceptsPendingDirectSnellNode(t *testing.T) {
	p := newTestMui(t)
	hostID, auth := p.enroll("direct-snell")
	p.newAgent(auth)
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "Surge", "format": "surge", "nodeIds": []string{}, "enabled": true}, nil)
	if code != 201 {
		t.Fatal(code, sub)
	}
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": hostID, "name": "Snell", "protocol": "snell", "port": 12306, "snellPort": 8443, "snellVersion": 6, "shadowTlsHost": "example.com", "password": "a-valid-v6-psk", "enabled": true, "direct": false}, nil)
	if code != 201 {
		t.Fatal(code, node)
	}
	p.applyAll(auth)
	nodeID := node["id"].(string)
	saved, err := p.store.Node(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	saved.Direct = true
	code, node, _ = p.do("PATCH", "/api/nodes/"+nodeID, saved, nil)
	if code != 200 || node["status"] != "pending" || node["direct"] != true {
		t.Fatalf("direct change must await apply: %d %v", code, node)
	}
	code, out, _ := p.do("PATCH", "/api/subscriptions/"+sub["id"].(string), map[string]any{"name": "Surge", "format": "surge", "nodeIds": []string{nodeID}, "enabled": true}, nil)
	if code != 200 {
		t.Fatalf("pending direct node rejected: %d %v", code, out)
	}
	path := strings.TrimPrefix(sub["url"].(string), "https://mui.example.test")
	if code, body := p.fetch(path); code != 503 {
		t.Fatalf("unapplied credentials exposed: %d %s", code, body)
	}
	// Choosing a pending node must still enforce the client's protocol support.
	code, out, _ = p.do("POST", "/api/subscriptions", map[string]any{"name": "unsupported", "format": "v2rayn", "nodeIds": []string{nodeID}, "enabled": true}, nil)
	if code != 400 || !strings.Contains(out["error"].(string), "Snell") {
		t.Fatalf("incompatible client accepted: %d %v", code, out)
	}
	p.applyAll(auth)
	if code, body := p.fetch(path); code != 200 || !strings.Contains(body, "version=6") || !strings.Contains(body, "shadow-tls-version=3") {
		t.Fatalf("applied node missing from subscription: %d %s", code, body)
	}
}
