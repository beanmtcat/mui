package server

import (
	"strings"
	"testing"
)

func TestCustomerSubscriptionAndSourceIPs(t *testing.T) {
	p := newTestMui(t)
	serverID, agent := p.enroll("Singapore")
	p.newAgent(agent)
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{"direct": true,
		"serverId": serverID, "name": "test-node", "protocol": "snell", "port": 54321,
		"password": "test-psk-123456", "shadowTlsHost": "www.example.com",
	}, nil)
	if code != 201 {
		t.Fatalf("node: %d %v", code, node)
	}
	nodeID := node["id"].(string)
	code, customer, _ := p.do("POST", "/api/customers", map[string]string{"name": "Alice", "notes": "phone"}, nil)
	if code != 201 {
		t.Fatalf("customer: %d %v", code, customer)
	}
	customerID := customer["id"].(string)
	if code, _, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "invalid", "format": "sing-box", "customerId": "missing"}, nil); code != 400 {
		t.Fatalf("missing customer accepted: %d", code)
	}
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "phone", "format": "sing-box", "nodeIds": []string{nodeID}, "customerId": customerID}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	if code, _, _ := p.do("DELETE", "/api/customers/"+customerID, nil, nil); code != 409 {
		t.Fatalf("bound customer deletion: %d", code)
	}
	p.applyAll(agent)
	url := sub["url"].(string)
	path := strings.TrimPrefix(url, "https://mui.example.test")
	if code, _, _ := p.do("GET", path, nil, map[string]string{"RemoteAddr": "198.51.100.24:1234", "X-Forwarded-For": "203.0.113.9"}); code != 200 {
		t.Fatalf("subscription fetch: %d", code)
	}
	if code, _, _ := p.do("POST", "/agent/report", map[string]any{"connections": []map[string]string{
		{"nodeId": nodeID, "ip": "203.0.113.44"},
		{"nodeId": "spoofed", "ip": "203.0.113.45"},
		{"nodeId": nodeID, "ip": "invalid"},
	}}, agent); code != 200 {
		t.Fatalf("agent report: %d", code)
	}
	code, activity, _ := p.do("GET", "/api/clients/activity", nil, nil)
	if code != 200 {
		t.Fatalf("activity: %d %v", code, activity)
	}
	access := activity["accesses"].([]any)
	if len(access) != 1 {
		t.Fatalf("accesses: %v", access)
	}
	got := access[0].(map[string]any)
	if got["customerId"] != customerID || got["subscriptionId"] != sub["id"] || got["ip"] != "198.51.100.24" {
		t.Fatalf("access attribution: %v", got)
	}
	connections := activity["connections"].([]any)
	if len(connections) != 1 || connections[0].(map[string]any)["ip"] != "203.0.113.44" {
		t.Fatalf("connections: %v", connections)
	}
}
