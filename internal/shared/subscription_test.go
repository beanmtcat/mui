package shared

import (
	"encoding/json"
	"testing"
)

func TestSnellSubscription(t *testing.T) {
	item := SubscriptionItem{Node: Node{ID: "12345678", Name: "Snell", Protocol: "snell", Port: 1234, Obfs: "http", Enabled: true, Status: "active"}, Server: Server{IPv4: "203.0.113.3"}, Password: "secret-key"}
	raw, excluded, err := RenderSubscription("sing-box", []SubscriptionItem{item})
	if err != nil || len(excluded) > 0 {
		t.Fatalf("render: %v %v", err, excluded)
	}
	var doc map[string][]map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := doc["outbounds"][0]
	if out["version"] != float64(4) || out["obfs_mode"] != "http" {
		t.Fatalf("unexpected Snell outbound: %#v", out)
	}
}

func TestSnellShadowTLSSubscriptions(t *testing.T) {
	item := SubscriptionItem{Node: Node{ID: "shadow123", Name: "Snell TLS", Protocol: "snell", Port: 54321, ShadowTLSHost: "www.example.com", Enabled: true, Status: "active"}, Server: Server{IPv4: "203.0.113.3"}, Password: "snell-secret", ShadowTLSPassword: "outer-secret"}
	raw, excluded, err := RenderSubscription("sing-box", []SubscriptionItem{item})
	if err != nil || len(excluded) != 0 {
		t.Fatalf("sing-box render: %v %v", err, excluded)
	}
	var doc map[string][]map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc["outbounds"]) != 2 {
		t.Fatalf("missing ShadowTLS outbound: %s", raw)
	}
	snell, outer := doc["outbounds"][0], doc["outbounds"][1]
	if snell["type"] != "snell" || snell["detour"] != outer["tag"] || outer["type"] != "shadowtls" || outer["version"] != float64(3) || outer["password"] != "outer-secret" || outer["tls"].(map[string]any)["server_name"] != "www.example.com" {
		t.Fatalf("invalid outbound chain: %s", raw)
	}
}
