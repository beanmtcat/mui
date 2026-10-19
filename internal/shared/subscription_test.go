package shared

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestV2rayNSubscription(t *testing.T) {
	items := []SubscriptionItem{}
	for i, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		items = append(items, SubscriptionItem{
			Node:   Node{ID: "123456789", Name: "香港 SS + " + string(rune('A'+i)), Protocol: "ss", Method: method, Port: 54321, Enabled: true, Status: "active"},
			Server: Server{IPv6: "2001:db8::1"}, Password: "server+/==:user+/==",
		})
	}
	items = append(items, SubscriptionItem{
		Node:   Node{ID: "anytls123", Name: "AnyTLS 空格 + #", Protocol: "anytls", Port: 54443, TLSName: "tls.example.com", PublishAddress: "entry.example.com", Enabled: true, Status: "active"},
		Server: Server{IPv4: "192.0.2.1"}, Password: "pass word+/@:#?%2F",
	})
	items = append(items,
		SubscriptionItem{Node: Node{Name: "Snell", Protocol: "snell", Enabled: true, Status: "active"}},
		SubscriptionItem{Node: Node{Name: "Pending", Protocol: "ss", Enabled: true, Status: "pending"}},
		SubscriptionItem{Node: Node{Name: "Disabled", Protocol: "ss", Status: "active"}},
		SubscriptionItem{Node: Node{Name: "No address", Protocol: "anytls", Enabled: true, Status: "active"}},
	)
	raw, excluded, err := RenderSubscription("v2rayn", items)
	if err != nil || len(excluded) != 4 {
		t.Fatalf("render: %v %v", err, excluded)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(decoded), "\n")
	if len(lines) != 4 {
		t.Fatalf("wanted four supported nodes: %s", decoded)
	}
	for i, line := range lines {
		u, err := url.Parse(line)
		if err != nil {
			t.Fatal(err)
		}
		if u.Fragment != items[i].Node.Name {
			t.Fatalf("node name did not survive URI escaping: %s", line)
		}
		if i < 3 {
			credentials, err := base64.RawURLEncoding.DecodeString(u.User.Username())
			if err != nil || string(credentials) != items[i].Node.Method+":"+items[i].Password || u.Scheme != "ss" || u.Host != "[2001:db8::1]:54321" {
				t.Fatalf("SS multi-user key or IPv6 was lost: %s (%v)", line, err)
			}
		} else if u.Scheme != "anytls" || u.User.Username() != items[i].Password || u.Host != "entry.example.com:54443" || u.Query().Get("sni") != "tls.example.com" || u.Query().Get("insecure") != "" {
			t.Fatalf("AnyTLS password, route address or TLS settings were lost: %s", line)
		}
	}
}

func TestShareURIPercentEscapes(t *testing.T) {
	item := SubscriptionItem{
		Node:   Node{Name: "空格 + #", Protocol: "anytls", Port: 443, TLSName: "tls.example.com"},
		Server: Server{IPv4: "192.0.2.1"}, Password: "space +%2F:@/?#",
	}
	raw, err := ShareURI(item)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != item.Node.Name || u.User.Username() != item.Password || strings.Contains(raw, "space+") || strings.Contains(raw, "#%E7%A9%BA%E6%A0%BC+") {
		t.Fatalf("share URI corrupted a password or name: %s (%v)", raw, err)
	}
}

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
