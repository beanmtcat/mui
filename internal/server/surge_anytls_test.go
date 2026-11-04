package server

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestSurgeAnyTLSDirectAndRouteSubscriptions(t *testing.T) {
	l := newRouteLab(t)
	p := l.p
	certPEM, keyPEM := makeTestCertificate(t, false, nil, 30)
	cert := shared.Certificate{ID: ID(), Domain: "example.com", PEM: certPEM, Key: keyPEM, ExpiresAt: time.Now().Add(24 * time.Hour)}
	if err := p.store.PutCertificate(cert); err != nil {
		t.Fatal(err)
	}
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{"serverId": l.exit, "name": "直连 AnyTLS", "protocol": "anytls", "port": 50443, "tlsName": "example.com", "certificateId": cert.ID, "password": "original-node-password", "enabled": true, "direct": true}, nil)
	if code != 201 {
		t.Fatal(code, node)
	}
	nodeID := node["id"].(string)
	code, route := l.route(map[string]any{"name": "链路 AnyTLS", "entryServerId": l.entry, "nodeId": nodeID, "enabled": true})
	if code != 201 {
		t.Fatal(code, route)
	}
	body := map[string]any{"name": "Surge AnyTLS", "format": "surge", "nodeIds": []string{nodeID}, "routeIds": []string{route["id"].(string)}, "enabled": true}
	code, sub, _ := p.do("POST", "/api/subscriptions", body, nil)
	if code != 201 {
		t.Fatal("Surge must accept AnyTLS nodes and routes", code, sub)
	}
	path := strings.TrimPrefix(sub["url"].(string), "https://mui.example.test")
	if code, _ := p.fetch(path); code != 503 {
		t.Fatal("unapplied credentials were offered", code)
	}
	l.applyAll()
	body["name"] = "Surge AnyTLS edited"
	if code, out, _ := p.do("PATCH", "/api/subscriptions/"+sub["id"].(string), body, nil); code != 200 {
		t.Fatal("Surge edit rejected AnyTLS", code, out)
	}
	l.applyAll()
	code, content := p.fetch(path)
	if code != 200 {
		t.Fatal(code, content)
	}
	n, _ := p.store.Node(nodeID)
	user := p.store.SubscriptionUser(n, sub["id"].(string))
	for _, want := range []string{
		fmt.Sprintf("直连 AnyTLS = anytls, 198.51.100.4, 50443, password=%s, sni=example.com", user.Password),
		fmt.Sprintf("链路 AnyTLS = anytls, entry.example.com, 50443, password=%s, sni=example.com", user.Password),
	} {
		if !strings.Contains(content, want) {
			t.Fatal("entry address, subscription password or landing SNI lost", content)
		}
	}
	if strings.Contains(content, "original-node-password") || strings.Contains(content, "skip-cert-verify") {
		t.Fatal("base password exported or verification disabled")
	}
	if code, preview, _ := p.do("GET", "/api/subscriptions/"+sub["id"].(string)+"/preview", nil, nil); code != 200 || preview["content"] != content || len(preview["excluded"].([]any)) != 0 {
		t.Fatal("preview differs from download", code, preview)
	}
	code, profile := p.fetch(path + "?profile=1")
	if code != 200 {
		t.Fatal(code, profile)
	}
	for _, want := range []string{
		"#!MANAGED-CONFIG https://mui.example.test" + path + "?profile=1 interval=43200 strict=false\n",
		strings.TrimSuffix(content, "\n"),
		"节点选择 = select, 自动选择, 故障转移, 直连 AnyTLS, 链路 AnyTLS, DIRECT",
		"FINAL,漏网之鱼,dns-failed",
	} {
		if !strings.Contains(profile, want) {
			t.Fatal("profile lacks", want, profile)
		}
	}
	if !strings.HasPrefix(profile, "#!MANAGED-CONFIG ") || strings.Contains(profile, "{{") {
		t.Fatal("MANAGED-CONFIG must be the first line and every placeholder filled", profile)
	}
	if code, out, _ := p.do("PUT", "/api/settings/surge-profile", map[string]any{"template": "[Proxy]\n{{PROXIES}}\n[Rule]\nGEOIP,CN,DIRECT"}, nil); code != 400 {
		t.Fatal("a template without FINAL was saved", code, out)
	}
	custom := "#!MANAGED-CONFIG https://elsewhere.example/x\r\n[Proxy]\r\n{{PROXIES}}\r\n[Proxy Group]\r\n出口 = select, {{PROXY_NAMES}}\r\n[Rule]\r\nFINAL,出口\r\n"
	if code, out, _ := p.do("PUT", "/api/settings/surge-profile", map[string]any{"template": custom}, nil); code != 200 || out["custom"] != true {
		t.Fatal(code, out)
	}
	if _, profile = p.fetch(path + "?profile=1"); !strings.Contains(profile, "出口 = select, 直连 AnyTLS, 链路 AnyTLS\n") ||
		strings.Contains(profile, "elsewhere") || strings.Contains(profile, "\r") || strings.Contains(profile, "漏网之鱼") {
		t.Fatal("custom template not applied", profile)
	}
	if code, out, _ := p.do("PUT", "/api/settings/surge-profile", map[string]any{"template": ""}, nil); code != 200 || out["custom"] != false || out["template"] != shared.DefaultSurgeProfileTemplate {
		t.Fatal("clearing the template must restore the default", code, out)
	}
}
