package server

import (
	"strings"
	"testing"
)

func TestSellerProvidedNodeWithoutAgent(t *testing.T) {
	p := newTestMui(t)
	create := map[string]any{
		"name": "seller-exit", "country": "SG", "domain": "seller.example.test",
		"roles": []string{"exit"}, "managementMode": "external", "firewallMode": "manual",
	}
	code, result, _ := p.do("POST", "/api/servers", create, nil)
	if code != 201 || result["enrollToken"] != nil || result["installCommand"] != nil {
		t.Fatalf("external server exposed enrollment: %d %v", code, result)
	}
	id := result["server"].(map[string]any)["id"].(string)
	if server, err := p.store.Server(id); err != nil || serverStatus(server) != "external" {
		t.Fatalf("external server status: %+v %v", server, err)
	}
	for _, path := range []string{"enrollment", "agent/upgrade", "core/upgrade", "ufw/init"} {
		if code, _, _ := p.do("POST", "/api/servers/"+id+"/"+path, nil, nil); code < 400 {
			t.Fatalf("external server accepted online action %s: %d", path, code)
		}
	}
	if code, _, _ := p.do("POST", "/agent/enroll", map[string]any{"serverId": id, "token": "invalid"}, nil); code != 403 {
		t.Fatalf("external server accepted enrollment: %d", code)
	}
	if code, _, _ := p.do("POST", "/api/forwards", map[string]any{"serverId": id, "name": "wrong", "network": "tcp", "port": 55000, "targets": []map[string]any{{"host": "example.org", "port": 443}}}, nil); code < 400 {
		t.Fatalf("external server accepted a forward: %d", code)
	}
	node := map[string]any{
		"serverId": id, "name": "seller-ss", "protocol": "ss", "method": "aes-256-gcm",
		"port": 443, "password": "vendor-secret-123", "direct": true, "enabled": true,
	}
	code, out, _ := p.do("POST", "/api/nodes", node, nil)
	if code != 201 || out["status"] != "external" || out["singleUser"] != true {
		t.Fatalf("seller node: %d %v", code, out)
	}
	nodeID := out["id"].(string)
	if secret, _ := p.store.NodeSecret(nodeID); secret != "vendor-secret-123" {
		t.Fatal("seller credential was regenerated")
	}
	code, updated, _ := p.do("PATCH", "/api/nodes/"+nodeID, map[string]any{
		"name": "seller-ss", "protocol": "ss", "method": "aes-256-gcm", "port": 444,
		"direct": true, "enabled": true,
	}, nil)
	if code != 200 || updated["status"] != "external" {
		t.Fatalf("seller node edit: %d %v", code, updated)
	}
	if secret, _ := p.store.NodeSecret(nodeID); secret != "vendor-secret-123" {
		t.Fatal("seller credential changed on edit")
	}
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "seller", "format": "surge", "nodeIds": []string{nodeID}}, nil)
	if code != 201 {
		t.Fatalf("seller subscription: %d %v", code, sub)
	}
	path := strings.TrimPrefix(sub["url"].(string), p.app.PublicURL)
	if code, body := p.fetch(path); code != 200 || !strings.Contains(body, "seller.example.test") || !strings.Contains(body, "vendor-secret-123") {
		t.Fatalf("seller subscription missing original connection: %d %s", code, body)
	}
	var jobs int
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_operations WHERE server_id=$1`, id).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatalf("seller node queued Agent jobs: %d %v", jobs, err)
	}
	if code, out, _ := p.do("PATCH", "/api/servers/"+id, map[string]any{"name": "seller-exit", "country": "SG", "domain": "seller.example.test", "roles": []string{"exit"}, "managementMode": "online", "firewallMode": "ufw"}, nil); code != 409 {
		t.Fatalf("external mode migration accepted: %d %v", code, out)
	}
	if code, out, _ := p.do("DELETE", "/api/nodes/"+nodeID, nil, nil); code != 200 {
		t.Fatalf("seller node delete: %d %v", code, out)
	}
	if code, _ := p.fetch(path); code == 200 {
		t.Fatal("deleted seller node remains in subscription")
	}
}

func TestSellerNodeRequiresOriginalCredential(t *testing.T) {
	p := newTestMui(t)
	code, out, _ := p.do("POST", "/api/servers", map[string]any{"name": "seller", "country": "SG", "ipv4": "203.0.113.10", "roles": []string{"exit"}, "managementMode": "external", "firewallMode": "manual"}, nil)
	if code != 201 {
		t.Fatalf("server: %d %v", code, out)
	}
	id := out["server"].(map[string]any)["id"].(string)
	for _, node := range []map[string]any{
		{"serverId": id, "name": "missing-password", "protocol": "ss", "method": "aes-256-gcm", "port": 443, "direct": true},
		{"serverId": id, "name": "missing-shadow-password", "protocol": "snell", "snellVersion": 5, "port": 444, "shadowTlsHost": "example.com", "password": "vendor-psk-123", "direct": true},
	} {
		if code, out, _ := p.do("POST", "/api/nodes", node, nil); code != 400 {
			t.Fatalf("seller node accepted missing credential: %d %v", code, out)
		}
	}
	code, out, _ = p.do("POST", "/api/nodes", map[string]any{"serverId": id, "name": "plain-snell", "protocol": "snell", "snellVersion": 5, "port": 444, "password": "vendor-psk-123", "direct": true}, nil)
	if code != 201 || out["status"] != "external" {
		t.Fatalf("plain Snell seller node: %d %v", code, out)
	}
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "plain-snell", "format": "surge", "nodeIds": []string{out["id"].(string)}}, nil)
	if code != 201 {
		t.Fatalf("plain Snell subscription: %d %v", code, sub)
	}
	path := strings.TrimPrefix(sub["url"].(string), p.app.PublicURL)
	if code, body := p.fetch(path); code != 200 || !strings.Contains(body, "psk=vendor-psk-123") || strings.Contains(body, "shadow-tls-") {
		t.Fatalf("plain Snell output: %d %s", code, body)
	}
}

func TestSellerNodeAsRouteExit(t *testing.T) {
	l := newRouteLab(t)
	p := l.p
	code, result, _ := p.do("POST", "/api/servers", map[string]any{
		"name": "seller-route-exit", "country": "SG", "domain": "seller-route.example.test",
		"roles": []string{"exit"}, "managementMode": "external", "firewallMode": "manual",
	}, nil)
	if code != 201 {
		t.Fatalf("external exit: %d %v", code, result)
	}
	id := result["server"].(map[string]any)["id"].(string)
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{
		"serverId": id, "name": "seller-route-node", "protocol": "ss", "method": "aes-256-gcm",
		"port": 443, "password": "seller-route-password", "enabled": true,
	}, nil)
	if code != 201 {
		t.Fatalf("external route node: %d %v", code, node)
	}
	code, route := l.route(map[string]any{"name": "seller-route", "entryServerId": l.entry, "nodeId": node["id"].(string), "enabled": true})
	if code != 201 {
		t.Fatalf("route to external node: %d %v", code, route)
	}
	for _, f := range l.forwards(l.entry) {
		if len(f.Targets) != 1 || f.Targets[0].Host != "seller-route.example.test" || f.Targets[0].Port != 443 {
			t.Fatalf("wrong external route target: %+v", f)
		}
	}
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "seller-route", "format": "surge", "routeIds": []string{route["id"].(string)}}, nil)
	if code != 201 {
		t.Fatalf("route subscription: %d %v", code, sub)
	}
	l.applyAll()
	path := strings.TrimPrefix(sub["url"].(string), p.app.PublicURL)
	if code, body := p.fetch(path); code != 200 || !strings.Contains(body, "seller-route-password") || !strings.Contains(body, "entry.example.com") {
		t.Fatalf("external route subscription: %d %s", code, body)
	}
	var jobs int
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_operations WHERE server_id=$1`, id).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatalf("external exit got Agent jobs: %d %v", jobs, err)
	}
}

func TestSellerAnyTLSWithoutCertificateUpload(t *testing.T) {
	p := newTestMui(t)
	code, result, _ := p.do("POST", "/api/servers", map[string]any{
		"name": "seller-anytls", "country": "SG", "domain": "anytls.example.test",
		"roles": []string{"exit"}, "managementMode": "external", "firewallMode": "manual",
	}, nil)
	if code != 201 {
		t.Fatalf("server: %d %v", code, result)
	}
	id := result["server"].(map[string]any)["id"].(string)
	code, node, _ := p.do("POST", "/api/nodes", map[string]any{
		"serverId": id, "name": "seller-anytls", "protocol": "anytls", "port": 443,
		"tlsName": "tls.example.test", "password": "seller-anytls-password", "direct": true,
	}, nil)
	if code != 201 || node["certificateId"] != "" {
		t.Fatalf("external AnyTLS required/uploaded a local certificate: %d %v", code, node)
	}
	code, sub, _ := p.do("POST", "/api/subscriptions", map[string]any{"name": "seller-anytls", "format": "surge", "nodeIds": []string{node["id"].(string)}}, nil)
	if code != 201 {
		t.Fatalf("subscription: %d %v", code, sub)
	}
	path := strings.TrimPrefix(sub["url"].(string), p.app.PublicURL)
	if code, body := p.fetch(path); code != 200 || !strings.Contains(body, "sni=tls.example.test") || !strings.Contains(body, "seller-anytls-password") {
		t.Fatalf("external AnyTLS subscription: %d %s", code, body)
	}
}
