package server

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestKomariSettingsAndPerServerTokenDelivery(t *testing.T) {
	p := newTestMui(t)
	if code, _, _ := p.do("PUT", "/api/settings/komari", map[string]string{"endpoint": "http://komari.example.com"}, nil); code != 400 {
		t.Fatalf("accepted insecure endpoint: %d", code)
	}
	if code, out, _ := p.do("PUT", "/api/settings/komari", map[string]string{"endpoint": "https://komari.example.com"}, nil); code != 200 || out["endpoint"] != "https://komari.example.com" {
		t.Fatalf("save endpoint: %d %v", code, out)
	}
	create := func(name, token string) (string, map[string]string) {
		t.Helper()
		body := map[string]any{"name": name, "roles": []string{"exit"}, "country": "SG", "ipv4": "8.8.8.8"}
		if token != "" {
			body["komariToken"] = token
		}
		code, out, _ := p.do("POST", "/api/servers", body, nil)
		if code != 201 {
			t.Fatalf("create %s: %d %v", name, code, out)
		}
		id := out["server"].(map[string]any)["id"].(string)
		code, enrolled, _ := p.do("POST", "/agent/enroll", map[string]string{"serverId": id, "token": out["enrollToken"].(string)}, nil)
		if code != 200 {
			t.Fatalf("enroll %s: %d %v", name, code, enrolled)
		}
		return id, map[string]string{"X-Server-ID": id, "Authorization": "Bearer " + enrolled["agentToken"].(string)}
	}
	firstID, firstAgent := create("komari-enabled", "per-server-private-token")
	_, secondAgent := create("komari-disabled", "")
	var sealed string
	if err := p.store.DB.QueryRow(`SELECT token_enc FROM mui_komari_tokens WHERE server_id=$1`, firstID).Scan(&sealed); err != nil || strings.Contains(sealed, "per-server-private-token") {
		t.Fatalf("token was not encrypted: %v", err)
	}
	if code, out, _ := p.do("GET", "/api/servers", nil, nil); code != 200 || strings.Contains(Marshal(out), "per-server-private-token") {
		t.Fatalf("server list exposed token: %d %v", code, out)
	}
	if code, out, _ := p.do("GET", "/agent/komari", nil, firstAgent); code != 200 || out["endpoint"] != "https://komari.example.com" || out["token"] != "per-server-private-token" || out["ipv4"] != "8.8.8.8" {
		t.Fatalf("first Agent config: %d %v", code, out)
	}
	if code, out, _ := p.do("GET", "/agent/komari", nil, secondAgent); code != 200 || out["token"] != "" || out["endpoint"] != "" {
		t.Fatalf("tokenless Agent should be disabled: %d %v", code, out)
	}
	server, err := p.store.Server(firstID)
	if err != nil {
		t.Fatal(err)
	}
	server.DetectedIPv4 = "1.1.1.1"
	server.DetectedIPv6 = "2606:4700:4700::1111"
	if err := p.store.PutServer(server); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := p.do("GET", "/agent/komari", nil, firstAgent); code != 200 || out["ipv4"] != "8.8.8.8" || out["ipv6"] != "2606:4700:4700::1111" {
		t.Fatalf("Agent did not use configured IP before detected fallback: %d %v", code, out)
	}
	var update map[string]any
	if err := json.Unmarshal([]byte(Marshal(server)), &update); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := p.do("PATCH", "/api/servers/"+firstID, update, nil); code != 200 {
		t.Fatalf("ordinary server edit: %d", code)
	}
	if code, out, _ := p.do("GET", "/agent/komari", nil, firstAgent); code != 200 || out["token"] != "per-server-private-token" {
		t.Fatalf("ordinary edit cleared token: %d %v", code, out)
	}
	if code, _, _ := p.do("PUT", "/api/settings/komari", map[string]string{"endpoint": ""}, nil); code != 200 {
		t.Fatalf("clear endpoint: %d", code)
	}
	if code, out, _ := p.do("GET", "/agent/komari", nil, firstAgent); code != 200 || out["token"] != "" || out["endpoint"] != "" {
		t.Fatalf("cleared endpoint remained active: %d %v", code, out)
	}
	if code, _, _ := p.do("PUT", "/api/settings/komari", map[string]string{"endpoint": "https://komari.example.com"}, nil); code != 200 {
		t.Fatalf("restore endpoint: %d", code)
	}
	update["komariToken"] = ""
	if code, _, _ := p.do("PATCH", "/api/servers/"+firstID, update, nil); code != 200 {
		t.Fatalf("clear token: %d", code)
	}
	if code, out, _ := p.do("GET", "/agent/komari", nil, firstAgent); code != 200 || out["token"] != "" || out["endpoint"] != "" {
		t.Fatalf("cleared token remained active: %d %v", code, out)
	}
}

func TestKomariPanelIPRejectsPrivateAndCGNAT(t *testing.T) {
	if got := komariPanelIP("192.168.1.2", "8.8.8.8", false); got != "8.8.8.8" {
		t.Fatalf("private configured IP hid public detected IP: %q", got)
	}
	for _, raw := range []string{"127.0.0.1", "169.254.169.254", "100.64.10.2", "0.0.0.0"} {
		if got := komariPanelIP(raw, "", false); got != "" {
			t.Errorf("accepted unsafe IPv4 %s: %q", raw, got)
		}
	}
}
