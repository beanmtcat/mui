package server

import (
	"testing"
)

func TestLegacyAgentKomariReturnsEmptyConfigAndAdminSettingsRemoved(t *testing.T) {
	p := newTestMui(t)

	// External Komari admin endpoints are removed.
	if code, _, _ := p.do("GET", "/api/settings/komari", nil, nil); code != 404 && code != 405 {
		t.Fatalf("expected /api/settings/komari to be removed, got %d", code)
	}
	if code, _, _ := p.do("PUT", "/api/settings/komari", map[string]string{"endpoint": "https://komari.example.com"}, nil); code != 404 && code != 405 {
		t.Fatalf("expected PUT /api/settings/komari to be removed, got %d", code)
	}

	// Migration #27 dropped mui_komari_tokens.
	var dummy int
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_komari_tokens`).Scan(&dummy); err == nil {
		t.Fatal("expected mui_komari_tokens table to be dropped by migration")
	}

	// Legacy <= 0.6.30 Agents polling GET /agent/komari receive an empty config so they stay quiet.
	code, created, _ := p.do("POST", "/api/servers", map[string]any{
		"name":    "legacy-agent-host",
		"roles":   []string{"exit"},
		"country": "SG",
		"ipv4":    "8.8.8.8",
	}, nil)
	if code != 201 {
		t.Fatalf("create server: %d %v", code, created)
	}
	serverID := created["server"].(map[string]any)["id"].(string)
	code, enrolled, _ := p.do("POST", "/agent/enroll", map[string]string{
		"serverId": serverID,
		"token":    created["enrollToken"].(string),
	}, nil)
	if code != 200 {
		t.Fatalf("enroll server: %d %v", code, enrolled)
	}
	agentHeaders := map[string]string{
		"X-Server-ID":   serverID,
		"Authorization": "Bearer " + enrolled["agentToken"].(string),
	}
	code, out, _ := p.do("GET", "/agent/komari", nil, agentHeaders)
	if code != 200 {
		t.Fatalf("GET /agent/komari failed: %d %v", code, out)
	}
	for _, key := range []string{"endpoint", "token", "ipv4", "ipv6"} {
		val, exists := out[key]
		if !exists || val != "" {
			t.Fatalf("expected empty %q in /agent/komari response, got %v", key, out)
		}
	}
}
