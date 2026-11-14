package server

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicStatusDisabledUnconfiguredAndVisibilityFilter(t *testing.T) {
	// Case A: MUI_STATUS_LISTEN is NOT configured -> status page unavailable even if enabled in DB.
	pUnconf := newTestMui(t)
	code, cfgOut, _ := pUnconf.do("GET", "/api/settings/status-page", nil, nil)
	if code != 200 {
		t.Fatalf("GET status-page settings: %d %v", code, cfgOut)
	}
	if cfgOut["listenConfigured"] != false {
		t.Fatalf("expected listenConfigured=false when MUI_STATUS_LISTEN unset, got %v", cfgOut["listenConfigured"])
	}
	code, _, _ = pUnconf.do("PUT", "/api/settings/status-page", map[string]any{
		"enabled": true,
		"title":   "Test Status",
	}, nil)
	if code != 200 {
		t.Fatalf("PUT status-page settings: %d", code)
	}
	unconfStatus := pUnconf.app.StatusHandler()
	for _, path := range []string{"/api/public/status", "/api/public/servers/" + strings.Repeat("a", 32) + "/records", "/api/public/servers/" + strings.Repeat("a", 32) + "/pings"} {
		if rec := statusServe(unconfStatus, "GET", path, nil, "198.51.100.10:12345"); rec.Code != 404 {
			t.Fatalf("expected 404 on %s when MUI_STATUS_LISTEN is unset, got %d", path, rec.Code)
		}
	}

	// Case B: MUI_STATUS_LISTEN configured -> disabled returns 404 indistinguishable from unknown route;
	// enabled shows only publicVisible && non-revoked servers, sorted by sortWeight DESC.
	t.Setenv("MUI_STATUS_LISTEN", "127.0.0.1:18088")
	t.Setenv("MUI_STATUS_URL", "https://status.example.test")
	p := newTestMui(t)
	statusMux := p.app.StatusHandler()

	code, cfgOut, _ = p.do("GET", "/api/settings/status-page", nil, nil)
	if code != 200 || cfgOut["listenConfigured"] != true || cfgOut["statusUrl"] != "https://status.example.test" {
		t.Fatalf("unexpected status-page settings response: %d %v", code, cfgOut)
	}

	pubID1, _, _ := enrollMonitorTestServer(t, p, "alpha-node")
	hiddenID, _, _ := enrollMonitorTestServer(t, p, "hidden-node")
	pubID2, _, _ := enrollMonitorTestServer(t, p, "beta-node")

	code, _, _ = p.do("PATCH", "/api/servers/"+pubID1, map[string]any{
		"name":          "alpha-node",
		"roles":         []string{"exit"},
		"country":       "JP",
		"ipv4":          "203.0.113.11",
		"publicVisible": true,
		"publicName":    "Tokyo-A",
		"group":         "亚太",
		"sortWeight":    10,
	}, nil)
	if code != 200 {
		t.Fatalf("patch pubID1: %d", code)
	}
	code, _, _ = p.do("PATCH", "/api/servers/"+pubID2, map[string]any{
		"name":          "beta-node",
		"roles":         []string{"exit"},
		"country":       "SG",
		"ipv4":          "203.0.113.12",
		"publicVisible": true,
		"publicName":    "Singapore-B",
		"group":         "亚太",
		"sortWeight":    50,
	}, nil)
	if code != 200 {
		t.Fatalf("patch pubID2: %d", code)
	}

	fpPub1 := p.store.Fingerprint("status-page", pubID1)
	fpHidden := p.store.Fingerprint("status-page", hiddenID)

	// While disabled (default), all 3 endpoints return 404 identical to /nonexistent.
	notFoundRef := statusServe(statusMux, "GET", "/does-not-exist", nil, "198.51.100.10:12345")
	for _, path := range []string{
		"/api/public/status",
		"/api/public/servers/" + fpPub1 + "/records?range=1h",
		"/api/public/servers/" + fpPub1 + "/pings?range=1h",
	} {
		rec := statusServe(statusMux, "GET", path, nil, "198.51.100.10:12345")
		if rec.Code != 404 || rec.Body.String() != notFoundRef.Body.String() {
			t.Fatalf("disabled %s: got %d %q, want 404 %q", path, rec.Code, rec.Body.String(), notFoundRef.Body.String())
		}
	}

	// Enable status page.
	code, _, _ = p.do("PUT", "/api/settings/status-page", map[string]any{
		"enabled":     true,
		"title":       "全球节点状态",
		"description": "实时可用性监控",
		"showTraffic": true,
		"showPing":    true,
	}, nil)
	if code != 200 {
		t.Fatalf("enable status page: %d", code)
	}

	rec := statusServe(statusMux, "GET", "/api/public/status", nil, "198.51.100.10:12345")
	if rec.Code != 200 {
		t.Fatalf("GET /api/public/status: %d %s", rec.Code, rec.Body.String())
	}
	var statusResp PublicStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if len(statusResp.Servers) != 2 {
		t.Fatalf("expected 2 visible servers, got %d: %+v", len(statusResp.Servers), statusResp.Servers)
	}
	// Sorted by sortWeight DESC: Singapore-B (50) before Tokyo-A (10).
	if statusResp.Servers[0].Name != "Singapore-B" || statusResp.Servers[1].Name != "Tokyo-A" {
		t.Fatalf("unexpected server sort order: %s then %s", statusResp.Servers[0].Name, statusResp.Servers[1].Name)
	}

	// Hidden server fingerprint must 404 on /records and /pings.
	if r := statusServe(statusMux, "GET", "/api/public/servers/"+fpHidden+"/records?range=1h", nil, "198.51.100.10:12345"); r.Code != 404 {
		t.Fatalf("expected 404 for hidden server records, got %d", r.Code)
	}
	if r := statusServe(statusMux, "GET", "/api/public/servers/"+fpHidden+"/pings?range=1h", nil, "198.51.100.10:12345"); r.Code != 404 {
		t.Fatalf("expected 404 for hidden server pings, got %d", r.Code)
	}

	// Revoke pubID1 -> immediately excluded from /api/public/status and 404 on /records.
	code, _, _ = p.do("POST", "/api/servers/"+pubID1+"/revoke", map[string]any{}, nil)
	if code != 200 {
		t.Fatalf("revoke server: %d", code)
	}
	rec = statusServe(statusMux, "GET", "/api/public/status", nil, "198.51.100.10:12345")
	if err := json.Unmarshal(rec.Body.Bytes(), &statusResp); err != nil {
		t.Fatal(err)
	}
	if len(statusResp.Servers) != 1 || statusResp.Servers[0].Name != "Singapore-B" {
		t.Fatalf("revoked server still visible: %+v", statusResp.Servers)
	}
	if r := statusServe(statusMux, "GET", "/api/public/servers/"+fpPub1+"/records?range=1h", nil, "198.51.100.10:12345"); r.Code != 404 {
		t.Fatalf("expected 404 for revoked server records, got %d", r.Code)
	}
}
