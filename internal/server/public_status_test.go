package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

func statusServe(h http.Handler, method, target string, headers map[string]string, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func assertOnlyAllowedKeys(t *testing.T, path string, obj map[string]any, allowed ...string) {
	t.Helper()
	allowSet := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		allowSet[k] = true
	}
	for k := range obj {
		if !allowSet[k] {
			t.Fatalf("%s exposed unexpected JSON field %q (value=%v)", path, k, obj[k])
		}
	}
}

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

func TestPublicStatusStrictFieldWhitelistAndNoSensitiveLeaks(t *testing.T) {
	t.Setenv("MUI_STATUS_LISTEN", "127.0.0.1:18088")
	t.Setenv("MUI_STATUS_URL", "https://status.example.test")
	p := newTestMui(t)
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	p.app.monitorNow = func() time.Time { return now }

	srvID, srvToken, _ := enrollMonitorTestServer(t, p, "internal-secret-name")
	expAt := now.Add(15 * 24 * time.Hour)
	code, patchOut, _ := p.do("PATCH", "/api/servers/"+srvID, map[string]any{
		"name":             "internal-secret-name",
		"roles":            []string{"exit"},
		"country":          "DE",
		"region":           "Hesse",
		"city":             "Frankfurt",
		"provider":         "SecretProviderCorp",
		"tags":             "vip-tag,internal-tag",
		"notes":            "SSH root password hint: never-leak-this-note",
		"ipv4":             "8.8.4.4",
		"ipv6":             "2606:4700:4700::8888",
		"domain":           "hidden-origin.example.net",
		"internalAddress":  "10.99.88.77",
		"publicVisible":    true,
		"publicName":       "Frankfurt-Public-1",
		"publicNote":       "BGP 优化线路",
		"expiresAt":        expAt.Format(time.RFC3339),
		"price":            49.99,
		"currency":         "EUR",
		"billingCycle":     "month",
		"autoRenew":        true,
		"trafficLimit":     1099511627776,
		"trafficLimitType": "sum",
		"trafficResetDay":  1,
		"group":            "欧洲",
		"sortWeight":       9419,
		"alertMuted":       true,
	}, nil)
	if code != 200 {
		t.Fatalf("patch server: %d %v", code, patchOut)
	}

	// Simulate internal agent-reported sensitive fields stored on the server document.
	srvDoc, err := p.store.Server(srvID)
	if err != nil {
		t.Fatal(err)
	}
	srvDoc.DetectedIPv4 = "198.51.100.222"
	srvDoc.DetectedIPv6 = "2001:db8::2222"
	srvDoc.AgentVersion = "0.9.9-secret"
	srvDoc.CoreVersion = "1.12.0-secret"
	srvDoc.SSHPorts = []int{22022}
	srvDoc.LastSeen = &now
	if err := p.store.PutServer(srvDoc); err != nil {
		t.Fatal(err)
	}

	// Create a ping task with a sensitive target IP:port.
	code, taskOut, _ := p.do("POST", "/api/ping-tasks", map[string]any{
		"name":            "电信回程",
		"target":          "1.1.1.1:443",
		"intervalSeconds": 60,
		"serverIds":       []string{srvID},
	}, nil)
	if code != 201 {
		t.Fatalf("create ping task: %d %v", code, taskOut)
	}
	taskID := taskOut["id"].(string)

	// Send signed monitor report with host, sample, and ping data.
	monPayload, _ := json.Marshal(shared.MonitorRequest{
		Host: &shared.MonitorHost{
			OS:             "Debian 12",
			Arch:           "amd64",
			Kernel:         "6.1.0-secret-kernel",
			Virtualization: "kvm",
			CPUName:        "AMD EPYC 9654",
			CPUCores:       4,
			MemTotal:       8589934592,
			SwapTotal:      1073741824,
			DiskTotal:      85899345920,
		},
		Sample: shared.MonitorSample{
			At:           now,
			CPU:          18.5,
			Load1:        0.42,
			Load5:        0.38,
			Load15:       0.31,
			RAMUsed:      2147483648,
			RAMTotal:     8589934592,
			SwapUsed:     0,
			SwapTotal:    1073741824,
			DiskUsed:     10737418240,
			DiskTotal:    85899345920,
			NetUp:        1048576,
			NetDown:      2097152,
			NetTotalUp:   5368709120,
			NetTotalDown: 10737418240,
			TCP:          64,
			UDP:          12,
			Process:      118,
			Uptime:       864000,
		},
		Pings: []shared.PingResult{{TaskID: taskID, Ms: 37}},
	})
	monReq := httptest.NewRequest("POST", "/agent/monitor", bytes.NewReader(monPayload))
	monReq.Header.Set("X-Server-ID", srvID)
	monReq.Header.Set("Authorization", "Bearer "+srvToken)
	signAgentRequest(t, monReq, srvToken, monPayload)
	monRec := httptest.NewRecorder()
	p.handler.ServeHTTP(monRec, monReq)
	if monRec.Code != 200 {
		t.Fatalf("POST /agent/monitor: %d %s", monRec.Code, monRec.Body.String())
	}

	// Enable status page with showTraffic=true, showPing=true.
	code, _, _ = p.do("PUT", "/api/settings/status-page", map[string]any{
		"enabled":     true,
		"title":       "Status",
		"description": "Public monitor",
		"showTraffic": true,
		"showPing":    true,
	}, nil)
	if code != 200 {
		t.Fatalf("enable status page: %d", code)
	}

	statusMux := p.app.StatusHandler()
	pubID := p.store.Fingerprint("status-page", srvID)

	statusRes := statusServe(statusMux, "GET", "/api/public/status", nil, "198.51.100.10:1234")
	recordsRes := statusServe(statusMux, "GET", "/api/public/servers/"+pubID+"/records?range=1h", nil, "198.51.100.10:1234")
	pingsRes := statusServe(statusMux, "GET", "/api/public/servers/"+pubID+"/pings?range=1h", nil, "198.51.100.10:1234")
	if statusRes.Code != 200 || recordsRes.Code != 200 || pingsRes.Code != 200 {
		t.Fatalf("unexpected codes: status=%d records=%d pings=%d", statusRes.Code, recordsRes.Code, pingsRes.Code)
	}

	// Substring leak check across ALL 3 responses.
	forbiddenSubstrings := []string{
		srvID,
		taskID,
		"internal-secret-name",
		"SecretProviderCorp",
		"vip-tag",
		"never-leak-this-note",
		"8.8.4.4",
		"2606:4700:4700::8888",
		"198.51.100.222",
		"2001:db8::2222",
		"hidden-origin.example.net",
		"10.99.88.77",
		"1.1.1.1",
		"0.9.9-secret",
		"1.12.0-secret",
		"6.1.0-secret-kernel",
		"22022",
		"49.99",
		"EUR",
		"9419",
		"sortWeight",
		"mui.example.test",
	}
	for name, body := range map[string]string{
		"status":  statusRes.Body.String(),
		"records": recordsRes.Body.String(),
		"pings":   pingsRes.Body.String(),
	} {
		for _, needle := range forbiddenSubstrings {
			if strings.Contains(body, needle) {
				t.Fatalf("%s response leaked forbidden value %q: %s", name, needle, body)
			}
		}
	}

	// Strict field-by-field JSON key whitelist verification.
	var rawStatus map[string]any
	if err := json.Unmarshal(statusRes.Body.Bytes(), &rawStatus); err != nil {
		t.Fatal(err)
	}
	assertOnlyAllowedKeys(t, "status", rawStatus, "title", "description", "showTraffic", "showPing", "generatedAt", "servers")
	srvList := rawStatus["servers"].([]any)
	if len(srvList) != 1 {
		t.Fatalf("expected 1 server, got %d", len(srvList))
	}
	srvMap := srvList[0].(map[string]any)
	assertOnlyAllowedKeys(t, "status.servers[0]", srvMap,
		"id", "name", "group", "country", "region", "city", "online", "hostMonitor",
		"os", "arch", "virtualization", "cpuName", "cpuCores", "memTotal", "swapTotal", "diskTotal",
		"sample", "cycleTraffic", "expiresAt", "publicNote",
	)
	if srvMap["group"] != "欧洲" || srvMap["name"] != "Frankfurt-Public-1" || srvMap["publicNote"] != "BGP 优化线路" {
		t.Fatalf("unexpected public fields: %v", srvMap)
	}
	sampleMap := srvMap["sample"].(map[string]any)
	assertOnlyAllowedKeys(t, "status.servers[0].sample", sampleMap,
		"at", "cpu", "load1", "load5", "load15", "ramUsed", "ramTotal", "swapUsed", "swapTotal",
		"diskUsed", "diskTotal", "netUp", "netDown", "netTotalUp", "netTotalDown",
		"tcp", "udp", "process", "uptime",
	)
	ctMap := srvMap["cycleTraffic"].(map[string]any)
	assertOnlyAllowedKeys(t, "status.servers[0].cycleTraffic", ctMap,
		"startAt", "resetAt", "used", "limit", "type",
	)

	var rawRecords []map[string]any
	if err := json.Unmarshal(recordsRes.Body.Bytes(), &rawRecords); err != nil {
		t.Fatal(err)
	}
	if len(rawRecords) == 0 {
		t.Fatal("expected at least 1 monitor record")
	}
	for i, r := range rawRecords {
		assertOnlyAllowedKeys(t, fmt.Sprintf("records[%d]", i), r,
			"at", "cpu", "load1", "ramUsed", "ramTotal", "swapUsed", "diskUsed", "diskTotal",
			"netUp", "netDown", "netUpPeak", "netDownPeak", "totalUp", "totalDown",
			"tcp", "udp", "process",
		)
	}

	var rawPings []map[string]any
	if err := json.Unmarshal(pingsRes.Body.Bytes(), &rawPings); err != nil {
		t.Fatal(err)
	}
	if len(rawPings) != 1 {
		t.Fatalf("expected 1 ping series, got %d", len(rawPings))
	}
	assertOnlyAllowedKeys(t, "pings[0]", rawPings[0], "id", "name", "intervalSeconds", "records")
	pingPts := rawPings[0]["records"].([]any)
	if len(pingPts) == 0 {
		t.Fatal("expected at least 1 ping point")
	}
	for i, pt := range pingPts {
		assertOnlyAllowedKeys(t, fmt.Sprintf("pings[0].records[%d]", i), pt.(map[string]any),
			"at", "msAvg", "msMax", "sent", "lost",
		)
	}

	// Range 30d must be rejected (400) on public endpoints; only 1h|6h|24h|7d allowed.
	if r := statusServe(statusMux, "GET", "/api/public/servers/"+pubID+"/records?range=30d", nil, "198.51.100.10:1234"); r.Code != 400 {
		t.Fatalf("expected 400 for range=30d on public records, got %d", r.Code)
	}
	if r := statusServe(statusMux, "GET", "/api/public/servers/"+pubID+"/pings?range=30d", nil, "198.51.100.10:1234"); r.Code != 400 {
		t.Fatalf("expected 400 for range=30d on public pings, got %d", r.Code)
	}

	// Turn off showTraffic and showPing -> traffic omitted and /pings returns 404.
	code, _, _ = p.do("PUT", "/api/settings/status-page", map[string]any{
		"showTraffic": false,
		"showPing":    false,
	}, nil)
	if code != 200 {
		t.Fatalf("disable traffic & ping: %d", code)
	}
	statusNoTraf := statusServe(statusMux, "GET", "/api/public/status", nil, "198.51.100.10:1234")
	var rawNoTraf map[string]any
	_ = json.Unmarshal(statusNoTraf.Body.Bytes(), &rawNoTraf)
	srvNoTraf := rawNoTraf["servers"].([]any)[0].(map[string]any)
	if _, exists := srvNoTraf["cycleTraffic"]; exists {
		t.Fatalf("cycleTraffic must be omitted when showTraffic=false: %v", srvNoTraf)
	}
	sampNoTraf := srvNoTraf["sample"].(map[string]any)
	if _, exists := sampNoTraf["netTotalUp"]; exists {
		t.Fatalf("netTotalUp must be omitted when showTraffic=false: %v", sampNoTraf)
	}
	if _, exists := sampNoTraf["netTotalDown"]; exists {
		t.Fatalf("netTotalDown must be omitted when showTraffic=false: %v", sampNoTraf)
	}
	recNoTraf := statusServe(statusMux, "GET", "/api/public/servers/"+pubID+"/records?range=1h", nil, "198.51.100.10:1234")
	var rawRecNoTraf []map[string]any
	_ = json.Unmarshal(recNoTraf.Body.Bytes(), &rawRecNoTraf)
	if _, exists := rawRecNoTraf[0]["totalUp"]; exists {
		t.Fatalf("totalUp must be omitted when showTraffic=false: %v", rawRecNoTraf[0])
	}
	if r := statusServe(statusMux, "GET", "/api/public/servers/"+pubID+"/pings?range=1h", nil, "198.51.100.10:1234"); r.Code != 404 {
		t.Fatalf("expected 404 on /pings when showPing=false, got %d", r.Code)
	}
}

func TestPublicIDRejectedOnAdminAndAgentEndpoints(t *testing.T) {
	t.Setenv("MUI_STATUS_LISTEN", "127.0.0.1:18088")
	p := newTestMui(t)
	srvID, srvToken, _ := enrollMonitorTestServer(t, p, "target-srv")
	code, _, _ := p.do("PATCH", "/api/servers/"+srvID, map[string]any{
		"name":          "target-srv",
		"roles":         []string{"exit"},
		"country":       "US",
		"ipv4":          "203.0.113.44",
		"publicVisible": true,
	}, nil)
	if code != 200 {
		t.Fatalf("patch: %d", code)
	}
	pubID := p.store.Fingerprint("status-page", srvID)
	if pubID == srvID {
		t.Fatal("public ID must not equal internal server ID")
	}

	// Admin endpoints must return 404 for publicID.
	for _, tc := range []struct {
		method string
		path   string
		body   any
	}{
		{"GET", "/api/monitor/" + pubID + "/records?range=1h", nil},
		{"GET", "/api/servers/" + pubID + "/traffic", nil},
		{"PATCH", "/api/servers/" + pubID, map[string]any{"name": "x", "roles": []string{"exit"}, "country": "US", "ipv4": "203.0.113.44"}},
		{"DELETE", "/api/servers/" + pubID, nil},
		{"POST", "/api/servers/" + pubID + "/renew", map[string]any{}},
		{"POST", "/api/servers/" + pubID + "/revoke", map[string]any{}},
		{"POST", "/api/servers/" + pubID + "/enrollment", map[string]any{}},
	} {
		c, _, _ := p.do(tc.method, tc.path, tc.body, nil)
		if c != 404 {
			t.Fatalf("admin %s %s with publicID: got %d, want 404", tc.method, tc.path, c)
		}
	}

	// Agent endpoints must return 401 when given publicID instead of internal server ID.
	c, _, _ := p.do("POST", "/agent/enroll", map[string]string{
		"serverId": pubID,
		"token":    "any-token",
	}, nil)
	if c != 401 {
		t.Fatalf("POST /agent/enroll with publicID: got %d, want 401", c)
	}

	for _, tc := range []struct {
		method string
		path   string
		body   []byte
	}{
		{"GET", "/agent/job", nil},
		{"POST", "/agent/monitor", []byte(`{"sample":{"cpu":10}}`)},
		{"POST", "/agent/report", []byte(`{}`)},
	} {
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
		req.Header.Set("X-Server-ID", pubID)
		req.Header.Set("Authorization", "Bearer "+srvToken)
		signAgentRequest(t, req, srvToken, tc.body)
		rec := httptest.NewRecorder()
		p.handler.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Fatalf("agent %s %s with publicID: got %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
}

func TestPublicStatusRateLimitAndCaching(t *testing.T) {
	t.Setenv("MUI_STATUS_LISTEN", "127.0.0.1:18088")
	t.Setenv("MUI_TRUSTED_PROXIES", "10.0.0.0/8")
	p := newTestMui(t)
	now := time.Date(2026, 11, 14, 15, 0, 0, 0, time.UTC)
	p.app.monitorNow = func() time.Time { return now }

	srvID, _, _ := enrollMonitorTestServer(t, p, "cache-srv")
	code, _, _ := p.do("PATCH", "/api/servers/"+srvID, map[string]any{
		"name":          "cache-srv",
		"roles":         []string{"exit"},
		"country":       "JP",
		"ipv4":          "203.0.113.55",
		"publicVisible": true,
		"publicName":    "InitialName",
	}, nil)
	if code != 200 {
		t.Fatalf("patch: %d", code)
	}
	if err := p.store.PutMonitorMinute(srvID, now.Add(-2*time.Minute).UnixMilli(), MonitorRecord{
		At:  now.Add(-2 * time.Minute),
		CPU: 12.5,
	}); err != nil {
		t.Fatal(err)
	}
	code, _, _ = p.do("PUT", "/api/settings/status-page", map[string]any{
		"enabled":     true,
		"title":       "Cached",
		"showTraffic": true,
		"showPing":    true,
	}, nil)
	if code != 200 {
		t.Fatalf("enable: %d", code)
	}

	statusMux := p.app.StatusHandler()
	pubID := p.store.Fingerprint("status-page", srvID)

	// 1. 2-second snapshot cache + Cache-Control header.
	r1 := statusServe(statusMux, "GET", "/api/public/status", nil, "198.51.100.20:1111")
	if r1.Code != 200 || r1.Header().Get("Cache-Control") != "public, max-age=2" {
		t.Fatalf("unexpected first status response: %d cc=%q", r1.Code, r1.Header().Get("Cache-Control"))
	}
	// Mutate DB directly without admin API invalidation; within 2s cached body is served.
	srvDoc, _ := p.store.Server(srvID)
	srvDoc.PublicName = "DirectDBMutated"
	_ = p.store.PutServer(srvDoc)

	now = now.Add(1 * time.Second)
	r2 := statusServe(statusMux, "GET", "/api/public/status", nil, "198.51.100.20:1111")
	if !strings.Contains(r2.Body.String(), "InitialName") {
		t.Fatalf("expected cached InitialName at +1s, got %s", r2.Body.String())
	}
	// Advance past 2s TTL -> fresh DB value served.
	now = now.Add(2 * time.Second)
	r3 := statusServe(statusMux, "GET", "/api/public/status", nil, "198.51.100.20:1111")
	if !strings.Contains(r3.Body.String(), "DirectDBMutated") {
		t.Fatalf("expected refreshed DirectDBMutated after 2s TTL, got %s", r3.Body.String())
	}

	// 2. 30-second history cache + Cache-Control header.
	h1 := statusServe(statusMux, "GET", "/api/public/servers/"+pubID+"/records?range=1h", nil, "198.51.100.20:1111")
	if h1.Code != 200 || h1.Header().Get("Cache-Control") != "public, max-age=30" {
		t.Fatalf("unexpected history response: %d cc=%q", h1.Code, h1.Header().Get("Cache-Control"))
	}
	_ = p.store.PutMonitorMinute(srvID, now.Add(-time.Minute).UnixMilli(), MonitorRecord{
		At:  now.Add(-time.Minute),
		CPU: 88.0,
	})
	now = now.Add(10 * time.Second)
	h2 := statusServe(statusMux, "GET", "/api/public/servers/"+pubID+"/records?range=1h", nil, "198.51.100.20:1111")
	if strings.Contains(h2.Body.String(), "88") {
		t.Fatalf("expected 30s cached records at +10s, got %s", h2.Body.String())
	}
	now = now.Add(25 * time.Second)
	h3 := statusServe(statusMux, "GET", "/api/public/servers/"+pubID+"/records?range=1h", nil, "198.51.100.20:1111")
	if !strings.Contains(h3.Body.String(), "88") {
		t.Fatalf("expected refreshed records after 30s TTL, got %s", h3.Body.String())
	}

	// 3. Per-IP rate limiting (120/min) honoring MUI_TRUSTED_PROXIES X-Forwarded-For.
	for i := 1; i <= 120; i++ {
		rec := statusServe(statusMux, "GET", "/api/public/status", map[string]string{
			"X-Forwarded-For": "203.0.113.200",
		}, "10.0.0.5:4321")
		if rec.Code != 200 {
			t.Fatalf("request %d unexpectedly failed: %d", i, rec.Code)
		}
	}
	recLimited := statusServe(statusMux, "GET", "/api/public/status", map[string]string{
		"X-Forwarded-For": "203.0.113.200",
	}, "10.0.0.5:4321")
	if recLimited.Code != 429 {
		t.Fatalf("expected 429 on 121st request from same IP, got %d", recLimited.Code)
	}
	// Different client IP via trusted proxy still succeeds.
	recOtherIP := statusServe(statusMux, "GET", "/api/public/status", map[string]string{
		"X-Forwarded-For": "203.0.113.201",
	}, "10.0.0.5:4321")
	if recOtherIP.Code != 200 {
		t.Fatalf("expected 200 for different client IP, got %d", recOtherIP.Code)
	}
}

func TestPublicStatusEntryIsolationHeadersAndNoPublicURLHostname(t *testing.T) {
	t.Setenv("MUI_STATUS_LISTEN", "127.0.0.1:18088")
	t.Setenv("MUI_STATUS_URL", "https://status-isolated.example.org")
	p := newTestMui(t)

	srvID, _, _ := enrollMonitorTestServer(t, p, "iso-srv")
	code, _, _ := p.do("PATCH", "/api/servers/"+srvID, map[string]any{
		"name":          "iso-srv",
		"roles":         []string{"exit"},
		"country":       "SG",
		"ipv4":          "203.0.113.66",
		"publicVisible": true,
	}, nil)
	if code != 200 {
		t.Fatalf("patch: %d", code)
	}
	code, _, _ = p.do("PUT", "/api/settings/status-page", map[string]any{
		"enabled":     true,
		"title":       "Isolated Status",
		"showTraffic": true,
		"showPing":    true,
	}, nil)
	if code != 200 {
		t.Fatalf("enable: %d", code)
	}

	statusMux := p.app.StatusHandler()
	pubID := p.store.Fingerprint("status-page", srvID)

	// 1. Status listener ONLY serves /api/public/* and /healthz; every admin/agent/subscription/download path is 404.
	for _, tc := range []struct {
		method string
		path   string
	}{
		{"POST", "/api/login"},
		{"GET", "/api/login"},
		{"GET", "/api/servers"},
		{"GET", "/api/monitor"},
		{"GET", "/api/settings/status-page"},
		{"GET", "/agent/job"},
		{"POST", "/agent/monitor"},
		{"GET", "/s/x"},
		{"GET", "/download/install.sh"},
	} {
		rec := statusServe(statusMux, tc.method, tc.path, nil, "198.51.100.30:2222")
		if rec.Code != 404 {
			t.Fatalf("status listener %s %s: got %d, want 404", tc.method, tc.path, rec.Code)
		}
	}
	if rec := statusServe(statusMux, "GET", "/healthz", nil, "198.51.100.30:2222"); rec.Code != 200 {
		t.Fatalf("status listener GET /healthz: got %d, want 200", rec.Code)
	}

	// 2. Main listener returns 404 for /api/public/* even when MUI_STATUS_LISTEN is set and status_page is enabled.
	for _, path := range []string{
		"/api/public/status",
		"/api/public/servers/" + pubID + "/records?range=1h",
		"/api/public/servers/" + pubID + "/pings?range=1h",
	} {
		c, _, _ := p.do("GET", path, nil, nil)
		if c != 404 {
			t.Fatalf("main listener GET %s: got %d, want 404", path, c)
		}
	}

	// 3. Security headers on status listener (including X-Robots-Tag: noindex & HSTS on https)
	// and zero mention of MUI_PUBLIC_URL hostname ("mui.example.test").
	httpsReq := httptest.NewRequest("GET", "https://status-isolated.example.org/api/public/status", nil)
	httpsReq.RemoteAddr = "198.51.100.30:2222"
	httpsRec := httptest.NewRecorder()
	statusMux.ServeHTTP(httpsRec, httpsReq)
	if httpsRec.Code != 200 {
		t.Fatalf("https status request: %d", httpsRec.Code)
	}
	if got := httpsRec.Header().Get("X-Robots-Tag"); got != "noindex" {
		t.Fatalf("expected X-Robots-Tag=noindex, got %q", got)
	}
	if got := httpsRec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected X-Content-Type-Options=nosniff, got %q", got)
	}
	if got := httpsRec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("expected X-Frame-Options=DENY, got %q", got)
	}
	if got := httpsRec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("expected Referrer-Policy=no-referrer, got %q", got)
	}
	if !strings.Contains(httpsRec.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("unexpected CSP: %q", httpsRec.Header().Get("Content-Security-Policy"))
	}
	if got := httpsRec.Header().Get("Strict-Transport-Security"); got == "" {
		t.Fatal("expected Strict-Transport-Security on https status request")
	}
	for k, vals := range httpsRec.Header() {
		for _, v := range vals {
			if strings.Contains(v, "mui.example.test") {
				t.Fatalf("header %s leaked MUI_PUBLIC_URL hostname: %q", k, v)
			}
		}
	}
	if strings.Contains(httpsRec.Body.String(), "mui.example.test") {
		t.Fatalf("body leaked MUI_PUBLIC_URL hostname: %s", httpsRec.Body.String())
	}

	// Conversely, enrollment commands generated by panel must never contain MUI_STATUS_URL.
	c, enrollOut, _ := p.do("POST", "/api/servers/"+srvID+"/enrollment", map[string]any{}, nil)
	if c != 200 {
		t.Fatalf("enrollment: %d", c)
	}
	rawEnroll, _ := json.Marshal(enrollOut)
	if strings.Contains(string(rawEnroll), "status-isolated.example.org") {
		t.Fatalf("panel enrollment output leaked MUI_STATUS_URL: %s", string(rawEnroll))
	}
}

func TestPublicStatusDeleteServerInvalidatesCache(t *testing.T) {
	t.Setenv("MUI_STATUS_LISTEN", "127.0.0.1:18088")
	p := newTestMui(t)
	now := time.Date(2026, 11, 14, 15, 0, 0, 0, time.UTC)
	p.app.monitorNow = func() time.Time { return now }

	delID, delToken, _ := enrollMonitorTestServer(t, p, "to-delete-srv")
	keepID, _, _ := enrollMonitorTestServer(t, p, "keep-srv")

	code, _, _ := p.do("PATCH", "/api/servers/"+delID, map[string]any{
		"name":          "to-delete-srv",
		"roles":         []string{"exit"},
		"country":       "JP",
		"ipv4":          "203.0.113.71",
		"publicVisible": true,
		"publicName":    "Tokyo-Delete-Me",
	}, nil)
	if code != 200 {
		t.Fatalf("patch delID: %d", code)
	}
	code, _, _ = p.do("PATCH", "/api/servers/"+keepID, map[string]any{
		"name":          "keep-srv",
		"roles":         []string{"exit"},
		"country":       "SG",
		"ipv4":          "203.0.113.72",
		"publicVisible": true,
		"publicName":    "Singapore-Keep",
	}, nil)
	if code != 200 {
		t.Fatalf("patch keepID: %d", code)
	}

	// Report a monitor sample for delID so /records returns 200 and gets cached.
	monPayload, _ := json.Marshal(shared.MonitorRequest{
		Sample: shared.MonitorSample{
			At:       now,
			CPU:      24.5,
			RAMUsed:  1024,
			RAMTotal: 4096,
			DiskUsed: 2048,
			DiskTotal: 8192,
		},
	})
	monReq := httptest.NewRequest("POST", "/agent/monitor", bytes.NewReader(monPayload))
	monReq.Header.Set("X-Server-ID", delID)
	monReq.Header.Set("Authorization", "Bearer "+delToken)
	signAgentRequest(t, monReq, delToken, monPayload)
	monRec := httptest.NewRecorder()
	p.handler.ServeHTTP(monRec, monReq)
	if monRec.Code != 200 {
		t.Fatalf("POST /agent/monitor: %d %s", monRec.Code, monRec.Body.String())
	}

	// Mark delID offline (>90s since LastSeen) so DELETE /api/servers/{id} succeeds directly
	// without revoking first (ensuring cache invalidation is tested on delete itself).
	srvDoc, err := p.store.Server(delID)
	if err != nil {
		t.Fatal(err)
	}
	offlineSeen := time.Now().Add(-5 * time.Minute)
	srvDoc.LastSeen = &offlineSeen
	if err := p.store.PutServer(srvDoc); err != nil {
		t.Fatal(err)
	}

	code, _, _ = p.do("PUT", "/api/settings/status-page", map[string]any{
		"enabled":     true,
		"title":       "Delete Cache Test",
		"showTraffic": true,
		"showPing":    true,
	}, nil)
	if code != 200 {
		t.Fatalf("enable status page: %d", code)
	}

	statusMux := p.app.StatusHandler()
	fpDel := p.store.Fingerprint("status-page", delID)

	// Warm both the 2s /api/public/status snapshot cache and the 30s /records history cache.
	sBefore := statusServe(statusMux, "GET", "/api/public/status", nil, "198.51.100.40:1000")
	if sBefore.Code != 200 || !strings.Contains(sBefore.Body.String(), "Tokyo-Delete-Me") {
		t.Fatalf("expected Tokyo-Delete-Me in status before delete: %d %s", sBefore.Code, sBefore.Body.String())
	}
	rBefore := statusServe(statusMux, "GET", "/api/public/servers/"+fpDel+"/records?range=1h", nil, "198.51.100.40:1000")
	if rBefore.Code != 200 || !strings.Contains(rBefore.Body.String(), "24.5") {
		t.Fatalf("expected 200 with sample in records before delete: %d %s", rBefore.Code, rBefore.Body.String())
	}

	// Delete the server while `now` has NOT advanced (both caches would still be fresh unless invalidated).
	code, delOut, _ := p.do("DELETE", "/api/servers/"+delID, nil, nil)
	if code != 200 {
		t.Fatalf("DELETE /api/servers/%s: %d %v", delID, code, delOut)
	}

	// Immediately re-query: deleted server must vanish from /api/public/status and /records must return 404.
	sAfter := statusServe(statusMux, "GET", "/api/public/status", nil, "198.51.100.40:1000")
	if sAfter.Code != 200 {
		t.Fatalf("GET /api/public/status after delete: %d", sAfter.Code)
	}
	var afterResp PublicStatusResponse
	if err := json.Unmarshal(sAfter.Body.Bytes(), &afterResp); err != nil {
		t.Fatal(err)
	}
	for _, s := range afterResp.Servers {
		if s.ID == fpDel || s.Name == "Tokyo-Delete-Me" {
			t.Fatalf("deleted server still present in cached /api/public/status: %+v", afterResp.Servers)
		}
	}
	if len(afterResp.Servers) != 1 || afterResp.Servers[0].Name != "Singapore-Keep" {
		t.Fatalf("unexpected remaining servers after delete: %+v", afterResp.Servers)
	}

	rAfter := statusServe(statusMux, "GET", "/api/public/servers/"+fpDel+"/records?range=1h", nil, "198.51.100.40:1000")
	if rAfter.Code != 404 {
		t.Fatalf("expected 404 on deleted server /records immediately after delete, got %d %s", rAfter.Code, rAfter.Body.String())
	}
}
