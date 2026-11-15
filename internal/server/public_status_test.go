package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"mui/internal/shared"
)

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
		"ipv4", "ipv6",
		"os", "arch", "virtualization", "cpuName", "cpuCores", "memTotal", "swapTotal", "diskTotal",
		"sample", "cycleTraffic", "ping", "pingLines", "expiresAt", "publicNote",
	)
	if srvMap["ipv4"] != true || srvMap["ipv6"] != true {
		t.Fatalf("expected ipv4=true and ipv6=true, got %v / %v", srvMap["ipv4"], srvMap["ipv6"])
	}
	pingList, ok := srvMap["ping"].([]any)
	if !ok || len(pingList) != 1 {
		t.Fatalf("expected 1 ping bucket on server, got %#v", srvMap["ping"])
	}
	pingBucket0 := pingList[0].(map[string]any)
	assertOnlyAllowedKeys(t, "status.servers[0].ping[0]", pingBucket0, "at", "ms", "loss")
	if pingBucket0["ms"] != float64(37) || pingBucket0["loss"] != float64(0) {
		t.Fatalf("unexpected ping bucket[0]: %v", pingBucket0)
	}
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
	if _, exists := srvNoTraf["ping"]; exists {
		t.Fatalf("ping must be omitted when showPing=false: %v", srvNoTraf)
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
			At:        now,
			CPU:       24.5,
			RAMUsed:   1024,
			RAMTotal:  4096,
			DiskUsed:  2048,
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

func TestPublicStatusStampedeSingleflightAndErrorPropagation(t *testing.T) {
	t.Setenv("MUI_STATUS_LISTEN", "127.0.0.1:18081")
	p := newTestMui(t)

	var clockMu sync.Mutex
	curNow := time.Date(2026, 11, 14, 14, 0, 0, 0, time.UTC)
	p.app.monitorNow = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return curNow
	}
	advanceClock := func(d time.Duration) {
		clockMu.Lock()
		curNow = curNow.Add(d)
		clockMu.Unlock()
	}

	srvID, _, _ := enrollMonitorTestServer(t, p, "Stampede-Node")
	srv, err := p.store.Server(srvID)
	if err != nil {
		t.Fatal(err)
	}
	lastSeen := curNow.Add(-5 * time.Second)
	srv.PublicVisible = true
	srv.HostMonitor = true
	srv.LastSeen = &lastSeen
	if err := p.store.PutServer(srv); err != nil {
		t.Fatal(err)
	}
	minAt := curNow.Add(-time.Minute).Truncate(time.Minute)
	if err := p.store.PutMonitorMinute(srvID, minAt.UnixMilli(), MonitorRecord{
		At:      minAt,
		CPU:     18.5,
		RAMUsed: 1024,
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.store.PutPingTask(MonitorPingTask{
		ID: "pt1", Name: "CF", Target: "1.1.1.1:443", IntervalSeconds: 30,
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.store.UpsertPingMinute("pt1", srvID, minAt.UnixMilli(), 12, 16, 2, 0); err != nil {
		t.Fatal(err)
	}

	code, _, _ := p.do("PUT", "/api/settings/status-page", map[string]any{
		"enabled":     true,
		"title":       "Stampede Check",
		"showTraffic": true,
		"showPing":    true,
	}, nil)
	if code != 200 {
		t.Fatalf("enable status page: %d", code)
	}

	statusMux := p.app.StatusHandler()
	fp := p.store.Fingerprint("status-page", srvID)

	// Warm all three caches first, then advance past TTL so all 50 concurrent
	// requests hit an expired (non-nil) cache entry simultaneously.
	if w := statusServe(statusMux, "GET", "/api/public/status", nil, "198.51.100.1:3000"); w.Code != 200 {
		t.Fatalf("warm /api/public/status: %d", w.Code)
	}
	if w := statusServe(statusMux, "GET", "/api/public/servers/"+fp+"/records?range=1h", nil, "198.51.100.1:3000"); w.Code != 200 {
		t.Fatalf("warm /records: %d", w.Code)
	}
	if w := statusServe(statusMux, "GET", "/api/public/servers/"+fp+"/pings?range=1h", nil, "198.51.100.1:3000"); w.Code != 200 {
		t.Fatalf("warm /pings: %d", w.Code)
	}

	p.app.statusBuildHook = func(string) {
		time.Sleep(40 * time.Millisecond)
	}

	fire50 := func(target string, wantCode int) {
		t.Helper()
		const n = 50
		start := make(chan struct{})
		codes := make([]int, n)
		bodies := make([]string, n)
		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func(idx int) {
				defer wg.Done()
				<-start
				rec := statusServe(statusMux, "GET", target, nil, fmt.Sprintf("198.51.100.%d:4000", (idx%50)+1))
				codes[idx] = rec.Code
				bodies[idx] = rec.Body.String()
			}(i)
		}
		close(start)
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("concurrent requests to %s timed out (hung waiters)", target)
		}
		for i := 0; i < n; i++ {
			if codes[i] != wantCode {
				t.Fatalf("%s request %d: expected %d, got %d (%s)", target, i, wantCode, codes[i], bodies[i])
			}
			if wantCode == 200 && bodies[i] != bodies[0] {
				t.Fatalf("%s request %d got mismatched body", target, i)
			}
		}
	}

	// 1. Expire 2s /api/public/status cache and fire 50 concurrent requests -> 1 rebuild.
	advanceClock(3 * time.Second)
	beforeSnap := p.app.statusSnapshotBuilds.Load()
	fire50("/api/public/status", 200)
	if got := p.app.statusSnapshotBuilds.Load() - beforeSnap; got != 1 {
		t.Fatalf("expected 1 snapshot rebuild for 50 concurrent requests on expired cache, got %d", got)
	}

	// 2. Expire 30s history cache and fire 50 concurrent requests at /records and /pings -> 1 rebuild each.
	advanceClock(31 * time.Second)
	beforeHist := p.app.statusHistoryBuilds.Load()
	fire50("/api/public/servers/"+fp+"/records?range=1h", 200)
	if got := p.app.statusHistoryBuilds.Load() - beforeHist; got != 1 {
		t.Fatalf("expected 1 records rebuild for 50 concurrent requests on expired cache, got %d", got)
	}

	beforePings := p.app.statusHistoryBuilds.Load()
	fire50("/api/public/servers/"+fp+"/pings?range=1h", 200)
	if got := p.app.statusHistoryBuilds.Load() - beforePings; got != 1 {
		t.Fatalf("expected 1 pings rebuild for 50 concurrent requests on expired cache, got %d", got)
	}

	// 3. Rebuild failure: close underlying DB after expiring cache; all 50 waiters must receive 500 without blocking.
	advanceClock(35 * time.Second)
	_ = p.store.DB.Close()
	beforeErrSnap := p.app.statusSnapshotBuilds.Load()
	fire50("/api/public/status", 500)
	if got := p.app.statusSnapshotBuilds.Load() - beforeErrSnap; got != 1 {
		t.Fatalf("expected 1 failing snapshot rebuild for 50 concurrent requests, got %d", got)
	}
}

func TestPublicStatusPingBucketsAllLostIPvStackAndSingleQuery(t *testing.T) {
	t.Setenv("MUI_STATUS_LISTEN", "127.0.0.1:18088")
	p := newTestMui(t)
	now := time.Date(2026, 11, 14, 15, 30, 20, 0, time.UTC)
	p.app.monitorNow = func() time.Time { return now }

	srv1, srv1Tok, _ := enrollMonitorTestServer(t, p, "ping-v4-only")
	srv2, _, _ := enrollMonitorTestServer(t, p, "noping-v6-only")

	if code, out, _ := p.do("PATCH", "/api/servers/"+srv1, map[string]any{
		"name":          "ping-v4-only",
		"roles":         []string{"exit"},
		"country":       "JP",
		"ipv4":          "203.0.113.10",
		"publicVisible": true,
		"publicName":    "Tokyo-Ping",
	}, nil); code != 200 {
		t.Fatalf("patch srv1: %d %v", code, out)
	}
	if code, out, _ := p.do("PATCH", "/api/servers/"+srv2, map[string]any{
		"name":          "noping-v6-only",
		"roles":         []string{"exit"},
		"country":       "SG",
		"ipv6":          "2001:db8::99",
		"publicVisible": true,
		"publicName":    "Singapore-Quiet",
	}, nil); code != 200 {
		t.Fatalf("patch srv2: %d %v", code, out)
	}

	code, task1Out, _ := p.do("POST", "/api/ping-tasks", map[string]any{
		"name":            "Secret-Task-A",
		"target":          "9.9.9.9:443",
		"intervalSeconds": 60,
		"serverIds":       []string{srv1},
	}, nil)
	if code != 201 {
		t.Fatalf("task1: %d %v", code, task1Out)
	}
	task1ID := task1Out["id"].(string)

	code, task2Out, _ := p.do("POST", "/api/ping-tasks", map[string]any{
		"name":            "Secret-Task-B",
		"target":          "8.8.8.8:443",
		"intervalSeconds": 60,
		"serverIds":       []string{srv1},
	}, nil)
	if code != 201 {
		t.Fatalf("task2: %d %v", code, task2Out)
	}
	task2ID := task2Out["id"].(string)

	// Unassigned task data on srv1 must not appear in public ping buckets.
	code, taskOtherOut, _ := p.do("POST", "/api/ping-tasks", map[string]any{
		"name":            "Unassigned-Task",
		"target":          "1.0.0.1:443",
		"intervalSeconds": 60,
		"serverIds":       []string{srv2},
	}, nil)
	if code != 201 {
		t.Fatalf("taskOther: %d %v", code, taskOtherOut)
	}
	taskOtherID := taskOtherOut["id"].(string)

	curMinute := now.Truncate(time.Minute)
	// Insert 34 historical minutes (-34m .. -1m) into DB so window trimming to 30 buckets is exercised.
	for i := 34; i >= 1; i-- {
		atMs := curMinute.Add(-time.Duration(i) * time.Minute).UnixMilli()
		switch i {
		case 3:
			// Mixed: task1 (2 sent, 0 lost, 20ms) + task2 (2 sent, 1 lost, 40ms) -> ms=30, loss=25
			if err := p.store.UpsertPingMinute(task1ID, srv1, atMs, 20, 22, 2, 0); err != nil {
				t.Fatal(err)
			}
			if err := p.store.UpsertPingMinute(task2ID, srv1, atMs, 40, 45, 2, 1); err != nil {
				t.Fatal(err)
			}
		case 2:
			// All lost across assigned tasks -> ms=-1, loss=100
			if err := p.store.UpsertPingMinute(task1ID, srv1, atMs, 0, 0, 2, 2); err != nil {
				t.Fatal(err)
			}
			if err := p.store.UpsertPingMinute(task2ID, srv1, atMs, 0, 0, 2, 2); err != nil {
				t.Fatal(err)
			}
		default:
			if err := p.store.UpsertPingMinute(task1ID, srv1, atMs, 25, 30, 1, 0); err != nil {
				t.Fatal(err)
			}
		}
		if err := p.store.UpsertPingMinute(taskOtherID, srv1, atMs, 999, 999, 1, 0); err != nil {
			t.Fatal(err)
		}
	}

	// Send current minute in-memory sample for srv1.
	monPayload, _ := json.Marshal(shared.MonitorRequest{
		Sample: shared.MonitorSample{At: now, CPU: 12, NetUp: 100, NetDown: 200},
		Pings: []shared.PingResult{
			{TaskID: task1ID, Ms: 18},
			{TaskID: task2ID, Ms: -1},
		},
	})
	monReq := httptest.NewRequest("POST", "/agent/monitor", bytes.NewReader(monPayload))
	monReq.Header.Set("X-Server-ID", srv1)
	monReq.Header.Set("Authorization", "Bearer "+srv1Tok)
	signAgentRequest(t, monReq, srv1Tok, monPayload)
	monRec := httptest.NewRecorder()
	p.handler.ServeHTTP(monRec, monReq)
	if monRec.Code != 200 {
		t.Fatalf("POST /agent/monitor: %d %s", monRec.Code, monRec.Body.String())
	}

	if code, _, _ := p.do("PUT", "/api/settings/status-page", map[string]any{
		"enabled":     true,
		"title":       "Status",
		"showTraffic": true,
		"showPing":    true,
	}, nil); code != 200 {
		t.Fatalf("enable status page failed: %d", code)
	}

	statusMux := p.app.StatusHandler()
	beforeQ := p.store.publicPingQueries.Load()
	res1 := statusServe(statusMux, "GET", "/api/public/status", nil, "198.51.100.20:1234")
	if res1.Code != 200 {
		t.Fatalf("status code=%d body=%s", res1.Code, res1.Body.String())
	}
	if delta := p.store.publicPingQueries.Load() - beforeQ; delta != 1 {
		t.Fatalf("expected 1 batch ping query during snapshot build, got %d", delta)
	}

	// Second request within 2s TTL hits cache with 0 DB queries.
	res2 := statusServe(statusMux, "GET", "/api/public/status", nil, "198.51.100.21:1234")
	if res2.Code != 200 {
		t.Fatalf("cached status code=%d", res2.Code)
	}
	if delta := p.store.publicPingQueries.Load() - beforeQ; delta != 1 {
		t.Fatalf("expected 0 extra ping queries on cache hit, total=%d", delta)
	}

	bodyStr := res1.Body.String()
	// Task names are public (the per-task lines on a card need them, and the
	// detail endpoint already exposes them); IDs, targets and addresses are not.
	for _, secret := range []string{"203.0.113.10", "2001:db8::99", task1ID, task2ID, "9.9.9.9", "8.8.8.8"} {
		if strings.Contains(bodyStr, secret) {
			t.Fatalf("status leaked secret %q in %s", secret, bodyStr)
		}
	}
	var linesDoc struct {
		Servers []struct {
			Name      string           `json:"name"`
			PingLines []map[string]any `json:"pingLines"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(res1.Body.Bytes(), &linesDoc); err != nil {
		t.Fatal(err)
	}
	for _, srv := range linesDoc.Servers {
		if srv.Name != "Tokyo-Ping" {
			if len(srv.PingLines) != 0 {
				t.Fatalf("server %s without probe data must not carry pingLines: %v", srv.Name, srv.PingLines)
			}
			continue
		}
		if len(srv.PingLines) != 2 {
			t.Fatalf("expected one line per probe task (2), got %d", len(srv.PingLines))
		}
		for i, want := range []string{"Secret-Task-A", "Secret-Task-B"} {
			line := srv.PingLines[i]
			assertOnlyAllowedKeys(t, "status.servers[].pingLines[]", line, "name", "buckets")
			if line["name"] != want {
				t.Fatalf("pingLines[%d] name = %v, want %s (admin order)", i, line["name"], want)
			}
			buckets, _ := line["buckets"].([]any)
			if len(buckets) == 0 {
				t.Fatalf("pingLines[%d] has no buckets", i)
			}
			assertOnlyAllowedKeys(t, "status.servers[].pingLines[].buckets[]", buckets[0].(map[string]any), "at", "ms", "loss")
		}
	}

	var decoded struct {
		Servers []map[string]any `json:"servers"`
	}
	if err := json.Unmarshal(res1.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	byName := map[string]map[string]any{}
	for _, item := range decoded.Servers {
		byName[item["name"].(string)] = item
	}

	s1 := byName["Tokyo-Ping"]
	if s1["ipv4"] != true || s1["ipv6"] != false {
		t.Fatalf("srv1 ipv flags mismatch: %v", s1)
	}
	buckets := s1["ping"].([]any)
	if len(buckets) != 30 {
		t.Fatalf("expected 30 ping buckets, got %d", len(buckets))
	}
	// Trailing 4 buckets correspond to -3m (mixed), -2m (all lost), -1m (25ms), 0m (live 18ms + 1 lost -> loss 50%).
	m3 := buckets[len(buckets)-4].(map[string]any)
	if m3["ms"] != float64(30) || m3["loss"] != float64(25) {
		t.Fatalf("expected -3m bucket ms=30 loss=25, got %v", m3)
	}
	m2 := buckets[len(buckets)-3].(map[string]any)
	if m2["ms"] != float64(-1) || m2["loss"] != float64(100) {
		t.Fatalf("expected -2m all-lost bucket ms=-1 loss=100, got %v", m2)
	}
	m0 := buckets[len(buckets)-1].(map[string]any)
	if m0["ms"] != float64(18) || m0["loss"] != float64(50) {
		t.Fatalf("expected current minute live bucket ms=18 loss=50, got %v", m0)
	}

	s2 := byName["Singapore-Quiet"]
	if s2["ipv4"] != false || s2["ipv6"] != true {
		t.Fatalf("srv2 ipv flags mismatch: %v", s2)
	}
	if _, exists := s2["ping"]; exists {
		t.Fatalf("expected srv2 ping to be omitted when no ping data exists: %v", s2)
	}
}

func TestPublicStatusPingSummaryCached30sAndInvalidatedWithSnapshot(t *testing.T) {
	t.Setenv("MUI_STATUS_LISTEN", "127.0.0.1:18088")
	p := newTestMui(t)
	now := time.Date(2026, 11, 14, 16, 0, 10, 0, time.UTC)
	var nowMu sync.Mutex
	setNow := func(next time.Time) {
		nowMu.Lock()
		now = next
		nowMu.Unlock()
	}
	p.app.monitorNow = func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}

	srvID, srvTok, _ := enrollMonitorTestServer(t, p, "ping-cache-node")
	if code, out, _ := p.do("PATCH", "/api/servers/"+srvID, map[string]any{
		"name":          "ping-cache-node",
		"roles":         []string{"exit"},
		"country":       "JP",
		"ipv4":          "203.0.113.20",
		"publicVisible": true,
		"publicName":    "Tokyo-Cached-Ping",
	}, nil); code != 200 {
		t.Fatalf("patch server: %d %v", code, out)
	}

	code, taskOut, _ := p.do("POST", "/api/ping-tasks", map[string]any{
		"name":            "Ping-Cache-Task",
		"target":          "1.1.1.1:443",
		"intervalSeconds": 60,
		"serverIds":       []string{srvID},
	}, nil)
	if code != 201 {
		t.Fatalf("create ping task: %d %v", code, taskOut)
	}
	taskID := taskOut["id"].(string)

	curMinute := now.Truncate(time.Minute)
	for i := 5; i >= 1; i-- {
		atMs := curMinute.Add(-time.Duration(i) * time.Minute).UnixMilli()
		if err := p.store.UpsertPingMinute(taskID, srvID, atMs, 32, 36, 2, 0); err != nil {
			t.Fatal(err)
		}
	}

	reportSample := func(cpu float64) {
		monPayload, _ := json.Marshal(shared.MonitorRequest{
			Sample: shared.MonitorSample{At: p.app.monitorNow(), CPU: cpu, NetUp: 120, NetDown: 340},
		})
		monReq := httptest.NewRequest("POST", "/agent/monitor", bytes.NewReader(monPayload))
		monReq.Header.Set("X-Server-ID", srvID)
		monReq.Header.Set("Authorization", "Bearer "+srvTok)
		signAgentRequest(t, monReq, srvTok, monPayload)
		monRec := httptest.NewRecorder()
		p.handler.ServeHTTP(monRec, monReq)
		if monRec.Code != 200 {
			t.Fatalf("POST /agent/monitor: %d %s", monRec.Code, monRec.Body.String())
		}
	}

	if code, _, _ := p.do("PUT", "/api/settings/status-page", map[string]any{
		"enabled":     true,
		"title":       "Status",
		"showTraffic": true,
		"showPing":    true,
	}, nil); code != 200 {
		t.Fatalf("enable status page failed: %d", code)
	}

	statusMux := p.app.StatusHandler()
	fetchStatus := func(ip string) map[string]any {
		res := statusServe(statusMux, "GET", "/api/public/status", nil, ip)
		if res.Code != 200 {
			t.Fatalf("GET /api/public/status: %d %s", res.Code, res.Body.String())
		}
		var out struct {
			Servers []map[string]any `json:"servers"`
		}
		if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Servers) != 1 {
			t.Fatalf("expected 1 server, got %d", len(out.Servers))
		}
		return out.Servers[0]
	}

	baseBuilds := p.app.statusSnapshotBuilds.Load()
	baseQueries := p.store.publicPingQueries.Load()

	// Initial build at T0: builds snapshot once and executes ping query once.
	reportSample(15)
	s0 := fetchStatus("198.51.100.30:1001")
	if got := p.app.statusSnapshotBuilds.Load() - baseBuilds; got != 1 {
		t.Fatalf("initial snapshot builds=%d, want 1", got)
	}
	if got := p.store.publicPingQueries.Load() - baseQueries; got != 1 {
		t.Fatalf("initial ping queries=%d, want 1", got)
	}
	if pingList, ok := s0["ping"].([]any); !ok || len(pingList) != 5 {
		t.Fatalf("expected 5 cached ping buckets on initial build, got %v", s0["ping"])
	}

	// Multiple snapshot rebuilds (>2s snapshot TTL) within 30s must reuse the cached ping summary.
	t0 := now
	for idx, step := range []struct {
		offset time.Duration
		cpu    float64
	}{
		{3 * time.Second, 25},
		{10 * time.Second, 35},
		{25 * time.Second, 45},
	} {
		setNow(t0.Add(step.offset))
		reportSample(step.cpu)
		srvItem := fetchStatus(fmt.Sprintf("198.51.100.%d:1002", 31+idx))
		wantBuilds := int64(2 + idx)
		if got := p.app.statusSnapshotBuilds.Load() - baseBuilds; got != wantBuilds {
			t.Fatalf("step %d (%s): snapshot builds=%d, want %d", idx, step.offset, got, wantBuilds)
		}
		if got := p.store.publicPingQueries.Load() - baseQueries; got != 1 {
			t.Fatalf("step %d (%s): expected ping summary cache hit (queries=%d, want 1)", idx, step.offset, got)
		}
		sampleMap := srvItem["sample"].(map[string]any)
		if sampleMap["cpu"] != step.cpu {
			t.Fatalf("step %d: expected fresh cpu=%.0f in rebuilt snapshot, got %v", idx, step.cpu, sampleMap["cpu"])
		}
		if pingList, ok := srvItem["ping"].([]any); !ok || len(pingList) != 5 {
			t.Fatalf("step %d: expected 5 ping buckets from cache, got %v", idx, srvItem["ping"])
		}
	}

	// invalidatePublicStatusSnapshot must invalidate the 30s ping summary cache too.
	setNow(t0.Add(26 * time.Second))
	p.app.invalidatePublicStatusSnapshot()
	fetchStatus("198.51.100.40:1003")
	if got := p.app.statusSnapshotBuilds.Load() - baseBuilds; got != 5 {
		t.Fatalf("after invalidate: snapshot builds=%d, want 5", got)
	}
	if got := p.store.publicPingQueries.Load() - baseQueries; got != 2 {
		t.Fatalf("after invalidate: expected ping query re-execution (queries=%d, want 2)", got)
	}

	// Advancing past 30s ping summary TTL must re-query on the next snapshot rebuild.
	setNow(t0.Add(26*time.Second + 31*time.Second))
	fetchStatus("198.51.100.41:1004")
	if got := p.app.statusSnapshotBuilds.Load() - baseBuilds; got != 6 {
		t.Fatalf("after 30s expiry: snapshot builds=%d, want 6", got)
	}
	if got := p.store.publicPingQueries.Load() - baseQueries; got != 3 {
		t.Fatalf("after 30s expiry: expected ping query re-execution (queries=%d, want 3)", got)
	}
}
