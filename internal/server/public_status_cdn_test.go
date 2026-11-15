package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

func sendAgentMonitorReport(t *testing.T, p *testMui, srvID, srvToken string, reqPayload shared.MonitorRequest) {
	t.Helper()
	payload, err := json.Marshal(reqPayload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/agent/monitor", bytes.NewReader(payload))
	req.Header.Set("X-Server-ID", srvID)
	req.Header.Set("Authorization", "Bearer "+srvToken)
	signAgentRequest(t, req, srvToken, payload)
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /agent/monitor: %d %s", rec.Code, rec.Body.String())
	}
}

func extractJSONFromCDNScript(t *testing.T, jsBody string) []byte {
	t.Helper()
	const sep = "})("
	idx := strings.LastIndex(jsBody, sep)
	if idx < 0 || !strings.HasSuffix(jsBody, ");\n") {
		t.Fatalf("unexpected JS wrapper shape: %q", jsBody)
	}
	return []byte(jsBody[idx+len(sep) : len(jsBody)-len(");\n")])
}

func TestPublicStatusCDNFilteringLatenciesAndSecurity(t *testing.T) {
	t.Setenv("MUI_STATUS_LISTEN", "127.0.0.1:18088")
	t.Setenv("MUI_STATUS_URL", "https://tz.example.test")
	p := newTestMui(t)
	now := time.Date(2026, 11, 15, 10, 0, 10, 0, time.UTC)
	p.app.monitorNow = func() time.Time { return now }

	// 1. Visible CDN node (mixed case/whitespace group, lower SortWeight than Edge-Top, online via LastSeen).
	cdnUpper, tokUpper, _ := enrollMonitorTestServer(t, p, "secret-cdn-upper")
	// 2. Visible CDN node (higher SortWeight -> first in list, partial packet loss, contains </script> to test JSON escaping).
	cdnTop, tokTop, _ := enrollMonitorTestServer(t, p, "secret-cdn-top")
	// 3. Visible CDN node with 100% packet loss (ms -> null, loss -> 100).
	cdnAllLoss, tokAllLoss, _ := enrollMonitorTestServer(t, p, "secret-cdn-loss")
	// 4. Visible CDN node offline with no ping data.
	cdnNoPing, _, _ := enrollMonitorTestServer(t, p, "secret-cdn-quiet")
	// 5. Hidden CDN node (publicVisible=false -> excluded).
	cdnHidden, _, _ := enrollMonitorTestServer(t, p, "secret-cdn-hidden")
	// 6. Revoked CDN node (publicVisible=true but revoked -> excluded).
	cdnRevoked, _, _ := enrollMonitorTestServer(t, p, "secret-cdn-revoked")
	// 7. Visible non-CDN node (excluded from /api/public/cdn.*, must retain ping on /api/public/status).
	nonCDN, tokNonCDN, _ := enrollMonitorTestServer(t, p, "secret-non-cdn")

	patchServer := func(id string, body map[string]any) {
		t.Helper()
		c, out, _ := p.do(http.MethodPatch, "/api/servers/"+id, body, nil)
		if c != http.StatusOK {
			t.Fatalf("patch %s: %d %v", id, c, out)
		}
	}

	patchServer(cdnUpper, map[string]any{
		"name":          "secret-cdn-upper",
		"roles":         []string{"other"},
		"country":       "jp",
		"region":        "Tokyo",
		"city":          "Chiyoda",
		"provider":      "SecretEdgeCorp",
		"notes":         "never-leak-cdn-note",
		"ipv4":          "203.0.113.11",
		"domain":        "cdn1-origin.example.net",
		"publicVisible": true,
		"publicName":    "JP-CDN-Standard",
		"publicNote":    "public-note-not-in-compact-cdn",
		"group":         " cdn ",
		"sortWeight":    10,
	})
	patchServer(cdnTop, map[string]any{
		"name":          "secret-cdn-top",
		"roles":         []string{"other"},
		"country":       "HK",
		"ipv4":          "203.0.113.12",
		"publicVisible": true,
		"publicName":    "HK-CDN-Primary</script>",
		"group":         "CDN",
		"sortWeight":    50,
	})
	patchServer(cdnAllLoss, map[string]any{
		"name":          "secret-cdn-loss",
		"roles":         []string{"other"},
		"country":       "SG",
		"ipv4":          "203.0.113.13",
		"publicVisible": true,
		"publicName":    "SG-CDN-Loss",
		"group":         "CDN",
		"sortWeight":    5,
	})
	patchServer(cdnNoPing, map[string]any{
		"name":          "secret-cdn-quiet",
		"roles":         []string{"other"},
		"country":       "US",
		"ipv4":          "203.0.113.14",
		"publicVisible": true,
		"publicName":    "US-CDN-Offline",
		"group":         "CDN",
		"sortWeight":    1,
	})
	patchServer(cdnHidden, map[string]any{
		"name":          "secret-cdn-hidden",
		"roles":         []string{"other"},
		"country":       "DE",
		"ipv4":          "203.0.113.15",
		"publicVisible": false,
		"publicName":    "Hidden-CDN-Node",
		"group":         "CDN",
	})
	patchServer(cdnRevoked, map[string]any{
		"name":          "secret-cdn-revoked",
		"roles":         []string{"other"},
		"country":       "FR",
		"ipv4":          "203.0.113.16",
		"publicVisible": true,
		"publicName":    "Revoked-CDN-Node",
		"group":         "CDN",
	})
	if c, _, _ := p.do(http.MethodPost, "/api/servers/"+cdnRevoked+"/revoke", map[string]any{}, nil); c != http.StatusOK {
		t.Fatalf("revoke server failed: %d", c)
	}
	patchServer(nonCDN, map[string]any{
		"name":          "secret-non-cdn",
		"roles":         []string{"exit"},
		"country":       "TW",
		"ipv4":          "203.0.113.17",
		"publicVisible": true,
		"publicName":    "TW-Exit-Node",
		"group":         "香港",
	})

	// Set LastSeen only for cdnUpper; cdnTop/cdnAllLoss/nonCDN will be online via live monitor report.
	upperDoc, err := p.store.Server(cdnUpper)
	if err != nil {
		t.Fatal(err)
	}
	upperDoc.LastSeen = &now
	if err := p.store.PutServer(upperDoc); err != nil {
		t.Fatal(err)
	}

	// Create two ping tasks covering our servers.
	c, t1Out, _ := p.do(http.MethodPost, "/api/ping-tasks", map[string]any{
		"name":            "CDN-Probe-CT",
		"target":          "1.1.1.1:443",
		"intervalSeconds": 60,
		"serverIds":       []string{cdnUpper, cdnTop, cdnAllLoss, nonCDN},
	}, nil)
	if c != http.StatusCreated {
		t.Fatalf("task1: %d %v", c, t1Out)
	}
	task1ID := t1Out["id"].(string)

	c, t2Out, _ := p.do(http.MethodPost, "/api/ping-tasks", map[string]any{
		"name":            "CDN-Probe-CU",
		"target":          "8.8.4.4:443",
		"intervalSeconds": 60,
		"serverIds":       []string{cdnTop},
	}, nil)
	if c != http.StatusCreated {
		t.Fatalf("task2: %d %v", c, t2Out)
	}
	task2ID := t2Out["id"].(string)

	// Historical bucket for cdnUpper (-2m: ms=32, loss=0) and cdnTop (-1m).
	curMinute := now.Truncate(time.Minute)
	if err := p.store.UpsertPingMinute(task1ID, cdnUpper, curMinute.Add(-2*time.Minute).UnixMilli(), 32, 35, 2, 0); err != nil {
		t.Fatal(err)
	}
	if err := p.store.UpsertPingMinute(task1ID, cdnTop, curMinute.Add(-1*time.Minute).UnixMilli(), 20, 20, 2, 0); err != nil {
		t.Fatal(err)
	}
	if err := p.store.UpsertPingMinute(task2ID, cdnTop, curMinute.Add(-1*time.Minute).UnixMilli(), 60, 60, 2, 2); err != nil {
		t.Fatal(err)
	}

	// Current minute live reports for cdnTop: task1 avgs 30ms (0 lost), task2 avgs 60ms (1/2 lost) -> ms=45, loss=25%.
	sendAgentMonitorReport(t, p, cdnTop, tokTop, shared.MonitorRequest{
		Sample: shared.MonitorSample{At: now, CPU: 10},
		Pings: []shared.PingResult{
			{TaskID: task1ID, Ms: 20},
			{TaskID: task2ID, Ms: -1},
		},
	})
	sendAgentMonitorReport(t, p, cdnTop, tokTop, shared.MonitorRequest{
		Sample: shared.MonitorSample{At: now, CPU: 11},
		Pings: []shared.PingResult{
			{TaskID: task1ID, Ms: 40},
			{TaskID: task2ID, Ms: 60},
		},
	})
	// Check: in live accum for curMinute, task1: sent=2, lost=0, avg=(20+40)/2=30; task2: sent=2, lost=1, avg=60.
	// Note addSample averages task avgs unweighted: ms=(30+60)/2=45, loss=(0+1)/(2+2)=25%! Let's verify 45 & 25!
	sendAgentMonitorReport(t, p, cdnAllLoss, tokAllLoss, shared.MonitorRequest{
		Sample: shared.MonitorSample{At: now, CPU: 5},
		Pings: []shared.PingResult{
			{TaskID: task1ID, Ms: -1},
		},
	})
	sendAgentMonitorReport(t, p, nonCDN, tokNonCDN, shared.MonitorRequest{
		Sample: shared.MonitorSample{At: now, CPU: 8},
		Pings: []shared.PingResult{
			{TaskID: task1ID, Ms: 19},
		},
	})

	// Satisfy lint/tokUpper unused by sending host-only monitor sample without overwriting LastSeen logic.
	_ = tokUpper

	if code, _, _ := p.do(http.MethodPut, "/api/settings/status-page", map[string]any{
		"enabled":     true,
		"title":       "Status",
		"showTraffic": true,
		"showPing":    true,
	}, nil); code != http.StatusOK {
		t.Fatalf("enable status page failed: %d", code)
	}

	statusMux := p.app.StatusHandler()
	beforePingQueries := p.store.publicPingQueries.Load()

	// Hit /api/public/cdn.js on cold cache FIRST.
	jsRes := statusServe(statusMux, http.MethodGet, "/api/public/cdn.js", nil, "198.51.100.10:1234")
	if jsRes.Code != http.StatusOK {
		t.Fatalf("GET /api/public/cdn.js = %d %s", jsRes.Code, jsRes.Body.String())
	}
	if ct := jsRes.Header().Get("Content-Type"); ct != "application/javascript; charset=utf-8" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if acao := jsRes.Header().Get("Access-Control-Allow-Origin"); acao != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q", acao)
	}
	if corp := jsRes.Header().Get("Cross-Origin-Resource-Policy"); corp != "cross-origin" {
		t.Fatalf("Cross-Origin-Resource-Policy = %q", corp)
	}
	if nosniff := jsRes.Header().Get("X-Content-Type-Options"); nosniff != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", nosniff)
	}
	if cc := jsRes.Header().Get("Cache-Control"); cc != "public, max-age=15" {
		t.Fatalf("Cache-Control = %q", cc)
	}

	jsBody := jsRes.Body.String()
	if !strings.HasPrefix(jsBody, "/**/;(function(d){") {
		t.Fatalf("missing JS IIFE prefix: %s", jsBody)
	}
	if !strings.Contains(jsBody, "window.__MUI_CDN_STATUS__=d;") {
		t.Fatalf("missing window.__MUI_CDN_STATUS__ assignment: %s", jsBody)
	}
	if !strings.Contains(jsBody, `new CustomEvent("mui:cdn-status",{detail:d})`) {
		t.Fatalf("missing mui:cdn-status CustomEvent dispatch: %s", jsBody)
	}
	if strings.Contains(jsBody, "</script>") {
		t.Fatalf("raw </script> was not escaped inside JS payload: %s", jsBody)
	}

	// Hit /api/public/cdn.json as well and confirm CORS/CORP headers and exact payload match.
	jsonRes := statusServe(statusMux, http.MethodGet, "/api/public/cdn.json", nil, "198.51.100.11:1234")
	if jsonRes.Code != http.StatusOK {
		t.Fatalf("GET /api/public/cdn.json = %d %s", jsonRes.Code, jsonRes.Body.String())
	}
	if ct := jsonRes.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("cdn.json Content-Type = %q", ct)
	}
	if acao := jsonRes.Header().Get("Access-Control-Allow-Origin"); acao != "*" {
		t.Fatalf("cdn.json ACAO = %q", acao)
	}
	if corp := jsonRes.Header().Get("Cross-Origin-Resource-Policy"); corp != "cross-origin" {
		t.Fatalf("cdn.json CORP = %q", corp)
	}

	embeddedJSON := extractJSONFromCDNScript(t, jsBody)
	if !bytes.Equal(embeddedJSON, jsonRes.Body.Bytes()) {
		t.Fatalf("JS embedded JSON != /api/public/cdn.json\njs:   %s\njson: %s", embeddedJSON, jsonRes.Body.String())
	}

	// Substring security check across both responses.
	forbiddenSubstrings := []string{
		cdnUpper, cdnTop, cdnAllLoss, cdnNoPing, cdnHidden, cdnRevoked, nonCDN,
		task1ID, task2ID,
		"secret-cdn-upper", "secret-cdn-top", "secret-non-cdn",
		"Hidden-CDN-Node", "Revoked-CDN-Node", "TW-Exit-Node",
		"SecretEdgeCorp", "never-leak-cdn-note", "public-note-not-in-compact-cdn",
		"203.0.113.", "cdn1-origin.example.net", "1.1.1.1", "8.8.4.4", "mui.example.test",
	}
	for label, body := range map[string]string{
		"cdn.js":   jsBody,
		"cdn.json": jsonRes.Body.String(),
	} {
		for _, needle := range forbiddenSubstrings {
			if strings.Contains(body, needle) {
				t.Fatalf("%s leaked forbidden value %q: %s", label, needle, body)
			}
		}
	}

	// Strict field whitelist and exact latency/order assertions.
	var raw map[string]any
	if err := json.Unmarshal(jsonRes.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	assertOnlyAllowedKeys(t, "cdn", raw, "generatedAt", "showPing", "total", "online", "servers")
	if raw["showPing"] != true || raw["total"] != float64(4) || raw["online"] != float64(3) {
		t.Fatalf("unexpected cdn header counts: %v", raw)
	}

	srvList := raw["servers"].([]any)
	if len(srvList) != 4 {
		t.Fatalf("expected 4 visible CDN servers, got %d", len(srvList))
	}
	wantNames := []string{"HK-CDN-Primary</script>", "JP-CDN-Standard", "SG-CDN-Loss", "US-CDN-Offline"}
	byName := make(map[string]map[string]any, len(srvList))
	for i, itemAny := range srvList {
		m := itemAny.(map[string]any)
		assertOnlyAllowedKeys(t, "cdn.servers[]", m, "id", "name", "country", "region", "city", "online", "ms", "loss", "testedAt")
		if m["name"] != wantNames[i] {
			t.Fatalf("servers[%d].name = %v, want %s", i, m["name"], wantNames[i])
		}
		byName[m["name"].(string)] = m
	}

	sTop := byName["HK-CDN-Primary</script>"]
	if sTop["id"] != p.store.Fingerprint("status-page", cdnTop) || sTop["online"] != true || sTop["ms"] != float64(45) || sTop["loss"] != float64(25) || sTop["testedAt"] == nil {
		t.Fatalf("unexpected cdnTop item: %v", sTop)
	}
	sUpper := byName["JP-CDN-Standard"]
	if sUpper["country"] != "JP" || sUpper["region"] != "Tokyo" || sUpper["city"] != "Chiyoda" || sUpper["online"] != true || sUpper["ms"] != float64(32) || sUpper["loss"] != float64(0) || sUpper["testedAt"] == nil {
		t.Fatalf("unexpected cdnUpper item: %v", sUpper)
	}
	sLoss := byName["SG-CDN-Loss"]
	if sLoss["online"] != true || sLoss["ms"] != nil || sLoss["loss"] != float64(100) || sLoss["testedAt"] == nil {
		t.Fatalf("unexpected cdnAllLoss item: %v", sLoss)
	}
	sOffline := byName["US-CDN-Offline"]
	if sOffline["online"] != false || sOffline["ms"] != nil || sOffline["loss"] != nil {
		t.Fatalf("unexpected cdnNoPing item: %v", sOffline)
	}
	if _, hasTestedAt := sOffline["testedAt"]; hasTestedAt {
		t.Fatalf("expected testedAt omitted when no ping data exists: %v", sOffline)
	}

	// Critical shared-cache check: hitting /api/public/cdn.js first must NOT starve nonCDN ping data on /api/public/status.
	statusRes := statusServe(statusMux, http.MethodGet, "/api/public/status", nil, "198.51.100.12:1234")
	if statusRes.Code != http.StatusOK {
		t.Fatalf("GET /api/public/status = %d %s", statusRes.Code, statusRes.Body.String())
	}
	if delta := p.store.publicPingQueries.Load() - beforePingQueries; delta != 1 {
		t.Fatalf("expected 1 total ping DB query shared across cdn and status, got %d", delta)
	}
	var fullStatus struct {
		Servers []map[string]any `json:"servers"`
	}
	if err := json.Unmarshal(statusRes.Body.Bytes(), &fullStatus); err != nil {
		t.Fatal(err)
	}
	var foundNonCDN bool
	for _, s := range fullStatus.Servers {
		if s["name"] == "TW-Exit-Node" {
			foundNonCDN = true
			buckets, _ := s["ping"].([]any)
			if len(buckets) == 0 {
				t.Fatalf("nonCDN server ping was starved after /api/public/cdn.js cold hit: %v", s)
			}
		}
	}
	if !foundNonCDN {
		t.Fatal("nonCDN server missing from /api/public/status")
	}

	// Callback validation: valid vs rejected.
	cbRes := statusServe(statusMux, http.MethodGet, "/api/public/cdn.js?callback=onHzcatCdn", nil, "198.51.100.13:1234")
	if cbRes.Code != http.StatusOK {
		t.Fatalf("valid callback GET /api/public/cdn.js = %d", cbRes.Code)
	}
	if !strings.Contains(cbRes.Body.String(), `if(typeof onHzcatCdn==="function"){onHzcatCdn(d);}else if(typeof window!=="undefined"&&typeof window["onHzcatCdn"]==="function"){window["onHzcatCdn"](d);}`) {
		t.Fatalf("callback invocation missing from body: %s", cbRes.Body.String())
	}

	for _, badQuery := range []string{
		"callback=",
		"callback=eval",
		"callback=alert",
		"callback=window",
		"callback=a.b",
		"callback=1x",
		"callback=x()",
		"callback=foo;bar",
		"callback=foo%3Bbar",
		"callback=ok&callback=eval",
		"callback=" + strings.Repeat("a", 65),
	} {
		badRes := statusServe(statusMux, http.MethodGet, "/api/public/cdn.js?"+badQuery, nil, "198.51.100.14:1234")
		if badRes.Code != http.StatusBadRequest {
			t.Fatalf("%s got %d, want 400", badQuery, badRes.Code)
		}
		if !strings.HasPrefix(badRes.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("%s invalid error content-type %q", badQuery, badRes.Header().Get("Content-Type"))
		}
	}

	// Turn off showPing -> invalidates cache immediately; showPing=false and ms/loss=null.
	if code, _, _ := p.do(http.MethodPut, "/api/settings/status-page", map[string]any{
		"showPing": false,
	}, nil); code != http.StatusOK {
		t.Fatalf("disable showPing failed: %d", code)
	}
	noPingRes := statusServe(statusMux, http.MethodGet, "/api/public/cdn.json", nil, "198.51.100.15:1234")
	if noPingRes.Code != http.StatusOK {
		t.Fatalf("cdn.json with showPing=false = %d", noPingRes.Code)
	}
	var noPingPayload PublicCDNStatusResponse
	if err := json.Unmarshal(noPingRes.Body.Bytes(), &noPingPayload); err != nil {
		t.Fatal(err)
	}
	if noPingPayload.ShowPing {
		t.Fatal("expected showPing=false")
	}
	for _, item := range noPingPayload.Servers {
		if item.Ms != nil || item.Loss != nil || item.TestedAt != nil {
			t.Fatalf("expected ping fields cleared when showPing=false: %+v", item)
		}
	}
}

func TestPublicStatusCDNIsolationRateLimitAndGates(t *testing.T) {
	// 1. Unconfigured MUI_STATUS_LISTEN returns 404.
	pUnconf := newTestMui(t)
	if _, _, _ = pUnconf.do(http.MethodPut, "/api/settings/status-page", map[string]any{"enabled": true}, nil); true {
		for _, path := range []string{"/api/public/cdn.js", "/api/public/cdn.json"} {
			if rec := statusServe(pUnconf.app.StatusHandler(), http.MethodGet, path, nil, "198.51.100.55:1234"); rec.Code != http.StatusNotFound {
				t.Fatalf("unconfigured %s = %d, want 404", path, rec.Code)
			}
		}
	}

	t.Setenv("MUI_STATUS_LISTEN", "127.0.0.1:18088")
	t.Setenv("MUI_TRUSTED_PROXIES", "10.0.0.0/8")
	p := newTestMui(t)
	now := time.Date(2026, 11, 15, 11, 0, 0, 0, time.UTC)
	p.app.monitorNow = func() time.Time { return now }

	srvID, _, _ := enrollMonitorTestServer(t, p, "cdn-gate-srv")
	if c, out, _ := p.do(http.MethodPatch, "/api/servers/"+srvID, map[string]any{
		"name":          "cdn-gate-srv",
		"roles":         []string{"other"},
		"country":       "HK",
		"ipv4":          "203.0.113.88",
		"publicVisible": true,
		"publicName":    "Initial-CDN",
		"group":         "CDN",
	}, nil); c != http.StatusOK {
		t.Fatalf("patch: %d %v", c, out)
	}

	statusMux := p.app.StatusHandler()

	// 2. Disabled status page returns 404 on /api/public/cdn.*.
	for _, path := range []string{"/api/public/cdn.js", "/api/public/cdn.json"} {
		if rec := statusServe(statusMux, http.MethodGet, path, nil, "198.51.100.40:1234"); rec.Code != http.StatusNotFound {
			t.Fatalf("disabled %s = %d, want 404", path, rec.Code)
		}
	}

	if c, _, _ := p.do(http.MethodPut, "/api/settings/status-page", map[string]any{"enabled": true}, nil); c != http.StatusOK {
		t.Fatalf("enable: %d", c)
	}

	// 3. Main admin listener returns 404 for /api/public/cdn.*; status listener rejects non-GET methods.
	for _, path := range []string{"/api/public/cdn.js", "/api/public/cdn.json"} {
		if c, _, _ := p.do(http.MethodGet, path, nil, nil); c != http.StatusNotFound {
			t.Fatalf("main mux GET %s = %d, want 404", path, c)
		}
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			if rec := statusServe(statusMux, method, path, nil, "198.51.100.40:1234"); rec.Code != http.StatusNotFound {
				t.Fatalf("status mux %s %s = %d, want 404", method, path, rec.Code)
			}
		}
	}

	// 4. 2s CDN snapshot cache & invalidation.
	r1 := statusServe(statusMux, http.MethodGet, "/api/public/cdn.json", nil, "198.51.100.60:1111")
	if r1.Code != http.StatusOK || !strings.Contains(r1.Body.String(), "Initial-CDN") {
		t.Fatalf("r1 = %d %s", r1.Code, r1.Body.String())
	}
	srvDoc, _ := p.store.Server(srvID)
	srvDoc.PublicName = "Mutated-CDN"
	_ = p.store.PutServer(srvDoc)

	now = now.Add(1 * time.Second)
	r2 := statusServe(statusMux, http.MethodGet, "/api/public/cdn.json", nil, "198.51.100.60:1111")
	if !strings.Contains(r2.Body.String(), "Initial-CDN") {
		t.Fatalf("expected cached Initial-CDN within 2s TTL, got %s", r2.Body.String())
	}
	now = now.Add(2 * time.Second)
	r3 := statusServe(statusMux, http.MethodGet, "/api/public/cdn.json", nil, "198.51.100.60:1111")
	if !strings.Contains(r3.Body.String(), "Mutated-CDN") {
		t.Fatalf("expected refreshed Mutated-CDN after 2s TTL, got %s", r3.Body.String())
	}

	// 5. Rate limiting (120/min) applies to /api/public/cdn.js.
	for i := 1; i <= 120; i++ {
		rec := statusServe(statusMux, http.MethodGet, "/api/public/cdn.js", map[string]string{
			"X-Forwarded-For": "203.0.113.210",
		}, "10.0.0.5:4321")
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d failed: %d", i, rec.Code)
		}
	}
	limited := statusServe(statusMux, http.MethodGet, "/api/public/cdn.js", map[string]string{
		"X-Forwarded-For": "203.0.113.210",
	}, "10.0.0.5:4321")
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 121st request, got %d", limited.Code)
	}
}
