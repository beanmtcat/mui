package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"mui/internal/shared"
)

func enrollMonitorTestServer(t *testing.T, p *testMui, name string) (string, string, map[string]string) {
	t.Helper()
	code, out, _ := p.do("POST", "/api/servers", map[string]any{
		"name":    name,
		"roles":   []string{"exit"},
		"country": "JP",
		"ipv4":    "203.0.113.10",
	}, nil)
	if code != 201 {
		t.Fatalf("create server %s: %d %v", name, code, out)
	}
	id := out["server"].(map[string]any)["id"].(string)
	code, enrolled, _ := p.do("POST", "/agent/enroll", map[string]string{
		"serverId": id,
		"token":    out["enrollToken"].(string),
	}, nil)
	if code != 200 {
		t.Fatalf("enroll server %s: %d %v", name, code, enrolled)
	}
	token := enrolled["agentToken"].(string)
	return id, token, map[string]string{
		"X-Server-ID":   id,
		"Authorization": "Bearer " + token,
	}
}

func TestAgentMonitorAuthClampingPingIsolationAndZeroServerLocks(t *testing.T) {
	p := newTestMui(t)
	s1ID, s1Token, s1Headers := enrollMonitorTestServer(t, p, "mon-1")
	s2ID, _, _ := enrollMonitorTestServer(t, p, "mon-2")

	// Clear serverLocks populated during enrollment so we can assert /agent/monitor never touches it.
	p.app.serverLocksMu.Lock()
	delete(p.app.serverLocks, s1ID)
	p.app.serverLocksMu.Unlock()

	validBody, _ := json.Marshal(shared.MonitorRequest{
		Sample: shared.MonitorSample{At: time.Now().UTC(), CPU: 25.5, RAMUsed: 512, RAMTotal: 1024},
	})

	// 1. Unsigned request must be rejected even when agent_signs == 0 right after enrollment.
	unsignedReq := httptest.NewRequest("POST", "/agent/monitor", bytes.NewReader(validBody))
	unsignedReq.Header.Set("X-Server-ID", s1ID)
	unsignedReq.Header.Set("Authorization", "Bearer "+s1Token)
	rec := httptest.NewRecorder()
	p.handler.ServeHTTP(rec, unsignedReq)
	if rec.Code != 401 {
		t.Fatalf("expected 401 for unsigned /agent/monitor, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Bad signature must be rejected.
	badSigReq := httptest.NewRequest("POST", "/agent/monitor", bytes.NewReader(validBody))
	badSigReq.Header.Set("X-Server-ID", s1ID)
	badSigReq.Header.Set("Authorization", "Bearer "+s1Token)
	signAgentRequest(t, badSigReq, s1Token, validBody)
	badSigReq.Header.Set("X-Agent-Signature", strings.Repeat("0", 64))
	rec = httptest.NewRecorder()
	p.handler.ServeHTTP(rec, badSigReq)
	if rec.Code != 401 {
		t.Fatalf("expected 401 for invalid signature, got %d", rec.Code)
	}

	// 3. NaN / Inf samples are rejected by sanitizeMonitorSample, and overflow JSON floats return 400.
	if _, ok := sanitizeMonitorSample(shared.MonitorSample{CPU: math.NaN()}, time.Now()); ok {
		t.Fatal("expected NaN CPU to be rejected")
	}
	if _, ok := sanitizeMonitorSample(shared.MonitorSample{Load1: math.Inf(1)}, time.Now()); ok {
		t.Fatal("expected +Inf Load1 to be rejected")
	}
	overflowJSON := []byte(`{"sample":{"cpu":1e400}}`)
	nanReq := httptest.NewRequest("POST", "/agent/monitor", bytes.NewReader(overflowJSON))
	nanReq.Header.Set("X-Server-ID", s1ID)
	nanReq.Header.Set("Authorization", "Bearer "+s1Token)
	signAgentRequest(t, nanReq, s1Token, overflowJSON)
	rec = httptest.NewRecorder()
	p.handler.ServeHTTP(rec, nanReq)
	if rec.Code != 400 {
		t.Fatalf("expected 400 for overflow float JSON, got %d", rec.Code)
	}

	// 4. Create two ping tasks: one assigned to all servers, one assigned exclusively to s2.
	code, taskAll, _ := p.do("POST", "/api/ping-tasks", map[string]any{
		"name":            "Cloudflare",
		"target":          "1.1.1.1:443",
		"intervalSeconds": 60,
	}, nil)
	if code != 201 {
		t.Fatalf("create taskAll: %d %v", code, taskAll)
	}
	taskAllID := taskAll["id"].(string)

	code, taskS2Only, _ := p.do("POST", "/api/ping-tasks", map[string]any{
		"name":            "Quad9-S2",
		"target":          "9.9.9.9:443",
		"intervalSeconds": 60,
		"serverIds":       []string{s2ID},
	}, nil)
	if code != 201 {
		t.Fatalf("create taskS2Only: %d %v", code, taskS2Only)
	}
	taskS2OnlyID := taskS2Only["id"].(string)

	// Re-clear serverLocks in case any admin call touched locks.
	p.app.serverLocksMu.Lock()
	delete(p.app.serverLocks, s1ID)
	p.app.serverLocksMu.Unlock()

	// 5. Submit sample with out-of-range values, oversized UTF-8 host strings, and pings for both tasks.
	now := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
	panelClock := now
	p.app.monitorNow = func() time.Time { return panelClock }
	longStr := strings.Repeat("霄", 80) // 240 UTF-8 bytes > 128
	code, monResp, _ := p.do("POST", "/agent/monitor", shared.MonitorRequest{
		Sample: shared.MonitorSample{
			At:       now.Add(25 * time.Minute), // skewed Agent clock; panel receive time must win
			CPU:      175.5,
			Load1:    -3.2,
			RAMUsed:  8192,
			RAMTotal: 4096,
			DiskUsed: -50,
			NetUp:    1 << 60,
			TCP:      -5,
		},
		Host: &shared.MonitorHost{
			CPUName:  longStr,
			CPUCores: -4,
			OS:       "Debian 13",
			Arch:     "amd64",
			MemTotal: 4096,
		},
		Pings: []shared.PingResult{
			{TaskID: taskAllID, At: now.Add(25 * time.Minute), Ms: 18},
			{TaskID: taskS2OnlyID, At: now, Ms: 22},
			{TaskID: "non-existent-task", At: now, Ms: 11},
		},
	}, s1Headers)
	if code != 200 {
		t.Fatalf("POST /agent/monitor failed: %d %v", code, monResp)
	}

	// Verify serverLocks does NOT contain s1ID!
	p.app.serverLocksMu.Lock()
	_, hasLock := p.app.serverLocks[s1ID]
	p.app.serverLocksMu.Unlock()
	if hasLock {
		t.Fatal("POST /agent/monitor must not create or acquire a serverLocks entry")
	}

	// Response only returns tasks assigned to s1 (taskAllID, NOT taskS2OnlyID).
	pingsAssigned, _ := monResp["pings"].([]any)
	if len(pingsAssigned) != 1 || pingsAssigned[0].(map[string]any)["id"] != taskAllID {
		t.Fatalf("expected only taskAllID assigned to s1, got %v", pingsAssigned)
	}

	// Advance panel clock to next minute so ping & sample buckets flush to SQLite.
	nextMin := now.Add(time.Minute)
	panelClock = nextMin
	code, _, _ = p.do("POST", "/agent/monitor", shared.MonitorRequest{
		Sample: shared.MonitorSample{At: nextMin, CPU: 10, RAMUsed: 1024, RAMTotal: 4096},
	}, s1Headers)
	if code != 200 {
		t.Fatalf("second POST /agent/monitor failed: %d", code)
	}

	// Check clamped values via GET /api/monitor and mui_monitor_minutes.
	hosts, err := p.store.MonitorHosts()
	if err != nil {
		t.Fatal(err)
	}
	h := hosts[s1ID]
	if len(h.CPUName) > 128 || h.CPUCores != 0 {
		t.Fatalf("host fields were not clamped properly: len(CPUName)=%d cores=%d", len(h.CPUName), h.CPUCores)
	}
	records, err := p.store.MonitorRecords(s1ID, "1h", time.Now().UTC(), 1500)
	if err != nil || len(records) == 0 {
		t.Fatalf("MonitorRecords: %v %v", err, records)
	}
	first := records[0]
	if first.CPU != 100 || first.Load1 != 0 || first.RAMUsed != 4096 || first.DiskUsed != 0 || first.NetUp != maxMonitorInt || first.TCP != 0 {
		t.Fatalf("minute record was not clamped properly: %+v", first)
	}

	// Unassigned taskS2OnlyID ping submitted by s1 must NOT be stored!
	s2Recs, err := p.store.PingRecords(taskS2OnlyID, "", "24h", time.Now().UTC(), 1500)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2Recs) != 0 {
		t.Fatalf("expected unassigned ping result to be ignored, got %+v", s2Recs)
	}
	allRecs, err := p.store.PingRecords(taskAllID, s1ID, "24h", time.Now().UTC(), 1500)
	if err != nil || len(allRecs) != 1 || allRecs[0].MsAvg != 18 || allRecs[0].Sent != 1 || allRecs[0].Lost != 0 {
		t.Fatalf("expected assigned ping result to be recorded, got %v %+v", err, allRecs)
	}
}

func TestMonitorAggregationHourlyRollupIdempotencyAndRetentionPruning(t *testing.T) {
	p := newTestMui(t)
	sID, _, headers := enrollMonitorTestServer(t, p, "rollup-srv")

	// Feed 2 samples in minute M0 and 1 sample in minute M1 to verify minute aggregation math.
	m0 := time.Now().UTC().Truncate(time.Minute).Add(-3 * time.Minute)
	panelClock := m0
	p.app.monitorNow = func() time.Time { return panelClock }
	steps := []struct {
		recvAt time.Time
		sample shared.MonitorSample
	}{
		{
			recvAt: m0.Add(5 * time.Second),
			sample: shared.MonitorSample{
				At: m0.Add(40 * time.Minute), CPU: 20, Load1: 1.0,
				RAMUsed: 1000, RAMTotal: 4000, SwapUsed: 100, DiskUsed: 5000, DiskTotal: 10000,
				NetUp: 100, NetDown: 200, NetTotalUp: 1000, NetTotalDown: 2000,
				TCP: 10, UDP: 4, Process: 80,
			},
		},
		{
			recvAt: m0.Add(25 * time.Second),
			sample: shared.MonitorSample{
				At: m0.Add(-40 * time.Minute), CPU: 40, Load1: 3.0,
				RAMUsed: 3000, RAMTotal: 4000, SwapUsed: 300, DiskUsed: 7000, DiskTotal: 10000,
				NetUp: 500, NetDown: 600, NetTotalUp: 1500, NetTotalDown: 2600,
				TCP: 20, UDP: 8, Process: 100,
			},
		},
		{
			recvAt: m0.Add(65 * time.Second),
			sample: shared.MonitorSample{
				CPU: 50, Load1: 2.0,
				RAMUsed: 2000, RAMTotal: 4000,
			},
		},
	}
	for _, st := range steps {
		panelClock = st.recvAt
		if code, out, _ := p.do("POST", "/agent/monitor", shared.MonitorRequest{Sample: st.sample}, headers); code != 200 {
			t.Fatalf("POST /agent/monitor: %d %v", code, out)
		}
	}

	minRecs, err := p.store.MonitorRecords(sID, "1h", time.Now().UTC(), 1500)
	if err != nil || len(minRecs) != 1 {
		t.Fatalf("expected 1 flushed minute record, got %d (%v)", len(minRecs), err)
	}
	got := minRecs[0]
	if got.CPU != 30 || got.Load1 != 2.0 || got.RAMUsed != 2000 || got.SwapUsed != 200 || got.DiskUsed != 6000 ||
		got.NetUp != 300 || got.NetDown != 400 || got.NetUpPeak != 500 || got.NetDownPeak != 600 ||
		got.TotalUp != 1500 || got.TotalDown != 2600 || got.TCP != 15 || got.UDP != 6 || got.Process != 90 {
		t.Fatalf("unexpected minute aggregation values: %+v", got)
	}

	// Insert two minute rows in a completed hour (2 hours ago) and verify RollupMonitorHours accuracy + idempotency.
	now := time.Now().UTC()
	completedHour := now.Truncate(time.Hour).Add(-2 * time.Hour)
	if err := p.store.PutMonitorMinute(sID, completedHour.UnixMilli(), MonitorRecord{
		CPU: 10, Load1: 0.5, RAMUsed: 1000, RAMTotal: 8000, SwapUsed: 50, DiskUsed: 2000, DiskTotal: 20000,
		NetUp: 100, NetDown: 300, NetUpPeak: 250, NetDownPeak: 700, TotalUp: 5000, TotalDown: 9000,
		TCP: 10, UDP: 2, Process: 50,
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.store.PutMonitorMinute(sID, completedHour.Add(15*time.Minute).UnixMilli(), MonitorRecord{
		CPU: 30, Load1: 1.5, RAMUsed: 3000, RAMTotal: 8000, SwapUsed: 150, DiskUsed: 4000, DiskTotal: 20000,
		NetUp: 300, NetDown: 500, NetUpPeak: 900, NetDownPeak: 600, TotalUp: 8500, TotalDown: 14000,
		TCP: 30, UDP: 6, Process: 70,
	}); err != nil {
		t.Fatal(err)
	}

	// Insert a minute row 5 hours ago: RollupMonitorHours must only scan the last 3 completed hours.
	fiveHoursAgo := now.Truncate(time.Hour).Add(-5 * time.Hour)
	if err := p.store.PutMonitorMinute(sID, fiveHoursAgo.UnixMilli(), MonitorRecord{CPU: 88, Load1: 4.0}); err != nil {
		t.Fatal(err)
	}

	if err := p.store.RollupMonitorHours(now); err != nil {
		t.Fatalf("first RollupMonitorHours: %v", err)
	}
	if err := p.store.RollupMonitorHours(now); err != nil {
		t.Fatalf("second RollupMonitorHours (idempotency): %v", err)
	}

	hourRecs, err := p.store.MonitorRecords(sID, "7d", now, 1500)
	if err != nil || len(hourRecs) != 1 {
		t.Fatalf("expected 1 rolled-up hour record (3h window, excluding 5h-old row), got %d (%v)", len(hourRecs), err)
	}
	hr := hourRecs[0]
	if !hr.At.Equal(completedHour) || hr.CPU != 20 || hr.Load1 != 1.0 || hr.RAMUsed != 2000 || hr.RAMTotal != 8000 ||
		hr.NetUp != 200 || hr.NetDown != 400 || hr.NetUpPeak != 900 || hr.NetDownPeak != 700 ||
		hr.TotalUp != 8500 || hr.TotalDown != 14000 || hr.TCP != 20 || hr.UDP != 4 || hr.Process != 60 {
		t.Fatalf("unexpected hourly rollup values: %+v", hr)
	}

	// Verify retention pruning for monitor minutes (3d), ping minutes (7d), and monitor hours (retention days).
	oldMin := now.Add(-4 * 24 * time.Hour)
	if err := p.store.PutMonitorMinute(sID, oldMin.UnixMilli(), MonitorRecord{CPU: 99}); err != nil {
		t.Fatal(err)
	}
	oldHour := now.Add(-95 * 24 * time.Hour).Truncate(time.Hour)
	_, err = p.store.DB.Exec(
		`INSERT INTO mui_monitor_hours(server_id,at_ms,cpu,load1,ram_used,ram_total,swap_used,disk_used,disk_total,net_up,net_down,net_up_peak,net_down_peak,total_up,total_down,tcp,udp,process) VALUES($1,$2,50,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0)`,
		sID, oldHour.UnixMilli(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.store.UpsertPingMinute("t-prune", sID, now.Add(-8*24*time.Hour).UnixMilli(), 20, 25, 2, 0); err != nil {
		t.Fatal(err)
	}
	if err := p.store.UpsertPingMinute("t-prune", sID, now.Add(-2*24*time.Hour).UnixMilli(), 15, 18, 2, 0); err != nil {
		t.Fatal(err)
	}

	if err := p.store.PruneMonitorMinutes(now.Add(-72 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := p.store.PruneMonitorHours(now.AddDate(0, 0, -90)); err != nil {
		t.Fatal(err)
	}
	if err := p.store.PrunePingMinutes(now.Add(-7 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_monitor_minutes WHERE at_ms=$1`, oldMin.UnixMilli()).Scan(&count); err != nil || count != 0 {
		t.Fatalf("expected 4d-old monitor minute to be pruned, count=%d err=%v", count, err)
	}
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_monitor_hours WHERE at_ms=$1`, oldHour.UnixMilli()).Scan(&count); err != nil || count != 0 {
		t.Fatalf("expected 95d-old monitor hour to be pruned, count=%d err=%v", count, err)
	}
	if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_monitor_hours WHERE at_ms=$1`, completedHour.UnixMilli()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("expected recent monitor hour to be retained, count=%d err=%v", count, err)
	}
	pingLeft, err := p.store.PingRecords("t-prune", sID, "7d", now, 1500)
	if err != nil || len(pingLeft) != 1 {
		t.Fatalf("expected only 2d-old ping minute to remain, got %d (%v)", len(pingLeft), err)
	}
}

func TestPurgeServerCleansAllMonitorTablesAndMemory(t *testing.T) {
	p := newTestMui(t)
	sID, _, headers := enrollMonitorTestServer(t, p, "purge-target")

	code, taskOut, _ := p.do("POST", "/api/ping-tasks", map[string]any{
		"name":            "Exclusive-Ping",
		"target":          "1.1.1.1:443",
		"intervalSeconds": 60,
		"serverIds":       []string{sID},
	}, nil)
	if code != 201 {
		t.Fatalf("create ping task: %d %v", code, taskOut)
	}
	taskID := taskOut["id"].(string)

	now := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
	panelClock := now
	p.app.monitorNow = func() time.Time { return panelClock }
	if code, _, _ := p.do("POST", "/agent/monitor", shared.MonitorRequest{
		Sample: shared.MonitorSample{At: now, CPU: 42, RAMUsed: 512, RAMTotal: 1024},
		Host:   &shared.MonitorHost{CPUName: "EPYC", CPUCores: 4, OS: "Ubuntu", Arch: "amd64"},
		Pings:  []shared.PingResult{{TaskID: taskID, At: now, Ms: 14}},
	}, headers); code != 200 {
		t.Fatalf("first monitor post failed: %d", code)
	}
	// Flush completed minute buckets via background flush without a second Agent request!
	p.app.FlushMonitorBuckets(now.Add(time.Minute))
	if err := p.store.RollupMonitorHourRange(now.Add(-2*time.Hour).UnixMilli(), now.Add(2*time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}

	// Revoke so server is offline/revoked, then DELETE.
	if code, _, _ := p.do("POST", "/api/servers/"+sID+"/revoke", nil, nil); code != 200 {
		t.Fatalf("revoke server: %d", code)
	}
	if code, out, _ := p.do("DELETE", "/api/servers/"+sID+"?force=1", nil, nil); code != 200 {
		t.Fatalf("delete server: %d %v", code, out)
	}

	for _, table := range []string{"mui_monitor_hosts", "mui_monitor_minutes", "mui_monitor_hours", "mui_ping_minutes", "mui_ping_tasks"} {
		var n int
		if err := p.store.DB.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("expected %s to be empty after server deletion, got count=%d err=%v", table, n, err)
		}
	}
	if _, ok := p.app.latestMonitorSample(sID); ok {
		t.Fatal("expected in-memory latestSamples entry to be cleared on server deletion")
	}
}

func TestPingTasksValidationAndMaxLimit(t *testing.T) {
	p := newTestMui(t)
	for _, bad := range []string{
		"",
		"1.1.1.1",
		"127.0.0.1:80",
		"[::1]:443",
		"10.0.0.1:443",
		"172.16.0.1:80",
		"192.168.1.1:80",
		"100.64.0.1:443",
		"169.254.169.254:80",
		"localhost:443",
		"svc.local:443",
	} {
		if code, _, _ := p.do("POST", "/api/ping-tasks", map[string]any{
			"name":   "bad",
			"target": bad,
		}, nil); code != 400 {
			t.Fatalf("expected target %q to be rejected with 400, got %d", bad, code)
		}
	}

	var firstID string
	for i := 0; i < 32; i++ {
		code, out, _ := p.do("POST", "/api/ping-tasks", map[string]any{
			"name":            fmt.Sprintf("task-%02d", i),
			"target":          fmt.Sprintf("example-%d.com:443", i),
			"intervalSeconds": 60,
		}, nil)
		if code != 201 {
			t.Fatalf("create task %d: %d %v", i, code, out)
		}
		if i == 0 {
			firstID = out["id"].(string)
		}
	}
	if code, _, _ := p.do("POST", "/api/ping-tasks", map[string]any{
		"name":   "task-33",
		"target": "1.1.1.1:443",
	}, nil); code != 400 {
		t.Fatalf("expected 33rd ping task to be rejected with 400, got %d", code)
	}
	if code, out, _ := p.do("PATCH", "/api/ping-tasks/"+firstID, map[string]any{
		"name":            "Updated-Task",
		"intervalSeconds": 120,
	}, nil); code != 200 || out["name"] != "Updated-Task" {
		t.Fatalf("PATCH ping task failed: %d %v", code, out)
	}
	if code, _, _ := p.do("DELETE", "/api/ping-tasks/"+firstID, nil, nil); code != 200 {
		t.Fatalf("DELETE ping task failed: %d", code)
	}
}

func TestStage2TelegramServerExpiringAndResourceAlerts(t *testing.T) {
	p := newTestMui(t)

	var mu sync.Mutex
	var messages []string
	p.app.tgClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			var payload map[string]any
			_ = json.NewDecoder(req.Body).Decode(&payload)
			mu.Lock()
			messages = append(messages, fmt.Sprint(payload["text"]))
			mu.Unlock()
			return &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			}, nil
		}),
	}
	t.Cleanup(func() { p.app.CloseTelegram() })

	now := time.Now().UTC().Truncate(time.Second)
	p.app.startedAt = now.Add(-10 * time.Minute)

	if code, out, _ := p.do("PUT", "/api/settings/telegram", map[string]any{
		"enabled":  true,
		"botToken": "123456789:AAH_test_stage2_alerts_token",
		"chatId":   "-100123456",
		"events": map[string]any{
			"serverExpiring": map[string]any{"enabled": true},
			"resource":       map[string]any{"enabled": true, "minutes": 5, "threshold": 90},
		},
	}, nil); code != 200 {
		t.Fatalf("save telegram settings: %d %v", code, out)
	}

	exp := now.Add(2 * 24 * time.Hour)
	code, created, _ := p.do("POST", "/api/servers", map[string]any{
		"name":       "tokyo-edge",
		"roles":      []string{"exit"},
		"country":    "JP",
		"city":       "Tokyo",
		"ipv4":       "203.0.113.55",
		"expiresAt":  exp.Format(time.RFC3339),
		"publicNote": "BGP 1Gbps",
	}, nil)
	if code != 201 {
		t.Fatalf("create server with expiresAt: %d %v", code, created)
	}
	sID := created["server"].(map[string]any)["id"].(string)

	// Mark server online and inject a high-CPU monitor sample.
	srv, err := p.store.Server(sID)
	if err != nil {
		t.Fatal(err)
	}
	seen := now
	srv.LastSeen = &seen
	if err := p.store.PutServer(srv); err != nil {
		t.Fatal(err)
	}

	setSample := func(at time.Time, cpu, memPct float64) {
		p.app.monitorMu.Lock()
		p.app.latestSamples[sID] = latestMonitorSample{
			sample: shared.MonitorSample{
				At:       at,
				CPU:      cpu,
				RAMUsed:  int64(memPct * 10),
				RAMTotal: 1000,
				DiskUsed: 200,
				DiskTotal: 1000,
			},
			receivedAt: at,
		}
		p.app.monitorMu.Unlock()
		last := at
		srv.LastSeen = &last
		_ = p.store.PutServer(srv)
	}

	setSample(now, 95.0, 50.0)
	p.app.evaluateAlertsAt(now)
	if !p.app.FlushTelegramForTest(2 * time.Second) {
		t.Fatal("telegram worker did not drain")
	}

	// At t=0: serverExpiring fires immediately (<=3d), resource does NOT fire yet (needs 5m).
	mu.Lock()
	if len(messages) != 1 || !strings.Contains(messages[0], "[MUI] 服务器即将到期") {
		t.Fatalf("expected only serverExpiring at t=0, got %v", messages)
	}
	messages = nil
	mu.Unlock()

	// At t+3m: still below 5m sustain -> no resource alert yet.
	setSample(now.Add(3*time.Minute), 96.0, 50.0)
	p.app.evaluateAlertsAt(now.Add(3 * time.Minute))
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	mu.Lock()
	if len(messages) != 0 {
		t.Fatalf("expected no resource alert at 3m, got %v", messages)
	}
	mu.Unlock()

	// At t+5m: sustained >= 5m -> resource alert fires!
	setSample(now.Add(5*time.Minute), 94.5, 50.0)
	p.app.evaluateAlertsAt(now.Add(5 * time.Minute))
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	mu.Lock()
	if len(messages) != 1 || !strings.Contains(messages[0], "[MUI] 服务器资源告警") || !strings.Contains(messages[0], "CPU") {
		t.Fatalf("expected CPU resource firing alert at 5m, got %v", messages)
	}
	messages = nil
	mu.Unlock()

	// Drop CPU to 30% at t+6m and hold until t+11m -> recovery notification fires!
	setSample(now.Add(6*time.Minute), 30.0, 50.0)
	p.app.evaluateAlertsAt(now.Add(6 * time.Minute))
	setSample(now.Add(11*time.Minute), 28.0, 50.0)
	p.app.evaluateAlertsAt(now.Add(11 * time.Minute))
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	mu.Lock()
	if len(messages) != 1 || !strings.Contains(messages[0], "[MUI] 服务器资源恢复") {
		t.Fatalf("expected CPU resource recovery alert at 11m, got %v", messages)
	}
	mu.Unlock()
}
