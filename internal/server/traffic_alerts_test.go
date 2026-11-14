package server

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestTrafficReportsValidationAlertMutedAndRateLimitedMonitorErrors(t *testing.T) {
	p := newTestMui(t)
	loc := time.FixedZone("CST", 8*3600)
	p.store.timeLoc = loc

	sink := setupTelegramRecorder(t, p, map[string]any{
		"serverOffline": map[string]any{"enabled": true, "offlineMinutes": 3},
		"resource":      map[string]any{"enabled": true, "minutes": 5, "threshold": 90},
		"trafficReport": map[string]any{"daily": true, "weekly": true, "monthly": true},
	})

	// 1. Field validation checks on POST /api/servers.
	badInputs := []map[string]any{
		{"price": -1},
		{"price": 1_000_001},
		{"price": 5.123},
		{"currency": "123456789"},
		{"billingCycle": "decade"},
		{"billingCycle": "days", "billingCycleDays": 0},
		{"billingCycle": "days", "billingCycleDays": 3651},
		{"trafficLimit": -5},
		{"trafficLimitType": "avg"},
		{"trafficResetDay": 32},
		{"group": strings.Repeat("组", 41)},
		{"sortWeight": 10000},
		{"sortWeight": -10000},
	}
	for _, extra := range badInputs {
		payload := map[string]any{
			"name":    "bad-srv",
			"roles":   []string{"exit"},
			"country": "JP",
			"ipv4":    "203.0.113.99",
		}
		for k, v := range extra {
			payload[k] = v
		}
		if code, _, _ := p.do("POST", "/api/servers", payload, nil); code != 400 {
			t.Fatalf("expected 400 for invalid billing/org payload %v, got %d", extra, code)
		}
	}

	// 2. alertMuted suppresses serverOffline and resource alerts.
	code, mutedOut, _ := p.do("POST", "/api/servers", map[string]any{
		"name":       "muted-srv",
		"roles":      []string{"exit"},
		"country":    "SG",
		"ipv4":       "203.0.113.88",
		"alertMuted": true,
	}, nil)
	if code != 201 {
		t.Fatalf("create muted-srv: %d %v", code, mutedOut)
	}
	mutedID := mutedOut["server"].(map[string]any)["id"].(string)

	base := time.Date(2026, 11, 10, 8, 0, 0, 0, loc) // 08:00 CST (before 09:00 report window)
	p.app.startedAt = base.Add(-time.Hour)
	srv, _ := p.store.Server(mutedID)
	oldSeen := base.Add(-10 * time.Minute) // offline 10m > 3m threshold
	srv.LastSeen = &oldSeen
	_ = p.store.PutServer(srv)

	p.app.monitorMu.Lock()
	p.app.latestSamples[mutedID] = latestMonitorSample{
		sample:     shared.MonitorSample{At: base, CPU: 99, RAMUsed: 990, RAMTotal: 1000},
		receivedAt: base,
	}
	p.app.monitorMu.Unlock()

	p.app.evaluateAlertsAt(base)
	p.app.evaluateAlertsAt(base.Add(6 * time.Minute))
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	if msgs := sink.take(); len(msgs) != 0 {
		t.Fatalf("alertMuted server must not emit offline or resource alerts, got %v", msgs)
	}

	// 3. Traffic reports:
	// Insert traffic on 2026-11-09 (Sunday -> included in Nov 9 daily AND Nov 3..Nov 9 weekly!).
	sun := time.Date(2026, 11, 9, 15, 0, 0, 0, loc)
	if err := p.store.SaveServerTraffic(mutedID, []shared.ServerTrafficPoint{
		{BootID: "r1", Sequence: 1, Interface: "eth0", Rx: 2048, Tx: 1024, At: sun},
	}); err != nil {
		t.Fatal(err)
	}

	// Before 09:00 on Nov 10 (Tuesday): no report due.
	// At 09:00 on Nov 10: daily report fires once; repeating at 09:30 does NOT re-send!
	nov10Nine := time.Date(2026, 11, 10, 9, 0, 0, 0, loc)
	p.app.evaluateAlertsAt(nov10Nine)
	p.app.evaluateAlertsAt(nov10Nine.Add(30 * time.Minute))
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs := sink.take()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "[MUI] 每日流量报告") || !strings.Contains(msgs[0], "2026-11-09") {
		t.Fatalf("expected single daily report at 09:00, got %v", msgs)
	}

	// Catchup window test: panel down at 09:00 on Nov 11, starts at 18:00 (within 12h) -> sends catchup once!
	nov11Catchup := time.Date(2026, 11, 11, 18, 0, 0, 0, loc)
	p.app.evaluateAlertsAt(nov11Catchup)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs = sink.take()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "2026-11-10") {
		t.Fatalf("expected catchup daily report within 12h window, got %v", msgs)
	}

	// Expired window test: panel down at 09:00 on Nov 12, starts at 21:30 (>12h) -> skipped!
	nov12Late := time.Date(2026, 11, 12, 21, 30, 0, 0, loc)
	p.app.evaluateAlertsAt(nov12Late)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	if msgs := sink.take(); len(msgs) != 0 {
		t.Fatalf("expected report past 12h window to be skipped, got %v", msgs)
	}

	// 4. Rate-limited monitor DB error logging.
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOut)

	tErr := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	p.app.monitorNow = func() time.Time { return tErr }
	p.app.logMonitorError("put_minute", errors.New("disk full"))
	p.app.logMonitorError("put_minute", errors.New("disk full again"))
	if strings.Count(logBuf.String(), "monitor put_minute:") != 1 {
		t.Fatalf("expected rate-limited monitor error to log once within 1m, got %q", logBuf.String())
	}
	tErr = tErr.Add(61 * time.Second)
	p.app.logMonitorError("put_minute", errors.New("disk still full"))
	if strings.Count(logBuf.String(), "monitor put_minute:") != 2 {
		t.Fatalf("expected monitor error to log again after 1m cooldown, got %q", logBuf.String())
	}
}
