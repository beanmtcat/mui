package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"mui/internal/shared"
)

func setupTelegramRecorder(t *testing.T, p *testMui, events map[string]any) *telegramTestSink {
	t.Helper()
	sink := &telegramTestSink{}
	p.app.tgClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			var payload map[string]any
			_ = json.NewDecoder(req.Body).Decode(&payload)
			sink.mu.Lock()
			sink.messages = append(sink.messages, fmt.Sprint(payload["text"]))
			sink.mu.Unlock()
			return &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			}, nil
		}),
	}
	t.Cleanup(func() { p.app.CloseTelegram() })

	body := map[string]any{
		"enabled":  true,
		"botToken": "123456789:AAH_test_stage2b_billing_token",
		"chatId":   "-100987654",
	}
	if events != nil {
		body["events"] = events
	}
	if code, out, _ := p.do("PUT", "/api/settings/telegram", body, nil); code != 200 {
		t.Fatalf("save telegram settings: %d %v", code, out)
	}
	return sink
}

type telegramTestSink struct {
	mu       sync.Mutex
	messages []string
}

func (s *telegramTestSink) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]string(nil), s.messages...)
	s.messages = nil
	return out
}

func TestBillingRenewalEndOfMonthCatchupModesAndConcurrency(t *testing.T) {
	p := newTestMui(t)
	loc := time.FixedZone("CST", 8*3600)
	p.store.timeLoc = loc
	sink := setupTelegramRecorder(t, p, map[string]any{
		"serverExpiring": map[string]any{"enabled": true},
		"serverRenewed":  map[string]any{"enabled": true},
		"serverOffline":  map[string]any{"enabled": false},
	})

	// 1. Month-end non-leap & leap year without drift across separate renewals:
	// 2026-01-31 -> 2026-02-28 -> 2026-03-31, and 2028-01-31 -> 2028-02-29 -> 2028-03-31.
	jan31 := time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC)
	code, created, _ := p.do("POST", "/api/servers", map[string]any{
		"name":         "eom-srv",
		"roles":        []string{"exit"},
		"country":      "JP",
		"city":         "Tokyo",
		"ipv4":         "203.0.113.11",
		"expiresAt":    jan31.Format(time.RFC3339),
		"billingCycle": "month",
		"autoRenew":    true,
		"price":        5,
		"currency":     "$",
	}, nil)
	if code != 201 {
		t.Fatalf("create eom-srv: %d %v", code, created)
	}
	eomID := created["server"].(map[string]any)["id"].(string)

	setLastSeen := func(id string, seen time.Time) {
		srv, err := p.store.Server(id)
		if err != nil {
			t.Fatal(err)
		}
		srv.LastSeen = &seen
		if err := p.store.PutServer(srv); err != nil {
			t.Fatal(err)
		}
	}

	// At 6 days before expiry (2026-01-25): autoRenew server must NOT emit 7-day serverExpiring.
	t6d := time.Date(2026, 1, 25, 12, 0, 0, 0, time.UTC)
	setLastSeen(eomID, t6d)
	p.app.evaluateAlertsAt(t6d)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	if msgs := sink.take(); len(msgs) != 0 {
		t.Fatalf("autoRenew server should skip 7-day reminder, got %v", msgs)
	}

	// At 2 days before expiry (2026-01-29): emits "即将自动续期" exactly once.
	t2d := time.Date(2026, 1, 29, 12, 0, 0, 0, time.UTC)
	setLastSeen(eomID, t2d)
	p.app.evaluateAlertsAt(t2d)
	p.app.evaluateAlertsAt(t2d.Add(time.Hour))
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs := sink.take()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "[MUI] 服务器即将自动续期") {
		t.Fatalf("expected single 即将自动续期 message, got %v", msgs)
	}

	// At 2026-02-01: auto-renews Jan 31 -> Feb 28 and sends "服务器已自动续期" once.
	feb1 := time.Date(2026, 2, 1, 1, 0, 0, 0, time.UTC)
	setLastSeen(eomID, feb1)
	p.app.evaluateAlertsAt(feb1)
	p.app.evaluateAlertsAt(feb1.Add(time.Minute))
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs = sink.take()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "[MUI] 服务器已自动续期") || !strings.Contains(msgs[0], "2026-02-28") || !strings.Contains(msgs[0], "$5.00") {
		t.Fatalf("expected auto-renew to 2026-02-28 with $5.00, got %v", msgs)
	}

	// Next month at 2026-03-01: must renew Feb 28 -> Mar 31 (NO drift to Mar 28!).
	mar1 := time.Date(2026, 3, 1, 1, 0, 0, 0, time.UTC)
	setLastSeen(eomID, mar1)
	p.app.evaluateAlertsAt(mar1)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs = sink.take()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "2026-03-31") {
		t.Fatalf("expected second renewal to restore 31st (2026-03-31), got %v", msgs)
	}

	// Verify leap year 2028-01-31 -> 2028-02-29 -> 2028-03-31 via computeRenewedExpiry.
	leapExp := time.Date(2028, 1, 31, 0, 0, 0, 0, time.UTC)
	leapSrv := shared.Server{ExpiresAt: &leapExp, BillingCycle: "month"}
	r1, anchor, exceeded, err := computeRenewedExpiry(leapSrv, time.Date(2028, 2, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || exceeded || formatExpiryDate(r1, loc) != "2028-02-29" {
		t.Fatalf("leap year step 1 got %v anchor=%d exceeded=%v err=%v", r1, anchor, exceeded, err)
	}
	leapSrv.ExpiresAt = &r1
	leapSrv.BillingAnchorDay = anchor
	r2, _, exceeded, err := computeRenewedExpiry(leapSrv, time.Date(2028, 3, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || exceeded || formatExpiryDate(r2, loc) != "2028-03-31" {
		t.Fatalf("leap year step 2 got %v exceeded=%v err=%v", r2, exceeded, err)
	}

	// 2. Long-expired catchup in one pass + days cycle + manual renew (no Telegram).
	old2024 := time.Date(2024, 1, 31, 0, 0, 0, 0, time.UTC)
	code, catchupOut, _ := p.do("POST", "/api/servers", map[string]any{
		"name":           "offline-catchup",
		"managementMode": "offline",
		"firewallMode":   "manual",
		"roles":          []string{"entry"},
		"country":        "SG",
		"ipv4":           "203.0.113.12",
		"expiresAt":      old2024.Format(time.RFC3339),
		"billingCycle":   "month",
		"autoRenew":      true,
	}, nil)
	if code != 201 {
		t.Fatalf("create offline-catchup: %d %v", code, catchupOut)
	}
	catchupID := catchupOut["server"].(map[string]any)["id"].(string)
	// Offline-managed has no LastSeen and must still auto-renew directly into the future.
	nowCatchup := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	p.app.evaluateAlertsAt(nowCatchup)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	_ = sink.take()
	gotCatchup, err := p.store.Server(catchupID)
	if err != nil || gotCatchup.ExpiresAt == nil || formatExpiryDate(*gotCatchup.ExpiresAt, loc) != "2026-03-31" {
		t.Fatalf("expected offline-managed catchup to 2026-03-31, got %+v err=%v", gotCatchup.ExpiresAt, err)
	}

	// Days cycle manual renew via POST /api/servers/{id}/renew: extends without Telegram, writes audit.
	daysStart := time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC)
	code, daysOut, _ := p.do("POST", "/api/servers", map[string]any{
		"name":             "days-srv",
		"managementMode":   "external",
		"firewallMode":     "manual",
		"roles":            []string{"exit"},
		"country":          "US",
		"ipv4":             "203.0.113.13",
		"expiresAt":        daysStart.Format(time.RFC3339),
		"billingCycle":     "days",
		"billingCycleDays": 15,
	}, nil)
	if code != 201 {
		t.Fatalf("create days-srv: %d %v", code, daysOut)
	}
	daysID := daysOut["server"].(map[string]any)["id"].(string)
	p.app.monitorNow = func() time.Time { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) }
	code, renewedOut, _ := p.do("POST", "/api/servers/"+daysID+"/renew", nil, nil)
	if code != 200 {
		t.Fatalf("manual renew days-srv: %d %v", code, renewedOut)
	}
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	if msgs := sink.take(); len(msgs) != 0 {
		t.Fatalf("manual renew must not send Telegram, got %v", msgs)
	}
	afterDays, _ := p.store.Server(daysID)
	if formatExpiryDate(*afterDays.ExpiresAt, loc) != "2026-05-25" {
		t.Fatalf("expected days manual renew to 2026-05-25, got %v", afterDays.ExpiresAt)
	}

	// 3. Long-offline (>24h) online server must NOT auto-renew and must emit "已到期" reminder instead.
	staleExp := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)
	code, staleOut, _ := p.do("POST", "/api/servers", map[string]any{
		"name":         "stale-online",
		"roles":        []string{"exit"},
		"country":      "DE",
		"ipv4":         "203.0.113.14",
		"expiresAt":    staleExp.Format(time.RFC3339),
		"billingCycle": "month",
		"autoRenew":    true,
	}, nil)
	if code != 201 {
		t.Fatalf("create stale-online: %d %v", code, staleOut)
	}
	staleID := staleOut["server"].(map[string]any)["id"].(string)
	evalStaleAt := time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
	setLastSeen(staleID, evalStaleAt.Add(-30*time.Hour)) // >24h ago
	p.app.evaluateAlertsAt(evalStaleAt)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs = sink.take()
	staleSrv, _ := p.store.Server(staleID)
	if formatExpiryDate(*staleSrv.ExpiresAt, loc) != "2026-04-10" {
		t.Fatalf("long-offline server must not auto-renew, got %v", staleSrv.ExpiresAt)
	}
	foundStaleExpired := false
	for _, m := range msgs {
		if strings.Contains(m, "stale-online") && strings.Contains(m, "服务器已自动续期") {
			t.Fatalf("stale-online must not emit auto-renew message: %s", m)
		}
		if strings.Contains(m, "stale-online") && strings.Contains(m, "已到期") {
			foundStaleExpired = true
		}
	}
	if !foundStaleExpired {
		t.Fatalf("long-offline server should emit 已到期 alert, got %v", msgs)
	}

	// 4. Revoked server must NOT auto-renew or manually renew.
	revID, _, _ := enrollMonitorTestServer(t, p, "revoked-renew")
	revExp := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	if code, _, _ := p.do("PATCH", "/api/servers/"+revID, map[string]any{
		"name":         "revoked-renew",
		"roles":        []string{"exit"},
		"country":      "JP",
		"ipv4":         "203.0.113.10",
		"expiresAt":    revExp.Format(time.RFC3339),
		"billingCycle": "month",
		"autoRenew":    true,
	}, nil); code != 200 {
		t.Fatalf("patch revoked-renew: %d", code)
	}
	setLastSeen(revID, time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC))
	if code, _, _ := p.do("POST", "/api/servers/"+revID+"/revoke", nil, nil); code != 200 {
		t.Fatalf("revoke revID: %d", code)
	}
	p.app.evaluateAlertsAt(time.Date(2026, 4, 2, 1, 0, 0, 0, time.UTC))
	revSrv, _ := p.store.Server(revID)
	if formatExpiryDate(*revSrv.ExpiresAt, loc) != "2026-04-01" {
		t.Fatalf("revoked server must not auto-renew, got %v", revSrv.ExpiresAt)
	}
	if code, _, _ := p.do("POST", "/api/servers/"+revID+"/renew", nil, nil); code != 409 {
		t.Fatalf("expected 409 on manual renew of revoked server, got %d", code)
	}

	// 5. Concurrent Agent report + auto-renew must serialize via lockServer and preserve both writes.
	concID, _, concHeaders := enrollMonitorTestServer(t, p, "conc-srv")
	concExp := time.Now().UTC().Add(-time.Hour).Truncate(24 * time.Hour)
	if code, _, _ := p.do("PATCH", "/api/servers/"+concID, map[string]any{
		"name":         "conc-srv",
		"roles":        []string{"exit"},
		"country":      "JP",
		"ipv4":         "203.0.113.10",
		"expiresAt":    concExp.Format(time.RFC3339),
		"billingCycle": "month",
		"autoRenew":    true,
	}, nil); code != 200 {
		t.Fatalf("patch conc-srv: %d", code)
	}
	setLastSeen(concID, time.Now().UTC())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			_, _, _ = p.do("POST", "/agent/report", shared.AgentReport{
				OS:           "Debian 13",
				Arch:         "amd64",
				AgentVersion: fmt.Sprintf("0.6.31-r%d", i),
				HostMonitor:  true,
			}, concHeaders)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			p.app.autoRenewServers(time.Now().UTC())
		}
	}()
	wg.Wait()

	finalConc, err := p.store.Server(concID)
	if err != nil {
		t.Fatal(err)
	}
	if !finalConc.ExpiresAt.After(time.Now().UTC()) {
		t.Fatalf("expected conc-srv ExpiresAt to remain renewed in the future, got %v", finalConc.ExpiresAt)
	}
	if !strings.HasPrefix(finalConc.AgentVersion, "0.6.31-r") || !finalConc.HostMonitor {
		t.Fatalf("expected concurrent AgentReport fields to be preserved, got version=%q hostMonitor=%v", finalConc.AgentVersion, finalConc.HostMonitor)
	}
}

func TestCycleTrafficAccumulationDedupeRecalcModesBackfillAndAlerts(t *testing.T) {
	p := newTestMui(t)
	loc := time.FixedZone("CST", 8*3600)
	p.store.timeLoc = loc

	sink := setupTelegramRecorder(t, p, map[string]any{
		"trafficLimit": map[string]any{"enabled": true, "threshold": 80},
	})

	const gb = int64(1024 * 1024 * 1024)
	code, created, _ := p.do("POST", "/api/servers", map[string]any{
		"name":             "traffic-srv",
		"roles":            []string{"exit"},
		"country":          "HK",
		"city":             "Hong Kong",
		"ipv4":             "203.0.113.50",
		"trafficLimit":     100 * gb,
		"trafficLimitType": "sum",
		"trafficResetDay":  15,
		"alertMuted":       true, // alertMuted must NOT silence trafficLimit alerts!
	}, nil)
	if code != 201 {
		t.Fatalf("create traffic-srv: %d %v", code, created)
	}
	sID := created["server"].(map[string]any)["id"].(string)

	// Cycle A: [2026-10-15 00:00 CST, 2026-11-15 00:00 CST)
	// Cycle B: [2026-11-15 00:00 CST, 2026-12-15 00:00 CST)
	tOct20 := time.Date(2026, 10, 20, 10, 0, 0, 0, loc)
	tNov10 := time.Date(2026, 11, 10, 10, 0, 0, 0, loc)
	tNov16 := time.Date(2026, 11, 16, 10, 0, 0, 0, loc)

	pts := []shared.ServerTrafficPoint{
		{BootID: "b1", Sequence: 1, Interface: "eth0", Rx: 30 * gb, Tx: 10 * gb, At: tOct20}, // 40 GB in Cycle A
		{BootID: "b1", Sequence: 2, Interface: "eth0", Rx: 25 * gb, Tx: 16 * gb, At: tNov10}, // +41 GB = 81 GB in Cycle A
		{BootID: "b1", Sequence: 2, Interface: "eth0", Rx: 25 * gb, Tx: 16 * gb, At: tNov10}, // duplicate sequence -> ignored!
		{BootID: "b1", Sequence: 3, Interface: "eth0", Rx: 50 * gb, Tx: 46 * gb, At: tNov16}, // 96 GB in Cycle B
	}
	if err := p.store.SaveServerTraffic(sID, pts); err != nil {
		t.Fatalf("SaveServerTraffic: %v", err)
	}

	// Check Cycle A (at Nov 12): Rx=55 GB, Tx=26 GB, sum=81 GB.
	p.app.monitorNow = func() time.Time { return time.Date(2026, 11, 12, 12, 0, 0, 0, loc) }
	code, listOut, _ := p.do("GET", "/api/servers?limit=100", nil, nil)
	if code != 200 {
		t.Fatalf("GET /api/servers: %d", code)
	}
	items := listOut["items"].([]any)
	ctA := items[0].(map[string]any)["cycleTraffic"].(map[string]any)
	if int64(ctA["rx"].(float64)) != 55*gb || int64(ctA["tx"].(float64)) != 26*gb || int64(ctA["used"].(float64)) != 81*gb {
		t.Fatalf("unexpected Cycle A traffic: %v", ctA)
	}

	// Verify all 5 trafficLimitType modes via computeCycleUsed.
	for _, tc := range []struct {
		mode string
		want int64
	}{
		{"sum", 81 * gb},
		{"up", 26 * gb},
		{"down", 55 * gb},
		{"max", 55 * gb},
		{"min", 26 * gb},
	} {
		got, _ := computeCycleUsed(55*gb, 26*gb, tc.mode)
		if got != tc.want {
			t.Fatalf("computeCycleUsed(%q) = %d, want %d", tc.mode, got, tc.want)
		}
	}

	// Evaluate trafficLimit alerts in Cycle A:
	// At 81%: triggers 80% tier once (even though alertMuted=true!).
	nowNov12 := time.Date(2026, 11, 12, 12, 0, 0, 0, loc)
	p.app.evaluateAlertsAt(nowNov12)
	p.app.evaluateAlertsAt(nowNov12.Add(time.Minute))
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs := sink.take()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "[MUI] 流量用量告警") || !strings.Contains(msgs[0], "81%") {
		t.Fatalf("expected 80-tier alert once at 81%%, got %v", msgs)
	}

	// Add 10 GB -> 91%: triggers 90% tier once.
	if err := p.store.SaveServerTraffic(sID, []shared.ServerTrafficPoint{
		{BootID: "b1", Sequence: 4, Interface: "eth0", Rx: 10 * gb, Tx: 0, At: nowNov12.Add(2 * time.Minute)},
	}); err != nil {
		t.Fatal(err)
	}
	p.app.evaluateAlertsAt(nowNov12.Add(3 * time.Minute))
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs = sink.take()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "91%") {
		t.Fatalf("expected 90-tier alert once at 91%%, got %v", msgs)
	}

	// Add 10 GB -> 101%: triggers 100% tier once.
	if err := p.store.SaveServerTraffic(sID, []shared.ServerTrafficPoint{
		{BootID: "b1", Sequence: 5, Interface: "eth0", Rx: 10 * gb, Tx: 0, At: nowNov12.Add(4 * time.Minute)},
	}); err != nil {
		t.Fatal(err)
	}
	p.app.evaluateAlertsAt(nowNov12.Add(5 * time.Minute))
	p.app.evaluateAlertsAt(nowNov12.Add(6 * time.Minute))
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs = sink.take()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "101%") {
		t.Fatalf("expected 100-tier alert once at 101%%, got %v", msgs)
	}

	// Raise threshold to 95% and move into Cycle B (Nov 17, where usage is 96 GB = 96%):
	// Tier 90 must be skipped; 95% tier fires once, and 100% fires later when reaching 100 GB!
	if code, out, _ := p.do("PUT", "/api/settings/telegram", map[string]any{
		"enabled": true,
		"chatId":  "-100987654",
		"events": map[string]any{
			"trafficLimit": map[string]any{"enabled": true, "threshold": 95},
		},
	}, nil); code != 200 {
		t.Fatalf("update threshold to 95: %d %v", code, out)
	}
	if tiers := trafficAlertTiers(95); len(tiers) != 2 || tiers[0] != 95 || tiers[1] != 100 {
		t.Fatalf("expected tiers [95 100] when threshold=95, got %v", tiers)
	}

	nowNov17 := time.Date(2026, 11, 17, 12, 0, 0, 0, loc)
	p.app.evaluateAlertsAt(nowNov17)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs = sink.take()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "96%") {
		t.Fatalf("expected new cycle 95-tier alert at 96%%, got %v", msgs)
	}

	// Change trafficResetDay from 15 -> 1 at Nov 17: current cycle becomes [Nov 1, Dec 1),
	// so Nov 10 (41 GB + 10 GB + 10 GB = 61 GB) + Nov 16 (96 GB) = 157 GB!
	p.app.monitorNow = func() time.Time { return nowNov17 }
	code, patched, _ := p.do("PATCH", "/api/servers/"+sID, map[string]any{
		"name":             "traffic-srv",
		"roles":            []string{"exit"},
		"country":          "HK",
		"city":             "Hong Kong",
		"ipv4":             "203.0.113.50",
		"trafficLimit":     100 * gb,
		"trafficLimitType": "sum",
		"trafficResetDay":  1,
		"alertMuted":       true,
	}, nil)
	if code != 200 {
		t.Fatalf("PATCH resetDay=1: %d %v", code, patched)
	}
	ctPatched := patched["cycleTraffic"].(map[string]any)
	if int64(ctPatched["used"].(float64)) != 157*gb {
		t.Fatalf("expected recalculated cycle traffic 157 GB after resetDay change, got %v", ctPatched)
	}

	// Backfill idempotency + concurrent SaveServerTraffic must not lose increments.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for seq := int64(100); seq < 120; seq++ {
			if err := p.store.SaveServerTraffic(sID, []shared.ServerTrafficPoint{
				{BootID: "b2", Sequence: seq, Interface: "eth0", Rx: gb, Tx: 0, At: nowNov17.Add(time.Duration(seq) * time.Second)},
			}); err != nil {
				t.Errorf("concurrent SaveServerTraffic: %v", err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			if err := p.store.BackfillCurrentCycleTraffic(nowNov17); err != nil {
				t.Errorf("concurrent BackfillCurrentCycleTraffic: %v", err)
			}
		}
	}()
	wg.Wait()

	// Final recalculation check: stored row must equal 157 GB + 20 GB = 177 GB!
	srvNow, _ := p.store.Server(sID)
	cycleMap, err := p.store.CycleTrafficMap([]shared.Server{srvNow}, nowNov17)
	if err != nil {
		t.Fatal(err)
	}
	if cycleMap[sID].Used != 177*gb {
		t.Fatalf("expected 177 GB with zero lost increments during concurrent backfill, got %d", cycleMap[sID].Used/gb)
	}

	// Pruning retains 13 cycles and deletes older ones.
	old14Months := time.Date(2025, 9, 1, 0, 0, 0, 0, loc)
	_, err = p.store.DB.Exec(`INSERT INTO mui_server_cycle_traffic(server_id,cycle_start_ms,rx,tx) VALUES($1,$2,100,100)`, sID, old14Months.UTC().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.store.PruneServerCycleTraffic(nowNov17); err != nil {
		t.Fatal(err)
	}
	var oldCount int
	_ = p.store.DB.QueryRow(`SELECT COUNT(*) FROM mui_server_cycle_traffic WHERE server_id=$1 AND cycle_start_ms=$2`, sID, old14Months.UTC().UnixMilli()).Scan(&oldCount)
	if oldCount != 0 {
		t.Fatalf("expected 14-month-old cycle row to be pruned, got count=%d", oldCount)
	}
}

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

func TestMonthEndAnchorCycleBoundsAcrossFebAndMar(t *testing.T) {
	p := newTestMui(t)
	loc := time.FixedZone("CST", 8*3600)
	p.store.timeLoc = loc

	code, created, _ := p.do("POST", "/api/servers", map[string]any{
		"name":            "anchor-eom",
		"managementMode":  "offline",
		"firewallMode":    "manual",
		"roles":           []string{"entry"},
		"country":         "JP",
		"ipv4":            "203.0.113.101",
		"expiresAt":       "2026-01-31T00:00:00Z",
		"billingCycle":    "month",
		"autoRenew":       true,
		"trafficResetDay": 0,
	}, nil)
	if code != 201 {
		t.Fatalf("create anchor-eom: %d %v", code, created)
	}
	id := created["server"].(map[string]any)["id"].(string)

	// 1/31 auto-renews to 2/28 while retaining BillingAnchorDay = 31.
	jan31 := time.Date(2026, 1, 31, 0, 5, 0, 0, time.UTC)
	p.app.autoRenewServers(jan31)

	srvAfterFebRenew, err := p.store.Server(id)
	if err != nil {
		t.Fatal(err)
	}
	if got := formatExpiryDate(*srvAfterFebRenew.ExpiresAt, loc); got != "2026-02-28" {
		t.Fatalf("expected 2026-02-28 after Jan 31 renewal, got %s", got)
	}
	if srvAfterFebRenew.BillingAnchorDay != 31 {
		t.Fatalf("expected BillingAnchorDay=31, got %d", srvAfterFebRenew.BillingAnchorDay)
	}

	// Even while ExpiresAt is still 2026-02-28, evaluating bounds on 3/29 must be [2/28, 3/31), NOT [3/28, 4/28).
	mar29 := time.Date(2026, 3, 29, 12, 0, 0, 0, loc)
	wantStart := time.Date(2026, 2, 28, 0, 0, 0, 0, loc)
	wantReset := time.Date(2026, 3, 31, 0, 0, 0, 0, loc)
	gotStart, gotReset := serverTrafficCycleBounds(srvAfterFebRenew, mar29, loc)
	if !gotStart.Equal(wantStart) || !gotReset.Equal(wantReset) {
		t.Fatalf("on 3/29 (with 2/28 expiry & anchor 31): expected [%s, %s), got [%s, %s)",
			wantStart.Format("2006-01-02"), wantReset.Format("2006-01-02"),
			gotStart.Format("2006-01-02"), gotReset.Format("2006-01-02"))
	}

	// Renew 2/28 -> 3/31 on Feb 28, then check 3/29 again: still [2/28, 3/31).
	feb28 := time.Date(2026, 2, 28, 0, 5, 0, 0, time.UTC)
	p.app.autoRenewServers(feb28)
	srvMarExp, _ := p.store.Server(id)
	if got := formatExpiryDate(*srvMarExp.ExpiresAt, loc); got != "2026-03-31" {
		t.Fatalf("expected 2026-03-31 after Feb 28 renewal, got %s", got)
	}
	gotStart, gotReset = serverTrafficCycleBounds(srvMarExp, mar29, loc)
	if !gotStart.Equal(wantStart) || !gotReset.Equal(wantReset) {
		t.Fatalf("on 3/29 (with 3/31 expiry): expected [%s, %s), got [%s, %s)",
			wantStart.Format("2006-01-02"), wantReset.Format("2006-01-02"),
			gotStart.Format("2006-01-02"), gotReset.Format("2006-01-02"))
	}

	// On 3/31 (both at local midnight reset and after UTC 00:05 auto-renewal to 4/30),
	// cycle seamlessly transitions from [2/28, 3/31) to [3/31, 4/30) with no 3/28-3/31 mini-cycle.
	mar31Local := time.Date(2026, 3, 31, 0, 5, 0, 0, loc)
	localResetStart, localResetEnd := serverTrafficCycleBounds(srvAfterFebRenew, mar31Local, loc)
	mar31Renew := time.Date(2026, 3, 31, 0, 5, 0, 0, time.UTC)
	preRenewStart, preRenewReset := serverTrafficCycleBounds(srvMarExp, mar31Renew, loc)
	p.app.autoRenewServers(mar31Renew)
	srvAprExp, _ := p.store.Server(id)
	if got := formatExpiryDate(*srvAprExp.ExpiresAt, loc); got != "2026-04-30" {
		t.Fatalf("expected 2026-04-30 after Mar 31 renewal, got %s", got)
	}
	postRenewStart, postRenewReset := serverTrafficCycleBounds(srvAprExp, mar31Renew, loc)
	wantAprStart := time.Date(2026, 3, 31, 0, 0, 0, 0, loc)
	wantAprReset := time.Date(2026, 4, 30, 0, 0, 0, 0, loc)
	if !localResetStart.Equal(wantAprStart) || !localResetEnd.Equal(wantAprReset) ||
		!preRenewStart.Equal(wantAprStart) || !postRenewStart.Equal(wantAprStart) ||
		!preRenewReset.Equal(wantAprReset) || !postRenewReset.Equal(wantAprReset) {
		t.Fatalf("expected seamless [2026-03-31, 2026-04-30) across Mar 31 renewal, local=[%s,%s) pre=[%s,%s) post=[%s,%s)",
			localResetStart.Format("2006-01-02"), localResetEnd.Format("2006-01-02"),
			preRenewStart.Format("2006-01-02"), preRenewReset.Format("2006-01-02"),
			postRenewStart.Format("2006-01-02"), postRenewReset.Format("2006-01-02"))
	}
}

func TestAutoRenewStaleOnlineFallsBackToNormalExpiryWarnings(t *testing.T) {
	p := newTestMui(t)
	sink := setupTelegramRecorder(t, p, map[string]any{
		"serverOffline":  map[string]any{"enabled": false, "offlineMinutes": 3},
		"serverExpiring": map[string]any{"enabled": true},
		"serverRenewed":  map[string]any{"enabled": true},
	})

	// Server A: online-managed, autoRenew=true, LastSeen=nil (never reported).
	code, outA, _ := p.do("POST", "/api/servers", map[string]any{
		"name":         "never-seen-autorenew",
		"roles":        []string{"exit"},
		"country":      "US",
		"ipv4":         "203.0.113.111",
		"expiresAt":    "2026-06-10T00:00:00Z",
		"billingCycle": "month",
		"autoRenew":    true,
	}, nil)
	if code != 201 {
		t.Fatalf("create never-seen: %d %v", code, outA)
	}

	// Server B: online-managed, autoRenew=true, LastSeen > 24h ago.
	code, outB, _ := p.do("POST", "/api/servers", map[string]any{
		"name":         "stale-seen-autorenew",
		"roles":        []string{"exit"},
		"country":      "DE",
		"ipv4":         "203.0.113.112",
		"expiresAt":    "2026-06-10T00:00:00Z",
		"billingCycle": "month",
		"autoRenew":    true,
	}, nil)
	if code != 201 {
		t.Fatalf("create stale-seen: %d %v", code, outB)
	}
	staleID := outB["server"].(map[string]any)["id"].(string)

	// At 5 days before expiry: stale LastSeen (30h old) and nil LastSeen must emit normal 7-day warning!
	t5d := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	srvB, _ := p.store.Server(staleID)
	seen30hAgo := t5d.Add(-30 * time.Hour)
	srvB.LastSeen = &seen30hAgo
	_ = p.store.PutServer(srvB)

	p.app.evaluateAlertsAt(t5d)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs := sink.take()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 normal 7-day expiry warnings for nil/stale online servers, got %d: %v", len(msgs), msgs)
	}
	for _, m := range msgs {
		if strings.Contains(m, "即将自动续期") || !strings.Contains(m, "[MUI] 服务器即将到期") {
			t.Fatalf("expected normal expiry warning instead of auto-renew notice, got %q", m)
		}
	}

	// At 2 days before expiry (< 3d): still offline >24h -> must emit normal 3-day warning, NOT "即将自动续期"!
	t2d := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	p.app.evaluateAlertsAt(t2d)
	_ = p.app.FlushTelegramForTest(2 * time.Second)
	msgs = sink.take()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 normal 3-day expiry warnings, got %d: %v", len(msgs), msgs)
	}
	for _, m := range msgs {
		if strings.Contains(m, "即将自动续期") || !strings.Contains(m, "[MUI] 服务器即将到期") {
			t.Fatalf("expected normal 3-day expiry warning instead of auto-renew notice, got %q", m)
		}
	}
}

func TestServerPatchStaleDialogPreservesAutoRenewedExpiry(t *testing.T) {
	p := newTestMui(t)

	code, created, _ := p.do("POST", "/api/servers", map[string]any{
		"name":           "patch-race-srv",
		"managementMode": "offline",
		"firewallMode":   "manual",
		"roles":          []string{"entry"},
		"country":        "SG",
		"ipv4":           "203.0.113.120",
		"expiresAt":      "2026-01-31T00:00:00Z",
		"billingCycle":   "month",
		"autoRenew":      true,
	}, nil)
	if code != 201 {
		t.Fatalf("create server: %d %v", code, created)
	}
	id := created["server"].(map[string]any)["id"].(string)

	// User opens edit modal when expiresAt is 2026-01-31T00:00:00Z.
	// Before user clicks Save, autoRenew runs on Jan 31 and advances expiresAt to 2026-02-28T00:00:00Z (anchor 31).
	p.app.autoRenewServers(time.Date(2026, 1, 31, 1, 0, 0, 0, time.UTC))

	// User edits notes in the stale modal without changing expiresAt (expiresAt == initialExpiresAt).
	code, patched, _ := p.do("PATCH", "/api/servers/"+id, map[string]any{
		"name":             "patch-race-srv",
		"managementMode":   "offline",
		"firewallMode":     "manual",
		"roles":            []string{"entry"},
		"country":          "SG",
		"ipv4":             "203.0.113.120",
		"notes":            "edited while modal was open",
		"expiresAt":        "2026-01-31T00:00:00Z",
		"initialExpiresAt": "2026-01-31T00:00:00Z",
		"billingCycle":     "month",
		"autoRenew":        true,
	}, nil)
	if code != 200 {
		t.Fatalf("PATCH stale modal: %d %v", code, patched)
	}
	srv, err := p.store.Server(id)
	if err != nil {
		t.Fatal(err)
	}
	if srv.Notes != "edited while modal was open" {
		t.Fatalf("expected notes update to be saved, got %q", srv.Notes)
	}
	if got := srv.ExpiresAt.UTC().Format("2006-01-02"); got != "2026-02-28" {
		t.Fatalf("stale modal overwrote auto-renewed expiresAt: got %s, want 2026-02-28", got)
	}
	if srv.BillingAnchorDay != 31 {
		t.Fatalf("expected BillingAnchorDay=31 to be preserved, got %d", srv.BillingAnchorDay)
	}

	// Conversely, if the user explicitly changes expiresAt in the modal (expiresAt != initialExpiresAt), the new value takes effect!
	code, patched2, _ := p.do("PATCH", "/api/servers/"+id, map[string]any{
		"name":             "patch-race-srv",
		"managementMode":   "offline",
		"firewallMode":     "manual",
		"roles":            []string{"entry"},
		"country":          "SG",
		"ipv4":             "203.0.113.120",
		"expiresAt":        "2026-05-15T00:00:00Z",
		"initialExpiresAt": "2026-01-31T00:00:00Z",
		"billingCycle":     "month",
		"autoRenew":        true,
	}, nil)
	if code != 200 {
		t.Fatalf("PATCH explicit expiresAt change: %d %v", code, patched2)
	}
	srv2, _ := p.store.Server(id)
	if got := srv2.ExpiresAt.UTC().Format("2006-01-02"); got != "2026-05-15" || srv2.BillingAnchorDay != 15 {
		t.Fatalf("expected explicit expiresAt=2026-05-15 and anchor=15, got %s anchor=%d", got, srv2.BillingAnchorDay)
	}
}

func TestManualRenewLogsAndSucceedsWhenCycleRecalcFails(t *testing.T) {
	p := newTestMui(t)
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	p.app.monitorNow = func() time.Time { return now }

	code, created, _ := p.do("POST", "/api/servers", map[string]any{
		"name":             "renew-recalc-err",
		"managementMode":   "offline",
		"firewallMode":     "manual",
		"roles":            []string{"entry"},
		"country":          "JP",
		"ipv4":             "203.0.113.130",
		"expiresAt":        "2026-01-15T00:00:00Z",
		"billingCycle":     "days",
		"billingCycleDays": 10,
	}, nil)
	if code != 201 {
		t.Fatalf("create server: %d %v", code, created)
	}
	id := created["server"].(map[string]any)["id"].(string)

	// Force RecalcServerCurrentCycleTraffic to fail after PutServer succeeds.
	if _, err := p.store.DB.Exec(`DROP TABLE mui_server_cycle_traffic`); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(origOut)

	code, renewed, _ := p.do("POST", "/api/servers/"+id+"/renew", nil, nil)
	if code != 200 {
		t.Fatalf("expected manual renew to return 200 even when cycle recalc fails, got %d %v", code, renewed)
	}
	srv, _ := p.store.Server(id)
	if got := srv.ExpiresAt.UTC().Format("2006-01-02"); got != "2026-01-25" {
		t.Fatalf("expected renewed expiresAt=2026-01-25, got %s", got)
	}
	if !strings.Contains(logBuf.String(), "recalc server") {
		t.Fatalf("expected recalc failure to be logged, got %q", logBuf.String())
	}
}

func TestEnsureCycleTrafficBackfillTracksTimezone(t *testing.T) {
	origLocal := time.Local
	t.Cleanup(func() { time.Local = origLocal })

	shanghai, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		shanghai = time.FixedZone("Asia/Shanghai", 8*3600)
	}

	p := newTestMui(t)
	const gb = int64(1024 * 1024 * 1024)

	code, created, _ := p.do("POST", "/api/servers", map[string]any{
		"name":             "tz-backfill-srv",
		"roles":            []string{"exit"},
		"country":          "SG",
		"ipv4":             "203.0.113.140",
		"trafficLimit":     100 * gb,
		"trafficLimitType": "sum",
		"trafficResetDay":  1,
	}, nil)
	if code != 201 {
		t.Fatalf("create server: %d %v", code, created)
	}
	id := created["server"].(map[string]any)["id"].(string)

	// Record raw samples via SaveServerTraffic and clear mui_server_cycle_traffic to simulate pre-upgrade history:
	// - sample 1: 2026-10-31 18:00 UTC (= 2026-11-01 02:00 Asia/Shanghai) -> 15 GB (Oct in UTC, Nov in Asia/Shanghai)
	// - sample 2: 2026-11-02 12:00 UTC (= 2026-11-02 20:00 Asia/Shanghai) -> 30 GB (Nov in both)
	time.Local = time.UTC
	if err := p.store.SaveServerTraffic(id, []shared.ServerTrafficPoint{
		{BootID: "b1", Sequence: 1, Interface: "eth0", Rx: 10 * gb, Tx: 5 * gb, At: time.Date(2026, 10, 31, 18, 0, 0, 0, time.UTC)},
		{BootID: "b1", Sequence: 2, Interface: "eth0", Rx: 20 * gb, Tx: 10 * gb, At: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.store.DB.Exec(`DELETE FROM mui_server_cycle_traffic`); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

	// 1. Initial startup under UTC: backfills 30 GB and stores "UTC".
	time.Local = time.UTC
	if err := p.store.EnsureCycleTrafficBackfill(now); err != nil {
		t.Fatalf("EnsureCycleTrafficBackfill (UTC): %v", err)
	}
	var settingVal string
	if err := p.store.DB.QueryRow(`SELECT value FROM mui_settings WHERE key='cycle_traffic_backfilled'`).Scan(&settingVal); err != nil || settingVal != "UTC" {
		t.Fatalf("expected cycle_traffic_backfilled='UTC', got %q (err=%v)", settingVal, err)
	}
	srv, _ := p.store.Server(id)
	cm, err := p.store.CycleTrafficMap([]shared.Server{srv}, now)
	if err != nil {
		t.Fatal(err)
	}
	if cm[id].Used != 30*gb {
		t.Fatalf("expected 30 GB under UTC cycle, got %d GB", cm[id].Used/gb)
	}

	// 2. Startup again with the SAME timezone ("UTC"): skips backfill.
	utcCycleStartMs := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	if _, err := p.store.DB.Exec(`UPDATE mui_server_cycle_traffic SET rx=123, tx=0 WHERE server_id=$1 AND cycle_start_ms=$2`, id, utcCycleStartMs); err != nil {
		t.Fatal(err)
	}
	if err := p.store.EnsureCycleTrafficBackfill(now); err != nil {
		t.Fatal(err)
	}
	cm, _ = p.store.CycleTrafficMap([]shared.Server{srv}, now)
	if cm[id].Used != 123 {
		t.Fatalf("expected backfill to be skipped when timezone unchanged, got used=%d", cm[id].Used)
	}

	// 3. Legacy value "1" in mui_settings triggers re-backfill and updates value to current timezone name.
	if _, err := p.store.DB.Exec(`UPDATE mui_settings SET value='1' WHERE key='cycle_traffic_backfilled'`); err != nil {
		t.Fatal(err)
	}
	if err := p.store.EnsureCycleTrafficBackfill(now); err != nil {
		t.Fatal(err)
	}
	_ = p.store.DB.QueryRow(`SELECT value FROM mui_settings WHERE key='cycle_traffic_backfilled'`).Scan(&settingVal)
	if settingVal != "UTC" {
		t.Fatalf("expected legacy '1' to update to 'UTC', got %q", settingVal)
	}
	cm, _ = p.store.CycleTrafficMap([]shared.Server{srv}, now)
	if cm[id].Used != 30*gb {
		t.Fatalf("expected legacy '1' to trigger re-backfill to 30 GB, got %d GB", cm[id].Used/gb)
	}

	// 4. Timezone changes to Asia/Shanghai: re-runs BackfillCurrentCycleTraffic (15 GB + 30 GB = 45 GB) and updates setting to "Asia/Shanghai".
	time.Local = shanghai
	if err := p.store.EnsureCycleTrafficBackfill(now); err != nil {
		t.Fatalf("EnsureCycleTrafficBackfill (Asia/Shanghai): %v", err)
	}
	_ = p.store.DB.QueryRow(`SELECT value FROM mui_settings WHERE key='cycle_traffic_backfilled'`).Scan(&settingVal)
	if settingVal != shanghai.String() {
		t.Fatalf("expected cycle_traffic_backfilled=%q, got %q", shanghai.String(), settingVal)
	}
	cm, err = p.store.CycleTrafficMap([]shared.Server{srv}, now)
	if err != nil {
		t.Fatal(err)
	}
	if cm[id].Used != 45*gb {
		t.Fatalf("expected 45 GB under Asia/Shanghai cycle after timezone change, got %d GB", cm[id].Used/gb)
	}
}
