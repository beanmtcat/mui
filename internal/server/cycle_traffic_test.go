package server

import (
	"strings"
	"sync"
	"testing"
	"time"

	"mui/internal/shared"
)

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
