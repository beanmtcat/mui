package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"mui/internal/shared"
)

const (
	maxServerPrice        float64 = 1_000_000
	maxServerTrafficLimit int64   = 1 << 53
	maxBillingRenewSteps  int     = 120
	retainedTrafficCycles int     = 13
)

func (s *Store) timeLocation() *time.Location {
	if s != nil && s.timeLoc != nil {
		return s.timeLoc
	}
	return time.Local
}

func (s *Store) lockCycleTraffic(serverID string) func() {
	s.cycleLocksMu.Lock()
	if s.cycleLocks == nil {
		s.cycleLocks = map[string]*sync.Mutex{}
	}
	mu, ok := s.cycleLocks[serverID]
	if !ok {
		mu = &sync.Mutex{}
		s.cycleLocks[serverID] = mu
	}
	s.cycleLocksMu.Unlock()
	mu.Lock()
	return mu.Unlock
}

func serverExpiryDate(t time.Time, loc *time.Location) (int, time.Month, int) {
	u := t.UTC()
	if u.Hour() == 0 && u.Minute() == 0 && u.Second() == 0 && u.Nanosecond() == 0 {
		return u.Date()
	}
	if loc == nil {
		loc = time.Local
	}
	return t.In(loc).Date()
}

func formatExpiryDate(t time.Time, loc *time.Location) string {
	y, m, d := serverExpiryDate(t, loc)
	return fmt.Sprintf("%04d-%02d-%02d", y, int(m), d)
}

func currencyOrDefault(c string) string {
	c = strings.TrimSpace(c)
	if c == "" {
		return "$"
	}
	return c
}

func effectiveTrafficLimitType(raw string) string {
	switch strings.TrimSpace(raw) {
	case "up", "down", "max", "min", "sum":
		return strings.TrimSpace(raw)
	default:
		return "sum"
	}
}

func trafficLimitTypeLabel(raw string) string {
	switch effectiveTrafficLimitType(raw) {
	case "up":
		return "仅上行"
	case "down":
		return "仅下行"
	case "max":
		return "按较大方向"
	case "min":
		return "按较小方向"
	default:
		return "按上行+下行"
	}
}

func computeCycleUsed(rx, tx int64, limitType string) (int64, string) {
	norm := effectiveTrafficLimitType(limitType)
	switch norm {
	case "up":
		return tx, norm
	case "down":
		return rx, norm
	case "max":
		return max(rx, tx), norm
	case "min":
		return min(rx, tx), norm
	default:
		return rx + tx, "sum"
	}
}

type optionalTimeField struct {
	Set   bool
	Value *time.Time
}

func (o *optionalTimeField) UnmarshalJSON(b []byte) error {
	o.Set = true
	if string(b) == "null" {
		o.Value = nil
		return nil
	}
	var t time.Time
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	o.Value = &t
	return nil
}

func sameOptionalTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func applyServerBillingFields(dst *shared.Server, in shared.Server, before *shared.Server, initialExpiresAt *optionalTimeField) error {
	if math.IsNaN(in.Price) || math.IsInf(in.Price, 0) || in.Price < 0 || in.Price > maxServerPrice {
		return errors.New("价格需在 0–1000000 之间")
	}
	cents := in.Price * 100
	if math.Abs(cents-math.Round(cents)) > 1e-6 {
		return errors.New("价格最多保留两位小数")
	}
	dst.Price = math.Round(cents) / 100

	cur := strings.TrimSpace(in.Currency)
	if utf8.RuneCountInString(cur) > 8 {
		return errors.New("货币符号或代码不能超过 8 个字符")
	}
	if cur == "" {
		cur = "$"
	}
	dst.Currency = cur

	cycle := strings.TrimSpace(in.BillingCycle)
	switch cycle {
	case "", "month", "quarter", "halfyear", "year", "2year", "3year":
		dst.BillingCycle = cycle
		dst.BillingCycleDays = 0
	case "days":
		if in.BillingCycleDays < 1 || in.BillingCycleDays > 3650 {
			return errors.New("按天计费周期天数需在 1–3650 之间")
		}
		dst.BillingCycle = "days"
		dst.BillingCycleDays = in.BillingCycleDays
	default:
		return errors.New("计费周期无效")
	}

	dst.AutoRenew = in.AutoRenew

	if in.TrafficLimit < 0 || in.TrafficLimit > maxServerTrafficLimit {
		return errors.New("流量限额超出有效范围")
	}
	dst.TrafficLimit = in.TrafficLimit

	lt := strings.TrimSpace(in.TrafficLimitType)
	if lt == "" {
		lt = "sum"
	}
	switch lt {
	case "sum", "up", "down", "max", "min":
		dst.TrafficLimitType = lt
	default:
		return errors.New("流量限额计费方式无效")
	}

	if in.TrafficResetDay < 0 || in.TrafficResetDay > 31 {
		return errors.New("流量重置日需在 0–31 之间")
	}
	dst.TrafficResetDay = in.TrafficResetDay

	grp := strings.TrimSpace(in.Group)
	if utf8.RuneCountInString(grp) > 40 {
		return errors.New("分组名不能超过 40 个字符")
	}
	dst.Group = grp

	if in.SortWeight < -9999 || in.SortWeight > 9999 {
		return errors.New("排序权重需在 -9999–9999 之间")
	}
	dst.SortWeight = in.SortWeight
	dst.AlertMuted = in.AlertMuted

	if before != nil && initialExpiresAt != nil && initialExpiresAt.Set && sameOptionalTime(in.ExpiresAt, initialExpiresAt.Value) {
		dst.ExpiresAt = before.ExpiresAt
		dst.BillingAnchorDay = before.BillingAnchorDay
		if dst.ExpiresAt != nil && dst.BillingAnchorDay <= 0 {
			_, _, d := serverExpiryDate(*dst.ExpiresAt, nil)
			dst.BillingAnchorDay = d
		}
		return nil
	}

	dst.ExpiresAt = in.ExpiresAt
	if in.ExpiresAt == nil {
		dst.BillingAnchorDay = 0
	} else if before == nil || before.ExpiresAt == nil || !before.ExpiresAt.Equal(*in.ExpiresAt) {
		_, _, d := serverExpiryDate(*in.ExpiresAt, nil)
		dst.BillingAnchorDay = d
	} else if before.BillingAnchorDay > 0 {
		dst.BillingAnchorDay = before.BillingAnchorDay
	} else {
		_, _, d := serverExpiryDate(*in.ExpiresAt, nil)
		dst.BillingAnchorDay = d
	}
	return nil
}

func billingCycleMonths(cycle string) (int, bool) {
	switch cycle {
	case "month":
		return 1, true
	case "quarter":
		return 3, true
	case "halfyear":
		return 6, true
	case "year":
		return 12, true
	case "2year":
		return 24, true
	case "3year":
		return 36, true
	default:
		return 0, false
	}
}

func daysInCalendarMonth(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

func addMonthsAnchor(base time.Time, anchorDay int, addMonths int) time.Time {
	loc := base.Location()
	u := base.UTC()
	if u.Hour() == 0 && u.Minute() == 0 && u.Second() == 0 && u.Nanosecond() == 0 {
		loc = time.UTC
	}
	inLoc := base.In(loc)
	y, m, d := inLoc.Date()
	if anchorDay <= 0 {
		anchorDay = d
	}
	totalMonths := (y*12 + int(m) - 1) + addMonths
	ny := totalMonths / 12
	nm := time.Month(totalMonths%12 + 1)
	if totalMonths < 0 && totalMonths%12 != 0 {
		ny--
		nm += 12
	}
	nd := min(anchorDay, daysInCalendarMonth(ny, nm))
	return time.Date(ny, nm, nd, inLoc.Hour(), inLoc.Minute(), inLoc.Second(), inLoc.Nanosecond(), loc)
}

func computeRenewedExpiry(srv shared.Server, now time.Time) (newExp time.Time, anchorDay int, exceeded bool, err error) {
	if srv.ExpiresAt == nil {
		return time.Time{}, 0, false, errors.New("请先设置服务器到期日")
	}
	oldExp := *srv.ExpiresAt
	if months, ok := billingCycleMonths(srv.BillingCycle); ok {
		anchorDay = srv.BillingAnchorDay
		if anchorDay <= 0 {
			_, _, anchorDay = serverExpiryDate(oldExp, nil)
		}
		for step := 1; step <= maxBillingRenewSteps; step++ {
			cand := addMonthsAnchor(oldExp, anchorDay, step*months)
			if cand.After(now) {
				return cand, anchorDay, false, nil
			}
		}
		return time.Time{}, anchorDay, true, nil
	}
	if srv.BillingCycle == "days" {
		if srv.BillingCycleDays < 1 || srv.BillingCycleDays > 3650 {
			return time.Time{}, 0, false, errors.New("按天计费周期天数无效")
		}
		loc := oldExp.Location()
		u := oldExp.UTC()
		if u.Hour() == 0 && u.Minute() == 0 && u.Second() == 0 && u.Nanosecond() == 0 {
			loc = time.UTC
		}
		inLoc := oldExp.In(loc)
		for step := 1; step <= maxBillingRenewSteps; step++ {
			cand := inLoc.AddDate(0, 0, step*srv.BillingCycleDays)
			if cand.After(now) {
				_, _, d := serverExpiryDate(cand, nil)
				return cand, d, false, nil
			}
		}
		return time.Time{}, 0, true, nil
	}
	return time.Time{}, 0, false, errors.New("请先设置计费周期")
}

func (s *Store) DeleteServerExpiryStatesForDate(serverID, expDate string) error {
	prefix := "serverExpiring:" + likeEscape(serverID) + ":" + likeEscape(expDate) + ":%"
	_, err := s.DB.Exec(`DELETE FROM mui_alert_state WHERE key LIKE $1 ESCAPE '\'`, prefix)
	return err
}

func autoRenewWillRun(srv shared.Server, now time.Time) bool {
	if !srv.AutoRenew || srv.BillingCycle == "" || srv.Status == "revoked" {
		return false
	}
	if !shared.NoAgentManaged(srv) {
		if srv.LastSeen == nil || now.Sub(*srv.LastSeen) > 24*time.Hour {
			return false
		}
	}
	return true
}

func autoRenewEligible(srv shared.Server, now time.Time) bool {
	if !autoRenewWillRun(srv, now) || srv.ExpiresAt == nil {
		return false
	}
	return !srv.ExpiresAt.After(now)
}

// autoRenewServers extends expired auto-renew servers without holding a.mu or
// alertEvalMu. Each server update acquires lockServer(id), reloads the fresh
// server document, and writes via PutServer so concurrent Agent reports are
// never overwritten.
func (a *App) autoRenewServers(now time.Time) {
	servers, err := a.Store.Servers()
	if err != nil {
		return
	}
	loc := a.Store.timeLocation()
	for _, s := range servers {
		if !autoRenewEligible(s, now) {
			continue
		}
		a.autoRenewOneServer(s.ID, now, loc)
	}
}

func (a *App) autoRenewOneServer(id string, now time.Time, loc *time.Location) {
	unlock := a.lockServer(id)
	cur, err := a.Store.Server(id)
	if err != nil || !autoRenewEligible(cur, now) {
		unlock()
		return
	}
	oldExp := *cur.ExpiresAt
	oldExpDate := formatExpiryDate(oldExp, loc)

	newExp, anchorDay, exceeded, err := computeRenewedExpiry(cur, now)
	if err != nil {
		unlock()
		return
	}
	if exceeded {
		unlock()
		abandonKey := fmt.Sprintf("serverRenewAbandoned:%s:%s", cur.ID, oldExpDate)
		var existing string
		if a.Store.DB.QueryRow(`SELECT status FROM mui_alert_state WHERE key=$1`, abandonKey).Scan(&existing) != nil {
			nowMs := now.UnixMilli()
			_ = a.Store.putAlertState(abandonKey, "sent", nowMs, nowMs)
			a.Store.Audit("server.renew", cur.ID, fmt.Sprintf("自动续期已放弃：原到期日 %s 顺延 %d 个周期后仍未晚于当前时间", oldExpDate, maxBillingRenewSteps))
		}
		return
	}

	before := cur
	cur.ExpiresAt = &newExp
	cur.BillingAnchorDay = anchorDay
	if err := a.Store.PutServer(cur); err != nil {
		unlock()
		return
	}
	unlock()

	newExpDate := formatExpiryDate(newExp, loc)
	_ = a.Store.DeleteServerExpiryStatesForDate(cur.ID, oldExpDate)

	oldCycleStart, _ := serverTrafficCycleBounds(before, now, loc)
	newCycleStart, _ := serverTrafficCycleBounds(cur, now, loc)
	if !oldCycleStart.Equal(newCycleStart) {
		if err := a.Store.RecalcServerCurrentCycleTraffic(cur, now); err != nil {
			log.Printf("recalc server %s cycle traffic after auto renew: %v", cur.ID, err)
		}
	}

	a.Store.Audit("server.renew", cur.ID, fmt.Sprintf("自动续期：%s -> %s", oldExpDate, newExpDate))

	var msg strings.Builder
	msg.WriteString("[MUI] 服务器已自动续期\n服务器：")
	msg.WriteString(formatAlertServer(cur))
	msg.WriteString("\n新到期日：")
	msg.WriteString(newExpDate)
	if cur.Price > 0 {
		msg.WriteString(fmt.Sprintf("\n周期费用：%s%.2f", currencyOrDefault(cur.Currency), cur.Price))
	}
	a.notify("serverRenewed", "serverRenewed:"+cur.ID+":"+newExpDate, msg.String())
}

func (a *App) renewServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validServerID(id) || !a.serverExists(id) {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	now := a.nowMonitorUTC()
	loc := a.Store.timeLocation()

	unlock := a.lockServer(id)
	cur, err := a.Store.Server(id)
	if err != nil {
		unlock()
		errorJSON(w, 404, "服务器不存在")
		return
	}
	if cur.Status == "revoked" {
		unlock()
		errorJSON(w, 409, "已吊销的服务器不能续期")
		return
	}
	if cur.BillingCycle == "" {
		unlock()
		errorJSON(w, 400, "请先设置计费周期")
		return
	}
	if cur.ExpiresAt == nil {
		unlock()
		errorJSON(w, 400, "请先设置服务器到期日")
		return
	}

	oldExp := *cur.ExpiresAt
	oldExpDate := formatExpiryDate(oldExp, loc)
	newExp, anchorDay, exceeded, err := computeRenewedExpiry(cur, now)
	if err != nil {
		unlock()
		errorJSON(w, 400, err.Error())
		return
	}
	if exceeded {
		unlock()
		a.auditRequest(r, "server.renew", cur.ID, fmt.Sprintf("手动续期已放弃：原到期日 %s 顺延 %d 个周期后仍未晚于当前时间", oldExpDate, maxBillingRenewSteps))
		errorJSON(w, 409, "原到期日距今超过 120 个计费周期，请直接编辑到期日")
		return
	}

	before := cur
	cur.ExpiresAt = &newExp
	cur.BillingAnchorDay = anchorDay
	if err := a.Store.PutServer(cur); err != nil {
		unlock()
		errorJSON(w, 500, err.Error())
		return
	}
	unlock()

	newExpDate := formatExpiryDate(newExp, loc)
	_ = a.Store.DeleteServerExpiryStatesForDate(cur.ID, oldExpDate)

	oldCycleStart, _ := serverTrafficCycleBounds(before, now, loc)
	newCycleStart, _ := serverTrafficCycleBounds(cur, now, loc)
	if !oldCycleStart.Equal(newCycleStart) {
		if err := a.Store.RecalcServerCurrentCycleTraffic(cur, now); err != nil {
			log.Printf("recalc server %s cycle traffic after manual renew: %v", cur.ID, err)
		}
	}

	a.auditRequest(r, "server.renew", cur.ID, fmt.Sprintf("%s -> %s", oldExpDate, newExpDate))
	cur.Status = serverStatus(cur)
	if cycleMap, err := a.Store.CycleTrafficMap([]shared.Server{cur}, now); err == nil {
		ct := cycleMap[cur.ID]
		cur.CycleTraffic = &ct
	}
	writeJSON(w, 200, cur)
}

func effectiveTrafficResetDay(srv shared.Server, loc *time.Location) int {
	if srv.TrafficResetDay >= 1 && srv.TrafficResetDay <= 31 {
		return srv.TrafficResetDay
	}
	if _, monthly := billingCycleMonths(srv.BillingCycle); monthly && srv.BillingAnchorDay >= 1 && srv.BillingAnchorDay <= 31 {
		return srv.BillingAnchorDay
	}
	if srv.ExpiresAt != nil {
		_, _, d := serverExpiryDate(*srv.ExpiresAt, loc)
		if d >= 1 && d <= 31 {
			return d
		}
	}
	return 1
}

func resetBoundaryInMonth(year int, month time.Month, resetDay int, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.Local
	}
	if resetDay < 1 {
		resetDay = 1
	}
	d := min(resetDay, daysInCalendarMonth(year, month))
	return time.Date(year, month, d, 0, 0, 0, 0, loc)
}

func shiftYearMonth(year int, month time.Month, deltaMonths int) (int, time.Month) {
	total := (year*12 + int(month) - 1) + deltaMonths
	ny := total / 12
	nm := time.Month(total%12 + 1)
	if total < 0 && total%12 != 0 {
		ny--
		nm += 12
	}
	return ny, nm
}

func serverTrafficCycleBounds(srv shared.Server, at time.Time, loc *time.Location) (start, reset time.Time) {
	if loc == nil {
		loc = time.Local
	}
	resetDay := effectiveTrafficResetDay(srv, loc)
	localAt := at.In(loc)
	y, m, _ := localAt.Date()
	thisReset := resetBoundaryInMonth(y, m, resetDay, loc)
	if !localAt.Before(thisReset) {
		ny, nm := shiftYearMonth(y, m, 1)
		return thisReset, resetBoundaryInMonth(ny, nm, resetDay, loc)
	}
	py, pm := shiftYearMonth(y, m, -1)
	return resetBoundaryInMonth(py, pm, resetDay, loc), thisReset
}

func (s *Store) RecalcServerCurrentCycleTraffic(srv shared.Server, now time.Time) error {
	unlock := s.lockCycleTraffic(srv.ID)
	defer unlock()

	loc := s.timeLocation()
	cycleStart, cycleReset := serverTrafficCycleBounds(srv, now, loc)
	startMs := cycleStart.UTC().UnixMilli()
	endMs := cycleReset.UTC().UnixMilli()

	var rx, tx int64
	if err := s.DB.QueryRow(
		`SELECT COALESCE(SUM(rx),0), COALESCE(SUM(tx),0) FROM mui_server_traffic WHERE server_id=$1 AND at_ms>=$2 AND at_ms<$3`,
		srv.ID, startMs, endMs,
	).Scan(&rx, &tx); err != nil {
		return err
	}
	_, err := s.DB.Exec(
		`INSERT INTO mui_server_cycle_traffic(server_id,cycle_start_ms,rx,tx) VALUES($1,$2,$3,$4) ON CONFLICT(server_id,cycle_start_ms) DO UPDATE SET rx=excluded.rx,tx=excluded.tx`,
		srv.ID, startMs, rx, tx,
	)
	return err
}

func (s *Store) BackfillCurrentCycleTraffic(now time.Time) error {
	servers, err := s.Servers()
	if err != nil {
		return err
	}
	for _, srv := range servers {
		if err := s.RecalcServerCurrentCycleTraffic(srv, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) EnsureCycleTrafficBackfill(now time.Time) error {
	tz := s.timeLocation().String()
	var done string
	err := s.DB.QueryRow(`SELECT value FROM mui_settings WHERE key='cycle_traffic_backfilled'`).Scan(&done)
	if err == nil && done == tz {
		return nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err := s.BackfillCurrentCycleTraffic(now); err != nil {
		return err
	}
	_, err = s.DB.Exec(
		`INSERT INTO mui_settings(key,value) VALUES('cycle_traffic_backfilled',$1) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		tz,
	)
	return err
}

func (s *Store) CycleTrafficMap(servers []shared.Server, now time.Time) (map[string]shared.CycleTrafficSummary, error) {
	out := make(map[string]shared.CycleTrafficSummary, len(servers))
	if len(servers) == 0 {
		return out, nil
	}
	loc := s.timeLocation()
	type wanted struct {
		start   time.Time
		reset   time.Time
		startMs int64
	}
	bounds := make(map[string]wanted, len(servers))
	var minStartMs int64
	for i, srv := range servers {
		st, rst := serverTrafficCycleBounds(srv, now, loc)
		ms := st.UTC().UnixMilli()
		bounds[srv.ID] = wanted{start: st, reset: rst, startMs: ms}
		if i == 0 || ms < minStartMs {
			minStartMs = ms
		}
	}

	type serverCycleKey struct {
		serverID string
		startMs  int64
	}
	stored := map[serverCycleKey][2]int64{}
	rows, err := s.DB.Query(
		`SELECT server_id,cycle_start_ms,rx,tx FROM mui_server_cycle_traffic WHERE cycle_start_ms>=$1`,
		minStartMs,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var srvID string
		var startMs, rx, tx int64
		if err := rows.Scan(&srvID, &startMs, &rx, &tx); err != nil {
			return nil, err
		}
		stored[serverCycleKey{serverID: srvID, startMs: startMs}] = [2]int64{rx, tx}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, srv := range servers {
		b := bounds[srv.ID]
		pair := stored[serverCycleKey{serverID: srv.ID, startMs: b.startMs}]
		used, normType := computeCycleUsed(pair[0], pair[1], srv.TrafficLimitType)
		out[srv.ID] = shared.CycleTrafficSummary{
			StartAt: b.start.UTC(),
			ResetAt: b.reset.UTC(),
			Rx:      pair[0],
			Tx:      pair[1],
			Used:    used,
			Limit:   srv.TrafficLimit,
			Type:    normType,
		}
	}
	return out, nil
}

// PruneServerCycleTraffic retains the 13 most recent cycles per server and removes older rows.
func (s *Store) PruneServerCycleTraffic(now time.Time) error {
	servers, err := s.Servers()
	if err != nil {
		return err
	}
	loc := s.timeLocation()
	known := make(map[string]bool, len(servers))
	for _, srv := range servers {
		known[srv.ID] = true
		curStart, _ := serverTrafficCycleBounds(srv, now, loc)
		resetDay := effectiveTrafficResetDay(srv, loc)
		y, m, _ := curStart.In(loc).Date()
		cy, cm := shiftYearMonth(y, m, -(retainedTrafficCycles - 1))
		cutoff := resetBoundaryInMonth(cy, cm, resetDay, loc)
		if _, err := s.DB.Exec(
			`DELETE FROM mui_server_cycle_traffic WHERE server_id=$1 AND cycle_start_ms<$2`,
			srv.ID, cutoff.UTC().UnixMilli(),
		); err != nil {
			return err
		}
	}
	fallbackCutoff := now.In(loc).AddDate(0, -retainedTrafficCycles, 0).UTC().UnixMilli()
	rows, err := s.DB.Query(`SELECT DISTINCT server_id FROM mui_server_cycle_traffic WHERE cycle_start_ms<$1`, fallbackCutoff)
	if err != nil {
		return err
	}
	var orphans []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil && !known[id] {
			orphans = append(orphans, id)
		}
	}
	rows.Close()
	for _, id := range orphans {
		if _, err := s.DB.Exec(`DELETE FROM mui_server_cycle_traffic WHERE server_id=$1 AND cycle_start_ms<$2`, id, fallbackCutoff); err != nil {
			return err
		}
	}
	return nil
}

func formatBytesAlert(v int64) string {
	if v < 0 {
		v = 0
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	val := float64(v)
	i := 0
	for val >= 1024 && i < len(units)-1 {
		val /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", v)
	}
	if math.Abs(val-math.Round(val)) < 0.05 {
		return fmt.Sprintf("%.0f %s", math.Round(val), units[i])
	}
	return fmt.Sprintf("%.1f %s", val, units[i])
}

func trafficAlertTiers(threshold int) []int {
	if threshold < 50 || threshold > 100 {
		threshold = 80
	}
	raw := []int{threshold, 90, 100}
	var out []int
	for _, t := range raw {
		if t < threshold {
			continue
		}
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	slices.Sort(out)
	return out
}

func (a *App) evaluateTrafficLimitAlerts(
	now time.Time,
	cfg TelegramThresholdEvent,
	servers []shared.Server,
	states map[string]alertStateRow,
) {
	if len(servers) == 0 {
		return
	}
	cycleMap, err := a.Store.CycleTrafficMap(servers, now)
	if err != nil {
		return
	}
	tiers := trafficAlertTiers(cfg.Threshold)
	loc := a.Store.timeLocation()
	nowMs := now.UnixMilli()

	for _, s := range servers {
		if s.TrafficLimit <= 0 || s.Status == "revoked" {
			continue
		}
		ct, ok := cycleMap[s.ID]
		if !ok || ct.Limit <= 0 {
			continue
		}
		pctFloat := 100 * float64(ct.Used) / float64(ct.Limit)
		startMs := ct.StartAt.UTC().UnixMilli()

		var rollbacks []alertStateRollback
		for _, tier := range tiers {
			if pctFloat < float64(tier) {
				continue
			}
			key := fmt.Sprintf("trafficLimit:%s:%d:%d", s.ID, startMs, tier)
			round, pending := parseAlertRetryRound(states[key].Status)
			if !pending {
				continue
			}
			if err := a.Store.putAlertState(key, "sent", nowMs, nowMs); err == nil {
				states[key] = alertStateRow{Key: key, Status: "sent", SinceMs: nowMs, UpdatedMs: nowMs}
				rollbacks = append(rollbacks, alertStateRollback{key: key, round: round})
			}
		}
		if len(rollbacks) == 0 {
			continue
		}

		pctInt := int(math.Floor(pctFloat + 1e-9))
		startStr := ct.StartAt.In(loc).Format("2006-01-02")
		endStr := ct.ResetAt.In(loc).AddDate(0, 0, -1).Format("2006-01-02")
		text := fmt.Sprintf(
			"[MUI] 流量用量告警\n服务器：%s\n已用：%s / %s（%d%%，%s）\n周期：%s 至 %s",
			formatAlertServer(s),
			formatBytesAlert(ct.Used),
			formatBytesAlert(ct.Limit),
			pctInt,
			trafficLimitTypeLabel(ct.Type),
			startStr,
			endStr,
		)
		a.notifyStateful("trafficLimit", fmt.Sprintf("trafficLimit:%s:%d:alert", s.ID, startMs), text, rollbacks)
	}
}

type serverTrafficReportItem struct {
	ServerID string
	Name     string
	Rx       int64
	Tx       int64
	Total    int64
}

func (s *Store) TrafficReportTotals(from, to time.Time) (map[string][2]int64, error) {
	rows, err := s.DB.Query(
		`SELECT server_id, COALESCE(SUM(rx),0), COALESCE(SUM(tx),0) FROM mui_server_traffic WHERE at_ms>=$1 AND at_ms<$2 GROUP BY server_id`,
		from.UTC().UnixMilli(), to.UTC().UnixMilli(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][2]int64{}
	for rows.Next() {
		var id string
		var rx, tx int64
		if err := rows.Scan(&id, &rx, &tx); err != nil {
			return nil, err
		}
		out[id] = [2]int64{rx, tx}
	}
	return out, rows.Err()
}

type trafficReportWindow struct {
	kind        string
	title       string
	stateKey    string
	scheduledAt time.Time
	periodStart time.Time
	periodEnd   time.Time
	periodLabel string
}

func dueTrafficReportWindows(now time.Time, cfg TelegramTrafficReport, loc *time.Location) []trafficReportWindow {
	if loc == nil {
		loc = time.Local
	}
	localNow := now.In(loc)
	today := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), 0, 0, 0, 0, loc)
	var out []trafficReportWindow

	if cfg.Daily {
		sched := today.Add(9 * time.Hour)
		if !localNow.Before(sched) && localNow.Before(sched.Add(12*time.Hour)) {
			start := today.AddDate(0, 0, -1)
			dayTag := start.Format("2006-01-02")
			out = append(out, trafficReportWindow{
				kind:        "daily",
				title:       "每日流量报告",
				stateKey:    "trafficReport:daily:" + dayTag,
				scheduledAt: sched,
				periodStart: start,
				periodEnd:   today,
				periodLabel: dayTag,
			})
		}
	}

	if cfg.Weekly {
		daysSinceMonday := (int(today.Weekday()) + 6) % 7
		thisMonday := today.AddDate(0, 0, -daysSinceMonday)
		sched := thisMonday.Add(9 * time.Hour)
		if !localNow.Before(sched) && localNow.Before(sched.Add(12*time.Hour)) {
			start := thisMonday.AddDate(0, 0, -7)
			endInclusive := thisMonday.AddDate(0, 0, -1)
			out = append(out, trafficReportWindow{
				kind:        "weekly",
				title:       "每周流量报告",
				stateKey:    "trafficReport:weekly:" + start.Format("2006-01-02"),
				scheduledAt: sched,
				periodStart: start,
				periodEnd:   thisMonday,
				periodLabel: start.Format("2006-01-02") + " 至 " + endInclusive.Format("2006-01-02"),
			})
		}
	}

	if cfg.Monthly {
		thisFirst := time.Date(localNow.Year(), localNow.Month(), 1, 0, 0, 0, 0, loc)
		sched := thisFirst.Add(9 * time.Hour)
		if !localNow.Before(sched) && localNow.Before(sched.Add(12*time.Hour)) {
			start := thisFirst.AddDate(0, -1, 0)
			out = append(out, trafficReportWindow{
				kind:        "monthly",
				title:       "每月流量报告",
				stateKey:    "trafficReport:monthly:" + start.Format("2006-01"),
				scheduledAt: sched,
				periodStart: start,
				periodEnd:   thisFirst,
				periodLabel: start.Format("2006-01"),
			})
		}
	}

	return out
}

func (a *App) evaluateTrafficReports(
	now time.Time,
	cfg TelegramTrafficReport,
	servers []shared.Server,
	states map[string]alertStateRow,
) {
	loc := a.Store.timeLocation()
	windows := dueTrafficReportWindows(now, cfg, loc)
	if len(windows) == 0 {
		return
	}
	nameByID := make(map[string]string, len(servers))
	for _, s := range servers {
		nameByID[s.ID] = formatAlertServer(s)
	}
	nowMs := now.UnixMilli()

	for _, w := range windows {
		round, pending := parseAlertRetryRound(states[w.stateKey].Status)
		if !pending {
			continue
		}
		totals, err := a.Store.TrafficReportTotals(w.periodStart, w.periodEnd)
		if err != nil {
			continue
		}
		var items []serverTrafficReportItem
		var grandRx, grandTx int64
		for id, pair := range totals {
			tot := pair[0] + pair[1]
			if tot <= 0 {
				continue
			}
			grandRx += pair[0]
			grandTx += pair[1]
			label := nameByID[id]
			if label == "" {
				label = id
			}
			items = append(items, serverTrafficReportItem{
				ServerID: id,
				Name:     label,
				Rx:       pair[0],
				Tx:       pair[1],
				Total:    tot,
			})
		}
		slices.SortFunc(items, func(a, b serverTrafficReportItem) int {
			if a.Total != b.Total {
				if a.Total > b.Total {
					return -1
				}
				return 1
			}
			return strings.Compare(a.Name, b.Name)
		})

		var msg strings.Builder
		msg.WriteString("[MUI] ")
		msg.WriteString(w.title)
		msg.WriteString("\n统计周期：")
		msg.WriteString(w.periodLabel)
		msg.WriteString("\n总用量：")
		msg.WriteString(formatBytesAlert(grandRx + grandTx))
		msg.WriteString("（↑ ")
		msg.WriteString(formatBytesAlert(grandTx))
		msg.WriteString(" · ↓ ")
		msg.WriteString(formatBytesAlert(grandRx))
		msg.WriteString("）")

		if len(items) == 0 {
			msg.WriteString("\n本周期无流量记录")
		} else {
			limit := min(30, len(items))
			for i := 0; i < limit; i++ {
				it := items[i]
				msg.WriteString("\n")
				msg.WriteString(strconv.Itoa(i + 1))
				msg.WriteString(". ")
				msg.WriteString(it.Name)
				msg.WriteString("：")
				msg.WriteString(formatBytesAlert(it.Total))
				msg.WriteString("（↑ ")
				msg.WriteString(formatBytesAlert(it.Tx))
				msg.WriteString(" · ↓ ")
				msg.WriteString(formatBytesAlert(it.Rx))
				msg.WriteString("）")
			}
			if len(items) > 30 {
				var restRx, restTx int64
				for _, it := range items[30:] {
					restRx += it.Rx
					restTx += it.Tx
				}
				msg.WriteString(fmt.Sprintf(
					"\n其余 %d 台合计：%s（↑ %s · ↓ %s）",
					len(items)-30,
					formatBytesAlert(restRx+restTx),
					formatBytesAlert(restTx),
					formatBytesAlert(restRx),
				))
			}
		}

		if err := a.Store.putAlertState(w.stateKey, "sent", nowMs, nowMs); err == nil {
			states[w.stateKey] = alertStateRow{Key: w.stateKey, Status: "sent", SinceMs: nowMs, UpdatedMs: nowMs}
			a.notifyStateful("trafficReport", w.stateKey, msg.String(), []alertStateRollback{{key: w.stateKey, round: round}})
		}
	}
}
