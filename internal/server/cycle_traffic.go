package server

import (
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"

	"mui/internal/shared"
)

const retainedTrafficCycles int = 13

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

func effectiveTrafficLimitType(raw string) string {
	switch strings.TrimSpace(raw) {
	case "up", "down", "max", "min", "sum":
		return strings.TrimSpace(raw)
	default:
		return "sum"
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
