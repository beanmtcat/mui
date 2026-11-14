package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"mui/internal/shared"
)

const (
	maxServerPrice        float64 = 1_000_000
	maxServerTrafficLimit int64   = 1 << 53
	maxBillingRenewSteps  int     = 120
)

func (s *Store) timeLocation() *time.Location {
	if s != nil && s.timeLoc != nil {
		return s.timeLoc
	}
	return time.Local
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
func (a *App) autoRenewServers(now time.Time) ([]shared.Server, bool, error) {
	servers, err := a.Store.Servers()
	if err != nil {
		return nil, false, err
	}
	loc := a.Store.timeLocation()
	renewed := false
	for _, s := range servers {
		if !autoRenewEligible(s, now) {
			continue
		}
		if a.autoRenewOneServer(s.ID, now, loc) {
			renewed = true
		}
	}
	return servers, renewed, nil
}

func (a *App) autoRenewOneServer(id string, now time.Time, loc *time.Location) bool {
	unlock := a.lockServer(id)
	cur, err := a.Store.Server(id)
	if err != nil || !autoRenewEligible(cur, now) {
		unlock()
		return false
	}
	oldExp := *cur.ExpiresAt
	oldExpDate := formatExpiryDate(oldExp, loc)

	newExp, anchorDay, exceeded, err := computeRenewedExpiry(cur, now)
	if err != nil {
		unlock()
		return false
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
		return false
	}

	before := cur
	cur.ExpiresAt = &newExp
	cur.BillingAnchorDay = anchorDay
	if err := a.Store.PutServer(cur); err != nil {
		unlock()
		return false
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

	a.invalidatePublicStatusSnapshot()
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
	return true
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

	a.invalidatePublicStatusSnapshot()
	a.auditRequest(r, "server.renew", cur.ID, fmt.Sprintf("%s -> %s", oldExpDate, newExpDate))
	cur.Status = serverStatus(cur)
	if cycleMap, err := a.Store.CycleTrafficMap([]shared.Server{cur}, now); err == nil {
		ct := cycleMap[cur.ID]
		cur.CycleTraffic = &ct
	}
	writeJSON(w, 200, cur)
}
