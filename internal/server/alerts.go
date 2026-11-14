package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"mui/internal/shared"
)

type alertStateRow struct {
	Key       string
	Status    string
	SinceMs   int64
	UpdatedMs int64
}

// resourceSnapshot holds host usage percentages (0–100) for Stage 2's built-in monitor.
type resourceSnapshot struct {
	CPU    float64
	Memory float64
	Disk   float64
}

func formatAlertTime(t time.Time) string {
	return t.Local().Format("2006-01-02 15:04:05")
}

func formatAlertServer(s shared.Server) string {
	name := strings.TrimSpace(s.Name)
	if name == "" {
		name = s.ID
	}
	var loc []string
	if c := strings.TrimSpace(s.Country); c != "" {
		loc = append(loc, c)
	}
	if city := strings.TrimSpace(s.City); city != "" {
		loc = append(loc, city)
	} else if region := strings.TrimSpace(s.Region); region != "" {
		loc = append(loc, region)
	}
	if len(loc) == 0 {
		return name
	}
	return fmt.Sprintf("%s（%s）", name, strings.Join(loc, " · "))
}

func isAlertableFailedOp(kind string) bool {
	return strings.HasSuffix(kind, ".apply") ||
		kind == "agent.upgrade" ||
		kind == "core.upgrade" ||
		strings.HasPrefix(kind, "ufw.")
}

func (s *Store) loadAlertStates() (map[string]alertStateRow, error) {
	rows, err := s.DB.Query(`SELECT key,status,since_ms,updated_ms FROM mui_alert_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]alertStateRow{}
	for rows.Next() {
		var r alertStateRow
		if err := rows.Scan(&r.Key, &r.Status, &r.SinceMs, &r.UpdatedMs); err != nil {
			return nil, err
		}
		out[r.Key] = r
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) putAlertState(key, status string, sinceMs, updatedMs int64) error {
	_, err := s.DB.Exec(
		`INSERT INTO mui_alert_state(key,status,since_ms,updated_ms) VALUES($1,$2,$3,$4) ON CONFLICT(key) DO UPDATE SET status=excluded.status,since_ms=excluded.since_ms,updated_ms=excluded.updated_ms`,
		key, status, sinceMs, updatedMs,
	)
	return err
}

func (s *Store) deleteAlertState(key string) error {
	_, err := s.DB.Exec(`DELETE FROM mui_alert_state WHERE key=$1`, key)
	return err
}

func (s *Store) DeleteServerAlertStatesTx(tx *sql.Tx, serverID string) error {
	esc := likeEscape(serverID)
	_, err := tx.Exec(
		`DELETE FROM mui_alert_state WHERE key=$1 OR key LIKE $2 ESCAPE '\' OR key LIKE $3 ESCAPE '\' OR key LIKE $4 ESCAPE '\' OR key LIKE $5 ESCAPE '\'`,
		"serverOffline:"+serverID,
		"serverExpiring:"+esc+":%",
		"resource:"+esc+":%",
		"trafficLimit:"+esc+":%",
		"serverRenewAbandoned:"+esc+":%",
	)
	return err
}

func (s *Store) DeleteCertAlertStates(certID string) error {
	_, err := s.DB.Exec(`DELETE FROM mui_alert_state WHERE key LIKE $1 ESCAPE '\'`, "certExpiring:"+likeEscape(certID)+":%")
	return err
}

func (s *Store) DeleteSubscriptionAlertStates(subID string) error {
	_, err := s.DB.Exec(`DELETE FROM mui_alert_state WHERE key LIKE $1 ESCAPE '\'`, "subscriptionExpiring:"+likeEscape(subID)+":%")
	return err
}

// PruneAlertState deletes resolved, sent, or retry-pending alert state rows older than before.
func (s *Store) PruneAlertState(before time.Time) error {
	_, err := s.DB.Exec(`DELETE FROM mui_alert_state WHERE (status IN ('resolved','sent') OR status LIKE 'retry:%') AND updated_ms<$1`, before.UnixMilli())
	return err
}

// parseAlertRetryRound reports whether an expiry reminder key still needs sending
// and how many failed delivery rounds have already occurred.
func parseAlertRetryRound(status string) (round int, pending bool) {
	if status == "" {
		return 0, true
	}
	if rest, ok := strings.CutPrefix(status, "retry:"); ok {
		n, err := strconv.Atoi(rest)
		if err == nil && n >= 0 {
			return n, true
		}
		return maxExpiryAlertRequeues, false
	}
	if status == "sent" {
		return 0, false
	}
	return 0, true
}

func (a *App) clearServerResourcePending(serverID string) {
	a.alertEvalMu.Lock()
	defer a.alertEvalMu.Unlock()
	prefix := "resource:" + serverID + ":"
	for k := range a.resourceSince {
		if strings.HasPrefix(k, prefix) {
			delete(a.resourceSince, k)
		}
	}
}

// EvaluateAlerts evaluates all stateful alert rules without acquiring a.mu or lockServer.
func (a *App) EvaluateAlerts() {
	a.evaluateAlertsAt(time.Now())
}

func (a *App) evaluateAlertsAt(now time.Time) {
	a.autoRenewServers(now)

	a.alertEvalMu.Lock()
	defer a.alertEvalMu.Unlock()

	cfg, err := a.loadTelegramRuntimeConfig()
	if err != nil || !cfg.Enabled || cfg.BotToken == "" || cfg.ChatID == "" {
		return
	}

	states, err := a.Store.loadAlertStates()
	if err != nil {
		return
	}

	hasTrafficReport := cfg.Events.TrafficReport.Daily || cfg.Events.TrafficReport.Weekly || cfg.Events.TrafficReport.Monthly
	var servers []shared.Server
	needServers := cfg.Events.ServerOffline.Enabled ||
		cfg.Events.ServerExpiring.Enabled ||
		cfg.Events.Resource.Enabled ||
		cfg.Events.TrafficLimit.Enabled ||
		hasTrafficReport
	if needServers {
		servers, err = a.Store.Servers()
		if err != nil {
			return
		}
	}

	if cfg.Events.ServerOffline.Enabled {
		a.evaluateServerOffline(now, cfg.Events.ServerOffline, servers, states)
	}
	if cfg.Events.CertExpiring.Enabled {
		a.evaluateCertExpiring(now, states)
	}
	if cfg.Events.SubscriptionExpiring.Enabled {
		a.evaluateSubscriptionExpiring(now, states)
	}
	if cfg.Events.ServerExpiring.Enabled {
		a.evaluateServerExpiring(now, servers, states)
	}
	if cfg.Events.TrafficLimit.Enabled {
		a.evaluateTrafficLimitAlerts(now, cfg.Events.TrafficLimit, servers, states)
	}
	if hasTrafficReport {
		a.evaluateTrafficReports(now, cfg.Events.TrafficReport, servers, states)
	}
	if cfg.Events.Resource.Enabled {
		a.evaluateResourceAlerts(now, cfg.Events.Resource, servers, states)
	}
}

func (a *App) loadUpgradingServers() map[string]bool {
	out := map[string]bool{}
	rows, err := a.Store.DB.Query(`SELECT server_id,data FROM mui_operations WHERE state<>''`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var serverID, raw string
		if err := rows.Scan(&serverID, &raw); err != nil {
			continue
		}
		var op shared.Operation
		if json.Unmarshal([]byte(raw), &op) == nil &&
			op.Kind == "agent.upgrade" &&
			(op.Status == "running" || op.Status == "activating") {
			out[serverID] = true
		}
	}
	return out
}

func (a *App) evaluateServerOffline(now time.Time, cfg TelegramServerOfflineEvent, servers []shared.Server, states map[string]alertStateRow) {
	offlineMinutes := cfg.OfflineMinutes
	if offlineMinutes < 2 || offlineMinutes > 60 {
		offlineMinutes = 3
	}
	threshold := time.Duration(offlineMinutes) * time.Minute
	inStartupGrace := !a.startedAt.IsZero() && now.Sub(a.startedAt) < time.Duration(offlineMinutes+1)*time.Minute
	upgrading := a.loadUpgradingServers()

	for _, s := range servers {
		key := "serverOffline:" + s.ID
		cur, hasCur := states[key]

		if s.AlertMuted || shared.OfflineManaged(s) || shared.ExternalManaged(s) || s.Status == "revoked" || s.LastSeen == nil {
			if hasCur && cur.Status == "firing" {
				_ = a.Store.deleteAlertState(key)
				delete(states, key)
			}
			continue
		}

		offlineDur := now.Sub(*s.LastSeen)
		isOffline := offlineDur > threshold

		if cur.Status == "firing" {
			if !isOffline {
				since := time.UnixMilli(cur.SinceMs)
				recoveredDur := s.LastSeen.Sub(since)
				if recoveredDur <= 0 {
					recoveredDur = now.Sub(since)
				}
				mins := max(1, int(recoveredDur.Round(time.Minute)/time.Minute))
				nowMs := now.UnixMilli()
				if err := a.Store.putAlertState(key, "resolved", cur.SinceMs, nowMs); err == nil {
					states[key] = alertStateRow{Key: key, Status: "resolved", SinceMs: cur.SinceMs, UpdatedMs: nowMs}
					text := fmt.Sprintf("[MUI] 服务器恢复在线\n服务器：%s\n已恢复，离线了 %d 分钟",
						formatAlertServer(s), mins)
					a.notify("serverOffline", key+":resolved", text)
				}
			}
			continue
		}

		if !isOffline || inStartupGrace || upgrading[s.ID] {
			continue
		}

		sinceMs := s.LastSeen.UnixMilli()
		nowMs := now.UnixMilli()
		mins := max(offlineMinutes, int(offlineDur/time.Minute))
		if err := a.Store.putAlertState(key, "firing", sinceMs, nowMs); err == nil {
			states[key] = alertStateRow{Key: key, Status: "firing", SinceMs: sinceMs, UpdatedMs: nowMs}
			text := fmt.Sprintf("[MUI] 服务器离线\n服务器：%s\n最后上报：%s\n已离线：%d 分钟",
				formatAlertServer(s), formatAlertTime(*s.LastSeen), mins)
			a.notify("serverOffline", key, text)
		}
	}
}

// certExpiryStatusAt matches shared.CertExpiryStatus parameterized by now.
func certExpiryStatusAt(expiresAt, now time.Time) (days int, expiringSoon bool) {
	days = int(expiresAt.Sub(now).Hours() / 24)
	return days, days <= 30
}

func (a *App) evaluateCertExpiring(now time.Time, states map[string]alertStateRow) {
	certs, err := a.Store.Certificates()
	if err != nil {
		return
	}
	nowMs := now.UnixMilli()
	for _, c := range certs {
		days, soon := certExpiryStatusAt(c.ExpiresAt, now)
		if !soon {
			continue
		}
		expDate := c.ExpiresAt.UTC().Format("2006-01-02")
		prefix := fmt.Sprintf("certExpiring:%s:%s:", c.ID, expDate)

		// Three reminder stages per (certID, expiry date): enter threshold (<=30d), <=3d, <=1d.
		type stageSpec struct {
			tag     string
			reached bool
		}
		stages := []stageSpec{
			{tag: "30", reached: days <= 30},
			{tag: "3", reached: days <= 3},
			{tag: "1", reached: days <= 1},
		}

		var rollbacks []alertStateRollback
		for _, st := range stages {
			if !st.reached {
				continue
			}
			key := prefix + st.tag
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

		label := strings.TrimSpace(c.Name)
		domain := strings.TrimSpace(c.Domain)
		if label == "" {
			label = domain
		} else if domain != "" && domain != label {
			label = fmt.Sprintf("%s（%s）", label, domain)
		}
		var remainLine string
		if !c.ExpiresAt.After(now) {
			if days < 0 {
				remainLine = fmt.Sprintf("状态：已过期 %d 天", -days)
			} else {
				remainLine = "状态：已过期"
			}
		} else if days == 0 {
			remainLine = "剩余天数：不足 1 天"
		} else {
			remainLine = fmt.Sprintf("剩余天数：%d 天", days)
		}
		text := fmt.Sprintf("[MUI] 证书即将到期\n证书：%s\n到期日：%s\n%s",
			label, expDate, remainLine)
		a.notifyStateful("certExpiring", prefix+"alert", text, rollbacks)
	}
}

func (a *App) evaluateSubscriptionExpiring(now time.Time, states map[string]alertStateRow) {
	subs, err := a.Store.Subscriptions()
	if err != nil {
		return
	}
	nowMs := now.UnixMilli()
	for _, sub := range subs {
		if !sub.Enabled || sub.ExpiresAt == nil {
			continue
		}
		rem := sub.ExpiresAt.Sub(now)
		if rem >= 72*time.Hour {
			continue
		}
		expTag := sub.ExpiresAt.UTC().Format(time.RFC3339)
		soonKey := fmt.Sprintf("subscriptionExpiring:%s:%s:soon", sub.ID, expTag)
		expiredKey := fmt.Sprintf("subscriptionExpiring:%s:%s:expired", sub.ID, expTag)

		name := strings.TrimSpace(sub.Name)
		if name == "" {
			name = sub.ID
		}

		if rem <= 0 {
			expRound, expPending := parseAlertRetryRound(states[expiredKey].Status)
			if !expPending {
				continue
			}
			var rollbacks []alertStateRollback
			if soonRound, soonPending := parseAlertRetryRound(states[soonKey].Status); soonPending {
				if err := a.Store.putAlertState(soonKey, "sent", nowMs, nowMs); err == nil {
					states[soonKey] = alertStateRow{Key: soonKey, Status: "sent", SinceMs: nowMs, UpdatedMs: nowMs}
					rollbacks = append(rollbacks, alertStateRollback{key: soonKey, round: soonRound})
				}
			}
			if err := a.Store.putAlertState(expiredKey, "sent", nowMs, nowMs); err == nil {
				states[expiredKey] = alertStateRow{Key: expiredKey, Status: "sent", SinceMs: nowMs, UpdatedMs: nowMs}
				rollbacks = append(rollbacks, alertStateRollback{key: expiredKey, round: expRound})
				text := fmt.Sprintf("[MUI] 订阅已到期\n订阅：%s\n到期时间：%s",
					name, formatAlertTime(*sub.ExpiresAt))
				a.notifyStateful("subscriptionExpiring", expiredKey, text, rollbacks)
			}
			continue
		}

		soonRound, soonPending := parseAlertRetryRound(states[soonKey].Status)
		if !soonPending {
			continue
		}
		hours := max(1, int(rem.Hours()))
		remainDesc := fmt.Sprintf("%d 小时", hours)
		if days := int(rem.Hours() / 24); days >= 1 {
			remainDesc = fmt.Sprintf("%d 天", days)
		}
		if err := a.Store.putAlertState(soonKey, "sent", nowMs, nowMs); err == nil {
			states[soonKey] = alertStateRow{Key: soonKey, Status: "sent", SinceMs: nowMs, UpdatedMs: nowMs}
			text := fmt.Sprintf("[MUI] 订阅即将到期\n订阅：%s\n到期时间：%s\n剩余：%s",
				name, formatAlertTime(*sub.ExpiresAt), remainDesc)
			a.notifyStateful("subscriptionExpiring", soonKey, text, []alertStateRollback{{key: soonKey, round: soonRound}})
		}
	}
}

func serverExpiresAt(s shared.Server) *time.Time {
	return s.ExpiresAt
}

func (a *App) evaluateServerExpiring(now time.Time, servers []shared.Server, states map[string]alertStateRow) {
	for _, s := range servers {
		exp := serverExpiresAt(s)
		if exp == nil {
			continue
		}
		a.evaluateServerExpiryItem(now, s, *exp, states)
	}
}

func (a *App) evaluateServerExpiryItem(now time.Time, s shared.Server, expiresAt time.Time, states map[string]alertStateRow) {
	if s.Status == "revoked" {
		return
	}
	rem := expiresAt.Sub(now)
	if rem >= 7*24*time.Hour {
		return
	}
	days := int(rem.Hours() / 24)
	expDate := formatExpiryDate(expiresAt, a.Store.timeLocation())
	prefix := fmt.Sprintf("serverExpiring:%s:%s:", s.ID, expDate)
	nowMs := now.UnixMilli()

	// Servers where autoRenew will actually run do not emit 7/3/1-day expiry
	// warnings before expiry; instead they emit a single "即将自动续期" reminder
	// within 3 days. Online-managed servers without LastSeen or offline >24h fall
	// back to normal 7/3/1-day expiry warnings because autoRenew skips them.
	if autoRenewWillRun(s, now) && expiresAt.After(now) {
		if rem >= 3*24*time.Hour {
			return
		}
		key := prefix + "autorenew"
		round, pending := parseAlertRetryRound(states[key].Status)
		if !pending {
			return
		}
		if err := a.Store.putAlertState(key, "sent", nowMs, nowMs); err != nil {
			return
		}
		states[key] = alertStateRow{Key: key, Status: "sent", SinceMs: nowMs, UpdatedMs: nowMs}
		remainLine := fmt.Sprintf("剩余天数：%d 天", days)
		if days == 0 {
			remainLine = "剩余天数：不足 1 天"
		}
		var msg strings.Builder
		msg.WriteString(fmt.Sprintf("[MUI] 服务器即将自动续期\n服务器：%s\n到期日：%s\n%s",
			formatAlertServer(s), expDate, remainLine))
		if s.Price > 0 {
			msg.WriteString(fmt.Sprintf("\n周期费用：%s%.2f", currencyOrDefault(s.Currency), s.Price))
		}
		a.notifyStateful("serverExpiring", key, msg.String(), []alertStateRollback{{key: key, round: round}})
		return
	}

	type stageSpec struct {
		tag     string
		reached bool
	}
	stages := []stageSpec{
		{tag: "7", reached: rem < 7*24*time.Hour},
		{tag: "3", reached: rem < 3*24*time.Hour},
		{tag: "1", reached: rem < 24*time.Hour},
	}
	var rollbacks []alertStateRollback
	for _, st := range stages {
		if !st.reached {
			continue
		}
		key := prefix + st.tag
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
		return
	}
	var remainLine string
	if !expiresAt.After(now) {
		if days < 0 {
			remainLine = fmt.Sprintf("状态：已到期 %d 天", -days)
		} else {
			remainLine = "状态：已到期"
		}
	} else if days == 0 {
		remainLine = "剩余天数：不足 1 天"
	} else {
		remainLine = fmt.Sprintf("剩余天数：%d 天", days)
	}
	text := fmt.Sprintf("[MUI] 服务器即将到期\n服务器：%s\n到期日：%s\n%s",
		formatAlertServer(s), expDate, remainLine)
	a.notifyStateful("serverExpiring", prefix+"alert", text, rollbacks)
}

func (a *App) serverResourceSnapshot(s shared.Server, now time.Time) (resourceSnapshot, bool) {
	if shared.NoAgentManaged(s) || s.Status == "revoked" {
		return resourceSnapshot{}, false
	}
	entry, ok := a.latestMonitorSample(s.ID)
	if !ok {
		return resourceSnapshot{}, false
	}
	if s.LastSeen != nil && now.Sub(*s.LastSeen) > 90*time.Second && now.Sub(entry.receivedAt) > 90*time.Second {
		return resourceSnapshot{}, false
	}
	if now.Sub(entry.receivedAt) > 2*time.Minute {
		return resourceSnapshot{}, false
	}
	snap := resourceSnapshot{CPU: entry.sample.CPU}
	if entry.sample.RAMTotal > 0 {
		snap.Memory = 100 * float64(entry.sample.RAMUsed) / float64(entry.sample.RAMTotal)
	}
	if entry.sample.DiskTotal > 0 {
		snap.Disk = 100 * float64(entry.sample.DiskUsed) / float64(entry.sample.DiskTotal)
	}
	return snap, true
}

func (a *App) evaluateResourceAlerts(now time.Time, cfg TelegramResourceEvent, servers []shared.Server, states map[string]alertStateRow) {
	minutes := cfg.Minutes
	if minutes < 1 || minutes > 60 {
		minutes = 5
	}
	threshold := cfg.Threshold
	if threshold < 1 || threshold > 100 {
		threshold = 90
	}
	dur := time.Duration(minutes) * time.Minute

	for _, s := range servers {
		if s.AlertMuted {
			prefix := "resource:" + s.ID + ":"
			for k := range a.resourceSince {
				if strings.HasPrefix(k, prefix) {
					delete(a.resourceSince, k)
				}
			}
			for _, m := range []string{"cpu", "memory", "disk"} {
				stKey := prefix + m
				if states[stKey].Status == "firing" {
					_ = a.Store.deleteAlertState(stKey)
					delete(states, stKey)
				}
			}
			continue
		}
		snap, ok := a.serverResourceSnapshot(s, now)
		if !ok {
			continue
		}
		a.evaluateResourceMetric(now, s, "cpu", "CPU", snap.CPU, float64(threshold), minutes, dur, states)
		a.evaluateResourceMetric(now, s, "memory", "内存", snap.Memory, float64(threshold), minutes, dur, states)
		a.evaluateResourceMetric(now, s, "disk", "磁盘", snap.Disk, float64(threshold), minutes, dur, states)
	}
}

func (a *App) evaluateResourceMetric(
	now time.Time,
	s shared.Server,
	metricKey, metricLabel string,
	value, threshold float64,
	minutes int,
	sustain time.Duration,
	states map[string]alertStateRow,
) {
	if a.resourceSince == nil {
		a.resourceSince = map[string]time.Time{}
	}
	stateKey := fmt.Sprintf("resource:%s:%s", s.ID, metricKey)
	highPendingKey := stateKey + ":high"
	lowPendingKey := stateKey + ":low"
	cur := states[stateKey]
	nowMs := now.UnixMilli()

	if cur.Status == "firing" {
		delete(a.resourceSince, highPendingKey)
		if value > threshold {
			delete(a.resourceSince, lowPendingKey)
			return
		}
		lowStart, ok := a.resourceSince[lowPendingKey]
		if !ok {
			a.resourceSince[lowPendingKey] = now
			return
		}
		if now.Sub(lowStart) < sustain {
			return
		}
		delete(a.resourceSince, lowPendingKey)
		if err := a.Store.putAlertState(stateKey, "resolved", cur.SinceMs, nowMs); err == nil {
			states[stateKey] = alertStateRow{Key: stateKey, Status: "resolved", SinceMs: cur.SinceMs, UpdatedMs: nowMs}
			text := fmt.Sprintf("[MUI] 服务器资源恢复\n服务器：%s\n指标：%s（当前 %.1f%%，阈值 %.0f%%）\n状态：已回落并持续 %d 分钟",
				formatAlertServer(s), metricLabel, value, threshold, minutes)
			a.notify("resource", stateKey+":resolved", text)
		}
		return
	}

	delete(a.resourceSince, lowPendingKey)
	if value <= threshold {
		delete(a.resourceSince, highPendingKey)
		return
	}
	highStart, ok := a.resourceSince[highPendingKey]
	if !ok {
		a.resourceSince[highPendingKey] = now
		return
	}
	if now.Sub(highStart) < sustain {
		return
	}
	delete(a.resourceSince, highPendingKey)
	sinceMs := highStart.UnixMilli()
	if err := a.Store.putAlertState(stateKey, "firing", sinceMs, nowMs); err == nil {
		states[stateKey] = alertStateRow{Key: stateKey, Status: "firing", SinceMs: sinceMs, UpdatedMs: nowMs}
		text := fmt.Sprintf("[MUI] 服务器资源告警\n服务器：%s\n指标：%s\n当前使用率：%.1f%%（阈值 %.0f%%，已持续 %d 分钟）",
			formatAlertServer(s), metricLabel, value, threshold, minutes)
		a.notify("resource", stateKey, text)
	}
}

func (a *App) notifyApplyFailed(server shared.Server, op shared.Operation) {
	if !isAlertableFailedOp(op.Kind) {
		return
	}
	errMsg := strings.TrimSpace(op.Error)
	if errMsg == "" {
		errMsg = "未知错误"
	}
	errMsg = truncateRunes(errMsg, 500)
	text := fmt.Sprintf("[MUI] 操作执行失败\n服务器：%s\n操作：%s\n错误：%s",
		formatAlertServer(server), op.Kind, errMsg)
	a.notify("applyFailed", "applyFailed:"+op.ID, text)
}

func (a *App) notifySecurityEvent(title, clientIP, detail string) {
	var b strings.Builder
	b.WriteString("[MUI] 安全事件：")
	b.WriteString(title)
	if ip := strings.TrimSpace(clientIP); ip != "" {
		b.WriteString("\n来源 IP：")
		b.WriteString(ip)
	}
	if d := strings.TrimSpace(detail); d != "" {
		b.WriteString("\n说明：")
		b.WriteString(d)
	}
	b.WriteString("\n时间：")
	b.WriteString(formatAlertTime(time.Now()))
	a.notify("security", "security:"+title, b.String())
}

// ExpireUpgrades expires unconfirmed agent upgrades and emits applyFailed notifications.
func (a *App) ExpireUpgrades() error {
	expired, err := a.Store.expireUpgrades()
	for _, op := range expired {
		srv, srvErr := a.Store.Server(op.ServerID)
		if srvErr != nil {
			srv = shared.Server{ID: op.ServerID, Name: op.ServerID}
		}
		a.notifyApplyFailed(srv, op)
	}
	return err
}
