package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"mui/internal/shared"
)

func validateRouteTrafficFields(in *shared.Route, old *shared.Route, now time.Time) error {
	if in.TrafficLimit < 0 || in.TrafficLimit > shared.MaxRouteTrafficLimitBytes {
		return errors.New("链路周期流量配额超出有效范围")
	}
	lt := strings.TrimSpace(in.TrafficLimitType)
	if lt == "" {
		lt = "sum"
	}
	if !shared.ValidRouteTrafficLimitType(lt) {
		return errors.New("链路流量计量方向无效（仅支持上行+下行、仅上传、仅下载）")
	}
	in.TrafficLimitType = lt

	if in.TrafficResetDay < 0 || in.TrafficResetDay > 31 {
		return errors.New("链路每月重置日需在 0–31 之间")
	}

	if math.IsNaN(in.UpSpeedLimitMbps) || math.IsInf(in.UpSpeedLimitMbps, 0) || in.UpSpeedLimitMbps < 0 || in.UpSpeedLimitMbps > shared.MaxRouteSpeedLimitMbps {
		return errors.New("上传限速需在 0–100000 Mbps 之间")
	}
	if math.IsNaN(in.DownSpeedLimitMbps) || math.IsInf(in.DownSpeedLimitMbps, 0) || in.DownSpeedLimitMbps < 0 || in.DownSpeedLimitMbps > shared.MaxRouteSpeedLimitMbps {
		return errors.New("下载限速需在 0–100000 Mbps 之间")
	}
	in.UpSpeedLimitMbps = math.Round(in.UpSpeedLimitMbps*100) / 100
	in.DownSpeedLimitMbps = math.Round(in.DownSpeedLimitMbps*100) / 100

	if old != nil && old.TrafficMeteringStartedAt != nil {
		t := *old.TrafficMeteringStartedAt
		in.TrafficMeteringStartedAt = &t
	} else if old == nil || shared.RouteHasTrafficLimit(*in) {
		t := now.UTC()
		in.TrafficMeteringStartedAt = &t
	}
	return nil
}

func routeTrafficConfigChanged(a, b shared.Route) bool {
	return a.TrafficLimit != b.TrafficLimit ||
		a.TrafficLimitType != b.TrafficLimitType ||
		a.TrafficResetDay != b.TrafficResetDay ||
		a.UpSpeedLimitMbps != b.UpSpeedLimitMbps ||
		a.DownSpeedLimitMbps != b.DownSpeedLimitMbps ||
		a.EntryServerID != b.EntryServerID
}

// RouteEnforcementInfo reports how well the entry server can enforce route
// traffic quotas, aggregate speed limits, and entry total protection.
func RouteEnforcementInfo(rt shared.Route, entry shared.Server) (string, string) {
	if entry.ID == "" {
		return "unavailable", "首跳服务器不存在"
	}
	if shared.ExternalManaged(entry) {
		return "unavailable", "首跳为外部节点服务器，无法执行本机流量限制"
	}
	if shared.OfflineManaged(entry) {
		return "offline", "离线管理：导出并应用离线配置后由本机转发器独立执行计量、限速与超额阻断，面板无法实时汇总用量"
	}
	if !entry.ForwardTrafficLimitSupport {
		if shared.RouteHasTrafficLimit(rt) || (entry.TrafficProtectionEnabled && entry.TrafficLimit > 0) {
			return "upgrade_required", "入口服务器 Agent 版本过旧，不支持链路流量配额、限速与入口总额保护，请先升级入口 Agent"
		}
		return "upgrade_required", "入口服务器 Agent 尚未升级至支持链路流量限制的版本"
	}
	if shared.ManualFirewall(entry.FirewallMode) {
		return "manual_firewall", "入口防火墙为手动管理；链路计量、限速与超额阻断仍由入口本机转发器直接执行"
	}
	return "full", "由入口本机转发器实时计量、合计限速并执行超额阻断"
}

// SaveRouteTrafficStates persists per-route entry-hop cycle counters reported
// by an entry server's forwarder. Ownership is strictly verified: only the
// route's EntryServerID may update its cycle usage. Monotonic max() prevents
// duplicate reports or retries from double-counting.
func (s *Store) SaveRouteTrafficStates(serverID string, states []shared.RouteTrafficState) error {
	if len(states) == 0 {
		return nil
	}
	routes, err := s.Routes()
	if err != nil {
		return err
	}
	owned := make(map[string]shared.Route, len(routes))
	for _, rt := range routes {
		if rt.EntryServerID == serverID {
			owned[rt.ID] = rt
		}
	}
	if len(owned) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	nowMs := time.Now().UTC().UnixMilli()
	for _, st := range states {
		rt, ok := owned[st.RouteID]
		if !ok || st.CycleStartMs <= 0 || st.Uplink < 0 || st.Downlink < 0 {
			continue
		}
		meteringStartMs := nowMs
		if rt.TrafficMeteringStartedAt != nil {
			meteringStartMs = rt.TrafficMeteringStartedAt.UTC().UnixMilli()
		}
		pausedInt := 0
		var pausedAtMs int64
		if st.Paused {
			pausedInt = 1
			if st.PausedAt != nil {
				pausedAtMs = st.PausedAt.UTC().UnixMilli()
			} else {
				pausedAtMs = nowMs
			}
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO mui_route_cycle_traffic(route_id,cycle_start_ms,uplink,downlink,metering_start_ms,auto_paused,paused_at_ms,updated_ms)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT(route_id,cycle_start_ms) DO UPDATE SET
				uplink = CASE WHEN excluded.uplink > mui_route_cycle_traffic.uplink THEN excluded.uplink ELSE mui_route_cycle_traffic.uplink END,
				downlink = CASE WHEN excluded.downlink > mui_route_cycle_traffic.downlink THEN excluded.downlink ELSE mui_route_cycle_traffic.downlink END,
				metering_start_ms = CASE WHEN mui_route_cycle_traffic.metering_start_ms > 0 THEN mui_route_cycle_traffic.metering_start_ms ELSE excluded.metering_start_ms END,
				auto_paused = excluded.auto_paused,
				paused_at_ms = CASE WHEN excluded.auto_paused = 1 AND mui_route_cycle_traffic.paused_at_ms > 0 THEN mui_route_cycle_traffic.paused_at_ms WHEN excluded.auto_paused = 1 THEN excluded.paused_at_ms ELSE 0 END,
				updated_ms = excluded.updated_ms
		`, st.RouteID, st.CycleStartMs, st.Uplink, st.Downlink, meteringStartMs, pausedInt, pausedAtMs, nowMs)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DeleteRouteTrafficData(routeID string) error {
	if _, err := s.DB.Exec(`DELETE FROM mui_route_cycle_traffic WHERE route_id=$1`, routeID); err != nil {
		return err
	}
	esc := likeEscape(routeID)
	_, err := s.DB.Exec(`DELETE FROM mui_alert_state WHERE key LIKE $1 ESCAPE '\' OR key LIKE $2 ESCAPE '\' OR key LIKE $3 ESCAPE '\'`,
		"routeTrafficApproaching:"+esc+":%",
		"routeTrafficPaused:"+esc+":%",
		"routeTrafficResumed:"+esc+":%",
	)
	return err
}

func (s *Store) RouteCycleTrafficMap(routes []shared.Route, servers map[string]shared.Server, now time.Time) (map[string]shared.RouteCycleTrafficSummary, error) {
	loc := s.timeLocation()
	out := make(map[string]shared.RouteCycleTrafficSummary, len(routes))
	if len(routes) == 0 {
		return out, nil
	}
	type rowData struct {
		up, down, meteringStartMs, pausedAtMs int64
		autoPaused                            bool
	}
	byKey := map[string]rowData{}
	rows, err := s.DB.Query(`SELECT route_id,cycle_start_ms,uplink,downlink,metering_start_ms,auto_paused,paused_at_ms FROM mui_route_cycle_traffic`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var routeID string
		var cycleStartMs, up, down, meteringStartMs, pausedAtMs int64
		var autoPaused int
		if err := rows.Scan(&routeID, &cycleStartMs, &up, &down, &meteringStartMs, &autoPaused, &pausedAtMs); err != nil {
			return nil, err
		}
		key := fmt.Sprintf("%s\x00%d", routeID, cycleStartMs)
		byKey[key] = rowData{
			up:              up,
			down:            down,
			meteringStartMs: meteringStartMs,
			autoPaused:      autoPaused != 0,
			pausedAtMs:      pausedAtMs,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, rt := range routes {
		start, end := shared.MonthlyCycleBounds(now, rt.TrafficResetDay, loc)
		startMs := start.UTC().UnixMilli()
		lt := rt.TrafficLimitType
		if lt == "" {
			lt = "sum"
		}
		summary := shared.RouteCycleTrafficSummary{
			StartAt: start.UTC(),
			ResetAt: end.UTC(),
			Limit:   rt.TrafficLimit,
			Type:    lt,
		}
		if rt.TrafficMeteringStartedAt != nil {
			t := rt.TrafficMeteringStartedAt.UTC()
			summary.MeteringStartedAt = &t
		}
		if row, ok := byKey[fmt.Sprintf("%s\x00%d", rt.ID, startMs)]; ok {
			summary.Uplink = row.up
			summary.Downlink = row.down
			if summary.MeteringStartedAt == nil && row.meteringStartMs > 0 {
				t := time.UnixMilli(row.meteringStartMs).UTC()
				summary.MeteringStartedAt = &t
			}
			if row.autoPaused && rt.TrafficLimit > 0 {
				summary.AutoPaused = true
				summary.PauseReason = "route_quota"
				if row.pausedAtMs > 0 {
					t := time.UnixMilli(row.pausedAtMs).UTC()
					summary.PausedAt = &t
				}
			}
		}
		if summary.MeteringStartedAt != nil && summary.MeteringStartedAt.After(summary.StartAt) {
			summary.HasHistoricalGap = true
		}
		summary.Used = shared.ComputeRouteTrafficUsed(summary.Uplink, summary.Downlink, lt)
		if rt.TrafficLimit > 0 && summary.Used >= rt.TrafficLimit && !summary.AutoPaused {
			summary.AutoPaused = true
			summary.PauseReason = "route_quota"
		}
		if entry, ok := servers[rt.EntryServerID]; ok && entryProtectionActiveForCycle(entry, now, loc) {
			summary.AutoPaused = true
			if summary.PauseReason == "" {
				summary.PauseReason = "entry_protection"
			}
			if summary.PausedAt == nil && entry.TrafficProtectionState != nil && entry.TrafficProtectionState.TriggeredAt != nil {
				t := entry.TrafficProtectionState.TriggeredAt.UTC()
				summary.PausedAt = &t
			}
		}
		out[rt.ID] = summary
	}
	return out, nil
}

func entryProtectionActiveForCycle(srv shared.Server, now time.Time, loc *time.Location) bool {
	if !srv.TrafficProtectionEnabled || srv.TrafficLimit <= 0 || srv.TrafficProtectionState == nil || !srv.TrafficProtectionState.Active {
		return false
	}
	start, _ := serverTrafficCycleBounds(srv, now, loc)
	return srv.TrafficProtectionState.CycleStartMs == start.UTC().UnixMilli()
}

func entryAffectedRouteIDs(serverID string, routes []shared.Route) []string {
	var ids []string
	for _, rt := range routes {
		if rt.EntryServerID == serverID && rt.Enabled {
			ids = append(ids, rt.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

// reconcileServerEntryProtection updates srv.TrafficProtectionState for the
// current billing cycle using both host cycle usage and any agent-reported state.
func reconcileServerEntryProtection(srv *shared.Server, routes []shared.Route, ct shared.CycleTrafficSummary, agentState *shared.EntryTrafficProtectionState, now time.Time, loc *time.Location) (changed bool) {
	if !srv.TrafficProtectionEnabled || srv.TrafficLimit <= 0 {
		if srv.TrafficProtectionState != nil && srv.TrafficProtectionState.Active {
			srv.TrafficProtectionState = nil
			return true
		}
		srv.TrafficProtectionState = nil
		return false
	}
	start, _ := serverTrafficCycleBounds(*srv, now, loc)
	startMs := start.UTC().UnixMilli()
	thresholdPct := srv.TrafficProtectionThreshold
	if thresholdPct < shared.MinEntryProtectionThreshold || thresholdPct > shared.MaxEntryProtectionThreshold {
		thresholdPct = shared.DefaultEntryProtectionThreshold
	}
	thresholdBytes := shared.EntryProtectionThresholdBytes(srv.TrafficLimit, thresholdPct)
	affected := entryAffectedRouteIDs(srv.ID, routes)

	prevActive := srv.TrafficProtectionState != nil && srv.TrafficProtectionState.Active && srv.TrafficProtectionState.CycleStartMs == startMs
	agentActive := agentState != nil && agentState.Active && agentState.CycleStartMs == startMs
	panelActive := thresholdBytes > 0 && ct.Used >= thresholdBytes
	active := agentActive || panelActive

	next := &shared.EntryTrafficProtectionState{
		Active:           active,
		CycleStartMs:     startMs,
		ThresholdBytes:   thresholdBytes,
		LimitBytes:       srv.TrafficLimit,
		AffectedRouteIDs: affected,
		Source:           "panel",
	}
	if agentActive {
		next.Source = "agent"
	}
	if active {
		if prevActive && srv.TrafficProtectionState.TriggeredAt != nil {
			t := *srv.TrafficProtectionState.TriggeredAt
			next.TriggeredAt = &t
			next.TriggeredUsed = srv.TrafficProtectionState.TriggeredUsed
		} else if agentActive && agentState.TriggeredAt != nil {
			t := *agentState.TriggeredAt
			next.TriggeredAt = &t
			next.TriggeredUsed = agentState.TriggeredUsed
		} else {
			t := now.UTC()
			next.TriggeredAt = &t
			next.TriggeredUsed = ct.Used
		}
	}
	if prevActive != active || srv.TrafficProtectionState == nil || srv.TrafficProtectionState.CycleStartMs != startMs {
		changed = true
	}
	srv.TrafficProtectionState = next
	return changed
}

func (a *App) evaluateRouteAndEntryProtectionAlerts(now time.Time, cfg TelegramThresholdEvent, servers []shared.Server, states map[string]alertStateRow) {
	loc := a.Store.timeLocation()
	routes, err := a.Store.Routes()
	if err != nil {
		return
	}
	srvMap := make(map[string]shared.Server, len(servers))
	for _, s := range servers {
		srvMap[s.ID] = s
	}
	routeCycleMap, err := a.Store.RouteCycleTrafficMap(routes, srvMap, now)
	if err != nil {
		return
	}
	threshold := cfg.Threshold
	if threshold < 50 || threshold > 100 {
		threshold = 80
	}
	nowMs := now.UTC().UnixMilli()

	// 1. Route quota alerts: approaching, paused, and cycle resumed (per-cycle deduplicated).
	for _, rt := range routes {
		if !rt.Enabled || rt.TrafficLimit <= 0 {
			continue
		}
		summary := routeCycleMap[rt.ID]
		cycleKey := fmt.Sprintf("%d", summary.StartAt.UTC().UnixMilli())
		pct := int(math.Floor(float64(summary.Used) * 100.0 / float64(rt.TrafficLimit)))
		entryName := srvMap[rt.EntryServerID].Name
		if entryName == "" {
			entryName = rt.EntryServerID
		}

		// Approaching quota notification
		if pct >= threshold && !summary.AutoPaused {
			key := fmt.Sprintf("routeTrafficApproaching:%s:%s", rt.ID, cycleKey)
			if round, pending := parseAlertRetryRound(states[key].Status); pending {
				msg := fmt.Sprintf("[MUI] 链路流量接近配额\n链路：%s（入口：%s :%d）\n已用：%s / %s（%d%%）\n重置时间：%s",
					rt.Name, entryName, rt.Port,
					formatBytesAlert(summary.Used), formatBytesAlert(rt.TrafficLimit), pct,
					summary.ResetAt.In(loc).Format("2006-01-02 15:04"),
				)
				_ = a.Store.putAlertState(key, "sent", nowMs, nowMs)
				states[key] = alertStateRow{Key: key, Status: "sent", SinceMs: nowMs, UpdatedMs: nowMs}
				a.notifyStateful("trafficLimit", key, msg, []alertStateRollback{{key: key, round: round}})
			}
		}

		// Quota paused notification
		if summary.AutoPaused && summary.PauseReason == "route_quota" {
			key := fmt.Sprintf("routeTrafficPaused:%s:%s", rt.ID, cycleKey)
			if round, pending := parseAlertRetryRound(states[key].Status); pending {
				msg := fmt.Sprintf("[MUI] 链路达到流量配额已暂停\n链路：%s（入口：%s :%d）\n已用：%s / %s\n下次重置自动恢复：%s",
					rt.Name, entryName, rt.Port,
					formatBytesAlert(summary.Used), formatBytesAlert(rt.TrafficLimit),
					summary.ResetAt.In(loc).Format("2006-01-02 15:04"),
				)
				_ = a.Store.putAlertState(key, "sent", nowMs, nowMs)
				states[key] = alertStateRow{Key: key, Status: "sent", SinceMs: nowMs, UpdatedMs: nowMs}
				a.notifyStateful("trafficLimit", key, msg, []alertStateRollback{{key: key, round: round}})
			}
		} else {
			// Check if previous cycle was paused -> send cycle-resumed notification once for this new cycle.
			prevStart, _ := shared.MonthlyCycleBounds(summary.StartAt.Add(-time.Second), rt.TrafficResetDay, loc)
			prevPausedKey := fmt.Sprintf("routeTrafficPaused:%s:%d", rt.ID, prevStart.UTC().UnixMilli())
			resumedKey := fmt.Sprintf("routeTrafficResumed:%s:%s", rt.ID, cycleKey)
			if states[prevPausedKey].Status == "sent" {
				if round, pending := parseAlertRetryRound(states[resumedKey].Status); pending {
					msg := fmt.Sprintf("[MUI] 链路新周期已自动恢复\n链路：%s（入口：%s :%d）\n新周期：%s 至 %s",
						rt.Name, entryName, rt.Port,
						summary.StartAt.In(loc).Format("2006-01-02 15:04"),
						summary.ResetAt.In(loc).Format("2006-01-02 15:04"),
					)
					_ = a.Store.putAlertState(resumedKey, "sent", nowMs, nowMs)
					states[resumedKey] = alertStateRow{Key: resumedKey, Status: "sent", SinceMs: nowMs, UpdatedMs: nowMs}
					a.notifyStateful("trafficLimit", resumedKey, msg, []alertStateRollback{{key: resumedKey, round: round}})
				}
			}
		}
	}

	// 2. Entry server total traffic protection alerts (paused & cycle resumed).
	cycleMap, err := a.Store.CycleTrafficMap(servers, now)
	if err != nil {
		return
	}
	for i := range servers {
		srv := servers[i]
		if !srv.TrafficProtectionEnabled || srv.TrafficLimit <= 0 {
			continue
		}
		ct := cycleMap[srv.ID]
		fresh, eligible := a.reconcileServerEntryProtectionLocked(srv.ID, routes, ct, now, loc)
		if !eligible {
			continue
		}
		srv = fresh
		cycleKey := fmt.Sprintf("%d", ct.StartAt.UTC().UnixMilli())
		if srv.TrafficProtectionState != nil && srv.TrafficProtectionState.Active {
			key := fmt.Sprintf("entryProtectionPaused:%s:%s", srv.ID, cycleKey)
			if round, pending := parseAlertRetryRound(states[key].Status); pending {
				msg := fmt.Sprintf("[MUI] 入口机总流量保护已触发\n服务器：%s\n已用：%s / 阈值 %s（限额 %s）\n影响首跳链路：%d 条\n管理通道（SSH / Agent / 面板）保持可用。\n下次重置：%s",
					formatAlertServer(srv),
					formatBytesAlert(ct.Used),
					formatBytesAlert(srv.TrafficProtectionState.ThresholdBytes),
					formatBytesAlert(srv.TrafficLimit),
					len(srv.TrafficProtectionState.AffectedRouteIDs),
					ct.ResetAt.In(loc).Format("2006-01-02 15:04"),
				)
				_ = a.Store.putAlertState(key, "sent", nowMs, nowMs)
				states[key] = alertStateRow{Key: key, Status: "sent", SinceMs: nowMs, UpdatedMs: nowMs}
				a.notifyStateful("trafficLimit", key, msg, []alertStateRollback{{key: key, round: round}})
			}
		} else {
			prevStart, _ := serverTrafficCycleBounds(srv, ct.StartAt.Add(-time.Second), loc)
			prevKey := fmt.Sprintf("entryProtectionPaused:%s:%d", srv.ID, prevStart.UTC().UnixMilli())
			resumedKey := fmt.Sprintf("entryProtectionResumed:%s:%s", srv.ID, cycleKey)
			if states[prevKey].Status == "sent" {
				if round, pending := parseAlertRetryRound(states[resumedKey].Status); pending {
					msg := fmt.Sprintf("[MUI] 入口机新周期已解除总流量保护\n服务器：%s\n新周期：%s 至 %s",
						formatAlertServer(srv),
						ct.StartAt.In(loc).Format("2006-01-02 15:04"),
						ct.ResetAt.In(loc).Format("2006-01-02 15:04"),
					)
					_ = a.Store.putAlertState(resumedKey, "sent", nowMs, nowMs)
					states[resumedKey] = alertStateRow{Key: resumedKey, Status: "sent", SinceMs: nowMs, UpdatedMs: nowMs}
					a.notifyStateful("trafficLimit", resumedKey, msg, []alertStateRollback{{key: resumedKey, round: round}})
				}
			}
		}
	}
}

// reconcileServerEntryProtectionLocked acquires the server lock, re-reads the
// latest persisted server record, and updates ONLY TrafficProtectionState so
// concurrent admin edits, Agent heartbeats, or revision bumps are never
// overwritten by a stale alert-loop snapshot.
func (a *App) reconcileServerEntryProtectionLocked(serverID string, routes []shared.Route, ct shared.CycleTrafficSummary, now time.Time, loc *time.Location) (shared.Server, bool) {
	unlock := a.lockServer(serverID)
	defer unlock()
	fresh, err := a.Store.Server(serverID)
	if err != nil {
		return shared.Server{}, false
	}
	if !fresh.TrafficProtectionEnabled || fresh.TrafficLimit <= 0 {
		if fresh.TrafficProtectionState != nil {
			fresh.TrafficProtectionState = nil
			_ = a.Store.PutServer(fresh)
		}
		return fresh, false
	}
	if reconcileServerEntryProtection(&fresh, routes, ct, nil, now, loc) {
		_ = a.Store.PutServer(fresh)
	}
	return fresh, true
}

// routeBaselineForDesired loads the panel's current-cycle counters for a route
// so a freshly restarted forwarder starts from at least the panel-known usage.
func (s *Store) routeBaselineForDesired(routeID string, cycleStartMs int64) (up, down int64) {
	err := s.DB.QueryRow(`SELECT uplink,downlink FROM mui_route_cycle_traffic WHERE route_id=$1 AND cycle_start_ms=$2`, routeID, cycleStartMs).Scan(&up, &down)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, 0
	}
	return up, down
}
