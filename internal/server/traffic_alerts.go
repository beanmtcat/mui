package server

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"mui/internal/shared"
)

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
