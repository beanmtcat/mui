package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"time"

	"mui/internal/shared"
)

var errInvalidMonitorRange = errors.New("时间范围无效")

type MonitorRecord struct {
	At          time.Time `json:"at"`
	CPU         float64   `json:"cpu"`
	Load1       float64   `json:"load1"`
	RAMUsed     int64     `json:"ramUsed"`
	RAMTotal    int64     `json:"ramTotal"`
	SwapUsed    int64     `json:"swapUsed"`
	DiskUsed    int64     `json:"diskUsed"`
	DiskTotal   int64     `json:"diskTotal"`
	NetUp       int64     `json:"netUp"`
	NetDown     int64     `json:"netDown"`
	NetUpPeak   int64     `json:"netUpPeak"`
	NetDownPeak int64     `json:"netDownPeak"`
	TotalUp     int64     `json:"totalUp"`
	TotalDown   int64     `json:"totalDown"`
	TCP         int       `json:"tcp"`
	UDP         int       `json:"udp"`
	Process     int       `json:"process"`
}

type MonitorPingTask struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Target          string   `json:"target"`
	IntervalSeconds int      `json:"intervalSeconds"`
	ServerIDs       []string `json:"serverIds"`
}

type PingMinuteRecord struct {
	ServerID string    `json:"serverId"`
	At       time.Time `json:"at"`
	MsAvg    int       `json:"msAvg"`
	MsMax    int       `json:"msMax"`
	Sent     int       `json:"sent"`
	Lost     int       `json:"lost"`
}

func (s *Store) PutMonitorHost(serverID string, host shared.MonitorHost, updated time.Time) error {
	_, err := s.DB.Exec(
		`INSERT INTO mui_monitor_hosts(server_id,data,updated_ms) VALUES($1,$2,$3) ON CONFLICT(server_id) DO UPDATE SET data=excluded.data,updated_ms=excluded.updated_ms`,
		serverID, Marshal(host), updated.UnixMilli(),
	)
	return err
}

func (s *Store) MonitorHosts() (map[string]shared.MonitorHost, error) {
	rows, err := s.DB.Query(`SELECT server_id,data FROM mui_monitor_hosts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]shared.MonitorHost{}
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		var h shared.MonitorHost
		if err := json.Unmarshal([]byte(raw), &h); err != nil {
			continue
		}
		out[id] = h
	}
	return out, rows.Err()
}

func (s *Store) PutMonitorMinute(serverID string, atMs int64, r MonitorRecord) error {
	_, err := s.DB.Exec(
		`INSERT INTO mui_monitor_minutes(
			server_id,at_ms,cpu,load1,ram_used,ram_total,swap_used,disk_used,disk_total,
			net_up,net_down,net_up_peak,net_down_peak,total_up,total_down,tcp,udp,process
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		ON CONFLICT(server_id,at_ms) DO UPDATE SET
			cpu=excluded.cpu,load1=excluded.load1,ram_used=excluded.ram_used,ram_total=excluded.ram_total,
			swap_used=excluded.swap_used,disk_used=excluded.disk_used,disk_total=excluded.disk_total,
			net_up=excluded.net_up,net_down=excluded.net_down,net_up_peak=excluded.net_up_peak,
			net_down_peak=excluded.net_down_peak,total_up=excluded.total_up,total_down=excluded.total_down,
			tcp=excluded.tcp,udp=excluded.udp,process=excluded.process`,
		serverID, atMs, r.CPU, r.Load1, r.RAMUsed, r.RAMTotal, r.SwapUsed, r.DiskUsed, r.DiskTotal,
		r.NetUp, r.NetDown, r.NetUpPeak, r.NetDownPeak, r.TotalUp, r.TotalDown, r.TCP, r.UDP, r.Process,
	)
	return err
}

// RollupMonitorHours idempotently summarizes the last 3 completed hours from
// mui_monitor_minutes into mui_monitor_hours.
func (s *Store) RollupMonitorHours(now time.Time) error {
	hourEnd := now.UTC().Truncate(time.Hour)
	hourStart := hourEnd.Add(-3 * time.Hour)
	return s.RollupMonitorHourRange(hourStart.UnixMilli(), hourEnd.UnixMilli())
}

func (s *Store) RollupMonitorHourRange(fromMs, toMs int64) error {
	if toMs <= fromMs {
		return nil
	}
	rows, err := s.DB.Query(
		`SELECT server_id,at_ms,cpu,load1,ram_used,ram_total,swap_used,disk_used,disk_total,
			net_up,net_down,net_up_peak,net_down_peak,total_up,total_down,tcp,udp,process
		FROM mui_monitor_minutes
		WHERE at_ms>=$1 AND at_ms<$2
		ORDER BY server_id ASC, at_ms ASC`,
		fromMs, toMs,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	type hourBucket struct {
		serverID    string
		hourMs      int64
		count       int64
		cpuSum      float64
		load1Sum    float64
		ramUsedSum  int64
		ramTotal    int64
		swapUsedSum int64
		diskUsedSum int64
		diskTotal   int64
		netUpSum    int64
		netDownSum  int64
		netUpPeak   int64
		netDownPeak int64
		totalUp     int64
		totalDown   int64
		tcpSum      int64
		udpSum      int64
		processSum  int64
	}

	var buckets []hourBucket
	for rows.Next() {
		var (
			serverID                                          string
			atMs                                              int64
			cpu, load1                                        float64
			ramUsed, ramTotal, swapUsed, diskUsed, diskTotal  int64
			netUp, netDown, netUpPeak, netDownPeak            int64
			totalUp, totalDown                                int64
			tcp, udp, proc                                    int
		)
		if err := rows.Scan(
			&serverID, &atMs, &cpu, &load1, &ramUsed, &ramTotal, &swapUsed, &diskUsed, &diskTotal,
			&netUp, &netDown, &netUpPeak, &netDownPeak, &totalUp, &totalDown, &tcp, &udp, &proc,
		); err != nil {
			return err
		}
		hourMs := (atMs / 3_600_000) * 3_600_000
		if len(buckets) == 0 || buckets[len(buckets)-1].serverID != serverID || buckets[len(buckets)-1].hourMs != hourMs {
			buckets = append(buckets, hourBucket{serverID: serverID, hourMs: hourMs})
		}
		b := &buckets[len(buckets)-1]
		b.count++
		b.cpuSum += cpu
		b.load1Sum += load1
		b.ramUsedSum += ramUsed
		b.ramTotal = ramTotal
		b.swapUsedSum += swapUsed
		b.diskUsedSum += diskUsed
		b.diskTotal = diskTotal
		b.netUpSum += netUp
		b.netDownSum += netDown
		if netUpPeak > b.netUpPeak {
			b.netUpPeak = netUpPeak
		}
		if netDownPeak > b.netDownPeak {
			b.netDownPeak = netDownPeak
		}
		b.totalUp = totalUp
		b.totalDown = totalDown
		b.tcpSum += int64(tcp)
		b.udpSum += int64(udp)
		b.processSum += int64(proc)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	if len(buckets) == 0 {
		return nil
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, b := range buckets {
		n := float64(b.count)
		_, err := tx.Exec(
			`INSERT INTO mui_monitor_hours(
				server_id,at_ms,cpu,load1,ram_used,ram_total,swap_used,disk_used,disk_total,
				net_up,net_down,net_up_peak,net_down_peak,total_up,total_down,tcp,udp,process
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
			ON CONFLICT(server_id,at_ms) DO UPDATE SET
				cpu=excluded.cpu,load1=excluded.load1,ram_used=excluded.ram_used,ram_total=excluded.ram_total,
				swap_used=excluded.swap_used,disk_used=excluded.disk_used,disk_total=excluded.disk_total,
				net_up=excluded.net_up,net_down=excluded.net_down,net_up_peak=excluded.net_up_peak,
				net_down_peak=excluded.net_down_peak,total_up=excluded.total_up,total_down=excluded.total_down,
				tcp=excluded.tcp,udp=excluded.udp,process=excluded.process`,
			b.serverID, b.hourMs,
			b.cpuSum/n,
			b.load1Sum/n,
			int64(math.Round(float64(b.ramUsedSum)/n)),
			b.ramTotal,
			int64(math.Round(float64(b.swapUsedSum)/n)),
			int64(math.Round(float64(b.diskUsedSum)/n)),
			b.diskTotal,
			int64(math.Round(float64(b.netUpSum)/n)),
			int64(math.Round(float64(b.netDownSum)/n)),
			b.netUpPeak,
			b.netDownPeak,
			b.totalUp,
			b.totalDown,
			int(math.Round(float64(b.tcpSum)/n)),
			int(math.Round(float64(b.udpSum)/n)),
			int(math.Round(float64(b.processSum)/n)),
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func monitorRangeSpec(rangeKey string) (table string, dur time.Duration, err error) {
	switch rangeKey {
	case "", "24h":
		return "mui_monitor_minutes", 24 * time.Hour, nil
	case "1h":
		return "mui_monitor_minutes", time.Hour, nil
	case "6h":
		return "mui_monitor_minutes", 6 * time.Hour, nil
	case "7d":
		return "mui_monitor_hours", 7 * 24 * time.Hour, nil
	case "30d":
		return "mui_monitor_hours", 30 * 24 * time.Hour, nil
	default:
		return "", 0, errInvalidMonitorRange
	}
}

func downsampleSlice[T any](items []T, maxPoints int) []T {
	if maxPoints <= 0 || len(items) <= maxPoints {
		return items
	}
	if maxPoints == 1 {
		return []T{items[len(items)-1]}
	}
	out := make([]T, 0, maxPoints)
	last := len(items) - 1
	for i := 0; i < maxPoints-1; i++ {
		idx := (i * last) / (maxPoints - 1)
		out = append(out, items[idx])
	}
	out = append(out, items[last])
	return out
}

func (s *Store) MonitorRecords(serverID, rangeKey string, now time.Time, maxPoints int) ([]MonitorRecord, error) {
	table, dur, err := monitorRangeSpec(rangeKey)
	if err != nil {
		return nil, err
	}
	sinceMs := now.Add(-dur).UnixMilli()
	query := `SELECT at_ms,cpu,load1,ram_used,ram_total,swap_used,disk_used,disk_total,net_up,net_down,net_up_peak,net_down_peak,total_up,total_down,tcp,udp,process FROM ` + table + ` WHERE server_id=$1 AND at_ms>=$2 ORDER BY at_ms ASC`
	rows, err := s.DB.Query(query, serverID, sinceMs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MonitorRecord{}
	for rows.Next() {
		var atMs int64
		var rec MonitorRecord
		if err := rows.Scan(
			&atMs, &rec.CPU, &rec.Load1, &rec.RAMUsed, &rec.RAMTotal, &rec.SwapUsed, &rec.DiskUsed, &rec.DiskTotal,
			&rec.NetUp, &rec.NetDown, &rec.NetUpPeak, &rec.NetDownPeak, &rec.TotalUp, &rec.TotalDown,
			&rec.TCP, &rec.UDP, &rec.Process,
		); err != nil {
			return nil, err
		}
		rec.At = time.UnixMilli(atMs).UTC()
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return downsampleSlice(out, maxPoints), nil
}

func (s *Store) PingTasks() ([]MonitorPingTask, error) {
	rows, err := s.DB.Query(`SELECT data FROM mui_ping_tasks ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MonitorPingTask{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var t MonitorPingTask
		if err := json.Unmarshal([]byte(raw), &t); err != nil {
			continue
		}
		if t.ServerIDs == nil {
			t.ServerIDs = []string{}
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b MonitorPingTask) int {
		if a.Name != b.Name {
			if a.Name < b.Name {
				return -1
			}
			return 1
		}
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return out, nil
}

func (s *Store) PingTask(id string) (MonitorPingTask, error) {
	var raw string
	if err := s.DB.QueryRow(`SELECT data FROM mui_ping_tasks WHERE id=$1`, id).Scan(&raw); err != nil {
		return MonitorPingTask{}, err
	}
	var t MonitorPingTask
	if err := json.Unmarshal([]byte(raw), &t); err != nil {
		return MonitorPingTask{}, err
	}
	if t.ServerIDs == nil {
		t.ServerIDs = []string{}
	}
	return t, nil
}

func (s *Store) PutPingTask(t MonitorPingTask) error {
	if t.ServerIDs == nil {
		t.ServerIDs = []string{}
	}
	_, err := s.DB.Exec(
		`INSERT INTO mui_ping_tasks(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=excluded.data`,
		t.ID, Marshal(t),
	)
	return err
}

func (s *Store) DeletePingTask(id string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM mui_ping_minutes WHERE task_id=$1`, id); err != nil {
		return err
	}
	res, err := tx.Exec(`DELETE FROM mui_ping_tasks WHERE id=$1`, id)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

func (s *Store) UpsertPingMinute(taskID, serverID string, atMs int64, msAvg, msMax, sent, lost int) error {
	if sent <= 0 {
		return nil
	}
	_, err := s.DB.Exec(
		`INSERT INTO mui_ping_minutes(task_id,server_id,at_ms,ms_avg,ms_max,sent,lost)
		VALUES($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT(task_id,server_id,at_ms) DO UPDATE SET
			ms_avg = CASE
				WHEN (mui_ping_minutes.sent - mui_ping_minutes.lost + excluded.sent - excluded.lost) > 0
				THEN ((mui_ping_minutes.ms_avg * (mui_ping_minutes.sent - mui_ping_minutes.lost)) + (excluded.ms_avg * (excluded.sent - excluded.lost))) / (mui_ping_minutes.sent - mui_ping_minutes.lost + excluded.sent - excluded.lost)
				ELSE 0
			END,
			ms_max = CASE WHEN excluded.ms_max > mui_ping_minutes.ms_max THEN excluded.ms_max ELSE mui_ping_minutes.ms_max END,
			sent = mui_ping_minutes.sent + excluded.sent,
			lost = mui_ping_minutes.lost + excluded.lost`,
		taskID, serverID, atMs, msAvg, msMax, sent, lost,
	)
	return err
}

func pingRangeDuration(rangeKey string) (time.Duration, error) {
	switch rangeKey {
	case "", "24h":
		return 24 * time.Hour, nil
	case "1h":
		return time.Hour, nil
	case "6h":
		return 6 * time.Hour, nil
	case "7d":
		return 7 * 24 * time.Hour, nil
	default:
		return 0, errInvalidMonitorRange
	}
}

func (s *Store) PingRecords(taskID, serverID, rangeKey string, now time.Time, maxPoints int) ([]PingMinuteRecord, error) {
	dur, err := pingRangeDuration(rangeKey)
	if err != nil {
		return nil, err
	}
	sinceMs := now.Add(-dur).UnixMilli()
	var rows *sql.Rows
	if serverID != "" {
		rows, err = s.DB.Query(
			`SELECT server_id,at_ms,ms_avg,ms_max,sent,lost FROM mui_ping_minutes WHERE task_id=$1 AND server_id=$2 AND at_ms>=$3 ORDER BY at_ms ASC`,
			taskID, serverID, sinceMs,
		)
	} else {
		rows, err = s.DB.Query(
			`SELECT server_id,at_ms,ms_avg,ms_max,sent,lost FROM mui_ping_minutes WHERE task_id=$1 AND at_ms>=$2 ORDER BY at_ms ASC, server_id ASC`,
			taskID, sinceMs,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PingMinuteRecord{}
	for rows.Next() {
		var atMs int64
		var rec PingMinuteRecord
		if err := rows.Scan(&rec.ServerID, &atMs, &rec.MsAvg, &rec.MsMax, &rec.Sent, &rec.Lost); err != nil {
			return nil, err
		}
		rec.At = time.UnixMilli(atMs).UTC()
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return downsampleSlice(out, maxPoints), nil
}

func (s *Store) PruneMonitorMinutes(cutoff time.Time) error {
	_, err := s.DB.Exec(`DELETE FROM mui_monitor_minutes WHERE at_ms<$1`, cutoff.UnixMilli())
	return err
}

func (s *Store) PruneMonitorHours(cutoff time.Time) error {
	_, err := s.DB.Exec(`DELETE FROM mui_monitor_hours WHERE at_ms<$1`, cutoff.UnixMilli())
	return err
}

func (s *Store) PrunePingMinutes(cutoff time.Time) error {
	_, err := s.DB.Exec(`DELETE FROM mui_ping_minutes WHERE at_ms<$1`, cutoff.UnixMilli())
	return err
}

func (s *Store) DeleteServerMonitorTx(tx *sql.Tx, serverID string) error {
	for _, stmt := range []string{
		`DELETE FROM mui_monitor_hosts WHERE server_id=$1`,
		`DELETE FROM mui_monitor_minutes WHERE server_id=$1`,
		`DELETE FROM mui_monitor_hours WHERE server_id=$1`,
		`DELETE FROM mui_ping_minutes WHERE server_id=$1`,
	} {
		if _, err := tx.Exec(stmt, serverID); err != nil {
			return err
		}
	}

	rows, err := tx.Query(`SELECT id,data FROM mui_ping_tasks`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type taskUpdate struct {
		id     string
		task   MonitorPingTask
		delete bool
	}
	var updates []taskUpdate
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return err
		}
		var task MonitorPingTask
		if err := json.Unmarshal([]byte(raw), &task); err != nil || len(task.ServerIDs) == 0 {
			continue
		}
		kept := make([]string, 0, len(task.ServerIDs))
		for _, sid := range task.ServerIDs {
			if sid != serverID {
				kept = append(kept, sid)
			}
		}
		if len(kept) == len(task.ServerIDs) {
			continue
		}
		if len(kept) == 0 {
			updates = append(updates, taskUpdate{id: id, delete: true})
		} else {
			task.ServerIDs = kept
			updates = append(updates, taskUpdate{id: id, task: task})
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	for _, u := range updates {
		if u.delete {
			if _, err := tx.Exec(`DELETE FROM mui_ping_minutes WHERE task_id=$1`, u.id); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM mui_ping_tasks WHERE id=$1`, u.id); err != nil {
				return err
			}
		} else {
			if _, err := tx.Exec(`UPDATE mui_ping_tasks SET data=$1 WHERE id=$2`, Marshal(u.task), u.id); err != nil {
				return err
			}
		}
	}
	return nil
}
