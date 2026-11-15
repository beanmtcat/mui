package server

import (
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"mui/internal/shared"
)

const (
	publicStatusPingBuckets  = 30
	publicStatusPingWindow   = 30 * time.Minute
	publicStatusPingCacheTTL = 30 * time.Second
)

// PublicServerPingBucket summarizes one minute of public probe latency and packet loss.
type PublicServerPingBucket struct {
	At   time.Time `json:"at"`
	Ms   int       `json:"ms"`
	Loss float64   `json:"loss"`
}

// PingTaskMinuteRow represents one task/server/minute row from mui_ping_minutes.
type PingTaskMinuteRow struct {
	TaskID   string
	ServerID string
	AtMs     int64
	MsAvg    int
	Sent     int
	Lost     int
}

// RecentPingMinuteRows fetches minute-level ping rollups for all given servers in one query.
func (s *Store) RecentPingMinuteRows(serverIDs []string, sinceMs int64) ([]PingTaskMinuteRow, error) {
	if len(serverIDs) == 0 {
		return nil, nil
	}
	s.publicPingQueries.Add(1)

	args := make([]any, 0, 1+len(serverIDs))
	args = append(args, sinceMs)
	placeholders := make([]string, len(serverIDs))
	for i, id := range serverIDs {
		args = append(args, id)
		placeholders[i] = "$" + strconv.Itoa(i+2)
	}

	query := `SELECT task_id,server_id,at_ms,ms_avg,sent,lost FROM mui_ping_minutes WHERE at_ms>=$1 AND server_id IN (` + strings.Join(placeholders, ",") + `) ORDER BY at_ms ASC, task_id ASC`
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PingTaskMinuteRow
	for rows.Next() {
		var r PingTaskMinuteRow
		if err := rows.Scan(&r.TaskID, &r.ServerID, &r.AtMs, &r.MsAvg, &r.Sent, &r.Lost); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (a *App) cachedPublicPingSummary(visible []shared.Server, now time.Time) (map[string][]PublicServerPingBucket, error) {
	a.statusCacheMu.RLock()
	if a.statusPingCacheReady && now.Before(a.statusPingExpires) {
		cached := a.statusPingSummary
		a.statusCacheMu.RUnlock()
		return cached, nil
	}
	gen := a.statusCacheGen
	a.statusCacheMu.RUnlock()

	pingMap, err := a.buildPublicPingSummary(visible, now)
	if err != nil {
		return nil, err
	}

	a.statusCacheMu.Lock()
	if (!a.statusPingCacheReady || !now.Before(a.statusPingExpires)) && a.statusCacheGen == gen {
		a.statusPingSummary = pingMap
		a.statusPingExpires = now.Add(publicStatusPingCacheTTL)
		a.statusPingCacheReady = true
	}
	a.statusCacheMu.Unlock()

	return pingMap, nil
}

func (a *App) buildPublicPingSummary(visible []shared.Server, now time.Time) (map[string][]PublicServerPingBucket, error) {
	agentServerIDs := make([]string, 0, len(visible))
	serverSet := make(map[string]bool, len(visible))
	for _, s := range visible {
		if shared.NoAgentManaged(s) {
			continue
		}
		agentServerIDs = append(agentServerIDs, s.ID)
		serverSet[s.ID] = true
	}
	if len(agentServerIDs) == 0 {
		return nil, nil
	}

	tasks, err := a.cachedPingTasks()
	if err != nil {
		return nil, err
	}
	if len(tasks) == 0 {
		return nil, nil
	}

	taskByID := make(map[string]MonitorPingTask, len(tasks))
	taskAllowed := make(map[string]map[string]bool, len(tasks))
	for _, task := range tasks {
		taskByID[task.ID] = task
		if len(task.ServerIDs) > 0 {
			set := make(map[string]bool, len(task.ServerIDs))
			for _, sid := range task.ServerIDs {
				set[sid] = true
			}
			taskAllowed[task.ID] = set
		}
	}

	sinceMs := now.UTC().Truncate(time.Minute).Add(-publicStatusPingWindow).UnixMilli()
	dbRows, err := a.Store.RecentPingMinuteRows(agentServerIDs, sinceMs)
	if err != nil {
		return nil, err
	}

	type taskServerAtKey struct {
		taskID   string
		serverID string
		atMs     int64
	}
	type serverAtKey struct {
		serverID string
		atMs     int64
	}
	type pingBucketAccum struct {
		sent    int
		lost    int
		msSum   int64
		msCount int
	}

	seen := make(map[taskServerAtKey]bool, len(dbRows))
	byServerAt := make(map[serverAtKey]*pingBucketAccum)

	addSample := func(taskID, serverID string, atMs int64, msAvg, sent, lost int) {
		if atMs < sinceMs || sent <= 0 || !serverSet[serverID] {
			return
		}
		task, ok := taskByID[taskID]
		if !ok {
			return
		}
		if len(task.ServerIDs) > 0 && !taskAllowed[taskID][serverID] {
			return
		}
		k := taskServerAtKey{taskID: taskID, serverID: serverID, atMs: atMs}
		if seen[k] {
			return
		}
		seen[k] = true

		clampedLost := lost
		if clampedLost < 0 {
			clampedLost = 0
		} else if clampedLost > sent {
			clampedLost = sent
		}
		sk := serverAtKey{serverID: serverID, atMs: atMs}
		agg := byServerAt[sk]
		if agg == nil {
			agg = &pingBucketAccum{}
			byServerAt[sk] = agg
		}
		agg.sent += sent
		agg.lost += clampedLost
		if sent > clampedLost {
			avgVal := msAvg
			if avgVal < 0 {
				avgVal = 0
			}
			agg.msSum += int64(avgVal)
			agg.msCount++
		}
	}

	for _, r := range dbRows {
		addSample(r.TaskID, r.ServerID, r.AtMs, r.MsAvg, r.Sent, r.Lost)
	}

	a.pingAccumMu.Lock()
	for _, acc := range a.pingAccums {
		if acc == nil || acc.sent <= 0 || acc.minuteMs < sinceMs || !serverSet[acc.serverID] {
			continue
		}
		addSample(acc.taskID, acc.serverID, acc.minuteMs, acc.avg(), acc.sent, acc.lost)
	}
	a.pingAccumMu.Unlock()

	if len(byServerAt) == 0 {
		return nil, nil
	}

	perServerTimes := make(map[string][]int64)
	for sk := range byServerAt {
		perServerTimes[sk.serverID] = append(perServerTimes[sk.serverID], sk.atMs)
	}

	out := make(map[string][]PublicServerPingBucket, len(perServerTimes))
	for serverID, times := range perServerTimes {
		slices.Sort(times)
		if len(times) > publicStatusPingBuckets {
			times = times[len(times)-publicStatusPingBuckets:]
		}
		buckets := make([]PublicServerPingBucket, 0, len(times))
		for _, atMs := range times {
			agg := byServerAt[serverAtKey{serverID: serverID, atMs: atMs}]
			if agg == nil || agg.sent <= 0 {
				continue
			}
			ms := -1
			if agg.msCount > 0 {
				ms = int(math.Round(float64(agg.msSum) / float64(agg.msCount)))
			}
			loss := math.Round(float64(agg.lost)*1000/float64(agg.sent)) / 10
			buckets = append(buckets, PublicServerPingBucket{
				At:   time.UnixMilli(atMs).UTC(),
				Ms:   ms,
				Loss: loss,
			})
		}
		if len(buckets) > 0 {
			out[serverID] = buckets
		}
	}
	return out, nil
}
