package server

import (
	"errors"
	"net/http"
	"time"

	"mui/internal/shared"
)

const maxMonitorPoints int = 1500

type monitorOverviewItem struct {
	ServerID     string                      `json:"serverId"`
	Online       bool                        `json:"online"`
	HostMonitor  bool                        `json:"hostMonitor"`
	Sample       *shared.MonitorSample       `json:"sample,omitempty"`
	Host         *shared.MonitorHost         `json:"host,omitempty"`
	CycleTraffic *shared.CycleTrafficSummary `json:"cycleTraffic,omitempty"`
}

func (a *App) monitorOverview(w http.ResponseWriter, _ *http.Request) {
	servers, err := a.Store.Servers()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	hosts, err := a.Store.MonitorHosts()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	now := a.nowMonitorUTC()
	cycleMap, err := a.Store.CycleTrafficMap(servers, now)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.monitorMu.RLock()
	samples := make(map[string]latestMonitorSample, len(a.latestSamples))
	for k, v := range a.latestSamples {
		samples[k] = v
	}
	a.monitorMu.RUnlock()

	items := make([]monitorOverviewItem, 0, len(servers))
	for _, s := range servers {
		ct := cycleMap[s.ID]
		if shared.NoAgentManaged(s) {
			items = append(items, monitorOverviewItem{
				ServerID:     s.ID,
				Online:       false,
				HostMonitor:  false,
				CycleTraffic: &ct,
			})
			continue
		}
		entry, hasSample := samples[s.ID]
		host, hasHost := hosts[s.ID]
		online := serverStatus(s) == "online" || (s.Status != "revoked" && hasSample && now.Sub(entry.receivedAt) <= 30*time.Second)
		item := monitorOverviewItem{
			ServerID:     s.ID,
			Online:       online,
			HostMonitor:  s.HostMonitor || hasSample || hasHost,
			CycleTraffic: &ct,
		}
		if hasSample {
			samp := entry.sample
			item.Sample = &samp
		}
		if hasHost {
			h := host
			item.Host = &h
		}
		items = append(items, item)
	}
	writeJSON(w, 200, items)
}

func (a *App) currentMinuteMonitorRecord(serverID string, since time.Time) (MonitorRecord, bool) {
	a.minuteAccumMu.Lock()
	defer a.minuteAccumMu.Unlock()
	b := a.minuteAccums[serverID]
	if b == nil || b.count == 0 {
		return MonitorRecord{}, false
	}
	rec := b.record()
	if rec.At.Before(since) {
		return MonitorRecord{}, false
	}
	return rec, true
}

func (a *App) monitorServerRecords(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("serverId")
	if !validServerID(id) || !a.serverExists(id) {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	rangeKey := r.URL.Query().Get("range")
	now := a.nowMonitorUTC()
	records, err := a.Store.MonitorRecords(id, rangeKey, now, maxMonitorPoints)
	if err != nil {
		if errors.Is(err, errInvalidMonitorRange) {
			errorJSON(w, 400, err.Error())
			return
		}
		errorJSON(w, 500, err.Error())
		return
	}
	if table, dur, specErr := monitorRangeSpec(rangeKey); specErr == nil && table == "mui_monitor_minutes" {
		if live, ok := a.currentMinuteMonitorRecord(id, now.Add(-dur)); ok {
			if len(records) == 0 || live.At.After(records[len(records)-1].At) {
				records = downsampleSlice(append(records, live), maxMonitorPoints)
			}
		}
	}
	writeJSON(w, 200, records)
}
