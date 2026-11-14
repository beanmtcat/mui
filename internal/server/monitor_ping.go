package server

import (
	"database/sql"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"mui/internal/shared"
)

const maxPingTasksCount int = 32

func validPingHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	if lower == "" || lower == "localhost" ||
		strings.HasSuffix(lower, ".localhost") ||
		strings.HasSuffix(lower, ".local") ||
		strings.HasSuffix(lower, ".internal") {
		return false
	}
	labels := strings.Split(lower, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func validatePingTarget(raw string) (string, error) {
	target := strings.TrimSpace(raw)
	if target == "" || len(target) > 260 || strings.ContainsAny(target, "/@% \t\r\n") {
		return "", errors.New("监测目标格式无效，请填写公网 host:port")
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return "", errors.New("监测目标需包含端口（例如 1.1.1.1:443 或 example.com:443）")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("监测目标端口必须在 1–65535 之间")
	}
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		if !shared.AllowedPingPublicIP(ip) {
			return "", errors.New("监测目标只允许公网地址，不能使用内网、回环、链路本地或 CGNAT 地址")
		}
		return net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(port)), nil
	}
	if strings.Contains(host, ":") || !validPingHostname(host) {
		return "", errors.New("监测目标主机名无效")
	}
	return net.JoinHostPort(strings.ToLower(strings.TrimSuffix(host, ".")), strconv.Itoa(port)), nil
}

func (a *App) invalidatePingTasksCache() {
	a.pingTasksMu.Lock()
	a.pingTasksLoaded = false
	a.pingTasksCache = nil
	a.pingTasksMu.Unlock()
	a.invalidatePublicStatusSnapshot()
}

func (a *App) cachedPingTasks() ([]MonitorPingTask, error) {
	a.pingTasksMu.RLock()
	if a.pingTasksLoaded {
		out := make([]MonitorPingTask, len(a.pingTasksCache))
		copy(out, a.pingTasksCache)
		a.pingTasksMu.RUnlock()
		return out, nil
	}
	a.pingTasksMu.RUnlock()

	tasks, err := a.Store.PingTasks()
	if err != nil {
		return nil, err
	}
	a.pingTasksMu.Lock()
	a.pingTasksCache = tasks
	a.pingTasksLoaded = true
	out := make([]MonitorPingTask, len(tasks))
	copy(out, tasks)
	a.pingTasksMu.Unlock()
	return out, nil
}

type pingTaskInput struct {
	Name            *string   `json:"name"`
	Target          *string   `json:"target"`
	IntervalSeconds *int      `json:"intervalSeconds"`
	ServerIDs       *[]string `json:"serverIds"`
}

func (a *App) validatePingServerIDs(ids []string) ([]string, error) {
	if len(ids) == 0 {
		return []string{}, nil
	}
	if len(ids) > 500 {
		return nil, errors.New("所选服务器数量过多")
	}
	servers, err := a.Store.Servers()
	if err != nil {
		return nil, err
	}
	valid := make(map[string]shared.Server, len(servers))
	for _, s := range servers {
		valid[s.ID] = s
	}
	seen := make(map[string]bool, len(ids))
	clean := make([]string, 0, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" || seen[id] {
			continue
		}
		srv, ok := valid[id]
		if !ok {
			return nil, errors.New("所选服务器不存在")
		}
		if shared.NoAgentManaged(srv) {
			return nil, errors.New("离线或外部服务器不支持 TCP 延迟监测")
		}
		seen[id] = true
		clean = append(clean, id)
	}
	return clean, nil
}

func (a *App) pingTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tasks, err := a.cachedPingTasks()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, tasks)
		return
	}

	existing, err := a.Store.PingTasks()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if len(existing) >= maxPingTasksCount {
		errorJSON(w, 400, "延迟监测任务最多创建 32 个")
		return
	}

	var in pingTaskInput
	if !readJSON(w, r, &in) {
		return
	}
	name := ""
	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
	}
	if name == "" || utf8.RuneCountInString(name) > 80 {
		errorJSON(w, 400, "任务名称必填且不超过 80 个字符")
		return
	}
	rawTarget := ""
	if in.Target != nil {
		rawTarget = *in.Target
	}
	target, err := validatePingTarget(rawTarget)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	interval := 60
	if in.IntervalSeconds != nil {
		interval = *in.IntervalSeconds
	}
	if interval < 30 || interval > 3600 {
		errorJSON(w, 400, "检测间隔必须在 30–3600 秒之间")
		return
	}
	var rawServerIDs []string
	if in.ServerIDs != nil {
		rawServerIDs = *in.ServerIDs
	}
	serverIDs, err := a.validatePingServerIDs(rawServerIDs)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}

	task := MonitorPingTask{
		ID:              ID(),
		Name:            name,
		Target:          target,
		IntervalSeconds: interval,
		ServerIDs:       serverIDs,
	}
	if err := a.Store.PutPingTask(task); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.invalidatePingTasksCache()
	a.auditRequest(r, "ping-task.create", task.ID, task.Name+" ("+task.Target+")")
	writeJSON(w, 201, task)
}

func (a *App) pingTaskByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validServerID(id) {
		errorJSON(w, 404, "监测任务不存在")
		return
	}
	if r.Method == http.MethodDelete {
		old, err := a.Store.PingTask(id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				errorJSON(w, 404, "监测任务不存在")
				return
			}
			errorJSON(w, 500, err.Error())
			return
		}
		if err := a.Store.DeletePingTask(id); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.clearPingTaskMemory(id)
		a.auditRequest(r, "ping-task.delete", id, old.Name)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}

	cur, err := a.Store.PingTask(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			errorJSON(w, 404, "监测任务不存在")
			return
		}
		errorJSON(w, 500, err.Error())
		return
	}
	var in pingTaskInput
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" || utf8.RuneCountInString(name) > 80 {
			errorJSON(w, 400, "任务名称必填且不超过 80 个字符")
			return
		}
		cur.Name = name
	}
	if in.Target != nil {
		target, err := validatePingTarget(*in.Target)
		if err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		cur.Target = target
	}
	if in.IntervalSeconds != nil {
		if *in.IntervalSeconds < 30 || *in.IntervalSeconds > 3600 {
			errorJSON(w, 400, "检测间隔必须在 30–3600 秒之间")
			return
		}
		cur.IntervalSeconds = *in.IntervalSeconds
	}
	if in.ServerIDs != nil {
		serverIDs, err := a.validatePingServerIDs(*in.ServerIDs)
		if err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		cur.ServerIDs = serverIDs
	}

	if err := a.Store.PutPingTask(cur); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.invalidatePingTasksCache()
	a.auditRequest(r, "ping-task.update", cur.ID, cur.Name+" ("+cur.Target+")")
	writeJSON(w, 200, cur)
}

func (a *App) currentMinutePingRecords(taskID, serverID string, since time.Time) []PingMinuteRecord {
	a.pingAccumMu.Lock()
	defer a.pingAccumMu.Unlock()
	prefix := taskID + "\x00"
	var out []PingMinuteRecord
	for k, acc := range a.pingAccums {
		if !strings.HasPrefix(k, prefix) || acc.sent == 0 {
			continue
		}
		if serverID != "" && acc.serverID != serverID {
			continue
		}
		at := time.UnixMilli(acc.minuteMs).UTC()
		if at.Before(since) {
			continue
		}
		out = append(out, PingMinuteRecord{
			ServerID: acc.serverID,
			At:       at,
			MsAvg:    acc.avg(),
			MsMax:    acc.msMax,
			Sent:     acc.sent,
			Lost:     acc.lost,
		})
	}
	slices.SortFunc(out, func(a, b PingMinuteRecord) int {
		if !a.At.Equal(b.At) {
			if a.At.Before(b.At) {
				return -1
			}
			return 1
		}
		if a.ServerID < b.ServerID {
			return -1
		}
		if a.ServerID > b.ServerID {
			return 1
		}
		return 0
	})
	return out
}

func (a *App) pingTaskRecords(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validServerID(id) {
		errorJSON(w, 404, "监测任务不存在")
		return
	}
	if _, err := a.Store.PingTask(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			errorJSON(w, 404, "监测任务不存在")
			return
		}
		errorJSON(w, 500, err.Error())
		return
	}
	serverID := strings.TrimSpace(r.URL.Query().Get("serverId"))
	if serverID != "" && !validServerID(serverID) {
		errorJSON(w, 400, "服务器 ID 无效")
		return
	}
	rangeKey := r.URL.Query().Get("range")
	now := a.nowMonitorUTC()
	records, err := a.Store.PingRecords(id, serverID, rangeKey, now, maxMonitorPoints)
	if err != nil {
		if errors.Is(err, errInvalidMonitorRange) {
			errorJSON(w, 400, err.Error())
			return
		}
		errorJSON(w, 500, err.Error())
		return
	}
	if dur, durErr := pingRangeDuration(rangeKey); durErr == nil {
		live := a.currentMinutePingRecords(id, serverID, now.Add(-dur))
		if len(live) > 0 {
			seen := make(map[string]bool, len(records))
			for _, rec := range records {
				seen[rec.ServerID+"\x00"+strconv.FormatInt(rec.At.UnixMilli(), 10)] = true
			}
			for _, rec := range live {
				if !seen[rec.ServerID+"\x00"+strconv.FormatInt(rec.At.UnixMilli(), 10)] {
					records = append(records, rec)
				}
			}
			records = downsampleSlice(records, maxMonitorPoints)
		}
	}
	writeJSON(w, 200, records)
}
