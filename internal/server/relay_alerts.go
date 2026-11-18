package server

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"mui/internal/shared"
)

const relayAlertWindow = 10 * time.Minute

type relayAutoChange struct{ to, state, reason string }

type relayAlertWindowState struct {
	start            time.Time
	fromName, toName string
	suppressed       int
}

func relayStateLabel(state string) string {
	switch state {
	case shared.RelayNormal:
		return "正常"
	case shared.RelayDegraded:
		return "降级"
	case shared.RelayProbation:
		return "试跑"
	default:
		return "故障"
	}
}

func relayManualMessage(world routeWorld, line relayLine, override shared.RelayOverride, clear, expired bool) string {
	scope := "服务器「" + world.servers[line.to].Name + "」作为下一跳"
	if line.from != "" {
		scope = "线路「" + world.servers[line.from].Name + " → " + world.servers[line.to].Name + "」"
	}
	if clear && expired {
		return scope + "的手动覆盖已到期。原到期时间 " + formatAlertTime(*override.Until)
	}
	if clear {
		return scope + "已清除手动覆盖"
	}
	until := "永久"
	if override.Until != nil {
		until = formatAlertTime(*override.Until)
	}
	return scope + "已手动设为" + relayStateLabel(override.State) + "，到期时间 " + until
}

func (a *App) recordRelayChanges(from shared.Server, changes []relayAutoChange, now time.Time) {
	grouped := map[string]map[string][]string{}
	seen := map[relayAutoChange]bool{}
	for _, change := range changes {
		if seen[change] {
			continue
		}
		seen[change] = true
		to, err := a.Store.Server(change.to)
		if err != nil {
			continue
		}
		line := relayLine{from.ID, to.ID}
		a.relayAlertsMu.Lock()
		if a.relayAlerts == nil {
			a.relayAlerts = map[relayLine]relayAlertWindowState{}
		}
		window, exists := a.relayAlerts[line]
		if exists && now.Before(window.start.Add(relayAlertWindow)) {
			window.suppressed++
			a.relayAlerts[line] = window
			a.relayAlertsMu.Unlock()
			continue
		}
		a.relayAlerts[line] = relayAlertWindowState{start: now, fromName: from.Name, toName: to.Name}
		a.relayAlertsMu.Unlock()
		if exists {
			a.notifyRelayWindow(window)
		}
		reasons := grouped[change.state]
		if reasons == nil {
			reasons = map[string][]string{}
			grouped[change.state] = reasons
		}
		reasons[change.reason] = append(reasons[change.reason], to.Name)
	}
	for _, state := range []string{shared.RelayDown, shared.RelayDegraded, shared.RelayProbation, shared.RelayNormal} {
		reasons := grouped[state]
		if len(reasons) == 0 {
			continue
		}
		var groups []string
		for reason, names := range reasons {
			slices.Sort(names)
			detail := strings.Join(names, "、")
			if text := relayReasonLabel(reason); text != "" {
				detail += "（" + text + "）"
			}
			groups = append(groups, detail)
		}
		slices.Sort(groups)
		action := "自动判定" + relayStateLabel(state)
		if state == shared.RelayNormal {
			action = "自动判定恢复"
		}
		a.notify("relayState", "", fmt.Sprintf("%s → %s：%s", from.Name, strings.Join(groups, "；"), action))
	}
}

func relayReasonLabel(reason string) string {
	switch reason {
	case "downstream_down":
		return "下游不可用"
	case "slow_handshake":
		return "TCP 建连变慢"
	case "probe_loss":
		return "探测失败偏多"
	case "blackhole":
		return "上游多次未响应"
	case "probe_failed":
		return "TCP 探测失败"
	case "dial_failed":
		return "实际建连失败"
	case "recovering":
		return "观察期结束"
	default:
		return ""
	}
}

func (a *App) notifyRelayWindow(window relayAlertWindowState) {
	if window.suppressed > 0 {
		a.notify("relayState", "", fmt.Sprintf("%s → %s：10 分钟内切换 %d 次", window.fromName, window.toName, window.suppressed+1))
	}
}

func (a *App) FlushRelayAlerts(now time.Time) {
	a.relayAlertsMu.Lock()
	var done []relayAlertWindowState
	for key, window := range a.relayAlerts {
		if !now.Before(window.start.Add(relayAlertWindow)) {
			done = append(done, window)
			delete(a.relayAlerts, key)
		}
	}
	a.relayAlertsMu.Unlock()
	for _, window := range done {
		a.notifyRelayWindow(window)
	}
}
