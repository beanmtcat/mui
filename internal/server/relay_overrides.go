package server

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"mui/internal/shared"
)

type relayLine struct{ from, to string }
type relayOverrides map[relayLine]shared.RelayOverride

func (s *Store) relayOverrides() (relayOverrides, error) {
	rows, err := s.DB.Query(`SELECT from_server_id,to_server_id,state,until_ms,note FROM mui_relay_overrides`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := relayOverrides{}
	for rows.Next() {
		var o shared.RelayOverride
		var ms int64
		if err := rows.Scan(&o.FromServerID, &o.ToServerID, &o.State, &ms, &o.Note); err != nil {
			return nil, err
		}
		if ms != 0 {
			until := time.UnixMilli(ms).UTC()
			o.Until = &until
		}
		out[relayLine{o.FromServerID, o.ToServerID}] = o
	}
	return out, rows.Err()
}

func (o relayOverrides) effective(key relayLine, now time.Time) shared.RelayOverride {
	for _, candidate := range []relayLine{key, {"", key.to}} {
		if v, ok := o[candidate]; ok && (v.Until == nil || now.Before(*v.Until)) {
			return v
		}
	}
	return shared.RelayOverride{}
}

// Each group must keep a usable target independently for every preceding
// server. Include the landing node, which is a group of one.
func (w routeWorld) forEachRelayHop(rt shared.Route, visit func(from string, targets []string)) {
	if !rt.Enabled {
		return
	}
	from := []string{rt.EntryServerID}
	for _, hop := range rt.Hops {
		for _, id := range from {
			visit(id, hop.ServerIDs)
		}
		from = hop.ServerIDs
	}
	if node, ok := w.nodes[rt.NodeID]; ok {
		for _, id := range from {
			visit(id, []string{node.ServerID})
		}
	}
}

func (w routeWorld) blockedByRelayOverrides(rt shared.Route, overrides relayOverrides, now time.Time) bool {
	blocked := false
	w.forEachRelayHop(rt, func(from string, targets []string) {
		if len(targets) == 0 || blocked {
			return
		}
		times := []time.Time{now}
		for _, to := range targets {
			for _, key := range []relayLine{{from, to}, {"", to}} {
				if until := overrides[key].Until; until != nil && until.After(now) {
					times = append(times, *until)
				}
			}
		}
		for _, at := range times {
			if !slices.ContainsFunc(targets, func(to string) bool {
				return overrides.effective(relayLine{from, to}, at).State != shared.RelayDown
			}) {
				blocked = true
				return
			}
		}
	})
	return blocked
}

func (w routeWorld) relaySources(key relayLine) ([]string, bool) {
	sources := map[string]bool{}
	matched := false
	for _, rt := range w.routes {
		w.forEachRelayHop(rt, func(from string, targets []string) {
			if (key.from == "" || key.from == from) && slices.Contains(targets, key.to) {
				matched = true
				s := w.servers[from]
				if !shared.NoAgentManaged(s) && s.ForwardSupport && shared.VersionAtLeast(s.AgentVersion, shared.RelayHealthVersion) {
					sources[from] = true
				}
			}
		})
	}
	result := make([]string, 0, len(sources))
	for from := range sources {
		result = append(result, from)
	}
	slices.Sort(result)
	return result, matched
}

func (a *App) relayOverrideAPI(w http.ResponseWriter, r *http.Request) {
	current, err := a.Store.relayOverrides()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	now := time.Now()
	if r.Method == http.MethodGet {
		out := []shared.RelayOverride{}
		for _, v := range current {
			if v.Until == nil || now.Before(*v.Until) {
				out = append(out, v)
			}
		}
		slices.SortFunc(out, func(a, b shared.RelayOverride) int {
			if n := strings.Compare(a.ToServerID, b.ToServerID); n != 0 {
				return n
			}
			return strings.Compare(a.FromServerID, b.FromServerID)
		})
		writeJSON(w, 200, out)
		return
	}

	var in shared.RelayOverride
	clear := r.Method == http.MethodDelete
	if clear {
		in.FromServerID, in.ToServerID = r.URL.Query().Get("from"), r.URL.Query().Get("to")
	} else {
		if !readJSON(w, r, &in) {
			return
		}
		in.Note = strings.TrimSpace(in.Note)
		if !shared.ValidRelayState(in.State) || utf8.RuneCountInString(in.Note) > 200 {
			errorJSON(w, 400, "中转状态无效或备注超过 200 个字符")
			return
		}
		if in.Until != nil {
			until := time.UnixMilli(in.Until.UnixMilli()).UTC()
			if !until.After(now) || until.Year() > 9999 {
				errorJSON(w, 400, "到期时间必须在将来")
				return
			}
			in.Until = &until
		}
	}
	key := relayLine{in.FromServerID, in.ToServerID}
	world, err := a.loadRouteWorld()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if _, ok := world.servers[key.to]; !ok || key.from != "" && world.servers[key.from].ID == "" {
		errorJSON(w, 400, "服务器不存在")
		return
	}
	sources, matched := world.relaySources(key)
	// Permit clearing an old line override after its route is removed.
	if !clear && key.from != "" && !matched {
		errorJSON(w, 400, "这条线路未出现在启用的链路中")
		return
	}
	previous, existed := current[key]
	previousEffects := make(map[string]shared.RelayOverride, len(sources))
	for _, from := range sources {
		previousEffects[from] = current.effective(relayLine{from, key.to}, now)
	}
	var untilMS int64
	if clear {
		delete(current, key)
	} else {
		current[key] = in
		if in.Until != nil {
			untilMS = in.Until.UnixMilli()
		}
	}
	var blocked []string
	for _, rt := range world.routes {
		if world.blockedByRelayOverrides(rt, current, now) {
			blocked = append(blocked, rt.Name)
		}
	}
	if len(blocked) > 0 {
		errorJSON(w, 400, "此设置会使以下链路在现在或覆盖到期后没有可用目标："+strings.Join(blocked, "、")+"。如需停用只有一个目标的跳，请停用链路。")
		return
	}
	if clear {
		_, err = a.Store.DB.Exec(`DELETE FROM mui_relay_overrides WHERE from_server_id=$1 AND to_server_id=$2`, key.from, key.to)
	} else {
		_, err = a.Store.DB.Exec(`INSERT INTO mui_relay_overrides(from_server_id,to_server_id,state,until_ms,note,updated_ms)
			VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(from_server_id,to_server_id) DO UPDATE
			SET state=excluded.state,until_ms=excluded.until_ms,note=excluded.note,updated_ms=excluded.updated_ms`, key.from, key.to, in.State, untilMS, in.Note, now.UnixMilli())
	}
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	event := "relay.override.set"
	if clear {
		event = "relay.override.clear"
	}
	// A masked server override or a note edit does not change the signed
	// configuration. Repeating the same request can retry a failed enqueue.
	retry := clear && !existed || !clear && existed && previous.Note == in.Note && sameRelayEffect(previous, in)
	stateChanged := false
	sources = slices.DeleteFunc(sources, func(from string) bool {
		effective := current.effective(relayLine{from, key.to}, now)
		stateChanged = stateChanged || previousEffects[from].State != effective.State
		masked := key.from == "" && effective.FromServerID != ""
		return sameRelayEffect(previousEffects[from], effective) && !(retry && !masked)
	})
	message := relayManualMessage(world, key, in, clear, false)
	a.auditRequest(r, event, key.to, message)
	if stateChanged {
		a.notify("relayState", "", message)
	}
	if err = a.queueRelaySources(sources); err != nil {
		errorJSON(w, 503, "设置已保存，部分服务器未能创建下发任务。请重试："+err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func sameRelayEffect(a, b shared.RelayOverride) bool {
	if a.State != b.State {
		return false
	}
	if a.Until == nil || b.Until == nil {
		return a.Until == b.Until
	}
	return a.Until.Equal(*b.Until)
}

func (a *App) queueRelaySources(sources []string) error {
	var failed []string
	for _, from := range sources {
		if err := a.queueApply(from, "forwards.apply"); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", from, err))
		}
	}
	if len(failed) != 0 {
		return fmt.Errorf("%s", strings.Join(failed, "；"))
	}
	return nil
}

func (a *App) ExpireRelayOverrides() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	current, err := a.Store.relayOverrides()
	if err != nil {
		return err
	}
	var expired []relayLine
	for key, v := range current {
		if v.Until != nil && !now.Before(*v.Until) {
			expired = append(expired, key)
		}
	}
	if len(expired) == 0 {
		return nil
	}
	world, err := a.loadRouteWorld()
	if err != nil {
		return err
	}
	var sources []string
	for _, key := range expired {
		for _, from := range relayExpirySources(world, key, current) {
			if !slices.Contains(sources, from) {
				sources = append(sources, from)
			}
		}
	}
	// Desired state already ignores expired rows. Retain them and retry on
	// the next tick if the new state could not be queued.
	if err = a.queueRelaySources(sources); err != nil {
		return err
	}
	if _, err = a.Store.DB.Exec(`DELETE FROM mui_relay_overrides WHERE until_ms>0 AND until_ms<=$1`, now.UnixMilli()); err != nil {
		return err
	}
	for _, key := range expired {
		a.notify("relayState", "", relayManualMessage(world, key, current[key], true, true))
	}
	return nil
}

func relayExpirySources(world routeWorld, key relayLine, current relayOverrides) []string {
	sources, _ := world.relaySources(key)
	if key.from != "" {
		return sources
	}
	// A server-level expiry can affect only the sources where it was in use.
	before := current[key].Until.Add(-time.Millisecond)
	return slices.DeleteFunc(sources, func(from string) bool {
		return current.effective(relayLine{from, key.to}, before).FromServerID != ""
	})
}
