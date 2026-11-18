package forward

import (
	"slices"
	"time"

	"mui/internal/shared"
)

type relayTargetState struct {
	serverID, override, autoReason string
	downstream                     bool
	downstreamSince                time.Time
	until, autoSince, manualSince  time.Time
}

func (t *target) refreshDownLocked(now time.Time) {
	if t.down && !t.retryAt.IsZero() && !now.Before(t.retryAt) {
		t.down, t.streak, t.retryAt = false, 0, time.Time{}
		t.recordAutoLocked("", now)
	}
}

func (t *target) recordAutoLocked(reason string, now time.Time) {
	t.relay.autoReason, t.relay.autoSince = reason, now
}

func (t *target) updateRelay(spec shared.ForwardTarget, now time.Time) {
	t.healthMu.Lock()
	defer t.healthMu.Unlock()
	var until time.Time
	if spec.OverrideUntil != nil {
		until = *spec.OverrideUntil
	}
	if t.relay.override != spec.Override || !t.relay.until.Equal(until) {
		t.relay.manualSince = now
	}
	if t.relay.autoSince.IsZero() {
		t.relay.autoSince = now
	}
	downstream := spec.Downstream == shared.RelayDown
	if downstream != t.relay.downstream {
		t.relay.downstream, t.relay.downstreamSince = downstream, now
	}
	t.relay.serverID, t.relay.override, t.relay.until = spec.ServerID, spec.Override, until
}

func (t *target) relayStatusLocked(now time.Time, auto string) (string, bool) {
	// Allow one minute for clocks that run behind the panel.
	if t.relay.override != "" && (t.relay.override != shared.RelayNormal || auto != shared.RelayDown) &&
		(t.relay.until.IsZero() || now.Before(t.relay.until.Add(time.Minute))) {
		return t.relay.override, true
	}
	return auto, false
}

func (t *target) automaticStateLocked() (state, reason string, since time.Time, stats *shared.RelayStats) {
	state, reason, since = shared.RelayNormal, "healthy", t.relay.autoSince
	if t.quality.group != nil {
		var summary shared.RelayStats
		state, reason, since, summary = t.quality.status()
		if reason == "" {
			reason = "healthy"
		}
		stats = &summary
	} else if t.down {
		state, reason = shared.RelayDown, t.relay.autoReason
	}
	if t.relay.downstream {
		return shared.RelayDown, "downstream_down", t.relay.downstreamSince, stats
	}
	if t.relay.downstreamSince.After(since) {
		since = t.relay.downstreamSince
	}
	return
}

func (t *target) relayStatus(now time.Time) (string, bool) {
	t.healthMu.Lock()
	defer t.healthMu.Unlock()
	t.refreshDownLocked(now)
	auto := shared.RelayNormal
	if t.relay.downstream {
		auto = shared.RelayDown
	} else if t.quality.group != nil {
		auto = t.quality.currentState()
	} else if t.down {
		auto = shared.RelayDown
	}
	return t.relayStatusLocked(now, auto)
}

func (t *target) effectiveUsable() bool {
	state, _ := t.relayStatus(time.Now())
	return state != shared.RelayDown
}

func (r *rule) specWithRelayTargets() shared.ForwardRule {
	spec := r.spec
	spec.Targets = slices.Clone(spec.Targets)
	for i, t := range r.targets {
		t.healthMu.Lock()
		spec.Targets[i].ServerID, spec.Targets[i].Override = t.relay.serverID, t.relay.override
		spec.Targets[i].OverrideUntil = nil
		spec.Targets[i].Downstream = ""
		if t.relay.downstream {
			spec.Targets[i].Downstream = shared.RelayDown
		}
		if !t.relay.until.IsZero() {
			until := t.relay.until
			spec.Targets[i].OverrideUntil = &until
		}
		t.healthMu.Unlock()
	}
	return spec
}

func (r *rule) updateRelayTargets(targets []shared.ForwardTarget) {
	if r.spec.RouteID == "" {
		return
	}
	r.relayMu.Lock()
	defer r.relayMu.Unlock()
	now := time.Now()
	haveUsable := false
	for i, spec := range targets {
		r.targets[i].updateRelay(spec, now)
		haveUsable = haveUsable || r.targets[i].effectiveUsable()
	}
	if r.spec.Network == "udp" {
		r.dropSessions(func(session *udpSession) bool {
			state, manual := session.target.relayStatus(now)
			return state == shared.RelayDown && (manual || haveUsable)
		})
	}
}

// candidates keeps automatic failures as a last resort. A manual down target
// is never eligible. Degraded targets preserve configured order and existing
// sessions even when new connections can use a normal target.
func (r *rule) candidates() []*target { return r.relayCandidates(true) }

func (r *rule) relayCandidates(newConnection bool) []*target {
	r.relayMu.RLock()
	defer r.relayMu.RUnlock()
	now := time.Now()
	normal := make([]*target, 0, len(r.targets))
	var degraded, probation, down []*target
	autoDegraded := 0
	for _, t := range r.targets {
		state, manual := t.relayStatus(now)
		switch state {
		case shared.RelayNormal:
			normal = append(normal, t)
		case shared.RelayDegraded:
			degraded = append(degraded, t)
			if !manual {
				autoDegraded++
			}
		case shared.RelayProbation:
			probation = append(probation, t)
			degraded = append(degraded, t)
		case shared.RelayDown:
			if !manual {
				down = append(down, t)
			}
		}
	}
	// Keep the configured group in service if every target degraded
	// automatically. The independent quality states still appear in reports.
	if autoDegraded > 0 && autoDegraded == len(r.targets) {
		normal, degraded = degraded, nil
	}
	if len(normal) == 0 && len(degraded) == 0 && r.spec.RouteID == "" {
		normal, down = down, nil
	}
	if newConnection && r.spec.Balance == "round-robin" && len(normal) > 1 {
		start := int((r.next.Add(1) - 1) % uint32(len(normal)))
		normal = append(append([]*target{}, normal[start:]...), normal[:start]...)
	}
	if newConnection && len(normal) > 0 && len(probation) > 0 {
		trial := r.nextTrial.Add(1) - 1
		slot := int(trial % 10)
		if slot > 0 && slot <= len(probation) {
			pick := slot - 1
			if len(probation) > 9 {
				pick = (int(trial/10)*9 + pick) % len(probation)
			}
			chosen := probation[pick]
			normal = append([]*target{chosen}, normal...)
			degraded = slices.DeleteFunc(degraded, func(t *target) bool { return t == chosen })
		}
	}
	return append(append(normal, degraded...), down...)
}

func (t *target) relaySnapshot(forwardID string, now time.Time) (shared.RelayState, bool) {
	t.healthMu.Lock()
	defer t.healthMu.Unlock()
	if t.relay.serverID == "" {
		return shared.RelayState{}, false
	}
	t.refreshDownLocked(now)
	auto, reason, since, stats := t.automaticStateLocked()
	state, manual := t.relayStatusLocked(now, auto)
	report := shared.RelayState{
		ForwardID: forwardID, ServerID: t.relay.serverID, Host: t.host, Port: t.port,
		State: state, Source: "auto", AutoState: auto, Reason: reason, Since: since, Stats: stats,
	}
	if manual {
		report.AutoReason, report.AutoSince = reason, &since
		report.Source, report.Reason, report.Since = "manual", "manual", t.relay.manualSince
	} else if !t.relay.until.IsZero() && t.relay.until.Add(time.Minute).After(report.Since) {
		report.Since = t.relay.until.Add(time.Minute)
	} else if t.relay.override == "" && t.relay.manualSince.After(report.Since) {
		report.Since = t.relay.manualSince
	}
	return report, true
}

func (s *Service) RelaySnapshot() []shared.RelayState {
	s.mu.Lock()
	defer s.mu.Unlock()
	var points []shared.RelayState
	keys := make([]string, 0, len(s.rules))
	for key := range s.rules {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	now := time.Now()
	for _, key := range keys {
		r := s.rules[key]
		if r.spec.RouteID == "" || r.spec.Network != "tcp" {
			continue
		}
		for _, t := range r.targets {
			if point, ok := t.relaySnapshot(r.spec.ID, now); ok {
				points = append(points, point)
			}
		}
	}
	return points
}
