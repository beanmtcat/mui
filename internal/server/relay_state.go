package server

import (
	"slices"
	"time"

	"mui/internal/shared"
)

func isRouteForward(rule shared.ForwardRule) bool {
	return rule.RouteID != "" || len(rule.RouteIDs) != 0
}

func stripRelayTargetMetadata(targets []shared.ForwardTarget) {
	for i := range targets {
		targets[i] = shared.ForwardTarget{Host: targets[i].Host, Port: targets[i].Port}
	}
}

// relayTargets derives the identity from the route members while matching the
// stored sockets. A failed route sync can retain its last valid listener,
// but a new server's override must never be applied to that old endpoint.
func (w routeWorld) relayTargets(rule shared.ForwardRule) []string {
	var result []string
	for _, rt := range w.routes {
		if !rt.Enabled || !forwardBelongsToRoute(rule, rt.ID) || rule.Port != rt.Port {
			continue
		}
		var ids []string
		for i, hop := range rt.Hops {
			if i == 0 && rt.EntryServerID == rule.ServerID || i > 0 && slices.Contains(rt.Hops[i-1].ServerIDs, rule.ServerID) {
				if relayHopMatches(w, rule, hop.ServerIDs, hop.UsesInternal, rt.Port) {
					ids = hop.ServerIDs
				}
				break
			}
		}
		last := rt.EntryServerID == rule.ServerID
		if len(rt.Hops) > 0 {
			last = slices.Contains(rt.Hops[len(rt.Hops)-1].ServerIDs, rule.ServerID)
		}
		if node, ok := w.nodes[rt.NodeID]; last && ok && len(rule.Targets) == 1 &&
			rule.Targets[0].Host == hopAddress(w.servers[node.ServerID], rt.NodeInternal) && rule.Targets[0].Port == node.Port {
			ids = []string{node.ServerID}
		}
		if len(ids) == 0 || result != nil && !slices.Equal(result, ids) {
			return nil
		}
		result = ids
	}
	return result
}

func relayHopMatches(w routeWorld, rule shared.ForwardRule, ids []string, internal func(string) bool, port int) bool {
	if len(rule.Targets) != len(ids) {
		return false
	}
	for i, id := range ids {
		if rule.Targets[i].Host != hopAddress(w.servers[id], internal(id)) || rule.Targets[i].Port != port {
			return false
		}
	}
	return true
}

func (w routeWorld) assignRelayTargets(rule *shared.ForwardRule, overrides relayOverrides, now time.Time) {
	for i, id := range w.relayTargets(*rule) {
		o := overrides.effective(relayLine{rule.ServerID, id}, now)
		rule.Targets[i].ServerID = id
		rule.Targets[i].Override, rule.Targets[i].OverrideUntil = o.State, o.Until
	}
}

type relayPointKey struct {
	forward, server, host string
	port                  int
}

func relayKey(p shared.RelayState) relayPointKey {
	return relayPointKey{p.ForwardID, p.ServerID, p.Host, p.Port}
}

func allowedRelayPoints(world routeWorld, rules []shared.ForwardRule) map[relayPointKey]bool {
	allowed := map[relayPointKey]bool{}
	for _, rule := range rules {
		if !rule.Enabled || rule.Deleting || rule.Status != "active" || !shared.ForwardNetworkIncludes(rule.Network, "tcp") {
			continue
		}
		for i, id := range world.relayTargets(rule) {
			t := rule.Targets[i]
			allowed[relayPointKey{rule.ID, id, t.Host, t.Port}] = true
		}
	}
	return allowed
}

func validRelayAutoReason(state, reason string) bool {
	switch state {
	case shared.RelayNormal:
		return reason == "healthy"
	case shared.RelayDown:
		return reason == "probe_failed" || reason == "dial_failed" || reason == "downstream_down"
	case shared.RelayDegraded:
		return reason == "slow_handshake" || reason == "probe_loss" || reason == "blackhole" ||
			reason == "probe_failed" || reason == "dial_failed"
	case shared.RelayProbation:
		return reason == "recovering"
	default:
		return false
	}
}

func validRelayStats(s *shared.RelayStats) bool {
	return s == nil || s.ProbeSuccesses >= 0 && s.ProbeSuccesses <= 12 &&
		s.MedianMS >= 0 && s.MedianMS <= 3500 && s.BaselineMS >= 0 && s.BaselineMS <= 3500 &&
		s.PassiveBadPercent >= 0 && s.PassiveBadPercent <= 100 && s.PassiveSamples >= 0 && s.PassiveSamples <= 512
}

func validRelayState(p shared.RelayState, allowed map[relayPointKey]bool, now time.Time) bool {
	if len(p.ForwardID) > 64 || len(p.ServerID) > 64 || len(p.Host) > 253 ||
		!allowed[relayKey(p)] || p.Since.IsZero() || p.Since.After(now.Add(time.Minute)) ||
		!validRelayStats(p.Stats) || p.AutoSince != nil && (p.AutoSince.IsZero() || p.AutoSince.After(now.Add(time.Minute))) ||
		!shared.ValidRelayState(p.AutoState) && p.AutoState != shared.RelayProbation {
		return false
	}
	if p.Source == "manual" {
		return shared.ValidRelayState(p.State) && p.Reason == "manual" &&
			(p.AutoReason == "" || validRelayAutoReason(p.AutoState, p.AutoReason))
	}
	return p.Source == "auto" && p.State == p.AutoState && validRelayAutoReason(p.AutoState, p.Reason) && p.AutoReason == ""
}

func relayAutoEvent(p shared.RelayState) relayAutoChange {
	reason := p.Reason
	if p.Source == "manual" {
		reason = p.AutoReason
	}
	return relayAutoChange{p.ServerID, p.AutoState, reason}
}

func mergeRelaySamples(old []shared.RelayStateSample, points []shared.RelayState, allowed map[relayPointKey]bool, now time.Time) ([]shared.RelayStateSample, []relayAutoChange) {
	samples := make([]shared.RelayStateSample, 0, len(old))
	byKey := map[relayPointKey]int{}
	for _, s := range old {
		key := relayKey(s.RelayState)
		if allowed[key] && now.Sub(s.ReportedAt) <= routeLatencyFreshness {
			byKey[key] = len(samples)
			samples = append(samples, s)
		}
	}
	var changes []relayAutoChange
	for _, p := range points {
		if !validRelayState(p, allowed, now) {
			continue
		}
		key := relayKey(p)
		sample := shared.RelayStateSample{RelayState: p, ReportedAt: now}
		if i, ok := byKey[key]; ok {
			if samples[i].AutoState != p.AutoState || relayAutoEvent(p).reason == "downstream_down" && relayAutoEvent(samples[i].RelayState).reason != "downstream_down" {
				changes = append(changes, relayAutoEvent(p))
			}
			samples[i] = sample
		} else {
			if p.AutoState == shared.RelayDown || p.AutoState == shared.RelayDegraded {
				changes = append(changes, relayAutoEvent(p))
			}
			byKey[key] = len(samples)
			samples = append(samples, sample)
		}
	}
	return samples, changes
}

func relayAvailability(from shared.Server) string {
	if shared.NoAgentManaged(from) {
		return "offline"
	}
	if !shared.VersionAtLeast(from.AgentVersion, shared.RelayHealthVersion) {
		return "upgrade"
	}
	return ""
}

func routeRelayEdges(rt shared.Route, world routeWorld, overrides relayOverrides, now time.Time, downstream downstreamTopology) []shared.RelayEdge {
	if !rt.Enabled {
		return nil
	}
	tcp := map[string]shared.ForwardRule{}
	for _, f := range world.routeForwards(rt) {
		if f.Network == "tcp" {
			tcp[f.ServerID] = f
		}
	}
	var edges []shared.RelayEdge
	world.forEachRelayHop(rt, func(fromID string, toIDs []string) {
		from := world.servers[fromID]
		wanted := tcp[fromID]
		forwardID := world.routeTCPForwardID(rt, wanted)
		for i, to := range toIDs {
			edge := shared.RelayEdge{FromServerID: fromID, ToServerID: to, Availability: relayAvailability(from)}
			target := world.servers[to]
			key := downstream.routes[downstreamRouteKey{rt.ID, to}]
			if until := target.RelayDownstream[key].FlappingUntil; downstreamEligible(target) && until != nil && now.Before(*until) {
				edge.DownstreamFlapping = true
			}
			if override := overrides.effective(relayLine{fromID, to}, now); override.State != "" {
				edge.Override = &override
			}
			if i < len(wanted.Targets) && edge.Availability == "" {
				want := wanted.Targets[i]
				for _, sample := range from.RelayStates {
					if sample.ForwardID == forwardID && sample.ServerID == to && sample.Host == want.Host && sample.Port == want.Port && now.Sub(sample.ReportedAt) <= routeLatencyFreshness {
						reported := sample.RelayState
						edge.Reported = &reported
						break
					}
				}
			}
			edges = append(edges, edge)
		}
	})
	return edges
}

func (w routeWorld) routeTCPForwardID(rt shared.Route, wanted shared.ForwardRule) string {
	for _, rule := range w.forwards {
		if rule.ServerID != wanted.ServerID || !shared.ForwardNetworkIncludes(rule.Network, "tcp") ||
			!rule.Enabled || rule.Deleting || !forwardBelongsToRoute(rule, rt.ID) || rule.Port != wanted.Port {
			continue
		}
		if rule.RouteID == "" && w.manualForwardMatches(rt, wanted, rule) ||
			rule.RouteID != "" && rule.Balance == wanted.Balance && rule.HealthCheck == wanted.HealthCheck &&
				len(wanted.Targets) > 0 && slices.Equal(rule.Targets, wanted.Targets) {
			return rule.ID
		}
	}
	return routeForwardID(rt.ID, wanted.ServerID, "tcp")
}
