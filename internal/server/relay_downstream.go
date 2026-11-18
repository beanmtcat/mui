package server

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"time"

	"mui/internal/shared"
)

const relayDownstreamWindow = 10 * time.Minute
const relayDownstreamLimit = 6

type downstreamRouteKey struct{ route, relay string }

type downstreamGroup struct {
	keys     []relayPointKey
	previous []string
}

type downstreamTopology struct {
	groups map[string]downstreamGroup
	routes map[downstreamRouteKey]string
}

func precedingRelayServers(rt shared.Route, relay string) []string {
	previous := []string{rt.EntryServerID}
	for _, hop := range rt.Hops {
		if slices.Contains(hop.ServerIDs, relay) {
			return previous
		}
		previous = hop.ServerIDs
	}
	return nil
}

// Index only live TCP rules with an unambiguous target identity. TCP and UDP
// upstream listeners both get their signal from the same downstream TCP group.
func (w routeWorld) downstreamTopology(onlyServer string) downstreamTopology {
	out := downstreamTopology{groups: map[string]downstreamGroup{}, routes: map[downstreamRouteKey]string{}}
	for _, f := range w.forwards {
		if onlyServer != "" && f.ServerID != onlyServer || !isRouteForward(f) ||
			!f.Enabled || f.Deleting || f.Status != "active" || !shared.ForwardNetworkIncludes(f.Network, "tcp") {
			continue
		}
		ids := w.relayTargets(f)
		if len(ids) == 0 || len(ids) > 16 {
			continue
		}
		var group downstreamGroup
		for i, id := range ids {
			t := f.Targets[i]
			group.keys = append(group.keys, relayPointKey{f.ID, id, t.Host, t.Port})
		}
		// Include the destination identity and endpoint so an edited target
		// never inherits a failure observed on the old path.
		signature := struct {
			ID      string
			IDs     []string
			Targets []shared.ForwardTarget
		}{f.ID, ids, f.Targets}
		digest := sha256.Sum256([]byte(Marshal(signature)))
		key := hex.EncodeToString(digest[:16])
		for _, rt := range w.routes {
			if !rt.Enabled || !forwardBelongsToRoute(f, rt.ID) {
				continue
			}
			previous := precedingRelayServers(rt, f.ServerID)
			if len(previous) == 0 {
				continue
			}
			out.routes[downstreamRouteKey{rt.ID, f.ServerID}] = key
			for _, id := range previous {
				if !slices.Contains(group.previous, id) {
					group.previous = append(group.previous, id)
				}
			}
		}
		if len(group.previous) > 0 {
			slices.Sort(group.previous)
			out.groups[key] = group
		}
	}
	return out
}

// Reuse the same accepted points for display, alerts, and propagation.
// Missing members from an older report never count as fresh observations.
func (a *App) ingestRelayStates(server *shared.Server, points []shared.RelayState, now time.Time) ([]relayAutoChange, error) {
	if !downstreamEligible(*server) {
		reconcileDownstream(server, downstreamTopology{}, now)
		server.RelayStates = nil
		return nil, nil
	}
	if len(points) == 0 {
		return nil, nil
	}
	world, err := a.loadRouteWorld()
	if err != nil {
		return nil, err
	}
	var rules []shared.ForwardRule
	for _, f := range world.forwards {
		if f.ServerID == server.ID {
			rules = append(rules, f)
		}
	}
	var changes []relayAutoChange
	server.RelayStates, changes = mergeRelaySamples(server.RelayStates, points, allowedRelayPoints(world, rules), now)
	accepted := make(map[relayPointKey]string)
	for _, sample := range server.RelayStates {
		if sample.ReportedAt.Equal(now) {
			accepted[relayKey(sample.RelayState)] = sample.State
		}
	}
	recordDownstream(server, world.downstreamTopology(server.ID), accepted, now)
	return changes, nil
}

func (w routeWorld) downstreamHints(now time.Time, flapping bool) downstreamTopology {
	for _, s := range w.servers {
		for _, record := range s.RelayDownstream {
			if record.Down || flapping && record.FlappingUntil != nil && now.Before(*record.FlappingUntil) {
				return w.downstreamTopology("")
			}
		}
	}
	return downstreamTopology{}
}

func downstreamEligible(server shared.Server) bool {
	return relayAvailability(server) == "" && server.Status != "revoked"
}

func observeDownstream(s *shared.RelayDownstreamStatus, group downstreamGroup, accepted map[relayPointKey]string, now time.Time) bool {
	var down, healthy uint32
	for i, key := range group.keys {
		result, ok := accepted[key]
		if !ok {
			continue
		}
		if result == shared.RelayDown {
			down |= 1 << i
		} else {
			healthy |= 1 << i
		}
	}
	if down|healthy == 0 {
		return false
	}
	s.EvidenceAt = now
	var wantDown bool
	if s.Down {
		recovered := false
		for i := range group.keys {
			bit := uint32(1) << i
			if down&bit != 0 {
				delete(s.HealthyAt, i)
			}
			if healthy&bit != 0 {
				if previous, seen := s.HealthyAt[i]; seen && now.Sub(previous) <= routeLatencyFreshness {
					recovered = true
				}
				if s.HealthyAt == nil {
					s.HealthyAt = map[int]time.Time{}
				}
				s.HealthyAt[i] = now
			}
		}
		if !recovered {
			return false
		}
	} else {
		// Batches can split a target group. A complete all-down round
		// must collect a fresh failure for every target.
		if healthy != 0 {
			s.DownSeen, s.DownRoundAt, s.LastAllDownAt = 0, nil, nil
		}
		if down != 0 && (s.DownRoundAt == nil || now.Sub(*s.DownRoundAt) > routeLatencyFreshness) {
			s.DownSeen, s.DownRoundAt = 0, &now
		}
		s.DownSeen |= down
		if all := uint32(1)<<len(group.keys) - 1; s.DownSeen != all {
			return false
		}
		previous := s.LastAllDownAt
		s.DownSeen, s.DownRoundAt, s.LastAllDownAt = 0, nil, &now
		if previous == nil || now.Sub(*previous) > routeLatencyFreshness {
			return false
		}
		wantDown = true
	}
	s.Changes = slices.DeleteFunc(s.Changes, func(at time.Time) bool { return now.Sub(at) >= relayDownstreamWindow })
	if len(s.Changes) >= relayDownstreamLimit {
		until := s.Changes[0].Add(relayDownstreamWindow)
		s.FlappingUntil = &until
		return false
	}
	s.Down = wantDown
	s.DownSeen, s.DownRoundAt, s.LastAllDownAt, s.HealthyAt = 0, nil, nil, nil
	s.Changes = append(s.Changes, now)
	s.FlappingUntil = nil
	return true
}

func markDownstreamPending(s *shared.Server, previous []string, now time.Time) {
	if len(previous) == 0 {
		return
	}
	if s.RelayDownstreamPending == nil {
		s.RelayDownstreamPending = map[string]time.Time{}
	}
	for _, id := range previous {
		s.RelayDownstreamPending[id] = now
	}
}

// Reconcile topology independently of telemetry so disabling a path or
// changing its listener does not keep a hint from a previous configuration.
func reconcileDownstream(s *shared.Server, topology downstreamTopology, now time.Time) bool {
	changed := false
	for key, record := range s.RelayDownstream {
		group, ok := topology.groups[key]
		if !ok || !downstreamEligible(*s) {
			if record.Down {
				markDownstreamPending(s, record.Previous, now)
			}
			delete(s.RelayDownstream, key)
			changed = true
			continue
		}
		if !slices.Equal(record.Previous, group.previous) {
			if record.Down {
				markDownstreamPending(s, record.Previous, now)
				markDownstreamPending(s, group.previous, now)
			}
			record.Previous = group.previous
			s.RelayDownstream[key] = record
			changed = true
		}
	}
	return changed
}

func recordDownstream(s *shared.Server, topology downstreamTopology, accepted map[relayPointKey]string, now time.Time) {
	reconcileDownstream(s, topology, now)
	if !downstreamEligible(*s) {
		return
	}
	for key, group := range topology.groups {
		record := s.RelayDownstream[key]
		if observeDownstream(&record, group, accepted, now) {
			markDownstreamPending(s, group.previous, now)
		}
		if record.EvidenceAt.IsZero() {
			continue
		}
		if !record.Down && record.DownRoundAt == nil && record.LastAllDownAt == nil && len(record.Changes) == 0 {
			delete(s.RelayDownstream, key)
			continue
		}
		record.Previous = group.previous
		if s.RelayDownstream == nil {
			s.RelayDownstream = map[string]shared.RelayDownstreamStatus{}
		}
		s.RelayDownstream[key] = record
	}
}

func (w routeWorld) assignRelayDownstream(rule *shared.ForwardRule, index downstreamTopology) {
	for i, t := range rule.Targets {
		s := w.servers[t.ServerID]
		if !downstreamEligible(s) {
			continue
		}
		hasMember, allDown := false, true
		for _, rt := range w.routes {
			if !rt.Enabled || !forwardBelongsToRoute(*rule, rt.ID) {
				continue
			}
			hasMember = true
			key := index.routes[downstreamRouteKey{rt.ID, t.ServerID}]
			allDown = allDown && s.RelayDownstream[key].Down
		}
		if hasMember && allDown {
			rule.Targets[i].Downstream = shared.RelayDown
		}
	}
}
