package server

import (
	"time"

	"mui/internal/shared"
)

const routeLatencyFreshness = 2 * time.Minute

// Only retain measurements for TCP targets currently assigned to this Agent.
// Reports can arrive while a route is being edited, so stale target details
// must not be displayed as measurements of the new path.
func validRouteLatencies(points []shared.RouteLatency, forwards []shared.ForwardRule, now time.Time) []shared.RouteLatency {
	allowed := make(map[string]map[shared.ForwardTarget]bool)
	for _, rule := range forwards {
		if rule.RouteID == "" || rule.Network != "tcp" || !rule.Enabled || rule.Deleting {
			continue
		}
		for _, target := range rule.Targets {
			if allowed[rule.ID] == nil {
				allowed[rule.ID] = make(map[shared.ForwardTarget]bool)
			}
			allowed[rule.ID][target] = true
		}
	}
	var result []shared.RouteLatency
	for _, point := range points {
		if !allowed[point.ForwardID][shared.ForwardTarget{Host: point.Host, Port: point.Port}] ||
			point.At.After(now.Add(time.Minute)) || now.Sub(point.At) > routeLatencyFreshness ||
			point.TCPMs < 0 || point.TCPMs > 3500 {
			continue
		}
		result = append(result, point)
	}
	return result
}

func routeEdgeLatencies(rt shared.Route, world routeWorld, now time.Time) []shared.RouteEdgeLatency {
	if !rt.Enabled {
		return nil
	}
	node, ok := world.nodes[rt.NodeID]
	if !ok {
		return nil
	}
	groups := [][]string{{rt.EntryServerID}}
	for _, hop := range rt.Hops {
		groups = append(groups, hop.ServerIDs)
	}
	var edges []shared.RouteEdgeLatency
	for k, group := range groups {
		toIDs := []string{node.ServerID}
		port, internal := node.Port, rt.NodeInternal
		if k < len(rt.Hops) {
			toIDs = rt.Hops[k].ServerIDs
			port, internal = rt.Port, rt.Hops[k].Internal
		}
		for _, fromID := range group {
			from := world.servers[fromID]
			forwardID := routeForwardID(rt.ID, fromID, "tcp")
			for _, toID := range toIDs {
				to, ok := world.servers[toID]
				if !ok {
					continue
				}
				host := hopAddress(to, internal)
				for _, point := range from.RouteLatencies {
					if point.ForwardID == forwardID && point.Host == host && point.Port == port &&
						!point.At.After(now.Add(time.Minute)) && now.Sub(point.At) <= routeLatencyFreshness {
						edges = append(edges, shared.RouteEdgeLatency{FromServerID: fromID, ToServerID: toID, TCPMs: point.TCPMs, OK: point.OK, At: point.At})
						break
					}
				}
			}
		}
	}
	return edges
}
