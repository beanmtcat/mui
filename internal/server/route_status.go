package server

import (
	"net/netip"
	"slices"
	"strings"

	"mui/internal/shared"
)

// effectiveNodeAccess is the firewall a node really gets: a node without
// direct client access admits its routes' last hops and assigned Agent sources.
func effectiveNodeAccess(n shared.Node) (string, string) {
	automatic := strings.Trim(strings.Join([]string{n.RouteSources, n.AgentProxySources}, ","), ",")
	switch {
	case !n.Direct:
		if automatic == "" {
			return "closed", ""
		}
		return "restricted", automatic
	case n.FirewallPolicy == "manual":
		return n.FirewallPolicy, n.FirewallSources
	case n.FirewallPolicy == "restricted" && automatic != "":
		return "restricted", n.FirewallSources + "," + automatic
	}
	return n.FirewallPolicy, n.FirewallSources
}

// routeStatus summarises a route's forwards for the list view.
func routeStatus(rt shared.Route, forwards []shared.ForwardRule) string {
	if !rt.Enabled {
		return "disabled"
	}
	status := "active"
	hasOfflineExport := false
	for _, f := range forwards {
		if f.Deleting || !forwardBelongsToRoute(f, rt.ID) {
			continue
		}
		switch f.Status {
		case "error":
			return "error"
		case "active":
		case "exported":
			hasOfflineExport = true
		default:
			status = "pending"
		}
	}
	if status == "active" && hasOfflineExport {
		return "exported"
	}
	return status
}

// routeExitAccessLive checks the firewall the exit actually applied. Checking
// only the node login is insufficient when adding a new entry to an existing node.
func (a *App) routeExitAccessLive(rt shared.Route, world routeWorld) (bool, error) {
	node := world.nodes[rt.NodeID]
	if shared.ExternalManaged(world.servers[node.ServerID]) {
		return true, nil // The seller controls the exit firewall.
	}
	applied, known, err := a.Store.AppliedDeployment(node.ServerID)
	if err != nil || !known {
		return false, err
	}
	access, ok := applied[node.ID]
	if !ok {
		return false, nil
	}
	switch access.FirewallPolicy {
	case "all", "manual":
		return true, nil
	case "restricted":
	default:
		return false, nil
	}
	last := []string{rt.EntryServerID}
	if len(rt.Hops) > 0 {
		last = rt.Hops[len(rt.Hops)-1].ServerIDs
	}
	if err := world.checkSources(last, routeSourceInternal(rt.NodeInternal, rt.NodeSourceMode), rt.NodeSourceFamily, hopAddress(world.servers[node.ServerID], rt.NodeInternal)); err != nil {
		return false, nil
	}
	for _, source := range world.groupSources(last, routeSourceInternal(rt.NodeInternal, rt.NodeSourceMode), rt.NodeSourceFamily, hopAddress(world.servers[node.ServerID], rt.NodeInternal)) {
		addr, err := netip.ParseAddr(source)
		if err != nil {
			return false, nil
		}
		allowed := false
		for _, cidr := range strings.Split(access.FirewallSources, ",") {
			if ip, e := netip.ParseAddr(cidr); e == nil && ip.Unmap() == addr.Unmap() {
				allowed = true
				break
			}
			if prefix, e := netip.ParsePrefix(cidr); e == nil && prefix.Contains(addr.Unmap()) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false, nil
		}
	}
	return true, nil
}

// Offline hops are eligible after exporting the desired config. This does
// not verify whether the administrator applied it on the isolated host.
// Every offline member needs its current config exported, including backups:
// local application and connectivity remain the administrator's responsibility.
func offlineRouteReady(rt shared.Route, servers map[string]shared.Server) bool {
	for _, id := range routeServers(rt) {
		s := servers[id]
		if shared.OfflineManaged(s) && (s.OfflineExportedAt == nil || s.OfflineExportedRevision != s.Revision) {
			return false
		}
	}
	return true
}

func (a *App) routeLive(rt shared.Route, w routeWorld, subscriptionID string) (bool, error) {
	if !rt.Enabled || w.checkRouteShape(rt) != nil || !offlineRouteReady(rt, w.servers) {
		return false, nil
	}
	_, _, routeErrors := w.desiredRouteForwards()
	if routeErrors[rt.ID] != "" {
		return false, nil
	}
	node := w.nodes[rt.NodeID]
	live, err := a.nodeLive(node, w.servers[node.ServerID], subscriptionID)
	if err != nil || !live {
		return false, err
	}
	if allowed, err := a.routeExitAccessLive(rt, w); err != nil || !allowed {
		return false, err
	}
	active := map[string]bool{}
	for _, f := range w.forwards {
		if forwardBelongsToRoute(f, rt.ID) && shared.ForwardNetworkIncludes(f.Network, "tcp") && (f.Status == "active" || (shared.OfflineManaged(w.servers[f.ServerID]) && f.Status == "exported")) && !f.Deleting {
			active[f.ServerID] = true
		}
	}
	if !active[rt.EntryServerID] {
		return false, nil
	}
	for _, hop := range rt.Hops {
		if !slices.ContainsFunc(hop.ServerIDs, func(id string) bool { return active[id] }) {
			return false, nil
		}
	}
	return true, nil
}
