package server

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"mui/internal/shared"
)

// A route is entry → hop groups → exit node. The panel turns it into one
// forward per hop server (two when the node also needs UDP), all listening on
// the route's port. Compatible routes may share a middle-hop listener. Each
// hop after the first, and the exit node unless it allows direct use, admits
// only the addresses of the hop before.

func (s *Store) Routes() ([]shared.Route, error) {
	return queryJSON[shared.Route](s.DB, `SELECT data FROM mui_routes ORDER BY id`)
}

func (s *Store) PutRoute(v shared.Route) error {
	v.Status = ""
	v.Error = ""
	v.CycleTraffic = nil
	v.EnforcementCapability = ""
	v.EnforcementNote = ""
	v.EdgeLatencies = nil
	v.RelayEdges = nil
	_, err := s.DB.Exec(`INSERT INTO mui_routes(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, v.ID, Marshal(v))
	return err
}

// routeWorld is everything route checks and generation look at, loaded once.
type routeWorld struct {
	servers  map[string]shared.Server
	nodes    map[string]shared.Node
	forwards []shared.ForwardRule
	routes   []shared.Route
}

func (a *App) loadRouteWorld() (routeWorld, error) {
	w := routeWorld{servers: map[string]shared.Server{}, nodes: map[string]shared.Node{}}
	servers, err := a.Store.Servers()
	if err != nil {
		return w, err
	}
	for _, s := range servers {
		w.servers[s.ID] = s
	}
	nodes, err := a.Store.Nodes("")
	if err != nil {
		return w, err
	}
	for _, n := range nodes {
		w.nodes[n.ID] = n
	}
	if w.forwards, err = a.Store.Forwards(""); err != nil {
		return w, err
	}
	w.routes, err = a.Store.Routes()
	return w, err
}

func (a *App) routes(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		world, err := a.loadRouteWorld()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		overrides, err := a.Store.relayOverrides()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		now := time.Now()
		downstream := world.downstreamHints(now, true)
		_, _, routeErrors := world.desiredRouteForwards()
		routeCycleMap, err := a.Store.RouteCycleTrafficMap(world.routes, world.servers, now)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		for i := range world.routes {
			rt := &world.routes[i]
			rt.Status = routeStatus(*rt, world.forwards)
			if reason := routeErrors[rt.ID]; reason != "" {
				rt.Status, rt.Error = "error", reason
			}
			rt.EdgeLatencies = routeEdgeLatencies(*rt, world, now)
			rt.RelayEdges = routeRelayEdges(*rt, world, overrides, now, downstream)
			if (rt.Status == "active" || rt.Status == "exported") && !offlineRouteReady(*rt, world.servers) {
				rt.Status = "pending"
			}
			if rt.Status == "active" || rt.Status == "exported" {
				allowed, err := a.routeExitAccessLive(*rt, world)
				if err != nil {
					errorJSON(w, 500, err.Error())
					return
				}
				if !allowed || world.checkRouteShape(*rt) != nil {
					rt.Status = "pending"
				}
			}
			entrySrv := world.servers[rt.EntryServerID]
			rt.EnforcementCapability, rt.EnforcementNote = RouteEnforcementInfo(*rt, entrySrv)
			if ct, ok := routeCycleMap[rt.ID]; ok {
				ctCopy := ct
				rt.CycleTraffic = &ctCopy
			}
			// Auto-paused & upgrade-required states take precedence over "active"
			// while preserving admin manual disable ("disabled"), "error", and "pending".
			if rt.Enabled && rt.Status != "error" && rt.Status != "pending" {
				if rt.EnforcementCapability == "upgrade_required" && (shared.RouteHasTrafficLimit(*rt) || (entrySrv.TrafficProtectionEnabled && entrySrv.TrafficLimit > 0)) {
					rt.Status = "upgrade_required"
				} else if rt.CycleTraffic != nil && rt.CycleTraffic.AutoPaused {
					if rt.CycleTraffic.PauseReason == "entry_protection" {
						rt.Status = "entry_protected"
					} else {
						rt.Status = "quota_exceeded"
					}
				}
			}
		}
		paginateList(w, r, world.routes, func(rt shared.Route) string { return rt.ID })
		return
	}
	var in shared.Route
	if !readJSON(w, r, &in) {
		return
	}
	in.ID = ID()
	a.saveRoute(w, r, in, nil)
}

func (a *App) routeByID(w http.ResponseWriter, r *http.Request) {
	world, err := a.loadRouteWorld()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	idx := slices.IndexFunc(world.routes, func(rt shared.Route) bool { return rt.ID == r.PathValue("id") })
	if idx < 0 {
		errorJSON(w, 404, "链路不存在")
		return
	}
	old := world.routes[idx]
	if r.Method == http.MethodDelete {
		subs, err := a.Store.Subscriptions()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		for _, sub := range subs {
			if slices.Contains(sub.RouteIDs, old.ID) {
				errorJSON(w, 409, "链路被订阅“"+sub.Name+"”使用，请先从订阅中移除")
				return
			}
		}
		if _, err = a.Store.DB.Exec(`DELETE FROM mui_routes WHERE id=$1`, old.ID); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		_ = a.Store.DeleteRouteTrafficData(old.ID)
		if err = a.syncRoutes(); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.auditRequest(r, "route.delete", old.ID, old.Name)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	var in shared.Route
	if !readJSON(w, r, &in) {
		return
	}
	in.ID = old.ID
	a.saveRoute(w, r, in, &old)
}

func (a *App) saveRoute(w http.ResponseWriter, r *http.Request, in shared.Route, old *shared.Route) {
	world, err := a.loadRouteWorld()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Status = ""
	if err = validateRouteTrafficFields(&in, old, time.Now()); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if in.EntryFirewallPolicy == "restricted" {
		_, in.EntryFirewallSources, err = shared.NormalizeAdminFirewallAccess(in.EntryFirewallPolicy, in.EntryFirewallSources)
		if err != nil {
			errorJSON(w, 400, "入口放行来源："+err.Error())
			return
		}
	}
	if in.Hops == nil {
		in.Hops = []shared.RouteHop{}
	}
	for i := range in.Hops {
		if in.Hops[i].Balance == "" {
			in.Hops[i].Balance = "failover"
		}
	}
	if err = world.checkRouteShape(in); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if in.Port == 0 {
		if old != nil && old.NodeID == in.NodeID {
			in.Port = old.Port // Keep the port clients already use.
		}
		if in.Port == 0 || world.checkRoutePort(in) != nil {
			if in.Port, err = world.pickPort(in); err != nil {
				errorJSON(w, 409, err.Error())
				return
			}
		}
	}
	if err = world.checkRoutePort(in); err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	if old != nil && old.NodeID != in.NodeID {
		// Subscriptions that use the route move their login to the new node.
		subs, err := a.Store.Subscriptions()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		for _, sub := range subs {
			if !slices.Contains(sub.RouteIDs, in.ID) {
				continue
			}
			if err := validateSubscriptionNode(sub.Format, world.nodes[in.NodeID]); err != nil {
				errorJSON(w, 400, "链路被订阅“"+sub.Name+"”使用："+err.Error())
				return
			}
		}
	}
	// Validate only this route's part of the prospective plan. An unrelated
	// broken route must not block edits or new routes elsewhere.
	prospective := world
	prospective.routes = slices.Clone(world.routes)
	if old == nil {
		prospective.routes = append(prospective.routes, in)
	} else {
		idx := slices.IndexFunc(prospective.routes, func(rt shared.Route) bool { return rt.ID == in.ID })
		prospective.routes[idx] = in
	}
	_, _, routeErrors := prospective.desiredRouteForwards()
	if reason := routeErrors[in.ID]; reason != "" {
		errorJSON(w, 409, reason)
		return
	}
	overrides, err := a.Store.relayOverrides()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if world.blockedByRelayOverrides(in, overrides, time.Now()) {
		errorJSON(w, 400, "链路含有现在或覆盖到期后无可用目标的跳。请先调整手动中转状态。")
		return
	}
	if err = a.Store.PutRoute(in); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if err = a.syncRoutes(); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if old != nil && routeTrafficConfigChanged(*old, in) {
		if err = a.queueApply(in.EntryServerID, "forwards.apply"); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	if old != nil && old.NodeID != in.NodeID {
		if err = a.queueSubscriptionApply([]string{old.NodeID, in.NodeID}); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	if old == nil {
		a.auditRequest(r, "route.create", in.ID, in.Name)
		writeJSON(w, 201, in)
		return
	}
	a.auditRequest(r, "route.update", in.ID, in.Name)
	writeJSON(w, 200, in)
}

// routesUsing names the routes that involve a server (as a hop or through its
// node) or a node, for refusing deletions that would break them.
func routesUsing(routes []shared.Route, nodes map[string]shared.Node, serverID, nodeID string) []string {
	var names []string
	for _, rt := range routes {
		uses := rt.NodeID == nodeID && nodeID != ""
		if serverID != "" {
			uses = uses || slices.Contains(routeServers(rt), serverID) || nodes[rt.NodeID].ServerID == serverID
		}
		if uses {
			names = append(names, "“"+rt.Name+"”")
		}
	}
	return names
}

// subscriptionNodeIDs is every node a subscription needs a login on: its
// direct nodes and the exit nodes of its routes.
func subscriptionNodeIDs(sub shared.Subscription, routes []shared.Route) []string {
	ids := append([]string(nil), sub.NodeIDs...)
	for _, rt := range routes {
		if slices.Contains(sub.RouteIDs, rt.ID) && !slices.Contains(ids, rt.NodeID) {
			ids = append(ids, rt.NodeID)
		}
	}
	return ids
}
