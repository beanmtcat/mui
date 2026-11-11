package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"slices"
	"sort"
	"strings"

	"mui/internal/shared"
)

func forwardBelongsToRoute(f shared.ForwardRule, routeID string) bool {
	return f.RouteID == routeID && routeID != "" || slices.Contains(f.RouteIDs, routeID)
}

func (w routeWorld) manualForwardListenCompatible(rt shared.Route, manual shared.ForwardRule) bool {
	hopIndex := slices.IndexFunc(rt.Hops, func(h shared.RouteHop) bool { return slices.Contains(h.ServerIDs, manual.ServerID) })
	if hopIndex < 0 {
		return false // An entry always needs its own listener.
	}
	address := hopAddress(w.servers[manual.ServerID], rt.Hops[hopIndex].UsesInternal(manual.ServerID))
	addressIP := net.ParseIP(address)
	return manual.Listen == "::" || manual.Listen == address || manual.Listen == "0.0.0.0" && addressIP != nil && addressIP.To4() != nil
}

// A first attachment must match the current manual rule exactly. Existing
// members follow the route target, so target drift is checked as a group in
// desiredRouteForwards rather than preventing the whole plan from being built.
func (w routeWorld) manualForwardMatches(rt shared.Route, generated, manual shared.ForwardRule) bool {
	if manual.RouteID != "" || !manual.Enabled || manual.Deleting || manual.ServerID != generated.ServerID ||
		manual.Port != generated.Port || !shared.ForwardNetworkIncludes(manual.Network, generated.Network) ||
		!slices.Equal(manual.Targets, generated.Targets) {
		return false
	}
	if !w.manualForwardListenCompatible(rt, manual) {
		return false
	}
	if len(generated.Targets) > 1 && (manual.Balance != generated.Balance || manual.HealthCheck != generated.HealthCheck) {
		return false
	}
	return true
}

func (w routeWorld) manualForwardFor(rt shared.Route, generated shared.ForwardRule) (shared.ForwardRule, bool, error) {
	for _, manual := range w.forwards {
		if manual.RouteID != "" || !manual.Enabled || manual.Deleting || manual.ServerID != generated.ServerID ||
			manual.Port != generated.Port || !shared.ForwardNetworkIncludes(manual.Network, generated.Network) {
			continue
		}
		if !slices.Contains(manual.RouteIDs, rt.ID) && !w.manualForwardMatches(rt, generated, manual) {
			return shared.ForwardRule{}, false, fmt.Errorf("端口 %d 在服务器 %s 上的转发“%s”无法复用：需是中转，且协议、监听地址和转发目标与链路一致",
				generated.Port, w.servers[generated.ServerID].Name, manual.Name)
		}
		return manual, true, nil
	}
	return shared.ForwardRule{}, false, nil
}

func routeForwardID(routeID, serverID, network string) string {
	digest := sha256.Sum256([]byte(routeID + "\x00" + serverID + "\x00" + network))
	return hex.EncodeToString(digest[:16])
}

// routeForwards generates the forwards one route needs, keyed by ID.
func (w routeWorld) routeForwards(rt shared.Route) []shared.ForwardRule {
	node := w.nodes[rt.NodeID]
	exit := w.servers[node.ServerID]
	networks := []string{"tcp"}
	if node.Protocol == "ss" {
		networks = append(networks, "udp")
	}
	groups := [][]string{{rt.EntryServerID}}
	for _, hop := range rt.Hops {
		groups = append(groups, hop.ServerIDs)
	}
	var out []shared.ForwardRule
	for k, group := range groups {
		var targets []shared.ForwardTarget
		balance := ""
		if k+1 < len(groups) {
			next := rt.Hops[k]
			balance = next.Balance
			for _, id := range next.ServerIDs {
				targets = append(targets, shared.ForwardTarget{Host: hopAddress(w.servers[id], next.UsesInternal(id)), Port: rt.Port})
			}
		} else {
			targets = []shared.ForwardTarget{{Host: hopAddress(exit, rt.NodeInternal), Port: node.Port}}
		}
		for _, id := range group {
			policy, sources := "all", ""
			if k == 0 && rt.EntryFirewallPolicy == "restricted" {
				policy, sources = "restricted", rt.EntryFirewallSources
			} else if k > 0 {
				incoming := rt.Hops[k-1]
				selectedInternal := incoming.UsesInternal(id)
				internal := routeSourceInternal(selectedInternal, incoming.SourceMode)
				// This rule admits traffic into this hop. The address of its
				// outbound target may use a different family.
				destination := hopAddress(w.servers[id], selectedInternal)
				policy = "closed"
				if list := w.groupSources(groups[k-1], internal, incoming.SourceFamily, destination); len(list) > 0 && w.checkSources(groups[k-1], internal, incoming.SourceFamily, destination) == nil {
					policy, sources = "restricted", strings.Join(list, ",")
				}
			}
			if shared.ManualFirewall(w.servers[id].FirewallMode) {
				policy, sources = "manual", ""
			}
			for _, network := range networks {
				out = append(out, shared.ForwardRule{
					ID: routeForwardID(rt.ID, id, network), ServerID: id, Name: rt.Name, Network: network,
					Listen: "::", Port: rt.Port, Targets: targets, Balance: balance, HealthCheck: "tcp", RouteID: rt.ID,
					FirewallPolicy: policy, FirewallSources: sources, Enabled: rt.Enabled, Status: "pending",
				})
			}
		}
	}
	return out
}

type routeListenerKey struct {
	serverID string
	port     int
	network  string
}

func mergeRouteFirewall(dst *shared.ForwardRule, other shared.ForwardRule) {
	if dst.FirewallPolicy == "manual" || other.FirewallPolicy == "manual" {
		dst.FirewallPolicy, dst.FirewallSources = "manual", ""
		return
	}
	var sources []string
	for _, raw := range []string{dst.FirewallSources, other.FirewallSources} {
		for _, source := range strings.Split(raw, ",") {
			if source != "" && !slices.Contains(sources, source) {
				sources = append(sources, source)
			}
		}
	}
	if len(sources) == 0 {
		dst.FirewallPolicy, dst.FirewallSources = "closed", ""
		return
	}
	sort.Strings(sources)
	dst.FirewallPolicy, dst.FirewallSources = "restricted", strings.Join(sources, ",")
}

// Merge matching middle-hop listeners, including paths that meet partway
// through. Entries remain separate; every shared hop admits the union of its
// members' previous-hop sources. Routes are ID-ordered, so the first enabled
// member keeps its established forward ID.
func (w routeWorld) desiredRouteForwards() ([]shared.ForwardRule, map[string]shared.ForwardRule, map[string]string) {
	var desired []shared.ForwardRule
	manualDesired := map[string]shared.ForwardRule{}
	routeErrors := map[string]string{}
	manualTargets := map[string][]shared.ForwardTarget{}
	manualProblems := map[string]string{}
	for _, f := range w.forwards {
		if f.RouteID == "" && (f.ManualBasePolicy != "" || len(f.RouteIDs) > 0) {
			if f.ManualBaseTargets == nil {
				f.ManualBaseTargets = slices.Clone(f.Targets) // Existing attachments from older panel builds.
			}
			f.FirewallPolicy, f.FirewallSources = f.ManualBasePolicy, f.ManualBaseSources
			f.RouteIDs = nil
			manualDesired[f.ID] = f // Restore the original rule if no route still uses it.
		}
	}
	index := map[routeListenerKey]int{}
	owners := map[routeListenerKey]shared.Route{}
	badGenerated := map[routeListenerKey]string{}
	for _, rt := range w.routes {
		if _, ok := w.nodes[rt.NodeID]; !ok {
			continue
		}
		for _, f := range w.routeForwards(rt) {
			if rt.Enabled {
				manual, found, err := w.manualForwardFor(rt, f)
				if err != nil {
					routeErrors[rt.ID] = err.Error()
					continue
				}
				if found {
					current, ok := manualDesired[manual.ID]
					if !ok {
						current = manual
					}
					if current.ManualBasePolicy == "" {
						current.ManualBasePolicy, current.ManualBaseSources = manual.FirewallPolicy, manual.FirewallSources
						current.ManualBaseTargets = slices.Clone(manual.Targets)
					}
					if !slices.Contains(current.RouteIDs, rt.ID) {
						current.RouteIDs = append(current.RouteIDs, rt.ID)
					}
					if !w.manualForwardListenCompatible(rt, manual) {
						manualProblems[manual.ID] = fmt.Sprintf("转发“%s”的监听地址与服务器当前地址不兼容；请修改或删除关联链路", manual.Name)
					}
					if target, seen := manualTargets[manual.ID]; seen {
						if !slices.Equal(target, f.Targets) {
							manualProblems[manual.ID] = fmt.Sprintf("转发“%s”的关联链路目标不一致；请修改或删除关联链路", manual.Name)
						}
					} else {
						manualTargets[manual.ID] = slices.Clone(f.Targets)
					}
					current.Targets = slices.Clone(f.Targets)
					if current.ManualBasePolicy != "all" {
						mergeRouteFirewall(&current, f)
					}
					manualDesired[manual.ID] = current
					continue
				}
				key := routeListenerKey{f.ServerID, f.Port, f.Network}
				if position, found := index[key]; found {
					if !w.sameSharedHop(rt, owners[key], f.ServerID) {
						message := fmt.Sprintf("服务器 %s 的端口 %d 被不兼容的链路共用；请修改或删除关联链路", w.servers[f.ServerID].Name, f.Port)
						routeErrors[rt.ID], routeErrors[owners[key].ID] = message, message
						badGenerated[key] = message
						continue
					}
					shared := &desired[position]
					if len(shared.RouteIDs) == 0 {
						shared.RouteIDs = []string{shared.RouteID}
					}
					shared.RouteIDs = append(shared.RouteIDs, rt.ID)
					mergeRouteFirewall(shared, f)
					continue
				}
				index[key], owners[key] = len(desired), rt
			}
			desired = append(desired, f)
		}
	}
	// A generated listener can also exceed the firewall source limit after
	// several routes merge. Keep its last usable rule, while the rest of the
	// deployment proceeds. Do not canonicalize valid sources here: that would
	// rewrite old forwards on an otherwise unchanged panel upgrade.
	usable := desired[:0]
	for _, f := range desired {
		if !f.Enabled {
			usable = append(usable, f)
			continue
		}
		key := routeListenerKey{f.ServerID, f.Port, f.Network}
		problem := badGenerated[key]
		if problem == "" && f.FirewallPolicy == "restricted" {
			if _, _, err := shared.NormalizeFirewallAccess(f.FirewallPolicy, f.FirewallSources); err != nil {
				problem = fmt.Sprintf("服务器 %s 的链路转发来源无效：%v；请修改或删除关联链路", w.servers[f.ServerID].Name, err)
			}
		}
		if problem == "" {
			usable = append(usable, f)
			continue
		}
		members := f.RouteIDs
		if len(members) == 0 {
			members = []string{f.RouteID}
		}
		for _, routeID := range members {
			routeErrors[routeID] = problem
		}
		for _, old := range w.forwards {
			if old.ID == f.ID && !old.Deleting {
				if old.FirewallPolicy == "restricted" {
					if _, _, err := shared.NormalizeFirewallAccess(old.FirewallPolicy, old.FirewallSources); err != nil {
						break
					}
				}
				usable = append(usable, old)
				break
			}
		}
	}
	desired = usable
	for id, f := range manualDesired {
		if len(f.RouteIDs) == 0 {
			f.Targets = slices.Clone(f.ManualBaseTargets)
			f.ManualBasePolicy, f.ManualBaseSources, f.ManualBaseTargets = "", "", nil
		} else if f.FirewallPolicy == "restricted" {
			var err error
			f.FirewallPolicy, f.FirewallSources, err = shared.NormalizeFirewallAccess(f.FirewallPolicy, f.FirewallSources)
			if err != nil {
				manualProblems[id] = fmt.Sprintf("转发“%s”的共用来源无效：%v；请修改或删除关联链路", f.Name, err)
			}
		}
		if problem := manualProblems[id]; problem != "" {
			for _, routeID := range f.RouteIDs {
				routeErrors[routeID] = problem
			}
			// Keep the last valid runtime rule. A bad member must not rewrite
			// its target or firewall, or block unrelated route deployments.
			for _, old := range w.forwards {
				if old.ID == id {
					f = old
					break
				}
			}
		}
		manualDesired[id] = f
	}
	return desired, manualDesired, routeErrors
}

func (w routeWorld) groupSources(group []string, internal bool, family string, targets ...string) []string {
	var out []string
	for _, id := range group {
		for _, ip := range sourceAddressesFamily(w.servers[id], internal, family, targets...) {
			if !slices.Contains(out, ip) {
				out = append(out, ip)
			}
		}
	}
	return out
}

// nodeRouteSources lists the addresses the last hops of enabled routes reach
// a node from.
func (w routeWorld) nodeRouteSources(nodeID string) string {
	var out []string
	for _, rt := range w.routes {
		if rt.NodeID != nodeID || !rt.Enabled {
			continue
		}
		last := []string{rt.EntryServerID}
		if len(rt.Hops) > 0 {
			last = rt.Hops[len(rt.Hops)-1].ServerIDs
		}
		for _, ip := range w.groupSources(last, routeSourceInternal(rt.NodeInternal, rt.NodeSourceMode), rt.NodeSourceFamily, hopAddress(w.servers[w.nodes[nodeID].ServerID], rt.NodeInternal)) {
			if !slices.Contains(out, ip) {
				out = append(out, ip)
			}
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func sameRouteForward(a, b shared.ForwardRule) bool {
	return a.ServerID == b.ServerID && a.Name == b.Name && a.Network == b.Network && a.Listen == b.Listen && a.Port == b.Port && a.Balance == b.Balance && a.HealthCheck == b.HealthCheck &&
		slices.Equal(a.Targets, b.Targets) && a.FirewallPolicy == b.FirewallPolicy && a.FirewallSources == b.FirewallSources &&
		slices.Equal(a.RouteIDs, b.RouteIDs) && a.Enabled == b.Enabled && !b.Deleting
}

// syncRoutes makes the stored route forwards and the exit nodes' route sources
// match the routes, and queues an apply on every server whose part changed.
// Every change to routes, servers or nodes calls it; it is cheap when nothing
// changed.
func (a *App) syncRoutes() error {
	w, err := a.loadRouteWorld()
	if err != nil {
		return err
	}
	existing := map[string]shared.ForwardRule{}
	for _, f := range w.forwards {
		if f.RouteID != "" {
			existing[f.ID] = f
		}
	}
	queue := map[string]string{}
	desired, manualDesired, routeErrors := w.desiredRouteForwards()
	for routeID, reason := range routeErrors {
		log.Printf("sync routes: route %s: %s", routeID, reason)
	}
	for id, next := range manualDesired {
		old, err := a.Store.Forward(id)
		if err != nil {
			return err
		}
		if slices.Equal(old.RouteIDs, next.RouteIDs) && slices.Equal(old.Targets, next.Targets) && slices.Equal(old.ManualBaseTargets, next.ManualBaseTargets) &&
			old.FirewallPolicy == next.FirewallPolicy && old.FirewallSources == next.FirewallSources &&
			old.ManualBasePolicy == next.ManualBasePolicy && old.ManualBaseSources == next.ManualBaseSources {
			continue
		}
		// Route membership changes the transient RouteID sent to the Agent,
		// even when the firewall was already open to all sources.
		next.Status = "pending"
		queue[next.ServerID] = "forwards.apply"
		if err := a.Store.PutForward(next); err != nil {
			return err
		}
	}
	for _, f := range desired {
		old, ok := existing[f.ID]
		delete(existing, f.ID)
		if ok && sameRouteForward(f, old) {
			continue
		}
		if err = a.Store.PutForward(f); err != nil {
			return err
		}
		queue[f.ServerID] = "forwards.apply"
	}
	for _, old := range existing {
		if old.Deleting {
			continue
		}
		old.Deleting, old.Status = true, "pending"
		if err = a.Store.PutForward(old); err != nil {
			return err
		}
		queue[old.ServerID] = "forwards.apply"
	}
	for _, n := range w.nodes {
		sources, proxySources := w.nodeRouteSources(n.ID), w.nodeAgentProxySources(n.ID)
		if sources != n.RouteSources || proxySources != n.AgentProxySources {
			n.RouteSources, n.AgentProxySources = sources, proxySources
			password, err := a.Store.NodeSecret(n.ID)
			if err != nil {
				return err
			}
			if err = a.Store.PutNode(n, password); err != nil {
				return err
			}
			if !shared.ExternalManaged(w.servers[n.ServerID]) {
				queue[n.ServerID] = "nodes.apply"
			}
		}
	}
	for id, kind := range queue {
		if err = a.queueApply(id, kind); err != nil {
			return err
		}
	}
	return nil
}

// syncRoutesInBackground runs syncRoutes outside a request, under the same
// lock as administrator changes.
func (a *App) syncRoutesInBackground() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.syncRoutes(); err != nil {
		log.Printf("sync routes: %v", err)
	}
}
