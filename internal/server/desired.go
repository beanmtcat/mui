package server

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"mui/internal/shared"
)

func (a *App) desired(serverID string) (shared.DesiredState, error) {
	server, err := a.Store.Server(serverID)
	if err != nil {
		return shared.DesiredState{}, err
	}
	nodes, err := a.Store.Nodes(serverID)
	if err != nil {
		return shared.DesiredState{}, err
	}
	state := shared.DesiredState{OutboundInterface: server.OutboundInterface, FirewallMode: server.FirewallMode, Revision: server.Revision, ProtocolVersion: 1, Nodes: []shared.ManagedNode{}, Rules: []shared.FirewallRule{}, Forwards: []shared.ForwardRule{}}
	if server.AgentProxySupport || server.AgentProxyNodeID != "" {
		state.AgentProxy, err = a.agentProxy(server)
		if err != nil {
			return state, err
		}
	}
	subscriptions, err := a.Store.Subscriptions()
	if err != nil {
		return state, err
	}
	routes, err := a.Store.Routes()
	if err != nil {
		return state, err
	}
	subNodes := make([][]string, len(subscriptions))
	for i, sub := range subscriptions {
		subNodes[i] = subscriptionNodeIDs(sub, routes)
	}
	proxyWorld := routeWorld{servers: map[string]shared.Server{}, nodes: map[string]shared.Node{}}
	if slices.ContainsFunc(nodes, func(n shared.Node) bool { return n.Protocol == "socks5" }) {
		servers, err := a.Store.Servers()
		if err != nil {
			return state, err
		}
		for _, s := range servers {
			proxyWorld.servers[s.ID] = s
		}
		for _, n := range nodes {
			proxyWorld.nodes[n.ID] = n
		}
	}
	for _, n := range nodes {
		if n.Deleting {
			continue
		}
		// Compute from current assignments even before syncRoutes persists its
		// display cache. Closing client direct access must never queue a job
		// that temporarily removes existing Agents' access.
		n.AgentProxySources = proxyWorld.nodeAgentProxySources(n.ID)
		n.FirewallPolicy, n.FirewallSources = effectiveNodeAccess(n)
		// This is panel-only metadata. Older installed Agents need only the
		// normalized firewall sources, so signed jobs introduce no new field.
		n.AgentProxySources = ""
		if shared.ManualFirewall(server.FirewallMode) {
			n.FirewallPolicy, n.FirewallSources = "manual", ""
		}
		n.FirewallPolicy, n.FirewallSources, err = shared.NormalizeFirewallAccess(n.FirewallPolicy, n.FirewallSources)
		if err != nil {
			return state, fmt.Errorf("节点 %s 防火墙来源: %w", n.Name, err)
		}
		password, err := a.Store.NodeSecret(n.ID)
		if err != nil {
			return state, err
		}
		shadowPassword, err := a.Store.NodeShadowTLSSecret(n.ID)
		if err != nil {
			return state, err
		}
		item := shared.ManagedNode{Node: n, Password: password, ShadowTLSPassword: shadowPassword}
		if n.Enabled && n.OutboundMode == "socks5" {
			if item.Upstream, err = a.nodeUpstream(n); err != nil {
				return state, fmt.Errorf("节点 %s: %w", n.Name, err)
			}
		}
		if n.Protocol == "ss" && shared.SSMultiUser(n.Method) && !n.SingleUser {
			item.Users = append(item.Users, a.Store.SubscriptionUser(n, "direct"))
		}
		for i, sub := range subscriptions {
			if !sub.Enabled || sub.ExpiresAt != nil && time.Now().After(*sub.ExpiresAt) || shared.SharedSubscriptionPassword(n) {
				continue
			}
			if slices.Contains(subNodes[i], n.ID) {
				item.Users = append(item.Users, a.Store.SubscriptionUser(n, sub.ID))
			}
		}
		if n.CertificateID != "" {
			c, e := a.Store.Certificate(n.CertificateID)
			if e != nil {
				return state, e
			}
			key, e := a.Store.CertificateKey(c.ID)
			if e != nil {
				return state, e
			}
			item.CertificatePEM = c.PEM
			item.CertificateKey = key
		}
		state.Nodes = append(state.Nodes, item)
	}
	rules, err := a.Store.Rules(serverID)
	if err != nil {
		return state, err
	}
	for _, rule := range rules {
		if !rule.Deleting {
			state.Rules = append(state.Rules, rule)
		}
	}
	forwards, err := a.Store.Forwards(serverID)
	if err != nil {
		return state, err
	}
	for _, forward := range forwards {
		// Client observation is decided per job from the current routes, never
		// stored: a stored flag would rewrite every route forward (and bump every
		// hop's revision, including offline exports) when the panel upgrades.
		forward.ObserveClients, forward.ClientNodeID = false, ""
		for _, rt := range routes {
			if rt.ID == forward.RouteID && rt.EntryServerID == serverID {
				forward.ObserveClients, forward.ClientNodeID = true, rt.NodeID
				break
			}
		}
		// A reused manual listener is a route listener only in the desired
		// state. Its stored RouteID stays empty so it can be restored unchanged
		// after the last route is removed. The Agent uses this transient owner
		// for priority UFW rules and TCP latency probes.
		if forward.RouteID == "" && len(forward.RouteIDs) > 0 {
			forward.RouteID = forward.RouteIDs[0]
		}
		// RouteIDs and the manual baseline stay on the panel, not the Agent.
		forward.RouteIDs = nil
		forward.ManualBasePolicy, forward.ManualBaseSources = "", ""
		forward.ManualBaseTargets = nil
		if !forward.Deleting {
			if shared.ManualFirewall(server.FirewallMode) {
				forward.FirewallPolicy, forward.FirewallSources = "manual", ""
			}
			forward.FirewallPolicy, forward.FirewallSources, err = shared.NormalizeFirewallAccess(forward.FirewallPolicy, forward.FirewallSources)
			if err != nil {
				return state, fmt.Errorf("转发 %s 防火墙来源: %w", forward.Name, err)
			}
			state.Forwards = append(state.Forwards, forward)
		}
	}
	// Every queued configuration carries the panel's signature so the agent
	// can verify it came from the panel. Signing failure fails the queueing.
	return a.signDesiredState(state)
}

// queueApply snapshots the desired state of a server into a job for its agent.
// Only configuration jobs advance the revision: it identifies a configuration,
// and "ufw.init" does not change one. It takes the server's lock;
// queueApplyLocked is the same logic for callers that already hold it
// (agentReport), since Go mutexes are not reentrant. agentJob never holds
// the server lock: ClaimJob is atomic via compare-and-swap.
func (a *App) queueApply(serverID, kind string) error {
	unlock := a.lockServer(serverID)
	defer unlock()
	return a.queueApplyLocked(serverID, kind)
}

func (a *App) queueApplyLocked(serverID, kind string) error {
	server, err := a.Store.Server(serverID)
	if err != nil {
		return err
	}
	if shared.ExternalManaged(server) {
		return errors.New("外部节点服务器不执行配置任务")
	}
	if shared.ManualFirewall(server.FirewallMode) && strings.HasPrefix(kind, "ufw.") {
		return errors.New("手动管理模式不允许通过面板操作 UFW")
	}
	apply := strings.HasSuffix(kind, ".apply")
	if shared.OfflineManaged(server) {
		if !apply {
			return errors.New("离线服务器不执行在线任务，请导出配置并在目标机应用")
		}
		if err := a.Store.SupersedeQueuedApply(serverID); err != nil {
			return err
		}
		server.Revision++
		return a.Store.PutServer(server)
	}
	if kind == "forwards.apply" && !server.ForwardSupport {
		// This agent cannot act on forwards, and nothing else changed. The rule
		// stays pending; the first report from a capable agent queues a full
		// apply. Everything else on the server keeps flowing as usual.
		return nil
	}
	if apply {
		if err := a.Store.SupersedeQueuedApply(serverID); err != nil {
			return err
		}
		server.Revision++
		if err = a.Store.PutServer(server); err != nil {
			return err
		}
	}
	state, err := a.desired(serverID)
	if err != nil {
		return err
	}
	now := time.Now()
	op := shared.Operation{ID: ID(), ServerID: serverID, Kind: kind, Status: "queued", Revision: server.Revision, CreatedAt: now, UpdatedAt: now}
	if apply {
		op.Deployed = a.deployment(server, state)
	}
	return a.Store.PutOperation(op, state)
}

// nodeFingerprint covers everything a client configuration depends on. Two
// equal fingerprints mean a client built from the panel's current data can
// connect to what the server is running.
func (a *App) nodeFingerprint(server shared.Server, n shared.Node, password, shadowPassword string) string {
	scheme := "users"
	if n.Protocol == "snell" && n.ShadowTLSHost != "" && server.ShadowTLSAuth {
		scheme = "shadowtls"
	}
	fields := []string{n.Protocol, strconv.Itoa(n.Port), n.Method, n.Obfs, n.ShadowTLSHost, n.TLSName, password, shadowPassword, scheme}
	if n.SingleUser {
		fields = append(fields, "single-user")
	}
	if n.Protocol == "socks5" {
		fields = append(fields, n.Username)
	}
	if n.Protocol == "snell" && shared.SnellVersion(n) == 6 {
		fields = append(fields, "snell-v6")
	}
	if iface := shared.EffectiveOutboundInterface(n, server.OutboundInterface); iface != "" {
		fields = append(fields, "bind-interface", iface)
	}
	return a.Store.Fingerprint(fields...)
}

func (a *App) deployment(server shared.Server, state shared.DesiredState) map[string]shared.NodeDeployment {
	out := map[string]shared.NodeDeployment{}
	for _, item := range state.Nodes {
		if !item.Node.Enabled {
			continue
		}
		subs := make([]string, 0, len(item.Users))
		for _, user := range item.Users {
			subs = append(subs, user.SubscriptionID)
		}
		out[item.Node.ID] = shared.NodeDeployment{Fingerprint: a.nodeFingerprint(server, item.Node, item.Password, item.ShadowTLSPassword), Subscriptions: subs, FirewallPolicy: item.Node.FirewallPolicy, FirewallSources: item.Node.FirewallSources}
	}
	return out
}

type appliedServerState struct {
	nodes map[string]shared.NodeDeployment
	known bool
}

type livenessCache struct {
	app          *App
	world        routeWorld
	routeErrors  map[string]string
	applied      map[string]appliedServerState
	fingerprints map[string]string
}

func (a *App) newLivenessCache(world routeWorld) *livenessCache {
	_, _, routeErrors := world.desiredRouteForwards()
	return &livenessCache{
		app:          a,
		world:        world,
		routeErrors:  routeErrors,
		applied:      map[string]appliedServerState{},
		fingerprints: map[string]string{},
	}
}

func (c *livenessCache) appliedDeployment(serverID string) (map[string]shared.NodeDeployment, bool, error) {
	if state, ok := c.applied[serverID]; ok {
		return state.nodes, state.known, nil
	}
	nodes, known, err := c.app.Store.AppliedDeployment(serverID)
	if err != nil {
		return nil, false, err
	}
	c.applied[serverID] = appliedServerState{nodes: nodes, known: known}
	return nodes, known, nil
}

func (c *livenessCache) nodeLive(n shared.Node, server shared.Server, subscriptionID string) (bool, error) {
	if !n.Enabled || n.Deleting {
		return false, nil
	}
	if shared.ExternalManaged(server) {
		return true, nil
	}
	sharedPassword := shared.SharedSubscriptionPassword(n)
	if sharedPassword {
		subscriptionID = ""
	}
	if subscriptionID != "" && !server.MultiUserStats {
		return false, nil
	}
	applied, known, err := c.appliedDeployment(server.ID)
	if err != nil {
		return false, err
	}
	if !known {
		return n.Status == "active" && (server.MultiUserStats || sharedPassword) && server.AppliedRevision >= server.Revision, nil
	}
	deployed, ok := applied[n.ID]
	if !ok {
		return false, nil
	}
	// An active node has not been edited since its server last confirmed an
	// apply; only a pending Snell scheme transition can change its fingerprint
	// while status remains active.
	if n.Status != "active" || (n.Protocol == "snell" && n.ShadowTLSHost != "" && server.AppliedRevision < server.Revision) {
		fp, cached := c.fingerprints[n.ID]
		if !cached {
			password, err := c.app.Store.NodeSecret(n.ID)
			if err != nil {
				return false, err
			}
			shadowPassword, err := c.app.Store.NodeShadowTLSSecret(n.ID)
			if err != nil {
				return false, err
			}
			fp = c.app.nodeFingerprint(server, n, password, shadowPassword)
			c.fingerprints[n.ID] = fp
		}
		if deployed.Fingerprint != fp {
			return false, nil
		}
	}
	if subscriptionID == "" {
		return true, nil
	}
	for _, id := range deployed.Subscriptions {
		if id == subscriptionID {
			return true, nil
		}
	}
	return false, nil
}

// nodeLive reports whether a node, as the panel currently describes it, is what
// its server is running, with a login for the given subscription ("" for none).
// It looks at this node only: an unapplied change elsewhere on the server, or a
// server that is offline, does not make a working node unavailable.
func (a *App) nodeLive(n shared.Node, server shared.Server, subscriptionID string) (bool, error) {
	if !n.Enabled || n.Deleting {
		return false, nil
	}
	if shared.ExternalManaged(server) {
		// Seller-provided endpoints have no Agent acknowledgement. Enabled
		// means the administrator wants to publish the supplied credentials.
		return true, nil
	}
	sharedPassword := shared.SharedSubscriptionPassword(n)
	if sharedPassword {
		// There is no additional subscription login to install for this node.
		// Its deployed node fingerprint still has to match below.
		subscriptionID = ""
	}
	if subscriptionID != "" && !server.MultiUserStats {
		return false, nil
	}
	applied, known, err := a.Store.AppliedDeployment(server.ID)
	if err != nil {
		return false, err
	}
	if !known {
		// No apply has completed since deployments were first recorded; fall
		// back to the server-wide revision check used before.
		return n.Status == "active" && (server.MultiUserStats || sharedPassword) && server.AppliedRevision >= server.Revision, nil
	}
	deployed, ok := applied[n.ID]
	if !ok {
		return false, nil
	}
	password, err := a.Store.NodeSecret(n.ID)
	if err != nil {
		return false, err
	}
	shadowPassword, err := a.Store.NodeShadowTLSSecret(n.ID)
	if err != nil {
		return false, err
	}
	if deployed.Fingerprint != a.nodeFingerprint(server, n, password, shadowPassword) {
		return false, nil
	}
	if subscriptionID == "" {
		return true, nil
	}
	for _, id := range deployed.Subscriptions {
		if id == subscriptionID {
			return true, nil
		}
	}
	return false, nil
}
