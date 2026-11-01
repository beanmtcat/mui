package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"mui/internal/forward"
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
	v.EdgeLatencies = nil
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

// routeServers lists the hop servers of a route in order: the entry first.
func routeServers(rt shared.Route) []string {
	ids := []string{rt.EntryServerID}
	for _, hop := range rt.Hops {
		ids = append(ids, hop.ServerIDs...)
	}
	return ids
}

// hopAddress is how a previous hop reaches a server: its internal address
// when asked to, otherwise its public IPv4, IPv6 or domain. A server opted
// into dynamic public IPs is reached by its domain first, so forwards follow
// its address through DNS. Others keep literal IPs: an existing domain may be
// a CDN or subscription name, and switching would rewrite every route.
func hopAddress(s shared.Server, internal bool) string {
	if internal {
		return s.InternalAddress
	}
	if s.AutoSyncPublicIP && s.Domain != "" {
		return s.Domain
	}
	for _, v := range []string{s.IPv4, s.IPv6, s.Domain} {
		if v != "" {
			return v
		}
	}
	return ""
}

// clientAddress is what a subscription hands to clients for an entry server.
func clientAddress(s shared.Server) string {
	for _, v := range []string{s.Domain, s.IPv4, s.IPv6} {
		if v != "" {
			return v
		}
	}
	return ""
}

// sourceAddresses keeps the original destination-family behavior for routes
// saved before SourceFamily existed.
func sourceAddresses(s shared.Server, internal bool, targets ...string) []string {
	return sourceAddressesFamily(s, internal, "", targets...)
}

// sourceAddressesFamily lists the sender IPs the next hop may admit. Explicit
// family selection is intersected with the destination family, because an
// IPv4 connection cannot arrive from an IPv6 source (and vice versa).
func sourceAddressesFamily(s shared.Server, internal bool, family string, targets ...string) []string {
	ipv4, ipv6 := len(targets) == 0, len(targets) == 0
	for _, target := range targets {
		ip := net.ParseIP(target)
		if ip == nil {
			ipv4, ipv6 = true, true
		} else if ip.To4() != nil {
			ipv4 = true
		} else {
			ipv6 = true
		}
	}
	if family == "ipv4" {
		ipv6 = false
	} else if family == "ipv6" {
		ipv4 = false
	}
	// A detected IPv4 can be a NAT egress: valid as a firewall source, never
	// as the destination chosen by hopAddress.
	candidates := []string{s.IPv4, s.IPv6, s.DetectedIPv4, s.DetectedIPv6}
	if internal {
		candidates = []string{s.InternalAddress}
	}
	var out []string
	for _, v := range candidates {
		if ip := net.ParseIP(v); ip != nil && (ip.To4() != nil && ipv4 || ip.To4() == nil && ipv6) && !slices.Contains(out, ip.String()) {
			out = append(out, ip.String())
		}
	}
	return out
}

func validRouteSourceMode(mode string) bool {
	return mode == "" || mode == "auto" || mode == "public" || mode == "internal"
}

func validRouteSourceFamily(family string) bool {
	return family == "" || family == "ipv4" || family == "ipv6" || family == "both"
}

func routeSourceInternal(destinationInternal bool, mode string) bool {
	switch mode {
	case "internal":
		return true
	case "public":
		return false
	default:
		return destinationInternal
	}
}

func validRoles(roles []string) ([]string, error) {
	var out []string
	for _, r := range roles {
		switch r {
		case shared.RoleEntry, shared.RoleLine, shared.RoleTransit, shared.RoleExit:
			if !slices.Contains(out, r) {
				out = append(out, r)
			}
		default:
			return nil, fmt.Errorf("服务器类型 %q 无效", r)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("请至少选择一种服务器类型")
	}
	sort.Strings(out)
	return out, nil
}

func validInternalAddress(v string) error {
	if v == "" {
		return nil
	}
	if err := shared.ValidateForwardTarget(shared.ForwardTarget{Host: v, Port: 1}); err != nil {
		return errors.New("内网地址必须是 IP 或域名")
	}
	return reachableAddress(v)
}

// reachableAddress refuses a literal address no forward may send to
// (loopback, link-local, multicast, unspecified, cloud metadata): the agent
// would reject the whole configuration of the server forwarding to it.
func reachableAddress(v string) error {
	if addr, err := netip.ParseAddr(v); err == nil && forward.ForbiddenTarget(addr) {
		return fmt.Errorf("地址 %s 是回环、链路本地、组播或云元数据地址，不能作为转发目标", v)
	}
	return nil
}

// checkRouteShape validates a route's servers, roles, addresses and node
// against the current data; checkRoutePort checks its port on every hop
// server, ignoring the route's own forwards.
func (w routeWorld) checkRouteShape(rt shared.Route) error {
	if strings.TrimSpace(rt.Name) == "" || len(rt.Name) > 100 {
		return errors.New("链路名称不能为空且不能超过 100 字符")
	}
	if len([]rune(rt.Notes)) > 200 {
		return errors.New("链路备注不能超过 200 字符")
	}
	if !validRouteSourceMode(rt.NodeSourceMode) {
		return errors.New("落地 UFW 来源地址模式无效")
	}
	if !validRouteSourceFamily(rt.NodeSourceFamily) {
		return errors.New("落地 UFW 来源地址族无效")
	}
	entry, ok := w.servers[rt.EntryServerID]
	if !ok {
		return errors.New("首跳服务器不存在")
	}
	if !shared.HasRole(entry, shared.RoleEntry) && !shared.HasRole(entry, shared.RoleLine) {
		return fmt.Errorf("首跳服务器 %s 不是入口或线路", entry.Name)
	}
	if clientAddress(entry) == "" {
		return fmt.Errorf("首跳服务器 %s 没有公网地址", entry.Name)
	}
	if len(rt.Hops) > 8 {
		return errors.New("链路最多 8 跳中转")
	}
	seen := map[string]bool{rt.EntryServerID: true}
	for i, hop := range rt.Hops {
		if !validRouteSourceMode(hop.SourceMode) {
			return fmt.Errorf("第 %d 跳的 UFW 来源地址模式无效", i+1)
		}
		if !validRouteSourceFamily(hop.SourceFamily) {
			return fmt.Errorf("第 %d 跳的 UFW 来源地址族无效", i+1)
		}
		if len(hop.ServerIDs) == 0 || len(hop.ServerIDs) > 16 {
			return fmt.Errorf("第 %d 跳需要 1–16 台服务器", i+1)
		}
		if hop.Balance != "failover" && hop.Balance != "round-robin" {
			return fmt.Errorf("第 %d 跳的负载均衡模式无效", i+1)
		}
		for id, mode := range hop.AddressModes {
			if !slices.Contains(hop.ServerIDs, id) || mode != "public" && mode != "internal" {
				return fmt.Errorf("第 %d 跳的服务器连接地址设置无效", i+1)
			}
		}
		for _, id := range hop.ServerIDs {
			s, ok := w.servers[id]
			if !ok {
				return fmt.Errorf("第 %d 跳的服务器不存在", i+1)
			}
			if !shared.HasRole(s, shared.RoleTransit) && !shared.HasRole(s, shared.RoleLine) {
				return fmt.Errorf("第 %d 跳的服务器 %s 不是中转或线路", i+1, s.Name)
			}
			if seen[id] {
				return fmt.Errorf("服务器 %s 在链路中出现了多次", s.Name)
			}
			seen[id] = true
			internal := hop.UsesInternal(id)
			if hopAddress(s, internal) == "" {
				if internal {
					return fmt.Errorf("服务器 %s 没有填写内网地址", s.Name)
				}
				return fmt.Errorf("服务器 %s 没有地址", s.Name)
			}
			if err := reachableAddress(hopAddress(s, internal)); err != nil {
				return fmt.Errorf("服务器 %s：%w", s.Name, err)
			}
		}
	}
	node, ok := w.nodes[rt.NodeID]
	if !ok || node.Deleting {
		return errors.New("落地节点不存在")
	}
	exit, ok := w.servers[node.ServerID]
	if !ok || !shared.CanHostNodes(exit) {
		return errors.New("落地节点必须位于在线中转、在线落地或外部节点服务器")
	}
	if seen[exit.ID] {
		return fmt.Errorf("落地服务器 %s 不能同时是本链路的一跳", exit.Name)
	}
	if hopAddress(exit, rt.NodeInternal) == "" {
		if rt.NodeInternal {
			return fmt.Errorf("落地服务器 %s 没有填写内网地址", exit.Name)
		}
		return fmt.Errorf("落地服务器 %s 没有地址", exit.Name)
	}
	if err := reachableAddress(hopAddress(exit, rt.NodeInternal)); err != nil {
		return fmt.Errorf("落地服务器 %s：%w", exit.Name, err)
	}
	// A UFW-managed receiver needs explicit sender IPs for its allowlist.
	// Manual receivers leave access control to the administrator.
	if !rt.Enabled {
		return nil
	}
	previous := []string{rt.EntryServerID}
	for _, hop := range rt.Hops {
		for _, id := range hop.ServerIDs {
			if !shared.ManualFirewall(w.servers[id].FirewallMode) {
				internal := hop.UsesInternal(id)
				if err := w.checkSources(previous, routeSourceInternal(internal, hop.SourceMode), hop.SourceFamily, hopAddress(w.servers[id], internal)); err != nil {
					return err
				}
			}
		}
		previous = hop.ServerIDs
	}
	if shared.ManualFirewall(exit.FirewallMode) {
		return nil
	}
	return w.checkSources(previous, routeSourceInternal(rt.NodeInternal, rt.NodeSourceMode), rt.NodeSourceFamily, hopAddress(exit, rt.NodeInternal))
}

func (w routeWorld) checkSources(group []string, internal bool, family string, targets ...string) error {
	for _, id := range group {
		if len(sourceAddressesFamily(w.servers[id], internal, family, targets...)) == 0 {
			kind := "公网 IP"
			if internal {
				kind = "内网 IP（不能只填域名）"
			}
			return fmt.Errorf("服务器 %s 缺少与所选来源及下一跳地址族匹配、可用于防火墙的%s", w.servers[id].Name, kind)
		}
	}
	return nil
}

func (w routeWorld) checkRoutePort(rt shared.Route) error {
	if rt.Port < 1024 || rt.Port > 65535 || rt.Port == shared.StatsAPIPort || rt.Port == shared.ConnectionsAPIPort {
		return errors.New("链路端口必须为 1024–65535，且不能是本机统计接口端口")
	}
	if !rt.Enabled {
		return nil // A disabled route has no listener; re-enabling checks the port.
	}
	for _, id := range routeServers(rt) {
		if err := w.portFree(rt, id); err != nil {
			return err
		}
	}
	return nil
}

// Two routes may use one listener from a middle hop onward only when their
// remaining paths and generated listener settings agree. Their entries always
// remain separate so client observations keep the right route identity.
func (w routeWorld) sameSharedHop(a, b shared.Route, serverID string) bool {
	if a.ID == b.ID || !a.Enabled || !b.Enabled || a.Port != b.Port ||
		a.NodeID != b.NodeID || a.NodeInternal != b.NodeInternal {
		return false
	}
	ai := slices.IndexFunc(a.Hops, func(h shared.RouteHop) bool { return slices.Contains(h.ServerIDs, serverID) })
	bi := slices.IndexFunc(b.Hops, func(h shared.RouteHop) bool { return slices.Contains(h.ServerIDs, serverID) })
	if ai < 0 || bi < 0 || len(a.Hops)-ai != len(b.Hops)-bi {
		return false // An entry cannot share, and the suffix lengths must agree.
	}
	for offset := range len(a.Hops) - ai {
		left, right := a.Hops[ai+offset], b.Hops[bi+offset]
		if !slices.Equal(left.ServerIDs, right.ServerIDs) || left.Balance != right.Balance {
			return false
		}
		for _, id := range left.ServerIDs {
			if left.UsesInternal(id) != right.UsesInternal(id) {
				return false
			}
		}
	}
	// Compare the actual listeners as well as the route shape. This catches
	// changes to target addresses, node ports and future runtime parameters.
	var left, right []shared.ForwardRule
	for _, f := range w.routeForwards(a) {
		if f.ServerID == serverID {
			left = append(left, f)
		}
	}
	for _, f := range w.routeForwards(b) {
		if f.ServerID == serverID {
			right = append(right, f)
		}
	}
	if len(left) == 0 || len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].Network != right[i].Network || left[i].Listen != right[i].Listen ||
			left[i].Port != right[i].Port || left[i].Balance != right[i].Balance ||
			left[i].HealthCheck != right[i].HealthCheck || !slices.Equal(left[i].Targets, right[i].Targets) {
			return false
		}
	}
	return true
}

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

// portFree rejects incompatible manual forwards, nodes and route listeners.
// Route forwards always use TCP; SS also needs UDP on the same port.
func (w routeWorld) portFree(rt shared.Route, serverID string) error {
	s := w.servers[serverID]
	if err := sshPortError(s, rt.Port, rt.Port); err != nil {
		return fmt.Errorf("服务器 %s: %w", s.Name, err)
	}
	for _, generated := range w.routeForwards(rt) {
		if generated.ServerID == serverID {
			if _, _, err := w.manualForwardFor(rt, generated); err != nil {
				return err
			}
		}
	}
	// Use the prospective routes and node, rather than stored forwards: a node
	// edit may change its target before syncRoutes regenerates those forwards.
	for _, other := range w.routes {
		if other.ID != rt.ID && other.Enabled && other.Port == rt.Port && slices.Contains(routeServers(other), serverID) {
			if !w.sameSharedHop(rt, other, serverID) {
				return fmt.Errorf("端口 %d 在服务器 %s 上已被链路“%s”占用；两条链路须从该中转到落地的路径完全相同才能共用监听", rt.Port, s.Name, other.Name)
			}
		}
	}
	for _, n := range w.nodes {
		if n.ServerID == serverID && n.Enabled && !n.Deleting {
			for _, listener := range shared.NodeListeners(n) {
				if listener.Port == rt.Port {
					return fmt.Errorf("端口 %d 在服务器 %s 上已被节点“%s”占用", rt.Port, s.Name, n.Name)
				}
			}
		}
	}
	return nil
}

// pickPort keeps one port across the whole route: the node's own port when it
// is available on every hop (including compatible shared listeners), otherwise
// a random available one.
func (w routeWorld) pickPort(rt shared.Route) (int, error) {
	try := func(port int) bool {
		rt.Port = port
		return w.checkRoutePort(rt) == nil
	}
	if port := w.nodes[rt.NodeID].Port; try(port) {
		return port, nil
	}
	for range 200 {
		if port := 50000 + rand.IntN(10001); try(port) {
			return port, nil
		}
	}
	return 0, errors.New("找不到在每一跳都空闲的端口")
}

// checkNodeRoutes checks the prospective route listeners before changing a node.
func (a *App) checkNodeRoutes(n shared.Node) error {
	world, err := a.loadRouteWorld()
	if err != nil {
		return err
	}
	before := world
	world.nodes = make(map[string]shared.Node, len(before.nodes))
	for id, node := range before.nodes {
		world.nodes[id] = node
	}
	world.nodes[n.ID] = n
	for _, rt := range world.routes {
		if rt.NodeID == n.ID && rt.Enabled {
			if err := world.checkRoutePort(rt); err != nil && before.checkRoutePort(rt) == nil {
				return fmt.Errorf("链路“%s”：%w", rt.Name, err)
			}
		}
	}
	// Existing route errors must not prevent a node edit that may repair them.
	// Runtime drift in an attached manual listener is isolated by syncRoutes.
	return nil
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
			if k > 0 {
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

func (a *App) routes(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		world, err := a.loadRouteWorld()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		_, _, routeErrors := world.desiredRouteForwards()
		for i := range world.routes {
			world.routes[i].Status = routeStatus(world.routes[i], world.forwards)
			if reason := routeErrors[world.routes[i].ID]; reason != "" {
				world.routes[i].Status, world.routes[i].Error = "error", reason
			}
			world.routes[i].EdgeLatencies = routeEdgeLatencies(world.routes[i], world, time.Now())
			if (world.routes[i].Status == "active" || world.routes[i].Status == "exported") && !offlineRouteReady(world.routes[i], world.servers) {
				world.routes[i].Status = "pending"
			}
			if world.routes[i].Status == "active" || world.routes[i].Status == "exported" {
				allowed, err := a.routeExitAccessLive(world.routes[i], world)
				if err != nil {
					errorJSON(w, 500, err.Error())
					return
				}
				if !allowed || world.checkRouteShape(world.routes[i]) != nil {
					world.routes[i].Status = "pending"
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
	if err = a.Store.PutRoute(in); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if err = a.syncRoutes(); err != nil {
		errorJSON(w, 500, err.Error())
		return
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
