package server

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"mui/internal/forward"
	"mui/internal/shared"
)

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
	if rt.EntryFirewallPolicy != "" && rt.EntryFirewallPolicy != "all" && rt.EntryFirewallPolicy != "restricted" {
		return errors.New("入口放行模式无效")
	}
	if _, _, err := shared.NormalizeAdminFirewallAccess(rt.EntryFirewallPolicy, rt.EntryFirewallSources); err != nil {
		return fmt.Errorf("入口放行来源：%w", err)
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

// Two routes may use one middle-hop listener when that server's outbound
// settings, its selected public/private address and the path after its group
// agree. The current group's other members, order and balance only affect
// the previous hop, not this listener.
// Entries remain separate so client observations keep the right route identity.
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
	if a.Hops[ai].UsesInternal(serverID) != b.Hops[bi].UsesInternal(serverID) {
		return false
	}
	for offset := 1; offset < len(a.Hops)-ai; offset++ {
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
				return fmt.Errorf("端口 %d 在服务器 %s 上已被链路“%s”占用；该中转的连接地址、转发目标和后续路径相同时才能共用监听", rt.Port, s.Name, other.Name)
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
