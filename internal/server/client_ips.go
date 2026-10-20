package server

import (
	"mui/internal/shared"
	"net"
	"strings"
	"time"
)

func sourceContains(sources, ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, s := range strings.FieldsFunc(sources, func(c rune) bool { return c == ',' || c == ';' || c == ' ' || c == '\n' }) {
		if other := net.ParseIP(s); other != nil && other.Equal(addr) {
			return true
		}
		if _, prefix, err := net.ParseCIDR(s); err == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func classifyConnection(item *shared.ConnectionIP, w routeWorld) {
	if item.SourceKind == "entry" {
		item.ClientIP = item.IP
		return
	}
	item.PeerIP = item.IP
	n, exists := w.nodes[item.NodeID]
	item.SourceKind = "unknown"
	if !exists {
		return
	}
	if sourceContains(w.nodeAgentProxySources(n.ID), item.IP) {
		item.SourceKind = "agent"
		return
	}
	if sourceContains(n.RouteSources, item.IP) {
		item.SourceKind = "relay"
		return
	}
	for _, s := range w.servers {
		if sourceContains(strings.Join([]string{s.IPv4, s.IPv6, s.DetectedIPv4, s.DetectedIPv6, s.InternalAddress}, ","), item.IP) {
			item.SourceKind = "relay"
			return
		}
	}
	// A node reached through routes can also be used directly. Its peer alone
	// does not prove which path was taken (NAT may change a relay's address).
	for _, rt := range w.routes {
		if rt.NodeID == n.ID {
			return
		}
	}
	if n.Direct {
		item.SourceKind = "direct"
		item.ClientIP = item.IP
	}
}

func (a *App) saveForwardConnectionIPs(serverID string, points []shared.ForwardConnectionPoint) error {
	w, err := a.loadRouteWorld()
	if err != nil {
		return err
	}
	forwards, err := a.Store.Forwards(serverID)
	if err != nil {
		return err
	}
	allowed := map[string]shared.ForwardRule{}
	for _, f := range forwards {
		if f.Enabled && !f.Deleting {
			allowed[f.ID] = f
		}
	}
	now := time.Now()
	tx, err := a.Store.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO mui_entry_connection_ips(server_id,route_id,node_id,ip,at_ms,first_seen_ms) VALUES($1,$2,$3,$4,$5,$5) ON CONFLICT(server_id,route_id,node_id,ip) DO UPDATE SET at_ms=CASE WHEN excluded.at_ms>mui_entry_connection_ips.at_ms THEN excluded.at_ms ELSE mui_entry_connection_ips.at_ms END`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i, p := range points {
		if i >= 500 {
			break
		}
		f, ok := allowed[p.ForwardID]
		if !ok || f.RouteID != p.RouteID {
			continue
		}
		var route *shared.Route
		for i := range w.routes {
			if w.routes[i].ID == p.RouteID {
				route = &w.routes[i]
				break
			}
		}
		if route == nil || !route.Enabled || route.EntryServerID != serverID || route.NodeID != p.NodeID {
			continue
		}
		ip := net.ParseIP(p.IP)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || p.At.IsZero() || now.Sub(p.At) > 5*time.Minute || p.At.Sub(now) > time.Minute {
			continue
		}
		if _, err = stmt.Exec(serverID, p.RouteID, p.NodeID, ip.String(), p.At.UnixMilli()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
