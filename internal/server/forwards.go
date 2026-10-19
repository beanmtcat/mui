package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"mui/internal/forward"
	"mui/internal/shared"
)

func (a *App) forwards(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		list, err := a.Store.Forwards(r.URL.Query().Get("serverId"))
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		paginateList(w, r, list, func(f shared.ForwardRule) string { return f.ID })
		return
	}
	var in shared.ForwardRule
	if !readJSON(w, r, &in) {
		return
	}
	server, err := a.Store.Server(in.ServerID)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	in.ID = ID()
	in.RouteID = ""
	in.Deleting = false
	in.Status = "pending"
	if err := normalizeForward(&in); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if shared.ManualFirewall(server.FirewallMode) {
		in.FirewallPolicy, in.FirewallSources = "manual", ""
	}
	if err := a.checkForward(in, server); err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	if err := a.Store.PutForward(in); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if err := a.queueForwardApply(in.ServerID); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("forward.create", in.ID, in.Name)
	writeJSON(w, 201, in)
}

func (a *App) forwardByID(w http.ResponseWriter, r *http.Request) {
	old, err := a.Store.Forward(r.PathValue("id"))
	if err != nil {
		errorJSON(w, 404, "转发不存在")
		return
	}
	if old.RouteID != "" {
		errorJSON(w, 409, "该转发由链路生成，请在链路中修改或删除")
		return
	}
	if r.Method == http.MethodDelete {
		old.Deleting = true
		old.Status = "pending"
		if err := a.Store.PutForward(old); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		if err := a.queueForwardApply(old.ServerID); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.Store.Audit("forward.delete", old.ID, old.Name)
		writeJSON(w, 202, map[string]bool{"queued": true})
		return
	}
	if old.Deleting {
		errorJSON(w, 409, "转发正在删除，无法编辑")
		return
	}
	var in shared.ForwardRule
	if !readJSON(w, r, &in) {
		return
	}
	server, err := a.Store.Server(old.ServerID)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	in.ID, in.ServerID, in.RouteID = old.ID, old.ServerID, ""
	in.Deleting, in.Status, in.Error = false, "pending", ""
	if err := normalizeForward(&in); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if shared.ManualFirewall(server.FirewallMode) {
		in.FirewallPolicy, in.FirewallSources = "manual", ""
	}
	if err := a.checkForward(in, server); err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	if err := a.Store.PutForward(in); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if err := a.queueForwardApply(in.ServerID); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("forward.update", in.ID, in.Name)
	writeJSON(w, 200, in)
}

func normalizeForward(f *shared.ForwardRule) error {
	f.Name = strings.TrimSpace(f.Name)
	for i := range f.Targets {
		f.Targets[i].Host = strings.TrimSpace(f.Targets[i].Host)
	}
	if f.Balance == "" {
		f.Balance = "failover"
	}
	f.Uplink, f.Downlink = 0, 0
	if f.Listen == "" {
		f.Listen = "0.0.0.0"
	}
	policy, sources, err := shared.NormalizeAdminFirewallAccess(f.FirewallPolicy, f.FirewallSources)
	if err != nil {
		return err
	}
	f.FirewallPolicy, f.FirewallSources = policy, sources
	return shared.ValidateForward(*f)
}

func (a *App) queueForwardApply(serverID string) error {
	return a.queueApply(serverID, "forwards.apply")
}

func (a *App) checkForward(f shared.ForwardRule, server shared.Server) error {
	if shared.ForwardNetworkIncludes(f.Network, "tcp") {
		if err := sshPortError(server, f.Port, f.Port); err != nil {
			return err
		}
	}
	for _, t := range f.Targets {
		if sameLocalTarget(f, t) || t.Port == f.Port && (strings.EqualFold(t.Host, server.Domain) && server.Domain != "" || t.Host == server.IPv4 && server.IPv4 != "" || t.Host == server.IPv6 && server.IPv6 != "") {
			return errors.New("目标地址不能指向转发自身")
		}
		if err := checkForwardTargetNotLocal(t, server); err != nil {
			return err
		}
	}
	forwards, err := a.Store.Forwards(f.ServerID)
	if err != nil {
		return err
	}
	for _, other := range forwards {
		if !other.Enabled || other.Deleting || other.ID == f.ID || !shared.ForwardNetworksOverlap(other.Network, f.Network) {
			continue
		}
		if other.Port == f.Port && listenOverlap(other.Listen, f.Listen) {
			return errors.New("监听端口已被另一条转发占用")
		}
	}
	nodes, err := a.Store.Nodes(f.ServerID)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		if !node.Enabled || node.Deleting {
			continue
		}
		for _, listener := range shared.NodeListeners(node) {
			if listener.Port == f.Port && shared.ForwardNetworkIncludes(f.Network, listener.Network) && listenOverlap(listener.Listen, f.Listen) {
				return errors.New("监听端口已被节点占用（含 Snell 内层端口）")
			}
		}
	}
	return nil
}

// checkForwardTargetNotLocal resolves the target and refuses it when it is
// the server itself (by any name that resolves to the server's addresses) or
// loopback. A literal comparison alone is defeated by a DNS alias/CNAME that
// points at the server, or by 127.0.0.1/::1 spellings. Resolution failure
// rejects the rule (fail-closed) rather than letting an unchecked target
// through.
func checkForwardTargetNotLocal(t shared.ForwardTarget, server shared.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	targetIPs, err := (&net.Resolver{}).LookupIP(ctx, "ip", t.Host)
	if err != nil || len(targetIPs) == 0 {
		// The panel's resolver is not the relay's: a split-horizon name or a
		// DDNS name that is briefly down resolves there later. The agent
		// re-applies these address rules to whatever it resolves at run time.
		return nil
	}
	own := map[string]bool{}
	for _, raw := range []string{server.IPv4, server.IPv6} {
		if ip := net.ParseIP(raw); ip != nil {
			own[ip.String()] = true
		}
	}
	if server.Domain != "" {
		if resolved, err := (&net.Resolver{}).LookupIP(ctx, "ip", server.Domain); err == nil {
			for _, ip := range resolved {
				own[ip.String()] = true
			}
		}
	}
	for _, ip := range targetIPs {
		if ip.IsLoopback() {
			return errors.New("转发目标不能是回环地址")
		}
		if ip.IsUnspecified() {
			return errors.New("转发目标不能是未指定地址")
		}
		if addr, ok := netip.AddrFromSlice(ip); ok && forward.ForbiddenTarget(addr) {
			return errors.New("转发目标不能是链路本地、组播或云元数据地址")
		}
		if own[ip.String()] {
			return errors.New("目标地址不能指向转发自身")
		}
	}
	return nil
}

func listenOverlap(a, b string) bool {
	return a == b || a == "" || b == "" || a == "0.0.0.0" || b == "0.0.0.0" || a == "::" || b == "::"
}

func sameLocalTarget(f shared.ForwardRule, t shared.ForwardTarget) bool {
	if t.Port != f.Port {
		return false
	}
	target := net.ParseIP(t.Host)
	if target == nil {
		if !strings.EqualFold(t.Host, "localhost") {
			return false
		}
		listen := net.ParseIP(f.Listen)
		return listen != nil && (listen.IsUnspecified() || listen.IsLoopback())
	}
	listen := net.ParseIP(f.Listen)
	return listen != nil && (listen.Equal(target) || listen.IsUnspecified() && (target.IsLoopback() || target.IsUnspecified()))
}

func (a *App) checkNodeForwardPort(n shared.Node) error {
	forwards, err := a.Store.Forwards(n.ServerID)
	if err != nil {
		return err
	}
	for _, forward := range forwards {
		if !forward.Enabled || forward.Deleting {
			continue
		}
		for _, listener := range shared.NodeListeners(n) {
			if listener.Port == forward.Port && shared.ForwardNetworkIncludes(forward.Network, listener.Network) && listenOverlap(forward.Listen, listener.Listen) {
				return errors.New("端口已被转发规则占用（含 Snell 内层端口）")
			}
		}
	}
	return nil
}
