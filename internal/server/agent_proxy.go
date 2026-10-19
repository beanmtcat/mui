package server

import (
	"errors"
	"fmt"
	"net"
	"slices"

	"mui/internal/shared"
)

func checkSOCKSFirewall(s shared.Server, n shared.Node) error {
	if n.Protocol != "socks5" {
		return nil
	}
	if shared.ManualFirewall(s.FirewallMode) || s.UFWStatus != "active" || s.FirewallConflict != "" {
		return errors.New("SOCKS5 所在服务器必须使用 UFW 托管且已启用防火墙；请先在服务器列表安全初始化 UFW")
	}
	if n.FirewallPolicy == "manual" {
		return errors.New("SOCKS5 节点不能选择手动管理端口规则")
	}
	return nil
}

func (a *App) proxyUsers(nodeID string) ([]shared.Server, error) {
	servers, err := a.Store.Servers()
	if err != nil {
		return nil, err
	}
	var users []shared.Server
	for _, s := range servers {
		if s.AgentProxyNodeID == nodeID || s.AgentProxyPreviousNodeID == nodeID {
			users = append(users, s)
		}
	}
	return users, nil
}

// Resolve secrets only when building a signed job or an administrator's install
// command. Server list documents contain only the node ID and address choice.
func (a *App) agentProxy(s shared.Server) (*shared.SOCKS5Proxy, error) {
	p := &shared.SOCKS5Proxy{}
	if s.AgentProxyNodeID == "" {
		return p, nil
	}
	n, err := a.Store.Node(s.AgentProxyNodeID)
	if err != nil {
		return nil, errors.New("Agent SOCKS5 节点不存在")
	}
	host, err := a.Store.Server(n.ServerID)
	if err != nil {
		return nil, err
	}
	if n.Protocol != "socks5" || n.Deleting || !n.Enabled || !n.Direct || n.ServerID == s.ID {
		return nil, errors.New("Agent 代理须选择其他服务器上已启用、允许直连的 SOCKS5 节点")
	}
	if err := checkSOCKSFirewall(host, n); err != nil {
		return nil, err
	}
	p.Host = shared.PublishedAddress(shared.SubscriptionItem{Node: n, Server: host})
	if s.AgentProxyInternal {
		p.Host = host.InternalAddress
	}
	p.Port, p.Username = n.Port, n.Username
	p.Password, err = a.Store.NodeSecret(n.ID)
	if err != nil {
		return nil, err
	}
	if err := shared.ValidateAgentProxy(p); err != nil {
		return nil, fmt.Errorf("Agent 代理地址或凭据无效: %w", err)
	}
	if ip := net.ParseIP(p.Host); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return nil, errors.New("Agent 代理地址不能是回环或未指定地址")
	}
	return p, nil
}

func (a *App) validateAgentProxySelection(s shared.Server) error {
	if s.AgentProxyNodeID == "" {
		return nil
	}
	if shared.OfflineManaged(s) || !shared.HasRole(s, shared.RoleEntry) {
		return errors.New("仅在线管理的入口服务器可以设置 Agent SOCKS5 代理")
	}
	if s.AgentVersion != "" && !s.AgentProxySupport {
		return errors.New("请先将入口 Agent 升级至 0.6.10，再设置 SOCKS5 代理")
	}
	if _, err := a.agentProxy(s); err != nil {
		return err
	}
	n, _ := a.Store.Node(s.AgentProxyNodeID)
	if n.Status != "active" {
		return errors.New("请等待 SOCKS5 节点成功应用配置后再选择")
	}
	// A control-plane proxy cycle cannot bootstrap and would strand all members.
	seen := map[string]bool{s.ID: true}
	next := n.ServerID
	for next != "" {
		if seen[next] {
			return errors.New("Agent 代理不能形成循环依赖")
		}
		seen[next] = true
		server, err := a.Store.Server(next)
		if err != nil {
			return err
		}
		if server.AgentProxyNodeID == "" {
			break
		}
		node, err := a.Store.Node(server.AgentProxyNodeID)
		if err != nil {
			return err
		}
		next = node.ServerID
	}
	return nil
}

func (a *App) protectProxyNode(old, n shared.Node, password string, deleting bool) error {
	users, err := a.proxyUsers(old.ID)
	if err != nil || len(users) == 0 {
		return err
	}
	secret, err := a.Store.NodeSecret(old.ID)
	if err != nil {
		return err
	}
	if !deleting && old.Protocol == n.Protocol && old.Port == n.Port && old.Listen == n.Listen && old.PublishAddress == n.PublishAddress && old.Username == n.Username && old.Direct == n.Direct && old.Enabled == n.Enabled && old.FirewallPolicy == n.FirewallPolicy && old.FirewallSources == n.FirewallSources && (password == "" || password == secret) {
		return nil
	}
	names := []string{}
	for _, s := range users {
		names = append(names, s.Name)
	}
	return fmt.Errorf("该 SOCKS5 正供入口 %v 的 Agent 联网；请先为这些入口切换代理并等待配置应用，再修改连接参数、停用或删除", names)
}

func (a *App) protectProxyHost(old, changed shared.Server, deleting bool) error {
	nodes, err := a.Store.Nodes(old.ID)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		users, err := a.proxyUsers(n.ID)
		if err != nil {
			return err
		}
		if len(users) == 0 {
			continue
		}
		if deleting || old.IPv4 != changed.IPv4 || old.IPv6 != changed.IPv6 || old.Domain != changed.Domain || old.InternalAddress != changed.InternalAddress {
			return errors.New("服务器上的 SOCKS5 正供入口 Agent 联网；请先切换入口代理并等待应用，再删除服务器或修改地址")
		}
	}
	if shared.ManualFirewall(changed.FirewallMode) {
		if slices.ContainsFunc(nodes, func(n shared.Node) bool { return n.Protocol == "socks5" && !n.Deleting }) {
			return errors.New("服务器配置了 SOCKS5 节点，必须保持 UFW 托管")
		}
	}
	return nil
}
