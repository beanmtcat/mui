package server

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"mui/internal/shared"
)

// A managed node may send its traffic out through a seller's SOCKS5 node:
// clients connect to our node, and the seller's address is what they reach
// the Internet from. Only external SOCKS5 nodes qualify; our own SOCKS5
// nodes would also need source whitelists for the egress server.
func (a *App) checkNodeUpstream(server shared.Server, n *shared.Node) error {
	if n.OutboundMode != "socks5" {
		n.OutboundNodeID = ""
		return nil
	}
	if shared.NoAgentManaged(server) {
		return errors.New("SOCKS5 出口只能用于在线 Agent 管理的服务器")
	}
	if n.Enabled && server.AgentVersion != "" && !server.NodeSOCKSOutbound {
		return errors.New("请先将该服务器的 Agent 升级至 0.6.26，再设置 SOCKS5 出口")
	}
	_, err := a.nodeUpstream(*n)
	return err
}

// nodeUpstream resolves a node's SOCKS5 egress to the address and login the
// Agent dials, from the external node's current details.
func (a *App) nodeUpstream(n shared.Node) (*shared.SOCKS5Proxy, error) {
	up, err := a.Store.Node(n.OutboundNodeID)
	if err != nil {
		return nil, errors.New("出口 SOCKS5 节点不存在")
	}
	host, err := a.Store.Server(up.ServerID)
	if err != nil {
		return nil, err
	}
	if up.Protocol != "socks5" || !shared.ExternalManaged(host) {
		return nil, errors.New("出口须选择外部服务器上的 SOCKS5 节点")
	}
	if up.Deleting || !up.Enabled {
		return nil, fmt.Errorf("出口 SOCKS5 节点“%s”已停用", up.Name)
	}
	p := &shared.SOCKS5Proxy{Host: shared.PublishedAddress(shared.SubscriptionItem{Node: up, Server: host}), Port: up.Port, Username: up.Username}
	if p.Password, err = a.Store.NodeSecret(up.ID); err != nil {
		return nil, err
	}
	if p.Host == "" {
		return nil, fmt.Errorf("出口 SOCKS5 节点“%s”没有连接地址", up.Name)
	}
	if err := shared.ValidateAgentProxy(p); err != nil {
		return nil, fmt.Errorf("出口 SOCKS5 节点“%s”的地址或凭据无效: %w", up.Name, err)
	}
	if ip := net.ParseIP(p.Host); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return nil, errors.New("出口 SOCKS5 地址不能是回环或未指定地址")
	}
	return p, nil
}

// upstreamUsers lists the nodes sending their traffic through one of ids.
func (a *App) upstreamUsers(ids ...string) ([]shared.Node, error) {
	nodes, err := a.Store.Nodes("")
	if err != nil {
		return nil, err
	}
	var users []shared.Node
	for _, n := range nodes {
		if !n.Deleting && n.OutboundMode == "socks5" && n.OutboundNodeID != "" {
			for _, id := range ids {
				if n.OutboundNodeID == id {
					users = append(users, n)
					break
				}
			}
		}
	}
	return users, nil
}

// protectUpstreamNode keeps a SOCKS5 egress in place while nodes depend on
// it. Its address and login may change: the users are reconfigured after.
func (a *App) protectUpstreamNode(old, n shared.Node, deleting bool) error {
	users, err := a.upstreamUsers(old.ID)
	if err != nil || len(users) == 0 {
		return err
	}
	if !deleting && n.Enabled && n.Protocol == "socks5" {
		return nil
	}
	names := make([]string, 0, len(users))
	for _, u := range users {
		names = append(names, u.Name)
	}
	return fmt.Errorf("该 SOCKS5 是节点 %s 的出口；请先修改这些节点的出口，再停用、删除或更换协议", strings.Join(names, "、"))
}

// reapplyUpstreamUsers sends the new upstream details to every server whose
// nodes use one of ids as their egress.
func (a *App) reapplyUpstreamUsers(ids ...string) error {
	users, err := a.upstreamUsers(ids...)
	if err != nil {
		return err
	}
	queued := map[string]bool{}
	for _, u := range users {
		if !queued[u.ServerID] {
			queued[u.ServerID] = true
			if err := a.queueApply(u.ServerID, "nodes.apply"); err != nil {
				return err
			}
		}
	}
	return nil
}
