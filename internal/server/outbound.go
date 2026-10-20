package server

import "mui/internal/shared"

func outboundBindingRequired(server shared.Server, nodes []shared.Node) bool {
	if server.OutboundInterface != "" {
		return true
	}
	for _, n := range nodes {
		if !n.Deleting && n.Enabled && shared.EffectiveOutboundInterface(n, server.OutboundInterface) != "" {
			return true
		}
	}
	return false
}

func (a *App) markOutboundChangePending(before, after shared.Server) error {
	nodes, err := a.Store.Nodes(after.ID)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		if !n.Enabled || n.Deleting || shared.EffectiveOutboundInterface(n, before.OutboundInterface) == shared.EffectiveOutboundInterface(n, after.OutboundInterface) {
			continue
		}
		n.Status, n.Error = "pending", ""
		// Only metadata changes: encrypted credentials remain untouched.
		if _, err = a.Store.DB.Exec(`UPDATE mui_nodes SET data=$1 WHERE id=$2`, Marshal(n), n.ID); err != nil {
			return err
		}
	}
	return nil
}
