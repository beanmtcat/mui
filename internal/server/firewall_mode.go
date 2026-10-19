package server

import (
	"errors"

	"mui/internal/shared"
)

func requireManagedFirewall(server shared.Server) error {
	if shared.ManualFirewall(server.FirewallMode) {
		return errors.New("该服务器为手动管理防火墙，面板不操作 UFW；请先切换到 UFW 托管模式")
	}
	return nil
}

func (a *App) checkFirewallModeChange(server shared.Server, mode string) error {
	if !shared.ValidFirewallMode(mode) {
		return errors.New("防火墙管理模式无效")
	}
	if !shared.ManualFirewall(mode) || shared.ManualFirewall(server.FirewallMode) {
		return nil
	}
	if server.AgentVersion != "" && !server.ManualFirewallSupport {
		return errors.New("请先将该服务器的 Agent 升级到 0.6.4 或更高版本，再启用手动管理防火墙")
	}
	operations, err := queryJSON[shared.Operation](a.Store.DB, `SELECT data FROM mui_operations WHERE server_id=$1 AND claimed_at>=0`, server.ID)
	if err != nil {
		return err
	}
	for _, operation := range operations {
		if operation.Kind == "ufw.init" || operation.Kind == "ufw.delete" {
			return errors.New("该服务器有未完成的 UFW 操作，请等待完成后切换手动管理模式")
		}
	}
	return nil
}
