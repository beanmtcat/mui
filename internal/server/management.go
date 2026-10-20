package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"mui/internal/shared"
)

var errManagementBusy = errors.New("服务器仍有正在执行的任务，请等待完成后切换管理方式")

func resetManagementRuntime(s *shared.Server, before shared.Server) {
	s.ManagementMigrationFrom = "online"
	if shared.OfflineManaged(before) {
		s.ManagementMigrationFrom = "offline"
	}
	s.OfflineExportedAt, s.OfflineExportedRevision = nil, 0
	s.LastSeen, s.AppliedRevision, s.Status = nil, 0, "pending"
	s.AgentVersion, s.AgentBuild, s.CoreVersion, s.CoreBuild = "", "", "", ""
	s.AgentSelfUpdate, s.CoreSelfUpdate, s.AgentProxySupport = false, false, false
	s.OutboundBindingSupport = false
	s.ManualFirewallSupport, s.NodeFirewallPolicies, s.MultiUserStats = false, false, false
	s.ForwardSupport, s.ForwardTCPUDP, s.ShadowTLSAuth, s.SnellFixedPort, s.SnellV6 = false, false, false, false, false
	s.AgentProxySwitchPending, s.AgentProxyPreviousInternal, s.AgentProxyPreviousNodeID = false, false, ""
	s.AgentProxyPreviousSourceMode = ""
	s.UFWStatus, s.StatsStatus, s.FirewallConflict = "", "", ""
	s.UFWRules = nil
}

// Revoke the old control plane and invalidate its queued jobs atomically.
// Nothing here touches the host: the guide requires stopping the old local
// services before installing the new mode, preventing competing writers.
func (a *App) saveManagementChange(s shared.Server) error {
	forwards, err := a.Store.Forwards(s.ID)
	if err != nil {
		return err
	}
	tx, err := a.Store.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT data,claimed_at FROM mui_operations WHERE server_id=$1 AND (claimed_at>=0 OR state<>'')`, s.ID)
	if err != nil {
		return err
	}
	type unfinished struct {
		op        shared.Operation
		claimedAt int64
	}
	var pending []unfinished
	for rows.Next() {
		var raw string
		var claimedAt int64
		var op shared.Operation
		if err = rows.Scan(&raw, &claimedAt); err == nil {
			err = json.Unmarshal([]byte(raw), &op)
		}
		if err != nil {
			break
		}
		// A live claim may still change the host. A claim whose window has
		// passed belongs to an agent that went away, which is the usual
		// reason for switching, so it must not block the switch forever.
		window := 5 * time.Minute
		if op.Kind == "agent.upgrade" || op.Kind == "core.upgrade" {
			window = 30 * time.Minute
		}
		live := op.Status == "running" && claimedAt > 0 && claimedAt >= time.Now().Add(-window).UnixMilli() ||
			op.Status == "activating" && time.Since(op.UpdatedAt) <= 5*time.Minute
		if live {
			err = errManagementBusy
			break
		}
		if op.Status == "queued" || op.Status == "running" || op.Status == "activating" {
			pending = append(pending, unfinished{op, claimedAt})
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, p := range pending {
		op := p.op
		op.Status, op.Error, op.UpdatedAt = "superseded", "管理方式已切换", time.Now()
		// The agent claims jobs without the server lock; if it claimed this
		// one after it was read, the switch must wait for that job instead.
		result, err := tx.Exec(`UPDATE mui_operations SET data=$1,state='',claimed_at=-1 WHERE id=$2 AND claimed_at=$3`, Marshal(op), op.ID, p.claimedAt)
		if err != nil {
			return err
		}
		if n, _ := result.RowsAffected(); n == 0 {
			return errManagementBusy
		}
	}
	for _, f := range forwards {
		f.Status, f.Error = "pending", ""
		if !f.Enabled {
			f.Status = "disabled"
		}
		if f.Deleting {
			f.Status = "deleting"
		}
		if _, err = tx.Exec(`UPDATE mui_forwards SET data=$1 WHERE id=$2`, Marshal(f), f.ID); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`UPDATE mui_servers SET data=$1,revision=$2,agent_hash='',agent_signs=0,enroll_hash='',enroll_expires=0 WHERE id=$3`, Marshal(s), s.Revision, s.ID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// A separate, reviewable preparation step. Existing binaries never run before
// signature verification and pinned keys survive both migration directions.
func managementMigrationCommand(s shared.Server) string {
	if s.ManagementMigrationFrom == "" {
		return ""
	}
	marker := "/etc/mui-forward/offline.json"
	units := []string{"mui-forward"}
	if shared.OfflineManaged(s) {
		marker = "/etc/mui-agent/config.json"
		units = []string{"mui-agent", "mui-agent-helper", "mui-forward", "mui-sing-box"}
	}
	cmd := "(\nset -eu\numask 077\n[ \"$(id -u)\" -eq 0 ] || { printf '%s\\n' '请切换到 root 后执行迁移准备命令。' >&2; exit 1; }\n" +
		"if [ ! -f " + shellQuote(marker) + " ]; then\n  printf '%s\\n' '未发现旧模式配置，无需迁移准备，可继续安装。'\n  exit 0\nfi\n" +
		"mui_backup=$(mktemp -d /etc/mui-management-backup.XXXXXX)\n"
	if !shared.OfflineManaged(s) {
		cmd += "if [ -f /etc/mui-forward/release.pub ]; then\n" +
			"  if [ -f /etc/mui-agent/release.pub ]; then\n" +
			"    [ \"$(tr -d '[:space:]' < /etc/mui-forward/release.pub)\" = \"$(tr -d '[:space:]' < /etc/mui-agent/release.pub)\" ] || { printf '%s\\n' '固定发布公钥不一致，已停止迁移。' >&2; exit 1; }\n" +
			"  else\n    mkdir -p /etc/mui-agent\n    cp /etc/mui-forward/release.pub /etc/mui-agent/release.pub\n    chmod 644 /etc/mui-agent/release.pub\n  fi\nfi\n"
	}
	cmd += "if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then\n"
	for _, unit := range units {
		cmd += fmt.Sprintf("  if systemctl cat %s.service >/dev/null 2>&1; then systemctl disable --now %s.service; fi\n", unit, unit)
	}
	cmd += "elif command -v rc-service >/dev/null 2>&1; then\n"
	for _, unit := range units {
		cmd += fmt.Sprintf("  if [ -x /etc/init.d/%s ]; then\n    rc-service %s stop\n    if [ -e /etc/runlevels/default/%s ]; then rc-update del %s default; fi\n  fi\n", unit, unit, unit, unit)
	}
	cmd += "else\n  printf '%s\\n' '未检测到 systemd 或 OpenRC，已停止迁移。' >&2\n  exit 1\nfi\n" +
		"mv " + shellQuote(marker) + " \"$mui_backup/\"\n" +
		"printf '旧配置已备份至 %s；现在请执行下方安装命令。\\n' \"$mui_backup\"\n)"
	return cmd
}
