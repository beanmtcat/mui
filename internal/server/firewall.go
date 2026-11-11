package server

import (
	"errors"
	"net"
	"net/http"

	"mui/internal/shared"
)

func (a *App) firewall(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		list, err := a.Store.Rules(r.URL.Query().Get("serverId"))
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		paginateList(w, r, list, func(rule shared.FirewallRule) string { return rule.ID })
		return
	}
	var body struct {
		shared.FirewallRule
		// ReplaceHostRule converts a rule added on the host into this
		// custom rule: the host rule is removed first.
		ReplaceHostRule string `json:"replaceHostRule"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	in := body.FirewallRule
	server, err := a.Store.Server(in.ServerID)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	networks := []string{in.Network}
	if in.Network == "tcp+udp" {
		if body.ReplaceHostRule == "" {
			errorJSON(w, 400, "TCP + UDP 仅用于接管主机现有规则")
			return
		}
		networks = []string{"tcp", "udp"}
	}
	created := make([]shared.FirewallRule, 0, len(networks))
	for _, network := range networks {
		rule := in
		rule.Network = network
		if err := normalizeCustomRule(server, &rule); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
		rule.ID, rule.Owner, rule.Status, rule.Deleting = ID(), "custom", "pending", false
		created = append(created, rule)
	}
	if body.ReplaceHostRule != "" {
		lines, err := hostRules(server, []string{body.ReplaceHostRule})
		if err != nil {
			errorJSON(w, 409, err.Error())
			return
		}
		if err := a.queueHostRuleDelete(server.ID, lines); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.auditRequest(r, "firewall.host_delete", server.ID, body.ReplaceHostRule)
	}
	tx, err := a.Store.DB.Begin()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	defer tx.Rollback()
	for _, rule := range created {
		if _, err := tx.Exec(`INSERT INTO mui_firewall_rules(id,server_id,data) VALUES($1,$2,$3)`, rule.ID, rule.ServerID, Marshal(rule)); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	if err := tx.Commit(); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if err = a.queueApply(in.ServerID, "firewall.apply"); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	for _, rule := range created {
		a.auditRequest(r, "firewall.create", rule.ID, rule.Comment)
	}
	if len(created) == 1 {
		writeJSON(w, 201, created[0])
	} else {
		writeJSON(w, 201, map[string]any{"rules": created})
	}
}

func validateRule(r shared.FirewallRule) error {
	if r.PortFrom < 1 || r.PortFrom > 65535 || r.PortTo < r.PortFrom || r.PortTo > 65535 {
		return errors.New("端口范围无效")
	}
	if r.Network != "tcp" && r.Network != "udp" {
		return errors.New("协议只能是 tcp 或 udp")
	}
	if r.Action != "allow" && r.Action != "deny" {
		return errors.New("动作只能是 allow 或 deny")
	}
	if r.Source != "" {
		if _, _, err := net.ParseCIDR(r.Source); err != nil {
			return errors.New("来源必须是 CIDR")
		}
	}
	return shared.RuleFamilyError(r)
}

func (a *App) firewallByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rules, _ := a.Store.Rules("")
	var target *shared.FirewallRule
	for i := range rules {
		if rules[i].ID == id {
			target = &rules[i]
			break
		}
	}
	if target == nil {
		errorJSON(w, 404, "规则不存在")
		return
	}
	server, err := a.Store.Server(target.ServerID)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	if err := requireManagedFirewall(server); err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	if r.Method == http.MethodPatch {
		a.updateCustomRule(w, r, *target)
		return
	}
	target.Deleting = true
	_, err = a.Store.DB.Exec(`UPDATE mui_firewall_rules SET data=$1 WHERE id=$2`, Marshal(target), id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if err = a.queueApply(target.ServerID, "firewall.apply"); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "firewall.delete", id, target.Comment)
	writeJSON(w, 202, map[string]bool{"queued": true})
}

func (a *App) ufwInit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	server, err := a.Store.Server(id)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	if err := requireManagedFirewall(server); err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	if server.UFWStatus == "active" && serverStatus(server) == "online" {
		errorJSON(w, 409, "该服务器的 UFW 已启用，无需初始化")
		return
	}
	if err := a.queueApply(id, "ufw.init"); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "ufw.init", id, "")
	writeJSON(w, 202, map[string]bool{"queued": true})
}
