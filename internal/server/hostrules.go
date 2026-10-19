package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"mui/internal/shared"
)

// Host rules are the UFW rules an agent reports. Rules added on the host by
// other means can be deleted from the panel, or converted into a custom rule
// the panel manages from then on; rules the panel generated are changed
// where they come from.

// hostRules finds reported rules by their text and says whether the panel
// may remove them. The agent checks the same again against the live host.
// Each listed line stands alone: an IPv6 line is not its IPv4 twin.
func hostRules(server shared.Server, rules []string) ([]shared.UFWLine, error) {
	if err := requireManagedFirewall(server); err != nil {
		return nil, err
	}
	if len(rules) == 0 || len(rules) > 100 {
		return nil, errors.New("一次可处理 1–100 条规则")
	}
	var out []shared.UFWLine
	seen := map[string]bool{}
	for _, rule := range rules {
		key := shared.UFWRuleKey(rule)
		if key == "" || len(rule) > 300 {
			return nil, errors.New("规则无效")
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		found := false
		for _, raw := range server.UFWRules {
			line, ok := shared.ParseUFWLine(raw)
			if !ok || shared.UFWRuleKey(line.Rule) != key {
				continue
			}
			if reason := shared.HostRuleError(line, server.SSHPorts); reason != "" {
				return nil, fmt.Errorf("%s：%s", line.Rule, reason)
			}
			out = append(out, line)
			found = true
			break
		}
		if !found {
			return nil, fmt.Errorf("服务器上报的规则中没有“%s”，请刷新后重试", strings.TrimSpace(rule))
		}
	}
	return out, nil
}

// queueHostRuleDelete queues one job that removes host rules. It is not an
// apply: it changes no configuration and is never superseded, so it runs
// before any apply queued after it.
func (a *App) queueHostRuleDelete(serverID string, lines []shared.UFWLine) error {
	rules := make([]string, len(lines))
	for i, line := range lines {
		rules[i] = line.Rule
	}
	unlock := a.lockServer(serverID)
	defer unlock()
	server, err := a.Store.Server(serverID)
	if err != nil {
		return err
	}
	if err := requireManagedFirewall(server); err != nil {
		return err
	}
	state, err := a.signDesiredState(shared.DesiredState{Revision: server.Revision, ProtocolVersion: 1, HostRules: rules})
	if err != nil {
		return err
	}
	now := time.Now()
	return a.Store.PutOperation(shared.Operation{ID: ID(), ServerID: serverID, Kind: "ufw.delete", Status: "queued", Revision: server.Revision, CreatedAt: now, UpdatedAt: now}, state)
}

func (a *App) readHostRules(w http.ResponseWriter, r *http.Request) (shared.Server, []shared.UFWLine, bool) {
	server, err := a.Store.Server(r.PathValue("id"))
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return server, nil, false
	}
	var in struct {
		Rules []string `json:"rules"`
	}
	if !readJSON(w, r, &in) {
		return server, nil, false
	}
	lines, err := hostRules(server, in.Rules)
	if err != nil {
		errorJSON(w, 409, err.Error())
		return server, nil, false
	}
	return server, lines, true
}

func (a *App) hostRuleDelete(w http.ResponseWriter, r *http.Request) {
	server, lines, ok := a.readHostRules(w, r)
	if !ok {
		return
	}
	if err := a.queueHostRuleDelete(server.ID, lines); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	for _, line := range lines {
		a.Store.Audit("firewall.host_delete", server.ID, line.Rule)
	}
	writeJSON(w, 202, map[string]int{"queued": len(lines)})
}

// hostRuleAdopt turns host rules into custom rules with the same ports,
// protocol, source and action: one job removes the host rules, then one
// apply writes them back as panel rules.
func (a *App) hostRuleAdopt(w http.ResponseWriter, r *http.Request) {
	server, lines, ok := a.readHostRules(w, r)
	if !ok {
		return
	}
	var rules []shared.FirewallRule
	seen := map[shared.FirewallRule]bool{}
	for _, line := range lines {
		rule, ok := line.CustomRule()
		if !ok {
			errorJSON(w, 409, line.Rule+"：同时放行 TCP 和 UDP、是应用配置或动作为 REJECT/LIMIT，不能直接转为面板规则，请删除后新建")
			return
		}
		rule.ServerID, rule.Comment = server.ID, "接管自主机规则"
		if err := normalizeCustomRule(server, &rule); err != nil {
			errorJSON(w, 409, line.Rule+"："+err.Error())
			return
		}
		// Each line keeps its own family, so converting the IPv6 line of a
		// rule leaves its IPv4 line alone.
		if !seen[rule] {
			seen[rule] = true
			rules = append(rules, rule)
		}
	}
	if err := a.queueHostRuleDelete(server.ID, lines); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	tx, err := a.Store.DB.Begin()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	defer tx.Rollback()
	for i := range rules {
		rules[i].ID, rules[i].Owner, rules[i].Status = ID(), "custom", "pending"
		if _, err = tx.Exec(`INSERT INTO mui_firewall_rules(id,server_id,data) VALUES($1,$2,$3)`, rules[i].ID, server.ID, Marshal(rules[i])); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	if err = tx.Commit(); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if err = a.queueApply(server.ID, "firewall.apply"); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	for _, line := range lines {
		a.Store.Audit("firewall.host_adopt", server.ID, line.Rule)
	}
	writeJSON(w, 201, rules)
}

// normalizeCustomRule validates a custom rule as typed by an administrator.
func normalizeCustomRule(server shared.Server, in *shared.FirewallRule) error {
	if err := requireManagedFirewall(server); err != nil {
		return err
	}
	if strings.TrimSpace(in.Source) != "" {
		_, source, err := shared.NormalizeFirewallAccess("restricted", in.Source)
		if err != nil || strings.Contains(source, ",") {
			return errors.New("单条规则的来源必须是一个 IP 或 CIDR")
		}
		in.Source = source
	}
	if err := validateRule(*in); err != nil {
		return err
	}
	if in.Action == "deny" && in.Network == "tcp" {
		if err := sshPortError(server, in.PortFrom, in.PortTo); err != nil {
			return errors.New("拒绝规则不能覆盖 SSH 端口：" + err.Error())
		}
	}
	return nil
}

// updateCustomRule replaces a custom rule. UFW rules are matched by the ID
// in their comment, so the new values get a new ID and the old rule is
// removed in the same apply.
func (a *App) updateCustomRule(w http.ResponseWriter, r *http.Request, old shared.FirewallRule) {
	if old.Deleting {
		errorJSON(w, 409, "规则正在删除，无法修改")
		return
	}
	if old.Owner != "custom" {
		errorJSON(w, 409, "只能修改自定义规则")
		return
	}
	var in shared.FirewallRule
	if !readJSON(w, r, &in) {
		return
	}
	server, err := a.Store.Server(old.ServerID)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	in.ServerID = old.ServerID
	if err := normalizeCustomRule(server, &in); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	in.ID, in.Owner, in.Status, in.Deleting = ID(), "custom", "pending", false
	old.Deleting = true
	tx, err := a.Store.DB.Begin()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE mui_firewall_rules SET data=$1 WHERE id=$2`, Marshal(old), old.ID); err == nil {
		_, err = tx.Exec(`INSERT INTO mui_firewall_rules(id,server_id,data) VALUES($1,$2,$3)`, in.ID, in.ServerID, Marshal(in))
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if err = a.queueApply(in.ServerID, "firewall.apply"); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.Store.Audit("firewall.update", in.ID, in.Comment)
	writeJSON(w, 200, in)
}
