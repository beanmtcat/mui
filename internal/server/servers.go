package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"mui/internal/shared"
)

func validateServerPublicFields(publicName, publicNote string) (string, string, error) {
	name := strings.TrimSpace(publicName)
	if utf8.RuneCountInString(name) > 80 {
		return "", "", errors.New("公开名称不能超过 80 个字符")
	}
	note := strings.TrimSpace(publicNote)
	if utf8.RuneCountInString(note) > 200 {
		return "", "", errors.New("公开备注不能超过 200 个字符")
	}
	return name, note, nil
}

func validServerID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func (a *App) serverExists(id string) bool {
	var one int
	return a.Store.DB.QueryRow(`SELECT 1 FROM mui_servers WHERE id=$1`, id).Scan(&one) == nil
}

// lockServer returns the unlock function for one server's mutex, creating the
// mutex on first use. Callers must not hold two server locks at once.
func (a *App) lockServer(id string) func() {
	if !validServerID(id) {
		return func() {}
	}
	a.serverLocksMu.Lock()
	mu, ok := a.serverLocks[id]
	if !ok {
		mu = &sync.Mutex{}
		a.serverLocks[id] = mu
	}
	a.serverLocksMu.Unlock()
	mu.Lock()
	return mu.Unlock
}

func (a *App) servers(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		list, err := a.Store.Servers()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		cycleMap, err := a.Store.CycleTrafficMap(list, a.nowMonitorUTC())
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		for i := range list {
			list[i].Status = serverStatus(list[i])
			ct := cycleMap[list[i].ID]
			list[i].CycleTraffic = &ct
		}
		paginateList(w, r, list, func(s shared.Server) string { return s.ID })
		return
	}
	var in shared.Server
	if !readJSON(w, r, &in) {
		return
	}
	publicName, publicNote, err := validateServerPublicFields(in.PublicName, in.PublicNote)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if !shared.ValidFirewallMode(in.FirewallMode) {
		errorJSON(w, 400, "防火墙管理模式无效")
		return
	}
	// Only administrator-supplied fields are copied. Agent-reported fields
	// (AppliedRevision, AgentBuild, LastSeen, DetectedIPv4/IPv6, UFWRules,
	// SSHPorts, ...) are never writable at creation.
	roles, err := validRoles(in.Roles)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	srv := shared.Server{
		ID: ID(), Name: in.Name, Roles: roles,
		Country: strings.ToUpper(in.Country), Region: in.Region, City: in.City,
		Provider: in.Provider, Tags: in.Tags, Notes: in.Notes,
		PublicNote: publicNote, PublicVisible: in.PublicVisible, PublicName: publicName,
		IPv4: in.IPv4, IPv6: in.IPv6, Domain: in.Domain, AutoSyncPublicIP: in.AutoSyncPublicIP, InternalAddress: strings.TrimSpace(in.InternalAddress), OutboundInterface: strings.TrimSpace(in.OutboundInterface),
		Status: "pending", UFWStatus: "unknown",
		FirewallMode: in.FirewallMode, ManagementMode: in.ManagementMode, AgentProxyNodeID: in.AgentProxyNodeID, AgentProxyInternal: in.AgentProxyInternal, AgentProxySourceMode: in.AgentProxySourceMode,
	}
	if err = applyServerBillingFields(&srv, in, nil, nil); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err = shared.ValidateOutboundInterface(srv.OutboundInterface); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err = validInternalAddress(srv.InternalAddress); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(srv.Name) == "" || len(srv.Country) != 2 || (srv.IPv4 == "" && srv.IPv6 == "" && srv.Domain == "") {
		errorJSON(w, 400, "需填写名称、国家代码和公网地址或域名")
		return
	}
	if srv.IPv4 != "" && net.ParseIP(srv.IPv4).To4() == nil || srv.IPv6 != "" && (net.ParseIP(srv.IPv6) == nil || net.ParseIP(srv.IPv6).To4() != nil) {
		errorJSON(w, 400, "IP 格式无效")
		return
	}
	if err := validateManagement(srv); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := a.validateAgentProxySelection(srv); err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	token := Token()
	enrollHash, enrollExpires := Hash(token), time.Now().Add(10*time.Minute).Unix()
	if shared.NoAgentManaged(srv) {
		token, enrollHash, enrollExpires = "", "", 0
	}
	_, err = a.Store.DB.Exec(`INSERT INTO mui_servers(id,data,enroll_hash,enroll_expires) VALUES($1,$2,$3,$4)`, srv.ID, Marshal(srv), enrollHash, enrollExpires)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "server.create", srv.ID, srv.Name)
	if srv.AgentProxyNodeID != "" {
		if err = a.syncRoutes(); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	publicURL := a.publicURLForRequest(r)
	if shared.NoAgentManaged(srv) {
		writeJSON(w, 201, map[string]any{"server": srv})
		return
	}
	writeJSON(w, 201, map[string]any{"server": srv, "enrollToken": token, "installCommand": a.installCommandAt(publicURL, srv.ID, token, srv), "offlineInstall": a.offlineInstallAt(publicURL, srv.ID, token, srv), "standaloneInstall": a.standaloneInstallAt(publicURL)})
}

// serverStatus derives what the stored status cannot express: a server that
// stopped reporting is offline, whatever its last report said.
func serverStatus(s shared.Server) string {
	if shared.ExternalManaged(s) {
		return "external"
	}
	if shared.OfflineManaged(s) {
		return "offline-managed"
	}
	if s.Status == "revoked" {
		return "revoked"
	}
	if s.LastSeen == nil {
		return "pending"
	}
	// Agents report every 30 seconds; two missed reports mean offline.
	if time.Since(*s.LastSeen) > 90*time.Second {
		return "offline"
	}
	return "online"
}

// purgeServer removes a server together with everything that belongs to it.
// It is the only way to get rid of a server whose agent will never confirm a
// deletion again.
func (a *App) purgeServer(id string) error {
	nodes, err := a.Store.Nodes(id)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(nodes))
	for _, n := range nodes {
		ids = append(ids, n.ID)
	}
	tx, err := a.Store.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, nodeID := range ids {
		for _, stmt := range []string{`DELETE FROM mui_traffic WHERE node_id=$1`, `DELETE FROM mui_node_totals WHERE node_id=$1`, `DELETE FROM mui_user_traffic WHERE node_id=$1`, `DELETE FROM mui_user_totals WHERE node_id=$1`} {
			if _, err = tx.Exec(stmt, nodeID); err != nil {
				return err
			}
		}
	}
	for _, stmt := range []string{
		`DELETE FROM mui_forward_counters WHERE forward_id IN (SELECT id FROM mui_forwards WHERE server_id=$1)`,
		`DELETE FROM mui_forward_totals WHERE forward_id IN (SELECT id FROM mui_forwards WHERE server_id=$1)`,
	} {
		if _, err = tx.Exec(stmt, id); err != nil {
			return err
		}
	}
	if err = a.Store.DeleteServerMonitorTx(tx, id); err != nil {
		return err
	}
	for _, stmt := range []string{
		`DELETE FROM mui_nodes WHERE server_id=$1`, `DELETE FROM mui_firewall_rules WHERE server_id=$1`, `DELETE FROM mui_forwards WHERE server_id=$1`,
		`DELETE FROM mui_operations WHERE server_id=$1`, `DELETE FROM mui_server_traffic WHERE server_id=$1`, `DELETE FROM mui_server_totals WHERE server_id=$1`, `DELETE FROM mui_server_cycle_traffic WHERE server_id=$1`, `DELETE FROM mui_server_applied WHERE server_id=$1`,
		`DELETE FROM mui_connection_ips WHERE server_id=$1`, `DELETE FROM mui_entry_connection_ips WHERE server_id=$1`,
		`DELETE FROM mui_servers WHERE id=$1`,
	} {
		if _, err = tx.Exec(stmt, id); err != nil {
			return err
		}
	}
	if err = a.Store.DeleteServerAlertStatesTx(tx, id); err != nil {
		return err
	}
	if err = a.dropFromSubscriptionsTx(tx, ids); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	a.clearServerResourcePending(id)
	a.clearServerMonitorState(id)
	return nil
}

// dropFromSubscriptionsTx is dropFromSubscriptions inside an existing
// transaction, so a purge either removes the nodes and their subscription
// references together or removes nothing.
func (a *App) dropFromSubscriptionsTx(tx *sql.Tx, nodeIDs []string) error {
	if len(nodeIDs) == 0 {
		return nil
	}
	gone := map[string]bool{}
	for _, id := range nodeIDs {
		gone[id] = true
	}
	rows, err := tx.Query(`SELECT id,data FROM mui_subscriptions`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type subRow struct {
		id  string
		sub shared.Subscription
	}
	updates := []subRow{}
	for rows.Next() {
		var row subRow
		var raw string
		if err := rows.Scan(&row.id, &raw); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(raw), &row.sub); err != nil {
			return err
		}
		kept := make([]string, 0, len(row.sub.NodeIDs))
		for _, id := range row.sub.NodeIDs {
			if !gone[id] {
				kept = append(kept, id)
			}
		}
		if len(kept) != len(row.sub.NodeIDs) {
			row.sub.NodeIDs = kept
			updates = append(updates, row)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	for _, row := range updates {
		if _, err := tx.Exec(`UPDATE mui_subscriptions SET data=$1 WHERE id=$2`, Marshal(row.sub), row.id); err != nil {
			return err
		}
	}
	return nil
}

// dropFromSubscriptions removes deleted nodes from every subscription that lists them.
func (a *App) dropFromSubscriptions(nodeIDs []string) error {
	if len(nodeIDs) == 0 {
		return nil
	}
	gone := map[string]bool{}
	for _, id := range nodeIDs {
		gone[id] = true
	}
	subs, err := a.Store.Subscriptions()
	if err != nil {
		return err
	}
	for _, sub := range subs {
		kept := make([]string, 0, len(sub.NodeIDs))
		for _, id := range sub.NodeIDs {
			if !gone[id] {
				kept = append(kept, id)
			}
		}
		if len(kept) == len(sub.NodeIDs) {
			continue
		}
		sub.NodeIDs = kept
		if _, err = a.Store.DB.Exec(`UPDATE mui_subscriptions SET data=$1 WHERE id=$2`, Marshal(sub), sub.ID); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) serverByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validServerID(id) || !a.serverExists(id) {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	// PATCH writes the whole server document, including fields supplied by
	// heartbeats. Share their lock so neither writer restores an older snapshot.
	unlock := a.lockServer(id)
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	old, err := a.Store.Server(id)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	if r.Method == "DELETE" {
		if err := a.protectProxyHost(old, old, true); err != nil {
			errorJSON(w, 409, err.Error())
			return
		}
		if hosted, err := a.Store.Nodes(id); err == nil {
			for _, n := range hosted {
				if err := a.protectUpstreamNode(n, n, true); err != nil {
					errorJSON(w, 409, err.Error())
					return
				}
			}
		}
		if serverStatus(old) == "online" {
			errorJSON(w, 409, "服务器仍在线；请先删除其节点与规则并停用 Agent，或吊销 Agent 凭据后再删除")
			return
		}
		nodes, _ := a.Store.Nodes(id)
		rules, _ := a.Store.Rules(id)
		forwards, _ := a.Store.Forwards(id)
		routes, err := a.Store.Routes()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		nodeMap := map[string]shared.Node{}
		for _, n := range nodes {
			nodeMap[n.ID] = n
		}
		if names := routesUsing(routes, nodeMap, id, ""); len(names) > 0 {
			errorJSON(w, 409, "服务器被链路 "+strings.Join(names, "、")+" 使用，请先修改或删除这些链路")
			return
		}
		if (len(nodes) > 0 || len(rules) > 0 || len(forwards) > 0) && r.URL.Query().Get("force") != "1" {
			errorJSON(w, 409, "该服务器仍有节点、转发或规则；离线服务器可强制删除")
			return
		}
		if err = a.purgeServer(id); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		if err = a.syncRoutes(); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.auditRequest(r, "server.delete", id, old.Name)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	var patchIn struct {
		shared.Server
		InitialExpiresAt optionalTimeField `json:"initialExpiresAt"`
	}
	if !readJSON(w, r, &patchIn) {
		return
	}
	in := patchIn.Server
	publicName, publicNote, err := validateServerPublicFields(in.PublicName, in.PublicNote)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if in.ManagementMode == "" {
		in.ManagementMode = old.ManagementMode
	}
	if old.ManagementMode != in.ManagementMode && (shared.ExternalManaged(old) || shared.ExternalManaged(in)) {
		errorJSON(w, 409, "外部节点服务器不能切换管理方式；请新建服务器档案并重新录入节点")
		return
	}
	managementChanged := shared.OfflineManaged(old) != shared.OfflineManaged(in)
	if in.FirewallMode == "" {
		in.FirewallMode = old.FirewallMode
	}
	if !shared.ValidFirewallMode(in.FirewallMode) {
		errorJSON(w, 400, "防火墙管理模式无效")
		return
	}

	if !managementChanged {
		if err := a.checkFirewallModeChange(old, in.FirewallMode); err != nil {
			errorJSON(w, 409, err.Error())
			return
		}
	}
	modeChanged := shared.ManualFirewall(old.FirewallMode) != shared.ManualFirewall(in.FirewallMode)
	if in.AgentProxyNodeID == "" {
		in.AgentProxyInternal = false
		in.AgentProxySourceMode = ""
	}
	proxyChanged := old.AgentProxyNodeID != in.AgentProxyNodeID || old.AgentProxyInternal != in.AgentProxyInternal
	if !managementChanged && proxyChanged && old.AgentProxySwitchPending && (in.AgentProxyNodeID != old.AgentProxyPreviousNodeID || in.AgentProxyInternal != old.AgentProxyPreviousInternal) {
		errorJSON(w, 409, "Agent 代理切换尚未成功应用；请等待完成，或先改回之前的代理再重试")
		return
	}
	in.OutboundInterface = strings.TrimSpace(in.OutboundInterface)
	if err := shared.ValidateOutboundInterface(in.OutboundInterface); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	outboundChanged := old.OutboundInterface != in.OutboundInterface
	before := old
	old.OutboundInterface = in.OutboundInterface
	if proxyChanged && !managementChanged {
		old.AgentProxyPreviousNodeID, old.AgentProxyPreviousInternal = old.AgentProxyNodeID, old.AgentProxyInternal
		old.AgentProxyPreviousSourceMode = old.AgentProxySourceMode
		old.AgentProxySwitchPending = true
	}
	old.AgentProxyNodeID, old.AgentProxyInternal = in.AgentProxyNodeID, in.AgentProxyInternal
	old.AgentProxySourceMode = in.AgentProxySourceMode
	old.FirewallMode = in.FirewallMode
	old.ManagementMode = in.ManagementMode
	if managementChanged {
		resetManagementRuntime(&old, before)
	}
	old.Name = in.Name
	roles, err := validRoles(in.Roles)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	rolesChanged := !slices.Equal(before.Roles, roles)
	in.InternalAddress = strings.TrimSpace(in.InternalAddress)
	if err = validInternalAddress(in.InternalAddress); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	// Roles describe the intended use of the server. Core installation is a
	// separate action; changing roles must not depend on a last reported hash.
	candidate := old
	candidate.Roles = roles
	if shared.CanHostNodes(before) && !shared.CanHostNodes(candidate) {
		nodes, err := a.Store.Nodes(id)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		if len(nodes) > 0 {
			if shared.OfflineManaged(candidate) {
				errorJSON(w, 409, "该服务器仍有节点，不能切换为离线管理；请先删除所有节点并等待配置应用完成")
				return
			}
			errorJSON(w, 409, "该服务器仍有节点，请保留中转或落地类型，或先删除所有节点")
			return
		}
	}
	old.Roles = roles
	if err := validateManagement(old); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	old.InternalAddress = in.InternalAddress
	old.Country = strings.ToUpper(in.Country)
	old.Region = in.Region
	old.City = in.City
	old.Provider = in.Provider
	old.Tags = in.Tags
	old.Notes = in.Notes
	if err := applyServerBillingFields(&old, in, &before, &patchIn.InitialExpiresAt); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	old.PublicNote = publicNote
	old.PublicVisible = in.PublicVisible
	old.PublicName = publicName
	old.IPv4 = in.IPv4
	old.IPv6 = in.IPv6
	old.Domain = in.Domain
	old.AutoSyncPublicIP = in.AutoSyncPublicIP
	if err := validateManagement(old); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if old.Name == "" || len(old.Country) != 2 || (old.IPv4 == "" && old.IPv6 == "" && old.Domain == "") {
		errorJSON(w, 400, "名称、国家代码及地址必填")
		return
	}
	if old.IPv4 != "" && net.ParseIP(old.IPv4).To4() == nil || old.IPv6 != "" && (net.ParseIP(old.IPv6) == nil || net.ParseIP(old.IPv6).To4() != nil) {
		errorJSON(w, 400, "IP 格式无效")
		return
	}
	if err := a.validateAgentProxySelection(old); err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	if err := a.protectProxyHost(before, old, false); err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	world, err := a.loadRouteWorld()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	world.servers[id] = old
	for _, rt := range world.routes {
		if slices.Contains(routeServers(rt), id) || world.nodes[rt.NodeID].ServerID == id {
			if err := world.checkRouteShape(rt); err != nil {
				errorJSON(w, 409, "链路“"+rt.Name+"”将失效："+err.Error())
				return
			}
		}
	}
	if managementChanged {
		err = a.saveManagementChange(old)
	} else if shared.InstallsCore(before) != shared.InstallsCore(old) {
		err = a.Store.PutServerAndInvalidateEnrollment(old)
	} else {
		err = a.Store.PutServer(old)
	}
	if err != nil {
		if errors.Is(err, errManagementBusy) {
			errorJSON(w, 409, err.Error())
			return
		}
		errorJSON(w, 500, err.Error())
		return
	}
	if outboundChanged {
		if err = a.markOutboundChangePending(before, old); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	if modeChanged || managementChanged || proxyChanged || outboundChanged || rolesChanged {
		if err = a.queueApplyLocked(id, "nodes.apply"); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	// syncRoutes may queue this server's own forwards and takes its lock.
	// The document write is complete; release before reconciling routes.
	unlock()
	unlock = nil
	now := a.nowMonitorUTC()
	loc := a.Store.timeLocation()
	if before.ExpiresAt != nil && (old.ExpiresAt == nil || !before.ExpiresAt.Equal(*old.ExpiresAt)) {
		_ = a.Store.DeleteServerExpiryStatesForDate(id, formatExpiryDate(*before.ExpiresAt, loc))
	}
	oldCycleStart, _ := serverTrafficCycleBounds(before, now, loc)
	newCycleStart, _ := serverTrafficCycleBounds(old, now, loc)
	if !oldCycleStart.Equal(newCycleStart) {
		if err = a.Store.RecalcServerCurrentCycleTraffic(old, now); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	// An external server's address is the egress address of nodes that
	// send their traffic through its SOCKS5 nodes.
	if shared.ExternalManaged(old) && (before.Domain != old.Domain || before.IPv4 != old.IPv4 || before.IPv6 != old.IPv6) {
		hosted, err := a.Store.Nodes(id)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		ids := make([]string, 0, len(hosted))
		for _, n := range hosted {
			ids = append(ids, n.ID)
		}
		if err = a.reapplyUpstreamUsers(ids...); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	if err = a.syncRoutes(); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "server.update", id, old.Name)
	old.Status = serverStatus(old)
	if cycleMap, err := a.Store.CycleTrafficMap([]shared.Server{old}, now); err == nil {
		ct := cycleMap[old.ID]
		old.CycleTraffic = &ct
	}
	writeJSON(w, 200, old)
}
