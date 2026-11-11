package server

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"mui/internal/shared"
)

func (a *App) nodes(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		list, err := a.Store.Nodes(r.URL.Query().Get("serverId"))
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		totals, err := a.Store.NodeTotals()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		for i := range list {
			list[i].Uplink, list[i].Downlink = totals[list[i].ID][0], totals[list[i].ID][1]
		}
		paginateList(w, r, list, func(n shared.Node) string { return n.ID })
		return
	}
	var in struct {
		shared.Node
		Password          string `json:"password"`
		ShadowTLSPassword string `json:"shadowTlsPassword"`
		TemplateID        string `json:"templateId"`
		// Enabled is a pointer so creation can tell "omitted" (default true)
		// from an explicit false.
		Enabled *bool `json:"enabled"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	n := in.Node
	n.OutboundInterface = strings.TrimSpace(n.OutboundInterface)
	n.ShadowTLSHost = strings.TrimSpace(n.ShadowTLSHost)
	n.ID = ID()
	n.RouteSources = "" // No route ends here yet.
	n.AgentProxySources = ""
	n.CreatedAt = time.Now()
	n.Status = "pending"
	n.Deleting = false
	n.Enabled = true
	if in.Enabled != nil {
		n.Enabled = *in.Enabled
	}
	if n.Listen == "" {
		n.Listen = "0.0.0.0"
	}
	if n.Method == "" {
		n.Method = "2022-blake3-aes-128-gcm"
	}
	policy, sources, accessErr := shared.NormalizeAdminFirewallAccess(n.FirewallPolicy, n.FirewallSources)
	if accessErr != nil {
		errorJSON(w, 400, accessErr.Error())
		return
	}
	n.FirewallPolicy, n.FirewallSources = policy, sources
	if n.Protocol == "snell" {
		if n.SnellVersion == 0 {
			n.SnellVersion = 5
		}
		if n.SnellPort == 0 {
			n.SnellPort = shared.SnellListenPort(n)
		}
	}
	server, err := a.Store.Server(n.ServerID)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	if err := normalizeNodeBlock(server, &n); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if !shared.ExternalManaged(server) {
		if err := a.checkNodeUpstream(server, &n); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
	}
	if !shared.CanHostNodes(server) {
		errorJSON(w, 409, "只有在线管理的中转、落地或外部节点服务器可以建节点")
		return
	}
	if n.Protocol == "snell" && n.ShadowTLSHost == "" && !shared.ExternalManaged(server) {
		errorJSON(w, 400, "Snell 节点需要 ShadowTLS SNI / 握手域名")
		return
	}
	if shared.ExternalManaged(server) {
		prepareExternalNode(&n)
	} else if server.CoreBuild == "" && (server.AgentVersion != "" || !shared.HasRole(server, shared.RoleExit)) {
		errorJSON(w, 409, "该服务器未安装 sing-box；请先在服务器列表安装 sing-box，安装成功后即可建节点")
		return
	}
	var cert *shared.Certificate
	if n.CertificateID != "" {
		v, err := a.Store.Certificate(n.CertificateID)
		if err == nil {
			cert = &v
		}
	}
	if shared.ExternalManaged(server) {
		cert = externalNodeCertificate(n)
	} else {
		if err := checkSOCKSFirewall(server, n); err != nil {
			errorJSON(w, 409, err.Error())
			return
		}
	}
	if err := shared.ValidateNode(n, cert, false); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if n.Protocol == "snell" {
		if err := sshPortError(server, n.SnellPort, n.SnellPort); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
	}
	if err := sshPortError(server, n.Port, n.Port); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	others, _ := a.Store.Nodes(n.ServerID)
	for _, other := range others {
		if shared.PortConflict(n, other) {
			errorJSON(w, 409, "端口已被其他节点占用")
			return
		}
	}
	if err := a.checkNodeForwardPort(n); err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	password := in.Password
	shadowPassword := in.ShadowTLSPassword
	if in.TemplateID != "" {
		template, err := a.Store.NodeTemplate(in.TemplateID)
		if err != nil {
			errorJSON(w, 404, "节点模板不存在")
			return
		}
		if template.Protocol != n.Protocol || (n.Protocol == "ss" && template.Method != n.Method) || (n.Protocol == "snell" && template.ShadowTLSHost != n.ShadowTLSHost) {
			errorJSON(w, 400, "节点协议、加密方式或 ShadowTLS 域名与模板不一致")
			return
		}
		if password == "" {
			password, err = a.Store.NodeTemplateSecret(in.TemplateID)
			if err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
		if n.Protocol == "snell" && shadowPassword == "" {
			shadowPassword, err = a.Store.NodeTemplateShadowTLSSecret(in.TemplateID)
			if err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
	}
	if password == "" && shared.ExternalManaged(server) {
		errorJSON(w, 400, "外部节点必须填写卖家提供的密码 / PSK")
		return
	}
	if password == "" {
		password = Token()
		if n.Protocol == "ss" && strings.HasPrefix(n.Method, "2022-") {
			password = base64Key(n.Method)
		}
	}
	if err := validatePassword(n, password); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if n.Protocol == "snell" && n.ShadowTLSHost != "" && shadowPassword == "" && shared.ExternalManaged(server) {
		errorJSON(w, 400, "外部 ShadowTLS 节点必须填写卖家提供的 ShadowTLS 密码")
		return
	}
	if n.Protocol == "snell" && shadowPassword == "" && !shared.ExternalManaged(server) {
		shadowPassword = Token()
	}
	if err := validateShadowTLSPassword(n.Protocol, shadowPassword); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := a.Store.PutNodeWithShadowTLS(n, password, shadowPassword); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if !shared.ExternalManaged(server) {
		if err := a.queueApply(n.ServerID, "nodes.apply"); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	a.auditRequest(r, "node.create", n.ID, n.Name)
	writeJSON(w, 201, n)
}

// sshPortError refuses a port range that covers a port sshd listens on, as last
// reported by the agent. The agent enforces the same on the host; this only
// gives the answer before a job is queued.
func sshPortError(server shared.Server, from, to int) error {
	for _, port := range server.SSHPorts {
		if port >= from && port <= to {
			return fmt.Errorf("端口 %d 是该服务器的 SSH 端口", port)
		}
	}
	return nil
}

func base64Key(method string) string {
	length := 16
	if !strings.Contains(method, "128") {
		length = 32
	}
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func validatePassword(n shared.Node, password string) error {
	if n.Protocol == "socks5" {
		return shared.ValidateSOCKS5Credentials(n.Username, password)
	}
	if err := shared.ValidateSnellPSK(n, password); err != nil {
		return err
	}
	if len(password) < 8 {
		return errors.New("密码 / PSK 至少 8 字符")
	}
	if n.Protocol == "ss" && strings.HasPrefix(n.Method, "2022-") {
		raw, err := base64.StdEncoding.DecodeString(password)
		length := 16
		if !strings.Contains(n.Method, "128") {
			length = 32
		}
		if err != nil || len(raw) != length {
			return fmt.Errorf("%s 密钥必须是 %d 字节的 Base64", n.Method, length)
		}
	}
	return nil
}

func validateShadowTLSPassword(protocol, password string) error {
	if protocol != "snell" {
		if password != "" {
			return errors.New("只有 Snell 节点可以设置 ShadowTLS 密码")
		}
		return nil
	}
	if password != "" && (len(password) < 8 || strings.ContainsAny(password, ",\r\n")) {
		return errors.New("ShadowTLS 密码至少 8 字符，且不能包含逗号或换行")
	}
	return nil
}

func (a *App) nodeSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.Store.Node(id); err != nil {
		errorJSON(w, 404, "节点不存在")
		return
	}
	password, err := a.Store.NodeSecret(id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	shadowPassword, err := a.Store.NodeShadowTLSSecret(id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]string{"password": password, "shadowTlsPassword": shadowPassword})
}

func (a *App) nodeByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	old, err := a.Store.Node(id)
	if err != nil {
		errorJSON(w, 404, "节点不存在")
		return
	}
	if r.Method == "DELETE" {
		if err := a.protectProxyNode(old, old, "", true); err != nil {
			errorJSON(w, 409, err.Error())
			return
		}
		if err := a.protectUpstreamNode(old, old, true); err != nil {
			errorJSON(w, 409, err.Error())
			return
		}
		routes, err := a.Store.Routes()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		if names := routesUsing(routes, nil, "", id); len(names) > 0 {
			errorJSON(w, 409, "节点被链路 "+strings.Join(names, "、")+" 使用，请先修改或删除这些链路")
			return
		}
		if server, err := a.Store.Server(old.ServerID); err == nil && shared.ExternalManaged(server) {
			if err := a.deleteExternalNode(id); err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
			a.auditRequest(r, "node.delete", id, old.Name)
			writeJSON(w, 200, map[string]bool{"ok": true})
			return
		}
		old.Deleting = true
		old.Error = ""
		password, _ := a.Store.NodeSecret(id)
		if err = a.Store.PutNode(old, password); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		if err = a.queueApply(old.ServerID, "nodes.apply"); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.auditRequest(r, "node.delete", id, old.Name)
		writeJSON(w, 202, map[string]bool{"queued": true})
		return
	}
	if old.Deleting {
		errorJSON(w, 409, "节点正在删除，无法编辑")
		return
	}
	var in struct {
		shared.Node
		Password          string `json:"password"`
		ShadowTLSPassword string `json:"shadowTlsPassword"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	n := in.Node
	n.OutboundInterface = strings.TrimSpace(n.OutboundInterface)
	n.ShadowTLSHost = strings.TrimSpace(n.ShadowTLSHost)
	n.ID = old.ID
	n.ServerID = old.ServerID
	server, err := a.Store.Server(n.ServerID)
	if err != nil {
		errorJSON(w, 404, "服务器不存在")
		return
	}
	n.RouteSources = old.RouteSources
	n.AgentProxySources = old.AgentProxySources
	n.CreatedAt = old.CreatedAt
	n.Status = "pending"
	n.Deleting = false
	if n.Listen == "" {
		n.Listen = "0.0.0.0"
	}
	if n.Method == "" {
		n.Method = old.Method
	}
	if n.SnellVersion == 0 && n.Protocol == "snell" {
		if old.Protocol == "snell" {
			n.SnellVersion = shared.SnellVersion(old)
		} else {
			n.SnellVersion = 5
		}
	}
	if n.Protocol == "snell" && shared.SnellVersion(n) == 6 {
		n.Obfs = ""
	}
	policy, sources, accessErr := shared.NormalizeAdminFirewallAccess(n.FirewallPolicy, n.FirewallSources)
	if accessErr != nil {
		errorJSON(w, 400, accessErr.Error())
		return
	}
	n.FirewallPolicy, n.FirewallSources = policy, sources
	if err := normalizeNodeBlock(server, &n); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if shared.ExternalManaged(server) {
		prepareExternalNode(&n)
	} else if err := a.checkNodeUpstream(server, &n); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := a.protectProxyNode(old, n, in.Password, false); err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	if err := a.protectUpstreamNode(old, n, false); err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	if n.Protocol == "snell" && n.SnellPort == 0 {
		n.SnellPort = shared.SnellListenPort(n)
	}
	if n.Protocol == "snell" && n.ShadowTLSHost == "" && !shared.ExternalManaged(server) {
		errorJSON(w, 400, "Snell 节点需要 ShadowTLS SNI / 握手域名")
		return
	}
	var cert *shared.Certificate
	if n.CertificateID != "" {
		v, e := a.Store.Certificate(n.CertificateID)
		if e == nil {
			cert = &v
		}
	}
	if shared.ExternalManaged(server) {
		cert = externalNodeCertificate(n)
	}
	// A node may be switched off with an expired certificate, not kept running with one.
	if err = shared.ValidateNode(n, cert, !n.Enabled); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	subs, err := a.Store.Subscriptions()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	routes, err := a.Store.Routes()
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	for _, sub := range subs {
		direct := slices.Contains(sub.NodeIDs, n.ID)
		if direct && !n.Direct {
			errorJSON(w, 409, "节点被订阅“"+sub.Name+"”直连使用，不能关闭直连")
			return
		}
		if direct || slices.Contains(subscriptionNodeIDs(sub, routes), n.ID) {
			if err := validateSubscriptionNode(sub.Format, n); err != nil {
				errorJSON(w, 400, "节点被订阅“"+sub.Name+"”使用："+err.Error())
				return
			}
		}
	}
	if !shared.ExternalManaged(server) {
		if err := checkSOCKSFirewall(server, n); err != nil {
			errorJSON(w, 409, err.Error())
			return
		}
	}
	if n.Protocol == "snell" {
		if err := sshPortError(server, n.SnellPort, n.SnellPort); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
	}
	if n.Port != old.Port {
		if err = sshPortError(server, n.Port, n.Port); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
	}
	others, _ := a.Store.Nodes(n.ServerID)
	for _, other := range others {
		if shared.PortConflict(n, other) {
			errorJSON(w, 409, "端口已被其他节点占用")
			return
		}
	}
	if err := a.checkNodeForwardPort(n); err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	if err := a.checkNodeRoutes(n); err != nil {
		errorJSON(w, 409, err.Error())
		return
	}
	password := in.Password
	if password == "" {
		password, _ = a.Store.NodeSecret(id)
		if !shared.ExternalManaged(server) && n.Protocol == "ss" && strings.HasPrefix(n.Method, "2022-") && (old.Protocol != "ss" || old.Method != n.Method) {
			password = base64Key(n.Method)
		}
	}
	if err := validatePassword(n, password); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	shadowPassword := in.ShadowTLSPassword
	if n.Protocol == "snell" && shadowPassword == "" {
		if old.Protocol == "snell" {
			shadowPassword, err = a.Store.NodeShadowTLSSecret(id)
			if err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
		if shadowPassword == "" && !shared.ExternalManaged(server) {
			shadowPassword = Token()
		}
	}
	if n.Protocol != "snell" {
		shadowPassword = ""
	}
	if shared.ExternalManaged(server) && n.ShadowTLSHost == "" {
		shadowPassword = ""
	}
	if shared.ExternalManaged(server) {
		if err := validateExternalNodeCredentials(n, password, shadowPassword); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
	}
	if err := validateShadowTLSPassword(n.Protocol, shadowPassword); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err = a.Store.PutNodeWithShadowTLS(n, password, shadowPassword); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if !shared.ExternalManaged(server) {
		if err = a.queueApply(n.ServerID, "nodes.apply"); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
	}
	if err = a.reapplyUpstreamUsers(n.ID); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	// A new port or protocol changes the last hop of the routes ending here.
	if err = a.syncRoutes(); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "node.update", id, n.Name)
	writeJSON(w, 200, n)
}

func (a *App) share(w http.ResponseWriter, r *http.Request) {
	n, err := a.Store.Node(r.PathValue("id"))
	if err != nil {
		errorJSON(w, 404, "节点不存在")
		return
	}
	if !n.Direct {
		errorJSON(w, 409, "该节点未开启允许直连；请在节点编辑中开启，或通过链路订阅使用")
		return
	}
	server, _ := a.Store.Server(n.ServerID)
	password, _ := a.Store.NodeSecret(n.ID)
	if n.Protocol == "ss" && shared.SSMultiUser(n.Method) {
		login := "direct"
		if n.SingleUser {
			login = ""
		}
		if live, err := a.nodeLive(n, server, login); err != nil || !live {
			errorJSON(w, 503, "该节点的配置尚未在服务器上生效")
			return
		}
		if !n.SingleUser {
			password += ":" + a.Store.SubscriptionUser(n, "direct").Password
		}
	}
	uri, err := shared.ShareURI(shared.SubscriptionItem{Node: n, Server: server, Password: password, Username: n.Username})
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"uri": uri})
}
