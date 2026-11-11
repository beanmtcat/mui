package server

import (
	"errors"
	"net/http"
	"strings"

	"mui/internal/shared"
)

// An older Agent ignores the field, which would show a block that is not running.
func normalizeNodeBlock(server shared.Server, n *shared.Node) error {
	blocked, err := shared.NormalizeBlockedDomains(n.BlockedDomains)
	if err != nil {
		return err
	}
	n.BlockedDomains = blocked
	if n.Enabled && len(blocked) > 0 && server.AgentVersion != "" && !server.NodeDomainBlock && !shared.ExternalManaged(server) {
		return errors.New("请先将该服务器的 Agent 升级至 0.6.24，再设置域名拦截")
	}
	return nil
}

func normalizeNodeTemplate(t *shared.NodeTemplate) {
	t.Name = strings.TrimSpace(t.Name)
	t.Listen = strings.TrimSpace(t.Listen)
	t.ShadowTLSHost = strings.TrimSpace(t.ShadowTLSHost)
	if t.Listen == "" {
		t.Listen = "0.0.0.0"
	}
	switch t.Protocol {
	case "ss":
		if t.Method == "" {
			t.Method = "2022-blake3-aes-128-gcm"
		}
		t.SnellVersion, t.Obfs, t.ShadowTLSHost, t.TLSName = 0, "", "", ""
	case "snell":
		if t.SnellVersion == 0 {
			t.SnellVersion = 5
		}
		if t.SnellPort == 0 {
			t.SnellPort = shared.SnellListenPort(shared.Node{Port: t.Port})
		}
		if t.SnellVersion == 6 {
			t.Obfs = ""
		} else if t.Obfs == "" {
			t.Obfs = "none"
		}
		t.Method, t.TLSName = "", ""
	case "socks5":
		t.Method, t.SnellVersion, t.Obfs, t.ShadowTLSHost, t.TLSName = "", 0, "", "", ""
	case "anytls":
		t.TLSName = strings.TrimSpace(t.TLSName)
		t.Method, t.SnellVersion, t.Obfs, t.ShadowTLSHost = "", 0, "", ""
	}
}

func (a *App) nodeTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		list, err := a.Store.NodeTemplates()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		paginateList(w, r, list, func(t shared.NodeTemplate) string { return t.ID })
		return
	}
	var in struct {
		shared.NodeTemplate
		Password          string `json:"password"`
		ShadowTLSPassword string `json:"shadowTlsPassword"`
		// Older clients may still send these template fields; they are ignored.
		FirewallPolicy  string `json:"firewallPolicy"`
		FirewallSources string `json:"firewallSources"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	t := in.NodeTemplate
	t.ID = ID()
	normalizeNodeTemplate(&t)
	if t.Protocol == "snell" && t.ShadowTLSHost == "" {
		errorJSON(w, 400, "Snell 模板需要 ShadowTLS SNI / 握手域名")
		return
	}
	if err := shared.ValidateNodeTemplate(t); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if in.Password != "" {
		if err := validatePassword(shared.Node{Protocol: t.Protocol, Username: t.Username, Method: t.Method, SnellVersion: t.SnellVersion}, in.Password); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
	}
	if err := validateShadowTLSPassword(t.Protocol, in.ShadowTLSPassword); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := a.Store.PutNodeTemplate(t, in.Password, in.ShadowTLSPassword); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "node_template.create", t.ID, t.Name)
	writeJSON(w, 201, t)
}

func (a *App) nodeTemplateByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	old, err := a.Store.NodeTemplate(id)
	if err != nil {
		errorJSON(w, 404, "节点模板不存在")
		return
	}
	if r.Method == "GET" {
		password, err := a.Store.NodeTemplateSecret(id)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		shadowPassword, err := a.Store.NodeTemplateShadowTLSSecret(id)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, struct {
			shared.NodeTemplate
			Password          string `json:"password"`
			ShadowTLSPassword string `json:"shadowTlsPassword"`
		}{old, password, shadowPassword})
		return
	}
	if r.Method == "DELETE" {
		if err := a.Store.DeleteNodeTemplate(id); err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		a.auditRequest(r, "node_template.delete", id, "")
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	var in struct {
		shared.NodeTemplate
		Password          *string `json:"password"`
		ShadowTLSPassword *string `json:"shadowTlsPassword"`
		FirewallPolicy    string  `json:"firewallPolicy"`
		FirewallSources   string  `json:"firewallSources"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	t := in.NodeTemplate
	t.ID = id
	if t.Protocol == "snell" && t.SnellVersion == 0 && old.Protocol == "snell" {
		t.SnellVersion = old.SnellVersion
	}
	normalizeNodeTemplate(&t)
	if t.Protocol == "snell" && t.ShadowTLSHost == "" {
		errorJSON(w, 400, "Snell 模板需要 ShadowTLS SNI / 握手域名")
		return
	}
	if err := shared.ValidateNodeTemplate(t); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	password, err := a.Store.NodeTemplateSecret(id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if in.Password != nil {
		password = *in.Password
	}
	shadowPassword, err := a.Store.NodeTemplateShadowTLSSecret(id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if in.ShadowTLSPassword != nil {
		shadowPassword = *in.ShadowTLSPassword
	}
	if t.Protocol != "snell" {
		shadowPassword = ""
	}
	if password != "" {
		if err := validatePassword(shared.Node{Protocol: t.Protocol, Username: t.Username, Method: t.Method, SnellVersion: t.SnellVersion}, password); err != nil {
			errorJSON(w, 400, err.Error())
			return
		}
	}
	if err := validateShadowTLSPassword(t.Protocol, shadowPassword); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	if err := a.Store.PutNodeTemplate(t, password, shadowPassword); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "node_template.update", id, t.Name)
	writeJSON(w, 200, t)
}
