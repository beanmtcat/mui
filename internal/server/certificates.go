package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"

	"mui/internal/shared"
)

func (a *App) certificates(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		list, err := a.Store.Certificates()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		nodes, err := a.Store.Nodes("")
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		servers, err := a.Store.Servers()
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		serverByID := make(map[string]shared.Server, len(servers))
		for _, server := range servers {
			serverByID[server.ID] = server
		}
		pendingByCertificate := map[string]map[string]string{}
		for _, n := range nodes {
			if n.CertificateID == "" || n.Protocol != "anytls" || n.Deleting || n.Status != "pending" && n.Status != "error" {
				continue
			}
			server, ok := serverByID[n.ServerID]
			if !ok || shared.ExternalManaged(server) {
				continue
			}
			if pendingByCertificate[n.CertificateID] == nil {
				pendingByCertificate[n.CertificateID] = map[string]string{}
			}
			pendingByCertificate[n.CertificateID][server.ID] = server.Name
		}
		type certificateListItem struct {
			shared.Certificate
			PendingServers []string `json:"pendingServers"`
		}
		items := make([]certificateListItem, 0, len(list))
		for _, c := range list {
			c.DNSNames = shared.CertificateDNSNames(c.PEM)
			c.PEM = ""
			c.DaysUntilExpiry, c.ExpiringSoon = shared.CertExpiryStatus(c.ExpiresAt)
			item := certificateListItem{Certificate: c, PendingServers: []string{}}
			for _, name := range pendingByCertificate[c.ID] {
				item.PendingServers = append(item.PendingServers, name)
			}
			slices.Sort(item.PendingServers)
			items = append(items, item)
		}
		paginateList(w, r, items, func(c certificateListItem) string { return c.ID })
		return
	}
	var in shared.Certificate
	if !readJSON(w, r, &in) {
		return
	}
	if err := prepareCertificate(&in, true); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	in.ID = ID()
	if err := a.Store.PutCertificate(in); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	in.Key = ""
	a.auditRequest(r, "certificate.create", in.ID, in.Domain)
	writeJSON(w, 201, in)
}

// prepareCertificate validates uploaded PEM material and normalizes the
// metadata. Metadata-only edits retain the already validated certificate,
// including its expiry, so an expired certificate can still be renamed.
func prepareCertificate(in *shared.Certificate, replacement bool) error {
	in.PEM, in.Key = strings.TrimPrefix(in.PEM, "\ufeff"), strings.TrimPrefix(in.Key, "\ufeff")
	if replacement {
		expires, names, err := shared.ParseCertificate(in.PEM, in.Key)
		if err != nil {
			if strings.Contains(err.Error(), "private key does not match public key") {
				return errors.New("证书与私钥不匹配，请选择同一套 .pem 证书和 .key 私钥文件")
			}
			return fmt.Errorf("证书或私钥校验失败：%w", err)
		}
		if err := shared.CheckCertificateServerAuth(in.PEM, in.Key); err != nil {
			return err
		}
		in.ExpiresAt, in.DNSNames = expires, names
	}
	in.Domain = strings.TrimSpace(in.Domain)
	if in.Domain == "" && len(in.DNSNames) > 0 {
		in.Domain = in.DNSNames[0]
	}
	if in.Domain == "" {
		return errors.New("证书中没有 DNS 域名，请使用包含所需 TLS 域名的服务器证书")
	}
	if !shared.CertificateCovers(in.PEM, in.Domain) {
		return errors.New("证书域名不匹配")
	}
	if strings.TrimSpace(in.Name) == "" {
		in.Name = in.Domain
	}
	in.DaysUntilExpiry, in.ExpiringSoon = shared.CertExpiryStatus(in.ExpiresAt)
	return nil
}

func (a *App) certificateByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := a.Store.Certificate(id)
	if err != nil {
		errorJSON(w, 404, "证书不存在")
		return
	}
	if r.Method == "PATCH" {
		a.updateCertificate(w, r, c)
		return
	}
	nodes, err := a.Store.Nodes("")
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	for _, n := range nodes {
		if n.CertificateID == id {
			errorJSON(w, 409, "证书仍被节点使用")
			return
		}
	}
	_, err = a.Store.DB.Exec(`DELETE FROM mui_certificates WHERE id=$1`, id)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "certificate.delete", id, c.Domain)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) updateCertificate(w http.ResponseWriter, r *http.Request, old shared.Certificate) {
	var patch struct {
		ID     string  `json:"id"`
		Name   *string `json:"name"`
		Domain *string `json:"domain"`
		PEM    string  `json:"pem"`
		Key    string  `json:"key"`
	}
	if !readJSON(w, r, &patch) {
		return
	}
	if patch.ID != "" && patch.ID != old.ID {
		errorJSON(w, 400, "证书 ID 与请求地址不一致")
		return
	}
	in := old
	if patch.Name != nil {
		in.Name = *patch.Name
	}
	if patch.Domain != nil {
		in.Domain = *patch.Domain
	}
	replace := strings.TrimSpace(patch.PEM) != "" || strings.TrimSpace(patch.Key) != ""
	if replace && (strings.TrimSpace(patch.PEM) == "" || strings.TrimSpace(patch.Key) == "") {
		errorJSON(w, 400, "更换证书时必须同时提供证书和私钥")
		return
	}
	key, err := a.Store.CertificateKey(old.ID)
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	if replace {
		in.PEM, in.Key = patch.PEM, patch.Key
	} else {
		in.Key = key
	}
	if err := prepareCertificate(&in, replace); err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	nodes, err := a.Store.Nodes("")
	if err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	servers := map[string]string{}
	pendingNodes := []shared.Node{}
	for _, n := range nodes {
		if n.CertificateID != old.ID || n.Deleting || n.Protocol != "anytls" {
			continue
		}
		if !shared.CertificateCovers(in.PEM, n.TLSName) {
			label := "节点"
			if !n.Enabled {
				label = "已停用节点"
			}
			errorJSON(w, 409, "新证书未覆盖"+label+" “"+n.Name+"” 的 TLS 域名 "+n.TLSName+"；请先修改或删除该节点，再更换证书")
			return
		}
		server, err := a.Store.Server(n.ServerID)
		if err != nil {
			errorJSON(w, 500, err.Error())
			return
		}
		if shared.ExternalManaged(server) {
			continue
		}
		if replace {
			n.Status, n.Error = "pending", ""
			pendingNodes = append(pendingNodes, n)
		}
		if replace || n.Status == "pending" || n.Status == "error" {
			servers[n.ServerID] = server.Name
		}
	}
	if replace {
		for serverID := range servers {
			if err := a.preserveCertificateSubscriptionLiveness(serverID, nodes); err != nil {
				errorJSON(w, 500, err.Error())
				return
			}
		}
	}
	if err := a.Store.UpdateCertificate(in, pendingNodes); err != nil {
		errorJSON(w, 500, err.Error())
		return
	}
	a.auditRequest(r, "certificate.update", old.ID, in.Domain)
	// A metadata-only save retries pending/failed servers. The Agent compares
	// certificate files to desired bytes, so unchanged files alone do not
	// restart sing-box.
	failed := []string{}
	for serverID, name := range servers {
		if err := a.queueApply(serverID, "nodes.apply"); err != nil {
			log.Printf("certificate %s apply on server %s: %v", old.ID, serverID, err)
			failed = append(failed, name)
		}
	}
	if len(failed) > 0 {
		slices.Sort(failed)
		errorJSON(w, 503, "证书已更新，以下服务器未能创建下发任务："+strings.Join(failed, "、")+"。可再次点击保存重试，无需重新选择文件。")
		return
	}
	in.Key, in.PEM = "", ""
	writeJSON(w, 200, in)
}

// Older servers can have an applied server revision but no per-node deployment
// record yet. Record the currently live nodes before marking a certificate
// renewal pending, so the subscription keeps serving their existing config.
// The fingerprint calculation stays unchanged; only a successful apply
// replaces this baseline with the Agent-confirmed deployment.
func (a *App) preserveCertificateSubscriptionLiveness(serverID string, nodes []shared.Node) error {
	unlock := a.lockServer(serverID)
	defer unlock()
	server, err := a.Store.Server(serverID)
	if err != nil {
		return err
	}
	if !server.MultiUserStats || server.AppliedRevision < server.Revision {
		return nil
	}
	_, known, err := a.Store.AppliedDeployment(serverID)
	if err != nil || known {
		return err
	}
	state, err := a.desired(serverID)
	if err != nil {
		return err
	}
	deployed := a.deployment(server, state)
	for _, n := range nodes {
		if n.ServerID == serverID && n.Status != "active" {
			delete(deployed, n.ID)
		}
	}
	return a.Store.SetAppliedDeployment(serverID, deployed)
}

// CheckExpiringCertificates logs and audits certificates expiring within 30
// days. It runs on the pruning schedule, so one entry appears per check
// cycle per certificate, not per request.
func (a *App) CheckExpiringCertificates() {
	list, err := a.Store.Certificates()
	if err != nil {
		log.Printf("certificate expiry check: %v", err)
		return
	}
	for _, c := range list {
		days, soon := shared.CertExpiryStatus(c.ExpiresAt)
		if !soon {
			continue
		}
		msg := fmt.Sprintf("证书 %s %d 天后过期", c.Domain, days)
		log.Printf("certificate expiring: %s", msg)
		a.Store.Audit("certificate.expiring", c.ID, msg)
	}
}
