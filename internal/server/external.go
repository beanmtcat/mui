package server

import (
	"errors"
	"time"

	"mui/internal/shared"
)

// A seller controls the actual process and firewall. Keep only the connection
// details that can be published to a subscription; never imply an Agent apply.
func prepareExternalNode(n *shared.Node) {
	n.SingleUser = true
	n.CertificateID = ""
	n.OutboundMode, n.OutboundInterface = "system", ""
	n.FirewallPolicy, n.FirewallSources = "manual", ""
	n.AgentProxySources = ""
	n.Status = "external"
	if !n.Enabled {
		n.Status = "disabled"
	}
	if n.Protocol == "snell" && n.ShadowTLSHost == "" {
		n.SnellPort = 0
	}
}

// AnyTLS validates a TLS name against a certificate on managed hosts. For a
// seller's node, the seller owns that certificate; only the name is stored.
func externalNodeCertificate(n shared.Node) *shared.Certificate {
	if n.Protocol != "anytls" || n.TLSName == "" {
		return nil
	}
	return &shared.Certificate{Domain: n.TLSName, ExpiresAt: time.Now().AddDate(100, 0, 0)}
}

func (a *App) deleteExternalNode(id string) error {
	tx, err := a.Store.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM mui_nodes WHERE id=$1`, id); err != nil {
		return err
	}
	if err = a.dropFromSubscriptionsTx(tx, []string{id}); err != nil {
		return err
	}
	return tx.Commit()
}

func validateExternalNodeCredentials(n shared.Node, password, shadowPassword string) error {
	if password == "" {
		return errors.New("外部节点必须填写卖家提供的密码 / PSK")
	}
	if n.Protocol == "snell" && n.ShadowTLSHost != "" && shadowPassword == "" {
		return errors.New("外部 ShadowTLS 节点必须填写卖家提供的 ShadowTLS 密码")
	}
	return nil
}
