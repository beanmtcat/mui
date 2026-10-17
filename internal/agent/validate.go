package agent

import (
	"errors"
	"fmt"
	"net"

	"mui/internal/shared"
)

// portConflictIndex tracks claimed (port, protocol-class, listen) triples so
// port conflicts are found in O(n) instead of pairwise comparison. An ss
// node claims both tcp and udp; every other protocol claims tcp only. A
// wildcard listen ("", "0.0.0.0", "::") conflicts with every listen on the
// same port and class.
type portConflictIndex struct {
	wild map[portClass]bool
	seen map[portClass]map[string]bool
}

type portClass struct {
	port  int
	class string
}

func newPortConflictIndex() *portConflictIndex {
	return &portConflictIndex{wild: map[portClass]bool{}, seen: map[portClass]map[string]bool{}}
}

func normalizeListen(listen string) string {
	if listen == "" || listen == "0.0.0.0" || listen == "::" {
		return "*"
	}
	return listen
}

func (idx *portConflictIndex) conflicts(port int, class, listen string) bool {
	key := portClass{port, class}
	if idx.wild[key] {
		return true
	}
	norm := normalizeListen(listen)
	if norm == "*" {
		return len(idx.seen[key]) > 0
	}
	return idx.seen[key][norm]
}

func (idx *portConflictIndex) claim(port int, class, listen string) {
	key := portClass{port, class}
	if normalizeListen(listen) == "*" {
		idx.wild[key] = true
		return
	}
	if idx.seen[key] == nil {
		idx.seen[key] = map[string]bool{}
	}
	idx.seen[key][normalizeListen(listen)] = true
}

func nodePortClasses(protocol string) []string {
	if protocol == "ss" {
		return []string{"tcp", "udp"}
	}
	return []string{"tcp"}
}

// ValidateDesired validates the exact configuration accepted by the Linux helper.
func ValidateDesired(state shared.DesiredState) error {
	if state.Revision <= 0 || len(state.Nodes) > 500 || len(state.Rules) > 2000 || len(state.Forwards) > 500 {
		return errors.New("invalid desired state size or revision")
	}
	// nodeIndex holds every node (node-node conflicts ignore Enabled);
	// liveIndex holds only live nodes plus forwards, because a forward
	// only conflicts with a node that is actually listening.
	nodeIndex := newPortConflictIndex()
	liveIndex := newPortConflictIndex()
	for _, item := range state.Nodes {
		if !safeNodeID.MatchString(item.Node.ID) {
			return errors.New("invalid node ID")
		}
		if len(item.Users) > 128 {
			return errors.New("too many node users")
		}
		if len(item.CertificatePEM) > 1<<20 || len(item.CertificateKey) > 1<<20 {
			return errors.New("node certificate too large")
		}
		var cert *shared.Certificate
		// A disabled node gets no inbound, so its certificate is not looked at;
		// an expired one must not block every other change on this server.
		if item.Node.Protocol == "anytls" && item.Node.Enabled {
			expiry, _, err := shared.CertificateInfo(item.CertificatePEM, item.CertificateKey)
			if err != nil {
				return fmt.Errorf("节点 %q 证书无效: %w", item.Node.Name, err)
			}
			if shared.CertificateCovers(item.CertificatePEM, item.Node.TLSName) {
				cert = &shared.Certificate{Domain: item.Node.TLSName, ExpiresAt: expiry}
			}
		} else if item.Node.Protocol == "anytls" {
			cert = &shared.Certificate{Domain: item.Node.TLSName}
		}
		if err := shared.ValidateNode(item.Node, cert, true); err != nil {
			return fmt.Errorf("节点 %q: %w", item.Node.Name, err)
		}
		if len(item.Password) < 8 {
			return errors.New("invalid node password")
		}
		if item.Node.Protocol == "snell" && item.Node.ShadowTLSHost != "" && len(item.ShadowTLSPassword) < 8 {
			return errors.New("invalid ShadowTLS password")
		}
		for _, class := range nodePortClasses(item.Node.Protocol) {
			if nodeIndex.conflicts(item.Node.Port, class, item.Node.Listen) {
				return errors.New("duplicate node port")
			}
		}
		for _, class := range nodePortClasses(item.Node.Protocol) {
			nodeIndex.claim(item.Node.Port, class, item.Node.Listen)
			if item.Node.Enabled && !item.Node.Deleting {
				liveIndex.claim(item.Node.Port, class, item.Node.Listen)
			}
		}
	}
	for _, rule := range state.Rules {
		if !safeRuleID.MatchString(rule.ID) {
			return errors.New("invalid firewall rule ID")
		}
		if rule.PortFrom < 1 || rule.PortTo < rule.PortFrom || rule.PortTo > 65535 || (rule.Network != "tcp" && rule.Network != "udp") || (rule.Action != "allow" && rule.Action != "deny") {
			return errors.New("invalid firewall rule")
		}
		if rule.Source != "" {
			if _, _, err := net.ParseCIDR(rule.Source); err != nil {
				return err
			}
		}
	}
	for _, f := range state.Forwards {
		if !safeRuleID.MatchString(f.ID) {
			return errors.New("invalid forward ID")
		}
		if err := shared.ValidateForward(f); err != nil {
			return fmt.Errorf("转发 %q: %w", f.Name, err)
		}
		if !f.Enabled || f.Deleting {
			continue
		}
		// The live index holds every live node (an ss node claimed both
		// tcp and udp) and every earlier forward, so one lookup covers
		// forward-forward and forward-node conflicts together.
		if liveIndex.conflicts(f.Port, f.Network, f.Listen) {
			return errors.New("forward port conflicts with another forward or node")
		}
		liveIndex.claim(f.Port, f.Network, f.Listen)
	}
	return nil
}

func validateDesired(state shared.DesiredState) error { return ValidateDesired(state) }
