package shared

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// StatsAPIPort is the loopback port of the sing-box statistics API on every managed server.
const StatsAPIPort = 10085
const ConnectionsAPIPort = 10086

func ValidateNodeTemplate(t NodeTemplate) error {
	n := Node{
		Name: t.Name, Protocol: t.Protocol, Username: t.Username, Port: t.Port,
		Listen: t.Listen, Method: t.Method, SnellVersion: t.SnellVersion, SnellPort: t.SnellPort,
		Obfs: t.Obfs, ShadowTLSHost: t.ShadowTLSHost, TLSName: t.TLSName,
	}
	var cert *Certificate
	if t.Protocol == "anytls" && t.TLSName != "" {
		cert = &Certificate{Domain: t.TLSName, ExpiresAt: time.Now().Add(time.Hour)}
	}
	return ValidateNode(n, cert, false)
}

// ValidateNode checks a node definition. allowExpired skips the certificate expiry
// check: an expired certificate must not stop the node from being disabled or the
// rest of the server from being reconfigured.
func ValidateNode(n Node, cert *Certificate, allowExpired bool) error {
	if strings.TrimSpace(n.Name) == "" || len(n.Name) > 100 {
		return errors.New("节点名称不能为空且不能超过 100 字符")
	}
	// Nodes run as the unprivileged mui-core user, which cannot bind privileged
	// ports; forwards already enforce the same floor in ValidateForward.
	// sing-box runs with CAP_NET_BIND_SERVICE, so privileged ports such as 443
	// (the usual choice for AnyTLS and ShadowTLS) are fine.
	if n.Port < 1 || n.Port > 65535 {
		return errors.New("端口必须在 1-65535 之间")
	}
	if n.Port == StatsAPIPort || n.Port == ConnectionsAPIPort {
		return fmt.Errorf("端口 %d 保留给本机统计接口", n.Port)
	}
	if n.Listen == "" {
		n.Listen = "0.0.0.0"
	}
	if ip := net.ParseIP(n.Listen); ip == nil {
		return errors.New("监听地址必须是 IP")
	}
	if _, _, err := NormalizeFirewallAccess(n.FirewallPolicy, n.FirewallSources); err != nil {
		return err
	}
	switch n.Protocol {
	case "ss":
		if n.Method == "" {
			n.Method = "2022-blake3-aes-128-gcm"
		}
		switch n.Method {
		case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305":
		default:
			return errors.New("不支持的 SS 加密方式")
		}
	case "snell":
		if n.ShadowTLSHost != "" {
			port := SnellListenPort(n)
			if port < 1 || port > 65535 || port == n.Port || port == StatsAPIPort || port == ConnectionsAPIPort {
				return errors.New("Snell 内层端口必须在 1–65535 之间，且不能与公网端口或统计接口端口相同")
			}
		}
		if n.SnellVersion != 0 && n.SnellVersion != 5 && n.SnellVersion != 6 {
			return errors.New("Snell 版本仅支持 v5 或 v6")
		}
		if n.Obfs != "" && n.Obfs != "none" && n.Obfs != "http" {
			return errors.New("不支持的 Snell 混淆方式")
		}
		if n.ShadowTLSHost != "" && !validShadowTLSHost(n.ShadowTLSHost) {
			return errors.New("ShadowTLS SNI 必须是有效的域名")
		}
	case "socks5":
		if strings.HasPrefix(n.Username, "mui-") {
			return errors.New("用户名 mui- 前缀保留给订阅独立凭据，请使用其他用户名")
		}
		if err := ValidateSOCKS5Credentials(n.Username, "placeholder"); err != nil {
			return err
		}
	case "anytls":
		if n.TLSName == "" || cert == nil {
			return errors.New("AnyTLS 需要域名和有效证书")
		}
		if !allowExpired && time.Now().After(cert.ExpiresAt) {
			return errors.New("证书已过期")
		}
		matches := strings.EqualFold(n.TLSName, cert.Domain)
		if cert.PEM != "" {
			// A shared certificate can cover multiple DNS names or a wildcard.
			matches = CertificateCovers(cert.PEM, n.TLSName)
		}
		if !matches {
			return errors.New("证书域名与节点域名不匹配")
		}
	default:
		return errors.New("不支持的协议")
	}
	if n.Protocol != "snell" && n.ShadowTLSHost != "" {
		return errors.New("只有 Snell 节点可以设置 ShadowTLS")
	}
	return nil
}

// Zero is the original persisted v5 setting. New nodes/templates explicitly
// default to v6; reading an existing node must not change its wire protocol.
func SnellVersion(n Node) int {
	if n.SnellVersion == 0 {
		return 5
	}
	return n.SnellVersion
}

func ValidateSnellPSK(n Node, password string) error {
	if n.Protocol == "snell" && SnellVersion(n) == 6 && (len(password) < 12 || len(password) > 255) {
		return errors.New("Snell v6 PSK 必须是 12–255 字节")
	}
	return nil
}

// NormalizeFirewallAccess accepts IP addresses and CIDRs and turns each source
// into a canonical CIDR. An empty policy retains the behavior of older nodes.
func NormalizeFirewallAccess(policy, sources string) (string, string, error) {
	if policy == "" {
		policy = "all"
	}
	if policy != "all" && policy != "restricted" && policy != "manual" && policy != "closed" {
		return "", "", errors.New("节点防火墙模式无效")
	}
	if policy != "restricted" {
		if strings.TrimSpace(sources) != "" {
			return "", "", errors.New("只有指定来源模式可以填写来源 IP")
		}
		return policy, "", nil
	}
	parts := strings.FieldsFunc(sources, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
	if len(parts) == 0 || len(parts) > 256 {
		return "", "", errors.New("指定来源模式需要 1–256 个 IP 或 CIDR")
	}
	seen := make(map[string]bool, len(parts))
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		var prefix netip.Prefix
		if addr, err := netip.ParseAddr(part); err == nil {
			if addr.Zone() != "" {
				return "", "", errors.New("来源 IP 不能包含网卡区域")
			}
			addr = addr.Unmap()
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		} else {
			prefix, err = netip.ParsePrefix(part)
			if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
				return "", "", fmt.Errorf("来源 %q 不是有效 IP 或 CIDR", part)
			}
		}
		canonical := prefix.Masked().String()
		if !seen[canonical] {
			seen[canonical] = true
			normalized = append(normalized, canonical)
		}
	}
	return policy, strings.Join(normalized, ","), nil
}

// NormalizeAdminFirewallAccess is NormalizeFirewallAccess for what an
// administrator types: at most 32 sources, and no "closed", which only the
// panel sets. Lists the panel generates for routes may be longer.
func NormalizeAdminFirewallAccess(policy, sources string) (string, string, error) {
	if policy == "closed" {
		return "", "", errors.New("节点防火墙模式无效")
	}
	policy, sources, err := NormalizeFirewallAccess(policy, sources)
	if err == nil && strings.Count(sources, ",") >= 32 {
		err = errors.New("指定来源模式需要 1–32 个 IP 或 CIDR")
	}
	return policy, sources, err
}

func validShadowTLSHost(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

// CertificateInfo checks that the certificate and key belong together and returns
// the leaf's expiry and DNS names without judging whether it is currently valid.
func CertificateInfo(certPEM, keyPEM string) (time.Time, []string, error) {
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return time.Time{}, nil, err
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}, nil, errors.New("证书 PEM 无效")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, nil, err
	}
	return cert.NotAfter, cert.DNSNames, nil
}

func ParseCertificate(certPEM, keyPEM string) (time.Time, []string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if _, _, err := CertificateInfo(certPEM, keyPEM); err != nil {
		return time.Time{}, nil, err
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, nil, err
	}
	if time.Now().After(cert.NotAfter) {
		return time.Time{}, nil, errors.New("证书已过期")
	}
	if time.Now().Before(cert.NotBefore) {
		return time.Time{}, nil, errors.New("证书尚未生效")
	}
	return cert.NotAfter, cert.DNSNames, nil
}

// CheckCertificateServerAuth rejects CA certificates outright. When the leaf
// carries an extended-key-usage extension it must include ServerAuth; a leaf
// with no EKU extension is accepted, matching x509 semantics where an absent
// EKU means "any usage" (common for self-signed certificates).
func CheckCertificateServerAuth(certPEM, keyPEM string) error {
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("证书 PEM 无效")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if cert.IsCA {
		return errors.New("CA 证书不能用作服务器证书")
	}
	if len(cert.ExtKeyUsage) > 0 || len(cert.UnknownExtKeyUsage) > 0 {
		for _, usage := range cert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth {
				return nil
			}
		}
		return errors.New("证书缺少 ServerAuth 用途")
	}
	return nil
}

// CertExpiryStatus reports whole days until expiry and whether the
// certificate is expiring soon (30 days or fewer, including already expired).
func CertExpiryStatus(expiresAt time.Time) (days int, expiringSoon bool) {
	days = int(time.Until(expiresAt).Hours() / 24)
	return days, days <= 30
}

func CertificateCovers(certPEM, hostname string) bool {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	return err == nil && cert.VerifyHostname(hostname) == nil
}

func SingBoxConfig(nodes []ManagedNode, certDir string) ([]byte, error) {
	inbounds := make([]map[string]any, 0, len(nodes))
	tags := make([]string, 0, len(nodes))
	userNames := make([]string, 0)
	for _, item := range nodes {
		n := item.Node
		if !n.Enabled {
			continue
		}
		if n.Listen == "" {
			n.Listen = "0.0.0.0"
		}
		tag := "node-" + n.ID
		base := map[string]any{"tag": tag, "listen": n.Listen, "listen_port": n.Port}
		switch n.Protocol {
		case "ss":
			base["type"] = "shadowsocks"
			base["method"] = n.Method
			base["password"] = item.Password
			if len(item.Users) > 0 {
				if !SSMultiUser(n.Method) {
					return nil, fmt.Errorf("SS 节点 %q 的加密方式不支持多用户", n.Name)
				}
				users := make([]map[string]string, 0, len(item.Users))
				for _, user := range item.Users {
					users = append(users, map[string]string{"name": user.Name, "password": user.Password})
					if user.SubscriptionID != "direct" {
						userNames = append(userNames, user.Name)
					}
				}
				base["users"] = users
			}
		case "snell":
			base["type"] = "snell"
			base["version"] = SnellVersion(n)
			if err := ValidateSnellPSK(n, item.Password); err != nil {
				return nil, err
			}
			base["psk"] = item.Password
			if SnellVersion(n) == 5 {
				base["obfs_mode"] = n.Obfs
			} else {
				base["mode"] = "default"
			}
			// Behind ShadowTLS each subscription is authenticated by its own
			// ShadowTLS password and Snell itself stays single-user: stock Snell
			// clients such as Surge have no per-user key to send. sing-box carries
			// the ShadowTLS user name into the statistics, so traffic is still
			// attributed per subscription.
			if n.ShadowTLSHost == "" && len(item.Users) > 0 {
				users := make([]map[string]string, 0, len(item.Users))
				for _, user := range item.Users {
					users = append(users, map[string]string{"name": user.Name, "userkey": user.Password})
					userNames = append(userNames, user.Name)
				}
				base["users"] = users
			}
			if n.ShadowTLSHost != "" {
				if item.ShadowTLSPassword == "" {
					return nil, fmt.Errorf("Snell 节点 %q 缺少 ShadowTLS 密码", n.Name)
				}
				base["listen"] = "127.0.0.1"
				base["listen_port"] = SnellListenPort(n)
				shadowUsers := []map[string]string{{"name": n.ID, "password": item.ShadowTLSPassword}}
				for _, user := range item.Users {
					shadowUsers = append(shadowUsers, map[string]string{"name": user.Name, "password": user.ShadowTLSPassword})
					userNames = append(userNames, user.Name)
				}
				inbounds = append(inbounds, map[string]any{
					"type": "shadowtls", "tag": "shadowtls-" + n.ID,
					"listen": n.Listen, "listen_port": n.Port, "detour": tag,
					"version": 3, "users": shadowUsers,
					"handshake":   map[string]any{"server": n.ShadowTLSHost, "server_port": 443},
					"strict_mode": true,
				})
			}
		case "socks5":
			if err := ValidateSOCKS5Credentials(n.Username, item.Password); err != nil {
				return nil, err
			}
			base["type"] = "socks"
			users := []map[string]string{{"username": n.Username, "password": item.Password}}
			for _, user := range item.Users {
				if err := ValidateSOCKS5Credentials(user.Name, user.Password); err != nil {
					return nil, err
				}
				users = append(users, map[string]string{"username": user.Name, "password": user.Password})
				userNames = append(userNames, user.Name)
			}
			base["users"] = users
		case "anytls":
			base["type"] = "anytls"
			users := []map[string]string{{"name": n.ID, "password": item.Password}}
			for _, user := range item.Users {
				users = append(users, map[string]string{"name": user.Name, "password": user.Password})
				userNames = append(userNames, user.Name)
			}
			base["users"] = users
			base["tls"] = map[string]any{"enabled": true, "server_name": n.TLSName, "certificate_path": fmt.Sprintf("%s/%s.crt", certDir, n.ID), "key_path": fmt.Sprintf("%s/%s.key", certDir, n.ID)}
		default:
			return nil, fmt.Errorf("unsupported protocol %q", n.Protocol)
		}
		inbounds = append(inbounds, base)
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	sort.Strings(userNames)
	config := map[string]any{
		"log":          map[string]any{"level": "warn", "timestamp": true},
		"inbounds":     inbounds,
		"outbounds":    []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":        map[string]any{"final": "direct"},
		"experimental": map[string]any{"v2ray_api": map[string]any{"listen": fmt.Sprintf("127.0.0.1:%d", StatsAPIPort), "stats": map[string]any{"enabled": true, "inbounds": tags, "users": userNames}}, "clash_api": map[string]any{"external_controller": fmt.Sprintf("127.0.0.1:%d", ConnectionsAPIPort)}},
	}
	return json.MarshalIndent(config, "", "  ")
}

func SSMultiUser(method string) bool { return strings.HasPrefix(method, "2022-blake3-") }

// SharedSubscriptionPassword identifies single-user SS nodes. Their existing
// node password can be delivered in a subscription, but cannot identify which
// subscription a connection belongs to.
func SharedSubscriptionPassword(n Node) bool { return n.Protocol == "ss" && !SSMultiUser(n.Method) }

func ValidateForward(f ForwardRule) error {
	if strings.TrimSpace(f.Name) == "" || len(f.Name) > 100 {
		return errors.New("转发名称不能为空且不能超过 100 字符")
	}
	if len(ForwardNetworks(f.Network)) == 0 {
		return errors.New("转发协议只能是 TCP、UDP 或 TCP + UDP")
	}
	if f.Port < 1024 || f.Port > 65535 {
		return errors.New("监听端口必须为 1024–65535")
	}
	if f.Port == StatsAPIPort || f.Port == ConnectionsAPIPort {
		return errors.New("转发端口被本机统计接口占用")
	}
	if f.Listen != "" && net.ParseIP(f.Listen) == nil {
		return errors.New("监听地址必须是 IP")
	}
	if len(f.Targets) == 0 || len(f.Targets) > 16 {
		return errors.New("转发需要 1–16 个目标")
	}
	seen := map[string]bool{}
	for _, t := range f.Targets {
		if err := ValidateForwardTarget(t); err != nil {
			return err
		}
		key := strings.ToLower(t.Host) + ":" + strconv.Itoa(t.Port)
		if seen[key] {
			return errors.New("转发目标重复: " + t.Host)
		}
		seen[key] = true
	}
	if f.HealthCheck != "" && f.HealthCheck != "tcp" && f.HealthCheck != "none" {
		return errors.New("健康检查只能选择 TCP 或不主动探测")
	}
	if f.Balance != "" && f.Balance != "failover" && f.Balance != "round-robin" {
		return errors.New("负载均衡模式只能是主备或轮询")
	}
	_, _, err := NormalizeFirewallAccess(f.FirewallPolicy, f.FirewallSources)
	return err
}

func ValidateForwardTarget(t ForwardTarget) error {
	if t.Port < 1 || t.Port > 65535 {
		return errors.New("目标端口必须为 1–65535")
	}
	if t.Host == "" || len(t.Host) > 253 || t.Host != strings.TrimSpace(t.Host) {
		return errors.New("目标地址必须是 IP 或域名")
	}
	if net.ParseIP(t.Host) == nil && !validForwardHost(t.Host) {
		return errors.New("目标地址必须是 IP 或域名")
	}
	return nil
}

func validForwardHost(host string) bool {
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// SnellListenPort gives old saved nodes an explicit, reproducible port too.
// New nodes persist the chosen value; sing-box is never given port zero.
func SnellListenPort(n Node) int {
	if n.SnellPort != 0 {
		return n.SnellPort
	}
	return 20000 + n.Port%10000
}

type NodeListener struct {
	Port    int
	Listen  string
	Network string
}

func NodeListeners(n Node) []NodeListener {
	out := []NodeListener{{n.Port, n.Listen, "tcp"}}
	if n.Protocol == "ss" {
		out = append(out, NodeListener{n.Port, n.Listen, "udp"})
	}
	if n.Protocol == "snell" && n.ShadowTLSHost != "" {
		out = append(out, NodeListener{SnellListenPort(n), "127.0.0.1", "tcp"})
	}
	return out
}

func ListenerOverlap(a, b string) bool {
	return a == b || a == "" || b == "" || a == "0.0.0.0" || b == "0.0.0.0" || a == "::" || b == "::"
}

func PortConflict(a, b Node) bool {
	if a.ServerID != b.ServerID || a.ID == b.ID {
		return false
	}
	for _, al := range NodeListeners(a) {
		for _, bl := range NodeListeners(b) {
			if al.Port == bl.Port && al.Network == bl.Network && ListenerOverlap(al.Listen, bl.Listen) {
				return true
			}
		}
	}
	return false
}
