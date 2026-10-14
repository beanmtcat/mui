package shared

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
)

type SubscriptionItem struct {
	Node              Node
	Server            Server
	Password          string
	UserKey           string
	ShadowTLSPassword string
}

func PublishedAddress(item SubscriptionItem) string {
	if item.Node.PublishAddress != "" {
		return item.Node.PublishAddress
	}
	if item.Server.Domain != "" {
		return item.Server.Domain
	}
	if item.Server.IPv4 != "" {
		return item.Server.IPv4
	}
	return item.Server.IPv6
}

func RenderSubscription(format string, items []SubscriptionItem) ([]byte, []string, error) {
	excluded := []string{}
	switch format {
	case "sing-box":
		outbounds := []map[string]any{}
		for _, item := range items {
			n := item.Node
			if !n.Enabled || n.Status != "active" {
				excluded = append(excluded, n.Name+": 节点未生效或已停用")
				continue
			}
			address := PublishedAddress(item)
			if address == "" {
				excluded = append(excluded, n.Name+": 无发布地址")
				continue
			}
			out := map[string]any{"tag": subscriptionTag(n), "server": address, "server_port": n.Port}
			var shadowOutbound map[string]any
			switch n.Protocol {
			case "ss":
				out["type"] = "shadowsocks"
				out["method"] = n.Method
				out["password"] = item.Password
			case "snell":
				out["type"] = "snell"
				out["version"] = 4
				out["psk"] = item.Password
				if item.UserKey != "" {
					out["userkey"] = item.UserKey
				}
				if n.Obfs != "" && n.Obfs != "none" {
					out["obfs_mode"] = n.Obfs
				}
				if n.ShadowTLSHost != "" {
					if item.ShadowTLSPassword == "" {
						excluded = append(excluded, n.Name+": 缺少 ShadowTLS 密码")
						continue
					}
					shadowTag := "shadowtls-" + n.ID
					out["detour"] = shadowTag
					shadowOutbound = map[string]any{
						"type": "shadowtls", "tag": shadowTag,
						"server": address, "server_port": n.Port,
						"version": 3, "password": item.ShadowTLSPassword,
						"tls": map[string]any{"enabled": true, "server_name": n.ShadowTLSHost},
					}
				}
			case "anytls":
				out["type"] = "anytls"
				out["password"] = item.Password
				out["tls"] = map[string]any{"enabled": true, "server_name": n.TLSName}
			default:
				excluded = append(excluded, n.Name+": 不支持的协议")
				continue
			}
			outbounds = append(outbounds, out)
			if shadowOutbound != nil {
				outbounds = append(outbounds, shadowOutbound)
			}
		}
		b, err := json.MarshalIndent(map[string]any{"outbounds": outbounds}, "", "  ")
		return b, excluded, err
	case "surge":
		lines := []string{"[Proxy]"}
		for _, item := range items {
			n := item.Node
			if !n.Enabled || n.Status != "active" {
				excluded = append(excluded, n.Name+": 节点未生效或已停用")
				continue
			}
			address := PublishedAddress(item)
			if address == "" {
				excluded = append(excluded, n.Name+": 无发布地址")
				continue
			}
			if strings.ContainsAny(n.Name, "=\r\n,#[]") {
				excluded = append(excluded, n.Name+": 名称包含 Surge 保留字符")
				continue
			}
			if strings.ContainsAny(item.Password+item.ShadowTLSPassword, ",\r\n") {
				excluded = append(excluded, n.Name+": 密码包含 Surge 保留字符")
				continue
			}
			switch n.Protocol {
			case "ss":
				if n.Method != "2022-blake3-aes-128-gcm" && n.Method != "2022-blake3-aes-256-gcm" {
					excluded = append(excluded, n.Name+": Surge 订阅仅支持 AES-GCM 的 SS 2022 节点")
					continue
				}
				lines = append(lines, fmt.Sprintf("%s = ss, %s, %d, encrypt-method=%s, password=%s", subscriptionTag(n), address, n.Port, n.Method, item.Password))
			case "snell":
				// A per-user Snell key is a sing-box extension Surge cannot send.
				if n.ShadowTLSHost == "" || item.ShadowTLSPassword == "" || item.UserKey != "" {
					excluded = append(excluded, n.Name+": Surge 订阅中的 Snell 节点需启用 ShadowTLS，且服务器 Agent 需为新版")
					continue
				}
				line := fmt.Sprintf("%s = snell, %s, %d, psk=%s, version=4", subscriptionTag(n), address, n.Port, item.Password)
				if n.Obfs == "http" {
					line += ", obfs=http"
				}
				lines = append(lines, line+fmt.Sprintf(", shadow-tls-password=%s, shadow-tls-sni=%s, shadow-tls-version=3", item.ShadowTLSPassword, n.ShadowTLSHost))
			default:
				excluded = append(excluded, n.Name+": Surge 订阅暂不支持 AnyTLS 节点")
			}
		}
		return []byte(strings.Join(lines, "\n") + "\n"), excluded, nil
	default:
		return nil, nil, fmt.Errorf("不支持的订阅格式 %q", format)
	}
}

func subscriptionTag(n Node) string {
	id := n.ID
	if len(id) > 8 {
		id = id[:8]
	}
	return n.Name + "-" + id
}

func ShareURI(item SubscriptionItem) (string, error) {
	n := item.Node
	a := PublishedAddress(item)
	if a == "" {
		return "", fmt.Errorf("缺少发布地址")
	}
	address := net.JoinHostPort(a, fmt.Sprint(n.Port))
	switch n.Protocol {
	case "ss":
		return "ss://" + base64.RawURLEncoding.EncodeToString([]byte(n.Method+":"+item.Password)) + "@" + address + "#" + url.QueryEscape(n.Name), nil
	case "anytls":
		return "anytls://" + url.QueryEscape(item.Password) + "@" + address + "?sni=" + url.QueryEscape(n.TLSName) + "#" + url.QueryEscape(n.Name), nil
	default:
		return "", fmt.Errorf("该协议使用订阅配置")
	}
}
