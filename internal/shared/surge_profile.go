package shared

import (
	_ "embed"
	"errors"
	"fmt"
	"strings"
)

// DefaultSurgeProfileTemplate is used until an administrator saves their own.
//
//go:embed surge_profile.conf
var DefaultSurgeProfileTemplate string

const maxSurgeProfileTemplate = 64 << 10

// Surge's built-in policies; a node with one of these names would be
// indistinguishable from the policy.
var surgeBuiltinPolicies = []string{"DIRECT", "REJECT", "REJECT-TINYGIF", "REJECT-DROP", "REJECT-NO-DROP"}

// ValidateSurgeProfileTemplate rejects templates Surge would refuse or that
// could not receive the subscription's nodes. CRLF is normalised first.
func ValidateSurgeProfileTemplate(template string) (string, error) {
	template = strings.ReplaceAll(template, "\r\n", "\n")
	if len(template) > maxSurgeProfileTemplate {
		return "", errors.New("Surge 配置模板不能超过 64 KiB")
	}
	if strings.ContainsAny(template, "\x00\r") {
		return "", errors.New("Surge 配置模板包含无效字符")
	}
	if !strings.Contains(template, "{{PROXIES}}") {
		return "", errors.New("Surge 配置模板需要包含 {{PROXIES}}，用于放入订阅节点")
	}
	rules := surgeSection(template, "Rule")
	if len(rules) == 0 || !strings.HasPrefix(strings.ToUpper(rules[len(rules)-1]), "FINAL,") {
		return "", errors.New("Surge 配置模板的 [Rule] 段必须以 FINAL 规则结尾")
	}
	return template, nil
}

// surgeSection returns the non-empty, non-comment lines of one section.
func surgeSection(profile, name string) []string {
	var lines []string
	inside := false
	for _, line := range strings.Split(profile, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inside = strings.EqualFold(line, "["+name+"]")
			continue
		}
		if inside && line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "//") && !strings.HasPrefix(line, ";") {
			lines = append(lines, line)
		}
	}
	return lines
}

// RenderSurgeProfile fills a profile template with the Surge node list, for
// "Install Config from URL". {{PROXIES}} receives the node lines and
// {{PROXY_NAMES}} their comma-separated names. MANAGED-CONFIG is always the
// first line, so Surge refreshes from the same link; strict=false keeps the
// last copy when an update fails. An empty template means the default.
func RenderSurgeProfile(items []SubscriptionItem, managedURL, template string) ([]byte, []string, error) {
	if template == "" {
		template = DefaultSurgeProfileTemplate
	}
	template, err := ValidateSurgeProfileTemplate(template)
	if err != nil {
		return nil, nil, err
	}
	list, excluded, err := RenderSubscription("surge", items)
	if err != nil {
		return nil, excluded, err
	}
	taken := map[string]bool{}
	for _, name := range surgeBuiltinPolicies {
		taken[name] = true
	}
	for _, line := range surgeSection(template, "Proxy Group") {
		if name, _, ok := strings.Cut(line, "="); ok {
			taken[strings.TrimSpace(name)] = true
		}
	}
	var proxies, names []string
	for _, line := range strings.Split(strings.TrimSuffix(string(list), "\n"), "\n")[1:] {
		name, _, _ := strings.Cut(line, " = ")
		if taken[name] {
			excluded = append(excluded, name+": 与 Surge 配置模板中的代理组或内置策略重名")
			continue
		}
		taken[name] = true
		proxies = append(proxies, line)
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, excluded, errors.New("没有可用于 Surge 的节点")
	}
	var lines []string
	for _, line := range strings.Split(template, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#!MANAGED-CONFIG") {
			lines = append(lines, line)
		}
	}
	body := strings.TrimSpace(strings.Join(lines, "\n"))
	body = strings.ReplaceAll(body, "{{PROXIES}}", strings.Join(proxies, "\n"))
	body = strings.ReplaceAll(body, "{{PROXY_NAMES}}", strings.Join(names, ", "))
	return []byte(fmt.Sprintf("#!MANAGED-CONFIG %s interval=43200 strict=false\n\n%s\n", managedURL, body)), excluded, nil
}
