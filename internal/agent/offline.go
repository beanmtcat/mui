package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"mui/internal/shared"
)

const OfflineModePath = ForwardDir + "/offline.json"
const OfflineReleaseKeyPath = ForwardDir + "/release.pub"

// IDs stay stable when editing endpoints so the reload can preserve every
// unchanged rule's connections and counters. Human-readable IDs are supported.
var offlineRuleID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$`)

const OfflineForwardExample = shared.OfflineForwardExample

func InitOfflineForwards(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.WriteString(OfflineForwardExample); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

// ReadOfflineForwards performs structural checks only: it never resolves a
// hostname, contacts a destination, binds a socket or modifies the firewall.
func ReadOfflineForwards(path string) ([]shared.ForwardRule, []byte, error) {
	rules, raw, _, err := readOfflineDocument(path)
	return rules, raw, err
}

func parseOfflineForwards(raw []byte) ([]shared.ForwardRule, []byte, error) {
	if len(raw) > 1<<20 {
		return nil, nil, errors.New("转发配置不能超过 1 MiB")
	}
	// A pointer distinguishes omitted Enabled (default true) from false.
	var input []struct {
		shared.ForwardRule
		Enabled *bool `json:"enabled"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		return nil, nil, fmt.Errorf("转发配置必须为 JSON 数组: %w", err)
	}
	if input == nil || len(input) > 500 {
		return nil, nil, errors.New("转发配置必须为数组，最多 500 条；清空规则请使用 []")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, nil, errors.New("转发配置末尾存在多余内容")
	}
	rules := make([]shared.ForwardRule, 0, len(input))
	ids := map[string]bool{}
	ports := newPortConflictIndex()
	for _, item := range input {
		rule := item.ForwardRule
		if !offlineRuleID.MatchString(rule.ID) || ids[rule.ID] {
			return nil, nil, fmt.Errorf("转发 ID %q 无效或重复，使用 1–100 位字母、数字、点、横线或下划线", rule.ID)
		}
		ids[rule.ID] = true
		rule.Enabled = item.Enabled == nil || *item.Enabled
		if rule.Name == "" {
			rule.Name = rule.ID
		}
		if rule.Listen == "" {
			rule.Listen = "0.0.0.0"
		}
		if rule.Balance == "" {
			rule.Balance = "failover"
		}
		if rule.FirewallPolicy != "" && rule.FirewallPolicy != "manual" || rule.FirewallSources != "" {
			return nil, nil, fmt.Errorf("转发 %q: 离线模式不操作 UFW，firewallPolicy 必须为 manual，来源限制请在防火墙配置", rule.ID)
		}
		rule.FirewallPolicy = "manual"
		if rule.Deleting {
			return nil, nil, fmt.Errorf("转发 %q: 删除规则请从数组移除，不能设置 deleting", rule.ID)
		}
		if err := validateForwardRule(rule); err != nil {
			return nil, nil, fmt.Errorf("转发 %q: %w", rule.ID, err)
		}
		if rule.Enabled {
			for _, network := range shared.ForwardNetworks(rule.Network) {
				if ports.conflicts(rule.Port, network, rule.Listen) {
					return nil, nil, fmt.Errorf("转发 %q 监听端口冲突（%s）", rule.ID, network)
				}
				ports.claim(rule.Port, network, rule.Listen)
			}
		}
		rules = append(rules, rule)
	}
	canonical, err := json.MarshalIndent(rules, "", "  ")
	return rules, canonical, err
}
