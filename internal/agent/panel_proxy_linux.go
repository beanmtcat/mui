//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"mui/internal/shared"
)

func proxyMatches(p *shared.SOCKS5Proxy) bool {
	if p == nil {
		return true
	}
	c, err := ReadConfig()
	return err == nil && proxyEqual(c.AgentProxy, p)
}

func prepareAgentProxy(state shared.DesiredState, raw []byte) error {
	if state.AgentProxy == nil || proxyMatches(state.AgentProxy) {
		return nil
	}
	key, err := panelPublicKey()
	if err != nil {
		return err
	}
	if key == nil || state.Signature == "" {
		return errors.New("Agent proxy changes require a pinned panel key and a signed configuration")
	}
	if len(raw) > 0 {
		err = shared.VerifyDesiredStateRaw(key, raw)
	} else {
		err = shared.VerifyDesiredState(key, state)
	}
	if err != nil {
		return err
	}
	c, err := ReadConfig()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := checkProxyPanel(ctx, c, state.AgentProxy); err != nil {
		return errors.New("new Agent connection failed; previous proxy retained: " + err.Error())
	}
	return nil
}

func saveAgentProxy(p *shared.SOCKS5Proxy) error {
	if p == nil || proxyMatches(p) {
		return nil
	}
	c, err := ReadConfig()
	if err != nil {
		return err
	}
	c.AgentProxy = p
	if p.Host == "" {
		c.AgentProxy = nil
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return writeOwned(ConfigDir+"/config.json", b, 0640, agentUser)
}
