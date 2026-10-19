package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/net/proxy"
	"mui/internal/shared"
)

func proxyEqual(a, b *shared.SOCKS5Proxy) bool {
	empty := shared.SOCKS5Proxy{}
	if a == nil {
		a = &empty
	}
	if b == nil {
		b = &empty
	}
	return *a == *b
}

// Always use an explicit transport. In particular, a failed proxy never falls
// back to direct access and panel DNS is resolved by SOCKS, not the entry host.
func panelHTTPClient(p *shared.SOCKS5Proxy, timeout time.Duration) (*http.Client, error) {
	if err := shared.ValidateAgentProxy(p); err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = dialer.DialContext
	if p != nil && p.Host != "" {
		d, err := proxy.SOCKS5("tcp", net.JoinHostPort(p.Host, strconv.Itoa(p.Port)), &proxy.Auth{User: p.Username, Password: p.Password}, dialer)
		if err != nil {
			return nil, errors.New("cannot initialize SOCKS5 transport")
		}
		tr.DialContext = d.(proxy.ContextDialer).DialContext
	}
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// ReadProxyFile is used only by installation. Credentials stay out of argv and
// environment variables; generated installers create this file with umask 077.
func ReadProxyFile(path string) (*shared.SOCKS5Proxy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p shared.SOCKS5Proxy
	if err = json.Unmarshal(data, &p); err != nil {
		return nil, errors.New("invalid Agent proxy JSON")
	}
	if err = shared.ValidateAgentProxy(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

func checkProxyPanel(ctx context.Context, c Config, p *shared.SOCKS5Proxy) error {
	client, err := panelHTTPClient(p, 15*time.Second)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	// A signed agent poll proves the new path reaches the intended panel and
	// accepts this Agent's credentials; it must not claim or execute a job.
	return sendJSON(ctx, client, "POST", c.URL+"/agent/report", shared.AgentReport{}, map[string]string{"X-Server-ID": c.ServerID, "Authorization": "Bearer " + c.Token}, nil, c.Token)
}
