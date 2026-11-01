package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
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

// panelObservedIPv4 makes a separate, signed IPv4-only request to the panel.
// A host behind NAT cannot read its public IPv4 from its own interfaces; the
// panel can see it when reached directly over IPv4. Never bypass an Agent's
// configured SOCKS5 proxy or mistake the proxy exit for the host's address.
func panelObservedIPv4(ctx context.Context, c Config) string {
	if c.AgentProxy != nil && c.AgentProxy.Host != "" {
		return ""
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", address)
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var result struct {
		IPv4 string `json:"ipv4"`
	}
	headers := map[string]string{"X-Server-ID": c.ServerID, "Authorization": "Bearer " + c.Token}
	if err := sendJSON(ctx, client, "GET", strings.TrimRight(c.URL, "/")+"/agent/observed-ipv4", nil, headers, &result, c.Token); err != nil {
		return ""
	}
	return validPublicIPv4(result.IPv4)
}

var agentCGNAT = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func validPublicIPv4(raw string) string {
	ip := net.ParseIP(raw)
	if ip == nil || ip.To4() == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || agentCGNAT.Contains(ip) {
		return ""
	}
	return ip.String()
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
