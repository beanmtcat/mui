package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	komarimonitor "github.com/komari-monitor/komari-agent/monitoring"
	komariunit "github.com/komari-monitor/komari-agent/monitoring/unit"
	komariv2 "github.com/komari-monitor/komari-agent/protocol/v2"
)

// Komari is an optional second reporting destination for the same mui-agent
// process. It has no command, terminal, file, startup-config, or update path.
type KomariConfig struct {
	Endpoint string `json:"endpoint"`
	Token    string `json:"token"`
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
}

// The MUI panel supplies this config over the signed Agent channel. The
// Komari token never needs to be placed in an installation command or file.
func fetchKomariConfig(ctx context.Context, c Config) (KomariConfig, error) {
	client, err := panelHTTPClient(c.AgentProxy, 15*time.Second)
	if err != nil {
		return KomariConfig{}, err
	}
	defer client.CloseIdleConnections()
	var out KomariConfig
	headers := map[string]string{"X-Server-ID": c.ServerID, "Authorization": "Bearer " + c.Token}
	if err := sendJSON(ctx, client, http.MethodGet, strings.TrimRight(c.URL, "/")+"/agent/komari", nil, headers, &out, c.Token); err != nil {
		return KomariConfig{}, err
	}
	if out.Token == "" && out.Endpoint == "" {
		return KomariConfig{}, nil
	}
	if out.Token == "" || out.Endpoint == "" {
		return KomariConfig{}, errors.New("incomplete Komari configuration")
	}
	if _, err := checkPanelURL(out.Endpoint); err != nil {
		return KomariConfig{}, errors.New("invalid Komari endpoint")
	}
	return out, nil
}

// Existing and newly installed Agents fetch immediately, then watch for
// endpoint or token changes. Without both values, no Komari worker runs.
func runKomariManager(ctx context.Context, c Config) {
	var current KomariConfig
	var cancel context.CancelFunc
	var done chan struct{}
	stop := func() {
		if cancel != nil {
			cancel()
			<-done
			cancel, done = nil, nil
		}
	}
	defer stop()
	refresh := func() bool {
		latest, err := ReadConfig()
		if err == nil && latest.ServerID == c.ServerID && latest.Token == c.Token && latest.URL == c.URL {
			c = latest
		}
		call, finish := context.WithTimeout(ctx, 15*time.Second)
		next, err := fetchKomariConfig(call, c)
		finish()
		if err != nil {
			if ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "komari config fetch:", err)
			}
			return false
		}
		if next == current {
			return true
		}
		stop()
		current = next
		if next.Token == "" {
			return true
		}
		workerCtx, workerCancel := context.WithCancel(ctx)
		cancel, done = workerCancel, make(chan struct{})
		go func() {
			defer close(done)
			runKomari(workerCtx, next)
		}()
		return true
	}
	success := refresh()
	timer := time.NewTimer(komariPollInterval(current, success))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			success = refresh()
			timer.Reset(komariPollInterval(current, success))
		}
	}
}

func komariPollInterval(config KomariConfig, fetchSucceeded bool) time.Duration {
	if fetchSucceeded && config.Token == "" {
		return 5 * time.Minute
	}
	return 30 * time.Second
}

type komariClient struct {
	endpoint string
	http     *http.Client
	tcpPing  func(context.Context, string) int
}

func newKomariClient(config KomariConfig) (*komariClient, error) {
	if strings.TrimSpace(config.Token) == "" {
		return nil, errors.New("Komari token is required")
	}
	u, err := checkPanelURL(config.Endpoint)
	if err != nil {
		return nil, err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/clients/v2/rpc"
	q := u.Query()
	q.Set("token", config.Token)
	u.RawQuery = q.Encode()
	return &komariClient{endpoint: u.String(), http: &http.Client{Timeout: 35 * time.Second}}, nil
}

// runKomari is isolated from MUI's panel loop. A Komari outage never blocks
// jobs, node configuration, or reports to the MUI panel.
func runKomari(ctx context.Context, config KomariConfig) {
	client, err := newKomariClient(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "komari config:", err)
		return
	}
	pullDone := make(chan struct{})
	go func() {
		defer close(pullDone)
		client.pull(ctx)
	}()
	defer func() {
		<-pullDone
		client.http.CloseIdleConnections()
	}()

	reportTicker := time.NewTicker(3 * time.Second)
	defer reportTicker.Stop()
	infoTicker := time.NewTicker(5 * time.Minute)
	defer infoTicker.Stop()
	client.sendReport(ctx)
	client.sendBasicInfo(ctx, config)
	for {
		select {
		case <-ctx.Done():
			return
		case <-reportTicker.C:
			client.sendReport(ctx)
		case <-infoTicker.C:
			client.sendBasicInfo(ctx, config)
		}
	}
}

func (c *komariClient) post(ctx context.Context, payload []byte, out *komariv2.Response) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return errors.New("invalid request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// net/http errors can contain the full URL, including Komari's token.
		return errors.New("connection failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var result komariv2.Response
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return errors.New("invalid response")
	}
	if result.JSONRPC != komariv2.Version {
		return errors.New("unsupported response version")
	}
	if result.Error != nil {
		return fmt.Errorf("RPC error %d", result.Error.Code)
	}
	if out != nil {
		*out = result
	}
	return nil
}

func (c *komariClient) sendBasicInfo(ctx context.Context, config KomariConfig) {
	cpu := komariunit.CpuStaticInfo()
	ram, swap, disk := komariunit.Ram(), komariunit.Swap(), komariunit.Disk()
	ipv4, ipv6 := komariBasicIPs(ctx, config, publicAddress, komariPublicAddress)
	info := map[string]any{
		"cpu_name": cpu.CPUName, "cpu_cores": cpu.CPUCores,
		"cpu_physical_cores": cpu.CPUPhysicalCores, "arch": runtime.GOARCH,
		"os": komariunit.OSName(), "kernel_version": komariunit.KernelVersion(),
		"ipv4": ipv4, "ipv6": ipv6,
		"mem_total": ram.Total, "swap_total": swap.Total,
		"disk_total": disk.Total, "gpu_name": komariunit.GpuName(),
		"virtualization": komariunit.Virtualized(), "version": "mui-agent " + Version,
	}
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := c.post(call, komariv2.BuildBasicInfoPayload(info), nil); err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "komari basic info:", err)
	}
}

func validKomariPublicIP(raw string, v6 bool) string {
	ip, err := netip.ParseAddr(raw)
	if err != nil || !allowedKomariPingIP(ip) || (ip.Unmap().Is6() != v6) {
		return ""
	}
	return ip.Unmap().String()
}

// Panel-reported addresses avoid third-party lookups. A public address on the
// local route is the next choice. Only when the panel has neither address do
// we use the bounded external lookup for a missing address family.
func komariBasicIPs(ctx context.Context, config KomariConfig, local func(string, string) string, external func(context.Context, string, string) string) (string, string) {
	ipv4 := validKomariPublicIP(config.IPv4, false)
	ipv6 := validKomariPublicIP(config.IPv6, true)
	panelKnown := ipv4 != "" || ipv6 != ""
	if ipv4 == "" {
		ipv4 = validKomariPublicIP(local("udp4", "192.0.2.1:9"), false)
	}
	if ipv6 == "" {
		ipv6 = validKomariPublicIP(local("udp6", "[2001:db8::1]:9"), true)
	}
	if !panelKnown {
		if ipv4 == "" {
			ipv4 = external(ctx, "udp4", "https://api.ipify.org?format=json")
		}
		if ipv6 == "" {
			ipv6 = external(ctx, "udp6", "https://api6.ipify.org?format=json")
		}
	}
	return ipv4, ipv6
}

// A NAT address is not visible on the host's interfaces. This bounded HTTPS
// lookup runs only when the panel knows neither public address.
func komariPublicAddress(ctx context.Context, network, lookupURL string) string {
	family := "tcp4"
	if network == "udp6" {
		family = "tcp6"
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, family, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, lookupURL, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	return parseKomariPublicIP(resp.Body, family)
}

func parseKomariPublicIP(reader io.Reader, family string) string {
	var data struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(io.LimitReader(reader, 128)).Decode(&data); err != nil {
		return ""
	}
	ip, err := netip.ParseAddr(data.IP)
	if err != nil || !allowedKomariPingIP(ip) ||
		(family == "tcp4" && !ip.Unmap().Is4()) || (family == "tcp6" && !ip.Unmap().Is6()) {
		return ""
	}
	return ip.Unmap().String()
}

func (c *komariClient) sendReport(ctx context.Context) {
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := c.post(call, komariv2.BuildReportPayload(komarimonitor.GenerateReport()), nil); err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "komari report:", err)
	}
}

func (c *komariClient) pull(ctx context.Context) {
	var ackIDs []string
	for ctx.Err() == nil {
		id := "pull-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		payload := komariv2.NewRequest(id, komariv2.MethodAgentPull, map[string]any{
			"capabilities":  []string{"ping"},
			"ack_event_ids": ackIDs,
		})
		call, cancel := context.WithTimeout(ctx, 35*time.Second)
		var response komariv2.Response
		err := c.post(call, payload, &response)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fmt.Fprintln(os.Stderr, "komari event pull:", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		ackIDs = nil
		var result komariv2.EventResult
		if err := komariv2.BindResult(response.Result, &result); err != nil {
			continue
		}
		for _, event := range result.Events {
			if c.handleEvent(ctx, event) && event.ID != "" {
				ackIDs = append(ackIDs, event.ID)
			}
		}
	}
}

// handleEvent is deliberately an allowlist. The Komari panel currently does
// not filter queued events by the pull request's capabilities, so unknown and
// remote-control methods are acknowledged and ignored.
func (c *komariClient) handleEvent(ctx context.Context, event komariv2.Event) bool {
	switch event.Method {
	case komariv2.MethodAgentPing:
		var params struct {
			TaskID uint   `json:"ping_task_id"`
			Type   string `json:"ping_type"`
			Target string `json:"ping_target"`
		}
		if err := komariv2.BindParams(event.Params, &params); err != nil || params.TaskID == 0 {
			return true
		}
		value := -1
		if params.Type == "tcp" {
			ping := c.tcpPing
			if ping == nil {
				ping = tcpPingKomari
			}
			value = ping(ctx, params.Target)
		}
		payload, err := json.Marshal(komariv2.BuildPingResultPayload(params.TaskID, params.Type, value, time.Now()))
		if err != nil {
			return true
		}
		call, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := c.post(call, payload, nil); err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "komari tcp ping result:", err)
			return false
		}
		return ctx.Err() == nil
	case komariv2.MethodAgentMessage, komariv2.MethodAgentEvent:
		// Informational events require no action on the host.
		return true
	default:
		// Never execute commands, open a terminal, touch files, disclose local
		// config, or allow the Komari panel to update mui-agent.
		return true
	}
}

var komariCGNAT = netip.MustParsePrefix("100.64.0.0/10")

func allowedKomariPingIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && ip.Zone() == "" && ip.IsGlobalUnicast() && !ip.IsPrivate() &&
		!ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() && !komariCGNAT.Contains(ip)
}

// Resolve once, inspect every answer, then dial only the approved literal IP.
// Rejecting a mixed public/private answer prevents a panel-controlled name
// from selecting an internal address or changing DNS between check and dial.
func resolveKomariTCPTarget(ctx context.Context, target string, lookup func(context.Context, string, string) ([]netip.Addr, error)) ([]string, error) {
	target = strings.TrimSpace(target)
	if target == "" || strings.ContainsAny(target, "/@% \t\r\n") {
		return nil, errors.New("invalid target")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		if ip, parseErr := netip.ParseAddr(target); parseErr == nil && ip.Zone() == "" {
			host, port = ip.String(), "80"
		} else if strings.Contains(target, ":") {
			return nil, errors.New("invalid host or port")
		} else {
			host, port = target, "80"
		}
	}
	if host == "" {
		return nil, errors.New("empty host")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("invalid port")
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		ips, err = lookup(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("DNS lookup failed")
		}
	}
	addresses := make([]string, 0, len(ips))
	for _, ip := range ips {
		if !allowedKomariPingIP(ip) {
			return nil, errors.New("target address is not public")
		}
		addresses = append(addresses, net.JoinHostPort(ip.Unmap().String(), port))
	}
	return addresses, nil
}

func tcpPingKomari(ctx context.Context, target string) int {
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addresses, err := resolveKomariTCPTarget(call, target, net.DefaultResolver.LookupNetIP)
	if err != nil {
		return -1
	}
	for _, address := range addresses {
		start := time.Now()
		conn, err := (&net.Dialer{}).DialContext(call, "tcp", address)
		if err == nil {
			_ = conn.Close()
			return int(time.Since(start).Milliseconds())
		}
	}
	return -1
}
