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
	refresh := func() {
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
			return
		}
		if next == current {
			return
		}
		stop()
		current = next
		if next.Token == "" {
			return
		}
		workerCtx, workerCancel := context.WithCancel(ctx)
		cancel, done = workerCancel, make(chan struct{})
		go func() {
			defer close(done)
			runKomari(workerCtx, next)
		}()
	}
	refresh()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
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
	client.sendBasicInfo(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-reportTicker.C:
			client.sendReport(ctx)
		case <-infoTicker.C:
			client.sendBasicInfo(ctx)
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

func (c *komariClient) sendBasicInfo(ctx context.Context) {
	cpu := komariunit.CpuStaticInfo()
	ram, swap, disk := komariunit.Ram(), komariunit.Swap(), komariunit.Disk()
	ipv4 := komariPublicAddress(ctx, "udp4", "192.0.2.1:9", "https://api.ipify.org?format=json")
	ipv6 := komariPublicAddress(ctx, "udp6", "[2001:db8::1]:9", "https://api6.ipify.org?format=json")
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

// A NAT address is not visible on the host's interfaces. Use a bounded HTTPS
// lookup only when routing does not reveal a public address.
func komariPublicAddress(ctx context.Context, network, probe, lookupURL string) string {
	if local := publicAddress(network, probe); local != "" {
		return local
	}
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
	ip := net.ParseIP(data.IP)
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() ||
		(family == "tcp4" && ip.To4() == nil) || (family == "tcp6" && ip.To4() != nil) {
		return ""
	}
	return ip.String()
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

func tcpPingKomari(ctx context.Context, target string) int {
	target = strings.TrimSpace(target)
	if target == "" || strings.ContainsAny(target, "/ \t\r\n") {
		return -1
	}
	address := target
	if _, _, err := net.SplitHostPort(target); err != nil {
		if ip := net.ParseIP(target); ip != nil {
			address = net.JoinHostPort(ip.String(), "80")
		} else if strings.Contains(target, ":") {
			return -1
		} else {
			address = net.JoinHostPort(target, "80")
		}
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return -1
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return -1
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(call, "tcp", address)
	if err != nil {
		return -1
	}
	_ = conn.Close()
	return int(time.Since(start).Milliseconds())
}
