package agent

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mui/internal/shared"
)

// A real SOCKS handshake with a deliberately unresolvable destination proves
// remote DNS, RFC1929 authentication and the absence of a direct fallback.
func TestPanelHTTPClientSOCKS5(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "panel-reached") }))
	defer target.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var count atomic.Int32
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				b := make([]byte, 2)
				if _, e := io.ReadFull(c, b); e != nil || b[0] != 5 {
					return
				}
				methods := make([]byte, int(b[1]))
				if _, e := io.ReadFull(c, methods); e != nil {
					return
				}
				c.Write([]byte{5, 2})
				b = make([]byte, 2)
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				u := make([]byte, int(b[1]))
				io.ReadFull(c, u)
				io.ReadFull(c, b[:1])
				pw := make([]byte, int(b[0]))
				io.ReadFull(c, pw)
				if string(u) != "entry" || string(pw) != "test-password" {
					c.Write([]byte{1, 1})
					return
				}
				c.Write([]byte{1, 0})
				h := make([]byte, 5)
				if _, e := io.ReadFull(c, h); e != nil {
					return
				}
				if h[3] != 3 {
					return
				}
				name := make([]byte, int(h[4]))
				io.ReadFull(c, name)
				port := make([]byte, 2)
				io.ReadFull(c, port)
				if string(name) != "panel.invalid" {
					return
				}
				count.Add(1)
				upstream, e := net.Dial("tcp", strings.TrimPrefix(target.URL, "http://"))
				if e != nil {
					return
				}
				defer upstream.Close()
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
				go io.Copy(upstream, c)
				io.Copy(c, upstream)
			}(c)
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	n, _ := strconv.Atoi(port)
	p := &shared.SOCKS5Proxy{Host: host, Port: n, Username: "entry", Password: "test-password"}
	client, e := panelHTTPClient(p, 3*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer client.CloseIdleConnections()
	response, e := client.Get("http://panel.invalid/report")
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(b) != "panel-reached" || count.Load() != 1 {
		t.Fatal(string(b), count.Load())
	}
	p.Password = "wrong-password"
	bad, e := panelHTTPClient(p, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer bad.CloseIdleConnections()
	if _, e := bad.Get(target.URL); e == nil {
		t.Fatal("bad authentication fell back to direct")
	}
	// Direct mode ignores ambient HTTP_PROXY too, avoiding accidental loopback proxying.
	direct, e := panelHTTPClient(nil, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer direct.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", target.URL, nil)
	resp, e := direct.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
}

// This optional smoke test runs the exact published core in a disposable Linux
// container. It checks real authentication and subscription user counters.
func TestPanelHTTPClientSingBoxSOCKS5(t *testing.T) {
	core := os.Getenv("MUI_TEST_SOCKS_CORE")
	if core == "" {
		t.Skip("set MUI_TEST_SOCKS_CORE to test the release core")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	nodeID := "18df91c7975ff67b0585b209dad9949d2231"
	subName := "mui-" + nodeID + "-subscription"
	raw, err := shared.SingBoxConfig([]shared.ManagedNode{{Node: shared.Node{ID: nodeID, Name: "SOCKS", Protocol: "socks5", Username: "entry", Port: port, Listen: "127.0.0.1", Enabled: true}, Password: "test-password", Users: []shared.NodeUser{{SubscriptionID: "subscription", Name: subName, Password: "subscription-password"}}}}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "core.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	cmd := exec.Command(core, "run", "-c", path)
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	for i := 0; i < 100; i++ {
		c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Millisecond*50)
		if e == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, strings.Repeat("response", 100)) }))
	defer target.Close()
	for _, login := range []struct {
		u, p  string
		valid bool
	}{{"entry", "test-password", true}, {subName, "subscription-password", true}, {"entry", "wrong-password", false}} {
		client, e := panelHTTPClient(&shared.SOCKS5Proxy{Host: "127.0.0.1", Port: port, Username: login.u, Password: login.p}, 3*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		resp, e := client.Get(target.URL)
		if (e == nil) != login.valid {
			t.Fatalf("authentication %s expected %v, got %v", login.u, login.valid, e)
		}
		if e == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		client.CloseIdleConnections()
	}
	conn, e := statsClient()
	if e != nil {
		t.Fatal(e)
	}
	defer dropStatsClient()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var response statsResponse
	if e = conn.Invoke(ctx, "/v2ray.core.app.stats.command.StatsService/QueryStats", &statsRequest{}, &response); e != nil {
		t.Fatal(e)
	}
	snapshot := parseStatsCounters(response.Counters)
	if snapshot.Nodes[nodeID][1] == 0 || snapshot.Users[subName][1] == 0 {
		t.Fatalf("missing node/subscription counters: %#v", snapshot)
	}
}
