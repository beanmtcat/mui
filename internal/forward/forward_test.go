package forward

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"mui/internal/shared"
)

func freePort(t *testing.T, network string) int {
	t.Helper()
	if network == "tcp" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port
	}
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.LocalAddr().(*net.UDPAddr).Port
}

func TestTCPForwardCreatesNewConnection(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	seen := make(chan string, 1)
	go func() {
		conn, err := target.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		seen <- conn.RemoteAddr().String()
		_, _ = io.Copy(conn, conn)
	}()
	port := freePort(t, "tcp")
	rule := shared.ForwardRule{ID: "tcp", Name: "test", Network: "tcp", Listen: "127.0.0.1", Port: port, Targets: []shared.ForwardTarget{{Host: "127.0.0.1", Port: target.Addr().(*net.TCPAddr).Port}}, Enabled: true}
	service, err := Start([]shared.ForwardRule{rule})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	client, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err = io.ReadFull(client, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo %q: %v", buf, err)
	}
	if remote := <-seen; remote == client.LocalAddr().String() {
		t.Fatal("TCP was not re-established by forwarder")
	}
	// The connection is still open: counters must follow it, not wait for its end.
	eventually(t, "traffic counted on an open connection", func() bool {
		stats := service.Snapshot()["tcp"]
		return stats.Uplink == 5 && stats.Downlink == 5
	})
}

func TestUDPForwardRepliesToOriginalClient(t *testing.T) {
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		buf := make([]byte, 64)
		n, addr, err := target.ReadFrom(buf)
		if err == nil {
			_, _ = target.WriteTo(buf[:n], addr)
		}
	}()
	port := freePort(t, "udp")
	rule := shared.ForwardRule{ID: "udp", Name: "test", Network: "udp", Listen: "127.0.0.1", Port: port, Targets: []shared.ForwardTarget{{Host: "127.0.0.1", Port: target.LocalAddr().(*net.UDPAddr).Port}}, Enabled: true}
	service, err := Start([]shared.ForwardRule{rule})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	client, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("echo %q: %v", buf[:n], err)
	}
	stats := service.Snapshot()["udp"]
	if stats.Uplink != 4 || stats.Downlink != 4 {
		t.Fatalf("traffic %+v", stats)
	}
}
