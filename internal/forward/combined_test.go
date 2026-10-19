package forward

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestTCPUDPSharedPortCountersAndReload(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	udpBackend, err := net.ListenPacket("udp", backend.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udpBackend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := udpBackend.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udpBackend.WriteTo(buf[:n], addr)
		}
	}()
	port := freePort(t, "tcp")
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	spec := shared.ForwardRule{ID: "combined", Name: "combined", Network: shared.ForwardTCPUDP, Listen: "127.0.0.1", Port: port, Targets: []shared.ForwardTarget{{Host: "127.0.0.1", Port: backend.Addr().(*net.TCPAddr).Port}}, HealthCheck: "none", Enabled: true}
	svc, err := Start([]shared.ForwardRule{spec})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	tcp, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	var total int64
	echo := func(conn net.Conn, network, message string) {
		t.Helper()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte(message)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(message))
		var n int
		var err error
		if network == "tcp" {
			n, err = io.ReadFull(conn, buf)
		} else {
			n, err = conn.Read(buf)
		}
		if err != nil || string(buf[:n]) != message {
			t.Fatalf("%s echo: %q %v", network, buf[:n], err)
		}
		total += int64(len(message))
	}
	udp, err := net.Dial("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	echo(tcp, "tcp", "tcp")
	echo(udp, "udp", "udp!")
	eventually(t, "combined counters", func() bool {
		snap := svc.Snapshot()
		return len(snap) == 1 && snap[spec.ID].Uplink == total && snap[spec.ID].Downlink == total
	})
	// TCP-only closes the UDP socket but retains the original TCP stream.
	spec.Network = "tcp"
	if err := svc.Reload([]shared.ForwardRule{spec}); err != nil {
		t.Fatal(err)
	}
	echo(tcp, "tcp", "kept")
	blocked, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatalf("UDP socket not released: %v", err)
	}
	spec.Network = shared.ForwardTCPUDP
	if err := svc.Reload([]shared.ForwardRule{spec}); err == nil {
		t.Fatal("reload ignored occupied UDP port")
	}
	echo(tcp, "tcp", "alive")
	_ = blocked.Close()
	if err := svc.Reload([]shared.ForwardRule{spec}); err != nil {
		t.Fatal(err)
	}
	udp2, err := net.Dial("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer udp2.Close()
	echo(udp2, "udp", "back")
	echo(tcp, "tcp", "same")
	// Removing just TCP keeps the existing UDP association usable.
	spec.Network = "udp"
	if err := svc.Reload([]shared.ForwardRule{spec}); err != nil {
		t.Fatal(err)
	}
	echo(udp2, "udp", "udp-only")
	eventually(t, "counters stay under the same logical ID", func() bool {
		snap := svc.Snapshot()
		return len(snap) == 1 && snap[spec.ID].Uplink == total && snap[spec.ID].Downlink == total
	})
	spec.Enabled = false
	if err := svc.Reload([]shared.ForwardRule{spec}); err != nil {
		t.Fatal(err)
	}
	probe, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatalf("disabled UDP still listening: %v", err)
	}
	_ = probe.Close()
	tcpProbe, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("TCP still listening: %v", err)
	}
	_ = tcpProbe.Close()
}
