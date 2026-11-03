package agent

import (
	"context"
	"net"
	"testing"
	"time"

	"mui/internal/shared"
)

func TestSampleRouteLatenciesConnectAndRejectUnrelatedForwards(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	forwards := []shared.ForwardRule{
		{ID: "route", RouteID: "r", Network: "tcp", Enabled: true, Targets: []shared.ForwardTarget{{Host: "127.0.0.1", Port: port}}},
		{ID: "manual", Network: "tcp", Enabled: true, Targets: []shared.ForwardTarget{{Host: "127.0.0.1", Port: port}}},
		{ID: "reused", RouteID: "r", Network: shared.ForwardTCPUDP, Enabled: true, Targets: []shared.ForwardTarget{{Host: "127.0.0.1", Port: port}}},
		{ID: "udp", RouteID: "r", Network: "udp", Enabled: true, Targets: []shared.ForwardTarget{{Host: "127.0.0.1", Port: port}}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	points := sampleRouteLatencies(ctx, forwards)
	if len(points) != 2 || points[0].ForwardID != "reused" || points[1].ForwardID != "route" || !points[0].OK || !points[1].OK || points[1].TCPMs < 1 {
		t.Fatalf("unexpected route measurements: %+v", points)
	}
}
