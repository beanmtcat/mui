package agent

import (
	"strings"
	"testing"
)

func TestDecodeConnections(t *testing.T) {
	// Node IDs must satisfy the safeNodeID whitelist (32-36 lowercase hex)
	// that decodeConnections enforces; short fixtures would be dropped.
	const nodeA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const nodeB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	raw := `{"connections":[{"metadata":{"type":"shadowsocks/node-` + nodeA + `","sourceIP":"203.0.113.1"}},{"metadata":{"type":"shadowtls/shadowtls-` + nodeB + `","sourceIP":"2001:db8::1"}},{"metadata":{"type":"shadowsocks/node-` + nodeA + `","sourceIP":"203.0.113.1"}},{"metadata":{"type":"direct/other","sourceIP":"203.0.113.2"}}]}`
	points, err := decodeConnections(strings.NewReader(raw))
	if err != nil || len(points) != 2 || points[0].NodeID != nodeA || points[1].NodeID != nodeB {
		t.Fatalf("points=%+v err=%v", points, err)
	}
}
