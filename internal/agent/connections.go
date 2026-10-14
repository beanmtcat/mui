package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"mui/internal/shared"
)

var connectionClient = &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}

// ActiveConnections reads a point-in-time snapshot. Short connections between
// snapshots cannot be observed; this is not an authentication audit log.
func ActiveConnections(ctx context.Context) ([]shared.ConnectionPoint, error) {
	url := "http://127.0.0.1:" + strconv.Itoa(shared.ConnectionsAPIPort) + "/connections"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := connectionClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("connections HTTP %d", resp.StatusCode)
	}
	return decodeConnections(io.LimitReader(resp.Body, 2<<20))
}

// decodeConnections streams the connections array element by element
// instead of decoding the whole snapshot: a busy host can report thousands
// of connections, and decoding stops as soon as 500 points are collected.
func decodeConnections(reader io.Reader) ([]shared.ConnectionPoint, error) {
	dec := json.NewDecoder(reader)
	if _, err := dec.Token(); err != nil { // '{'
		return nil, err
	}
	out := make([]shared.ConnectionPoint, 0, 64)
	seen := map[string]bool{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if key != "connections" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, err
			}
			continue
		}
		if _, err := dec.Token(); err != nil { // '['
			return nil, err
		}
		for dec.More() {
			var conn struct {
				Metadata struct {
					Type     string `json:"type"`
					SourceIP string `json:"sourceIP"`
				} `json:"metadata"`
			}
			if err := dec.Decode(&conn); err != nil {
				return nil, err
			}
			parts := strings.SplitN(conn.Metadata.Type, "/", 2)
			if len(parts) != 2 {
				continue
			}
			tag := parts[1]
			if !strings.HasPrefix(tag, "node-") && !strings.HasPrefix(tag, "shadowtls-") {
				continue
			}
			nodeID := strings.TrimPrefix(strings.TrimPrefix(tag, "node-"), "shadowtls-")
			// Only real node IDs are reported: anything else is a
			// foreign tag the API happened to serve.
			if !safeNodeID.MatchString(nodeID) {
				continue
			}
			ip := net.ParseIP(conn.Metadata.SourceIP)
			if ip == nil {
				continue
			}
			key := nodeID + "/" + ip.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, shared.ConnectionPoint{NodeID: nodeID, IP: ip.String()})
			if len(out) == 500 {
				return out, nil
			}
		}
		if _, err := dec.Token(); err != nil { // ']'
			return nil, err
		}
	}
	if _, err := dec.Token(); err != nil { // '}'
		return nil, err
	}
	return out, nil
}
