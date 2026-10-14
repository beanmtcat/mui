package agent

import (
	"google.golang.org/protobuf/encoding/protowire"
	"testing"
)

func TestStatsWireCodec(t *testing.T) {
	stat := protowire.AppendTag(nil, 1, protowire.BytesType)
	stat = protowire.AppendString(stat, "inbound>>>node-abc>>>traffic>>>uplink")
	stat = protowire.AppendTag(stat, 2, protowire.VarintType)
	stat = protowire.AppendVarint(stat, 4096)
	payload := protowire.AppendTag(nil, 1, protowire.BytesType)
	payload = protowire.AppendBytes(payload, stat)
	var response statsResponse
	if err := (wireCodec{}).Unmarshal(payload, &response); err != nil {
		t.Fatal(err)
	}
	if response.Counters["inbound>>>node-abc>>>traffic>>>uplink"] != 4096 {
		t.Fatalf("unexpected stats: %#v", response.Counters)
	}
}

func TestParseUserAndInboundCounters(t *testing.T) {
	stats := parseStatsCounters(map[string]int64{
		"inbound>>>node-one>>>traffic>>>uplink":        100,
		"inbound>>>node-one>>>traffic>>>downlink":      200,
		"user>>>mui-one-sub1>>>traffic>>>uplink":       30,
		"user>>>mui-one-sub1>>>traffic>>>downlink":     40,
		"user>>>outer-mui-one-sub1>>>traffic>>>uplink": 99,
	})
	if stats.Nodes["one"] != [2]int64{100, 200} || stats.Users["mui-one-sub1"] != [2]int64{30, 40} || len(stats.Users) != 1 {
		t.Fatalf("incorrect user attribution: %#v", stats)
	}
}
