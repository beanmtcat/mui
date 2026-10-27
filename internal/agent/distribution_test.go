package agent

import "testing"

func TestSupportedDistributions(t *testing.T) {
	for _, tc := range []struct {
		id, version string
		supported   bool
	}{
		{"alpine", "3.19.1", true}, {"alpine", "3.22.2", true},
		{"alpine", "3.18.9", false}, {"alpine", "3", false},
		{"ubuntu", "26.04", true},
		{"debian", "11", true}, {"debian", "12", true}, {"debian", "13", true}, {"debian", "10", false},
		{"unknown", "3.19.1", false},
	} {
		if got := supportedDistribution(tc.id, tc.version); got != tc.supported {
			t.Fatalf("%s %s: %v", tc.id, tc.version, got)
		}
	}
}
