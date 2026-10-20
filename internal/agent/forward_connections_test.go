package agent

import (
	"encoding/json"
	"mui/internal/shared"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestForwardConnectionFileIsAtomicAndRestricted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connections.json")
	points := []shared.ForwardConnectionPoint{{ForwardID: "f", RouteID: "r", NodeID: "n", IP: "203.0.113.55", At: time.Now()}}
	if err := writeForwardConnections(path, points); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal(info, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got []shared.ForwardConnectionPoint
	if err = json.Unmarshal(raw, &got); err != nil || len(got) != 1 || got[0].IP != points[0].IP {
		t.Fatal(got, err)
	}
	if _, err = os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary file remains")
	}
}
