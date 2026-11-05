//go:build linux || darwin

package agent

import (
	"os"
	"strconv"
	"testing"
)

func TestFileOwnerUID(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "owned")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	info, err := os.Stat(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if got := fileOwnerUID(info); got != strconv.Itoa(os.Getuid()) {
		t.Fatalf("owner %q, want %d", got, os.Getuid())
	}
}
