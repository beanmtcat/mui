package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineCommandsAndBadArguments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "forwards.json")
	if err := runOfflineCommand([]string{"init", path}); err != nil {
		t.Fatal(err)
	}
	if err := runOfflineCommand([]string{"check", path}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"receipt"}, {"init", path, "extra"}, {"install"}, {"install", "--config", path, "--unknown"}, {"install", "--config", path, "--release-key", "x", "--release-key-file", path}, {"apply"}, {"check", path, "extra"}, {"bogus"}} {
		if err := runOfflineCommand(args); err == nil {
			t.Errorf("bad args accepted: %v", args)
		}
	}
	if err := runOfflineCommand([]string{"install", "--config", path, "--release-key", " "}); err == nil || !strings.Contains(err.Error(), "公钥不能为空") {
		t.Fatalf("explicit empty key silently downgraded: %v", err)
	}
	emptyKey := filepath.Join(t.TempDir(), "release.pub")
	if err := os.WriteFile(emptyKey, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runOfflineCommand([]string{"install", "--config", path, "--release-key-file", emptyKey}); err == nil || !strings.Contains(err.Error(), "公钥文件为空") {
		t.Fatalf("empty key file silently downgraded: %v", err)
	}
}
