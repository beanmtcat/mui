package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDotEnv(t *testing.T) {
	t.Setenv("MUI_PUBLIC_URL", "https://from-process.example")
	t.Setenv("MUI_SECRET", "")
	const loadedKey = "MUI_DOTENV_TEST_PASSWORD"
	previous, existed := os.LookupEnv(loadedKey)
	os.Unsetenv(loadedKey)
	t.Cleanup(func() {
		if existed {
			os.Setenv(loadedKey, previous)
		} else {
			os.Unsetenv(loadedKey)
		}
	})
	path := filepath.Join(t.TempDir(), ".env")
	contents := "# local configuration\nexport MUI_PUBLIC_URL=http://127.0.0.1:8080\nMUI_SECRET='quoted secret'\nMUI_DOTENV_TEST_PASSWORD=\"a password with spaces\"\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("MUI_PUBLIC_URL"); got != "https://from-process.example" {
		t.Fatalf("process environment was overridden: %q", got)
	}
	if got := os.Getenv("MUI_SECRET"); got != "" {
		t.Fatalf("empty process environment was overridden: %q", got)
	}
	if got := os.Getenv("MUI_DOTENV_TEST_PASSWORD"); got != "a password with spaces" {
		t.Fatalf("quoted value was not loaded: %q", got)
	}
}

func TestLoadDotEnvMissingAndMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := loadDotEnv(path); err != nil {
		t.Fatalf("missing .env should be optional: %v", err)
	}
	if err := os.WriteFile(path, []byte("BAD-NAME=value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadDotEnv(path); err == nil || !strings.Contains(err.Error(), ":1:") {
		t.Fatalf("expected line-numbered error, got %v", err)
	}
}
