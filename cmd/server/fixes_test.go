package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDotEnvInlineCommentsAndLongLines(t *testing.T) {
	long := strings.Repeat("x", 70000) // Past bufio.Scanner's 64 KiB line cap.
	path := filepath.Join(t.TempDir(), ".env")
	contents := "MUI_DOTENV_TEST_A=value # trailing comment\n" +
		"MUI_DOTENV_TEST_B=\"quoted\" # trailing comment\n" +
		"MUI_DOTENV_TEST_C='single' # trailing comment\n" +
		"MUI_DOTENV_TEST_LONG=" + long + "\n" +
		"MUI_DOTENV_TEST_HASH=keep#this\n" +
		`MUI_DOTENV_TEST_ESC="a \"quoted\" value" # trailing` + "\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("MUI_DOTENV_TEST_A"); got != "value" {
		t.Fatalf("unquoted inline comment not stripped: %q", got)
	}
	if got := os.Getenv("MUI_DOTENV_TEST_B"); got != "quoted" {
		t.Fatalf("quoted inline comment not stripped: %q", got)
	}
	if got := os.Getenv("MUI_DOTENV_TEST_C"); got != "single" {
		t.Fatalf("single-quoted inline comment not stripped: %q", got)
	}
	if got := os.Getenv("MUI_DOTENV_TEST_LONG"); got != long {
		t.Fatalf("long line not loaded: len %d", len(got))
	}
	if got := os.Getenv("MUI_DOTENV_TEST_HASH"); got != "keep#this" {
		t.Fatalf("bare # inside a value should be kept: %q", got)
	}
	if got := os.Getenv("MUI_DOTENV_TEST_ESC"); got != `a "quoted" value` {
		t.Fatalf("escaped quote inside a quoted value should survive: %q", got)
	}
}

func TestDatabaseDSNRejectsNonPostgresScheme(t *testing.T) {
	for _, dsn := range []string{"sqlite:///tmp/mui.db", "mysql://user:pass@host/db", "://missing-scheme"} {
		values := map[string]string{"MUI_DB_URL": dsn}
		if _, err := databaseDSNFrom(func(key string) string { return values[key] }); err == nil {
			t.Fatalf("non-postgres MUI_DB_URL %q should be rejected", dsn)
		}
	}
}

func TestResolveSecretFilesPrefersFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("  file-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MUI_SECRET", "env-secret")
	t.Setenv("MUI_SECRET_FILE", path)
	if err := resolveSecretFiles(); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("MUI_SECRET"); got != "file-secret" {
		t.Fatalf("file secret should win over the environment variable: %q", got)
	}
}

func TestResolveSecretFilesMissingFileErrors(t *testing.T) {
	t.Setenv("MUI_DB_PASSWORD_FILE", filepath.Join(t.TempDir(), "does-not-exist"))
	if err := resolveSecretFiles(); err == nil {
		t.Fatal("unreadable secret file should error")
	}
}
