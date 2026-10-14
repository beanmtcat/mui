package main

import (
	"net/url"
	"strings"
	"testing"
)

func TestDatabaseDSNFromComponents(t *testing.T) {
	values := map[string]string{
		"MUI_DB_HOST":     "127.0.0.1",
		"MUI_DB_PORT":     "55432",
		"MUI_DB_NAME":     "mui",
		"MUI_DB_USER":     "mui",
		"MUI_DB_PASSWORD": "p@ss:word/with?chars",
		"MUI_DB_SSLMODE":  "disable",
	}
	dsn, err := databaseDSNFrom(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "postgres" || parsed.Host != "127.0.0.1:55432" || parsed.Path != "/mui" || parsed.User.Username() != "mui" {
		t.Fatalf("unexpected database URL: %s", parsed.Redacted())
	}
	if password, ok := parsed.User.Password(); !ok || password != values["MUI_DB_PASSWORD"] {
		t.Fatal("database password was not encoded correctly")
	}
	if parsed.Query().Get("sslmode") != "disable" {
		t.Fatal("sslmode was not applied")
	}
}

func TestDatabaseDSNOverrideAndMissingPassword(t *testing.T) {
	values := map[string]string{"MUI_DB_URL": "postgres://external.example/mui", "MUI_DB_PASSWORD": "other"}
	dsn, err := databaseDSNFrom(func(key string) string { return values[key] })
	if err != nil || dsn != values["MUI_DB_URL"] {
		t.Fatalf("explicit URL should take precedence: %q, %v", dsn, err)
	}
	values = map[string]string{"MUI_DB_HOST": "127.0.0.1"}
	if _, err := databaseDSNFrom(func(key string) string { return values[key] }); err == nil || !strings.Contains(err.Error(), "MUI_DB_PASSWORD") {
		t.Fatalf("expected missing-password error, got %v", err)
	}
	if dsn, err := databaseDSNFrom(func(string) string { return "" }); err != nil || dsn != "" {
		t.Fatalf("empty database configuration should use SQLite: %q, %v", dsn, err)
	}
}
