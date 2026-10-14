package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
)

func databaseDSN() (string, error) {
	return databaseDSNFrom(os.Getenv)
}

func databaseDSNFrom(getenv func(string) string) (string, error) {
	if dsn := getenv("MUI_DB_URL"); dsn != "" {
		// Without a scheme check a value like sqlite://... would silently be
		// treated as a SQLite file path downstream.
		parsed, err := url.Parse(dsn)
		if err != nil || parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
			return "", fmt.Errorf("MUI_DB_URL must use the postgres:// or postgresql:// scheme")
		}
		return dsn, nil
	}
	password := getenv("MUI_DB_PASSWORD")
	host := getenv("MUI_DB_HOST")
	port := getenv("MUI_DB_PORT")
	name := getenv("MUI_DB_NAME")
	user := getenv("MUI_DB_USER")
	sslmode := getenv("MUI_DB_SSLMODE")
	if password == "" {
		if host != "" || port != "" || name != "" || user != "" || sslmode != "" {
			return "", fmt.Errorf("MUI_DB_PASSWORD is required for PostgreSQL")
		}
		return "", nil // SQLite fallback for tests and standalone use.
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if port == "" {
		port = "5432"
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("MUI_DB_PORT must be between 1 and 65535")
	}
	if name == "" {
		name = "mui"
	}
	if user == "" {
		user = "mui"
	}
	if sslmode == "" {
		sslmode = "require"
	}
	dsn := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Host:   net.JoinHostPort(host, port),
		Path:   "/" + name,
	}
	query := url.Values{}
	query.Set("sslmode", sslmode)
	dsn.RawQuery = query.Encode()
	return dsn.String(), nil
}
