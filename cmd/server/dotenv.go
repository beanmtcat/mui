package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// loadDotEnv loads local defaults without overriding the process environment.
// A missing file is normal when the server is configured by its host or container.
func loadDotEnv(path string) error {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	// bufio.Reader has no 64 KiB line cap (bufio.Scanner does), so a long
	// value no longer fails startup.
	reader := bufio.NewReader(file)
	for line := 1; ; line++ {
		text, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read %s: %w", path, err)
		}
		entry := strings.TrimSpace(text)
		if entry != "" && !strings.HasPrefix(entry, "#") {
			entry = strings.TrimPrefix(entry, "export ")
			key, value, ok := strings.Cut(entry, "=")
			key = strings.TrimSpace(key)
			if !ok || !envKeyPattern.MatchString(key) {
				return fmt.Errorf("%s:%d: invalid environment variable", path, line)
			}
			value = strings.TrimSpace(value)
			if strings.HasPrefix(value, `"`) {
				// Quoted value: unquote the first quoted span; anything
				// after the closing quote may be a trailing comment. A
				// backslash-escaped quote inside does not end the span.
				end := -1
				for i := 1; i < len(value); i++ {
					if value[i] == '\\' {
						i++
						continue
					}
					if value[i] == '"' {
						end = i
						break
					}
				}
				if end < 0 {
					return fmt.Errorf("%s:%d: unterminated quoted value", path, line)
				}
				value, err = strconv.Unquote(value[:end+1])
				if err != nil {
					return fmt.Errorf("%s:%d: invalid quoted value: %w", path, line, err)
				}
			} else if strings.HasPrefix(value, "'") {
				end := strings.Index(value[1:], "'")
				if end < 0 {
					return fmt.Errorf("%s:%d: unterminated quoted value", path, line)
				}
				value = value[1 : end+1]
			} else {
				// Unquoted value: a " #" starts an inline comment. A bare
				// '#' inside the value is kept (e.g. a URL fragment).
				if idx := strings.Index(value, " #"); idx >= 0 {
					value = strings.TrimSpace(value[:idx])
				}
			}
			if _, exists := os.LookupEnv(key); !exists {
				if err := os.Setenv(key, value); err != nil {
					return fmt.Errorf("%s:%d: set %s: %w", path, line, key, err)
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return nil
}

// resolveSecretFiles implements *_FILE for secrets: when MUI_SECRET_FILE (and
// friends) is set, the file's trimmed contents win over the plaintext
// environment variable, so secrets can come from Docker secrets or a file
// mount instead of the process environment.
func resolveSecretFiles() error {
	for _, key := range []string{"MUI_SECRET", "MUI_DB_PASSWORD", "MUI_ADMIN_PASSWORD"} {
		path := os.Getenv(key + "_FILE")
		if path == "" {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", key+"_FILE", err)
		}
		if err := os.Setenv(key, strings.TrimSpace(string(raw))); err != nil {
			return fmt.Errorf("set %s from file: %w", key, err)
		}
	}
	return nil
}
