//go:build !linux

package agent

import (
	"errors"
	"mui/internal/shared"
)

func Install(_, _, _, _, _ string, _ ...*shared.SOCKS5Proxy) error { return errors.New("Linux only") }

func RollbackIfUnconfirmed(string) error { return errors.New("Linux only") }
