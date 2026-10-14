//go:build !linux

package agent

import "errors"

func Install(_, _, _, _, _ string) error     { return errors.New("Linux only") }
func RollbackIfUnconfirmed(string) error     { return errors.New("Linux only") }
func RollbackCoreIfUnconfirmed(string) error { return errors.New("Linux only") }
