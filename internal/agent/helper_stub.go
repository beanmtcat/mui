//go:build !linux

package agent

import (
	"errors"
	"mui/internal/shared"
)

func ServeHelper() error                           { return errors.New("Linux only") }
func CallHelper(string, shared.DesiredState) error { return errors.New("Linux only") }
func PersistAgentToken(string) error               { return errors.New("Linux only") }
func QueryHostStatus() HostStatus                  { return HostStatus{UFW: "unsupported", Supported: false} }
func ReadCurrent() shared.DesiredState             { return shared.DesiredState{} }
func CoreVersion() string                          { return "unavailable" }
func CheckCoreBuild() error                        { return errors.New("Linux only") }
