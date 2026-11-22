//go:build linux

package agent

func writeOwnedSignal(path string, data []byte, group string) error {
	return writeOwned(path, data, 0640, group)
}
