//go:build !linux

package agent

func writeOwnedSignal(path string, data []byte, _ string) error {
	return writeFileAtomic(path, data, 0640)
}
