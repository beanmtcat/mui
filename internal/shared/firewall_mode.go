package shared

// Empty persisted values retain UFW management for existing servers.
func ManualFirewall(mode string) bool { return mode == "manual" }

func ValidFirewallMode(mode string) bool {
	return mode == "" || mode == "ufw" || mode == "manual"
}
