package agent

import (
	"strconv"
	"strings"
)

func supportedDistribution(id, version string) bool {
	switch id {
	case "ubuntu":
		return version == "22.04" || version == "24.04" || version == "26.04"
	case "debian":
		return version == "11" || version == "12" || version == "13"
	case "alpine":
		parts := strings.Split(version, ".")
		if len(parts) < 2 || parts[0] != "3" {
			return false
		}
		minor, err := strconv.Atoi(parts[1])
		return err == nil && minor >= 19
	}
	return false
}
