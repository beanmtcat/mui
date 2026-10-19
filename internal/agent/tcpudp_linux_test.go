//go:build linux

package agent

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mui/internal/shared"
)

func TestTCPUDPHelperChecksBothProtocols(t *testing.T) {
	dir := t.TempDir()
	systemctl := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(systemctl, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var port int
			if network == "tcp" {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				port = l.Addr().(*net.TCPAddr).Port
			} else {
				l, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				port = l.LocalAddr().(*net.UDPAddr).Port
			}
			f := shared.ForwardRule{ID: "combined", Name: "combined", Network: shared.ForwardTCPUDP, Listen: "127.0.0.1", Port: port, Enabled: true}
			err := checkNewPorts(shared.DesiredState{}, shared.DesiredState{Forwards: []shared.ForwardRule{f}})
			if err == nil || !strings.Contains(err.Error(), strings.ToUpper(network)) {
				t.Fatalf("%s occupied port not checked: %v", network, err)
			}
		})
	}
	// Foreign allows for either transport must be recognized as bypassing
	// the combined rule's source restriction.
	for _, network := range []string{"tcp", "udp"} {
		script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' 'Status: active' '[ 1] 51000/%s ALLOW IN Anywhere'\n", network)
		if err := os.WriteFile(filepath.Join(dir, "ufw"), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
		f := shared.ForwardRule{ID: "combined", Name: "combined", Network: shared.ForwardTCPUDP, Port: 51000, Enabled: true, FirewallPolicy: "restricted", FirewallSources: "192.0.2.1/32"}
		if err := checkManualUFWBypass(shared.DesiredState{Forwards: []shared.ForwardRule{f}}); err == nil {
			t.Fatalf("foreign %s allow bypassed combined scope", network)
		}
	}
}
