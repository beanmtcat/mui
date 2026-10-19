package agent

import (
	"errors"
	"reflect"
	"testing"
)

func TestDetectSSHPortsRequiresLiveListener(t *testing.T) {
	for _, tc := range []struct {
		name, listeners, sockets, config string
		ssErr, configErr                 bool
		want                             map[int]bool
	}{
		{
			name: "LXC still listening on 22 after config changed to 12580",
			listeners: `LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=95,fd=3))
LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=95,fd=4))`,
			config: "port 12580\n", want: map[int]bool{22: true, 12580: true},
		},
		{
			name: "socket activated SSH owned by systemd",
			listeners: `LISTEN 0 4096 [::]:22 [::]:* users:(("systemd",pid=1,fd=56))
LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=40,fd=5))`,
			sockets: "[::]:22 ssh.socket ssh.service\n", config: "port 12580\n", want: map[int]bool{22: true, 12580: true},
		},
		{
			name: "multiple live ports and IPv6 zone",
			listeners: `LISTEN 0 128 *:2222 *:* users:(("sshd",pid=95,fd=3))
LISTEN 0 128 [fe80::1%eth0]:2200 [::]:* users:(("sshd",pid=96,fd=4))`,
			config: "port 2222\nport 2200\nport 0\nport 65536\n", want: map[int]bool{2222: true, 2200: true},
		},
		{
			name:      "live daemon survives broken configuration",
			listeners: `LISTEN 0 128 127.0.0.1:2200 0.0.0.0:* users:(("sshd",pid=95,fd=3))`,
			configErr: true, want: map[int]bool{2200: true},
		},
		{
			name:      "configured SSH without a live listener is rejected",
			listeners: `LISTEN 0 4096 *:443 *:* users:(("nginx",pid=40,fd=5))`,
			config:    "port 12580\n",
		},
		{
			name:      "SSH socket configuration without a bound TCP socket is rejected",
			listeners: `LISTEN 0 4096 *:443 *:* users:(("nginx",pid=40,fd=5))`,
			sockets:   "[::]:22 ssh.socket ssh.service\n", config: "port 12580\n",
		},
		{
			name:      "unrelated process and socket cannot masquerade as SSH",
			listeners: `LISTEN 0 4096 *:22 *:* users:(("not-sshd",pid=40,fd=5))`,
			sockets:   "[::]:22 not-ssh.socket custom.service\n", config: "port 22\n",
		},
		{name: "ss failure does not trust configuration", ssErr: true, config: "port 22\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(name string, args ...string) (string, error) {
				switch name {
				case "ss":
					if tc.ssErr {
						return "", errors.New("ss failed")
					}
					return tc.listeners, nil
				case "systemctl":
					return tc.sockets, nil
				case "sshd":
					if tc.configErr {
						return "", errors.New("invalid configuration")
					}
					return tc.config, nil
				}
				t.Fatalf("unexpected command: %s %v", name, args)
				return "", nil
			}
			got, err := detectSSHPorts(run)
			if (err != nil) != (tc.want == nil) || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ports=%v error=%v, want %v", got, err, tc.want)
			}
		})
	}
}
