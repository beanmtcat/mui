package agent

import "testing"

func TestParseUFWStatusRuleSource(t *testing.T) {
	cases := []struct {
		line, action, source string
		allowAll             bool
	}{
		{"[19] Anywhere                   ALLOW IN    172.18.0.0/16", "ALLOW", "172.18.0.0/16", true},
		{"[20] Anywhere (v6)              ALLOW IN    Anywhere (v6)", "ALLOW", "Anywhere", true},
		{"[ 2] 8000:8010/tcp              ALLOW IN    Anywhere", "ALLOW", "Anywhere", false},
		{"[ 3] 5201                       ALLOW IN    1.2.3.4                    # note", "ALLOW", "1.2.3.4", false},
		{"[ 4] 22/tcp                     DENY IN     Anywhere", "DENY", "Anywhere", false},
	}
	for _, c := range cases {
		rule, ok := parseUFWStatusRule(c.line)
		if !ok || rule.action != c.action || rule.source != c.source || rule.allowAll != c.allowAll {
			t.Errorf("%q => %+v ok=%v", c.line, rule, ok)
		}
	}
}

func TestLocalUFWSource(t *testing.T) {
	local := []string{"172.18.0.0/16", "10.0.0.0/8", "192.168.1.5", "127.0.0.1", "fd00::/8", "fe80::1", "::1"}
	public := []string{"Anywhere", "", "0.0.0.0/0", "::/0", "1.2.3.4", "172.0.0.0/8", "10.0.0.0/7", "fc00::/6", "2001:db8::/32", "not-an-ip"}
	for _, s := range local {
		if !localUFWSource(s) {
			t.Errorf("%q should be local", s)
		}
	}
	for _, s := range public {
		if localUFWSource(s) {
			t.Errorf("%q should not be local", s)
		}
	}
}
