package asusctl

import (
	"net/netip"
	"strings"
	"testing"
)

func TestServerInternetDNS(t *testing.T) {
	serverFixture(t)
	if e := serverSave(serverDefaults()); e != nil {
		t.Fatal(e)
	}
	if e := serverAdd("test"); e != nil {
		t.Fatal(e)
	}
	c, _ := readServer()
	c.Settings.Internet = true
	for _, tc := range []struct {
		lan       bool
		dns, want string
	}{{true, "", "192.168.50.2"}, {false, "", "1.1.1.1"}, {true, "9.9.9.9", "9.9.9.9"}} {
		c.Settings.AllowLAN = tc.lan
		c.Settings.DNS = tc.dns
		text, e := exportServerClient(c, c.Clients[0], "vpn.example.com", netip.MustParsePrefix("192.168.50.0/24"), nil)
		if e != nil || !strings.Contains(text, "DNS = "+tc.want+"\n") {
			t.Fatalf("DNS selection failed: %v", e)
		}
	}
	c.Settings.Internet = false
	c.Settings.DNS = ""
	text, e := exportServerClient(c, c.Clients[0], "vpn.example.com", netip.MustParsePrefix("192.168.50.0/24"), nil)
	if e != nil || strings.Contains(text, "DNS = ") {
		t.Fatal("LAN-only export should preserve device DNS")
	}
}
func TestServerFullvFallbackScopedAndReversible(t *testing.T) {
	for _, family := range []string{"-4", "-6"} {
		for _, internet := range []bool{false, true} {
			for _, compat := range []bool{false, true} {
				s := serverDefaults()
				s.Internet = internet
				s.Fullv = compat
				s.Address6 = "fd77:77::1/64"
				plan := serverPlan(s, family, "br0", "eth0", "192.168.50.2", []string{"192.168.50.0/24"})
				found := -1
				accept := -1
				for i, step := range plan {
					line := strings.Join(step.Do.Args, " ")
					if strings.Contains(line, "--dport 443") {
						found = i
						if !strings.Contains(line, "-i awgs0 -s ") || !strings.Contains(line, "-p udp --dport 443 -j REJECT") {
							t.Fatal("fallback escaped tunnel UDP443 scope")
						}
						if strings.Replace(line, "-A AWGS_F", "-D AWGS_F", 1) != strings.Join(step.Undo.Args, " ") {
							t.Fatal("fallback cannot be undone")
						}
					}
					if strings.Contains(line, "-o eth0 -j ACCEPT") {
						accept = i
					}
					if strings.Contains(line, "SHADOWSOCKS") {
						t.Fatal("must not mutate or reference foreign chains")
					}
				}
				if (found >= 0) != (internet && compat) {
					t.Fatal("fallback activated without opt in/internet")
				}
				if found >= 0 && found >= accept {
					t.Fatal("fallback must precede unconditional acceptance")
				}
			}
		}
	}
}
