package asusctl

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDualStackDNSCommands(t *testing.T) {
	testEnvironment(t)
	var commands []string
	runCommand = func(n string, args ...string) (string, error) {
		commands = append(commands, n+" "+strings.Join(args, " "))
		return "", nil
	}
	c, e := Parse(strings.Replace(testConfig, "DNS = 1.1.1.1", "DNS = 1.1.1.1, 2606:4700:4700::1111", 1))
	if e != nil {
		t.Fatal(e)
	}
	s := Settings{Mode: "lan", DNS: true}
	state := &State{}
	for _, n := range []Network{{"-4", "192.168.50.10/32", "br0", "iptables", "1.1.1.1"}, {"-6", "2001:db8:50::10/128", "br0", "ip6tables", "2606:4700:4700::1111"}} {
		if e := applyNetwork(state, c, s, n); e != nil {
			t.Fatal(e)
		}
	}
	out := strings.Join(commands, "\n")
	for _, required := range []string{"ip -4 route add 0.0.0.0/0", "ip -6 route add ::/0", "ip6tables -t nat -I POSTROUTING", "--dport 53", "--dport 853", "priority 10885", "--to-destination 2606:4700:4700::1111"} {
		if !strings.Contains(out, required) {
			t.Errorf("missing %s", required)
		}
	}
}
func TestGuardSurvivesTunnelCleanup(t *testing.T) {
	testEnvironment(t)
	old := guardPath
	guardPath = filepath.Join(runtimeDir, "guard.json")
	t.Cleanup(func() { guardPath = old })
	rules := map[string]bool{}
	runCommand = func(n string, args ...string) (string, error) {
		if n == "ip" {
			return "Cannot find device", errors.New("missing")
		}
		key := n + strings.Join(args[1:], " ")
		switch args[0] {
		case "-C":
			if !rules[key] {
				return "Bad rule", errors.New("missing")
			}
		case "-I":
			rules[key] = true
		case "-D":
			delete(rules, key)
		}
		return "", nil
	}
	if e := ensureGuard([]Network{{Family: "-4", Source: "192.168.50.10/32", LAN: "br0", Firewall: "iptables"}}); e != nil {
		t.Fatal(e)
	}
	count := len(rules)
	if count < 7 {
		t.Fatal("missing DNS fallback guards")
	}
	if e := writeJSON(statePath, State{}); e != nil {
		t.Fatal(e)
	}
	if e := down(); e != nil {
		t.Fatal(e)
	}
	if len(rules) != count || !exists(guardPath) {
		t.Fatal("tunnel failure removed protection")
	}
	if e := releaseGuard(); e != nil {
		t.Fatal(e)
	}
	if len(rules) != 0 || exists(guardPath) {
		t.Fatal("explicit stop left guard behind")
	}
}
func TestIPv6SourceValidation(t *testing.T) {
	testEnvironment(t)
	runCommand = func(n string, args ...string) (string, error) {
		return "2001:db8:50::/64 proto kernel metric 256\nfe80::/64 proto kernel metric 256", nil
	}
	s, e := source6(Settings{}, "br0")
	if e != nil || s != "2001:db8:50::/64" {
		t.Fatal(s, e)
	}
	if _, e = source6(Settings{Source6: "2001:db8:99::/64"}, "br0"); e == nil {
		t.Fatal("foreign IPv6 prefix accepted")
	}
}
func TestProfileTraversalRejected(t *testing.T) {
	for _, id := range []string{"../../etc/passwd", "/tmp/file", "1234", "AAAAAAAAAAAAAAAA"} {
		if _, e := profilePath(id); e == nil {
			t.Fatalf("accepted %s", id)
		}
	}
}
func TestProbeOutsideAllowedIPsRejected(t *testing.T) {
	c, e := Parse(strings.Replace(testConfig, "0.0.0.0/0, ::/0", "10.8.0.0/24", 1))
	if e != nil {
		t.Fatal(e)
	}
	if validateMonitor(c, Settings{Failover: true}) == nil {
		t.Fatal("probe outside VPN accepted")
	}
}
func TestGuardSnapshotContainsNoSecrets(t *testing.T) {
	g := guardCommands([]Network{{Family: "-6", Source: "2001:db8:50::/64", LAN: "br0", Firewall: "ip6tables"}})
	b, _ := json.Marshal(g)
	if strings.Contains(string(b), "private_key") {
		t.Fatal("secret stored")
	}
}
func TestProtectionRefusesEnabledAcceleration(t *testing.T) {
	testEnvironment(t)
	runCommand = func(name string, args ...string) (string, error) { return "0", nil }
	if requireSoftwarePath() == nil {
		t.Fatal("enabled acceleration accepted")
	}
	runCommand = func(name string, args ...string) (string, error) { return "1", nil }
	if e := requireSoftwarePath(); e != nil {
		t.Fatal(e)
	}
}
func TestPartialGuardIsNotReportedAsProtected(t *testing.T) {
	testEnvironment(t)
	old := guardPath
	guardPath = filepath.Join(runtimeDir, "guard.json")
	t.Cleanup(func() { guardPath = old })
	g := guardCommands([]Network{{Family: "-4", Source: "192.168.50.10/32", LAN: "br0", Firewall: "iptables"}})
	if e := writeJSON(guardPath, g); e != nil {
		t.Fatal(e)
	}
	complete := false
	runCommand = func(name string, args ...string) (string, error) {
		if name == "nvram" {
			return "1", nil
		}
		if !complete && strings.Contains(strings.Join(args, " "), "INPUT") {
			return "Bad rule", errors.New("missing")
		}
		return "", nil
	}
	if guardActive() {
		t.Fatal("incomplete guard was reported as effective")
	}
	complete = true
	if !guardActive() {
		t.Fatal("complete guard not detected")
	}
}
func TestProfileNamesAndFiles(t *testing.T) {
	testEnvironment(t)
	oldRoot, oldIndex := profileRoot, profileIndex
	profileRoot = filepath.Join(runtimeDir, "profiles")
	profileIndex = filepath.Join(runtimeDir, "profiles.json")
	t.Cleanup(func() { profileRoot, profileIndex = oldRoot, oldIndex })
	p := Profile{ID: "0123456789abcdef", Name: "测试节点"}
	if e := writeJSON(profileIndex, []Profile{p}); e != nil {
		t.Fatal(e)
	}
	path, e := profilePath(p.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = atomicWrite(path, []byte(testConfig)); e != nil {
		t.Fatal(e)
	}
	if _, e = configFor(p.ID); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(profileIndex)
	if e != nil || strings.Contains(string(b), "PrivateKey") {
		t.Fatal("index leaked config")
	}
}
