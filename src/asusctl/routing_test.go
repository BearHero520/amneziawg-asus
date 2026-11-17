package asusctl

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestRoutingValidationAndSharedGeoSources(t *testing.T) {
	r := RoutingSettings{
		Default: geoRef(2),
		Devices: []RoutingDevice{{"192.168.50.4", "direct"}, {"02:00:00:00:01:02", "vpn_all"}},
		Rules: []GeoRule{
			{ID: 1, Name: "服务", Mode: "include", GeoSite: "cn, github", Domains: "example.com\n# note\nexample.net"},
			{ID: 2, Name: "其它", Mode: "exclude", GeoIP: "cn", URLs: "https://example.test/ips?key=value", ExcludeNetworks: "203.0.113.0/24"},
		},
	}
	if err := r.validate(); err != nil {
		t.Fatal(err)
	}
	settings := policySettingsText(r)
	for _, text := range []string{"awg_geo_policies 1:1;2:2\n", "awg_geo_2_mode direct\n",
		"awg_geo_custom_domains example.com,example.net\n", "awg_geo_2_v2fly_ip cn\n",
		"awg_geo_2_custom_urls " + base64.StdEncoding.EncodeToString([]byte(r.Rules[1].URLs))} {
		if !strings.Contains(settings, text) {
			t.Fatal("missing setting:", text)
		}
	}
	r.Rules[1].ExcludeNetworks = "fd00::/64"
	if r.validate() == nil {
		t.Fatal("IPv6 list mixed with the IPv4 backend")
	}
	r.Rules[1].ExcludeNetworks = ""
	r.Rules[1].URLs = "file:///tmp/config"
	if r.validate() == nil {
		t.Fatal("non-HTTP file URL")
	}
	r.Rules[1].URLs = ""
	r.Devices = append(r.Devices, RoutingDevice{"02-00-00-00-01-02", "direct"})
	if r.validate() == nil {
		t.Fatal("accepted duplicate MAC with alternate notation")
	}
}

func TestRoutingClassifiesEachDeviceAndPreservesLAN(t *testing.T) {
	r := RoutingSettings{
		Default: "vpn_all",
		Devices: []RoutingDevice{{"192.168.50.20", "direct"}, {"02:34:56:aa:cc:ef", geoRef(2)}},
		Rules:   []GeoRule{{ID: 2, Name: "规则", Mode: "exclude", ExcludeDomains: "vpn.example.com"}},
	}
	old := runCommand
	t.Cleanup(func() { runCommand = old })
	runCommand = func(string, ...string) (string, error) { return "", errors.New("no proxy configured") }
	plan, err := policyClientRules(r, "br0", "192.168.50.0/24", "10.77.0.0/24", []string{"192.0.2.4"})
	if err != nil {
		t.Fatal(err)
	}
	var full strings.Builder
	for _, s := range plan {
		full.WriteString(strings.Join(s.Do.Args, " ") + "\n")
	}
	for _, rule := range []string{
		"AWGP_VPN -d 192.168.50.0/24 -j RETURN", "AWGP_VPN -d 10.77.0.0/24 -j RETURN",
		"AWGP_VPN -d 192.0.2.4 -j RETURN", "AWGP_LAN -s 192.168.50.20 -j RETURN",
		"AWGP_LAN -m mac --mac-source 02:34:56:aa:cc:ef -g AWGP_G2", "AWGP_G2 -m set --match-set awgp_dst2_x dst -g AWGP_VPN",
		"AWGP_G2 -m set --match-set awgp_dst2 dst -j RETURN", "PREROUTING -i br0 -j AWGP_LAN",
	} {
		if !strings.Contains(full.String(), rule) {
			t.Fatal("missing rule", rule)
		}
	}
}

func TestDeviceRouteKeepsKeysAndChangesOnlySelectedExport(t *testing.T) {
	serverFixture(t)
	s := serverDefaults()
	s.Internet = true
	if err := serverSave(s); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"手机", "公司电脑"} {
		if err := serverAdd(name); err != nil {
			t.Fatal(err)
		}
	}
	old, _ := readServer()
	lan := netip.MustParsePrefix("192.168.50.0/24")
	host := "vpn.example.com"
	before, err := exportServerClient(old, old.Clients[1], host, lan, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = serverSetDeviceRoute(old.Clients[0].ID, ServerDeviceRoute{Scope: "lan", Exit: "proxy"}); err != nil {
		t.Fatal(err)
	}
	if err = serverSetDeviceRoute(old.Clients[1].ID, ServerDeviceRoute{Exit: "wan"}); err != nil {
		t.Fatal(err)
	}
	current, _ := readServer()
	if current.Private != old.Private || current.Clients[0].Private != old.Clients[0].Private ||
		current.Clients[0].PSK != old.Clients[0].PSK || current.Clients[0].Address != old.Clients[0].Address {
		t.Fatal("identity or address changed")
	}
	phone, err := exportServerClient(current, current.Clients[0], host, lan, nil)
	if err != nil || !strings.Contains(phone, lan.String()) || strings.Contains(phone, "0.0.0.0/0") {
		t.Fatal("phone scope did not take effect", err)
	}
	office, err := exportServerClient(current, current.Clients[1], host, lan, nil)
	if err != nil || office != before {
		t.Fatal("egress change invalidated a previously exported profile", err)
	}
}

func TestDeviceFirewallScopeAndLiveRollback(t *testing.T) {
	serverFixture(t)
	s := serverDefaults()
	s.Internet = true
	_ = serverSave(s)
	_ = serverAdd("phone")
	_ = serverAdd("office")
	c, _ := readServer()
	_ = writeJSON(serverStatePath, State{})
	oldRPC, oldRun := peerRPC, runCommand
	t.Cleanup(func() { peerRPC, runCommand = oldRPC, oldRun })
	peerRPC = func(_ string, req string) (string, error) {
		if req != "get=1" {
			t.Fatal("routing change rewrote peers")
		}
		return "", nil
	}
	var commands []string
	fail := false
	runCommand = func(name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		commands = append(commands, line)
		if fail && strings.Contains(line, "-I SHADOWSOCKS 1") {
			fail = false
			return "test error", errors.New("test error")
		}
		return "", nil
	}
	if err := serverSetDeviceRoute(c.Clients[0].ID, ServerDeviceRoute{Exit: "wan"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(commands, "\n"), "-i awgs0 -s 10.77.0.2/32") {
		t.Fatal("peer bypass not limited to the tunnel and device")
	}
	fail = true
	commands = nil
	if err := serverSetDeviceRoute(c.Clients[1].ID, ServerDeviceRoute{Exit: "wan"}); err == nil {
		t.Fatal("iptables error lost")
	}
	if strings.Contains(strings.Join(commands, "\n"), "10.77.0.2/32") {
		t.Fatal("changing the office exit touched the phone's installed rules")
	}
	c, _ = readServer()
	if c.Clients[0].Route.Exit != "wan" || c.Clients[1].Route.Exit != "" || exists(peerJournal()) {
		t.Fatal("failed route change did not restore the previously running settings")
	}
	if err := clearDeviceRoutes(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(deviceRouteState()); !os.IsNotExist(err) {
		t.Fatal("device route journal not removed")
	}
}

func TestLegacyDeviceImportPreservesBothExistingAndImportedKeys(t *testing.T) {
	serverFixture(t)
	s := serverDefaults()
	s.Internet = true
	if err := serverSave(s); err != nil {
		t.Fatal(err)
	}
	if err := serverAdd("本机已有设备"); err != nil {
		t.Fatal(err)
	}
	current, _ := readServer()
	previousPath := legacyServerSettings
	legacyServerSettings = t.TempDir() + "/settings"
	t.Cleanup(func() { legacyServerSettings = previousPath })
	private, public, err := newServerKey()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := randomKey()
	if err != nil {
		t.Fatal(err)
	}
	record := strings.Join([]string{"手机", "10.9.0.2", "direct", "full", "1", public, private, psk, "0", "proxy"}, "|")
	archive := "awgs_peers " + record[:40] + "\nawgs_peers1 " + record[40:] + "\n"
	if err = os.WriteFile(legacyServerSettings, []byte(archive), 0600); err != nil {
		t.Fatal(err)
	}
	if n, err := importLegacyDevices(); n != 1 || err != nil {
		t.Fatalf("import (%d): %v", n, err)
	}
	migrated, _ := readServer()
	if migrated.Public != current.Public || migrated.Clients[0] != current.Clients[0] {
		t.Fatal("migration changed existing identity")
	}
	p := migrated.Clients[1]
	if p.Private != private || p.PSK != psk || p.Address != "10.77.0.3/32" || p.Route.Exit != "proxy" {
		t.Fatal("imported peer keys or routing do not match")
	}
	if n, err := importLegacyDevices(); n != 0 || err != nil {
		t.Fatalf("duplicate import (%d): %v", n, err)
	}
}

func TestPolicyFullIPv4Coverage(t *testing.T) {
	config := &Config{Peers: []Peer{
		{Allowed: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/2"), netip.MustParsePrefix("64.0.0.0/2")}},
		{Allowed: []netip.Prefix{netip.MustParsePrefix("128.0.0.0/2"), netip.MustParsePrefix("192.0.0.0/2")}},
	}}
	if !ipv4Default(config) {
		t.Fatal("split IPv4 default route not recognized")
	}
	config.Peers[1].Allowed = config.Peers[1].Allowed[:1]
	if ipv4Default(config) {
		t.Fatal("incomplete default route")
	}
}
