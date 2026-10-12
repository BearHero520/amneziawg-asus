package asusctl

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

func serverFixture(t *testing.T) {
	t.Helper()
	oldC, oldS, oldR, oldSocket := serverConfigPath, serverStatePath, runCommand, serverSocket
	dir := t.TempDir()
	serverSocket = filepath.Join(dir, "server.sock")
	serverConfigPath = filepath.Join(dir, "server.json")
	serverStatePath = filepath.Join(dir, "state.json")
	runCommand = func(name string, args ...string) (string, error) {
		if name == "nvram" && len(args) == 2 {
			switch args[1] {
			case "ddns_hostname_x":
				return "home.example.com", nil
			case "ddns_enable_x":
				return "1", nil
			case "wan0_ipaddr":
				return "203.0.113.9", nil
			case "lan_ipaddr":
				return "192.168.50.2", nil
			case "lan_netmask":
				return "255.255.255.0", nil
			case "lan_ifname":
				return "br0", nil
			}
		}
		return "", nil
	}
	t.Cleanup(func() { serverConfigPath, serverStatePath, runCommand, serverSocket = oldC, oldS, oldR, oldSocket })
}
func TestServerDevicesExportAndSecrets(t *testing.T) {
	serverFixture(t)
	s := serverDefaults()
	s.Address6 = "fd77:77::1/64"
	if e := serverSave(s); e != nil {
		t.Fatal(e)
	}
	if e := serverAdd("我的手机"); e != nil {
		t.Fatal(e)
	}
	if e := serverAdd("电脑"); e != nil {
		t.Fatal(e)
	}
	c, e := readServer()
	if e != nil {
		t.Fatal(e)
	}
	if c.Clients[0].Address == c.Clients[1].Address || c.Private == c.Clients[0].Private {
		t.Fatal("device isolation failed")
	}
	text, e := serverExport(c.Clients[0].ID)
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"Endpoint = home.example.com:51830", "192.168.50.0/24", "10.77.0.2/32", "fd77:77::2/128", c.Clients[0].Private, c.Public, c.Clients[0].PSK} {
		if !strings.Contains(text, want) {
			t.Fatalf("export missing %s", want)
		}
	}
	if strings.Contains(text, c.Private) || strings.Contains(text, c.Clients[1].Private) {
		t.Fatal("export exposed other private keys")
	}
	b, _ := json.Marshal(serverStatus())
	for _, secret := range []string{c.Private, c.Clients[0].Private, c.Clients[0].PSK, c.Clients[1].Private} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("status leaked key")
		}
	}
	c.Settings.Internet = true
	c.Settings.AllowLAN = false
	text, e = exportServerClient(c, c.Clients[0], "2001:db8::1", netip.MustParsePrefix("192.168.50.0/24"), nil)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(text, "AllowedIPs = 0.0.0.0/0, ::/0") || !strings.Contains(text, "Endpoint = [2001:db8::1]:51830") {
		t.Fatal("dual stack export wrong")
	}
	if e = serverDelete(c.Clients[0].ID); e != nil {
		t.Fatal(e)
	}
	if _, e = serverExport(c.Clients[0].ID); e == nil {
		t.Fatal("deleted device still exports")
	}
	if e = serverAdd("新手机"); e != nil {
		t.Fatal(e)
	}
	c, _ = readServer()
	if c.Clients[1].Address != "10.77.0.2/32" {
		t.Fatal("did not reuse free address")
	}
	if e = writeJSON(serverStatePath, State{}); e != nil {
		t.Fatal(e)
	}
	if serverAdd("blocked") == nil || serverDelete(c.Clients[0].ID) == nil || serverSave(s) == nil {
		t.Fatal("live mutation allowed")
	}
}
func TestServerValidationAndRollback(t *testing.T) {
	serverFixture(t)
	for _, extra := range []string{"PostUp = evil", "PrivateKey = fake", "Jc = 1\nJc = 2", "H1 = 1\rPrivateKey=bad"} {
		s := serverDefaults()
		s.Extra = extra
		if serverSave(s) == nil {
			t.Fatal("unsafe setting accepted")
		}
	}
	s := serverDefaults()
	s.Address = "192.168.1.5/24"
	if serverSave(s) == nil {
		t.Fatal("non-first host accepted")
	}
	s = serverDefaults()
	if e := serverSave(s); e != nil {
		t.Fatal(e)
	}
	if e := serverAdd("phone"); e != nil {
		t.Fatal(e)
	}
	s.Address = "10.78.0.1/24"
	if serverSave(s) == nil {
		t.Fatal("renumbered existing devices")
	}
	if e := writeJSON(serverStatePath, State{Undo: []Command{cmd("iptables", "-X", "AWGS_I"), cmd("iptables", "-D", "INPUT", "-i", "awgs0", "-j", "AWGS_I")}}); e != nil {
		t.Fatal(e)
	}
	var calls []string
	runCommand = func(name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		if strings.Contains(line, "link show") {
			return "Cannot find device", errors.New("missing")
		}
		if strings.Contains(line, "-D") {
			return "permission denied", errors.New("failure")
		}
		return "", nil
	}
	if serverDown() == nil {
		t.Fatal("rollback failure swallowed")
	}
	b, _ := os.ReadFile(serverStatePath)
	var state State
	_ = json.Unmarshal(b, &state)
	if len(state.Undo) != 1 || !strings.HasPrefix(calls[1], "ip link del") {
		t.Fatal("unsafe rollback ordering/journal")
	}
	runCommand = func(name string, args ...string) (string, error) {
		if name == "ip" && len(args) > 1 && args[1] == "show" {
			return "Cannot find device", errors.New("missing")
		}
		return "", nil
	}
	if e := serverDown(); e != nil {
		t.Fatal(e)
	}
	if exists(serverStatePath) {
		t.Fatal("journal not removed")
	}
}

// Interpret the generated forward-chain rules against representative packets.
func serverVerdict(plan []serverStep, in, out, dst, ct string) string {
	for _, step := range plan {
		a := step.Do.Args
		if len(a) < 4 || a[2] != "-A" || a[3] != "AWGS_F" {
			continue
		}
		match := true
		verdict := ""
		for i := 4; i+1 < len(a); i += 2 {
			key, v := a[i], a[i+1]
			switch key {
			case "-i":
				match = match && in == v
			case "-o":
				match = match && out == v
			case "-d":
				p, e := netip.ParsePrefix(v)
				match = match && e == nil && p.Contains(netip.MustParseAddr(dst))
			case "--ctstate":
				match = match && strings.Contains(v, ct)
			case "-j":
				verdict = v
			}
		}
		if match {
			return verdict
		}
	}
	return "NO MATCH"
}
func TestServerAccessTogglesEnforceForwarding(t *testing.T) {
	for _, family := range []string{"-4", "-6"} {
		lan := []string{"192.168.50.0/24"}
		private, public, peer := "192.168.50.10", "1.1.1.1", "10.77.0.2"
		address := "192.168.50.2"
		if family == "-6" {
			lan = []string{"2001:db8:50::/64"}
			private, public, peer = "2001:db8:50::10", "2606:4700:4700::1111", "fd77:77::2"
			address = ""
		}
		for _, allow := range []bool{false, true} {
			for _, internet := range []bool{false, true} {
				s := serverDefaults()
				s.AllowLAN = allow
				s.Internet = internet
				s.Address6 = "fd77:77::1/64"
				plan := serverPlan(s, family, "br0", "eth0", address, lan)
				wantLAN, wantNet := "REJECT", "REJECT"
				if allow {
					wantLAN = "ACCEPT"
				}
				if internet {
					wantNet = "ACCEPT"
				}
				for _, p := range []struct{ in, out, dst, ct, want string }{{"awgs0", "br0", private, "NEW", wantLAN}, {"awgs0", "eth0", public, "NEW", wantNet}, {"awgs0", "eth0", private, "NEW", "REJECT"}, {"awgs0", "awgs0", peer, "NEW", "REJECT"}, {"eth0", "awgs0", peer, "ESTABLISHED", "ACCEPT"}, {"eth0", "awgs0", peer, "NEW", "REJECT"}} {
					if got := serverVerdict(plan, p.in, p.out, p.dst, p.ct); got != p.want {
						t.Fatalf("%s LAN=%v Internet=%v %v got %s", family, allow, internet, p, got)
					}
				}
			}
		}
	}
}
func TestGeneratedServerAndExportCarryEncryptedTraffic(t *testing.T) {
	serverFixture(t)
	if e := serverSave(serverDefaults()); e != nil {
		t.Fatal(e)
	}
	if e := serverAdd("phone"); e != nil {
		t.Fatal(e)
	}
	c, _ := readServer()
	c.Settings.Port = 0
	var ds [2]*device.Device
	var ts [2]*tuntest.ChannelTUN
	for i := 0; i < 2; i++ {
		ts[i] = tuntest.NewChannelTUN()
		ds[i] = device.NewDevice(ts[i].TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
		defer ds[i].Close()
	}
	cfg, e := Parse(serverConf(c))
	if e != nil {
		t.Fatal(e)
	}
	u, _ := cfg.UAPI(resolveEndpoint)
	if e = ds[0].IpcSet(u); e != nil {
		t.Fatal(e)
	}
	if e = ds[0].Up(); e != nil {
		t.Fatal(e)
	}
	status, _ := ds[0].IpcGet()
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			c.Settings.Port, _ = strconv.Atoi(strings.TrimPrefix(line, "listen_port="))
		}
	}
	text, e := exportServerClient(c, c.Clients[0], "203.0.113.1", netip.MustParsePrefix("192.168.50.0/24"), nil)
	if e != nil {
		t.Fatal(e)
	}
	text = strings.ReplaceAll(text, "203.0.113.1", "127.0.0.1")
	cfg, e = Parse(text)
	if e != nil {
		t.Fatal(e)
	}
	u, e = cfg.UAPI(resolveEndpoint)
	if e != nil {
		t.Fatal(e)
	}
	if e = ds[1].IpcSet(u); e != nil {
		t.Fatal(e)
	}
	if e = ds[1].Up(); e != nil {
		t.Fatal(e)
	}
	checkTraffic := func() {
		for _, i := range []int{1, 0} {
			src, dst := "10.77.0.2", "10.77.0.1"
			if i == 0 {
				src, dst = dst, src
			}
			packet := tuntest.Ping(netip.MustParseAddr(dst), netip.MustParseAddr(src))
			gotPacket := false
			for attempt := 0; attempt < 12 && !gotPacket; attempt++ {
				select {
				case ts[i].Outbound <- packet:
				case <-time.After(time.Second):
					t.Fatal("TUN blocked")
				}
				select {
				case got := <-ts[i^1].Inbound:
					if !bytes.Equal(got, packet) {
						t.Fatal("payload differs")
					}
					gotPacket = true
				case <-time.After(500 * time.Millisecond):
				}
			}
			if !gotPacket {
				t.Fatal("exported client did not exchange encrypted traffic")
			}
		}
	}
	checkTraffic()
	originalPub, _ := keyHex(c.Clients[0].Public)
	oldRPC := peerRPC
	defer func() { peerRPC = oldRPC }()
	peerRPC = func(_ string, request string) (string, error) {
		if request == "get=1" {
			return ds[0].IpcGet()
		}
		if strings.Contains(request, originalPub) {
			t.Fatal("hot operation targeted unrelated peer")
		}
		if strings.Contains(request, "replace_peers") || strings.Contains(request, "private_key") || strings.Contains(request, "listen_port") {
			t.Fatal("hot update reset interface")
		}
		return "", ds[0].IpcSet(strings.TrimPrefix(request, "set=1\n"))
	}
	if e = writeJSON(serverStatePath, State{}); e != nil {
		t.Fatal(e)
	}
	baseline, _ := ds[0].IpcGet()
	if e = serverAdd("second device"); e != nil {
		t.Fatal(e)
	}
	checkTraffic()
	saved, _ := readServer()
	id := saved.Clients[1].ID
	targetPub, _ := keyHex(saved.Clients[1].Public)
	for _, disable := range []bool{true, false} {
		if e = serverSetDisabled(id, disable); e != nil {
			t.Fatal(e)
		}
		core, _ := ds[0].IpcGet()
		if strings.Contains(core, targetPub) == disable {
			t.Fatal("target runtime enable/disable incorrect")
		}
		checkTraffic()
	}
	if e = serverDelete(id); e != nil {
		t.Fatal(e)
	}
	checkTraffic()
	// The original peer's handshake session remains intact, in addition to packet delivery.
	after, _ := ds[0].IpcGet()
	handshake := func(text string) string {
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "last_handshake_time_") {
				return line
			}
		}
		return ""
	}
	if handshake(baseline) != handshake(after) {
		t.Fatal("unrelated handshake reset")
	}
}
