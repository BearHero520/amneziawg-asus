package asusctl

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

const testConfig = `[Interface]
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Address = 10.8.0.2/32, fd00::2/128
DNS = 1.1.1.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 16
S2 = 20
H1 = 100000-100001
H2 = 200000-200001
H3 = 300000-300001
H4 = 400000-400001
[Peer]
PresharedKey = AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
PersistentKeepalive = 25
`

func TestParseAndEngineCompatibility(t *testing.T) {
	for _, extra := range []string{"", "S3 = 16\nS4 = 16\nI1 = <b 0xdeadbeef>\nHeaderProtectionKey = BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nContentPaddingAddition = 0-4\nRekeyAfterTime = 110-120\nRandomTrailers = true\n"} {
		c, e := Parse(strings.Replace(testConfig, "[Peer]", extra+"[Peer]", 1))
		if e != nil {
			t.Fatal(e)
		}
		u, e := c.UAPI(func(s string) (string, error) { return "127.0.0.1:51820", nil })
		if e != nil {
			t.Fatal(e)
		}
		pub := strings.Index(u, "public_key=")
		psk := strings.Index(u, "preshared_key=")
		if pub < 0 || psk < pub {
			t.Fatal("peer public key must precede peer fields")
		}
		binds := bindtest.NewChannelBinds()
		tun := tuntest.NewChannelTUN()
		d := device.NewDevice(tun.TUN(), binds[0], device.NewLogger(device.LogLevelSilent, ""))
		if e = d.IpcSet(u); e != nil {
			d.Close()
			t.Fatalf("upstream rejected generated UAPI: %v", e)
		}
		d.Close()
	}
}
func TestRejectUnsafeAndInvalidConfig(t *testing.T) {
	cases := []string{
		strings.Replace(testConfig, "DNS = 1.1.1.1", "PostUp = touch /tmp/injected", 1),
		strings.Replace(testConfig, "DNS = 1.1.1.1", "PrivateKey = SECRET", 1),
		strings.Replace(testConfig, "10.8.0.2/32", "10.8.0.999/32", 1),
		strings.Replace(testConfig, "vpn.example.com:51820", "x;touch /tmp/pwn:51820", 1),
		strings.Replace(testConfig, "Jc = 4", "Jc = -1", 1),
		strings.Replace(testConfig, "100000-100001", "100001-100000", 1),
		strings.Replace(testConfig, "DNS = 1.1.1.1", "FwMark = 99", 1),
		testConfig + "[Interface]\nPrivateKey = x\n",
		strings.Repeat("x", 32769),
	}
	for i, c := range cases {
		if _, e := Parse(c); e == nil {
			t.Errorf("case %d accepted", i)
		} else if strings.Contains(e.Error(), "SECRET") {
			t.Fatal("secret leaked in error")
		}
	}
}
func TestEndpointFailure(t *testing.T) {
	c, _ := Parse(testConfig)
	if _, e := c.UAPI(func(string) (string, error) { return "", errors.New("no DNS") }); e == nil {
		t.Fatal("resolution failure ignored")
	}
}
func testEnvironment(t *testing.T) {
	t.Helper()
	oldState, oldRuntime, oldSocket, oldRun := statePath, runtimeDir, socket, runCommand
	runtimeDir = t.TempDir()
	statePath = filepath.Join(runtimeDir, "state.json")
	socket = filepath.Join(runtimeDir, "awg.sock")
	t.Cleanup(func() { statePath, runtimeDir, socket, runCommand = oldState, oldRuntime, oldSocket, oldRun })
}
func TestRollbackReverseOrder(t *testing.T) {
	testEnvironment(t)
	var calls []string
	runCommand = func(n string, args ...string) (string, error) {
		calls = append(calls, n+" "+strings.Join(args, " "))
		if strings.Join(args, " ") == "link show dev awg0" {
			return "Cannot find device", errors.New("missing")
		}
		return "", nil
	}
	s := &State{}
	for _, x := range []string{"one", "two", "three"} {
		if e := transact(s, cmd("fake", "add", x), cmd("fake", "del", x)); e != nil {
			t.Fatal(e)
		}
	}
	calls = nil
	if e := down(); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(calls[:3], []string{"fake del three", "fake del two", "fake del one"}) {
		t.Fatal(calls)
	}
	if exists(statePath) {
		t.Fatal("state not removed")
	}
}
func TestFailedCleanupKeepsJournal(t *testing.T) {
	testEnvironment(t)
	runCommand = func(n string, args ...string) (string, error) {
		if n == "fake" {
			return "permission denied", errors.New("permission denied")
		}
		return "Cannot find device", errors.New("missing")
	}
	if e := writeJSON(statePath, State{Undo: []Command{cmd("fake", "del")}}); e != nil {
		t.Fatal(e)
	}
	if down() == nil {
		t.Fatal("cleanup failure hidden")
	}
	if !exists(statePath) {
		t.Fatal("journal lost")
	}
}
func TestReservedPolicyCollision(t *testing.T) {
	testEnvironment(t)
	runCommand = func(n string, args ...string) (string, error) { return "10888: from all lookup other", nil }
	if preflightLAN() == nil {
		t.Fatal("collision accepted")
	}
}
func TestSourceMustBelongToLAN(t *testing.T) {
	testEnvironment(t)
	runCommand = func(n string, args ...string) (string, error) {
		if args[1] == "lan_ipaddr" {
			return "192.168.50.2", nil
		}
		return "255.255.255.0", nil
	}
	if _, e := lanSource(Settings{Source: "192.168.60.0/24"}); e == nil {
		t.Fatal("foreign network accepted")
	}
	if s, e := lanSource(Settings{Source: "192.168.50.10/32"}); e != nil || s != "192.168.50.10/32" {
		t.Fatal(s, e)
	}
}
func TestAtomicWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config", "client.conf")
	for _, v := range []string{"old", "new"} {
		if e := atomicWrite(p, []byte(v)); e != nil {
			t.Fatal(e)
		}
	}
	b, e := os.ReadFile(p)
	if e != nil || string(b) != "new" {
		t.Fatal(string(b), e)
	}
}
