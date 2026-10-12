package asusctl

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPeerDisablePersistExportAndRestart(t *testing.T) {
	serverFixture(t)
	if e := serverSave(serverDefaults()); e != nil {
		t.Fatal(e)
	}
	if e := serverAdd("one"); e != nil {
		t.Fatal(e)
	}
	if e := serverAdd("two"); e != nil {
		t.Fatal(e)
	}
	c, _ := readServer()
	p := c.Clients[0]
	if e := serverSetDisabled(p.ID, true); e != nil {
		t.Fatal(e)
	}
	c, _ = readServer()
	if !c.Clients[0].Disabled || enabledClients(c) != 1 {
		t.Fatal("disable not persisted")
	}
	if strings.Contains(serverConf(c), p.Public) {
		t.Fatal("disabled peer would restart")
	}
	if _, e := serverExport(p.ID); e != nil {
		t.Fatal("disabled export must remain available")
	}
	if e := serverAdd("three"); e != nil {
		t.Fatal(e)
	}
	c, _ = readServer()
	if c.Clients[2].Address == p.Address {
		t.Fatal("disabled address reused")
	}
	for _, p := range c.Clients {
		if e := serverSetDisabled(p.ID, true); e != nil {
			t.Fatal(e)
		}
	}
	c, _ = readServer()
	if e := serverValidateCore(c); e != nil {
		t.Fatal("all-disabled settings cannot validate", e)
	}
	if enabledClients(c) != 0 {
		t.Fatal("unexpected enabled peers")
	}
	if e := serverSetDisabled(p.ID, false); e != nil {
		t.Fatal(e)
	}
	c, _ = readServer()
	if c.Clients[0].Private != p.Private || c.Clients[0].PSK != p.PSK {
		t.Fatal("enable regenerated keys")
	}
	var legacy ServerClient
	_ = json.Unmarshal([]byte(`{"id":"old"}`), &legacy)
	if legacy.Disabled {
		t.Fatal("legacy disabled")
	}
}
func TestHotPeerFailuresRollbackAndPending(t *testing.T) {
	serverFixture(t)
	_ = serverSave(serverDefaults())
	_ = serverAdd("one")
	original, _ := os.ReadFile(serverConfigPath)
	c, _ := readServer()
	id := c.Clients[0].ID
	_ = writeJSON(serverStatePath, State{})
	oldRPC, oldPersist := peerRPC, persistPeerConfig
	defer func() { peerRPC = oldRPC; persistPeerConfig = oldPersist }()
	calls := []string{}
	peerRPC = func(_ string, request string) (string, error) {
		calls = append(calls, request)
		if len(calls) == 2 {
			return "", errors.New("failure")
		}
		return "", nil
	}
	if serverSetDisabled(id, true) == nil {
		t.Fatal("failure swallowed")
	}
	now, _ := os.ReadFile(serverConfigPath)
	if string(now) != string(original) || exists(peerJournal()) {
		t.Fatal("rollback incomplete")
	}
	if len(calls) != 3 || !strings.Contains(calls[1], "remove=true") || !strings.Contains(calls[2], "preshared_key=") {
		t.Fatal("incorrect target rollback")
	}
	calls = nil
	persistPeerConfig = func(ServerConfig) error { return errors.New("disk full") }
	if serverSetDisabled(id, true) == nil || len(calls) != 1 {
		t.Fatal("runtime changed after persistence failure")
	}
	persistPeerConfig = oldPersist
	peerRPC = func(_ string, request string) (string, error) {
		if request == "get=1" {
			return "", nil
		}
		return "", errors.New("unavailable")
	}
	if serverSetDisabled(id, true) == nil || !exists(peerJournal()) {
		t.Fatal("missing crash journal")
	}
	if serverAdd("blocked") == nil {
		t.Fatal("pending transaction overwritten")
	}
	now, _ = os.ReadFile(serverConfigPath)
	if string(now) != string(original) {
		t.Fatal("old config not restored")
	}
}
func TestLogsBoundedAndNoSecrets(t *testing.T) {
	old := runtimeDir
	runtimeDir = t.TempDir()
	defer func() { runtimeDir = old }()
	for i := 0; i < 350; i++ {
		recordOperation("server-add", i%2 == 0)
	}
	recordOperation("server-export", true)
	logs := readLogs()
	if len(logs) != 200 {
		t.Fatal(len(logs))
	}
	st, e := os.Stat(filepath.Join(runtimeDir, "operations.json"))
	if e != nil || st.Size() > 65536 {
		t.Fatal("unbounded log")
	}
	b, _ := json.Marshal(logs)
	for _, secret := range []string{"private", "PSK", "server-export"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("unexpected sensitive data")
		}
	}
}
func TestDiagnosticsReadOnlyAndDNSFailure(t *testing.T) {
	serverFixture(t)
	_ = serverSave(serverDefaults())
	_ = serverAdd("one")
	_ = writeJSON(serverStatePath, State{})
	oldRPC, oldCommand, oldDNS, oldConf := peerRPC, diagnosticCommand, diagnosticDNS, diagnosticDNSConfig
	defer func() {
		peerRPC = oldRPC
		diagnosticCommand = oldCommand
		diagnosticDNS = oldDNS
		diagnosticDNSConfig = oldConf
	}()
	peerRPC = func(_, request string) (string, error) {
		if request != "get=1" {
			t.Fatal("diagnostic mutates core")
		}
		return "", nil
	}
	diagnosticDNSConfig = filepath.Join(t.TempDir(), "dnsmasq.conf")
	_ = os.WriteFile(diagnosticDNSConfig, []byte("# interface=awgs0\ninterface=br0\n"), 0600)
	diagnosticDNS = func() error { return errors.New("timeout") }
	diagnosticCommand = func(name string, args ...string) (string, error) {
		line := strings.Join(args, " ")
		if !strings.Contains(line, "show") && !strings.Contains(line, "-S") {
			t.Fatal("diagnostic command modifies state", line)
		}
		return "", errors.New("missing")
	}
	checks := diagnose()
	foundDNS, foundRegistration := false, false
	for _, d := range checks {
		if d.Name == "本机 DNS 解析" && d.State == "fail" {
			foundDNS = true
		}
		if d.Name == "DNS 接口登记" && d.State == "warn" {
			foundRegistration = true
		}
	}
	if !foundDNS || !foundRegistration {
		t.Fatal("false positive DNS diagnosis")
	}
}
