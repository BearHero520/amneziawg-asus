package asusctl

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func watchFixture(t *testing.T) (*int, *int, *bool, *int64) {
	serverFixture(t)
	oldR, oldB, oldN, oldU, oldD, oldH := runtimeDir, bootID, serverNow, supervisedUp, supervisedDown, supervisedHealthy
	runtimeDir = t.TempDir()
	bootID = func() string { return "boot-a" }
	now := int64(1000)
	serverNow = func() int64 { return now }
	ups, downs := 0, 0
	healthy := false
	supervisedUp = func() error { ups++; healthy = true; return nil }
	supervisedDown = func() error { downs++; healthy = false; return nil }
	supervisedHealthy = func() bool { return healthy }
	t.Cleanup(func() {
		runtimeDir, bootID, serverNow, supervisedUp, supervisedDown, supervisedHealthy = oldR, oldB, oldN, oldU, oldD, oldH
	})
	if e := writeJSON(serverConfigPath, ServerConfig{Settings: ServerSettings{Auto: true}}); e != nil {
		t.Fatal(e)
	}
	return &ups, &downs, &healthy, &now
}
func TestWatchManualStopSurvivesHooks(t *testing.T) {
	ups, _, _, _ := watchFixture(t)
	if e := manualServerStart(); e != nil {
		t.Fatal(e)
	}
	if e := manualServerStop(); e != nil {
		t.Fatal(e)
	}
	for _, a := range []string{"server-recover", "server-boot"} {
		if _, e := execute(a); e != nil {
			t.Fatal(e)
		}
	}
	if e := superviseServer(false); e != nil {
		t.Fatal(e)
	}
	if *ups != 1 {
		t.Fatal("manual stop was ignored")
	}
	bootID = func() string { return "boot-b" }
	if e := superviseServer(false); e != nil {
		t.Fatal(e)
	}
	if *ups != 2 {
		t.Fatal("real reboot did not apply auto")
	}
}
func TestWatchBackoffSurvivesMissingState(t *testing.T) {
	_, _, _, now := watchFixture(t)
	attempts := 0
	supervisedUp = func() error { attempts++; return errors.New("iptables rule failed") }
	for n, delay := range []int64{60, 120, 240, 300, 300} {
		if e := superviseServer(false); e == nil {
			t.Fatal("expected failure")
		}
		r := serverRetry()
		if r.Failures != n+1 || r.Next != *now+delay {
			t.Fatalf("bad retry: %+v", r)
		}
		if exists(serverStatePath) {
			t.Fatal("test requires absent state")
		}
		if e := superviseServer(false); e != nil {
			t.Fatal(e)
		}
		if attempts != n+1 {
			t.Fatal("retried before deadline")
		}
		*now = r.Next
	}
	if e := manualServerStop(); e != nil {
		t.Fatal(e)
	}
	*now += 1000
	_ = superviseServer(false)
	if attempts != 5 || exists(serverRetryPath()) {
		t.Fatal("stop did not cancel retries")
	}
}
func TestWatchHealthyAndQueuedEvents(t *testing.T) {
	ups, _, healthy, _ := watchFixture(t)
	*healthy = true
	if e := superviseServer(false); e != nil {
		t.Fatal(e)
	}
	if *ups != 0 {
		t.Fatal("healthy core restarted")
	}
	if e := queueServerRecovery(); e != nil {
		t.Fatal(e)
	}
	supervisedUp = func() error { *ups++; *healthy = true; return atomicWrite(serverEventPath(), []byte("new-event")) }
	if e := superviseServer(false); e != nil {
		t.Fatal(e)
	}
	if pendingServerEvent() != "new-event" {
		t.Fatal("event arriving during recovery was lost")
	}
	supervisedUp = func() error { *ups++; *healthy = true; return nil }
	if e := superviseServer(false); e != nil {
		t.Fatal(e)
	}
	if *ups != 2 || pendingServerEvent() != "" {
		t.Fatal("events did not drain")
	}
	_ = superviseServer(false)
	if *ups != 2 {
		t.Fatal("healthy core restarted again")
	}
}
func TestWatchBusyLockRetainsRecoveryEvent(t *testing.T) {
	ups, _, _, _ := watchFixture(t)
	if e := os.Mkdir(filepath.Join(runtimeDir, "lock"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := execute("server-recover"); e == nil {
		t.Fatal("expected busy lock")
	}
	if pendingServerEvent() == "" {
		t.Fatal("lock collision lost event")
	}
	_ = os.Remove(filepath.Join(runtimeDir, "lock"))
	if e := superviseServer(false); e != nil {
		t.Fatal(e)
	}
	if *ups != 1 {
		t.Fatal("queued event not recovered")
	}
}
func TestWatchCleanupFailureAndPendingPeer(t *testing.T) {
	ups, _, _, now := watchFixture(t)
	supervisedDown = func() error { return errors.New("cleanup failed") }
	if e := superviseServer(false); e == nil {
		t.Fatal("expected cleanup error")
	}
	if *ups != 0 {
		t.Fatal("started over dirty state")
	}
	*now = serverRetry().Next
	_ = atomicWrite(peerJournal(), []byte("{}"))
	if e := superviseServer(false); e == nil {
		t.Fatal("expected transaction error")
	}
	if *ups != 0 {
		t.Fatal("modified pending peer transaction")
	}
	if e := manualServerStop(); e == nil {
		t.Fatal("expected cleanup error")
	}
	i, e := serverIntent()
	if e != nil || i.Wanted {
		t.Fatal("failed cleanup lost manual stop")
	}
}
func TestWatchMigrationAndRebootAutoOff(t *testing.T) {
	ups, _, _, _ := watchFixture(t)
	_ = writeJSON(serverConfigPath, ServerConfig{})
	_ = atomicWrite(serverStatePath, []byte("{}"))
	i, e := serverIntent()
	if e != nil || !i.Wanted {
		t.Fatal("running migration lost intent")
	}
	_ = os.Remove(serverStatePath)
	bootID = func() string { return "boot-b" }
	_ = superviseServer(false)
	if *ups != 0 {
		t.Fatal("auto off ignored after reboot")
	}
	_ = atomicWrite(serverIntentPath(), []byte("broken"))
	if e := superviseServer(false); e == nil {
		t.Fatal("corrupt intent must fail closed")
	}
}
func TestWatchRecoverySuccessClearsRetryAndRedactsLogs(t *testing.T) {
	_, _, healthy, now := watchFixture(t)
	supervisedUp = func() error {
		return errors.New("PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\ncommand failed")
	}
	_ = superviseServer(false)
	*now = serverRetry().Next
	supervisedUp = func() error { *healthy = true; return nil }
	if e := superviseServer(false); e != nil {
		t.Fatal(e)
	}
	if exists(serverRetryPath()) {
		t.Fatal("retry not cleared")
	}
	b, e := os.ReadFile(filepath.Join(runtimeDir, "operations.json"))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(b), "AAAAAAAA") || !strings.Contains(string(b), "恢复成功") {
		t.Fatal("bad recovery log")
	}
}

func TestWatchFirmwareStopPreservesIntent(t *testing.T) {
	ups, _, _, _ := watchFixture(t)
	if e := manualServerStart(); e != nil {
		t.Fatal(e)
	}
	if _, e := execute("server-service-stop"); e != nil {
		t.Fatal(e)
	}
	if e := superviseServer(false); e != nil {
		t.Fatal(e)
	}
	if *ups != 1 {
		t.Fatal("started during firmware suspension")
	}
	if _, e := execute("server-boot"); e != nil {
		t.Fatal(e)
	}
	if *ups != 2 {
		t.Fatal("firmware restart lost wanted state")
	}
	_ = manualServerStop()
	_, _ = execute("server-service-stop")
	_, _ = execute("server-boot")
	if *ups != 2 {
		t.Fatal("firmware restart undid manual stop")
	}
}
func TestWatchCoreUpdateBlocksMutations(t *testing.T) {
	ups, _, _, _ := watchFixture(t)
	old := updateRoot
	updateRoot = t.TempDir()
	t.Cleanup(func() { updateRoot = old })
	_ = atomicWrite(updateFile("update-busy"), []byte("busy"))
	if _, e := execute("watch"); e == nil {
		t.Fatal("watch ignored update")
	}
	if _, e := execute("server-recover"); e == nil {
		t.Fatal("hook ignored update")
	}
	if *ups != 0 || pendingServerEvent() == "" {
		t.Fatal("update must retain event without starting")
	}
}
