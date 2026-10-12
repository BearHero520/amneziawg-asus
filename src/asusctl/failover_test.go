package asusctl

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFailoverThresholdOrderAndGuardPreservation(t *testing.T) {
	testEnvironment(t)
	oldSettings, oldHealth, oldGuard := settingsPath, healthPath, guardPath
	oldCandidate, oldWait := switchCandidate, waitAfterSwitch
	settingsPath = filepath.Join(runtimeDir, "settings.json")
	healthPath = filepath.Join(runtimeDir, "health.json")
	guardPath = filepath.Join(runtimeDir, "guard.json")
	t.Cleanup(func() {
		settingsPath, healthPath, guardPath = oldSettings, oldHealth, oldGuard
		switchCandidate, waitAfterSwitch = oldCandidate, oldWait
	})
	s := Settings{Mode: "lan", Failover: true, KillSwitch: true, DNS: true, Profile: "1111111111111111", Fallbacks: []string{"2222222222222222", "3333333333333333"}}
	if e := writeJSON(settingsPath, s); e != nil {
		t.Fatal(e)
	}
	if e := writeJSON(guardPath, Guard{}); e != nil {
		t.Fatal(e)
	}
	var attempts []string
	switchCandidate = func(id string) error { attempts = append(attempts, id); return errors.New("candidate unavailable") }
	waitAfterSwitch = func() {}
	for fail := 0; fail < 3; fail++ {
		h := health()
		h.LastCheck = 0
		if e := writeJSON(healthPath, h); e != nil {
			t.Fatal(e)
		}
		if e := watch(); e != nil {
			t.Fatal(e)
		}
		if fail < 2 && len(attempts) > 0 {
			t.Fatal("switched before 3 failures")
		}
	}
	want := []string{"2222222222222222", "3333333333333333", "1111111111111111"}
	if !reflect.DeepEqual(attempts, want) {
		t.Fatalf("%v != %v", attempts, want)
	}
	if !exists(guardPath) {
		t.Fatal("all-candidate failure removed guard")
	}
	h := health()
	if h.Failures != 3 || h.LastSwitch == 0 {
		t.Fatal(h)
	}
	h.LastCheck = 0
	_ = writeJSON(healthPath, h)
	if e := watch(); e != nil {
		t.Fatal(e)
	}
	if len(attempts) != 3 {
		t.Fatal("cooldown ignored")
	}
}
func TestManualStopPreventsWatchRestart(t *testing.T) {
	testEnvironment(t)
	oldSettings, oldHealth, oldGuard := settingsPath, healthPath, guardPath
	oldCandidate := switchCandidate
	settingsPath = filepath.Join(runtimeDir, "settings.json")
	healthPath = filepath.Join(runtimeDir, "health.json")
	guardPath = filepath.Join(runtimeDir, "guard.json")
	t.Cleanup(func() {
		settingsPath, healthPath, guardPath = oldSettings, oldHealth, oldGuard
		switchCandidate = oldCandidate
	})
	_ = writeJSON(settingsPath, Settings{Failover: true})
	switchCandidate = func(string) error { t.Fatal("manual stop restarted tunnel"); return nil }
	if e := watch(); e != nil {
		t.Fatal(e)
	}
}
