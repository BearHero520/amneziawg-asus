package asusctl

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type coreTransport func(*http.Request) (*http.Response, error)

func (f coreTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func fakeCore(tail byte) []byte {
	b := make([]byte, 2048)
	copy(b, "\x7fELF")
	b[4] = 2
	b[5] = 1
	b[18] = 183
	b[len(b)-1] = tail
	return b
}
func coreTestEnv(t *testing.T) {
	t.Helper()
	oldRoot, oldBin, oldArch, oldProbe, oldSpace, oldChild, oldHTTP, oldBoot, oldRuntime := updateRoot, coreBinary, coreArch, probeCore, coreSpace, coreChild, coreHTTP, bootID, runtimeDir
	base := t.TempDir()
	updateRoot = filepath.Join(base, "data")
	coreBinary = filepath.Join(base, "core")
	runtimeDir = filepath.Join(base, "runtime")
	coreArch = func() string { return "arm64" }
	coreSpace = func(int64) error { return nil }
	probeCore = func(string) (CoreInfo, error) { return CoreInfo{"0.5.1", "arm64", 1, "0.5"}, nil }
	bootID = func() string { return "boot-2" }
	t.Cleanup(func() {
		updateRoot, coreBinary, coreArch, probeCore, coreSpace, coreChild, coreHTTP, bootID, runtimeDir = oldRoot, oldBin, oldArch, oldProbe, oldSpace, oldChild, oldHTTP, oldBoot, oldRuntime
	})
	if e := os.WriteFile(coreBinary, fakeCore(0), 0755); e != nil {
		t.Fatal(e)
	}
}
func TestCoreUpdateFilesystemRecovery(t *testing.T) {
	for _, kind := range []string{"success", "hash", "download", "probe", "space", "restart", "rollback-failure"} {
		t.Run(kind, func(t *testing.T) {
			coreTestEnv(t)
			candidate := fakeCore(1)
			m := testManifest()
			a := m.Assets["arm64"]
			h := sha256.Sum256(candidate)
			a.SHA256 = hex.EncodeToString(h[:])
			m.Assets["arm64"] = a
			coreHTTP = &http.Client{Transport: coreTransport(func(*http.Request) (*http.Response, error) {
				if kind == "download" {
					return nil, errors.New("offline")
				}
				data := append([]byte(nil), candidate...)
				if kind == "hash" {
					data[22] = 1
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data))}, nil
			})}
			if kind == "probe" {
				probeCore = func(string) (CoreInfo, error) { return CoreInfo{}, errors.New("not executable") }
			}
			if kind == "space" {
				coreSpace = func(int64) error { return errors.New("no space") }
			}
			var calls []string
			starts := 0
			coreChild = func(action string, j CoreJob) error {
				calls = append(calls, action)
				if action == "core-resume" {
					starts++
					if kind == "rollback-failure" || (kind == "restart" && starts == 1) {
						return errors.New("cannot start")
					}
				}
				return nil
			}
			j := CoreJob{Offer: m, Client: true, Server: true, Token: "test", Boot: "boot-2"}
			if e := atomicWrite(updateFile("update-busy"), []byte("test")); e != nil {
				t.Fatal(e)
			}
			secret := []byte("private config remains local")
			config := updateFile("config/example")
			if e := atomicWrite(config, secret); e != nil {
				t.Fatal(e)
			}
			err := prepareAndUpdate(&j)
			got, _ := os.ReadFile(coreBinary)
			kept, _ := os.ReadFile(config)
			if !bytes.Equal(kept, secret) {
				t.Fatal("config changed")
			}
			if kind == "success" {
				if err != nil || !bytes.Equal(got, candidate) || j.Phase != "success" || updateBusy() {
					t.Fatalf("success %v %+v", err, j)
				}
			} else {
				if err == nil {
					t.Fatal("failure returned success")
				}
				if !bytes.Equal(got, fakeCore(0)) {
					t.Fatal("old core not preserved/restored")
				}
				if kind == "restart" {
					if j.Phase != "rolled_back" || updateBusy() {
						t.Fatal(j.Phase)
					}
				} else if kind == "rollback-failure" {
					if j.Phase != "recovery_required" || !updateBusy() || !exists(updateFile("update-pending")) {
						t.Fatal("lost recovery state")
					}
				} else {
					if len(calls) != 0 || updateBusy() || j.Phase != "failed" {
						t.Fatalf("preflight touched services: %v %s", calls, j.Phase)
					}
				}
			}
			if exists(coreBinary + ".candidate") {
				t.Fatal("staging file leaked")
			}
		})
	}
}
func TestCoreRebootRecovery(t *testing.T) {
	coreTestEnv(t)
	old := fakeCore(0)
	h := sha256.Sum256(old)
	meta := CoreBackup{Info: coreInfo(), SHA256: hex.EncodeToString(h[:])}
	if e := linkExecutable(coreBinary, coreBinary+".previous"); e != nil {
		t.Fatal(e)
	}
	if e := writeJSON(updateFile("core-backup.json"), meta); e != nil {
		t.Fatal(e)
	}
	if e := writeExecutable(coreBinary, fakeCore(1)); e != nil {
		t.Fatal(e)
	}
	j := CoreJob{Token: "test", Boot: "boot-2"}
	_ = saveJob(&j, "activating", "pending")
	_ = atomicWrite(updateFile("update-busy"), []byte("test"))
	_ = atomicWrite(updateFile("update-pending"), []byte("test"))
	if recoverCoreBoot() == nil {
		t.Fatal("same-boot recovery allowed during live update")
	}
	bootID = func() string { return "boot-3" }
	if e := recoverCoreBoot(); e != nil {
		t.Fatal(e)
	}
	got, _ := os.ReadFile(coreBinary)
	if !bytes.Equal(got, old) || updateBusy() || exists(updateFile("update-pending")) {
		t.Fatal("reboot failed to restore")
	}
	if !strings.Contains(loadJob().Message, "中断") {
		t.Fatal("missing interrupted result")
	}
}

func TestCoreManualRollbackKeepsUndoBackup(t *testing.T) {
	coreTestEnv(t)
	oldVersion := coreVersion
	coreVersion = "0.5.1"
	defer func() { coreVersion = oldVersion }()
	previous := fakeCore(0)
	current := fakeCore(1)
	if e := os.WriteFile(coreBinary, current, 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(coreBinary+".previous", previous, 0755); e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(previous)
	meta := CoreBackup{Info: CoreInfo{"0.5.0", "arm64", 1, "0.5"}, SHA256: hex.EncodeToString(hash[:])}
	if e := writeJSON(updateFile("core-backup.json"), meta); e != nil {
		t.Fatal(e)
	}
	probeCore = func(string) (CoreInfo, error) { return meta.Info, nil }
	coreChild = func(string, CoreJob) error { return nil }
	coreHTTP = &http.Client{Transport: coreTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("rollback must work offline")
		return nil, errors.New("unexpected request")
	})}
	_ = atomicWrite(updateFile("update-busy"), []byte("test"))
	j := CoreJob{Rollback: true, Token: "test", Client: true, Server: true}
	if e := prepareAndUpdate(&j); e != nil {
		t.Fatal(e)
	}
	active, _ := os.ReadFile(coreBinary)
	backup, _ := os.ReadFile(coreBinary + ".previous")
	if !bytes.Equal(active, previous) || !bytes.Equal(backup, current) || updateBusy() {
		t.Fatal("manual rollback lost active or undo backup")
	}
	if e := loadJSONFile(updateFile("core-backup.json"), &meta); e != nil || meta.Info.Version != "0.5.1" {
		t.Fatal("incorrect undo version", e)
	}
}
