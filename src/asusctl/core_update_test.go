package asusctl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func testManifest() CoreManifest {
	return CoreManifest{Version: "0.5.1", Series: coreSeries, ABI: coreABI, Assets: map[string]CoreAsset{"arm64": {URL: coreReleaseBase + "0.5.1/amneziawg-core_0.5.1_arm64", SHA256: strings.Repeat("a", 64), Size: 2048}}}
}
func TestCoreManifestTrust(t *testing.T) {
	m := testManifest()
	if e := validateManifest(m, "arm64"); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*CoreManifest){func(m *CoreManifest) { m.ABI++ }, func(m *CoreManifest) { m.Series = "0.6" }, func(m *CoreManifest) { m.Version = "../../x" }, func(m *CoreManifest) { a := m.Assets["arm64"]; a.URL = "https://evil.test/core"; m.Assets["arm64"] = a }, func(m *CoreManifest) { a := m.Assets["arm64"]; a.Size = 33 << 20; m.Assets["arm64"] = a }, func(m *CoreManifest) { a := m.Assets["arm64"]; a.SHA256 = "bad"; m.Assets["arm64"] = a }} {
		m = testManifest()
		change(&m)
		if validateManifest(m, "arm64") == nil {
			t.Fatal("accepted invalid manifest", m)
		}
	}
	if validateManifest(testManifest(), "armv7") == nil {
		t.Fatal("missing architecture accepted")
	}
	for _, s := range []string{"http://github.com/x", "https://github.com.evil.test/x", "https://user@github.com/x", "https://github.com:444/x", "file:///tmp/core"} {
		if trustedCoreURL(s) {
			t.Fatal(s)
		}
	}
	if !trustedCoreURL("https://release-assets.githubusercontent.com/x") {
		t.Fatal("valid redirect rejected")
	}
}

type updateCheckTransport func(*http.Request) (*http.Response, error)

func (f updateCheckTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOnlineCheckOffersFullPluginSeparatelyFromCore(t *testing.T) {
	oldRoot, oldArch, oldVersion, oldHTTP := updateRoot, coreArch, coreVersion, coreHTTP
	t.Cleanup(func() {
		updateRoot, coreArch, coreVersion, coreHTTP = oldRoot, oldArch, oldVersion, oldHTTP
	})
	updateRoot = t.TempDir()
	coreArch = func() string { return "arm64" }
	coreVersion = "0.5.6"
	if err := os.WriteFile(updateFile("plugin-version"), []byte("0.5.5\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := testManifest()
	m.Version = "0.5.6"
	m.Assets["arm64"] = CoreAsset{
		URL: coreReleaseBase + "0.5.6/amneziawg-core_0.5.6_arm64", SHA256: strings.Repeat("a", 64), Size: 2048,
	}
	pkg := CoreAsset{
		URL: coreReleaseBase + "0.5.6/amneziawg_0.5.6_arm64.tar.gz", SHA256: strings.Repeat("b", 64), Size: 4096,
	}
	m.Packages = map[string]CoreAsset{"arm64": pkg}
	requests := 0
	coreHTTP = &http.Client{Transport: updateCheckTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.URL.String() != coreFeed || r.Method != http.MethodGet {
			t.Fatalf("unexpected update request: %s %s", r.Method, r.URL)
		}
		body, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})}
	if err := checkCore(); err != nil {
		t.Fatal(err)
	}
	s := coreStatus()
	if requests != 1 || s.Checked == 0 || s.Available || s.Release == nil || !s.Release.Available ||
		s.Release.Package == nil || *s.Release.Package != pkg {
		t.Fatalf("expected a complete package when the core is already current: %+v", s)
	}
	m.ABI++
	if err := checkCore(); err != nil {
		t.Fatal("an incompatible core should still offer the full plugin", err)
	}
	s = coreStatus()
	if s.Latest != "" || s.Available || s.Release == nil || s.Release.Package == nil {
		t.Fatalf("expected a package-only upgrade: %+v", s)
	}
	m.ABI = coreABI
	pkg.URL = "https://example.org/amneziawg_0.5.6_arm64.tar.gz"
	m.Packages["arm64"] = pkg
	if err := checkCore(); err != nil {
		t.Fatal("the valid core should still be recognized", err)
	}
	if s = coreStatus(); s.Release == nil || s.Release.Package != nil {
		t.Fatal("an untrusted package URL was offered")
	}
}
func TestCoreVersionOrdering(t *testing.T) {
	for _, v := range []string{"0.5.1", "0.5.10", "1.0.0"} {
		if !newerCore(v, "0.5.0") {
			t.Fatal(v)
		}
	}
	for _, v := range []string{"0.5.0", "0.4.9", "0.5.x", "v0.5.1", "00.5.1", "0.5.1;sh"} {
		if newerCore(v, "0.5.0") {
			t.Fatal(v)
		}
	}
}
func TestCoreHashAndArchitecture(t *testing.T) {
	b := make([]byte, 2048)
	copy(b, "\x7fELF")
	b[4] = 2
	b[5] = 1
	b[18] = 183
	h := sha256.Sum256(b)
	a := CoreAsset{Size: int64(len(b)), SHA256: hex.EncodeToString(h[:])}
	if e := verifyCoreBytes(b, a, "arm64"); e != nil {
		t.Fatal(e)
	}
	if verifyCoreBytes(b, a, "armv7") == nil {
		t.Fatal("architecture accepted")
	}
	b[80] = 1
	if verifyCoreBytes(b, a, "arm64") == nil {
		t.Fatal("tampered binary accepted")
	}
	if verifyCoreInfo(CoreInfo{"0.5.1", "arm64", 1, "0.5"}, "0.5.1", "arm64") != nil {
		t.Fatal("info rejected")
	}
	if verifyCoreInfo(CoreInfo{"0.5.1", "arm64", 2, "0.5"}, "0.5.1", "arm64") == nil {
		t.Fatal("bad ABI accepted")
	}
}
func TestCoreTransactionFailures(t *testing.T) {
	tests := []struct {
		name, fail, want string
		sequence         []string
	}{
		{"success", "", "success", []string{"stop", "activate", "resume"}},
		{"stop failure", "stop", "recovery_required", []string{"stop"}},
		{"rename failure", "activate", "rolled_back", []string{"stop", "activate", "stop", "restore", "resume"}},
		{"new service fails", "resume", "rolled_back", []string{"stop", "activate", "resume", "stop", "restore", "resume"}},
		{"rollback copy fails", "restore", "recovery_required", []string{"stop", "activate", "resume", "stop", "restore"}},
		{"old service fails", "old-resume", "recovery_required", []string{"stop", "activate", "resume", "stop", "restore", "resume"}},
		{"cleanup fails", "cleanup", "recovery_required", []string{"stop", "activate", "resume", "stop"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var seq []string
			counts := map[string]int{}
			call := func(s string) error {
				seq = append(seq, s)
				counts[s]++
				fail := tc.fail == s && (s != "resume" || counts[s] == 1)
				if s == "resume" && (tc.fail == "restore" || tc.fail == "old-resume" || tc.fail == "cleanup") {
					fail = true
				}
				if s == "stop" && counts[s] == 2 && tc.fail == "cleanup" {
					fail = true
				}
				if fail {
					return errors.New("injected")
				}
				return nil
			}
			phase, e := coreTransaction(CoreJob{Client: true, Server: true}, coreOps{Stop: func(CoreJob) error { return call("stop") }, Resume: func(CoreJob) error { return call("resume") }, Activate: func() error { return call("activate") }, Restore: func() error { return call("restore") }, Phase: func(string, string) error { return nil }})
			if phase != tc.want || !reflect.DeepEqual(seq, tc.sequence) || (e == nil) != (phase == "success") {
				t.Fatalf("%s %v %v", phase, e, seq)
			}
		})
	}
}
func TestCoreBusyBlocksMutations(t *testing.T) {
	oldRoot, oldRuntime := updateRoot, runtimeDir
	updateRoot = t.TempDir()
	runtimeDir = t.TempDir()
	defer func() { updateRoot = oldRoot; runtimeDir = oldRuntime }()
	if e := os.WriteFile(updateFile("update-busy"), []byte("token"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"up", "down", "server-add", "server-down", "watch", "core-upgrade", "core-check"} {
		if _, e := execute(action); e == nil {
			t.Fatal(action)
		}
	}
	if exists(filepath.Join(runtimeDir, "lock")) {
		t.Fatal("lock leaked")
	}
}
