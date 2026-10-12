package asusctl

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestEncodedRequestExecutesServerSaveAndCheck(t *testing.T) {
	serverFixture(t)
	oldBody := webRequestBody
	t.Cleanup(func() { webRequestBody = oldBody })
	settings := serverDefaults()
	settings.Internet = true
	settings.Auto = true
	raw, _ := json.Marshal(settings)
	stored := "AWGREQ64:" + base64.StdEncoding.EncodeToString(raw)
	oldRun := runCommand
	runCommand = func(name string, args ...string) (string, error) {
		if name == "dbus" {
			if args[0] == "get" {
				return stored, nil
			}
			return "", nil
		}
		return oldRun(name, args...)
	}
	if e := loadWebRequest(); e != nil {
		t.Fatal(e)
	}
	result, e := executeServer("server-save")
	if e != nil {
		t.Fatal(e)
	}
	if !result.OK || !result.Server.Configured || !result.Server.Settings.Auto || !result.Server.Settings.Internet {
		t.Fatal("encoded request was not saved")
	}
	raw, _ = json.Marshal(map[string]string{"probe": "中文\"引号\"\\换行\n"})
	stored = "AWGREQ64:" + base64.StdEncoding.EncodeToString(raw)
	if e = loadWebRequest(); e != nil {
		t.Fatal(e)
	}
	if result, e = checkRequest(); e != nil || !result.OK {
		t.Fatal("check failed", e)
	}
	for _, bad := range []string{"AWGREQ64:***", "AWGREQ64:" + base64.StdEncoding.EncodeToString([]byte(`{broken`)), `{\"id\":\"000\"}`} {
		stored = bad
		if loadWebRequest() == nil {
			t.Fatal("bad transport accepted")
		}
	}
}

func TestServerRequestErrorsDistinguishTypes(t *testing.T) {
	old := webRequestBody
	t.Cleanup(func() { webRequestBody = old })
	for _, tc := range []struct{ body, code string }{{"", "REQ_EMPTY"}, {`{"port":"51830"}`, "REQ_TYPE"}, {`{"unsupported":true}`, "REQ_FIELD"}, {`{"port":`, "REQ_DECODE"}} {
		webRequestBody = []byte(tc.body)
		var s ServerSettings
		e := readServerPayload(&s)
		if e == nil || !strings.Contains(e.Error(), tc.code) {
			t.Fatalf("got %v, want %s", e, tc.code)
		}
	}
}

func TestWebRequestReadsDBusWithoutShellStdin(t *testing.T) {
	oldRun, oldBody := runCommand, webRequestBody
	t.Cleanup(func() { runCommand, webRequestBody = oldRun, oldBody })
	var removed bool
	raw := `{"port":51830,"address":"10.77.0.1/24","address6":"","endpoint_mode":"auto","endpoint":"","auto":true,"allow_lan":true,"internet":true,"dns":"","extra":"Jc = 4\nJmin = 40\nJmax = 70"}`
	runCommand = func(name string, args ...string) (string, error) {
		if name != "dbus" || len(args) != 2 || args[1] != "amneziawg_payload" {
			t.Fatal("unexpected command")
		}
		if args[0] == "get" {
			return raw, nil
		}
		removed = true
		return "", nil
	}
	if e := loadWebRequest(); e != nil {
		t.Fatal(e)
	}
	if !removed {
		t.Fatal("private request not removed")
	}
	var s ServerSettings
	if e := readServerPayload(&s); e != nil {
		t.Fatal(e)
	}
	if s.Port != 51830 || !s.Internet || !s.Auto || !strings.Contains(s.Extra, "\n") {
		t.Fatal("settings changed in transit")
	}
	raw = `{"name":"手机 \"一号\"","config":"test"}`
	if e := loadWebRequest(); e != nil {
		t.Fatal(e)
	}
	var fields map[string]string
	if e := json.NewDecoder(requestInput()).Decode(&fields); e != nil {
		t.Fatal(e)
	}
	if fields["name"] != "手机 \"一号\"" {
		t.Fatal("Unicode/quotes corrupted")
	}
}

func TestWebRequestFailuresAreSafe(t *testing.T) {
	oldRun, oldBody := runCommand, webRequestBody
	t.Cleanup(func() { runCommand, webRequestBody = oldRun, oldBody })
	for _, scenario := range []string{"empty", "read", "remove", "large"} {
		t.Run(scenario, func(t *testing.T) {
			removed := false
			runCommand = func(name string, args ...string) (string, error) {
				if args[0] == "remove" {
					removed = true
					if scenario == "remove" {
						return "private diagnostic", errors.New("secret")
					}
					return "", nil
				}
				switch scenario {
				case "empty":
					return "", nil
				case "read":
					return "private diagnostic", errors.New("secret")
				case "large":
					return strings.Repeat("x", 70001), nil
				}
				return "{}", nil
			}
			e := loadWebRequest()
			if e == nil || strings.Contains(e.Error(), "secret") || !removed {
				t.Fatal("unsafe error path")
			}
		})
	}
	webRequestBody = []byte("{}")
	if _, e := io.ReadAll(requestInput()); e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"status", "up", "down", "server-status", "server-up", "server-down"} {
		if needsRequestBody(action) {
			t.Fatal("status/lifecycle should not consume payload")
		}
	}
}
