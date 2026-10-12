// SPDX-License-Identifier: MIT
package asusctl

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestSoftcenterResponse(t *testing.T) {
	for _, message := range []string{"状态已刷新", "节点 \"备用\"\\路径\n错误\t说明", "<script>alert(1)</script> 🌐"} {
		result := Result{OK: true, Message: message}
		var output bytes.Buffer
		if err := writeResponse(&output, result, true); err != nil {
			t.Fatal(err)
		}
		// Match the firmware's observed non-escaping wrapper byte for byte.
		raw := `{"result": "` + strings.TrimSpace(output.String()) + `"}`
		var envelope struct {
			Result string `json:"result"`
		}
		if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(envelope.Result, "AWG64:") {
			t.Fatal(envelope)
		}
		data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(envelope.Result, "AWG64:"))
		if err != nil {
			t.Fatal(err)
		}
		var decoded Result
		if err = json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Message != message || !decoded.OK {
			t.Fatalf("round trip mismatch: %#v", decoded)
		}
		output.Reset()
		if err = writeResponse(&output, result, false); err != nil {
			t.Fatal(err)
		}
		if !json.Valid(output.Bytes()) {
			t.Fatal("ctl output must remain JSON")
		}
	}
}
