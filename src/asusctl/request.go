package asusctl

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

var webRequestBody []byte

func requestInput() io.Reader {
	if webRequestBody != nil {
		return bytes.NewReader(webRequestBody)
	}
	return os.Stdin
}

func needsRequestBody(action string) bool {
	switch action {
	case "core-upgrade", "core-rollback", "import", "settings", "switch", "delete", "server-save", "server-add", "server-delete", "server-enable", "server-disable", "server-export", "request-check":
		return true
	}
	return false
}

// Keep the dbus transport ASCII-only. The firmware rejects JSON with quoted
// fields on the CLI path although its HTTP read API reports intact JSON.
func loadWebRequest() error {
	payload, readErr := runCommand("dbus", "get", "amneziawg_payload")
	_, removeErr := runCommand("dbus", "remove", "amneziawg_payload")
	if removeErr != nil {
		return errors.New("无法清除暂存请求参数，请检查 dbus")
	}
	if readErr != nil {
		return errors.New("无法读取软件中心请求参数")
	}
	if payload == "" {
		return errors.New("未收到请求参数，请刷新插件页面后重试")
	}
	if len(payload) > 70000 {
		return errors.New("请求参数超过大小限制")
	}
	body := []byte(payload)
	if strings.HasPrefix(payload, "AWGREQ64:") {
		var e error
		body, e = base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(payload, "AWGREQ64:"))
		if e != nil {
			return errors.New("请求编码损坏，请刷新页面后重试（REQ_BASE64）")
		}
	} else if !json.Valid(body) {
		return errors.New("旧版请求在传递中损坏，请 Ctrl+F5 刷新页面（REQ_LEGACY_JSON）")
	}
	if len(body) > 50000 {
		return errors.New("请求参数超过大小限制")
	}
	if !json.Valid(body) {
		return errors.New("解码后不是有效 JSON（REQ_JSON）")
	}
	webRequestBody = body
	return nil
}

func requestParseError(e error) error {
	if errors.Is(e, io.EOF) {
		return errors.New("服务端未收到参数（REQ_EMPTY）")
	}
	var syntax *json.SyntaxError
	if errors.As(e, &syntax) {
		return fmt.Errorf("服务端 JSON 格式错误，位置 %d（REQ_SYNTAX）", syntax.Offset)
	}
	var mismatch *json.UnmarshalTypeError
	if errors.As(e, &mismatch) {
		return errors.New("服务端参数类型不匹配（REQ_TYPE）")
	}
	if strings.HasPrefix(e.Error(), "json: unknown field ") {
		return errors.New("服务端收到不支持的字段，请刷新页面（REQ_FIELD）")
	}
	return errors.New("服务端参数解析失败（REQ_DECODE）")
}

func checkRequest() (Result, error) {
	var p struct {
		Probe string `json:"probe"`
	}
	if e := readServerPayload(&p); e != nil {
		return Result{}, e
	}
	if p.Probe != "中文\"引号\"\\换行\n" {
		return Result{}, errors.New("请求自检内容不一致（REQ_CHECK）")
	}
	return Result{OK: true, Message: "请求参数自检通过"}, nil
}
