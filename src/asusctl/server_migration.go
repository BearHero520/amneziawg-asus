// SPDX-License-Identifier: MIT
package asusctl

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

var legacyServerSettings = Root + "/config/advanced/settings"

func oldDeviceRecords(input string) []string {
	fields := make(map[string]string)
	for _, line := range strings.Split(input, "\n") {
		key, value, _ := strings.Cut(strings.TrimSuffix(line, "\r"), " ")
		if strings.HasPrefix(key, "awgs_peers") {
			fields[key] = value
		}
	}
	raw := fields["awgs_peers"]
	if raw == "" {
		return nil
	}
	for i := 1; i <= 10; i++ {
		part := fields["awgs_peers"+strconv.Itoa(i)]
		if part == "" {
			break
		}
		raw += part
	}
	return strings.Split(strings.Trim(raw, ";"), ";")
}

func migratedDevice(record string, s ServerSettings) (ServerClient, error) {
	f := strings.Split(record, "|")
	if len(f) < 8 || len(f) > 10 || f[4] != "0" && f[4] != "1" {
		return ServerClient{}, errors.New("旧设备记录不完整")
	}
	p := ServerClient{Name: strings.TrimSpace(f[0]), Public: f[5], Private: f[6], PSK: f[7], Disabled: f[4] == "0"}
	if p.Name == "" || len([]rune(p.Name)) > 40 || strings.ContainsAny(p.Name, "\r\n\x00") {
		return ServerClient{}, errors.New("旧设备名称超出长度或格式限制")
	}
	private, err := base64.StdEncoding.Strict().DecodeString(p.Private)
	if err != nil {
		return ServerClient{}, errors.New("旧设备密钥格式无效")
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil || base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) != p.Public {
		return ServerClient{}, errors.New("旧设备密钥不匹配")
	}
	if p.PSK == "" {
		p.PSK = base64.StdEncoding.EncodeToString(make([]byte, 32))
	}
	if _, err = keyHex(p.PSK); err != nil {
		return ServerClient{}, errors.New("旧设备预共享密钥格式无效")
	}
	if f[3] == "lan" && s.AllowLAN {
		p.Route.Scope = "lan"
	}
	if len(f) == 10 && (f[9] == "proxy" || f[9] == "wan") {
		p.Route.Exit = f[9]
	}
	return p, nil
}

func importLegacyDevices() (int, error) {
	if exists(serverStatePath) || exists(serverSocket) || exists(peerJournal()) {
		return 0, errors.New("请停止服务端后导入旧设备")
	}
	c, err := readServer()
	if err != nil {
		return 0, errors.New("请先在当前服务端保存设置")
	}
	f, err := os.Open(legacyServerSettings)
	if err != nil {
		return 0, errors.New("没有找到 0.5.3 设备归档")
	}
	defer f.Close()
	const limit = 128 * 1024
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(b) > limit {
		return 0, errors.New("未能读取旧配置归档")
	}
	original := len(c.Clients)
	known := make(map[string]bool, original)
	for _, p := range c.Clients {
		known[p.Public] = true
	}
	for i, entry := range oldDeviceRecords(string(b)) {
		p, err := migratedDevice(entry, c.Settings)
		if err != nil {
			return 0, fmt.Errorf("第 %d 条旧设备无法导入：%w", i+1, err)
		}
		if known[p.Public] {
			continue
		}
		if err = allocateServerDevice(c, &p); err != nil {
			return 0, err
		}
		known[p.Public] = true
		c.Clients = append(c.Clients, p)
	}
	if n := len(c.Clients) - original; n > 0 {
		if err = serverValidateCore(c); err != nil {
			return 0, errors.New("导入后的设备配置未通过校验")
		}
		return n, persistPeerConfig(c)
	}
	return 0, nil
}
