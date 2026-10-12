// SPDX-License-Identifier: MIT
package asusctl

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

var serverConfigPath = Root + "/config/server.json"
var serverStatePath = runtimeDir + "/server-state.json"
var serverSocket = "/var/run/amneziawg/awgs0.sock"

const serverInterface = "awgs0"

type ServerSettings struct {
	Port         int    `json:"port"`
	Address      string `json:"address"`
	Address6     string `json:"address6"`
	EndpointMode string `json:"endpoint_mode"`
	Endpoint     string `json:"endpoint"`
	Auto         bool   `json:"auto"`
	AllowLAN     bool   `json:"allow_lan"`
	Internet     bool   `json:"internet"`
	Fullv        bool   `json:"fullv"`
	DNS          string `json:"dns"`
	Extra        string `json:"extra"`
}
type ServerClient struct {
	Disabled bool   `json:"disabled"`
	ID       string `json:"id"`
	Name     string `json:"name"`
	Private  string `json:"private"`
	Public   string `json:"public"`
	PSK      string `json:"psk"`
	Address  string `json:"address"`
	Address6 string `json:"address6"`
}
type ServerConfig struct {
	Settings ServerSettings `json:"settings"`
	Private  string         `json:"private"`
	Public   string         `json:"public"`
	Clients  []ServerClient `json:"clients"`
}
type ServerClientView struct {
	Disabled  bool   `json:"disabled"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	Public    string `json:"public"`
	Address   string `json:"address"`
	Address6  string `json:"address6"`
	Handshake int64  `json:"handshake"`
	RX        uint64 `json:"rx"`
	TX        uint64 `json:"tx"`
}
type ServerStatus struct {
	Configured bool               `json:"configured"`
	Running    bool               `json:"running"`
	Pending    bool               `json:"pending"`
	Settings   ServerSettings     `json:"settings"`
	Public     string             `json:"public"`
	Clients    []ServerClientView `json:"clients"`
	DDNS       string             `json:"ddns"`
	Endpoint   string             `json:"endpoint"`
	WAN        string             `json:"wan"`
	LAN        string             `json:"lan"`
	Warning    string             `json:"warning"`
}

func serverDefaults() ServerSettings {
	return ServerSettings{Port: 51830, Address: "10.77.0.1/24", EndpointMode: "auto", AllowLAN: true}
}
func readServer() (ServerConfig, error) {
	c := ServerConfig{Settings: serverDefaults(), Clients: []ServerClient{}}
	b, e := os.ReadFile(serverConfigPath)
	if e != nil {
		return c, e
	}
	e = json.Unmarshal(b, &c)
	return c, e
}
func newServerKey() (string, string, error) {
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return "", "", e
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}
func randomKey() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return base64.StdEncoding.EncodeToString(b), e
}
func newServerExtra() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	// Non-overlapping header IDs, with conservative AWG 1.x-compatible defaults.
	s := "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 16\nS2 = 20\nS3 = 0\nS4 = 0\n"
	for i := 0; i < 4; i++ {
		s += fmt.Sprintf("H%d = %d\n", i+1, uint64(binary.LittleEndian.Uint32(b[i*4:]))%800000000+uint64(i)*900000000+100000)
	}
	return s, nil
}
func validServerHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "\r\n\t /#[]") {
		return false
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		return ip.IsGlobalUnicast() && !ip.IsLoopback()
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func serverAddress(value string, v6 bool) (netip.Prefix, error) {
	p, e := netip.ParsePrefix(value)
	if e != nil || p.Addr().Is6() != v6 || !p.Addr().IsPrivate() {
		return p, errors.New("隧道地址必须是私有地址 CIDR")
	}
	if v6 {
		if p.Bits() != 64 {
			return p, errors.New("IPv6 隧道使用 ULA /64 地址")
		}
	} else if p.Bits() < 16 || p.Bits() > 27 {
		return p, errors.New("IPv4 隧道网段须为 /16 至 /27")
	}
	// Reserve host .1 / ::1 for the server; clients allocate from the second host.
	if p.Masked().Addr().Next() != p.Addr() {
		return p, errors.New("服务端隧道地址必须使用网段中的第一个主机地址，例如 10.77.0.1/24")
	}
	return p, nil
}
func validateServerSettings(s ServerSettings) error {
	if s.Port < 1 || s.Port > 65535 {
		return errors.New("监听端口须为 1–65535")
	}
	if s.EndpointMode != "auto" && s.EndpointMode != "manual" {
		return errors.New("Endpoint 模式无效")
	}
	if s.EndpointMode == "manual" && !validServerHost(s.Endpoint) {
		return errors.New("外网地址填写域名或 IP，不要填写协议、端口或路径")
	}
	if !s.AllowLAN && !s.Internet {
		return errors.New("请至少允许访问局域网或通过家里上网")
	}
	if _, e := serverAddress(s.Address, false); e != nil {
		return e
	}
	if s.Address6 != "" {
		if _, e := serverAddress(s.Address6, true); e != nil {
			return e
		}
	}
	if len(s.Extra) > 4096 {
		return errors.New("混淆参数过长")
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(s.Extra, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			return errors.New("混淆参数每行格式为 字段 = 值")
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		allowed := extraKeys[k] != "" || k == "jc" || k == "jmin" || k == "jmax" || len(k) == 2 && (k[0] == 's' && k[1] >= '1' && k[1] <= '4' || k[0] == 'h' && k[1] >= '1' && k[1] <= '4' || k[0] == 'i' && k[1] >= '1' && k[1] <= '5')
		if !allowed || seen[k] || strings.ContainsAny(kv[1], "\x00\r#") {
			return errors.New("混淆参数包含未知、重复或不安全字段")
		}
		seen[k] = true
	}
	for _, value := range strings.Split(s.DNS, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		ip, e := netip.ParseAddr(value)
		if e != nil || !ip.IsGlobalUnicast() {
			return errors.New("DNS 必须是有效单播 IP")
		}
		if ip.Is6() && s.Address6 == "" {
			return errors.New("IPv6 DNS 需要启用 IPv6 隧道")
		}
	}
	return nil
}
func serverConf(c ServerConfig) string {
	s := c.Settings
	out := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s", c.Private, s.Address)
	if s.Address6 != "" {
		out += ", " + s.Address6
	}
	out += fmt.Sprintf("\nListenPort = %d\n%s\n", s.Port, s.Extra)
	for _, p := range c.Clients {
		if p.Disabled {
			continue
		}
		out += fmt.Sprintf("[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s", p.Public, p.PSK, p.Address)
		if p.Address6 != "" {
			out += ", " + p.Address6
		}
		out += "\n"
	}
	return out
}
func serverClientIP(s ServerSettings, slot int) (string, string) {
	p, _ := netip.ParsePrefix(s.Address)
	ip := p.Addr()
	for i := 0; i <= slot; i++ {
		ip = ip.Next()
	}
	v4 := ip.String() + "/32"
	v6 := ""
	if s.Address6 != "" {
		p6, _ := netip.ParsePrefix(s.Address6)
		ip6 := p6.Addr()
		for i := 0; i <= slot; i++ {
			ip6 = ip6.Next()
		}
		v6 = ip6.String() + "/128"
	}
	return v4, v6
}
func serverValidateCore(c ServerConfig) error {
	// Validate even before a real device has been added; this peer is never persisted.
	if enabledClients(c) == 0 {
		a, a6 := serverClientIP(c.Settings, 0)
		c.Clients = []ServerClient{{Public: c.Public, PSK: c.Private, Address: a, Address6: a6}}
	}
	_, e := Parse(serverConf(c))
	return e
}
func serverSave(s ServerSettings) error {
	if exists(serverStatePath) {
		return errors.New("请先停止 AmneziaWG 服务端再修改设置")
	}
	c, e := readServer()
	if e != nil && !os.IsNotExist(e) {
		return errors.New("服务端配置损坏，未覆盖")
	}
	if c.Private == "" {
		c.Private, c.Public, e = newServerKey()
		if e != nil {
			return e
		}
	}
	if strings.TrimSpace(s.Extra) == "" {
		s.Extra, e = newServerExtra()
		if e != nil {
			return e
		}
	}
	if e = validateServerSettings(s); e != nil {
		return e
	}
	if len(c.Clients) > 0 && (s.Address != c.Settings.Address || s.Address6 != c.Settings.Address6) {
		return errors.New("已有客户端时不能修改隧道网段；请先删除客户端，再重新生成配置")
	}
	c.Settings = s
	if e = serverValidateCore(c); e != nil {
		return e
	}
	return writeJSON(serverConfigPath, c)
}
func serverAdd(name string) error {
	c, e := readServer()
	if e != nil {
		return errors.New("请先保存服务端设置")
	}
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 40 || strings.ContainsAny(name, "\r\n\x00") {
		return errors.New("设备名称须为 1–40 个字符")
	}
	if len(c.Clients) >= 10 {
		return errors.New("最多添加 10 个客户端")
	}
	var p ServerClient
	p.Name = name
	p.Private, p.Public, e = newServerKey()
	if e != nil {
		return e
	}
	p.PSK, e = randomKey()
	if e != nil {
		return e
	}
	var id [8]byte
	if _, e = rand.Read(id[:]); e != nil {
		return e
	}
	p.ID = fmt.Sprintf("%x", id)
	used := map[string]bool{}
	for _, q := range c.Clients {
		used[q.Address] = true
	}
	for slot := 0; slot < 10; slot++ {
		p.Address, p.Address6 = serverClientIP(c.Settings, slot)
		if !used[p.Address] {
			break
		}
	}
	old := c
	c.Clients = append(append([]ServerClient{}, c.Clients...), p)
	return commitPeerChange(old, c, nil, &p)
}
func serverDelete(id string) error {
	c, e := readServer()
	if e != nil {
		return e
	}
	for i, p := range c.Clients {
		if p.ID == id {
			old := c
			c.Clients = append(append([]ServerClient{}, c.Clients[:i]...), c.Clients[i+1:]...)
			return commitPeerChange(old, c, &p, nil)
		}
	}
	return errors.New("未找到客户端")
}
func nvramValue(key string) string {
	v, e := runCommand("nvram", "get", key)
	if e != nil {
		return ""
	}
	return strings.TrimSpace(v)
}
func serverEndpoint(s ServerSettings) (host, ddns, wan, warning string) {
	ddns = nvramValue("ddns_hostname_x")
	unit := "0"
	if nvramValue("wan1_primary") == "1" {
		unit = "1"
	}
	wan = nvramValue("wan" + unit + "_ipaddr")
	if s.EndpointMode == "manual" {
		host = s.Endpoint
	} else if nvramValue("ddns_enable_x") == "1" && validServerHost(ddns) {
		host = ddns
	} else if validServerHost(wan) {
		host = wan
	}
	if host == "" {
		warning = "没有可用 DDNS 或 WAN 地址，请手动填写外网地址"
	}
	if a, e := netip.ParseAddr(wan); e == nil && (a.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(a)) {
		warning = "WAN 为私网/运营商 NAT：DDNS 不会自动打通入站连接，需要上级端口转发或可达的公网地址"
	}
	return
}
func serverStatus() ServerStatus {
	c, e := readServer()
	v := ServerStatus{Configured: e == nil, Settings: c.Settings, Public: c.Public, Clients: []ServerClientView{}}
	v.Endpoint, v.DDNS, v.WAN, v.Warning = serverEndpoint(c.Settings)
	if e != nil && !os.IsNotExist(e) {
		v.Warning = "服务端配置文件读取失败"
	}
	if lan, e := defaultLAN(); e == nil {
		v.LAN = lan.String()
	}
	stats := map[string]ServerClientView{}
	if exists(serverStatePath) {
		out, e := rpc(serverSocket, "get=1")
		v.Running = e == nil
		v.Pending = e != nil || exists(peerJournal())
		key := ""
		for _, line := range strings.Split(out, "\n") {
			kv := strings.SplitN(line, "=", 2)
			if len(kv) != 2 {
				continue
			}
			if kv[0] == "public_key" {
				key = kv[1]
			}
			if key == "" {
				continue
			}
			p := stats[key]
			switch kv[0] {
			case "last_handshake_time_sec":
				p.Handshake, _ = strconv.ParseInt(kv[1], 10, 64)
			case "rx_bytes":
				p.RX, _ = strconv.ParseUint(kv[1], 10, 64)
			case "tx_bytes":
				p.TX, _ = strconv.ParseUint(kv[1], 10, 64)
			}
			stats[key] = p
		}
	}
	for _, p := range c.Clients {
		hex, _ := keyHex(p.Public)
		pv := stats[hex]
		pv.Disabled = p.Disabled
		pv.ID = p.ID
		pv.Name = p.Name
		pv.Public = p.Public
		pv.Address = p.Address
		pv.Address6 = p.Address6
		v.Clients = append(v.Clients, pv)
	}
	return v
}
func exportServerClient(c ServerConfig, p ServerClient, host string, lan netip.Prefix, lan6 []string) (string, error) {
	s := c.Settings
	if !validServerHost(host) {
		return "", errors.New("没有可用外网地址，请配置路由器 DDNS 或手动填写")
	}
	a, _ := netip.ParsePrefix(s.Address)
	allowed := []string{a.Addr().String() + "/32"}
	if s.AllowLAN {
		allowed = append(allowed, lan.String())
	}
	if s.Internet {
		allowed = []string{"0.0.0.0/0"}
	}
	addr := p.Address
	if s.Address6 != "" {
		a6, _ := netip.ParsePrefix(s.Address6)
		addr += ", " + p.Address6
		if s.Internet {
			allowed = append(allowed, "::/0")
		} else {
			allowed = append(allowed, a6.Addr().String()+"/128")
			if s.AllowLAN {
				allowed = append(allowed, lan6...)
			}
		}
	}
	dns := strings.TrimSpace(s.DNS)
	if dns == "" && s.Internet {
		dns = "1.1.1.1"
		if s.AllowLAN {
			ip, err := netip.ParseAddr(nvramValue("lan_ipaddr"))
			if err != nil || !ip.Is4() || !lan.Contains(ip) {
				return "", errors.New("无法识别路由器 DNS，请手动填写客户端 DNS")
			}
			dns = ip.String()
		}
	}
	out := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\n", p.Private, addr)
	if dns != "" {
		out += "DNS = " + dns + "\n"
	}
	out += s.Extra + "\n" + fmt.Sprintf("[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n", c.Public, p.PSK, net.JoinHostPort(host, strconv.Itoa(s.Port)), strings.Join(allowed, ", "))
	if _, e := Parse(out); e != nil {
		return "", e
	}
	return out, nil
}
func serverExport(id string) (string, error) {
	c, e := readServer()
	if e != nil {
		return "", e
	}
	host, _, _, _ := serverEndpoint(c.Settings)
	lan, e := defaultLAN()
	if e != nil {
		return "", e
	}
	l6 := serverLAN6(nvramValue("lan_ifname"))
	for _, p := range c.Clients {
		if p.ID == id {
			return exportServerClient(c, p, host, lan, l6)
		}
	}
	return "", errors.New("未找到客户端")
}
func readServerPayload(v any) error {
	d := json.NewDecoder(io.LimitReader(requestInput(), 12288))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return requestParseError(e)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("请求包含多余数据")
	}
	return nil
}
