// SPDX-License-Identifier: MIT
package asusctl

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const Root = "/koolshare/amneziawg"

var runtimeDir = "/tmp/amneziawg-asus"
var socket = "/var/run/amneziawg/awg0.sock"
var configPath = Root + "/config/client.conf"
var settingsPath = Root + "/config/settings.json"
var statePath = runtimeDir + "/state.json"

type Settings struct {
	Mode          string   `json:"mode"`
	Source        string   `json:"source"`
	Auto          bool     `json:"auto"`
	IPv6          bool     `json:"ipv6"`
	Source6       string   `json:"source6"`
	DNS           bool     `json:"dns"`
	KillSwitch    bool     `json:"kill_switch"`
	Profile       string   `json:"profile"`
	Failover      bool     `json:"failover"`
	Fallbacks     []string `json:"fallbacks"`
	HealthTargets []string `json:"health_targets"`
}
type Command struct {
	Name string
	Args []string
}
type State struct {
	Undo    []Command
	Started int64
}
type PeerStatus struct {
	Endpoint  string `json:"endpoint"`
	Handshake int64  `json:"handshake"`
	RX        uint64 `json:"rx"`
	TX        uint64 `json:"tx"`
}
type Status struct {
	Running      bool         `json:"running"`
	Configured   bool         `json:"configured"`
	Settings     Settings     `json:"settings"`
	Peers        []PeerStatus `json:"peers"`
	DNS          []string     `json:"dns"`
	Version      string       `json:"version"`
	Protected    bool         `json:"protected"`
	GuardPending bool         `json:"guard_pending"`
	Profiles     []Profile    `json:"profiles"`
	Health       Health       `json:"health"`
}
type Result struct {
	Logs        []LogEntry    `json:"logs,omitempty"`
	Diagnostics []Diagnostic  `json:"diagnostics,omitempty"`
	OK          bool          `json:"ok"`
	Message     string        `json:"message"`
	Status      *Status       `json:"status,omitempty"`
	Server      *ServerStatus `json:"server,omitempty"`
	Export      string        `json:"export,omitempty"`
	Filename    string        `json:"filename,omitempty"`
}

var runCommand = func(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return string(out), fmt.Errorf("%s 执行失败: %s", name, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func atomicWrite(path string, b []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".awg-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
func writeJSON(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return atomicWrite(path, b)
}
func readConfig() (*Config, error) {
	if id := readSettings().Profile; id != "" {
		return configFor(id)
	}
	b, e := os.ReadFile(configPath)
	if e != nil {
		return nil, errors.New("请先导入 AmneziaWG .conf 配置")
	}
	return Parse(string(b))
}
func readSettings() Settings {
	s := Settings{Mode: "tunnel"}
	b, e := os.ReadFile(settingsPath)
	if e == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}
func exists(path string) bool { _, e := os.Stat(path); return e == nil }
func validateSettings(s Settings) error {
	if s.Mode != "tunnel" && s.Mode != "lan" {
		return errors.New("不支持的路由模式")
	}
	if s.Source != "" {
		p, e := netip.ParsePrefix(s.Source)
		if e != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() || p.Bits() < 8 {
			return errors.New("来源网段必须是私有 IPv4 CIDR")
		}
	}
	if s.Source6 != "" {
		p, e := netip.ParsePrefix(s.Source6)
		if e != nil || !p.Addr().Is6() || !p.Addr().IsGlobalUnicast() || p.Bits() < 16 {
			return errors.New("IPv6 来源必须是有效单播 CIDR")
		}
	}
	if s.KillSwitch && !s.DNS {
		return errors.New("断线保护需要同时开启 DNS 接管，避免回退到路由器 DNS")
	}
	if s.Mode != "lan" && (s.DNS || s.KillSwitch || s.IPv6) {
		return errors.New("DNS 接管、断线保护和 IPv6 分流需要选择 LAN 模式")
	}
	if len(s.Fallbacks) > 7 || len(s.HealthTargets) > 3 {
		return errors.New("最多 7 个备用配置、3 个探测地址")
	}
	if s.Profile != "" {
		if _, e := profilePath(s.Profile); e != nil {
			return e
		}
	}
	for _, id := range s.Fallbacks {
		if _, e := profilePath(id); e != nil {
			return e
		}
	}
	for _, target := range healthTargets(s) {
		ip, e := netip.ParseAddr(target)
		if e != nil || !ip.IsGlobalUnicast() {
			return errors.New("探测目标必须是单播 IP 地址")
		}
	}
	if s.Failover && !s.KillSwitch {
		return errors.New("自动故障切换需要开启断线保护")
	}
	if s.Failover && len(s.Fallbacks) == 0 {
		return errors.New("自动切换需要至少一个备用配置")
	}
	if s.Failover {
		different := false
		for _, id := range s.Fallbacks {
			if id != s.Profile {
				different = true
			}
		}
		if !different {
			return errors.New("备用配置必须包含当前节点之外的节点")
		}
	}
	return nil
}
func rpc(path, request string) (string, error) {
	c, e := net.DialTimeout("unix", path, 3*time.Second)
	if e != nil {
		return "", e
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, e = io.WriteString(c, request+"\n\n"); e != nil {
		return "", e
	}
	r := bufio.NewReader(io.LimitReader(c, 1<<20))
	var b strings.Builder
	code := ""
	for {
		line, e := r.ReadString('\n')
		if e != nil {
			return "", e
		}
		if line == "\n" {
			break
		}
		if strings.HasPrefix(line, "errno=") {
			code = strings.TrimSpace(strings.TrimPrefix(line, "errno="))
		} else {
			b.WriteString(line)
		}
	}
	if code != "0" {
		return "", fmt.Errorf("AmneziaWG 拒绝配置或查询 (errno=%s)", code)
	}
	return b.String(), nil
}
func resolveEndpoint(ep string) (string, error) {
	host, port, e := net.SplitHostPort(ep)
	if e != nil {
		return "", e
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		return net.JoinHostPort(ip.String(), port), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if e != nil || len(ips) == 0 {
		return "", errors.New("DNS lookup failed")
	}
	for _, ip := range ips {
		if ip.Is4() {
			return net.JoinHostPort(ip.String(), port), nil
		}
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}
func readStatus() Status {
	s := Status{Settings: readSettings(), Version: "0.4.0", Peers: []PeerStatus{}, DNS: []string{}}
	s.Protected = guardActive()
	s.GuardPending = exists(guardPath) && !s.Protected
	s.Profiles = profiles()
	s.Health = health()
	if c, e := readConfig(); e == nil {
		s.Configured = true
		for _, ip := range c.DNS {
			s.DNS = append(s.DNS, ip.String())
		}
	}
	if !exists(statePath) {
		return s
	}
	out, e := rpc(socket, "get=1")
	if e != nil {
		return s
	}
	s.Running = true
	var p *PeerStatus
	for _, line := range strings.Split(out, "\n") {
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := kv[0], kv[1]
		if k == "public_key" {
			s.Peers = append(s.Peers, PeerStatus{})
			p = &s.Peers[len(s.Peers)-1]
		}
		if p == nil {
			continue
		}
		switch k {
		case "endpoint":
			p.Endpoint = v
		case "last_handshake_time_sec":
			p.Handshake, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			p.RX, _ = strconv.ParseUint(v, 10, 64)
		case "tx_bytes":
			p.TX, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	return s
}
func defaultLAN() (netip.Prefix, error) {
	ip, e := runCommand("nvram", "get", "lan_ipaddr")
	if e != nil {
		return netip.Prefix{}, e
	}
	mask, e := runCommand("nvram", "get", "lan_netmask")
	if e != nil {
		return netip.Prefix{}, e
	}
	a, e := netip.ParseAddr(strings.TrimSpace(ip))
	m := net.ParseIP(strings.TrimSpace(mask)).To4()
	if e != nil || !a.Is4() || m == nil {
		return netip.Prefix{}, errors.New("无法读取 LAN 地址")
	}
	ones, bits := net.IPMask(m).Size()
	if bits != 32 {
		return netip.Prefix{}, errors.New("无效 LAN 子网掩码")
	}
	return netip.PrefixFrom(a, ones).Masked(), nil
}
func lanSource(s Settings) (string, error) {
	lan, e := defaultLAN()
	if e != nil {
		return "", e
	}
	if s.Source == "" {
		return lan.String(), nil
	}
	p, e := netip.ParsePrefix(s.Source)
	if e != nil || p.Bits() < lan.Bits() || !lan.Contains(p.Addr()) {
		return "", errors.New("来源网段必须位于路由器主 LAN 网段内")
	}
	return p.Masked().String(), nil
}
func transact(state *State, do, undo Command) error {
	// Journal before mutation; reserved table/rule priorities are checked for collisions first.
	state.Undo = append(state.Undo, undo)
	if e := writeJSON(statePath, state); e != nil {
		return e
	}
	_, e := runCommand(do.Name, do.Args...)
	return e
}
func cmd(name string, args ...string) Command { return Command{name, args} }
func down() error {
	b, e := os.ReadFile(statePath)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var state State
	if e = json.Unmarshal(b, &state); e != nil {
		return e
	}
	failed := []Command{}
	var problems []string
	for i := len(state.Undo) - 1; i >= 0; i-- {
		c := state.Undo[i]
		out, e := runCommand(c.Name, c.Args...)
		if e != nil && !missingResource(out) {
			failed = append([]Command{c}, failed...)
			problems = append(problems, e.Error())
		}
	}
	// Only our owned socket/interface is touched, never other VPN daemons.
	_ = os.Remove(socket)
	for i := 0; i < 20; i++ {
		if _, e := runCommand("ip", "link", "show", "dev", "awg0"); e != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, e := runCommand("ip", "link", "show", "dev", "awg0"); e == nil {
		out, e := runCommand("ip", "link", "del", "dev", "awg0")
		if e != nil && !missingResource(out) {
			problems = append(problems, e.Error())
		}
	}
	if len(problems) > 0 {
		state.Undo = failed
		_ = writeJSON(statePath, state)
		return errors.New(strings.Join(problems, "; "))
	}
	return os.Remove(statePath)
}
func missingResource(out string) bool {
	for _, s := range []string{"No such", "Cannot find", "does not exist", "Bad rule", "No chain/target/match"} {
		if strings.Contains(out, s) {
			return true
		}
	}
	return false
}
func preflightLAN() error { return preflightFamily("-4") }
func up() (err error) {
	c, e := readConfig()
	if e != nil {
		return e
	}
	s := readSettings()
	if e = validateSettings(s); e != nil {
		return e
	}
	if exists(statePath) {
		return errors.New("已有运行状态，请先停止再启动")
	}
	if exists(socket) {
		return errors.New("awg0 socket 已被占用")
	}
	if _, e = runCommand("ip", "link", "show", "dev", "awg0"); e == nil {
		return errors.New("awg0 接口已被占用")
	}
	if !exists("/dev/net/tun") {
		_, _ = runCommand("modprobe", "tun")
	}
	if !exists("/dev/net/tun") {
		return errors.New("固件缺少 /dev/net/tun，不能运行用户态隧道")
	}
	var ns []Network
	if e = validateMonitor(c, s); e != nil {
		return e
	}
	if s.Mode == "lan" {
		ns, e = networks(c, s)
		if e != nil {
			return e
		}
		if s.KillSwitch {
			if e = ensureGuard(ns); e != nil {
				return e
			}
		} else if exists(guardPath) {
			return errors.New("已有断线保护，请先停止并恢复直连")
		}
	}
	uapi, e := c.UAPI(resolveEndpoint)
	if e != nil {
		return e
	}
	uapi = "fwmark=51888\n" + uapi
	state := &State{Started: time.Now().Unix()}
	if e = writeJSON(statePath, state); e != nil {
		return e
	}
	defer func() {
		if err != nil {
			if ce := down(); ce != nil {
				err = fmt.Errorf("%v；清理未完成: %v", err, ce)
			}
		}
	}()
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	// The upstream daemon forks itself; no shell command is built from configuration.
	log, e := os.OpenFile(runtimeDir+"/engine.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer log.Close()
	proc := exec.Command(exe, "awg0")
	proc.Env = append(os.Environ(), "LOG_LEVEL=error")
	proc.Stdout = log
	proc.Stderr = log
	if e = proc.Run(); e != nil {
		return errors.New("AmneziaWG 引擎启动失败，请通过 SSH 查看 /tmp/amneziawg-asus/engine.log")
	}
	ready := false
	for i := 0; i < 40; i++ {
		if _, e = rpc(socket, "get=1"); e == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		return errors.New("AmneziaWG 控制接口未就绪")
	}
	if _, e = rpc(socket, "set=1\n"+strings.TrimSuffix(uapi, "\n")); e != nil {
		return e
	}
	for _, a := range c.Addresses {
		family := "-4"
		if a.Addr().Is6() {
			family = "-6"
		}
		if _, e = runCommand("ip", family, "address", "add", a.String(), "dev", "awg0"); e != nil {
			return e
		}
	}
	if _, e = runCommand("ip", "link", "set", "dev", "awg0", "mtu", strconv.Itoa(c.MTU), "up"); e != nil {
		return e
	}
	if s.Mode == "tunnel" {
		return nil
	}
	for _, n := range ns {
		if e = applyNetwork(state, c, s, n); e != nil {
			return e
		}
	}
	return nil
}

func lock() (func(), error) {
	if e := os.MkdirAll(runtimeDir, 0700); e != nil {
		return nil, e
	}
	p := runtimeDir + "/lock"
	if e := os.Mkdir(p, 0700); e != nil {
		return nil, errors.New("操作正在进行；若上次进程异常退出，请通过 SSH 检查 /tmp/amneziawg-asus/lock")
	}
	return func() { _ = os.Remove(p) }, nil
}
func execute(action string) (result Result, err error) {
	if action == "logs" {
		return Result{OK: true, Message: "操作日志已刷新", Logs: readLogs()}, nil
	}
	if action == "diagnose" {
		return Result{OK: true, Message: "诊断完成（路由器本机检查）", Diagnostics: diagnose()}, nil
	}
	if action == "request-check" {
		return checkRequest()
	}
	if action == "server-status" {
		return executeServer(action)
	}
	if action == "status" {
		s := readStatus()
		return Result{OK: true, Message: "状态已刷新", Status: &s}, nil
	}
	release, e := lock()
	if e != nil {
		return Result{}, e
	}
	defer release()
	defer func() { recordOperation(action, err == nil) }()
	if strings.HasPrefix(action, "server-") {
		return executeServer(action)
	}
	switch action {
	case "import":
		if _, e = importProfile(); e != nil {
			return Result{}, e
		}
	case "switch":
		id, err := payloadID()
		if err != nil {
			return Result{}, err
		}
		active := exists(statePath) || exists(guardPath)
		if e = switchProfile(id, active); e != nil {
			return Result{}, e
		}
	case "delete":
		id, err := payloadID()
		if err != nil {
			return Result{}, err
		}
		if e = deleteProfile(id); e != nil {
			return Result{}, e
		}
	case "watch":
		if e = watch(); e != nil {
			return Result{}, e
		}
	case "settings":
		if exists(statePath) || exists(guardPath) {
			return Result{}, errors.New("请先停止并恢复直连后再修改设置")
		}
		var s Settings
		d := json.NewDecoder(io.LimitReader(requestInput(), 4096))
		d.DisallowUnknownFields()
		if e = d.Decode(&s); e != nil {
			return Result{}, errors.New("设置格式错误")
		}
		if e = validateSettings(s); e != nil {
			return Result{}, e
		}
		if e = writeJSON(settingsPath, s); e != nil {
			return Result{}, e
		}
	case "up":
		if e = up(); e != nil {
			return Result{}, e
		}
	case "down":
		if e = down(); e != nil {
			return Result{}, e
		}
		if e = releaseGuard(); e != nil {
			return Result{}, e
		}
		_ = os.Remove(healthPath)
	case "recover":
		if !exists(statePath) && !exists(guardPath) {
			return Result{OK: true, Message: "隧道未启动"}, nil
		}
		if e = down(); e != nil {
			return Result{}, e
		}
		if e = up(); e != nil {
			return Result{}, e
		}
	case "boot":
		if !readSettings().Auto {
			return Result{OK: true, Message: "开机启动未开启"}, nil
		}
		if exists(statePath) {
			if e = down(); e != nil {
				return Result{}, e
			}
		}
		if e = up(); e != nil {
			return Result{}, e
		}
	default:
		return Result{}, errors.New("未知操作")
	}
	s := readStatus()
	return Result{OK: true, Message: "操作完成", Status: &s}, nil
}

// writeResponse keeps web replies safe inside Softcenter's unescaped JSON string wrapper.
func writeResponse(w io.Writer, result Result, web bool) error {
	if !web {
		return json.NewEncoder(w).Encode(result)
	}
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, "AWG64:"+base64.StdEncoding.EncodeToString(data))
	return err
}
func Run(args []string) bool {
	if len(args) < 2 || (args[1] != "ctl" && args[1] != "web") {
		return false
	}
	if len(args) != 3 {
		_ = writeResponse(os.Stdout, Result{OK: false, Message: "usage: amneziawg-go ctl|web action"}, args[1] == "web")
		return true
	}
	var result Result
	var e error
	webRequestBody = nil
	if args[1] == "web" && needsRequestBody(args[2]) {
		e = loadWebRequest()
	}
	if e == nil {
		result, e = execute(args[2])
	}
	if e != nil {
		s := readStatus()
		result = Result{OK: false, Message: e.Error(), Status: &s}
		if strings.HasPrefix(args[2], "server-") {
			v := serverStatus()
			result = Result{OK: false, Message: e.Error(), Server: &v}
		}
	}
	_ = writeResponse(os.Stdout, result, args[1] == "web")
	if e != nil {
		os.Exit(1)
	}
	return true
}
