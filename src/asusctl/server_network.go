// SPDX-License-Identifier: MIT
package asusctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func serverLAN6(dev string) []string {
	out, e := runCommand("ip", "-6", "route", "show", "dev", dev)
	if e != nil {
		return nil
	}
	var result []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		p, e := netip.ParsePrefix(f[0])
		if e == nil && p.Addr().Is6() && p.Addr().IsGlobalUnicast() && !p.Addr().IsLinkLocalUnicast() {
			result = append(result, p.Masked().String())
		}
	}
	return result
}
func serverWAN(family string) string {
	out, e := runCommand("ip", family, "route", "show", "default")
	if e != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "dev" {
				return f[i+1]
			}
		}
	}
	return ""
}

type serverStep struct{ Do, Undo Command }

func serverPlan(s ServerSettings, family, lanIf, wanIf, lanIP string, lans []string) []serverStep {
	fw := "iptables"
	address := s.Address
	if family == "-6" {
		fw = "ip6tables"
		address = s.Address6
	}
	p, _ := netip.ParsePrefix(address)
	source := p.Masked().String()
	var plan []serverStep
	add := func(do, undo Command) { plan = append(plan, serverStep{do, undo}) }
	rule := func(table, chain string, args ...string) {
		a := append([]string{"-t", table, "-A", chain}, args...)
		u := append([]string{"-t", table, "-D", chain}, args...)
		add(cmd(fw, a...), cmd(fw, u...))
	}
	hook := func(chain string, args ...string) {
		a := append([]string{"-I", chain, "1"}, args...)
		u := append([]string{"-D", chain}, args...)
		add(cmd(fw, a...), cmd(fw, u...))
	}
	for _, chain := range []string{"AWGS_I", "AWGS_F"} {
		add(cmd(fw, "-N", chain), cmd(fw, "-X", chain))
	}
	rule("filter", "AWGS_F", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
	rule("filter", "AWGS_F", "-o", serverInterface, "-d", source, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	// Only the main LAN is granted. Peer-to-peer and other local networks remain denied.
	if s.AllowLAN {
		rule("filter", "AWGS_I", "-s", source, "-d", p.Addr().String(), "-j", "ACCEPT")
		if lanIP != "" {
			rule("filter", "AWGS_I", "-s", source, "-d", lanIP, "-j", "ACCEPT")
		}
		for _, lan := range lans {
			rule("filter", "AWGS_F", "-i", serverInterface, "-s", source, "-o", lanIf, "-d", lan, "-j", "ACCEPT")
		}
		rule("nat", "POSTROUTING", "-s", source, "-o", lanIf, "-j", "MASQUERADE")
	}
	if s.Internet {
		blocked := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"}
		if family == "-6" {
			blocked = []string{"fc00::/7", "fe80::/10", "ff00::/8", "::/128", "::1/128"}
		}
		blocked = append(blocked, lans...)
		for _, dst := range blocked {
			rule("filter", "AWGS_F", "-i", serverInterface, "-d", dst, "-j", "REJECT")
		}
		// Our early ACCEPT bypasses the firmware/fullv QUIC fallback rules.
		// Keep this optional rule in our own chain; never modify proxy chains.
		if s.Fullv {
			rule("filter", "AWGS_F", "-i", serverInterface, "-s", source, "-p", "udp", "--dport", "443", "-j", "REJECT")
		}
		rule("filter", "AWGS_F", "-i", serverInterface, "-s", source, "-o", wanIf, "-j", "ACCEPT")
		rule("nat", "POSTROUTING", "-s", source, "-o", wanIf, "-j", "MASQUERADE")
	}
	rule("filter", "AWGS_I", "-j", "REJECT")
	rule("filter", "AWGS_F", "-j", "REJECT")
	hook("INPUT", "-i", serverInterface, "-j", "AWGS_I")
	hook("FORWARD", "-i", serverInterface, "-j", "AWGS_F")
	hook("FORWARD", "-o", serverInterface, "-j", "AWGS_F")
	return plan
}
func serverTransaction(state *State, step serverStep) error {
	state.Undo = append(state.Undo, step.Undo)
	if e := writeJSON(serverStatePath, state); e != nil {
		return e
	}
	_, e := runCommand(step.Do.Name, step.Do.Args...)
	return e
}
func serverDown() error {
	b, e := os.ReadFile(serverStatePath)
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
	// Close the owned tunnel before removing access restrictions.
	if e := os.Remove(serverSocket); e != nil && !os.IsNotExist(e) {
		return errors.New("无法关闭服务端控制接口；保留防火墙规则")
	}
	for i := 0; i < 20; i++ {
		if _, e := runCommand("ip", "link", "show", "dev", serverInterface); e != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	out, e := runCommand("ip", "link", "del", "dev", serverInterface)
	if e != nil && !missingResource(out) {
		return errors.New("服务端接口未能关闭；保留防火墙规则")
	}
	failed := []Command{}
	var errs []string
	for i := len(state.Undo) - 1; i >= 0; i-- {
		c := state.Undo[i]
		out, e := runCommand(c.Name, c.Args...)
		if e != nil && !missingResource(out) {
			failed = append([]Command{c}, failed...)
			errs = append(errs, e.Error())
		}
	}
	if len(errs) > 0 {
		state.Undo = failed
		_ = writeJSON(serverStatePath, state)
		return errors.New(strings.Join(errs, "; "))
	}
	if e := os.Remove(peerJournal()); e != nil && !os.IsNotExist(e) {
		return e
	}
	return os.Remove(serverStatePath)
}
func serverPreflight(family, address string) error {
	p, _ := netip.ParsePrefix(address)
	out, e := runCommand("ip", family, "route", "show", "table", "all")
	if e != nil {
		return e
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		q, e := netip.ParsePrefix(f[0])
		if e == nil && q.Bits() > 0 && p.Overlaps(q) {
			return fmt.Errorf("服务端网段与已有路由 %s 重叠", q)
		}
	}
	fw := "iptables"
	forward := "/proc/sys/net/ipv4/ip_forward"
	if family == "-6" {
		fw = "ip6tables"
		forward = "/proc/sys/net/ipv6/conf/all/forwarding"
	}
	b, e := os.ReadFile(forward)
	if e != nil || strings.TrimSpace(string(b)) != "1" {
		return errors.New("路由器未开启所需地址族的 IP 转发")
	}
	for _, chain := range []string{"AWGS_I", "AWGS_F"} {
		if _, e := runCommand(fw, "-S", chain); e == nil {
			return errors.New("服务端防火墙链已占用，请先清理上次运行状态")
		}
	}
	return nil
}
func serverUp() (err error) {
	if exists(serverStatePath) || exists(serverSocket) {
		return errors.New("服务端已有运行状态，请先停止")
	}
	c, e := readServer()
	if e != nil {
		return errors.New("请先保存服务端设置")
	}
	s := c.Settings
	if e = validateServerSettings(s); e != nil {
		return e
	}
	if enabledClients(c) == 0 {
		return errors.New("请先添加或启用至少一台设备")
	}
	parsed, e := Parse(serverConf(c))
	if e != nil {
		return e
	}
	uapi, e := parsed.UAPI(resolveEndpoint)
	if e != nil {
		return e
	}
	if _, e = runCommand("ip", "link", "show", "dev", serverInterface); e == nil {
		return errors.New("awgs0 接口已被占用")
	}
	lan, e := defaultLAN()
	if e != nil {
		return e
	}
	lanIf := nvramValue("lan_ifname")
	wan4 := serverWAN("-4")
	wan6 := serverWAN("-6")
	if lanIf == "" || wan4 == "" || wan4 == serverInterface || wan4 == "awg0" {
		return errors.New("无法识别独立 WAN / LAN 接口")
	}
	if !s.AllowLAN {
		if e = requireSoftwarePath(); e != nil {
			return fmt.Errorf("禁用局域网访问需要关闭 Flow Cache / Runner 硬件加速: %w", e)
		}
	}
	families := []string{"-4"}
	if s.Address6 != "" {
		families = append(families, "-6")
		if s.Internet && wan6 == "" {
			return errors.New("通过家里访问 IPv6 互联网需要有效 WAN IPv6 默认路由")
		}
	}
	var plan []serverStep
	for _, family := range families {
		address := s.Address
		w := wan4
		lip := nvramValue("lan_ipaddr")
		lans := []string{lan.String()}
		if family == "-6" {
			address = s.Address6
			w = wan6
			lip = ""
			lans = serverLAN6(lanIf)
		}
		if e = serverPreflight(family, address); e != nil {
			return e
		}
		rules, re := runCommand("ip", family, "rule", "show")
		if re != nil {
			return re
		}
		priority, pe := chooseServerPriority(rules, address)
		if pe != nil {
			return pe
		}
		plan = append(plan, serverPlan(s, family, lanIf, w, lip, lans)...)
		plan = append(plan, serverPolicyStep(family, priority))
	}
	// Detect conflicts with native WireGuard and other UDP services before mutation.
	listener, e := net.ListenPacket("udp", ":"+strconv.Itoa(s.Port))
	if e != nil {
		return errors.New("监听端口已占用，请更换端口")
	}
	_ = listener.Close()
	if !exists("/dev/net/tun") {
		_, _ = runCommand("modprobe", "tun")
	}
	if !exists("/dev/net/tun") {
		return errors.New("固件缺少 /dev/net/tun")
	}
	state := &State{Started: time.Now().Unix()}
	if e = writeJSON(serverStatePath, state); e != nil {
		return e
	}
	defer func() {
		if err != nil {
			if ce := serverDown(); ce != nil {
				err = fmt.Errorf("%v；回滚未完成: %v", err, ce)
			}
		}
	}()
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	log, e := os.OpenFile(runtimeDir+"/server-engine.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer log.Close()
	proc := exec.Command(exe, serverInterface)
	proc.Env = append(os.Environ(), "LOG_LEVEL=error")
	proc.Stdout = log
	proc.Stderr = log
	if e = proc.Run(); e != nil {
		return errors.New("服务端引擎启动失败")
	}
	ready := false
	for i := 0; i < 40; i++ {
		if _, e = rpc(serverSocket, "get=1"); e == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		return errors.New("服务端控制接口未就绪")
	}
	if _, e = rpc(serverSocket, "set=1\n"+strings.TrimSuffix(uapi, "\n")); e != nil {
		return e
	}
	for _, step := range plan {
		if e = serverTransaction(state, step); e != nil {
			return e
		}
	}
	for _, a := range parsed.Addresses {
		family := "-4"
		if a.Addr().Is6() {
			family = "-6"
		}
		if _, e = runCommand("ip", family, "address", "add", a.String(), "dev", serverInterface); e != nil {
			return e
		}
	}
	if _, e = runCommand("ip", "link", "set", "dev", serverInterface, "mtu", strconv.Itoa(parsed.MTU), "up"); e != nil {
		return e
	}
	for _, f := range []struct{ fw, dev string }{{"iptables", wan4}, {"ip6tables", wan6}} {
		if f.dev == "" {
			continue
		}
		args := []string{"INPUT", "-i", f.dev, "-p", "udp", "--dport", strconv.Itoa(s.Port), "-m", "comment", "--comment", "amneziawg-server", "-j", "ACCEPT"}
		do := append([]string{"-I"}, args...)
		undo := append([]string{"-D"}, args...)
		if e = serverTransaction(state, serverStep{cmd(f.fw, do...), cmd(f.fw, undo...)}); e != nil {
			return e
		}
	}
	return nil
}
func executeServer(action string) (Result, error) {
	var e error
	result := Result{OK: true, Message: "操作完成"}
	switch action {
	case "server-status":
	case "server-save":
		var s ServerSettings
		e = readServerPayload(&s)
		if e == nil {
			e = serverSave(s)
		}
	case "server-add":
		var p struct {
			Name string `json:"name"`
		}
		e = readServerPayload(&p)
		if e == nil {
			e = serverAdd(p.Name)
		}
	case "server-delete", "server-export", "server-enable", "server-disable":
		var p struct {
			ID string `json:"id"`
		}
		e = readServerPayload(&p)
		if e == nil {
			if action == "server-delete" {
				e = serverDelete(p.ID)
			} else if action == "server-enable" || action == "server-disable" {
				e = serverSetDisabled(p.ID, action == "server-disable")
			} else {
				result.Export, e = serverExport(p.ID)
				result.Filename = "amneziawg-" + p.ID + ".conf"
			}
		}
	case "server-up":
		e = serverUp()
	case "server-down":
		e = serverDown()
	case "server-boot":
		c, ce := readServer()
		if ce == nil && c.Settings.Auto {
			if exists(serverStatePath) {
				e = serverDown()
			}
			if e == nil {
				e = serverUp()
			}
		}
	case "server-recover":
		if exists(serverStatePath) {
			e = serverDown()
			if e == nil {
				e = serverUp()
			}
		}
	default:
		return Result{}, errors.New("未知服务端操作")
	}
	if e != nil {
		return Result{}, e
	}
	if name, ok := operationNames[action]; ok {
		result.Message = name + "完成"
	}
	s := serverStatus()
	result.Server = &s
	return result, nil
}
