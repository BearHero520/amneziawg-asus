// SPDX-License-Identifier: MIT
package asusctl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const policyScript = Root + "/policy/run.sh"
const policyMark = "0x8000000/0x8000000"
const policyTable = "51888"
const policyVPNChain = "AWGP_VPN"

func routingFile(name string) string { return filepath.Join(runtimeDir, "policy", name) }

func policyCommand(action string) Command { return cmd("/bin/sh", policyScript, action) }

func policyRun(action string) error {
	c := policyCommand(action)
	out, err := runCommand(c.Name, c.Args...)
	if err != nil {
		return fmt.Errorf("分流操作 %s 失败：%s", action, out)
	}
	return nil
}

func policyDestination(ref string, r RoutingSettings) string {
	switch ref {
	case "direct":
		return "RETURN"
	case "vpn_all":
		return policyVPNChain
	}
	g, _ := r.ruleFor(ref)
	return "AWGP_G" + strconv.Itoa(g.ID)
}

func policySetNames(id int) (string, string) {
	base := "awgp_dst"
	if id != 1 {
		base += strconv.Itoa(id)
	}
	return base, base + "_x"
}

func policyAddRule(plan *[]serverStep, fw, table, chain string, prepend bool, match ...string) {
	op := "-A"
	if prepend {
		op = "-I"
	}
	*plan = append(*plan, serverStep{
		cmd(fw, append([]string{"-t", table, op, chain}, match...)...),
		cmd(fw, append([]string{"-t", table, "-D", chain}, match...)...),
	})
}

func policyGeoSteps(plan *[]serverStep, r RoutingSettings) {
	for _, rule := range r.Rules {
		chain := policyDestination(geoRef(rule.ID), r)
		*plan = append(*plan, serverStep{
			cmd("iptables", "-t", "mangle", "-N", chain),
			cmd("iptables", "-t", "mangle", "-X", chain),
		})
		add := func(match ...string) { policyAddRule(plan, "iptables", "mangle", chain, false, match...) }
		inc, exc := policySetNames(rule.ID)
		useExceptions := len(routingList(rule.ExcludeDomains))+len(routingList(rule.ExcludeNetworks))+len(routingURLs(rule.ExcludeURLs)) > 0
		if rule.Mode == "include" {
			if useExceptions {
				add("-m", "set", "--match-set", exc, "dst", "-j", "RETURN")
			}
			add("-m", "set", "--match-set", inc, "dst", "-g", policyVPNChain)
		} else {
			if useExceptions {
				add("-m", "set", "--match-set", exc, "dst", "-g", policyVPNChain)
			}
			add("-m", "set", "--match-set", inc, "dst", "-j", "RETURN")
			add("-g", policyVPNChain)
		}
	}
}

func policyClientRules(r RoutingSettings, lanIf, lan, serverNet string, endpoints []string) ([]serverStep, error) {
	const chain = "AWGP_LAN"
	var plan []serverStep
	for _, name := range []string{policyVPNChain, chain} {
		plan = append(plan, serverStep{
			cmd("iptables", "-t", "mangle", "-N", name),
			cmd("iptables", "-t", "mangle", "-X", name),
		})
	}
	rule := func(name string, match ...string) { policyAddRule(&plan, "iptables", "mangle", name, false, match...) }
	rule(policyVPNChain, "-m", "addrtype", "--dst-type", "LOCAL", "-j", "RETURN")
	rule(policyVPNChain, "-p", "udp", "-m", "multiport", "--dports", "67,68,123", "-j", "RETURN")
	for _, dest := range append([]string{lan, serverNet, "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"}, endpoints...) {
		if dest != "" {
			rule(policyVPNChain, "-d", dest, "-j", "RETURN")
		}
	}
	rule(policyVPNChain, "-j", "MARK", "--set-xmark", policyMark)
	rule(policyVPNChain, "-j", "ACCEPT")
	policyGeoSteps(&plan, r)
	for _, d := range r.Devices {
		ip, mac, err := routingSource(d.Source)
		if err != nil {
			return nil, err
		}
		match := []string{"-s", ip}
		if mac != "" {
			match = []string{"-m", "mac", "--mac-source", mac}
		}
		target := policyDestination(d.Policy, r)
		jump := "-g"
		if target == "RETURN" {
			jump = "-j"
		}
		rule(chain, append(match, jump, target)...)
	}
	if p := r.defaultPolicy(); p != "direct" {
		rule(chain, "-g", policyDestination(p, r))
	}
	matchmark := []string{"-m", "mark", "--mark", policyMark, "-m", "comment", "--comment", "amneziawg-policy"}
	policyAddRule(&plan, "iptables", "nat", "POSTROUTING", true,
		append(slices.Clone(matchmark), "-o", "awg0", "-j", "MASQUERADE")...)
	policyAddRule(&plan, "iptables", "filter", "FORWARD", true,
		append(slices.Clone(matchmark), "-i", lanIf, "-o", "awg0", "-j", "ACCEPT")...)
	policyAddRule(&plan, "iptables", "filter", "FORWARD", true,
		"-i", "awg0", "-o", lanIf, "-d", lan, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	if _, err := runCommand("iptables", "-t", "nat", "-S", "SHADOWSOCKS"); err == nil {
		policyAddRule(&plan, "iptables", "nat", "SHADOWSOCKS", true, append(slices.Clone(matchmark), "-j", "RETURN")...)
	}
	policyAddRule(&plan, "iptables", "mangle", "PREROUTING", true, "-i", lanIf, "-j", chain)
	return plan, nil
}

func ipv4Default(c *Config) bool {
	type span struct{ start, end uint64 }
	var routes []span
	for _, p := range c.Peers {
		for _, a := range p.Allowed {
			if !a.Addr().Is4() {
				continue
			}
			b := a.Masked().Addr().As4()
			start := uint64(binary.BigEndian.Uint32(b[:]))
			routes = append(routes, span{start, start + (1 << (32 - a.Bits()))})
		}
	}
	slices.SortFunc(routes, func(a, b span) int {
		if a.start < b.start {
			return -1
		}
		if a.start > b.start {
			return 1
		}
		return 0
	})
	var end uint64
	for _, route := range routes {
		if route.start > end {
			return false
		}
		end = max(end, route.end)
	}
	return end == 1<<32
}

func policyCheck(c *Config, r RoutingSettings) (string, netip.Prefix, error) {
	if !ipv4Default(c) {
		return "", netip.Prefix{}, errors.New("按设备和规则分流要求当前节点的 AllowedIPs 覆盖全部 IPv4")
	}
	var hasAddress bool
	for _, addr := range c.Addresses {
		hasAddress = hasAddress || addr.Addr().Is4()
	}
	if !hasAddress {
		return "", netip.Prefix{}, errors.New("按设备和规则分流需要当前节点配置 IPv4 隧道地址")
	}
	lan, err := defaultLAN()
	if err != nil {
		return "", netip.Prefix{}, err
	}
	lanIf, err := runCommand("nvram", "get", "lan_ifname")
	if err != nil || lanIf == "" {
		return "", netip.Prefix{}, errors.New("无法读取主 LAN 接口")
	}
	for _, d := range r.Devices {
		if addr, err := netip.ParseAddr(d.Source); err == nil && !lan.Contains(addr) {
			return "", netip.Prefix{}, fmt.Errorf("设备 %s 不在主 LAN 网段", d.Source)
		}
	}
	if err = preflightLAN(); err != nil {
		return "", netip.Prefix{}, err
	}
	return lanIf, lan, nil
}

func applyPolicyNetwork(state *State, c *Config, r RoutingSettings, uapi string) error {
	if r.KillSwitch {
		if err := requireSoftwarePath(); err != nil {
			return err
		}
	}
	lanIf, lan, err := policyCheck(c, r)
	if err != nil {
		return err
	}
	var endpoints []string
	for _, line := range strings.Split(uapi, "\n") {
		if remote, ok := strings.CutPrefix(line, "endpoint="); ok {
			if peer, err := netip.ParseAddrPort(remote); err == nil && peer.Addr().Is4() {
				endpoints = append(endpoints, peer.Addr().String())
			}
		}
	}
	var serverNet string
	if srv, err := readServer(); err == nil {
		if p, err := netip.ParsePrefix(srv.Settings.Address); err == nil {
			serverNet = p.Masked().String()
		}
	}
	plan, err := policyClientRules(r, lanIf, lan.String(), serverNet, endpoints)
	if err != nil {
		return err
	}
	mangle, err := runCommand("iptables", "-t", "mangle", "-S")
	if err != nil {
		return err
	}
	for _, step := range plan {
		a := step.Do.Args
		if len(a) == 4 && a[2] == "-N" && strings.Contains("\n"+mangle+"\n", "\n-N "+a[3]+"\n") {
			return fmt.Errorf("分流链 %s 已被占用", a[3])
		}
	}
	if err = atomicWrite(routingFile("settings"), []byte(policySettingsText(r))); err != nil {
		return err
	}
	// Prepare set contents first. The journal destroys them only after all referring rules are removed.
	if err = transact(state, policyCommand("prepare"), policyCommand("clear")); err != nil {
		return err
	}
	if r.KillSwitch {
		blackhole := []string{"blackhole", "default", "metric", "32760", "table", policyTable}
		if err = transact(state, cmd("ip", append([]string{"-4", "route", "add"}, blackhole...)...), cmd("ip", append([]string{"-4", "route", "del"}, blackhole...)...)); err != nil {
			return err
		}
	}
	route := []string{"default", "dev", "awg0", "metric", "10", "table", policyTable}
	if err = transact(state, cmd("ip", append([]string{"-4", "route", "add"}, route...)...), cmd("ip", append([]string{"-4", "route", "del"}, route...)...)); err != nil {
		return err
	}
	markRule := []string{"priority", "10887", "fwmark", policyMark, "lookup", policyTable}
	if err = transact(state, cmd("ip", append([]string{"-4", "rule", "add"}, markRule...)...), cmd("ip", append([]string{"-4", "rule", "del"}, markRule...)...)); err != nil {
		return err
	}
	if r.IPv4Only {
		policyAddRule(&plan, "ip6tables", "filter", "FORWARD", true, "-i", lanIf, "!", "-o", lanIf, "-m", "comment", "--comment", "amneziawg-policy-ipv4", "-j", "REJECT")
	}
	for _, step := range plan {
		if err = transact(state, step.Do, step.Undo); err != nil {
			return err
		}
	}
	if err = activatePolicyDNS(state, c, r, lanIf); err != nil {
		return err
	}
	return atomicWrite(routingFile("active"), []byte("1\n"))
}

func activatePolicyDNS(state *State, c *Config, r RoutingSettings, lanIf string) error {
	if r.DNS == "intercept" || r.DNS == "tunnel" {
		if err := policyRun("check-dns"); err != nil {
			return err
		}
	}
	var dns string
	if r.DNS == "tunnel" {
		for _, ip := range c.DNS {
			if ip.Is4() {
				dns = ip.String()
				break
			}
		}
		if dns == "" {
			return errors.New("隧道 DNS 需要当前节点配置 IPv4 DNS 地址")
		}
		for _, ip := range c.Addresses {
			if ip.Addr().Is4() {
				rule := []string{"priority", "10888", "from", ip.Addr().String(), "lookup", policyTable}
				if e := transact(state, cmd("ip", append([]string{"-4", "rule", "add"}, rule...)...), cmd("ip", append([]string{"-4", "rule", "del"}, rule...)...)); e != nil {
					return e
				}
				break
			}
		}
		if e := atomicWrite(routingFile("dnsmasq_tunnel.conf"), []byte("no-resolv\nserver="+dns+"@awg0\n")); e != nil {
			return e
		}
	}
	if r.DNS != "intercept" && r.DNS != "tunnel" && len(r.Rules) == 0 {
		return nil
	}
	if err := transact(state, policyCommand("dns-on"), policyCommand("dns-off")); err != nil {
		return err
	}
	if r.DNS == "intercept" || r.DNS == "tunnel" {
		routerIP, err := runCommand("nvram", "get", "lan_ipaddr")
		ip, parse := netip.ParseAddr(routerIP)
		if err != nil || parse != nil || !ip.Is4() {
			return errors.New("无法读取供 DNS 接管使用的路由器地址")
		}
		for _, proto := range []string{"udp", "tcp"} {
			var dnsPlan []serverStep
			policyAddRule(&dnsPlan, "iptables", "nat", "PREROUTING", true, "-i", lanIf, "-p", proto, "--dport", "53",
				"-m", "comment", "--comment", "amneziawg-policy-dns", "-j", "DNAT", "--to-destination", ip.String())
			if err = transact(state, dnsPlan[0].Do, dnsPlan[0].Undo); err != nil {
				return err
			}
		}
	}
	return nil
}

func activePolicy() bool { return exists(routingFile("active")) && exists(statePath) }

func deactivatePolicy() {
	_ = os.Remove(routingFile("active"))
}

func watchPolicyDNS() error {
	if activePolicy() && exists(routingFile("dnsmasq_tunnel.conf")) && !exists("/sys/class/net/awg0") {
		return policyRun("dns-fallback")
	}
	return nil
}
