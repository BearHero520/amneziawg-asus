package asusctl

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

type Network struct{ Family, Source, LAN, Firewall, DNS string }

func source6(s Settings, lanIf string) (string, error) {
	out, e := runCommand("ip", "-6", "route", "show", "dev", lanIf)
	if e != nil {
		return "", e
	}
	prefixes := []netip.Prefix{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		p, e := netip.ParsePrefix(fields[0])
		if e == nil && p.Addr().Is6() && p.Addr().IsGlobalUnicast() && !p.Addr().IsLinkLocalUnicast() {
			prefixes = append(prefixes, p.Masked())
		}
	}
	if s.Source6 != "" {
		p, e := netip.ParsePrefix(s.Source6)
		if e != nil {
			return "", errors.New("IPv6 来源格式错误")
		}
		for _, lan := range prefixes {
			if p.Bits() >= lan.Bits() && lan.Contains(p.Addr()) {
				return p.Masked().String(), nil
			}
		}
		return "", errors.New("IPv6 来源不在主 LAN 的已连接 IPv6 网段内")
	}
	if len(prefixes) != 1 {
		return "", errors.New("未发现唯一 LAN IPv6 网段，请先启用路由器 IPv6 或手动指定来源 IPv6 网段")
	}
	return prefixes[0].String(), nil
}
func networks(c *Config, s Settings) ([]Network, error) {
	if s.KillSwitch {
		if e := requireSoftwarePath(); e != nil {
			return nil, e
		}
	}
	source, e := lanSource(s)
	if e != nil {
		return nil, e
	}
	lan, e := runCommand("nvram", "get", "lan_ifname")
	if e != nil || strings.TrimSpace(lan) == "" {
		return nil, errors.New("无法读取主 LAN 接口")
	}
	lan = strings.TrimSpace(lan)
	ns := []Network{{Family: "-4", Source: source, LAN: lan, Firewall: "iptables"}}
	if s.KillSwitch && !s.IPv6 {
		out, _ := runCommand("ip", "-6", "route", "show", "dev", lan)
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) > 0 {
				p, e := netip.ParsePrefix(f[0])
				if e == nil && p.Addr().Is6() && p.Addr().IsGlobalUnicast() {
					return nil, errors.New("LAN 已有 IPv6；为避免绕过断线保护，请同时配置 IPv6 分流，或先在路由器系统中关闭 IPv6")
				}
			}
		}
	}
	if s.IPv6 {
		source, e := source6(s, lan)
		if e != nil {
			return nil, e
		}
		b, e := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
		if e != nil || strings.TrimSpace(string(b)) != "1" {
			return nil, errors.New("路由器尚未开启 IPv6 转发，请先在系统 IPv6 设置中配置")
		}
		ns = append(ns, Network{Family: "-6", Source: source, LAN: lan, Firewall: "ip6tables"})
	}
	for i := range ns {
		n := &ns[i]
		is4 := n.Family == "-4"
		hasAddr, hasRoute := false, false
		for _, p := range c.Addresses {
			if p.Addr().Is4() == is4 {
				hasAddr = true
			}
		}
		for _, p := range c.Peers {
			for _, a := range p.Allowed {
				if a.Addr().Is4() == is4 {
					hasRoute = true
				}
			}
		}
		if !hasAddr || !hasRoute {
			return nil, fmt.Errorf("%s 模式需要对应的隧道 Address 和 AllowedIPs", n.Family)
		}
		if s.DNS {
			for _, ip := range c.DNS {
				if ip.Is4() == is4 {
					n.DNS = ip.String()
					break
				}
			}
			if n.DNS == "" {
				return nil, fmt.Errorf("DNS 接管需要配置中提供 %s DNS 服务器", n.Family)
			}
			ip := netip.MustParseAddr(n.DNS)
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || netip.MustParsePrefix(n.Source).Contains(ip) {
				return nil, errors.New("DNS 服务器不能是本机、链路本地或受保护的 LAN 地址")
			}
			if !configAllows(c, ip) {
				return nil, errors.New("DNS 服务器必须包含在 Peer AllowedIPs 中")
			}
		}
		if e := preflightFamily(n.Family); e != nil {
			return nil, e
		}
		if _, e := runCommand(n.Firewall, "-t", "nat", "-L", "POSTROUTING", "-n"); e != nil {
			return nil, fmt.Errorf("%s NAT 功能不可用: %w", n.Family, e)
		}
	}
	return ns, nil
}

// Broadcom fast-path flows can bypass software firewall policy. Refuse to
// advertise leak protection while the firmware reports acceleration enabled.
// We deliberately do not change global NVRAM or QoS settings for a VPN plugin.
func requireSoftwarePath() error {
	for _, key := range []string{"fc_disable", "runner_disable"} {
		value, e := runCommand("nvram", "get", key)
		if e != nil || strings.TrimSpace(value) != "1" {
			return errors.New("断线保护需要固件确认已关闭 Flow Cache / Runner 硬件加速；请先在路由器中关闭并重启。未检测到禁用状态，本次未启用保护")
		}
	}
	return nil
}
func configAllows(c *Config, ip netip.Addr) bool {
	for _, p := range c.Peers {
		for _, a := range p.Allowed {
			if a.Contains(ip) {
				return true
			}
		}
	}
	return false
}
func preflightFamily(family string) error {
	out, e := runCommand("ip", family, "rule", "show")
	if e != nil {
		return e
	}
	for _, p := range []string{"10885:", "10886:", "10887:", "10888:"} {
		if strings.Contains(out, p) {
			return fmt.Errorf("%s 策略路由优先级 10885–10888 已被占用", family)
		}
	}
	out, e = runCommand("ip", family, "route", "show", "table", "51888")
	if e != nil && !strings.Contains(out, "does not exist") {
		return e
	}
	if e == nil && strings.TrimSpace(out) != "" {
		return fmt.Errorf("%s 路由表 51888 已被占用", family)
	}
	return nil
}
func applyNetwork(state *State, c *Config, s Settings, n Network) error {
	routes := map[string]bool{}
	for _, p := range c.Peers {
		for _, a := range p.Allowed {
			if a.Addr().Is4() == (n.Family == "-4") {
				routes[a.String()] = true
			}
		}
	}
	if n.DNS != "" {
		bits := "/128"
		if n.Family == "-4" {
			bits = "/32"
		}
		routes[n.DNS+bits] = true
	}
	for a := range routes {
		if e := transact(state, cmd("ip", n.Family, "route", "add", a, "dev", "awg0", "table", "51888"), cmd("ip", n.Family, "route", "del", a, "dev", "awg0", "table", "51888")); e != nil {
			return e
		}
	}
	rules := [][]string{{"priority", "10886", "fwmark", "51888", "lookup", "main"}, {"priority", "10887", "from", n.Source, "lookup", "main", "suppress_prefixlength", "0"}, {"priority", "10888", "from", n.Source, "lookup", "51888"}}
	if n.DNS != "" {
		rules = append(rules, []string{"priority", "10885", "from", n.Source, "to", n.DNS, "lookup", "51888"})
	}
	fw := [][]string{{"-t", "nat", "-I", "POSTROUTING", "-s", n.Source, "-o", "awg0", "-m", "comment", "--comment", "amneziawg-asus", "-j", "MASQUERADE"}, {"-I", "FORWARD", "-s", n.Source, "-o", "awg0", "-m", "comment", "--comment", "amneziawg-asus", "-j", "ACCEPT"}, {"-I", "FORWARD", "-d", n.Source, "-i", "awg0", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", "amneziawg-asus", "-j", "ACCEPT"}}
	if s.DNS {
		for _, proto := range []string{"udp", "tcp"} {
			fw = append(fw, []string{"-t", "nat", "-I", "PREROUTING", "-i", n.LAN, "-s", n.Source, "-p", proto, "--dport", "53", "-m", "comment", "--comment", "amneziawg-asus", "-j", "DNAT", "--to-destination", n.DNS})
			fw = append(fw, []string{"-I", "FORWARD", "-s", n.Source, "-p", proto, "--dport", "853", "-m", "comment", "--comment", "amneziawg-asus", "-j", "REJECT"})
		}
	}
	// Firewall rules precede route activation. Cleanup reverses this order.
	for _, args := range fw {
		undo := append([]string{}, args...)
		for i, v := range undo {
			if v == "-I" {
				undo[i] = "-D"
			}
		}
		if e := transact(state, cmd(n.Firewall, args...), cmd(n.Firewall, undo...)); e != nil {
			return e
		}
	}
	for _, r := range rules {
		if e := transact(state, cmd("ip", append([]string{n.Family, "rule", "add"}, r...)...), cmd("ip", append([]string{n.Family, "rule", "del"}, r...)...)); e != nil {
			return e
		}
	}
	return nil
}
