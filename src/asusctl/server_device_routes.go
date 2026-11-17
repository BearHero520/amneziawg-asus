// SPDX-License-Identifier: MIT
package asusctl

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
)

// ServerDeviceRoute belongs to the native device record. Empty values retain
// the behavior of records created before device-level routing was available.
type ServerDeviceRoute struct {
	Scope string `json:"scope,omitempty"`
	Exit  string `json:"exit,omitempty"`
}

func (r ServerDeviceRoute) internet(s ServerSettings) bool {
	return s.Internet && r.Scope != "lan"
}

func (r ServerDeviceRoute) validate(s ServerSettings) error {
	switch r.Scope {
	case "", "lan", "full":
	default:
		return errors.New("访问范围无效")
	}
	if r.Scope == "lan" && !s.AllowLAN {
		return errors.New("仅家庭内网需要服务端开启局域网访问")
	}
	if r.Scope == "full" && !s.Internet {
		return errors.New("请先在服务端启用通过家里上网")
	}
	switch r.Exit {
	case "", "proxy", "wan":
		return nil
	}
	if peerUsesClient(r.Exit) && readSettings().Routing.validPolicy(r.Exit) {
		return nil
	}
	return errors.New("家庭出口无效")
}

func peerUsesClient(exit string) bool {
	return exit == "vpn_all" || strings.HasPrefix(exit, "vpn_geo_")
}

func validatePeerRoutingRules(r RoutingSettings) error {
	c, err := readServer()
	if err != nil {
		return nil
	}
	for _, p := range c.Clients {
		if peerUsesClient(p.Route.Exit) && !r.validPolicy(p.Route.Exit) {
			return fmt.Errorf("分流规则正在被接入设备 %s 使用，请先切换该设备出口", p.Name)
		}
	}
	return nil
}

func serverPolicyAvailable() bool {
	if !activePolicy() {
		return false
	}
	if !exists(serverStatePath) {
		return true
	}
	out, err := runCommand("ip", "-4", "rule", "show")
	if err != nil {
		return false
	}
	for _, rule := range strings.Split(out, "\n") {
		if strings.Contains(rule, "iif "+serverInterface+" ") && strings.Contains(rule, "fwmark "+policyMark+" ") {
			return true
		}
	}
	return false
}

func syncPolicyPeers() error {
	if !exists(serverStatePath) {
		return nil
	}
	c, err := readServer()
	if err != nil {
		return err
	}
	for _, p := range c.Clients {
		if peerUsesClient(p.Route.Exit) {
			return replaceDeviceRoutes(c)
		}
	}
	return nil
}

func serverSetDeviceRoute(id string, route ServerDeviceRoute) error {
	c, err := readServer()
	if err != nil {
		return err
	}
	if err = route.validate(c.Settings); err != nil {
		return err
	}
	for i, device := range c.Clients {
		if device.ID != id {
			continue
		}
		if device.Route == route {
			return nil
		}
		if exists(peerJournal()) {
			return errors.New("上次设备变更仍在处理")
		}
		c.Clients[i].Route = route
		if !exists(serverStatePath) {
			return persistPeerConfig(c)
		}
		if _, err = peerRPC(serverSocket, "get=1"); err != nil {
			return errors.New("服务端控制接口未就绪，请刷新状态")
		}
		if err = atomicWrite(peerJournal(), []byte("device routes pending\n")); err != nil {
			return err
		}
		previous := c
		previous.Clients = slices.Clone(c.Clients)
		previous.Clients[i] = device
		if err = replaceOneDeviceRoute(c, c.Clients[i]); err != nil {
			if restore := replaceOneDeviceRoute(previous, device); restore == nil {
				_ = os.Remove(peerJournal())
			}
			return err
		}
		if err = persistPeerConfig(c); err != nil {
			if restore := replaceOneDeviceRoute(previous, device); restore == nil {
				_ = os.Remove(peerJournal())
			}
			return err
		}
		return os.Remove(peerJournal())
	}
	return errors.New("未找到设备")
}

func deviceRouteState() string { return serverStatePath + ".devices" }

func deviceFirewallRule(fw, table, chain string, args ...string) serverStep {
	base := []string{"-t", table}
	do := append(append(slices.Clone(base), "-I", chain, "1"), args...)
	undo := append(append(slices.Clone(base), "-D", chain), args...)
	return serverStep{cmd(fw, do...), cmd(fw, undo...)}
}

func deviceRoutePlan(c ServerConfig) []serverStep {
	var plan []serverStep
	var clientPolicy bool
	routing := readSettings().Routing
	for _, p := range c.Clients {
		if !p.Disabled && p.Route.internet(c.Settings) && peerUsesClient(p.Route.Exit) {
			clientPolicy = serverPolicyAvailable()
			break
		}
	}
	for _, family := range []struct {
		fw, flag, chain string
	}{{"iptables", "-4", "SHADOWSOCKS"}, {"ip6tables", "-6", "SHADOWSOCKS6"}} {
		if family.flag == "-6" && c.Settings.Address6 == "" {
			continue
		}
		var nat, mangle, quic bool
		detected := false
		for _, p := range c.Clients {
			if p.Disabled || (p.Route == (ServerDeviceRoute{})) {
				continue
			}
			source := p.Address
			if family.flag == "-6" {
				source = p.Address6
			}
			prefix, err := netip.ParsePrefix(source)
			if err != nil || prefix.Bits() != prefix.Addr().BitLen() || prefix.Addr().Is4() != (family.flag == "-4") {
				continue
			}
			if !detected {
				_, e := runCommand(family.fw, "-t", "nat", "-S", family.chain)
				nat = e == nil
				_, e = runCommand(family.fw, "-t", "mangle", "-S", family.chain)
				mangle = e == nil
				_, e = runCommand(family.fw, "-C", "FORWARD", "-p", "udp", "--dport", "443", "-j", family.chain)
				quic = e == nil
				detected = true
			}
			match := []string{"-i", serverInterface, "-s", prefix.String(), "-m", "comment", "--comment", "amneziawg-device-route"}
			internet := p.Route.internet(c.Settings)
			switch {
			case !internet:
				if wan := serverWAN(family.flag); wan != "" {
					plan = append(plan, deviceFirewallRule(family.fw, "filter", "AWGS_F", append(slices.Clone(match), "-o", wan, "-j", "REJECT")...))
				}
				fallthrough
			case p.Route.Exit == "wan" || peerUsesClient(p.Route.Exit):
				for _, table := range []struct {
					name    string
					present bool
				}{{"nat", nat}, {"mangle", mangle}, {"filter", quic}} {
					if table.present {
						plan = append(plan, deviceFirewallRule(family.fw, table.name, family.chain, append(slices.Clone(match), "-j", "RETURN")...))
					}
				}
				if family.flag == "-4" && internet && clientPolicy && peerUsesClient(p.Route.Exit) && routing.validPolicy(p.Route.Exit) {
					plan = append(plan, deviceFirewallRule(family.fw, "mangle", "PREROUTING",
						append(slices.Clone(match), "-j", policyDestination(p.Route.Exit, routing))...))
					out := append(slices.Clone(match), "-o", "awg0", "-m", "mark", "--mark", policyMark)
					for _, private := range []string{"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"} {
						plan = append(plan, deviceFirewallRule(family.fw, "filter", "AWGS_F",
							append(slices.Clone(out), "-d", private, "-j", "REJECT")...))
					}
					// Insert the grant before the private-address denials in the plan so
					// those denials get the highest priority within the peer's rules.
					grant := deviceFirewallRule(family.fw, "filter", "AWGS_F",
						append(out, "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT")...)
					plan = slices.Insert(plan, len(plan)-4, grant)
				}
			case p.Route.Exit == "proxy":
				if quic {
					plan = append(plan, deviceFirewallRule(family.fw, "filter", "AWGS_F", append(slices.Clone(match), "-p", "udp", "--dport", "443", "-j", family.chain)...))
				}
				if nat && !c.Settings.AllowLAN {
					plan = append(plan, deviceFirewallRule(family.fw, "filter", "AWGS_I",
						append(slices.Clone(match), "-p", "tcp", "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT")...))
				}
			}
		}
	}
	return plan
}

func loadDeviceRoutes() ([]serverStep, error) {
	var rules []serverStep
	err := loadJSONFile(deviceRouteState(), &rules)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return rules, err
}

func removeDeviceRules(rules []serverStep) error {
	var failed []error
	for i := len(rules) - 1; i >= 0; i-- {
		c := rules[i].Undo
		out, err := runCommand(c.Name, c.Args...)
		if err != nil && !missingResource(out) {
			failed = append(failed, err)
		}
	}
	return errors.Join(failed...)
}

func clearDeviceRoutes() error {
	rules, err := loadDeviceRoutes()
	if err != nil {
		return err
	}
	if err = removeDeviceRules(rules); err != nil {
		return err
	}
	if err = os.Remove(deviceRouteState()); !os.IsNotExist(err) {
		return err
	}
	return nil
}

func replaceDeviceRoutes(c ServerConfig) error {
	return applyDeviceRoutes(c, nil)
}

func replaceOneDeviceRoute(c ServerConfig, p ServerClient) error {
	c.Clients = []ServerClient{p}
	return applyDeviceRoutes(c, &p)
}

func ruleMatchesDevice(step serverStep, device ServerClient) bool {
	args := step.Do.Args
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-s" {
			prefix, err := netip.ParsePrefix(args[i+1])
			if err != nil {
				return false
			}
			a, _ := netip.ParsePrefix(device.Address)
			a6, _ := netip.ParsePrefix(device.Address6)
			return prefix == a || prefix == a6
		}
	}
	return false
}

func applyDeviceRoutes(c ServerConfig, target *ServerClient) error {
	previous, err := loadDeviceRoutes()
	if err != nil {
		return err
	}
	next := deviceRoutePlan(c)
	var replace, keep []serverStep
	for _, rule := range previous {
		if target == nil || ruleMatchesDevice(rule, *target) {
			replace = append(replace, rule)
		} else {
			keep = append(keep, rule)
		}
	}
	// The union lets server-down clean both sets if an update is interrupted.
	if len(previous)+len(next) > 0 {
		if err = writeJSON(deviceRouteState(), append(slices.Clone(previous), next...)); err != nil {
			return err
		}
	}
	if err = removeDeviceRules(replace); err != nil {
		return fmt.Errorf("清理旧设备出口失败: %w", err)
	}
	for _, rule := range next {
		a := rule.Do
		if _, err = runCommand(a.Name, a.Args...); err != nil {
			return fmt.Errorf("应用设备出口失败: %w", err)
		}
	}
	next = append(keep, next...)
	if len(next) > 0 {
		return writeJSON(deviceRouteState(), next)
	}
	if err = os.Remove(deviceRouteState()); !os.IsNotExist(err) {
		return err
	}
	return nil
}
