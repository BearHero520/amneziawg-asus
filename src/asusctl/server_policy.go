package asusctl

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Only prove non-matches from the incoming interface or authenticated tunnel
// source range. Marks, destinations and unknown selectors remain conservative.
func serverRuleMayMatch(fields []string, source netip.Prefix) bool {
	for _, v := range fields {
		if v == "not" {
			return true
		}
	}
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "iif" && fields[i+1] != serverInterface {
			return false
		}
		if fields[i] == "from" && fields[i+1] != "all" {
			p, e := netip.ParsePrefix(fields[i+1])
			if e != nil {
				a, ae := netip.ParseAddr(fields[i+1])
				if ae != nil {
					return true
				}
				p = netip.PrefixFrom(a, a.BitLen())
			}
			if !source.Overlaps(p) {
				return false
			}
		}
	}
	return true
}

func chooseServerPriority(rules, address string) (int, error) {
	source, e := netip.ParsePrefix(address)
	if e != nil {
		return 0, e
	}
	used := map[int]bool{}
	first := 32766
	blocking := ""
	for _, line := range strings.Split(rules, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		n, e := strconv.Atoi(strings.TrimSuffix(f[0], ":"))
		if e != nil || n < 0 {
			return 0, fmt.Errorf("无法识别策略路由规则，未修改路由")
		}
		used[n] = true
		// Standard local lookup must stay first. Never delete or reorder it.
		normalLocal := strings.Join(f, " ") == "0: from all lookup local" || strings.Join(f, " ") == "0: from all lookup 255" || strings.Join(f, " ") == "0: from all lookup local proto kernel"
		if normalLocal {
			continue
		}
		if serverRuleMayMatch(f[1:], source) && n < first {
			first = n
			blocking = line
		}
	}
	// Prefer the original slot, then earlier free slots. If all are used only by
	// unrelated rules, later free slots are safe before the first possible match.
	for n := 90; n >= 1; n-- {
		if n < first && !used[n] {
			return n, nil
		}
	}
	for n := 91; n < first; n++ {
		if !used[n] {
			return n, nil
		}
	}
	if len(blocking) > 200 {
		blocking = blocking[:200]
	}
	return 0, fmt.Errorf("没有可安全插入服务端规则的优先级；现有规则可能匹配 %s：%s（未修改该规则）", serverInterface, strings.TrimSpace(blocking))
}

func serverPolicyStep(family string, priority int) serverStep {
	p := strconv.Itoa(priority)
	return serverStep{cmd("ip", family, "rule", "add", "priority", p, "iif", serverInterface, "lookup", "main"), cmd("ip", family, "rule", "del", "priority", p, "iif", serverInterface, "lookup", "main")}
}
