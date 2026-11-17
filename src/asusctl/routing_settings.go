// SPDX-License-Identifier: MIT
package asusctl

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type RoutingSettings struct {
	Default    string          `json:"default,omitempty"`
	DNS        string          `json:"dns,omitempty"`
	IPv4Only   bool            `json:"ipv4_only,omitempty"`
	KillSwitch bool            `json:"kill_switch,omitempty"`
	AutoUpdate bool            `json:"auto_update,omitempty"`
	Devices    []RoutingDevice `json:"devices,omitempty"`
	Rules      []GeoRule       `json:"rules,omitempty"`
}

type RoutingDevice struct {
	Source string `json:"source"`
	Policy string `json:"policy"`
}

type GeoRule struct {
	ID              int    `json:"id"`
	Name            string `json:"name"`
	Mode            string `json:"mode"`
	GeoIP           string `json:"geoip"`
	GeoSite         string `json:"geosite"`
	Antifilter      string `json:"antifilter"`
	Domains         string `json:"domains"`
	Networks        string `json:"networks"`
	URLs            string `json:"urls"`
	ExcludeDomains  string `json:"exclude_domains"`
	ExcludeNetworks string `json:"exclude_networks"`
	ExcludeURLs     string `json:"exclude_urls"`
}

var geoCategory = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.!-]{0,63}$`)
var geoDomain = regexp.MustCompile(`^([a-zA-Z0-9_][a-zA-Z0-9_-]{0,62}\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$`)

func routingList(raw string) []string {
	var entries []string
	for _, line := range strings.Split(raw, "\n") {
		line, _, _ = strings.Cut(line, "#")
		entries = append(entries, strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\r'
		})...)
	}
	return entries
}

func routingURLs(raw string) []string {
	var urls []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}
	return urls
}

func geoNetworkList(raw string) string {
	var entries []string
	for _, value := range routingList(raw) {
		if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Bits() == 0 {
			entries = append(entries, "0.0.0.0/1", "128.0.0.0/1")
		} else {
			entries = append(entries, value)
		}
	}
	return strings.Join(entries, ",")
}

func geoRef(id int) string { return "vpn_geo_" + strconv.Itoa(id) }

func (r RoutingSettings) defaultPolicy() string {
	if r.Default == "" {
		return "direct"
	}
	return r.Default
}

func (r RoutingSettings) ruleFor(ref string) (GeoRule, bool) {
	for _, rule := range r.Rules {
		if geoRef(rule.ID) == ref {
			return rule, true
		}
	}
	return GeoRule{}, false
}

func (r RoutingSettings) validPolicy(ref string) bool {
	if ref == "direct" || ref == "vpn_all" {
		return true
	}
	_, ok := r.ruleFor(ref)
	return ok
}

func routingSource(raw string) (ip, mac string, err error) {
	if a, e := netip.ParseAddr(raw); e == nil && a.Is4() && a.IsGlobalUnicast() {
		return a.String(), "", nil
	}
	if a, e := net.ParseMAC(raw); e == nil && len(a) == 6 && a[0]&1 == 0 {
		return "", a.String(), nil
	}
	return "", "", fmt.Errorf("设备地址须为 IPv4 或单播 MAC：%s", raw)
}

func (r RoutingSettings) validate() error {
	switch r.DNS {
	case "", "router", "intercept", "tunnel":
	default:
		return errors.New("不支持的 DNS 模式")
	}
	if len(r.Rules) > 8 || len(r.Devices) > 32 {
		return errors.New("最多 8 套分流规则和 32 台局域网设备")
	}
	ids := make(map[int]bool)
	for _, rule := range r.Rules {
		if rule.ID < 1 || rule.ID > 8 || ids[rule.ID] || strings.TrimSpace(rule.Name) == "" || len(rule.Name) > 64 {
			return errors.New("分流规则编号重复或名称不合法")
		}
		ids[rule.ID] = true
		if rule.Mode != "include" && rule.Mode != "exclude" {
			return errors.New("分流规则需要选择包含或排除模式")
		}
		if err := rule.validateLists(); err != nil {
			return fmt.Errorf("分流规则 %s：%w", rule.Name, err)
		}
	}
	if !r.validPolicy(r.defaultPolicy()) {
		return errors.New("默认策略引用了不存在的分流规则")
	}
	sources := make(map[string]bool)
	for _, device := range r.Devices {
		ip, mac, err := routingSource(device.Source)
		if err != nil {
			return err
		}
		if sources[ip+mac] || !r.validPolicy(device.Policy) {
			return errors.New("分流设备地址重复或引用了不存在的分流规则")
		}
		sources[ip+mac] = true
	}
	return nil
}

func (g GeoRule) validateLists() error {
	for _, v := range append(routingList(g.GeoIP), routingList(g.GeoSite)...) {
		if !geoCategory.MatchString(v) {
			return fmt.Errorf("分类无效：%s", v)
		}
	}
	allowed := []string{"allyouneed", "ipsum", "ip", "ipresolve", "subnet", "community", "community_domains"}
	for _, v := range routingList(g.Antifilter) {
		if !slices.Contains(allowed, v) {
			return fmt.Errorf("Antifilter 列表无效：%s", v)
		}
	}
	for _, v := range append(routingList(g.Domains), routingList(g.ExcludeDomains)...) {
		if len(v) > 253 || !geoDomain.MatchString(strings.TrimPrefix(v, ".")) {
			return fmt.Errorf("域名无效：%s", v)
		}
	}
	for _, v := range append(routingList(g.Networks), routingList(g.ExcludeNetworks)...) {
		if a, e := netip.ParseAddr(v); e == nil && a.Is4() {
			continue
		}
		if p, e := netip.ParsePrefix(v); e != nil || !p.Addr().Is4() {
			return fmt.Errorf("IPv4 地址或 CIDR 无效：%s", v)
		}
	}
	urls := append(routingURLs(g.URLs), routingURLs(g.ExcludeURLs)...)
	if len(urls) > 12 {
		return errors.New("每套规则最多 12 个订阅地址")
	}
	for _, raw := range urls {
		u, e := url.Parse(raw)
		if e != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil ||
			strings.ContainsAny(raw, " \t\r\n") || len(raw) > 512 {
			return errors.New("订阅地址需要是 HTTP 或 HTTPS URL")
		}
	}
	return nil
}

func policySettingsText(r RoutingSettings) string {
	var out strings.Builder
	var registry []string
	put := func(key, value string) {
		if value != "" {
			fmt.Fprintln(&out, key, value)
		}
	}
	for _, g := range r.Rules {
		id := strconv.Itoa(g.ID)
		registry = append(registry, id+":"+id)
		prefix, anti := "awg_geo_"+id+"_", "awg_antifilter_"+id+"_lists"
		if g.ID == 1 {
			prefix, anti = "awg_geo_", "awg_antifilter_lists"
		}
		mode := "vpn"
		if g.Mode == "exclude" {
			mode = "direct"
		}
		put(prefix+"mode", mode)
		put(prefix+"v2fly_ip", strings.Join(routingList(g.GeoIP), ","))
		put(prefix+"v2fly", strings.Join(routingList(g.GeoSite), ","))
		put(anti, strings.Join(routingList(g.Antifilter), ","))
		put(prefix+"custom_domains", strings.Join(routingList(g.Domains), ","))
		put(prefix+"custom_ips", geoNetworkList(g.Networks))
		put(prefix+"exc_domains", strings.Join(routingList(g.ExcludeDomains), ","))
		put(prefix+"exc_ips", geoNetworkList(g.ExcludeNetworks))
		put(prefix+"custom_urls", base64.StdEncoding.EncodeToString([]byte(strings.Join(routingURLs(g.URLs), "\n"))))
		put(prefix+"exc_urls", base64.StdEncoding.EncodeToString([]byte(strings.Join(routingURLs(g.ExcludeURLs), "\n"))))
	}
	put("awg_geo_policies", strings.Join(registry, ";"))
	return out.String()
}

func (r RoutingSettings) needsLists() bool {
	for _, g := range r.Rules {
		if strings.TrimSpace(g.GeoIP+g.GeoSite+g.Antifilter+g.URLs+g.ExcludeURLs) != "" {
			return true
		}
	}
	return false
}
