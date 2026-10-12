// SPDX-License-Identifier: MIT
package asusctl

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type Pair struct{ Key, Value string }
type Peer struct {
	Fields   []Pair
	Allowed  []netip.Prefix
	Endpoint string
}
type Config struct {
	Fields    []Pair
	Addresses []netip.Prefix
	DNS       []netip.Addr
	MTU       int
	Peers     []Peer
}

var extraKeys = map[string]string{
	"headerprotectionkey": "header_protection_key", "contentpaddingaddition": "content_padding_addition",
	"rekeyaftertime": "rekey_after_time", "rekeytimeout": "rekey_timeout", "rejectaftertime": "reject_after_time",
	"keepalivetimeout": "keepalive_timeout", "maxhandshakeattempts": "max_handshake_attempts",
	"randomtrailers": "random_trailers", "disablecookies": "disable_cookies",
}

func keyHex(s string) (string, error) {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil || len(b) != 32 {
		return "", errors.New("密钥必须是 32 字节的 Base64")
	}
	return hex.EncodeToString(b), nil
}
func uintValue(s string, bits int) error { _, e := strconv.ParseUint(s, 10, bits); return e }
func rangeValue(s string) error {
	p := strings.Split(s, "-")
	if len(p) > 2 {
		return errors.New("无效数值范围")
	}
	for _, v := range p {
		if e := uintValue(v, 32); e != nil {
			return e
		}
	}
	if len(p) == 2 {
		a, _ := strconv.ParseUint(p[0], 10, 32)
		b, _ := strconv.ParseUint(p[1], 10, 32)
		if a > b {
			return errors.New("范围起点大于终点")
		}
	}
	return nil
}
func Parse(text string) (*Config, error) {
	if len(text) > 32768 {
		return nil, errors.New("配置超过 32 KB")
	}
	c := &Config{MTU: 1420}
	section := ""
	seen := map[string]bool{}
	hasInterface := false
	scanner := bufio.NewScanner(strings.NewReader(strings.TrimPrefix(text, "\ufeff")))
	line := 0
	for scanner.Scan() {
		line++
		s := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "[") {
			switch strings.ToLower(s) {
			case "[interface]":
				if hasInterface || len(c.Peers) > 0 {
					return nil, errors.New("Interface 必须唯一且位于 Peer 前")
				}
				hasInterface = true
				section = "interface"
			case "[peer]":
				if !hasInterface {
					return nil, errors.New("缺少 Interface")
				}
				c.Peers = append(c.Peers, Peer{})
				section = "peer"
			default:
				return nil, fmt.Errorf("第 %d 行：未知配置段", line)
			}
			seen = map[string]bool{}
			continue
		}
		kv := strings.SplitN(s, "=", 2)
		if len(kv) != 2 || section == "" {
			return nil, fmt.Errorf("第 %d 行：配置格式错误", line)
		}
		k, v := strings.ToLower(strings.TrimSpace(kv[0])), strings.TrimSpace(kv[1])
		if v == "" || strings.ContainsAny(v, "\x00\r\n") {
			return nil, fmt.Errorf("第 %d 行：字段为空或含控制字符", line)
		}
		if seen[k] {
			return nil, fmt.Errorf("第 %d 行：重复字段 %s", line, k)
		}
		seen[k] = true
		fail := func() (*Config, error) { return nil, fmt.Errorf("第 %d 行：字段 %s 无效或不支持", line, k) }
		if section == "interface" {
			var value, key string
			key = k
			value = v
			switch k {
			case "privatekey":
				key = "private_key"
				var e error
				value, e = keyHex(v)
				if e != nil {
					return fail()
				}
			case "address":
				for _, a := range strings.Split(v, ",") {
					p, e := netip.ParsePrefix(strings.TrimSpace(a))
					if e != nil {
						return fail()
					}
					c.Addresses = append(c.Addresses, p)
				}
				continue
			case "dns":
				for _, a := range strings.Split(v, ",") {
					p, e := netip.ParseAddr(strings.TrimSpace(a))
					if e != nil {
						return fail()
					}
					c.DNS = append(c.DNS, p)
				}
				continue
			case "mtu":
				n, e := strconv.Atoi(v)
				if e != nil || n < 1280 || n > 9000 {
					return fail()
				}
				c.MTU = n
				continue
			case "listenport":
				key = "listen_port"
				if uintValue(v, 16) != nil {
					return fail()
				}
			case "jc", "jmin", "jmax":
				if uintValue(v, 32) != nil {
					return fail()
				}
			case "s1", "s2", "s3", "s4":
				if uintValue(v, 16) != nil {
					return fail()
				}
			case "h1", "h2", "h3", "h4":
				if rangeValue(v) != nil {
					return fail()
				}
			case "i1", "i2", "i3", "i4", "i5":
				if len(v) > 4096 {
					return fail()
				}
			case "table":
				if v != "auto" && v != "off" {
					return fail()
				}
				continue
			default:
				mapped, ok := extraKeys[k]
				if !ok {
					return fail()
				}
				key = mapped
				switch k {
				case "headerprotectionkey":
					var e error
					value, e = keyHex(v)
					if e != nil {
						return fail()
					}
				case "contentpaddingaddition":
					if rangeValue(v) != nil {
						return fail()
					}
				case "randomtrailers", "disablecookies":
					switch strings.ToLower(v) {
					case "true", "on", "1":
						value = "true"
					case "false", "off", "0":
						value = "false"
					default:
						return fail()
					}
				default:
					if rangeValue(v) != nil {
						return fail()
					}
				}
			}
			c.Fields = append(c.Fields, Pair{key, value})
		} else {
			p := &c.Peers[len(c.Peers)-1]
			switch k {
			case "publickey", "presharedkey":
				value, e := keyHex(v)
				if e != nil {
					return fail()
				}
				key := "public_key"
				if k == "presharedkey" {
					key = "preshared_key"
				}
				p.Fields = append(p.Fields, Pair{key, value})
			case "endpoint":
				host, port, e := net.SplitHostPort(v)
				if e != nil || host == "" || strings.ContainsAny(host, " \t/;`") {
					return fail()
				}
				n, e := strconv.Atoi(port)
				if e != nil || n < 1 || n > 65535 {
					return fail()
				}
				p.Endpoint = v
			case "allowedips":
				for _, a := range strings.Split(v, ",") {
					ip, e := netip.ParsePrefix(strings.TrimSpace(a))
					if e != nil {
						return fail()
					}
					p.Allowed = append(p.Allowed, ip.Masked())
				}
			case "persistentkeepalive":
				if v == "off" {
					v = "0"
				}
				if uintValue(v, 16) != nil {
					return fail()
				}
				p.Fields = append(p.Fields, Pair{"persistent_keepalive_interval", v})
			default:
				return fail()
			}
		}
	}
	if e := scanner.Err(); e != nil {
		return nil, e
	}
	hasKey := false
	for _, p := range c.Fields {
		if p.Key == "private_key" {
			hasKey = true
		}
	}
	if !hasKey || len(c.Addresses) == 0 || len(c.Peers) == 0 {
		return nil, errors.New("配置需要 PrivateKey、Address 和至少一个 Peer")
	}
	seenPeers := map[string]bool{}
	for _, p := range c.Peers {
		pub := ""
		for _, f := range p.Fields {
			if f.Key == "public_key" {
				pub = f.Value
			}
		}
		if pub == "" || len(p.Allowed) == 0 {
			return nil, errors.New("Peer 需要 PublicKey 和 AllowedIPs")
		}
		if seenPeers[pub] {
			return nil, errors.New("重复 Peer 公钥")
		}
		seenPeers[pub] = true
	}
	return c, nil
}

// UAPI does not execute any part of the supplied configuration.
func (c *Config) UAPI(resolve func(string) (string, error)) (string, error) {
	var b strings.Builder
	for _, p := range c.Fields {
		fmt.Fprintf(&b, "%s=%s\n", p.Key, p.Value)
	}
	b.WriteString("replace_peers=true\n")
	for _, p := range c.Peers {
		for _, f := range p.Fields {
			if f.Key == "public_key" {
				fmt.Fprintf(&b, "%s=%s\n", f.Key, f.Value)
			}
		}
		for _, f := range p.Fields {
			if f.Key != "public_key" {
				fmt.Fprintf(&b, "%s=%s\n", f.Key, f.Value)
			}
		}
		if p.Endpoint != "" {
			ep, e := resolve(p.Endpoint)
			if e != nil {
				return "", errors.New("无法解析 Peer Endpoint")
			}
			fmt.Fprintf(&b, "endpoint=%s\n", ep)
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, ip := range p.Allowed {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
		}
	}
	return b.String(), nil
}
