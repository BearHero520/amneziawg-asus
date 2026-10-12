package asusctl

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"
)

type LogEntry struct {
	Time    int64  `json:"time"`
	Action  string `json:"action"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}
type Diagnostic struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

var operationNames = map[string]string{
	"core-upgrade": "核心升级", "core-rollback": "核心回滚",
	"server-save": "保存服务端设置", "server-add": "添加设备", "server-delete": "删除设备", "server-enable": "启用设备", "server-disable": "禁用设备",
	"server-up": "启动服务端", "server-down": "停止服务端", "server-boot": "服务端开机启动", "server-recover": "恢复服务端",
	"import": "导入客户端配置", "settings": "保存客户端设置", "switch": "切换客户端节点", "delete": "删除客户端节点", "up": "启动客户端", "down": "停止客户端", "boot": "客户端开机启动", "recover": "恢复客户端",
}

func readLogs() []LogEntry {
	entries := []LogEntry{}
	f, e := os.Open(runtimeDir + "/operations.json")
	if e != nil {
		return entries
	}
	defer f.Close()
	// The file is internal, but bound memory even if it was externally corrupted.
	st, e := f.Stat()
	if e != nil || st.Size() > 65536 {
		return entries
	}
	if json.NewDecoder(f).Decode(&entries) != nil {
		return []LogEntry{}
	}
	return entries
}
func recordOperation(action string, ok bool) {
	name, known := operationNames[action]
	if !known {
		return
	}
	entries := readLogs()
	message := "操作成功"
	if !ok {
		message = "操作失败；请结合页面错误提示和诊断检查"
	}
	entries = append(entries, LogEntry{time.Now().Unix(), name, ok, message})
	if len(entries) > 200 {
		entries = entries[len(entries)-200:]
	}
	for len(entries) > 0 {
		b, _ := json.Marshal(entries)
		if len(b) <= 65536 {
			_ = atomicWrite(runtimeDir+"/operations.json", b)
			return
		}
		entries = entries[1:]
	}
}

var diagnosticCommand = func(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(b), e
}
var diagnosticDNS = func() error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	resolver := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:53")
	}}
	_, e := resolver.LookupHost(ctx, "www.google.com")
	return e
}
var diagnosticDNSConfig = "/etc/dnsmasq.conf"

func diagnose() []Diagnostic {
	checks := []Diagnostic{}
	add := func(name, state, detail string) { checks = append(checks, Diagnostic{name, state, detail}) }
	c, e := readServer()
	if e != nil {
		add("服务端配置", "warn", "尚未保存或无法读取配置")
		return checks
	}
	add("设备配置", "pass", "已保存服务端配置；禁用设备保留密钥和地址，不装入运行核心")
	if exists(peerJournal()) {
		add("设备变更事务", "fail", "上次更新未完成，设备配置与运行状态可能不一致；确认可中断后停止并重新启动服务端")
	} else {
		add("设备变更事务", "pass", "没有未完成的设备变更")
	}
	running := false
	if exists(serverStatePath) {
		_, e = peerRPC(serverSocket, "get=1")
		running = e == nil
		if running {
			add("服务端核心", "pass", "控制接口正常响应")
		} else {
			add("服务端核心", "fail", "运行状态存在，但控制接口没有响应；请检查服务端状态")
		}
	} else {
		add("服务端核心", "skip", "服务端已停止；网络检查需启动后执行")
	}
	if !running {
		return checks
	}
	for _, family := range []string{"-4", "-6"} {
		if family == "-6" && c.Settings.Address6 == "" {
			continue
		}
		label := "IPv4"
		fw := "iptables"
		if family == "-6" {
			label = "IPv6"
			fw = "ip6tables"
		}
		rules, re := diagnosticCommand("ip", family, "rule", "show")
		if re == nil && strings.Contains(rules, "iif awgs0 lookup main") {
			add(label+" 策略路由", "pass", "检测到 awgs0 独立出口规则（仍需外部设备验证实际转发）")
		} else {
			add(label+" 策略路由", "fail", "未检测到服务端独立出口规则，请检查启动日志")
		}
		for _, chain := range []struct{ name, hook string }{{"AWGS_I", "INPUT"}, {"AWGS_F", "FORWARD"}} {
			out, ce := diagnosticCommand(fw, "-S", chain.name)
			hooks, he := diagnosticCommand(fw, "-S", chain.hook)
			if ce == nil && he == nil && strings.Contains(out, "-A "+chain.name+" ") && strings.Contains(hooks, "-j "+chain.name) {
				add(label+" "+chain.name, "pass", "规则链和入口挂接存在")
			} else {
				add(label+" "+chain.name, "fail", "规则链或入口缺失；请检查防火墙是否被其他服务刷新")
			}
		}
	}
	dns, e := os.ReadFile(diagnosticDNSConfig)
	if e == nil && hasConfigLine(string(dns), "interface=awgs0") {
		add("DNS 接口登记", "pass", "当前 dnsmasq 配置已登记 awgs0")
	} else {
		add("DNS 接口登记", "warn", "当前 dnsmasq 配置未登记 awgs0；使用路由器 DNS 的远端设备可能解析失败")
	}
	if e = diagnosticDNS(); e == nil {
		add("本机 DNS 解析", "pass", "经 127.0.0.1:53 成功解析 www.google.com；不代表远端设备 UDP/TCP 53 已连通")
	} else {
		add("本机 DNS 解析", "fail", "路由器本机 DNS 查询失败或超时，请检查 DNS 上游")
	}
	if c.Settings.Internet {
		out, ne := diagnosticCommand("iptables", "-t", "nat", "-S", "POSTROUTING")
		route, re := diagnosticCommand("ip", "-4", "route", "show", "default")
		wan := interfaceFromRoute(route)
		prefix, _ := netip.ParsePrefix(c.Settings.Address)
		want := "-A POSTROUTING -s " + prefix.Masked().String() + " -o " + wan + " -j MASQUERADE"
		if ne == nil && re == nil && wan != "" && hasConfigLine(out, want) {
			add("互联网 NAT", "pass", "检测到服务端 IPv4 NAT 规则")
		} else {
			add("互联网 NAT", "warn", "未检测到服务端 NAT，请检查转发和出口设置")
		}
		if c.Settings.Fullv {
			add("fullv 兼容", "warn", "已启用公网 UDP 443 回退设置；fullv 节点与分流效果需在远端浏览器测试")
		} else {
			add("fullv 兼容", "skip", "未启用 TCP 回退；本诊断不判断 Google 网站是否可访问")
		}
	}
	add("检查范围", "warn", "只读检查，不修改网络。请在外网设备再测试 DNS、家庭 LAN、百度和 Google；不包含端口公网可达性验证")
	return checks
}

func interfaceFromRoute(route string) string {
	for _, line := range strings.Split(route, "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "dev" {
				return f[i+1]
			}
		}
	}
	return ""
}
