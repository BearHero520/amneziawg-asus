package asusctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type ServerIntent struct {
	Wanted    bool   `json:"wanted"`
	Suspended bool   `json:"suspended,omitempty"`
	Boot      string `json:"boot"`
}
type ServerRecovery struct {
	Failures int    `json:"failures"`
	Next     int64  `json:"next"`
	Phase    string `json:"phase"`
	Error    string `json:"error,omitempty"`
}

func serverIntentPath() string {
	return filepath.Join(filepath.Dir(serverConfigPath), "server-intent.json")
}
func serverRetryPath() string { return runtimeDir + "/server-retry.json" }
func serverEventPath() string { return runtimeDir + "/server-recovery-request" }

var serverNow = func() int64 { return time.Now().Unix() }
var supervisedUp = serverUp
var supervisedDown = serverDown
var supervisedHealthy = func() bool {
	if !exists(serverStatePath) {
		return false
	}
	_, e := rpc(serverSocket, "get=1")
	return e == nil
}

func serverIntent() (ServerIntent, error) {
	var i ServerIntent
	b, e := os.ReadFile(serverIntentPath())
	if e == nil {
		if e = json.Unmarshal(b, &i); e != nil {
			return i, errors.New("服务端运行意图文件损坏，拒绝自动启动")
		}
		if i.Boot == bootID() {
			return i, nil
		}
	} else if !os.IsNotExist(e) {
		return i, e
	}
	c, e := readServer()
	if e != nil {
		return i, e
	}
	i = ServerIntent{Wanted: c.Settings.Auto || exists(serverStatePath), Boot: bootID()}
	// A real reboot applies Auto; a same-boot manual stop survives WAN/NAT hooks.
	if e = writeJSON(serverIntentPath(), i); e != nil {
		return i, e
	}
	return i, nil
}
func setServerIntent(wanted bool) error {
	return writeJSON(serverIntentPath(), ServerIntent{Wanted: wanted, Boot: bootID()})
}
func serverRetry() ServerRecovery {
	var r ServerRecovery
	_ = loadJSONFile(serverRetryPath(), &r)
	return r
}
func queueServerRecovery() error {
	return atomicWrite(serverEventPath(), []byte(fmt.Sprintf("%d", time.Now().UnixNano())))
}
func consumeServerEvent(token string) {
	if token != "" {
		_ = atomicWrite(serverEventPath()+"-ack", []byte(token))
	}
}
func pendingServerEvent() string {
	b, _ := os.ReadFile(serverEventPath())
	ack, _ := os.ReadFile(serverEventPath() + "-ack")
	if string(b) == string(ack) {
		return ""
	}
	return string(b)
}

var logKey = regexp.MustCompile(`[A-Za-z0-9+/]{43}=|\b[0-9a-fA-F]{64}\b`)
var logCredential = regexp.MustCompile(`(?i)(private_?key|preshared_?key|password|authorization|token)\s*[:=]\s*[^\r\n]+`)

func safeFailure(s string) string {
	s = logCredential.ReplaceAllString(s, "[敏感字段已隐藏]")
	s = logKey.ReplaceAllString(s, "[密钥已隐藏]")
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) > 500 {
		s = string(r[:500]) + "…"
	}
	return s
}
func recoveryDelay(n int) int64 {
	if n < 1 {
		n = 1
	}
	if n > 4 {
		n = 4
	}
	d := int64(60) << (n - 1)
	if d > 300 {
		d = 300
	}
	return d
}
func serverFailed(r ServerRecovery, phase string, e error) error {
	r.Failures++
	r.Next = serverNow() + recoveryDelay(r.Failures)
	r.Phase = phase
	r.Error = safeFailure(e.Error())
	if we := writeJSON(serverRetryPath(), r); we != nil {
		return fmt.Errorf("记录恢复状态失败: %w", we)
	}
	appendOperation("服务端自动恢复", false, fmt.Sprintf("阶段=%s；第 %d 次失败；%d 秒后重试；原因=%s", phase, r.Failures, recoveryDelay(r.Failures), r.Error))
	return fmt.Errorf("服务端%s失败；已安排重试: %s", phase, r.Error)
}

// Called under the shared mutation lock. No sleeping under the lock: cron drives
// retries. A hook first queues its event, so a lock collision cannot lose it.
func superviseServer(force bool) error {
	i, e := serverIntent()
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	token := pendingServerEvent()
	if !i.Wanted || i.Suspended {
		consumeServerEvent(token)
		_ = os.Remove(serverRetryPath())
		return nil
	}
	r := serverRetry()
	if !force && r.Next > serverNow() {
		return nil
	}
	// Do not destroy a pending peer transaction to repair an unrelated fault.
	if exists(peerJournal()) {
		return serverFailed(r, "设备事务待处理", errors.New("请先检查设备变更事务，保活未修改设备或密钥"))
	}
	if token == "" && r.Failures == 0 && supervisedHealthy() {
		return nil
	}
	reason := "核心未响应"
	if token != "" {
		reason = "WAN/NAT 重载"
	}
	if r.Failures > 0 {
		reason = "失败重试"
	}
	appendOperation("服务端自动恢复", true, "开始恢复；触发="+reason)
	if e = supervisedDown(); e != nil {
		return serverFailed(r, "清理旧接口/规则", e)
	}
	if e = supervisedUp(); e != nil {
		return serverFailed(r, "启动/配置核心与网络", e)
	}
	if !supervisedHealthy() {
		return serverFailed(r, "启动后检查", errors.New("核心控制接口未响应"))
	}
	consumeServerEvent(token)
	_ = os.Remove(serverRetryPath())
	appendOperation("服务端自动恢复", true, "恢复成功；核心控制接口正常；此前失败次数="+fmt.Sprint(r.Failures))
	return nil
}
func manualServerStart() error {
	if e := setServerIntent(true); e != nil {
		return e
	}
	_ = os.Remove(serverRetryPath())
	return superviseServer(true)
}
func manualServerStop() error {
	// Persist STOP before cleanup: even if cleanup fails, watch must not restart.
	if e := setServerIntent(false); e != nil {
		return e
	}
	_ = os.Remove(serverRetryPath())
	_ = os.Remove(serverEventPath())
	return supervisedDown()
}
func serverRecoveryNote() string {
	var i ServerIntent
	if loadJSONFile(serverIntentPath(), &i) == nil && i.Boot == bootID() && !i.Wanted {
		return "已手动停止：保活和 WAN/NAT 恢复不会自动拉起；重启路由器后按开机自启设置处理"
	}
	r := serverRetry()
	if r.Failures > 0 {
		return fmt.Sprintf("自动恢复待重试：%s；连续失败 %d 次；下次 %s；%s", r.Phase, r.Failures, time.Unix(r.Next, 0).Format("15:04:05"), r.Error)
	}
	return ""
}

// Firmware service restarts are distinct from a user pressing Stop.
func suspendServer() error {
	i, e := serverIntent()
	if os.IsNotExist(e) {
		return supervisedDown()
	}
	if e != nil {
		return e
	}
	i.Suspended = true
	if e = writeJSON(serverIntentPath(), i); e != nil {
		return e
	}
	return supervisedDown()
}
func bootServer() error {
	i, e := serverIntent()
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if i.Suspended {
		i.Suspended = false
		if e = writeJSON(serverIntentPath(), i); e != nil {
			return e
		}
	}
	return superviseServer(false)
}
