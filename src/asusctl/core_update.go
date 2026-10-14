// SPDX-License-Identifier: MIT
package asusctl

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const pluginVersion = "0.5.1"
const coreABI = 1
const coreSeries = "0.5"
const coreFeed = "https://raw.githubusercontent.com/BearHero520/amneziawg-asus/main/updates/preview.json"
const coreReleaseBase = "https://github.com/BearHero520/amneziawg-asus/releases/download/v"

var coreVersion = pluginVersion // release builds may override with -X
var coreBinary = "/koolshare/bin/amneziawg-go"
var updateRoot = Root

type CoreAsset struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type CoreManifest struct {
	Version string               `json:"version"`
	Series  string               `json:"series"`
	ABI     int                  `json:"abi"`
	Assets  map[string]CoreAsset `json:"assets"`
	Checked int64                `json:"checked,omitempty"`
}
type CoreInfo struct {
	Version string `json:"version"`
	Arch    string `json:"arch"`
	ABI     int    `json:"abi"`
	Series  string `json:"series"`
}
type CoreBackup struct {
	Info   CoreInfo `json:"info"`
	SHA256 string   `json:"sha256"`
}
type CoreJob struct {
	Phase    string       `json:"phase"`
	Message  string       `json:"message"`
	Time     int64        `json:"time"`
	Token    string       `json:"token,omitempty"`
	Boot     string       `json:"boot,omitempty"`
	Rollback bool         `json:"rollback,omitempty"`
	Client   bool         `json:"client"`
	Server   bool         `json:"server"`
	Offer    CoreManifest `json:"offer"`
}
type CoreStatus struct {
	CoreInfo
	Plugin    string `json:"plugin"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
	Checked   int64  `json:"checked"`
	Backup    string `json:"backup"`
	Busy      bool   `json:"busy"`
	Phase     string `json:"phase"`
	Message   string `json:"message"`
	Time      int64  `json:"time"`
}

var coreArch = func() string {
	if runtime.GOARCH == "arm" {
		return "armv7"
	}
	return runtime.GOARCH
}

func coreInfo() CoreInfo            { return CoreInfo{coreVersion, coreArch(), coreABI, coreSeries} }
func updateFile(name string) string { return filepath.Join(updateRoot, name) }
func loadJSONFile(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if len(b) > 262144 {
		return errors.New("元数据过大")
	}
	return json.Unmarshal(b, v)
}
func loadJob() CoreJob {
	var j CoreJob
	_ = loadJSONFile(updateFile("update-state.json"), &j)
	return j
}
func updateBusy() bool { return exists(updateFile("update-busy")) }
func saveJob(j *CoreJob, phase, message string) error {
	j.Phase = phase
	j.Message = message
	j.Time = time.Now().Unix()
	return writeJSON(updateFile("update-state.json"), j)
}
func coreStatus() CoreStatus {
	j := loadJob()
	s := CoreStatus{CoreInfo: coreInfo(), Plugin: pluginVersion, Busy: updateBusy(), Phase: j.Phase, Message: j.Message, Time: j.Time}
	if b, e := os.ReadFile(updateFile("plugin-version")); e == nil {
		v := strings.TrimSpace(string(b))
		if _, e = versionParts(v); e == nil {
			s.Plugin = v
		}
	}
	var m CoreManifest
	if loadJSONFile(updateFile("update-offer.json"), &m) == nil && validateManifest(m, coreArch()) == nil {
		s.Latest = m.Version
		s.Checked = m.Checked
		s.Available = newerCore(m.Version, coreVersion) && time.Now().Unix()-m.Checked < 3600 && m.Checked <= time.Now().Unix()
	}
	var b CoreBackup
	if loadJSONFile(updateFile("core-backup.json"), &b) == nil && exists(coreBinary+".previous") {
		s.Backup = b.Info.Version
	}
	return s
}

var coreVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func versionParts(v string) ([3]int, error) {
	var p [3]int
	if !coreVersionPattern.MatchString(v) {
		return p, errors.New("版本号无效")
	}
	for i, s := range strings.Split(v, ".") {
		n, e := strconv.Atoi(s)
		if e != nil {
			return p, e
		}
		p[i] = n
	}
	return p, nil
}
func newerCore(a, b string) bool {
	x, e := versionParts(a)
	y, f := versionParts(b)
	if e != nil || f != nil {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return x[i] > y[i]
		}
	}
	return false
}
func validateManifest(m CoreManifest, arch string) error {
	if _, e := versionParts(m.Version); e != nil {
		return e
	}
	if m.Series != coreSeries || m.ABI != coreABI {
		return errors.New("新版需要升级完整插件，请从 GitHub 下载离线安装包")
	}
	if arch != "arm64" && arch != "armv7" {
		return errors.New("不支持的核心架构")
	}
	a, ok := m.Assets[arch]
	if !ok {
		return errors.New("发布版本缺少当前架构")
	}
	if a.URL != coreReleaseBase+m.Version+"/amneziawg-core_"+m.Version+"_"+arch {
		return errors.New("核心下载地址不属于本项目发布资源")
	}
	hash, e := hex.DecodeString(a.SHA256)
	if e != nil || len(hash) != 32 || a.SHA256 != strings.ToLower(a.SHA256) {
		return errors.New("SHA256 校验信息无效")
	}
	if a.Size < 1024 || a.Size > 32<<20 {
		return errors.New("核心大小超出限制")
	}
	return nil
}
func trustedCoreURL(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	switch u.Hostname() {
	case "raw.githubusercontent.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
		return true
	}
	return false
}

var coreHTTP = &http.Client{Timeout: 120 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
	if len(via) >= 5 || !trustedCoreURL(r.URL.String()) {
		return errors.New("拒绝不可信下载跳转")
	}
	return nil
}}

func fetchCore(ctx context.Context, address string, limit int64) ([]byte, error) {
	if !trustedCoreURL(address) {
		return nil, errors.New("拒绝不可信下载地址")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("User-Agent", "AmneziaWG-ASUS/"+pluginVersion)
	resp, e := coreHTTP.Do(req)
	if e != nil {
		return nil, errors.New("连接 GitHub 失败，请检查路由器网络、时间及 CA 证书")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub 返回 HTTP %d", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if e != nil {
		return nil, errors.New("下载中断")
	}
	if int64(len(b)) > limit {
		return nil, errors.New("下载内容超出大小限制")
	}
	return b, nil
}
func checkCore() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	b, e := fetchCore(ctx, coreFeed, 262144)
	if e != nil {
		return e
	}
	var m CoreManifest
	if json.Unmarshal(b, &m) != nil {
		return errors.New("更新清单格式错误")
	}
	if e = validateManifest(m, coreArch()); e != nil {
		return e
	}
	m.Checked = time.Now().Unix()
	return writeJSON(updateFile("update-offer.json"), m)
}
func verifyCoreBytes(b []byte, a CoreAsset, arch string) error {
	if int64(len(b)) != a.Size {
		return errors.New("下载大小不匹配")
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != a.SHA256 {
		return errors.New("SHA256 校验失败")
	}
	// Validate before executing any downloaded bytes.
	if len(b) < 20 || string(b[:4]) != "\x7fELF" || b[5] != 1 {
		return errors.New("核心不是有效的小端 ELF")
	}
	machine := uint16(b[18]) | uint16(b[19])<<8
	if (arch == "arm64" && (b[4] != byte(elf.ELFCLASS64) || machine != uint16(elf.EM_AARCH64))) || (arch == "armv7" && (b[4] != byte(elf.ELFCLASS32) || machine != uint16(elf.EM_ARM))) || (arch != "arm64" && arch != "armv7") {
		return errors.New("核心架构不匹配")
	}
	return nil
}
func writeExecutable(path string, b []byte) error {
	if e := atomicWrite(path, b); e != nil {
		return e
	}
	return os.Chmod(path, 0755)
}

var probeCore = func(path string) (CoreInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, path, "ctl", "core-info").Output()
	if e != nil {
		return CoreInfo{}, errors.New("候选核心无法运行")
	}
	var r Result
	if json.Unmarshal(b, &r) != nil || !r.OK || r.Core == nil {
		return CoreInfo{}, errors.New("候选核心没有兼容管理接口")
	}
	return r.Core.CoreInfo, nil
}

func verifyCoreInfo(i CoreInfo, version, arch string) error {
	if i.Version != version || i.Arch != arch || i.ABI != coreABI || i.Series != coreSeries {
		return errors.New("候选核心版本或管理接口不匹配")
	}
	return nil
}

var bootID = func() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}

func queueCore(rollback bool) error {
	var wanted struct {
		Version string `json:"version"`
	}
	if json.NewDecoder(io.LimitReader(requestInput(), 1024)).Decode(&wanted) != nil || wanted.Version == "" {
		return errors.New("请在页面确认要切换的核心版本")
	}
	if updateBusy() {
		return errors.New("核心操作正在进行或需要恢复，请查看更新状态")
	}
	j := CoreJob{Rollback: rollback, Boot: bootID()}
	s := readStatus()
	sv := serverStatus()
	j.Client = s.Running
	j.Server = sv.Running
	if sv.Pending || exists(peerJournal()) || (exists(statePath) && !s.Running) || (exists(serverStatePath) && !sv.Running) {
		return errors.New("现有服务状态异常，请先在日志与诊断中处理")
	}
	if rollback {
		var b CoreBackup
		if loadJSONFile(updateFile("core-backup.json"), &b) != nil || !exists(coreBinary+".previous") {
			return errors.New("没有可回滚的核心")
		}
		if wanted.Version != b.Info.Version {
			return errors.New("备份版本已改变，请刷新并重新确认")
		}
		if b.Info.Version == coreVersion {
			return errors.New("备份与当前核心版本相同")
		}
	} else {
		if loadJSONFile(updateFile("update-offer.json"), &j.Offer) != nil {
			return errors.New("请先检查更新")
		}
		if e := validateManifest(j.Offer, coreArch()); e != nil {
			return e
		}
		age := time.Now().Unix() - j.Offer.Checked
		if age < 0 || age > 3600 {
			return errors.New("更新信息已过期，请重新检查")
		}
		if wanted.Version != j.Offer.Version {
			return errors.New("更新版本已改变，请刷新并重新确认")
		}
		if !newerCore(j.Offer.Version, coreVersion) {
			return errors.New("当前没有可升级的新核心")
		}
	}
	token := make([]byte, 24)
	if _, e := rand.Read(token); e != nil {
		return e
	}
	j.Token = hex.EncodeToString(token)
	if e := saveJob(&j, "queued", "已排队，准备校验核心；配置与密钥保持不变"); e != nil {
		return e
	}
	if e := atomicWrite(updateFile("update-busy"), []byte(j.Token)); e != nil {
		return e
	}
	null, e := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if e != nil {
		_ = os.Remove(updateFile("update-busy"))
		return e
	}
	defer null.Close()
	cmd := exec.Command(coreBinary, "ctl", "core-worker")
	cmd.Env = append(os.Environ(), "AWG_UPDATE_TOKEN="+j.Token)
	detachCoreWorker(cmd)
	cmd.Stdin = null
	cmd.Stdout = null
	cmd.Stderr = null
	if e = cmd.Start(); e != nil {
		_ = os.Remove(updateFile("update-busy"))
		_ = saveJob(&j, "failed", "无法启动升级进程，现有服务未改变")
		return e
	}
	return cmd.Process.Release()
}
func coreAuthorized(j CoreJob) bool {
	return j.Token != "" && os.Getenv("AWG_UPDATE_TOKEN") == j.Token && updateBusy()
}

// Internal children run under the worker's lock. They always execute the binary at
// the active pathname, not the old worker's /proc/self/exe after atomic replacement.
var coreChild = func(action string, j CoreJob) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, coreBinary, "ctl", action)
	cmd.Env = append(os.Environ(), "AWG_UPDATE_TOKEN="+j.Token)
	if e := cmd.Run(); e != nil {
		return errors.New("核心服务恢复或清理失败")
	}
	return nil
}

func coreResume(j CoreJob) error {
	if j.Client {
		if e := up(); e != nil {
			return e
		}
		if !readStatus().Running {
			return errors.New("客户端核心未就绪")
		}
	}
	if j.Server {
		if e := serverUp(); e != nil {
			return e
		}
		if !serverStatus().Running {
			return errors.New("服务端核心未就绪")
		}
	}
	return nil
}
func coreStop(j CoreJob) error {
	if j.Client {
		if e := down(); e != nil {
			return e
		}
	}
	if j.Server {
		if e := serverDown(); e != nil {
			return e
		}
	}
	return nil
}

var coreSpace = func(need int64) error {
	out, e := runCommand("df", "-k", filepath.Dir(coreBinary))
	if e != nil {
		return errors.New("无法检查 JFFS 可用空间")
	}
	lines := strings.Split(out, "\n")
	f := strings.Fields(lines[len(lines)-1])
	if len(f) < 4 {
		return errors.New("无法读取 JFFS 可用空间")
	}
	n, e := strconv.ParseInt(f[3], 10, 64)
	if e != nil || n*1024 < need+(2<<20) {
		return errors.New("JFFS 空间不足，需要暂存新核心并保留 2 MB 余量")
	}
	return nil
}

// coreTransaction is deliberately injectable: tests exercise every destructive
// boundary and rollback failure without touching a router's network.
type coreOps struct {
	Stop     func(CoreJob) error
	Resume   func(CoreJob) error
	Activate func() error
	Restore  func() error
	Phase    func(string, string) error
}

func coreTransaction(j CoreJob, o coreOps) (string, error) {
	if e := o.Phase("stopping", "校验完成，正在停止原先运行的服务"); e != nil {
		return "failed", e
	}
	if e := o.Stop(j); e != nil {
		return "recovery_required", errors.New("停止服务失败，未替换核心；需检查服务状态")
	}
	cause := o.Phase("activating", "正在切换核心")
	if cause == nil {
		cause = o.Activate()
	}
	if cause == nil {
		cause = o.Phase("restarting", "正在恢复原先运行的服务")
	}
	if cause == nil {
		cause = o.Resume(j)
	}
	if cause == nil {
		return "success", nil
	}
	_ = o.Phase("rolling_back", "新核心未能恢复服务，正在回滚")
	if e := o.Stop(j); e != nil {
		return "recovery_required", errors.New("升级失败且服务清理失败；保留备份，请重启路由器恢复旧核心")
	}
	if e := o.Restore(); e != nil {
		return "recovery_required", errors.New("升级失败且旧核心恢复失败；保留备份，请检查存储")
	}
	if e := o.Resume(j); e != nil {
		return "recovery_required", errors.New("旧核心已恢复，但服务启动失败；请检查诊断")
	}
	return "rolled_back", errors.New("升级未成功，已回滚旧核心并恢复原先运行的服务")
}
func runCoreWorker() error {
	j := loadJob()
	if !coreAuthorized(j) || j.Phase != "queued" {
		return errors.New("无效的更新任务")
	}
	var release func()
	var e error
	for n := 0; n < 50; n++ {
		release, e = lock()
		if e == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if e != nil {
		_ = saveJob(&j, "failed", "未能获得操作锁，现有核心未改变")
		_ = os.Remove(updateFile("update-busy"))
		return e
	}
	defer release()
	e = prepareAndUpdate(&j)
	action := "core-upgrade"
	if j.Rollback {
		action = "core-rollback"
	}
	recordOperation(action, e == nil)
	return e
}
func prepareAndUpdate(j *CoreJob) (err error) {
	finished := false
	stage := coreBinary + ".candidate"
	defer os.Remove(stage)
	// Before the pending marker exists, failures cannot have touched services.
	defer func() {
		if err != nil && !finished && !exists(updateFile("update-pending")) {
			_ = saveJob(j, "failed", err.Error())
			_ = os.Remove(updateFile("update-busy"))
		}
	}()
	if e := saveJob(j, "downloading", "正在获取并校验核心，当前服务继续运行"); e != nil {
		return e
	}
	var b []byte
	var target string
	if j.Rollback {
		var meta CoreBackup
		if e := loadJSONFile(updateFile("core-backup.json"), &meta); e != nil {
			return e
		}
		var e error
		b, e = os.ReadFile(coreBinary + ".previous")
		if e != nil {
			return e
		}
		target = meta.Info.Version
		if e = verifyCoreBytes(b, CoreAsset{SHA256: meta.SHA256, Size: int64(len(b))}, coreArch()); e != nil {
			return e
		}
	} else {
		if e := validateManifest(j.Offer, coreArch()); e != nil {
			return e
		}
		a := j.Offer.Assets[coreArch()]
		if e := coreSpace(a.Size); e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		var e error
		b, e = fetchCore(ctx, a.URL, a.Size)
		if e != nil {
			return e
		}
		if e = verifyCoreBytes(b, a, coreArch()); e != nil {
			return e
		}
		target = j.Offer.Version
	}
	old, e := os.ReadFile(coreBinary)
	if e != nil {
		return e
	}
	if e = coreSpace(int64(len(b))); e != nil {
		return e
	}
	if e = writeExecutable(stage, b); e != nil {
		return e
	}
	info, e := probeCore(stage)
	if e != nil {
		return e
	}
	if e = verifyCoreInfo(info, target, coreArch()); e != nil {
		return e
	}
	hash := sha256.Sum256(old)
	meta := CoreBackup{Info: coreInfo(), SHA256: hex.EncodeToString(hash[:])}
	if e = linkExecutable(coreBinary, coreBinary+".previous"); e != nil {
		return e
	}
	if e = writeJSON(updateFile("core-backup.json"), meta); e != nil {
		return e
	}
	if e = atomicWrite(updateFile("update-pending"), []byte(j.Token)); e != nil {
		return e
	}
	phase, txerr := coreTransaction(*j, coreOps{Stop: func(j CoreJob) error { return coreChild("core-stop", j) }, Resume: func(j CoreJob) error { return coreChild("core-resume", j) }, Activate: func() error { return os.Rename(stage, coreBinary) }, Restore: restoreCoreBackup, Phase: func(p, m string) error { return saveJob(j, p, m) }})
	message := "核心已更新，原先运行的服务已恢复"
	if j.Rollback {
		message = "核心已回滚，原先运行的服务已恢复"
	}
	if txerr != nil {
		message = txerr.Error()
	}
	if e = saveJob(j, phase, message); e != nil {
		return e
	}
	if phase != "recovery_required" {
		_ = os.Remove(updateFile("update-pending"))
		_ = os.Remove(updateFile("update-busy"))
	}
	// Do not let the pre-change failure defer overwrite an accurate rollback result.
	finished = true
	if txerr != nil {
		recordOperation("core-rollback", phase == "rolled_back")
	}
	return txerr
}

// Retain the verified old inode without a second full copy on JFFS.
func linkExecutable(source, target string) error {
	temp := target + ".link"
	_ = os.Remove(temp)
	defer os.Remove(temp)
	if e := os.Link(source, temp); e != nil {
		return errors.New("当前存储不支持安全核心备份，取消升级")
	}
	return os.Rename(temp, target)
}
func restoreCoreBackup() error {
	var meta CoreBackup
	if e := loadJSONFile(updateFile("core-backup.json"), &meta); e != nil {
		return e
	}
	b, e := os.ReadFile(coreBinary + ".previous")
	if e != nil {
		return e
	}
	if e = verifyCoreBytes(b, CoreAsset{SHA256: meta.SHA256, Size: int64(len(b))}, coreArch()); e != nil {
		return e
	}
	if e = verifyCoreInfo(meta.Info, meta.Info.Version, coreArch()); e != nil {
		return e
	}
	tmp := coreBinary + ".restore"
	_ = os.Remove(tmp)
	defer os.Remove(tmp)
	if e = os.Link(coreBinary+".previous", tmp); e != nil {
		return e
	}
	return os.Rename(tmp, coreBinary)
}

// Boot-only recovery. Never tear down an in-flight task when a NAT hook runs.
func recoverCoreBoot() error {
	if !updateBusy() && !exists(updateFile("update-pending")) {
		return nil
	}
	j := loadJob()
	id := bootID()
	if id == "" || j.Boot == id {
		return errors.New("本次开机中的更新任务尚未结束，拒绝并发恢复")
	}
	if exists(updateFile("update-pending")) {
		if e := restoreCoreBackup(); e != nil {
			return e
		}
	}
	if e := saveJob(&j, "rolled_back", "上次更新被中断，已恢复旧核心；服务按开机启动设置恢复"); e != nil {
		return e
	}
	_ = os.Remove(updateFile("update-pending"))
	return os.Remove(updateFile("update-busy"))
}
func executeCore(action string) (Result, error) {
	var e error
	message := "核心状态已刷新"
	switch action {
	case "core-status", "core-info":
	case "core-check":
		e = checkCore()
		message = "检查完成"
	case "core-upgrade":
		e = queueCore(false)
		message = "升级任务已提交，可在此页查看进度"
	case "core-rollback":
		e = queueCore(true)
		message = "回滚任务已提交"
	default:
		e = errors.New("未知核心操作")
	}
	s := coreStatus()
	return Result{OK: e == nil, Message: message, Core: &s}, e
}
