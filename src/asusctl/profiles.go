package asusctl

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

var profileRoot = Root + "/config/profiles"
var profileIndex = Root + "/config/profiles.json"
var validID = regexp.MustCompile(`^[a-f0-9]{16}$`)

func profiles() []Profile {
	var ps []Profile
	b, e := os.ReadFile(profileIndex)
	if e == nil {
		_ = json.Unmarshal(b, &ps)
	}
	if ps == nil {
		return []Profile{}
	}
	return ps
}
func profilePath(id string) (string, error) {
	if !validID.MatchString(id) {
		return "", errors.New("配置 ID 无效")
	}
	for _, p := range profiles() {
		if p.ID == id {
			return filepath.Join(profileRoot, id+".conf"), nil
		}
	}
	return "", errors.New("配置不存在")
}
func configFor(id string) (*Config, error) {
	p, e := profilePath(id)
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return nil, e
	}
	return Parse(string(b))
}
func importProfile() (Profile, error) {
	var req struct {
		Name   string `json:"name"`
		Config string `json:"config"`
	}
	d := json.NewDecoder(io.LimitReader(requestInput(), 50000))
	d.DisallowUnknownFields()
	if e := d.Decode(&req); e != nil {
		return Profile{}, errors.New("导入请求格式错误")
	}
	ps := profiles()
	if len(ps) >= 8 {
		return Profile{}, errors.New("最多保存 8 个配置，请先删除不用的配置")
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		req.Name = fmt.Sprintf("配置 %d", len(ps)+1)
	}
	if len([]rune(req.Name)) > 60 || strings.ContainsAny(req.Name, "\r\n\x00") {
		return Profile{}, errors.New("配置名称过长或无效")
	}
	for _, p := range ps {
		if p.Name == req.Name {
			return Profile{}, errors.New("配置名称重复")
		}
	}
	b, e := base64.StdEncoding.DecodeString(req.Config)
	if e != nil {
		return Profile{}, errors.New("配置 Base64 无效")
	}
	if _, e = Parse(string(b)); e != nil {
		return Profile{}, e
	}
	var bytes [8]byte
	if _, e = rand.Read(bytes[:]); e != nil {
		return Profile{}, e
	}
	p := Profile{hex.EncodeToString(bytes[:]), req.Name}
	if e = atomicWrite(filepath.Join(profileRoot, p.ID+".conf"), b); e != nil {
		return Profile{}, e
	}
	ps = append(ps, p)
	if e = writeJSON(profileIndex, ps); e != nil {
		return Profile{}, e
	}
	s := readSettings()
	if s.Profile == "" {
		s.Profile = p.ID
		if e = writeJSON(settingsPath, s); e != nil {
			return Profile{}, e
		}
	}
	return p, nil
}
func payloadID() (string, error) {
	var req struct {
		Profile string `json:"profile"`
	}
	d := json.NewDecoder(io.LimitReader(requestInput(), 4096))
	d.DisallowUnknownFields()
	if e := d.Decode(&req); e != nil {
		return "", errors.New("节点请求格式错误")
	}
	if _, e := profilePath(req.Profile); e != nil {
		return "", e
	}
	return req.Profile, nil
}
func deleteProfile(id string) error {
	s := readSettings()
	if id == s.Profile {
		return errors.New("当前节点不能删除，请先切换到其他节点")
	}
	for _, f := range s.Fallbacks {
		if f == id {
			return errors.New("请先将该节点移出故障切换列表")
		}
	}
	path, e := profilePath(id)
	if e != nil {
		return e
	}
	ps := profiles()
	next := []Profile{}
	for _, p := range ps {
		if p.ID != id {
			next = append(next, p)
		}
	}
	if e = writeJSON(profileIndex, next); e != nil {
		return e
	}
	return os.Remove(path)
}
func switchProfile(id string, start bool) error {
	s := readSettings()
	if _, e := configFor(id); e != nil {
		return e
	}
	if exists(statePath) {
		if e := down(); e != nil {
			return e
		}
	}
	old := s.Profile
	s.Profile = id
	if s.Failover {
		next := []string{}
		seen := map[string]bool{id: true}
		for _, candidate := range append(s.Fallbacks, old) {
			if candidate != "" && !seen[candidate] {
				next = append(next, candidate)
				seen[candidate] = true
			}
		}
		s.Fallbacks = next
	}
	if e := writeJSON(settingsPath, s); e != nil {
		return e
	}
	if start {
		return up()
	}
	return nil
}

var healthPath = "/tmp/amneziawg-asus/health.json"
var switchCandidate = func(id string) error { return switchProfile(id, true) }
var waitAfterSwitch = func() { time.Sleep(time.Second) }

type Health struct {
	Failures   int    `json:"failures"`
	LastCheck  int64  `json:"last_check"`
	LastSwitch int64  `json:"last_switch"`
	Message    string `json:"message"`
}

func health() Health {
	var h Health
	b, e := os.ReadFile(healthPath)
	if e == nil {
		_ = json.Unmarshal(b, &h)
	}
	return h
}
func healthTargets(s Settings) []string {
	if len(s.HealthTargets) == 0 {
		return []string{"1.1.1.1", "9.9.9.9"}
	}
	return s.HealthTargets
}
func validateMonitor(c *Config, s Settings) error {
	if !s.Failover {
		return nil
	}
	for _, target := range healthTargets(s) {
		ip, e := netip.ParseAddr(target)
		if e != nil || !ip.IsGlobalUnicast() {
			return errors.New("探测目标必须是单播 IP 地址")
		}
		if !configAllows(c, ip) {
			return errors.New("自动切换探测地址必须在配置 AllowedIPs 内")
		}
	}
	return nil
}
func watch() error {
	s := readSettings()
	if !s.Failover || (!exists(statePath) && !exists(guardPath)) {
		return nil
	}
	h := health()
	now := time.Now().Unix()
	if now-h.LastCheck < 45 {
		return nil
	}
	h.LastCheck = now
	status := readStatus()
	healthy := false
	if status.Running {
		for _, target := range healthTargets(s) {
			ip, _ := netip.ParseAddr(target)
			program := "ping"
			if ip.Is6() {
				program = "ping6"
			}
			if _, e := runCommand(program, "-I", "awg0", "-c", "1", "-W", "3", target); e == nil {
				healthy = true
				break
			}
		}
	}
	if healthy {
		h.Failures = 0
		h.Message = "隧道探测正常"
		return writeJSON(healthPath, h)
	}
	h.Failures++
	h.Message = fmt.Sprintf("连续探测失败 %d 次", h.Failures)
	if h.Failures < 3 || now-h.LastSwitch < 180 {
		return writeJSON(healthPath, h)
	}
	h.LastSwitch = now
	// Each candidate uses the same source policy; persistent protection remains installed.
	candidates := append([]string{s.Profile}, s.Fallbacks...)
	seen := map[string]bool{}
	ordered := []string{}
	for _, id := range candidates {
		if id != "" && !seen[id] {
			seen[id] = true
			ordered = append(ordered, id)
		}
	}
	if len(ordered) > 1 {
		ordered = append(ordered[1:], ordered[0])
	}
	for _, id := range ordered {
		if e := switchCandidate(id); e != nil {
			continue
		}
		waitAfterSwitch()
		for _, target := range healthTargets(s) {
			ip, _ := netip.ParseAddr(target)
			program := "ping"
			if ip.Is6() {
				program = "ping6"
			}
			if _, e := runCommand(program, "-I", "awg0", "-c", "1", "-W", "3", target); e == nil {
				h.Failures = 0
				h.Message = "已切换到可用节点"
				return writeJSON(healthPath, h)
			}
		}
	}
	// Keep the final candidate up for recovery. Guard persists even when no candidate starts.
	h.Message = "全部节点探测失败；断线保护按当前设置保留"
	return writeJSON(healthPath, h)
}
