// SPDX-License-Identifier: MIT
package asusctl

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

type policyListStatus struct {
	Time    int64  `json:"time"`
	Running bool   `json:"running"`
	Message string `json:"message"`
}

func readPolicyLists() policyListStatus {
	var status policyListStatus
	_ = loadJSONFile(routingFile("list-status.json"), &status)
	if status.Running && time.Now().Unix()-status.Time > 660 {
		status.Running = false
		status.Message = "上次更新已超时"
	}
	return status
}

func queuePolicyLists(force bool) error {
	if !activePolicy() || !readSettings().Routing.needsLists() {
		if force {
			return errors.New("请启动按规则分流，并配置 GeoIP、GeoSite、Antifilter 或订阅地址")
		}
		return nil
	}
	status := readPolicyLists()
	if status.Running {
		if force {
			return errors.New("规则列表正在更新")
		}
		return nil
	}
	now := time.Now()
	if !force && !exists(routingFile("refresh-next")) {
		r := readSettings().Routing
		elapsed := now.Sub(time.Unix(status.Time, 0))
		if status.Time != 0 && (!r.AutoUpdate || elapsed < 24*time.Hour) {
			return nil
		}
	}
	file := routingFile("list-status.json")
	if err := writeJSON(file, policyListStatus{now.Unix(), true, "规则列表正在更新"}); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err == nil {
		worker := exec.Command(exe, "ctl", "policy-list-worker")
		detachCoreWorker(worker)
		if err = worker.Start(); err == nil {
			_ = worker.Process.Release()
			_ = os.Remove(routingFile("refresh-next"))
		}
	}
	if err != nil {
		_ = writeJSON(file, policyListStatus{now.Unix(), false, "未能启动规则列表更新"})
	}
	return err
}

func policyListWorker() (err error) {
	status := policyListStatus{time.Now().Unix(), false, "规则列表已更新"}
	defer func() {
		if err != nil {
			status.Message = err.Error()
		}
		_ = writeJSON(routingFile("list-status.json"), status)
	}()
	input, err := os.ReadFile(routingFile("settings"))
	if err != nil {
		return err
	}
	if err = atomicWrite(routingFile("fetch-settings"), input); err != nil {
		return err
	}
	defer os.Remove(routingFile("fetch-settings"))
	fetchErr := policyRun("fetch")
	// Downloads are independent of active routes. Rebuild only while the
	// configuration that requested the update is still running.
	for i := 0; i < 30; i++ {
		unlock, lockErr := lock()
		if lockErr != nil {
			time.Sleep(time.Second)
			continue
		}
		defer unlock()
		current, readErr := os.ReadFile(routingFile("settings"))
		if readErr != nil || updateBusy() || !activePolicy() || !slices.Equal(input, current) {
			return errors.New("分流设置已变更，更新将在下次启动时应用")
		}
		if err = policyRun("prepare"); err != nil {
			return err
		}
		if err = policyRun("dns-refresh"); err != nil {
			return err
		}
		return fetchErr
	}
	return errors.New("配置正在变更，请稍后重试规则更新")
}

func readTrafficAnalysis() json.RawMessage {
	b, err := os.ReadFile(routingFile("awg_analyze.htm"))
	if err != nil || len(b) > 60*1024 || !json.Valid(b) {
		return json.RawMessage(`{"active":false,"entries":[]}`)
	}
	return b
}

func analysisPolicy(r RoutingSettings, addr netip.Addr, mac string) string {
	for _, device := range r.Devices {
		ip, hw, _ := routingSource(device.Source)
		if ip == addr.String() || mac != "" && hw == mac {
			return device.Policy
		}
	}
	return r.defaultPolicy()
}

func startTrafficAnalysis() error {
	var p struct {
		Device string `json:"device"`
	}
	if err := readServerPayload(&p); err != nil {
		return err
	}
	if !activePolicy() {
		return errors.New("请先启动按设备和规则分流")
	}
	a, err := netip.ParseAddr(strings.TrimSpace(p.Device))
	if err != nil || !a.Is4() {
		return errors.New("请输入设备的 IPv4 地址")
	}
	lan, err := defaultLAN()
	if err != nil {
		return err
	}
	r := readSettings().Routing
	var ref string
	if lan.Contains(a) {
		mac := ""
		if out, e := runCommand("ip", "-4", "neigh", "show", "to", a.String()); e == nil {
			fields := strings.Fields(out)
			for i := 0; i+1 < len(fields); i++ {
				if fields[i] == "lladdr" {
					_, mac, _ = routingSource(fields[i+1])
					break
				}
			}
		}
		ref = analysisPolicy(r, a, mac)
	} else if c, err := readServer(); err == nil {
		for _, device := range c.Clients {
			prefix, e := netip.ParsePrefix(device.Address)
			if e == nil && prefix.Addr() == a && !device.Disabled {
				ref = "direct"
				if peerUsesClient(device.Route.Exit) {
					ref = device.Route.Exit
				}
				break
			}
		}
	}
	if ref == "" {
		return errors.New("请选择主 LAN 或已启用的接入设备")
	}
	if err = atomicWrite(routingFile("analyze-device"), []byte(a.String()+"\n")); err != nil {
		return err
	}
	if err = atomicWrite(routingFile("analyze-policy"), []byte(ref+"\n")); err != nil {
		return err
	}
	return policyRun("analyze-start")
}
