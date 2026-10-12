package asusctl

import (
	"errors"
	"os"
	"strings"
)

var peerRPC = rpc
var persistPeerConfig = func(c ServerConfig) error { return writeJSON(serverConfigPath, c) }

func peerJournal() string { return serverStatePath + ".peer-pending" }
func enabledClients(c ServerConfig) int {
	n := 0
	for _, p := range c.Clients {
		if !p.Disabled {
			n++
		}
	}
	return n
}

// A peer delta never writes interface keys, replace_peers, routes or firewall rules.
func peerDelta(p ServerClient, remove bool) (string, error) {
	pub, e := keyHex(p.Public)
	if e != nil {
		return "", e
	}
	out := "set=1\npublic_key=" + pub
	if remove || p.Disabled {
		return out + "\nremove=true", nil
	}
	psk, e := keyHex(p.PSK)
	if e != nil {
		return "", e
	}
	out += "\npreshared_key=" + psk + "\nreplace_allowed_ips=true\nallowed_ip=" + p.Address
	if p.Address6 != "" {
		out += "\nallowed_ip=" + p.Address6
	}
	return out, nil
}
func commitPeerChange(old, next ServerConfig, before, after *ServerClient) error {
	if exists(peerJournal()) {
		return errors.New("上次设备变更未完成，请查看诊断；确认可中断连接后停止并重新启动服务端")
	}
	if !exists(serverStatePath) {
		if exists(serverSocket) {
			return errors.New("检测到未登记的服务端进程，未修改设备")
		}
		return persistPeerConfig(next)
	}
	if _, e := peerRPC(serverSocket, "get=1"); e != nil {
		return errors.New("服务端控制接口未就绪，未修改设备，请刷新状态")
	}
	target := after
	if target == nil {
		target = before
	}
	delta, e := peerDelta(*target, after == nil)
	if e != nil {
		return e
	}
	// Journal contains no keys. A crash leaves a visible pending state, never silent divergence.
	if e = atomicWrite(peerJournal(), []byte("peer update pending\n")); e != nil {
		return e
	}
	if e = persistPeerConfig(next); e != nil {
		_ = os.Remove(peerJournal())
		return errors.New("设备配置保存失败，运行状态未修改")
	}
	if _, e = peerRPC(serverSocket, delta); e != nil {
		undoTarget := before
		if undoTarget == nil {
			undoTarget = after
		}
		undo, ue := peerDelta(*undoTarget, before == nil)
		if ue == nil {
			_, ue = peerRPC(serverSocket, undo)
		}
		pe := persistPeerConfig(old)
		if ue != nil || pe != nil {
			return errors.New("设备更新失败且回滚未完成，请查看诊断；其他设备未重置")
		}
		if e = os.Remove(peerJournal()); e != nil {
			return errors.New("设备变更已回滚，但事务标记清理失败，请查看诊断")
		}
		return errors.New("设备更新失败，已恢复原配置；其他设备未重置")
	}
	if e = os.Remove(peerJournal()); e != nil {
		return errors.New("设备已更新，但事务标记清理失败，请查看诊断")
	}
	return nil
}
func serverSetDisabled(id string, disabled bool) error {
	c, e := readServer()
	if e != nil {
		return e
	}
	for i, p := range c.Clients {
		if p.ID != id {
			continue
		}
		if p.Disabled == disabled {
			return nil
		}
		old := c
		c.Clients = append([]ServerClient{}, c.Clients...)
		c.Clients[i].Disabled = disabled
		return commitPeerChange(old, c, &p, &c.Clients[i])
	}
	return errors.New("未找到客户端")
}

// Exact-line check: never count comments or another interface as registration.
func hasConfigLine(data, want string) bool {
	for _, line := range strings.Split(data, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}
