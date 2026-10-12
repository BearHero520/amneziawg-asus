package asusctl

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
)

var guardPath = "/tmp/amneziawg-asus/guard.json"

func guardActive() bool {
	b, e := os.ReadFile(guardPath)
	if e != nil {
		return false
	}
	if requireSoftwarePath() != nil {
		return false
	}
	var g Guard
	if json.Unmarshal(b, &g) != nil || len(g.Do) == 0 {
		return false
	}
	for _, c := range g.Do {
		args := append([]string{}, c.Args...)
		args[0] = "-C"
		if _, e := runCommand(c.Name, args...); e != nil {
			return false
		}
	}
	return true
}

type Guard struct {
	Do   []Command
	Undo []Command
}

func guardCommands(ns []Network) Guard {
	g := Guard{}
	for _, n := range ns {
		// Insert broad reject first, then narrow LAN/tunnel allowances before it.
		// INPUT blocks fallback to the router's own DNS when DNAT disappears.
		rules := [][]string{{"-I", "FORWARD", "-s", n.Source, "-m", "comment", "--comment", "amneziawg-guard", "-j", "REJECT"}, {"-I", "FORWARD", "-s", n.Source, "-o", n.LAN, "-m", "comment", "--comment", "amneziawg-guard", "-j", "ACCEPT"}, {"-I", "FORWARD", "-s", n.Source, "-o", "awg0", "-m", "comment", "--comment", "amneziawg-guard", "-j", "ACCEPT"}}
		for _, proto := range []string{"udp", "tcp"} {
			for _, port := range []string{"53", "853"} {
				rules = append(rules, []string{"-I", "INPUT", "-s", n.Source, "-p", proto, "--dport", port, "-m", "comment", "--comment", "amneziawg-guard", "-j", "REJECT"})
			}
		}
		for _, r := range rules {
			undo := append([]string{}, r...)
			undo[0] = "-D"
			g.Do = append(g.Do, cmd(n.Firewall, r...))
			g.Undo = append(g.Undo, cmd(n.Firewall, undo...))
		}
	}
	return g
}
func ensureGuard(ns []Network) error {
	wanted := guardCommands(ns)
	b, e := os.ReadFile(guardPath)
	if e == nil {
		var old Guard
		if json.Unmarshal(b, &old) != nil {
			return errors.New("断线保护记录损坏，请先停止并恢复直连")
		}
		newB, _ := json.Marshal(wanted)
		oldB, _ := json.Marshal(old)
		if string(newB) != string(oldB) {
			return errors.New("保护网段改变，请先停止并恢复直连后重新启动")
		}
	}
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	if e = writeJSON(guardPath, wanted); e != nil {
		return e
	}
	for _, c := range wanted.Do {
		check := append([]string{}, c.Args...)
		check[0] = "-C"
		if _, e = runCommand(c.Name, check...); e == nil {
			continue
		}
		if _, e = runCommand(c.Name, c.Args...); e != nil {
			return e
		}
	}
	return nil
}
func releaseGuard() error {
	b, e := os.ReadFile(guardPath)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var g Guard
	if e = json.Unmarshal(b, &g); e != nil {
		return e
	}
	var problems []string
	for i := len(g.Undo) - 1; i >= 0; i-- {
		c := g.Undo[i]
		out, e := runCommand(c.Name, c.Args...)
		if e != nil && !missingResource(out) {
			problems = append(problems, e.Error())
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return os.Remove(guardPath)
}
