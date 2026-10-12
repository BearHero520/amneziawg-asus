package asusctl

import (
	"fmt"
	"strings"
	"testing"
)

func TestServerPolicyPriorityCoexistsWithOtherVPNs(t *testing.T) {
	base := "0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n"
	for _, tc := range []struct {
		name, rules, address string
		want                 int
	}{
		{"empty", base, "10.77.0.1/24", 90},
		{"early global VPN", base + "50: from all fwmark 0x1 lookup 100\n", "10.77.0.1/24", 49},
		{"reserved 90", base + "90: from all lookup 200\n", "10.77.0.1/24", 89},
		{"LAN and local output", base + "1: from 192.168.50.0/24 lookup 100\n2: from all iif lo lookup 200\n90: from all iif br0 lookup 300\n", "10.77.0.1/24", 89},
		{"source host", base + "1: from 192.168.50.10 lookup 100\n", "10.77.0.1/24", 90},
		{"overlapping source", base + "20: from 10.0.0.0/8 lookup 100\n", "10.77.0.1/24", 19},
		{"IPv6 unrelated LAN", base + "1: from 2001:db8:50::/64 lookup 100\n30: from all lookup 200\n", "fd77:77::1/64", 29},
		{"negated interface", base + "10: not from all iif br0 lookup 100\n", "10.77.0.1/24", 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, e := chooseServerPriority(tc.rules, tc.address)
			if e != nil || got != tc.want {
				t.Fatalf("got %d %v want %d", got, e, tc.want)
			}
		})
	}
	crowded := base
	for i := 1; i <= 90; i++ {
		crowded += fmt.Sprintf("%d: from all iif br0 lookup 100\n", i)
	}
	if got, e := chooseServerPriority(crowded, "10.77.0.1/24"); e != nil || got != 91 {
		t.Fatalf("unrelated occupied range: %d %v", got, e)
	}
	for _, r := range []string{"1: from all lookup 100", "1: from all fwmark 0x1 lookup 100", "0: from all lookup 100", "1: not from 192.168.50.0/24 lookup 100", "unparseable rule"} {
		if _, e := chooseServerPriority(base+r, "10.77.0.1/24"); e == nil {
			t.Fatal("unsafe earlier rule accepted", r)
		}
	}
}

func TestServerPolicyUndoOnlyDeletesChosenInterfaceRule(t *testing.T) {
	for _, f := range []string{"-4", "-6"} {
		s := serverPolicyStep(f, 49)
		if strings.Join(s.Do.Args, " ") != f+" rule add priority 49 iif awgs0 lookup main" {
			t.Fatal(s.Do)
		}
		if strings.Join(s.Undo.Args, " ") != f+" rule del priority 49 iif awgs0 lookup main" {
			t.Fatal(s.Undo)
		}
	}
}
