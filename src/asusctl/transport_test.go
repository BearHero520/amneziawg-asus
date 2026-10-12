package asusctl

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"golang.org/x/crypto/curve25519"
)

// Uses real local UDP sockets and the official core. Retransmits packets because
// the upstream TUN reader can be blocked with the old S4 offset during IpcSet.
func TestConvertedConfigsCarryEncryptedTraffic(t *testing.T) {
	for _, version := range []string{"legacy", "v2", "v3"} {
		t.Run(version, func(t *testing.T) {
			privs := [][]byte{bytes.Repeat([]byte{17}, 32), bytes.Repeat([]byte{23}, 32)}
			pubs := make([][]byte, 2)
			for i := range privs {
				var e error
				pubs[i], e = curve25519.X25519(privs[i], curve25519.Basepoint)
				if e != nil {
					t.Fatal(e)
				}
			}
			var ds [2]*device.Device
			var ts [2]*tuntest.ChannelTUN
			var ports [2]string
			for i := 0; i < 2; i++ {
				ts[i] = tuntest.NewChannelTUN()
				ds[i] = device.NewDevice(ts[i].TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
				defer ds[i].Close()
				extra := "S3 = 0\nS4 = 0\n"
				if version != "legacy" {
					extra = "S3 = 16\nS4 = 25\n"
				}
				if version == "v3" {
					extra += "HeaderProtectionKey = BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=\nContentPaddingAddition = 0-4\nRekeyAfterTime = 110-120\n"
				}
				text := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.8.0.%d/32\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 16\nS2 = 20\nH1 = 100000-100001\nH2 = 200000-200001\nH3 = 300000-300001\nH4 = 400000-400001\n%s[Peer]\nPublicKey = %s\nAllowedIPs = 10.8.0.%d/32\n", base64.StdEncoding.EncodeToString(privs[i]), i+1, extra, base64.StdEncoding.EncodeToString(pubs[i^1]), (i^1)+1)
				c, e := Parse(text)
				if e != nil {
					t.Fatal(e)
				}
				u, e := c.UAPI(resolveEndpoint)
				if e != nil {
					t.Fatal(e)
				}
				if e = ds[i].IpcSet(u); e != nil {
					t.Fatal(e)
				}
				if e = ds[i].Up(); e != nil {
					t.Fatal(e)
				}
				out, e := ds[i].IpcGet()
				if e != nil {
					t.Fatal(e)
				}
				for _, line := range strings.Split(out, "\n") {
					if strings.HasPrefix(line, "listen_port=") {
						ports[i] = strings.TrimPrefix(line, "listen_port=")
					}
				}
			}
			for i := 0; i < 2; i++ {
				if e := ds[i].IpcSet("public_key=" + hex.EncodeToString(pubs[i^1]) + "\nendpoint=127.0.0.1:" + ports[i^1] + "\n"); e != nil {
					t.Fatal(e)
				}
			}
			for i := 0; i < 2; i++ {
				packet := tuntest.Ping(netip.MustParseAddr(fmt.Sprintf("10.8.0.%d", (i^1)+1)), netip.MustParseAddr(fmt.Sprintf("10.8.0.%d", i+1)))
				received := false
				for attempt := 0; attempt < 12 && !received; attempt++ {
					select {
					case ts[i].Outbound <- packet:
					case <-time.After(time.Second):
						t.Fatal("TUN send blocked")
					}
					select {
					case got := <-ts[i^1].Inbound:
						if !bytes.Equal(got, packet) {
							t.Fatal("decrypted payload differs")
						}
						received = true
					case <-time.After(500 * time.Millisecond):
					}
				}
				if !received {
					t.Fatalf("direction %d did not carry traffic", i)
				}
			}
		})
	}
}
