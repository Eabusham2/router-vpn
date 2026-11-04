//go:build linux && routervpn_controller_privileged && routervpn_standard_service_native

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// This component gate uses the real retained service engine/pidfd and native
// namespace Tracker. DNS uses the actual original child listener and two real
// uncached exchanges; its router and nft/TUN setup are explicit fixture models.
// Actual link/address/route/rule away-and-back events are required.
// Missing NET_ADMIN/netlink capability fails rather than skipping this gate.
func TestLinuxStandardServiceNamespaceNetworkEpochRejectsAwayAndBack(t *testing.T) {
	if os.Getenv(linuxControllerNamespaceMarker) != "1" || os.Geteuid() != 0 {
		t.Fatal("network epoch requires original privileged namespace runner")
	}
	ip := func(args ...string) []byte {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		body, err := exec.CommandContext(ctx, "/usr/sbin/ip", args...).CombinedOutput()
		if err != nil {
			t.Fatal("original namespace event fixture failed", args, err, string(body))
		}
		return body
	}
	name := "rvpn-epoch"
	ip("link", "add", name, "type", "dummy")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if body, err := exec.CommandContext(ctx, "/usr/sbin/ip", "link", "delete", name).CombinedOutput(); err != nil {
			t.Error(err, string(body))
		}
	})
	ip("link", "set", name, "addrgenmode", "none")
	ip("link", "set", name, "mtu", "1500")
	ip("link", "set", name, "up")
	for _, kind := range []string{"link", "address", "route", "rule"} {
		t.Run(kind, func(t *testing.T) {
			s, _, peer, request, ctx := standardNetworkSessionWithDNS(t, "on-connect", true)
			if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "prove-dns", false), nil); err != nil {
				t.Fatal("actual kernel event observer did not arm", err)
			}
			original := s.session.network
			var before, after []byte
			switch kind {
			case "link":
				before = ip("-j", "link", "show", "dev", name)
				ip("link", "set", name, "mtu", "1400")
				ip("link", "set", name, "mtu", "1500")
				after = ip("-j", "link", "show", "dev", name)
			case "address":
				before = ip("-j", "address", "show", "dev", name)
				ip("address", "add", "198.18.3.2/24", "dev", name)
				ip("address", "delete", "198.18.3.2/24", "dev", name)
				after = ip("-j", "address", "show", "dev", name)
			case "route":
				before = ip("-j", "route", "show", "table", "all")
				ip("route", "add", "blackhole", "198.18.4.0/24", "table", "2001")
				ip("route", "delete", "blackhole", "198.18.4.0/24", "table", "2001")
				after = ip("-j", "route", "show", "table", "all")
			case "rule":
				before = ip("-j", "rule", "show")
				ip("rule", "add", "priority", "19191", "lookup", "2002")
				ip("rule", "delete", "priority", "19191", "lookup", "2002")
				after = ip("-j", "rule", "show")
			}
			if !bytes.Equal(before, after) {
				t.Fatal("native fixture did not restore identical final topology", kind, string(before), string(after))
			}
			if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "current", false), nil); err == nil {
				t.Fatal("shipping proof accepted actual native away-and-back", kind)
			}
			if err := s.networkCurrent(ctx, s.session, true); err == nil || s.session.network != original {
				t.Fatal("original epoch invalidation was cleared", err)
			}
			if err := s.handle(ctx, peer, linuxStandardServiceTestAction(request, "stop", true), nil); err != nil {
				t.Fatal("invalid network prevented original cleanup", err)
			}
			if !original.closed || !s.session.joined {
				t.Fatal("native observer and original engine were not joined")
			}
		})
	}
}
