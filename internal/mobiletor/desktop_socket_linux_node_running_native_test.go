//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func linuxRunningNativeSource(t *testing.T, baseline *DesktopLinuxNodeBaseline, network string,
	remote netip.AddrPort) (*DesktopLinuxSocketPolicy, DesktopLinuxNodeRunningSelection, DesktopLinuxProtectionRecord) {
	t.Helper()
	physical, err := net.InterfaceByName("rvpn-test")
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr("198.18.0.1")
	if network[3] == '6' {
		address = netip.MustParseAddr("fd50::1")
	}
	options := DesktopLinuxSocketOptions{
		Interfaces:          []DesktopLinuxSocketInterface{{Name: physical.Name, Index: uint32(physical.Index), Address: address}},
		PrivateDestinations: []DesktopLinuxSocketDestination{{Network: network[:3], Address: remote}},
	}
	source, err := NewDesktopLinuxNodeSocketPolicy(context.Background(), baseline.nft.Capture, options)
	if source != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := source.Close(ctx); err != nil {
				t.Error("actual running fixture did not join its original source", err)
			}
		})
	}
	if err != nil || source == nil {
		t.Fatal("running observation fixture could not create its actual native source", err)
	}
	record, err := source.ObservePreparedProtection(context.Background(), source.capture)
	if err != nil {
		t.Fatal(err)
	}
	if err := baseline.BindPrepared(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	return source, DesktopLinuxNodeRunningSelection{Interfaces: options.Interfaces, Destinations: options.PrivateDestinations}, record
}

func linuxRunningPeerTraffic(t *testing.T, connection net.Conn) {
	t.Helper()
	message := []byte("original running policy carries owned peer traffic")
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(message); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(message))
	if _, err := io.ReadFull(connection, reply); err != nil || string(reply) != string(message) {
		t.Fatal("running policy fixture lost actual original peer traffic", err)
	}
}

func TestDesktopLinuxGuardianKernelNodeRunning(t *testing.T) {
	for _, scenario := range []string{"tcp4", "udp4", "tcp6", "udp6", "wrong-destination", "wrong-interface", "wrong-record", "foreign-counter", "cancelled", "retired"} {
		t.Run(scenario, func(t *testing.T) {
			network := "udp4"
			if scenario == "tcp4" || scenario == "udp4" || scenario == "tcp6" || scenario == "udp6" {
				network = scenario
			}
			remote := desktopLinuxKernelPeer(t, network)
			baseline := linuxNodeBaselineFixture(t, false)
			source, selection, original := linuxRunningNativeSource(t, baseline, network, remote)
			broker := desktopLinuxKernelBroker(t, source)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			connection, err := broker.DialContext(ctx, network, remote.String())
			if err != nil {
				t.Fatal("running fixture could not create its actual owned peer socket", err)
			}
			t.Cleanup(func() { _ = connection.Close() })
			linuxRunningPeerTraffic(t, connection)
			if err := baseline.ObserveRunning(ctx, original, selection); err != nil {
				t.Fatal("original live native policy was refused", err)
			}
			if err := baseline.ObserveClosed(ctx); err == nil {
				t.Fatal("active original sockets became a closed native baseline")
			}
			changed, selected, checkContext := original, selection, ctx
			selected.Interfaces = append([]DesktopLinuxSocketInterface(nil), selection.Interfaces...)
			selected.Destinations = append([]DesktopLinuxSocketDestination(nil), selection.Destinations...)
			switch scenario {
			case "wrong-destination":
				selected.Destinations[0].Address = netip.MustParseAddrPort("198.18.0.3:8443")
			case "wrong-interface":
				selected.Interfaces[0].Index++
			case "wrong-record":
				changed.UID++
			case "foreign-counter":
				table := baseline.nft.table()
				desktopLinuxProtectionNativeCommand(t, fmt.Sprintf("add counter inet %s foreign_running_observation\n", table))
				defer desktopLinuxProtectionNativeCommand(t, fmt.Sprintf("delete counter inet %s foreign_running_observation\n", table))
			case "cancelled":
				var stop context.CancelFunc
				checkContext, stop = context.WithCancel(ctx)
				stop()
			case "retired":
				if err := connection.Close(); err != nil {
					t.Fatal(err)
				}
				if err := broker.Close(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if scenario != network {
				if err := baseline.ObserveRunning(checkContext, changed, selected); err == nil {
					t.Fatal("running observation accepted changed original policy", scenario)
				}
			} else {
				if err := baseline.ObserveRunning(checkContext, changed, selected); err != nil {
					t.Fatal("stable actual running inventory was rejected", err)
				}
			}
			if scenario != "retired" {
				linuxRunningPeerTraffic(t, connection)
				if err := connection.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "foreign-counter" {
				// Leave removal to the retained test-only defer before the original
				// source/baseline cleanups. The read-only method may not delete it.
				rows, err := desktopLinuxNFTReadTable(ctx, baseline.nft.table())
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, row := range rows {
					if value, ok := row["counter"].(map[string]any); ok && value["name"] == "foreign_running_observation" {
						found = true
					}
				}
				if !found {
					t.Fatal("running observation mutated an unrelated native object")
				}
				return
			}
			if err := broker.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if err := baseline.ObserveClosed(ctx); err != nil {
				t.Fatal("joined source lost its original closed baseline", err)
			}
			if err := baseline.Release(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
