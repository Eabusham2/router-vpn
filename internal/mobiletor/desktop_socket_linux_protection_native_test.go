//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func desktopLinuxNoProtectionObservation(t *testing.T, record DesktopLinuxProtectionRecord, err error, witness string) {
	t.Helper()
	if err == nil || record != (DesktopLinuxProtectionRecord{}) {
		t.Fatal(witness, record, err)
	}
}

func desktopLinuxProtectionNativeCommand(t *testing.T, script string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := desktopLinuxNFTCommand(ctx, []string{"-f", "-"}, script); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopLinuxGuardianKernelClosedProtectionObservations(t *testing.T) {
	t.Run("complete-owner-lifecycle", func(t *testing.T) {
		remote := desktopLinuxKernelPeer(t, "udp4")
		p := desktopLinuxKernelPolicy(t, []DesktopLinuxSocketDestination{{Network: "udp", Address: remote}})
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		prepared, err := p.ObservePreparedProtection(ctx, p.capture)
		if err != nil || prepared.Validate() != nil || prepared.Owner != p.owner || prepared.UID != p.uid || prepared.PermitPrefix != p.nft.Prefix {
			t.Fatal("actual unused guardian did not prove its closed preparation", err)
		}
		for _, field := range []string{"session", "source", "network"} {
			changed := p.capture
			switch field {
			case "session":
				changed.SessionID = strings.Repeat("e", 32)
			case "source":
				changed.SourceSHA256 = strings.Repeat("e", 64)
			case "network":
				changed.NetworkID = strings.Repeat("e", 32)
			}
			record, err := p.ObservePreparedProtection(ctx, changed)
			desktopLinuxNoProtectionObservation(t, record, err, "changed capture acquired the actual prepared baseline")
		}
		cancelled, stop := context.WithCancel(ctx)
		stop()
		for _, invalid := range []context.Context{nil, cancelled} {
			record, err := p.ObservePreparedProtection(invalid, p.capture)
			desktopLinuxNoProtectionObservation(t, record, err, "cancelled preparation produced a native observation")
		}
		record, err := p.ObserveRetiredProtection(ctx, p.capture)
		desktopLinuxNoProtectionObservation(t, record, err, "live guardian produced a retired observation")
		broker := desktopLinuxKernelBroker(t, p)
		connection, err := broker.DialContext(ctx, "udp4", remote.String())
		if err != nil {
			t.Fatal(err)
		}
		connection.SetDeadline(time.Now().Add(time.Second))
		if _, err = connection.Write([]byte("closed baseline owner lifecycle")); err != nil {
			t.Fatal(err)
		}
		var reply [64]byte
		if _, err = connection.Read(reply[:]); err != nil {
			t.Fatal("actual owned tuple did not carry peer traffic", err)
		}
		if err = connection.Close(); err != nil {
			t.Fatal(err)
		}
		rows, err := desktopLinuxNFTRead(ctx)
		if err != nil || desktopLinuxProtectionRows(p.nft, rows, true) != nil || !p.Current(p.capture, p.owner) {
			t.Fatal("retired socket did not leave a live source with empty native tuple sets", err)
		}
		record, err = p.ObservePreparedProtection(ctx, p.capture)
		desktopLinuxNoProtectionObservation(t, record, err, "used source was relabelled as a fresh preparation")
		if err = broker.Close(ctx); err != nil {
			t.Fatal("actual broker did not join its native source", err)
		}
		retired, err := p.ObserveRetiredProtection(ctx, p.capture)
		if err != nil || retired != prepared {
			t.Fatal("joined source did not retain the exact prepared baseline", err)
		}
		for _, invalid := range []context.Context{nil, cancelled} {
			record, err := p.ObserveRetiredProtection(invalid, p.capture)
			desktopLinuxNoProtectionObservation(t, record, err, "cancelled retirement produced a native observation")
		}
		changed := p.capture
		changed.NetworkID = strings.Repeat("e", 32)
		record, err = p.ObserveRetiredProtection(ctx, changed)
		desktopLinuxNoProtectionObservation(t, record, err, "changed network acquired the retired baseline")
	})

	t.Run("unjoined-empty-inventory", func(t *testing.T) {
		p := desktopLinuxKernelPolicy(t, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := p.ObservePreparedProtection(ctx, p.capture); err != nil {
			t.Fatal(err)
		}
		// Only this isolated test's exact owned permits are removed. Kernel
		// absence alone must not claim that the still-running creator joined.
		if err := p.nft.close(ctx); err != nil {
			t.Fatal(err)
		}
		record, err := p.ObserveRetiredProtection(ctx, p.capture)
		desktopLinuxNoProtectionObservation(t, record, err, "empty inventory substituted for native close acknowledgment")
	})

	t.Run("failed-close-and-retry", func(t *testing.T) {
		remote := netip.MustParseAddrPort("198.18.0.2:19002")
		p := desktopLinuxKernelPolicy(t, []DesktopLinuxSocketDestination{{Network: "udp", Address: remote}})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		prepared, err := p.ObservePreparedProtection(ctx, p.capture)
		if err != nil {
			t.Fatal(err)
		}
		binding, err := p.Select(ctx, p.capture, "udp", remote)
		if err != nil {
			t.Fatal(err)
		}
		creation := DesktopSocketCreation{Capture: p.capture, Binding: binding, SocketID: strings.Repeat("f", 32), Network: "udp"}
		created, err := p.CreateSocket(ctx, creation)
		if err != nil {
			t.Fatal(err)
		}
		defer created.File.Close()
		if err = p.Close(ctx); err == nil || p.closeAcknowledged.Load() {
			t.Fatal("unretired native descriptor produced a close acknowledgment", err)
		}
		record, err := p.ObserveRetiredProtection(ctx, p.capture)
		desktopLinuxNoProtectionObservation(t, record, err, "failed native close produced a retained observation")
		if err = created.File.Close(); err != nil {
			t.Fatal(err)
		}
		if err = p.ReleaseSocket(ctx, creation); err != nil {
			t.Fatal(err)
		}
		if err = p.Close(ctx); err != nil {
			t.Fatal("exact native cleanup retry did not join", err)
		}
		record, err = p.ObserveRetiredProtection(ctx, p.capture)
		if err != nil || record != prepared {
			t.Fatal("successful joined retry lost its original baseline", err)
		}
	})

	t.Run("active-prepared-permit", func(t *testing.T) {
		p := desktopLinuxKernelPolicy(t, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := p.ObservePreparedProtection(ctx, p.capture); err != nil {
			t.Fatal(err)
		}
		desktopLinuxProtectionNativeCommand(t, fmt.Sprintf("add element inet %s %s_udp4 { %d . 198.18.0.1 . 19001 . 198.18.0.2 . 19002 timeout 9s }\n", desktopLinuxNFTTable, p.nft.Prefix, p.options.Interfaces[0].Index))
		record, err := p.ObservePreparedProtection(ctx, p.capture)
		desktopLinuxNoProtectionObservation(t, record, err, "active native tuple was accepted as closed preparation")
	})

	t.Run("foreign-set", func(t *testing.T) {
		p := desktopLinuxKernelPolicy(t, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		prepared, err := p.ObservePreparedProtection(ctx, p.capture)
		if err != nil {
			t.Fatal(err)
		}
		desktopLinuxProtectionNativeCommand(t, "add set inet router_vpn_killswitch rvpn_unselected { type ipv4_addr; }\n")
		record, err := p.ObservePreparedProtection(ctx, p.capture)
		desktopLinuxNoProtectionObservation(t, record, err, "foreign native set was accepted as closed preparation")
		if err = p.Close(ctx); err != nil {
			t.Fatal(err)
		}
		record, err = p.ObserveRetiredProtection(ctx, p.capture)
		desktopLinuxNoProtectionObservation(t, record, err, "foreign native set was accepted as retained protection")
		desktopLinuxProtectionNativeCommand(t, "delete set inet router_vpn_killswitch rvpn_unselected\n")
		record, err = p.ObserveRetiredProtection(ctx, p.capture)
		if err != nil || record != prepared {
			t.Fatal("restored exact kernel namespace did not prove its retained baseline", err)
		}
	})

	for _, change := range []string{"extra-exemption", "dormant", "replaced"} {
		t.Run("retired-"+change, func(t *testing.T) {
			p := desktopLinuxKernelPolicy(t, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := p.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := p.ObserveRetiredProtection(ctx, p.capture); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "extra-exemption":
				desktopLinuxProtectionNativeCommand(t, "add rule inet router_vpn_killswitch output accept\n")
			case "dormant":
				desktopLinuxProtectionNativeCommand(t, "add table inet router_vpn_killswitch { flags dormant; }\n")
			case "replaced":
				desktopLinuxProtectionNativeCommand(t, "delete table inet router_vpn_killswitch\n")
				desktopLinuxKernelInstallBaseline(t, p.capture)
			}
			before, err := desktopLinuxNFTRead(ctx)
			if err != nil {
				t.Fatal(err)
			}
			record, err := p.ObserveRetiredProtection(ctx, p.capture)
			desktopLinuxNoProtectionObservation(t, record, err, "changed native baseline was accepted as retained protection")
			if err = p.Close(ctx); err != nil {
				t.Fatal("old owner could not repeat its exact cleanup", err)
			}
			after, err := desktopLinuxNFTRead(ctx)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("observation or old cleanup mutated the changed/replacement baseline", err)
			}
		})
	}
}
