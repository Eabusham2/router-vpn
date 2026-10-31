//go:build linux && routervpn_linux_guardian

package mobiletor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func linuxNodeBaselineFixture(t *testing.T, homeLAN bool) *DesktopLinuxNodeBaseline {
	t.Helper()
	if os.Getenv("ROUTERVPN_LINUX_GUARDIAN_TEST_NS") != "1" || os.Geteuid() != 0 {
		t.Fatal("Node baseline tests require the original isolated namespace runner")
	}
	capture := desktopSocketFixtureCapture()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	capture.SessionID = hex.EncodeToString(nonce[:])
	baseline, err := NewDesktopLinuxNodeBaseline(context.Background(), capture, homeLAN)
	if baseline != nil {
		t.Cleanup(func() {
			if err := baseline.Close(context.Background()); err != nil {
				t.Error(err)
			}
			// This disposable fixture owns only its exact random session name.
			// Deliberately corrupted/replaced test policies are cleaned here,
			// never by a failed production creation/removal capability.
			rows, err := desktopLinuxNFTReadTable(context.Background(), desktopLinuxNodeTable(capture))
			if err != nil {
				t.Error(err)
			} else if len(rows) != 0 {
				if _, err := desktopLinuxNFTCommand(context.Background(), []string{"delete", "table", "inet", desktopLinuxNodeTable(capture)}, ""); err != nil {
					t.Error(err)
				}
			}
		})
	}
	if err != nil || baseline == nil {
		t.Fatal("native exclusive Node baseline creation failed", err)
	}
	return baseline
}

func linuxNodeBaselineSource(t *testing.T, baseline *DesktopLinuxNodeBaseline, homeLAN bool, destinations ...DesktopLinuxSocketDestination) *DesktopLinuxSocketPolicy {
	t.Helper()
	physical, err := net.InterfaceByName("rvpn-test")
	if err != nil {
		t.Fatal(err)
	}
	options := DesktopLinuxSocketOptions{Interfaces: []DesktopLinuxSocketInterface{{Name: physical.Name, Index: uint32(physical.Index), Address: netip.MustParseAddr("198.18.0.1")}}, PrivateDestinations: destinations}
	if homeLAN {
		for _, prefix := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"} {
			options.LANPrefixes = append(options.LANPrefixes, netip.MustParsePrefix(prefix))
		}
	}
	source, err := NewDesktopLinuxNodeSocketPolicy(context.Background(), baseline.nft.Capture, options)
	if source != nil {
		t.Cleanup(func() {
			if err := source.Close(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil || source == nil {
		t.Fatal("actual Node guardian did not bind its original scoped baseline", err)
	}
	record, err := source.ObservePreparedProtection(context.Background(), source.capture)
	if err != nil || baseline.BindPrepared(context.Background(), record) != nil {
		t.Fatal("original Node baseline rejected its actual guardian preparation", err)
	}
	return source
}

func TestDesktopLinuxGuardianKernelNodeBaselineSuccession(t *testing.T) {
	t.Run("exclusive-creation-and-selected-LAN", func(t *testing.T) {
		for _, homeLAN := range []bool{false, true} {
			t.Run(map[bool]string{false: "blocked-LAN", true: "selected-LAN"}[homeLAN], func(t *testing.T) {
				baseline := linuxNodeBaselineFixture(t, homeLAN)
				if err := ReadDesktopLinuxProtectionAbsence(context.Background()); err == nil {
					t.Fatal("scoped Node baseline was hidden from initial journal absence")
				}
				duplicate, err := NewDesktopLinuxNodeBaseline(context.Background(), baseline.nft.Capture, homeLAN)
				if err == nil || duplicate == nil || duplicate.complete || duplicate.Release(context.Background()) == nil {
					t.Fatal("same-name create adopted existing native table ownership", err)
				}
				if err := duplicate.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := baseline.ObserveClosed(context.Background()); err != nil {
					t.Fatal("rejected duplicate creation changed original baseline", err)
				}
				source := linuxNodeBaselineSource(t, baseline, homeLAN)
				if err := baseline.Release(context.Background()); err == nil {
					t.Fatal("live Node guardian permitted original parent release")
				}
				if err := source.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := baseline.Release(context.Background()); err != nil {
					t.Fatal("joined Node source could not release original scoped table", err)
				}
				if err := baseline.Release(context.Background()); err != nil {
					t.Fatal("acknowledged scoped removal was not idempotent", err)
				}
			})
		}
	})
	t.Run("captured-successor-and-fixed-namespace", func(t *testing.T) {
		// The fixed Tor/global baseline is a distinct retained owner. None of
		// the Node constructors or successor cleanup can delete/adopt it.
		desktopLinuxKernelBaseline(t)
		fixedBefore, err := desktopLinuxNFTRead(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		old := linuxNodeBaselineFixture(t, false)
		oldSource := linuxNodeBaselineSource(t, old, false)
		next := linuxNodeBaselineFixture(t, false)
		nextSource := linuxNodeBaselineSource(t, next, false)
		if err := old.Supersede(context.Background(), next); err == nil {
			t.Fatal("unretired Node predecessor authorized successor deletion")
		}
		if err := oldSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if err := old.Supersede(cancelled, next); err == nil {
			t.Fatal("cancelled Node succession removed original protection")
		}
		for i := 0; i < 2; i++ {
			if err := old.Supersede(context.Background(), next); err != nil {
				t.Fatal("closed Node successor did not replace the exact predecessor", err)
			}
		}
		if old.Release(context.Background()) == nil {
			t.Fatal("explicit release replaced an already captured succession")
		}
		if rows, err := desktopLinuxNFTReadTable(context.Background(), old.nft.table()); err != nil || len(rows) != 0 {
			t.Fatal("committed successor retained old Node table", err)
		}
		if _, err := nextSource.ObservePreparedProtection(context.Background(), next.nft.Capture); err != nil {
			t.Fatal("predecessor cleanup changed the original successor", err)
		}
		fixedAfter, err := desktopLinuxNFTRead(context.Background())
		if err != nil || !linuxNodeEqualJSON(fixedBefore, fixedAfter) {
			t.Fatal("Node succession changed fixed Tor/global protection", err)
		}
		if err := nextSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := next.Release(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("changed-successor-preserves-predecessor", func(t *testing.T) {
		old := linuxNodeBaselineFixture(t, false)
		oldSource := linuxNodeBaselineSource(t, old, false)
		if err := oldSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		next := linuxNodeBaselineFixture(t, false)
		nextSource := linuxNodeBaselineSource(t, next, false)
		if _, err := desktopLinuxNFTCommand(context.Background(), []string{"-f", "-"}, "add rule inet "+next.nft.table()+" output accept\n"); err != nil {
			t.Fatal(err)
		}
		if err := old.Supersede(context.Background(), next); err == nil {
			t.Fatal("changed successor allowed predecessor removal")
		}
		if err := old.ObserveClosed(context.Background()); err != nil {
			t.Fatal("rejected successor changed old deny baseline", err)
		}
		if err := nextSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("same-name-replacement-is-not-original", func(t *testing.T) {
		old := linuxNodeBaselineFixture(t, false)
		oldSource := linuxNodeBaselineSource(t, old, false)
		if err := oldSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := desktopLinuxNFTCommand(context.Background(), []string{"delete", "table", "inet", old.nft.table()}, ""); err != nil {
			t.Fatal(err)
		}
		replacement, err := NewDesktopLinuxNodeBaseline(context.Background(), old.nft.Capture, false)
		if err != nil {
			t.Fatal(err)
		}
		defer replacement.Close(context.Background())
		if replacement.nft.TableHandle == old.nft.TableHandle || old.Release(context.Background()) == nil {
			t.Fatal("old Node creator adopted a replacement table")
		}
		if err := replacement.ObserveClosed(context.Background()); err != nil {
			t.Fatal("old cleanup changed replacement deny policy", err)
		}
		if err := replacement.Release(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("actual-successor-permit-and-blocked-bypass", func(t *testing.T) {
		remote := desktopLinuxKernelPeer(t, "udp4")
		linuxNodeBaselineBypass(t, remote, false)
		old := linuxNodeBaselineFixture(t, false)
		oldSource := linuxNodeBaselineSource(t, old, false)
		if err := oldSource.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		linuxNodeBaselineBypass(t, remote, true)
		next := linuxNodeBaselineFixture(t, false)
		nextSource := linuxNodeBaselineSource(t, next, false, DesktopLinuxSocketDestination{Network: "udp", Address: remote})
		linuxNodeBaselineBypass(t, remote, true)
		if err := old.Supersede(context.Background(), next); err != nil {
			t.Fatal(err)
		}
		linuxNodeBaselineBypass(t, remote, true)
		broker, err := NewDesktopSocketBroker(context.Background(), next.nft.Capture, nextSource, func() bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = broker.Close(context.Background()) })
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		connection, err := broker.DialContext(ctx, "udp4", remote.String())
		if err != nil {
			t.Fatal("exact successor permit did not carry its original source", err)
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		payload := []byte("exact Node successor packet")
		if _, err := connection.Write(payload); err != nil {
			t.Fatal(err)
		}
		answer := make([]byte, 128)
		count, err := connection.Read(answer)
		if err != nil || !bytes.Equal(answer[:count], payload) {
			t.Fatal("successor's actual peer did not echo protected traffic", err)
		}
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
		if err := broker.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		linuxNodeBaselineBypass(t, remote, true)
		if err := next.Release(context.Background()); err != nil {
			t.Fatal(err)
		}
		linuxNodeBaselineBypass(t, remote, false)
	})
	t.Run("malformed-reserved-table-is-not-absence", func(t *testing.T) {
		name := desktopLinuxNodeTablePrefix + "MALFORMED"
		if _, err := desktopLinuxNFTCommand(context.Background(), []string{"add", "table", "inet", name}, ""); err != nil {
			t.Fatal(err)
		}
		defer desktopLinuxNFTCommand(context.Background(), []string{"delete", "table", "inet", name}, "")
		if err := ReadDesktopLinuxProtectionAbsence(context.Background()); err == nil {
			t.Fatal("malformed reserved Node table was hidden from initial absence")
		}
	})
}

func linuxNodeEqualJSON(a, b any) bool {
	first, _ := json.Marshal(a)
	second, _ := json.Marshal(b)
	return string(first) == string(second)
}

func linuxNodeBaselineBypass(t *testing.T, remote netip.AddrPort, blocked bool) {
	t.Helper()
	connection, err := net.DialTimeout("udp4", remote.String(), time.Second)
	if err != nil {
		t.Fatal("physical positive-control socket creation failed", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(200 * time.Millisecond))
	payload := []byte("unpermitted Node bypass")
	_, err = connection.Write(payload)
	echo := false
	if err == nil {
		answer := make([]byte, 128)
		var count int
		count, err = connection.Read(answer)
		echo = err == nil && bytes.Equal(answer[:count], payload)
	}
	if blocked == echo {
		t.Fatal("native Node baseline changed actual blocked-bypass semantics", blocked, echo, err)
	}
}
