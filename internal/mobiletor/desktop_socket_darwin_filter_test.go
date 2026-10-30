//go:build darwin && routervpn_darwin_guardian

package mobiletor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDesktopPFAnchorProbeNativeFilterProjection(t *testing.T) {
	if os.Geteuid() != 0 || desktopDarwinTestFixture.Nonce == "" {
		t.Fatal("actual captured Darwin native filter projection fixture is required")
	}
	anchor := desktopDarwinTestForeignNamespace()
	capture := desktopSocketFixtureCapture()
	projectionGeneration := strings.Replace(desktopDarwinPFGeneration(capture), desktopDarwinPFNamespace, anchor, 1)
	if !desktopDarwinFixturePFOwned(projectionGeneration) {
		t.Fatal("native projection inventory lost its exact captured generation")
	}
	other := capture
	other.SessionID = strings.Repeat("9", 32)
	for _, unowned := range []string{
		projectionGeneration + "/unowned",
		strings.Replace(desktopDarwinPFGeneration(other), desktopDarwinPFNamespace, anchor, 1),
		anchor + "/g" + strings.Repeat("x", 32),
	} {
		if desktopDarwinFixturePFOwned(unowned) {
			t.Fatal("native projection inventory adopted an uncaptured sibling or descendant", unowned)
		}
	}
	policy := &desktopDarwinPF{Capture: capture, UID: uint32(os.Geteuid()), permits: make(map[string]desktopDarwinPFPermit)}
	for _, network := range []string{"tcp", "udp"} {
		for _, pair := range [][2]int{{0, 1}, {2, 3}} {
			grant := DesktopSocketGrant{Capture: capture, SocketID: strings.Repeat("4", 32), Network: network,
				Local:   netip.AddrPortFrom(desktopDarwinTestFixture.Addresses[pair[0]], 41111),
				Remote:  netip.AddrPortFrom(desktopDarwinTestFixture.Addresses[pair[1]], 42222),
				Binding: DesktopSocketBinding{InterfaceName: "lo0", InterfaceIndex: 1}, Sequence: 1}
			policy.permits[network+grant.Local.String()] = desktopDarwinPFPermit{Grant: grant}
		}
	}
	cleanup := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := desktopDarwinPFNativeReplace(ctx, anchor, nil); err != nil {
			t.Error("native filter projection cleanup did not retire its exact owner", err)
			return
		}
		if present, err := desktopDarwinFixturePFPresent(ctx, anchor); err != nil || present {
			t.Error("native filter projection cleanup retained its namespace", anchor, err)
		}
	}
	t.Cleanup(cleanup)
	for _, test := range []struct {
		name, source string
		fullPointer  bool
	}{
		{"captured-generation", policy.render(), false},
		{"captured-baseline", desktopDarwinPFBaseline(capture, DesktopDarwinSocketOptions{}), false},
		// A non-byte-aligned IPv6 mask must survive the C/kernel boundary,
		// not merely the pure Go compiler. Both rules still target only the
		// corresponding newly owned loopback address.
		{"scoped-v4-prefix", fmt.Sprintf("pass out on lo0 inet proto udp from %s to %s port 42222 no state\n", netip.PrefixFrom(desktopDarwinTestFixture.Addresses[0], 24).Masked(), desktopDarwinTestFixture.Addresses[1]), false},
		{"scoped-v6-prefix", fmt.Sprintf("pass out on lo0 inet6 proto udp from %s to %s port 42222 no state\n", netip.PrefixFrom(desktopDarwinTestFixture.Addresses[2], 49).Masked(), desktopDarwinTestFixture.Addresses[3]), false},
		{"scoped-icmp6", fmt.Sprintf("pass out on lo0 inet6 proto icmp6 from %s to %s no state\n", desktopDarwinTestFixture.Addresses[2], desktopDarwinTestFixture.Addresses[3]), false},
		{"complete-pointer", strings.Replace(desktopDarwinPFPointer(capture), desktopDarwinPFNamespace, anchor, 1), true},
		{"scoped-floating-state", fmt.Sprintf("pass out quick on lo0 inet proto udp from %s to %s port 42222 keep state (floating)\n", desktopDarwinTestFixture.Addresses[0], desktopDarwinTestFixture.Addresses[1]), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if present, err := desktopDarwinFixturePFPresent(ctx, anchor); err != nil || present {
				t.Fatal("typed native PF case did not capture a fresh absent anchor", anchor, err)
			}
			rules, err := desktopPFCompileFilters(test.source)
			if err != nil || len(rules) == 0 {
				t.Fatal("actual generated PF policy did not reach the typed native projection", err)
			}
			expected, err := desktopDarwinPFCanonical(ctx, test.source)
			if err != nil {
				t.Fatal("independent PF parser rejected the captured projection fixture", err)
			}
			if test.fullPointer {
				// The parser's display can shorten absolute paths. Independently
				// require the entire original capture, as the shipping readback does.
				expected = strings.TrimSpace(test.source)
			}
			if err := desktopDarwinPFNativeReplace(ctx, anchor, rules); err != nil {
				t.Fatal("actual typed native PF replacement failed", err)
			}
			if actual, err := desktopDarwinPFRead(ctx, anchor); err != nil || actual != expected {
				t.Fatal("native filter fields differ from the independent parser", actual, expected, err)
			}
			if err := desktopDarwinPFNativeReplace(ctx, anchor, nil); err != nil {
				t.Fatal("native filter transaction did not retire its complete queue", err)
			}
			if present, err := desktopDarwinFixturePFPresent(ctx, anchor); err != nil || present {
				t.Fatal("typed native filter transaction retained its empty anchor", anchor, err)
			}
			if test.fullPointer {
				generation := strings.Replace(desktopDarwinPFGeneration(capture), desktopDarwinPFNamespace, anchor, 1)
				if present, err := desktopDarwinFixturePFPresent(ctx, generation); err != nil || present {
					t.Fatal("native pointer retirement retained its empty captured generation", err)
				}
			}
		})
		if t.Failed() {
			return
		}
	}
	t.Run("rejected-record-preserves-owner", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		source := fmt.Sprintf("block drop out on lo0 inet to %s label \"owned-before-rejection\"\n", desktopDarwinTestFixture.Addresses[1])
		rules, err := desktopPFCompileFilters(source)
		if err != nil || len(rules) != 1 {
			t.Fatal(err)
		}
		if err := desktopDarwinPFNativeReplace(ctx, anchor, rules); err != nil {
			t.Fatal(err)
		}
		before, err := desktopDarwinPFRead(ctx, anchor)
		if err != nil || before == "" {
			t.Fatal(err)
		}
		invalid := rules[0]
		invalid.Destination = netip.PrefixFrom(desktopDarwinTestFixture.Addresses[1], 33)
		if err := desktopDarwinPFNativeReplace(ctx, anchor, append(rules, invalid)); err == nil {
			t.Fatal("native filter accepted an invalid second record after a valid prefix")
		}
		foreign := desktopPFFilterRule{Action: "anchor", Direction: "out", Anchor: "/com.apple/foreign-uncaptured"}
		if err := desktopDarwinPFNativeReplace(ctx, anchor, append(rules, foreign)); err == nil {
			t.Fatal("native filter referenced an uncaptured foreign anchor after a valid prefix")
		}
		stopped, stop := context.WithCancel(ctx)
		stop()
		if err := desktopDarwinPFNativeReplace(stopped, anchor, nil); !errors.Is(err, context.Canceled) {
			t.Fatal("native filter ignored cancellation before replacing its captured owner", err)
		}
		if actual, err := desktopDarwinPFRead(ctx, anchor); err != nil || actual != before {
			t.Fatal("rejected or cancelled native filter changed its retained active owner", actual, before, err)
		}
	})
}
