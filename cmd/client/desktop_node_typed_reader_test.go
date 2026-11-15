package main

import (
	"context"
	"net"
	"router-vpn/internal/mobilemultihop"
	"strings"
	"testing"
	"time"
)

func TestDesktopDarwinTypedReaderRequiresOriginalRetirement(t *testing.T) {
	for _, scenario := range []string{"same-alias", "renamed", "rollback", "old-index", "old-index-renamed", "same-index", "stale-reader", "kernel-name", "kernel-mtu", "kernel-down", "kernel-missing", "duplicate-index"} {
		t.Run(scenario, func(t *testing.T) {
			old := &mobilemultihop.DesktopNodeChainReadyRecord{InterfaceName: "utun91", InterfaceIndex: 91, Reader: 4}
			next := desktopNodeMTURecord{Interface: "utun91", Index: 92, Reader: 5, MTU: 1380}
			if scenario == "renamed" {
				next.Interface = "utun92"
			}
			if scenario == "rollback" {
				next.Reader++
				next.MTU = 1420
			}
			kernel := []net.Interface{{Name: next.Interface, Index: next.Index, MTU: next.MTU, Flags: net.FlagUp}}
			switch scenario {
			case "old-index":
				kernel = append(kernel, net.Interface{Name: old.InterfaceName, Index: 91})
			case "old-index-renamed":
				kernel = append(kernel, net.Interface{Name: "utun99", Index: 91})
			case "same-index":
				next.Index = 91
				kernel[0].Index = 91
			case "stale-reader":
				next.Reader = 4
			case "kernel-name":
				kernel[0].Name = "utun93"
			case "kernel-mtu":
				kernel[0].MTU++
			case "kernel-down":
				kernel[0].Flags = 0
			case "kernel-missing":
				kernel = nil
			case "duplicate-index":
				kernel = append(kernel, kernel[0])
			}
			err := validateDesktopMacOSTypedReaderRetirement(old, next, kernel)
			if (err == nil) != (scenario == "same-alias" || scenario == "renamed" || scenario == "rollback") {
				t.Fatal("typed reader retirement verdict changed", scenario, err)
			}
		})
	}
}

// Actual parent mailbox/nonce/lease parsing precedes the unchanged-reader path.
// Only the native child and kernel observation are explicit fixture boundaries.
func TestDesktopDarwinTypedMTUUnchangedRollbackMailbox(t *testing.T) {
	for _, family := range []string{"connect", "socks", "execution"} {
		t.Run(family, func(t *testing.T) {
			for _, fault := range []string{"original", "stale-reader", "future-reader", "foreign-lease"} {
				t.Run(fault, func(t *testing.T) {
					var launch *desktopNodeLaunch
					switch family {
					case "connect":
						_, _, launch = desktopCONNECTPlatformFixture(t, "wg", "darwin")
					case "socks":
						_, _, launch = desktopSOCKSPlatformFixture(t, "wg", "darwin")
					default:
						launch, _ = desktopExecutionAttachedFixture(t, "darwin")
					}
					fixture := newDesktopNodeMTUFixture(t)
					meta := launch.chain.policyMetadata()
					fixture.launch.chain = launch.chain
					fixture.launch.chain.platform = &desktopNodeChainPlatformRuntime{}
					fixture.launch.mtuSession, fixture.launch.configSHA256 = meta.SessionID, meta.ConfigSHA256
					fixture.base.Session, fixture.base.Config, fixture.base.Interface = meta.SessionID, meta.ConfigSHA256, "utun71"
					if err := fixture.publish(fixture.base, false); err != nil {
						t.Fatal(err)
					}
					startDesktopNodeMTUFixtureChild(t, fixture, func(command desktopNodeMTUCommand, next *desktopNodeMTURecord) {
						if command.Action != "rollback" {
							return
						}
						next.Interface = fixture.base.Interface
						next.Index = fixture.base.Index
						next.MTU = fixture.base.MTU
						// The actual typed raw path publishes a new readback epoch even
						// when its original native reader is retained unchanged.
						next.Reader = fixture.base.Reader + 1
						switch fault {
						case "stale-reader":
							next.Reader = fixture.base.Reader - 1
						case "future-reader":
							next.Reader = fixture.base.Reader + 2
						case "foreign-lease":
							next.Lease = strings.Repeat("f", 32)
						}
					})
					ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
					defer cancel()
					kernel, err := openDesktopNodeMTUOwnerContext(ctx, fixture.launch, mtuLiveSnapshot{Interface: fixture.base.Interface, Family: 4, OriginalMTU: fixture.base.MTU}, strings.Repeat("a", 32))
					if err != nil {
						t.Fatal(err)
					}
					owner := kernel.(*desktopNodeMTUOwner)
					before := owner.record
					calls := 0
					owner.verifyReaderChange = func(context.Context, desktopNodeMTURecord, desktopNodeMTURecord) error {
						calls++
						t.Fatal("unchanged native reader requested replacement proof")
						return nil
					}
					_, err = owner.RestoreContext(ctx)
					if (err == nil) != (fault == "original") {
						t.Fatal("typed rollback ACK bounds changed", fault, err)
					}
					if calls != 0 {
						t.Fatal("unchanged reader used a replacement capability")
					}
					if fault == "original" {
						if owner.record.Reader != before.Reader+1 || owner.record.Index != before.Index || !owner.record.Restored {
							t.Fatal("unchanged rollback lost exact original reader")
						}
					} else if owner.record != before {
						t.Fatal("stale or foreign ACK mutated original reader")
					}
				})
			}
		})
	}
}
