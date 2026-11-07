package mobiletor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func desktopRenewalControlMembers() []desktopSocketRenewal {
	owner := desktopSocketFixturePolicy().owner
	binding := DesktopSocketBinding{Owner: owner, InterfaceName: "fixture-owned", InterfaceIndex: 2, LocalAddress: netip.MustParseAddr("192.0.2.2")}
	var members []desktopSocketRenewal
	for index := range 2 {
		grant := DesktopSocketGrant{Capture: desktopSocketFixtureCapture(), Binding: binding, SocketID: fmt.Sprintf("%032x", index+1),
			Network: "tcp", Local: netip.AddrPortFrom(binding.LocalAddress, uint16(40000+index)), Remote: netip.MustParseAddrPort("192.0.2.1:443"), Sequence: 2}
		members = append(members, desktopSocketRenewal{context.Background(), grant})
	}
	return members
}

func desktopRenewalControlReceipts(requests []DesktopSocketGrant) []DesktopSocketReceipt {
	now := time.Now()
	receipts := make([]DesktopSocketReceipt, len(requests))
	for index, request := range requests {
		receipts[index] = DesktopSocketReceipt{request, now.UnixMilli(), now.Add(7 * time.Second).UnixMilli()}
	}
	return receipts
}

func TestDesktopSocketRenewalControlCompleteReplyInventory(t *testing.T) {
	for _, fault := range []string{"valid", "missing", "extra", "duplicate", "reordered", "capture", "owner", "socket", "sequence", "remote", "local", "interface", "future", "stale", "expired", "excess-expiry", "late-context", "unknown-error", "unsubmitted", "foreign-unsubmitted", "nonempty-unsubmitted"} {
		t.Run(fault, func(t *testing.T) {
			members := desktopRenewalControlMembers()
			policy := &desktopRenewalFixture{desktopSocketPolicyFixture: desktopSocketFixturePolicy()}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			called := 0
			results := desktopSocketControlRenewals(ctx, members, policy.enter, func(_ context.Context, requests []DesktopSocketGrant) ([]DesktopSocketReceipt, error) {
				called++
				receipts := desktopRenewalControlReceipts(requests)
				switch fault {
				case "missing":
					receipts = receipts[:1]
				case "extra":
					receipts = append(receipts, receipts[0])
				case "duplicate":
					receipts[1] = receipts[0]
				case "reordered":
					receipts[0], receipts[1] = receipts[1], receipts[0]
				case "capture":
					receipts[1].Grant.Capture.SessionID = strings.Repeat("a", 32)
				case "owner":
					receipts[1].Grant.Binding.Owner.Generation++
				case "socket":
					receipts[1].Grant.SocketID = strings.Repeat("b", 32)
				case "sequence":
					receipts[1].Grant.Sequence++
				case "remote":
					receipts[1].Grant.Remote = netip.MustParseAddrPort("192.0.2.1:444")
				case "local":
					receipts[1].Grant.Local = netip.MustParseAddrPort("192.0.2.2:45000")
				case "interface":
					receipts[1].Grant.Binding.InterfaceIndex++
				case "future":
					receipts[1].ObservedAt = time.Now().Add(time.Second).UnixMilli()
				case "stale":
					receipts[1].ObservedAt = time.Now().Add(-DesktopSocketReadbackAge - time.Millisecond).UnixMilli()
				case "expired":
					receipts[1].ExpiresAt = time.Now().Add(-time.Millisecond).UnixMilli()
				case "excess-expiry":
					receipts[1].ExpiresAt = receipts[1].ObservedAt + DesktopSocketGrantMaxAge.Milliseconds() + 1
				case "late-context":
					cancel()
				case "unknown-error":
					return nil, errors.New("modeled native transaction lost its reply")
				case "unsubmitted", "foreign-unsubmitted", "nonempty-unsubmitted":
					captured := slices.Clone(requests)
					if fault == "foreign-unsubmitted" {
						captured[0].Sequence++
					}
					err := desktopSocketUnsubmittedRenewals(captured, context.Canceled)
					if fault == "nonempty-unsubmitted" {
						return receipts, err
					}
					return nil, err
				}
				return receipts, nil
			})
			if called != 1 || len(results) != len(members) {
				t.Fatal("renewal did not retain its one captured call and result set", called, len(results))
			}
			for index, result := range results {
				if fault == "valid" {
					if result.err != nil || !validDesktopSocketReceipt(result.receipt, members[index].grant, time.Now()) {
						t.Fatal("exact renewal lost its original receipt", result.err)
					}
					continue
				}
				if result.err == nil || result.receipt != (DesktopSocketReceipt{}) {
					t.Fatal("malformed group partially authorized a member", fault, index)
				}
				var notSent *desktopSocketGrantNotSubmitted
				rollback := errors.As(result.err, &notSent)
				if rollback != (fault == "unsubmitted") || rollback && notSent.request != members[index].grant {
					t.Fatal("unknown batch result changed its exact revoke identity", fault, index)
				}
			}
		})
	}
}

func TestDesktopSocketRenewalControlRejectsUncapturedMembers(t *testing.T) {
	for _, fault := range []string{"empty", "limit", "duplicate", "duplicate-interface", "capture", "owner", "initial", "zero", "nil-context"} {
		t.Run(fault, func(t *testing.T) {
			members := desktopRenewalControlMembers()
			switch fault {
			case "empty":
				members = nil
			case "limit":
				for len(members) <= desktopSocketRenewalLimit {
					members = append(members, members[0])
				}
			case "duplicate", "duplicate-interface":
				members[1] = members[0]
				if fault == "duplicate-interface" {
					members[1].grant.Binding.InterfaceIndex++
				}
			case "capture":
				members[1].grant.Capture.NetworkID = strings.Repeat("b", 32)
			case "owner":
				members[1].grant.Binding.Owner.Generation++
			case "initial":
				members[1].grant.Sequence = 1
			case "zero":
				members[1].grant.Sequence = 0
			case "nil-context":
				members[1].context = nil
			}
			admitted := false
			results := desktopSocketControlRenewals(context.Background(), members,
				func(context.Context) (context.Context, func(), error) {
					admitted = true
					return context.Background(), func() {}, nil
				},
				func(context.Context, []DesktopSocketGrant) ([]DesktopSocketReceipt, error) {
					t.Fatal("unowned renewal reached native execution")
					return nil, nil
				})
			if admitted || len(results) != len(members) {
				t.Fatal("invalid renewal entered original FIFO", fault)
			}
			for index, result := range results {
				var notSent *desktopSocketGrantNotSubmitted
				if !errors.As(result.err, &notSent) || notSent.request != members[index].grant || result.receipt != (DesktopSocketReceipt{}) {
					t.Fatal("rejected capture lost its exact unsent identity")
				}
			}
		})
	}
}

func TestDesktopSocketRenewalControlQueuedMemberCancellation(t *testing.T) {
	for _, whole := range []bool{false, true} {
		t.Run(fmt.Sprint(whole), func(t *testing.T) {
			members := desktopRenewalControlMembers()
			memberContext, cancelMember := context.WithCancel(context.Background())
			defer cancelMember()
			members[0].context = memberContext
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			policy := &desktopRenewalFixture{desktopSocketPolicyFixture: desktopSocketFixturePolicy()}
			policy.control.Lock()
			locked := true
			defer func() {
				if locked {
					policy.control.Unlock()
				}
			}()
			called := make(chan []DesktopSocketGrant, 1)
			finished := make(chan []desktopSocketRenewalResult, 1)
			go func() {
				finished <- desktopSocketControlRenewals(ctx, members, policy.enter, func(_ context.Context, requests []DesktopSocketGrant) ([]DesktopSocketReceipt, error) {
					called <- slices.Clone(requests)
					return desktopRenewalControlReceipts(requests), nil
				})
			}()
			desktopSocketAwaitControlQueue(t, &policy.control, 1)
			cancelMember()
			if whole {
				cancel()
			}
			policy.control.Unlock()
			locked = false
			results := desktopSocketAwait(t, finished)
			if len(results) != 2 {
				t.Fatal("cancelled group omitted original owners")
			}
			for index, result := range results {
				if whole || index == 0 {
					var notSent *desktopSocketGrantNotSubmitted
					if !errors.As(result.err, &notSent) || notSent.request != members[index].grant || !errors.Is(result.err, context.Canceled) || result.receipt != (DesktopSocketReceipt{}) {
						t.Fatal("queued cancellation lost its unsent exact operation", index, result.err)
					}
				} else if result.err != nil || !validDesktopSocketReceipt(result.receipt, members[index].grant, time.Now()) {
					t.Fatal("cancelled sibling discarded the still-owned request", result.err)
				}
			}
			if whole {
				select {
				case <-called:
					t.Fatal("cancelled queued group sent native bytes")
				default:
				}
			} else {
				actual := desktopSocketAwait(t, called)
				if len(actual) != 1 || actual[0] != members[1].grant {
					t.Fatal("cancelled queued member escaped into the native group", actual)
				}
			}
			policy.control.mu.Lock()
			remaining, held := len(policy.control.waiters), policy.control.held
			policy.control.mu.Unlock()
			if remaining != 0 || held {
				t.Fatal("cancelled group retained a FIFO admission")
			}
		})
	}
}
