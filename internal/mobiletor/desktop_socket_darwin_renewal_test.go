//go:build darwin && routervpn_darwin_guardian

package mobiletor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// Execute the same captured operation used by the monitor against the actual
// independently running privileged guardian. Only selection of this one due
// group is explicit; no receipt, descriptor identity or PF readback is modeled.
// Manual native evidence uses the same exclusive renewal slot as the monitor.
// Never hold one parent operation while waiting for a child's in-flight renewal:
// the monitor must remain free to renew the complete original family meanwhile.
func desktopDarwinCaptureOriginalRenewalGroup(ctx context.Context, broker *DesktopSocketBroker, sockets []*desktopSocket) ([]desktopSocketRenewalPeer, []DesktopSocketGrant, func(), error) {
	if ctx == nil || len(sockets) == 0 || len(sockets) > desktopSocketRenewalLimit {
		return nil, nil, nil, errors.New("native renewal capture requires its bounded original group")
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}
		broker.mu.Lock()
		closing, busy := broker.closing, broker.renewing
		if !closing && !busy {
			broker.renewing = true
		}
		broker.mu.Unlock()
		if closing {
			return nil, nil, nil, net.ErrClosed
		}
		if !busy {
			release := func() { broker.mu.Lock(); broker.renewing = false; broker.mu.Unlock() }
			var group []desktopSocketRenewalPeer
			var expected []DesktopSocketGrant
			var failure error
			for _, socket := range sockets {
				socket.mu.Lock()
				peer := socket.peers[socket.remote]
				socket.mu.Unlock()
				if peer == nil {
					failure = errors.New("native renewal lost its original peer")
					break
				}
				if !peer.op.TryLock() {
					break
				}
				if err := socket.beginIO(); err != nil {
					peer.op.Unlock()
					failure = err
					break
				}
				peer.mu.Lock()
				valid := peer.valid && !peer.applying && validDesktopSocketReceipt(peer.receipt, peer.request, time.Now())
				grant, until := peer.request, desktopSocketRenewalUntil(peer.receipt)
				if valid {
					peer.applying = true
				}
				peer.mu.Unlock()
				if !valid {
					peer.op.Unlock()
					socket.io.Done()
					failure = errors.New("native renewal lost its fresh acknowledged original")
					break
				}
				group = append(group, desktopSocketRenewalPeer{socket, peer, until, grant.Remote})
				grant.Sequence++
				expected = append(expected, grant)
			}
			if len(group) == len(sockets) && ctx.Err() == nil {
				return group, expected, release, nil
			}
			for _, member := range group {
				member.peer.mu.Lock()
				member.peer.applying = false
				member.peer.mu.Unlock()
				member.peer.op.Unlock()
				member.socket.io.Done()
			}
			release()
			if failure != nil {
				return nil, nil, nil, failure
			}
		}
		// This waits only for original ownership admission, never for a second
		// native attempt. Receipt clocks remain untouched and still expire.
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, nil, nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func desktopDarwinRenewOriginalGroup(t *testing.T, broker *DesktopSocketBroker, policy *DesktopDarwinSocketPolicy, sockets []*desktopSocket) []DesktopSocketReceipt {
	t.Helper()
	ctx, cancel := context.WithTimeout(broker.ctx, desktopSocketControlWait)
	defer cancel()
	group, expected, release, err := desktopDarwinCaptureOriginalRenewalGroup(ctx, broker, sockets)
	if err != nil {
		t.Fatal("native renewal could not capture its complete original group", err)
	}
	defer release()
	broker.applyRenewals(policy, group)
	receipts := make([]DesktopSocketReceipt, len(group))
	for index, member := range group {
		receipt, valid := member.peer.snapshot()
		if !valid || !validDesktopSocketReceipt(receipt, expected[index], time.Now()) || !member.socket.allowed(member.socket.remote) {
			t.Fatal("actual native renewal did not acknowledge every exact original tuple", index, member.socket.admission.first.Load())
		}
		if index > 0 && receipt.ObservedAt != receipts[0].ObservedAt {
			t.Fatal("native group did not share its completed original PF transaction")
		}
		receipts[index] = receipt
	}
	return receipts
}

func desktopDarwinRenewalAuthorityControls(t *testing.T, capture func() *desktopDarwinGuardian, parent, child, sibling *desktopSocket) {
	t.Helper()
	for _, fault := range []string{"empty", "limit", "duplicate", "capture", "sequence", "initial", "receipt", "identity", "child-before-parent", "parent-receipt", "parent-expired", "cancelled"} {
		g := capture()
		parentGrant := g.sockets[parent.id].grants[parent.remote.String()]
		childGrant := g.sockets[child.id].grants[child.remote.String()]
		siblingGrant := g.sockets[sibling.id].grants[sibling.remote.String()]
		parentGrant.Sequence++
		childGrant.Sequence++
		siblingGrant.Sequence++
		requests := []DesktopSocketGrant{parentGrant, siblingGrant, childGrant}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		switch fault {
		case "empty":
			requests = nil
		case "limit":
			for len(requests) <= desktopSocketRenewalLimit {
				requests = append(requests, parentGrant)
			}
		case "duplicate":
			requests = append(requests, requests[0])
		case "capture":
			requests[0].Capture.NetworkID = strings.Repeat("a", 32)
		case "sequence":
			requests[0].Sequence++
		case "initial":
			requests[0].Sequence = 1
		case "receipt":
			delete(g.sockets[parent.id].receipts, parent.remote.String())
		case "identity":
			g.sockets[parent.id].identity.socket ^= 1
		case "child-before-parent":
			requests = []DesktopSocketGrant{childGrant, parentGrant}
		case "parent-receipt":
			delete(g.sockets[parent.id].receipts, parent.remote.String())
			requests = []DesktopSocketGrant{childGrant}
		case "parent-expired":
			original := g.sockets[parent.id].grants[parent.remote.String()]
			permit := g.pf.permits[g.pf.key(original)]
			permit.Expires = time.Now().Add(-time.Millisecond)
			g.pf.permits[g.pf.key(original)] = permit
			requests = []DesktopSocketGrant{childGrant}
		case "cancelled":
			cancel()
		}
		permits := maps.Clone(g.pf.permits)
		grants := make(map[string]map[string]DesktopSocketGrant)
		receipts := make(map[string]map[string]DesktopSocketReceipt)
		for id, socket := range g.sockets {
			grants[id] = maps.Clone(socket.grants)
			receipts[id] = maps.Clone(socket.receipts)
		}
		actual, err := g.renew(ctx, requests)
		cancel()
		if err == nil || len(actual) != 0 {
			t.Fatal("native renewal accepted a malformed original group", fault, err)
		}
		if !reflect.DeepEqual(permits, g.pf.permits) {
			t.Fatal("rejected native renewal changed PF attempt identities", fault)
		}
		for id, socket := range g.sockets {
			if !reflect.DeepEqual(grants[id], socket.grants) || !reflect.DeepEqual(receipts[id], socket.receipts) {
				t.Fatal("rejected native renewal partially authorized an original member", fault, id)
			}
		}
	}
}

func desktopDarwinRenewalFrameControls(t *testing.T, receipt DesktopSocketReceipt) {
	t.Helper()
	var requests []DesktopSocketGrant
	for index := range desktopSocketRenewalLimit {
		grant := receipt.Grant
		grant.SocketID = fmt.Sprintf("%032x", index+1)
		grant.Binding.InterfaceName = strings.Repeat("i", 15)
		grant.Binding.InterfaceIndex = ^uint32(0)
		grant.Binding.Owner.Generation = ^uint64(0)
		grant.Binding.Owner.ProcessID = ^uint32(0)
		grant.Sequence = ^uint64(0)
		grant.Local = netip.MustParseAddrPort("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe]:65535")
		grant.Remote = netip.MustParseAddrPort("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")
		grant.Binding.LocalAddress = grant.Local.Addr()
		requests = append(requests, grant)
	}
	request := desktopDarwinRequest{Operation: "renew", Sequence: 42, Capture: receipt.Grant.Capture, Renewals: requests}
	if !desktopDarwinRenewalFrame(request) {
		t.Fatal("bounded native renewal frame was rejected")
	}
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) > 32<<10 {
		t.Fatal("renewal request exceeds original authenticated frame bound", len(encoded), err)
	}
	reply := desktopDarwinReply{Sequence: request.Sequence, Capture: request.Capture}
	for _, grant := range requests {
		changed := receipt
		changed.Grant = grant
		reply.Receipts = append(reply.Receipts, changed)
	}
	encoded, err = json.Marshal(reply)
	if err != nil || len(encoded) > 32<<10 {
		t.Fatal("renewal receipt set exceeds original authenticated frame bound", len(encoded), err)
	}
	for _, fault := range []string{"empty", "limit", "operation", "creation", "grant", "socks", "tunnel", "index", "interfaces", "destinations", "lan"} {
		changed := request
		switch fault {
		case "empty":
			changed.Renewals = nil
		case "limit":
			changed.Renewals = append(append([]DesktopSocketGrant{}, requests...), requests[0])
		case "operation":
			changed.Operation = "grant"
		case "creation":
			changed.Creation.SocketID = receipt.Grant.SocketID
		case "grant":
			changed.Grant = receipt.Grant
		case "socks":
			changed.SOCKS = &desktopDarwinSOCKSAssociation{}
		case "tunnel":
			changed.Tunnel = "utun1"
		case "index":
			changed.Index = 1
		case "interfaces":
			changed.Options.Interfaces = []DesktopDarwinSocketInterface{{}}
		case "destinations":
			changed.Options.PrivateDestinations = []DesktopDarwinSocketDestination{{}}
		case "lan":
			changed.Options.LANPrefixes = []netip.Prefix{{}}
		}
		if desktopDarwinRenewalFrame(changed) {
			t.Fatal("native renewal frame borrowed another operation's authority", fault)
		}
	}
}

// The actual fixture capture runs with modeled native policy only. A busy child
// and an existing monitor transaction must never pin an earlier parent lease.
func TestDesktopDarwinGuardianRenewalCaptureOwnership(t *testing.T) {
	for _, fault := range []string{"ready", "held-child", "joined-child", "active-monitor", "cancelled", "stale"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				broker := &DesktopSocketBroker{ctx: ctx, current: func() bool { return true }, policy: desktopSocketFixturePolicy()}
				remote := netip.MustParseAddrPort("192.0.2.1:443")
				grant := DesktopSocketGrant{Sequence: 3, Remote: remote}
				receipt := DesktopSocketReceipt{Grant: grant, ObservedAt: time.Now().UnixMilli(), ExpiresAt: time.Now().Add(7 * time.Second).UnixMilli()}
				first, child := &desktopSocketPeer{request: grant, receipt: receipt, valid: true}, &desktopSocketPeer{request: grant, receipt: receipt, valid: true}
				sockets := []*desktopSocket{{ctx: ctx, broker: broker, remote: remote, peers: map[netip.AddrPort]*desktopSocketPeer{remote: first}}, {ctx: ctx, broker: broker, remote: remote, peers: map[netip.AddrPort]*desktopSocketPeer{remote: child}}}
				if fault == "held-child" || fault == "joined-child" {
					child.op.Lock()
				}
				if fault == "active-monitor" {
					broker.renewing = true
				}
				if fault == "cancelled" {
					cancel()
				}
				if fault == "stale" {
					child.receipt.ObservedAt = time.Now().Add(-DesktopSocketReadbackAge - time.Millisecond).UnixMilli()
				}
				done := make(chan error, 1)
				go func() {
					group, expected, release, err := desktopDarwinCaptureOriginalRenewalGroup(ctx, broker, sockets)
					if err == nil {
						if len(group) != 2 || len(expected) != 2 || expected[0].Sequence != 4 || expected[1].Sequence != 4 {
							err = errors.New("fixture changed the complete original renewal inventory")
						}
						for _, member := range group {
							member.peer.mu.Lock()
							member.peer.applying = false
							member.peer.mu.Unlock()
							member.peer.op.Unlock()
							member.socket.io.Done()
						}
						release()
					}
					done <- err
				}()
				synctest.Wait()
				if !first.op.TryLock() {
					t.Fatal("fixture capture pinned the original parent while waiting for a child")
				}
				first.op.Unlock()
				first.mu.Lock()
				applying := first.applying
				unchanged := first.receipt == receipt && first.request == grant
				first.mu.Unlock()
				if applying || !unchanged {
					t.Fatal("fixture wait changed original receipt or retained partial parent ownership")
				}
				if fault == "held-child" || fault == "joined-child" || fault == "active-monitor" {
					select {
					case err := <-done:
						t.Fatal("capture bypassed original active owner", err)
					default:
					}
					broker.mu.Lock()
					busy := broker.renewing
					broker.mu.Unlock()
					if busy != (fault == "active-monitor") {
						t.Fatal("fixture borrowed or retained the monitor renewal slot")
					}
					if fault != "joined-child" {
						cancel()
					}
					if fault == "held-child" || fault == "joined-child" {
						child.op.Unlock()
					}
				}
				if err := <-done; (err == nil) != (fault == "ready" || fault == "joined-child") {
					t.Fatal("capture changed original ownership acceptance", err)
				}
				if fault == "active-monitor" {
					broker.renewing = false
				}
				sockets[0].io.Wait()
				sockets[1].io.Wait()
			})
		})
	}
}
