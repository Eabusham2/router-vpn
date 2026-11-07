//go:build darwin && routervpn_darwin_guardian

package mobiletor

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Execute the same captured operation used by the monitor against the actual
// independently running privileged guardian. Only selection of this one due
// group is explicit; no receipt, descriptor identity or PF readback is modeled.
func desktopDarwinRenewOriginalGroup(t *testing.T, broker *DesktopSocketBroker, policy *DesktopDarwinSocketPolicy, sockets []*desktopSocket) []DesktopSocketReceipt {
	t.Helper()
	var group []desktopSocketRenewalPeer
	var expected []DesktopSocketGrant
	accepted := false
	defer func() {
		if !accepted {
			for _, member := range group {
				member.peer.mu.Lock()
				member.peer.applying = false
				member.peer.mu.Unlock()
				member.peer.op.Unlock()
				member.socket.io.Done()
			}
		}
	}()
	for _, socket := range sockets {
		socket.mu.Lock()
		peer := socket.peers[socket.remote]
		socket.mu.Unlock()
		peer.op.Lock()
		if err := socket.beginIO(); err != nil {
			peer.op.Unlock()
			t.Fatal("native renewal lost its original live descriptor", err)
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
			t.Fatal("native renewal did not retain a fresh acknowledged original")
		}
		group = append(group, desktopSocketRenewalPeer{socket, peer, until, grant.Remote})
		grant.Sequence++
		expected = append(expected, grant)
	}
	accepted = true
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
