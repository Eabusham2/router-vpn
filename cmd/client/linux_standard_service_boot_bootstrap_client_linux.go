//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
)

type linuxStandardBootBootstrapClient struct {
	mu                  sync.Mutex
	app                 *app
	parent              *desktopLinuxNodeParentCapture
	operation           context.Context
	image, namespace    os.FileInfo
	peer                *linuxStandardServicePeer
	protection          *linuxStandardServiceProtectionClient
	session             string
	request             linuxStandardBootBootstrapRequest
	attempted           bool
	complete            bool
	cleanupAcknowledged bool
	consumed            atomic.Bool
	closed              atomic.Bool
	addresses           []netip.Addr
}

var linuxStandardBootBootstraps sync.Map // *app -> exact original conversation
func (b *linuxStandardBootBootstrapClient) rpc(ctx context.Context, action string) (linuxStandardServiceResponse, error) {
	if e := b.parent.retirementCurrent(ctx); e != nil {
		return linuxStandardServiceResponse{}, e
	}
	request := linuxStandardServiceRequest{Schema: 1, Action: action, Session: b.session, Bootstrap: &b.request}
	before := func() { b.attempted = true }
	if b.protection != nil {
		p := b.protection
		if e := desktopnetwork.LockContext(ctx, &p.mu); e != nil {
			return linuxStandardServiceResponse{}, e
		}
		defer p.mu.Unlock()
		if p.peer != b.peer || p.controller != b.parent.controller {
			return linuxStandardServiceResponse{}, errors.New("bootstrap lost its captured service protection peer")
		}
		return linuxStandardServiceRPC(ctx, b.image, b.namespace, &p.peer, request, nil, before)
	}
	return linuxStandardServiceRPC(ctx, b.image, b.namespace, &b.peer, request, nil, before)
}
func (b *linuxStandardBootBootstrapClient) forget(ctx context.Context) error {
	if b.consumed.Load() || b.closed.Load() {
		return nil
	}
	if original, ok := linuxStandardBootBootstraps.Load(b.app); !ok || original != b {
		return errors.New("bootstrap original registration changed before retirement")
	}
	if b.peer != nil && b.protection == nil {
		if e := b.peer.CloseContext(ctx); e != nil {
			return e
		}
		b.peer = nil
	}
	if e := b.releaseParent(ctx); e != nil {
		return e
	}
	if !linuxStandardBootBootstraps.CompareAndDelete(b.app, b) {
		return errors.New("bootstrap original registration changed")
	}
	b.closed.Store(true)
	return nil
}
func (b *linuxStandardBootBootstrapClient) cleanup(ctx context.Context) error {
	if b == nil || b.consumed.Load() || b.closed.Load() {
		return nil
	}
	if e := desktopnetwork.LockContext(ctx, &b.mu); e != nil {
		return e
	}
	defer b.mu.Unlock()
	if b.consumed.Load() || b.closed.Load() {
		return nil
	}
	if !b.attempted || b.cleanupAcknowledged {
		return b.forget(ctx)
	}
	response, e := b.rpc(ctx, "boot-bootstrap-cleanup")
	if e != nil {
		return e
	}
	if response.Bootstrap == nil || response.Bootstrap.ID != b.request.ID || !response.Bootstrap.Clean || len(response.Bootstrap.Addresses) != 0 {
		return errors.New("bootstrap cleanup lacks exact service acknowledgement")
	}
	b.cleanupAcknowledged = true
	return b.forget(ctx)
}
func captureLinuxBootBootstrapClient(ctx context.Context, a *app, parent *desktopLinuxNodeParentCapture, operation context.Context, profile common.RouterProfile, mode, network string) (*linuxStandardBootBootstrapClient, error) {
	if previous, ok := linuxStandardBootBootstraps.Load(a); ok {
		p, ok := previous.(*linuxStandardBootBootstrapClient)
		if !ok || p == nil {
			return nil, errors.New("bootstrap original registration malformed")
		}
		if e := p.cleanup(ctx); e != nil {
			return nil, e
		}
	}
	if e := parent.Current(ctx); e != nil {
		return nil, e
	}
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil {
		return nil, errors.Join(ctx.Err(), errors.New("bootstrap omitted its original deadline"))
	}
	p := parent.parent
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.gate:
	}
	e := p.currentLocked(false)
	var ns os.FileInfo
	if e == nil {
		ns, e = p.networkNamespace.Stat()
	}
	image := p.imageInfo
	p.gate <- struct{}{}
	if e != nil {
		return nil, e
	}
	id, e := randomHex(16)
	if e != nil {
		return nil, e
	}
	session, e := randomHex(16)
	if e != nil {
		return nil, e
	}
	// The service RPC's millisecond budget rounds down; retain a slightly earlier
	// absolute work stamp once, rather than extending it on subsequent calls.
	stamp := deadline.Add(-2 * time.Millisecond)
	if !time.Now().Before(stamp) {
		return nil, context.DeadlineExceeded
	}
	b := &linuxStandardBootBootstrapClient{app: a, parent: parent, operation: operation, image: image, namespace: ns, session: session, request: linuxStandardBootBootstrapRequest{ID: id, DeadlineNS: stamp.UnixNano(), ProfileID: profile.ID, ProfileRevision: desktopOwnedNodeProfileToken(profile), Mode: mode, Hostname: profile.Endpoint, NetworkID: network}}
	if raw, ok := linuxStandardServiceProtectionClients.Load(a); ok {
		client, ok := raw.(*linuxStandardServiceProtectionClient)
		if !ok || client == nil || client.controller != parent.controller {
			return nil, errors.New("bootstrap found another protection client")
		}
		if e = desktopnetwork.LockContext(ctx, &client.mu); e != nil {
			return nil, e
		}
		if client.peer != nil {
			b.protection = client
			b.peer = client.peer
		}
		client.mu.Unlock()
	}
	// Publish the cleanup dependency while original parent admission is fenced.
	// Shutdown snapshots these owners before canceling the native parent.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.gate:
	}
	defer func() { p.gate <- struct{}{} }()
	if e := p.currentLocked(true); e != nil {
		return nil, e
	}
	if _, loaded := linuxStandardBootBootstraps.LoadOrStore(a, b); loaded {
		return nil, errors.New("bootstrap cannot replace original registration")
	}
	if p.dependents == nil {
		p.dependents = make(map[ownedDesktopNodeParent]struct{})
	}
	p.dependents[b] = struct{}{}
	return b, nil
}
func (b *linuxStandardBootBootstrapClient) lookup(ctx context.Context, name string) (addresses []netip.Addr, handled bool, failure error) {
	if e := desktopnetwork.LockContext(ctx, &b.mu); e != nil {
		return nil, true, e
	}
	defer b.mu.Unlock()
	if b.closed.Load() || b.consumed.Load() || name != b.request.Hostname || b.operation.Err() != nil {
		return nil, true, errors.New("bootstrap changed original outer hostname or operation")
	}
	work, cancel := context.WithDeadline(ctx, time.Unix(0, b.request.DeadlineNS))
	defer cancel()
	// Keep the transport envelope deadline at ctx's original bound: the inner
	// immutable work stamp remains earlier despite millisecond wire rounding.
	response, e := b.rpc(ctx, "boot-bootstrap")
	if e != nil && b.unsentAbsent(response, e) {
		return nil, false, b.forget(ctx)
	}
	if e != nil {
		return nil, true, e
	}
	r := response.Bootstrap
	if r == nil || r.ID != b.request.ID || !r.Clean {
		return nil, true, errors.New("bootstrap lacks original clean response")
	}
	if r.NoBoot {
		if len(r.Addresses) != 0 {
			return nil, true, errors.New("missing boot reply supplied addresses")
		}
		b.cleanupAcknowledged = true
		return nil, false, b.forget(ctx)
	}
	if len(r.Addresses) == 0 || len(r.Addresses) > 32 {
		return nil, true, errors.New("bootstrap answer bounds changed")
	}
	seen := map[netip.Addr]bool{}
	for _, raw := range r.Addresses {
		ip, e := netip.ParseAddr(raw)
		if e != nil || ip.String() != raw || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.Is4In6() || ip.Zone() != "" || seen[ip] {
			return nil, true, errors.New("bootstrap returned an unusable or repeated address")
		}
		seen[ip] = true
		addresses = append(addresses, ip)
	}
	if e = work.Err(); e != nil {
		return nil, true, e
	}
	b.complete = true
	b.addresses = append([]netip.Addr(nil), addresses...)
	return addresses, true, nil
}

func (b *linuxStandardBootBootstrapClient) bindTransferLocked(ctx context.Context, h *desktopLinuxNodeHost, source *linuxStandardServiceBootTransferSource) (*linuxStandardBootBootstrapBinding, error) {
	if b == nil || b.closed.Load() || b.consumed.Load() || !b.complete || b.peer == nil || b.parent != h.parent || b.operation != h.operation || b.request.ProfileID != h.launch.profileID || b.request.ProfileRevision != h.revision || time.Now().UnixNano() >= b.request.DeadlineNS {
		return nil, errors.New("boot transfer lost its original completed hostname bootstrap")
	}
	if raw, ok := linuxStandardBootBootstraps.Load(b.app); !ok || raw != b {
		return nil, errors.New("bootstrap registration changed before transfer")
	}
	if e := b.peer.Current(ctx); e != nil {
		return nil, e
	}
	network, e := physicalNetworkIdentityContext(ctx)
	if e != nil || network != b.request.NetworkID {
		return nil, errors.Join(e, errors.New("bootstrap physical path changed before transfer"))
	}
	address, e := netip.ParseAddr(h.launch.endpoint)
	if e != nil {
		return nil, e
	}
	found := false
	for _, ip := range b.addresses {
		found = found || ip == address
	}
	if !found {
		return nil, errors.New("transfer adopted an uncaptured bootstrap address")
	}
	source.peer = b.peer
	source.protection = b.protection
	return &linuxStandardBootBootstrapBinding{ID: b.request.ID, Address: address.String()}, nil
}
func (b *linuxStandardBootBootstrapClient) consumeTransferLocked(ctx context.Context) error {
	if !linuxStandardBootBootstraps.CompareAndDelete(b.app, b) {
		return errors.New("bootstrap transfer lost original registration")
	}
	b.consumed.Store(true)
	return b.releaseParent(ctx)
}

// Close joins only this original bootstrap before parent cancellation. After
// transfer consumption the successor owns the peer; only detach our dependency.
func (b *linuxStandardBootBootstrapClient) Close(ctx context.Context) error {
	if b == nil {
		return nil
	}
	if e := b.cleanup(ctx); e != nil {
		return e
	}
	if b.consumed.Load() {
		return b.releaseParent(ctx)
	}
	return nil
}
func (b *linuxStandardBootBootstrapClient) unsentAbsent(response linuxStandardServiceResponse, failure error) bool {
	if b.attempted || b.peer != nil || response.unconnectedSocket == "" {
		return false
	}
	operation, ok := failure.(*net.OpError)
	if !ok || operation.Op != "dial" || operation.Net != "unixpacket" {
		return false
	}
	address, ok := operation.Addr.(*net.UnixAddr)
	if !ok || address.Name != response.unconnectedSocket || address.Net != "unixpacket" {
		return false
	}
	call, ok := operation.Err.(*os.SyscallError)
	return ok && call.Syscall == "connect" && call.Err == syscall.ENOENT
}

func (b *linuxStandardBootBootstrapClient) releaseParent(ctx context.Context) error {
	if b == nil || b.parent == nil || b.parent.parent == nil {
		return errors.New("bootstrap lost its original parent dependency")
	}
	return b.parent.parent.releaseDependent(ctx, b)
}
