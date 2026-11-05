//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/linuxprotection"
)

// This is an original authenticated service conversation, not an engine launch
// reconstructed from a boot receipt. The service retains the actual boot guard.
type linuxStandardServiceBootTransferSource struct {
	app              *app
	parent           *desktopLinuxNodeParentCapture
	image, namespace os.FileInfo
	peer             *linuxStandardServicePeer
	protection       *linuxStandardServiceProtectionClient
	session          string
	mu               sync.Mutex
	exchange         func(context.Context, linuxStandardServiceRequest, *os.File, func()) (linuxStandardServiceResponse, error)
}

var linuxStandardBootTransfers sync.Map // *app -> original *linuxStandardServiceNodeTransfer

func captureLinuxStandardBootNodeTransfer(ctx context.Context, h *desktopLinuxNodeHost) (*linuxStandardServiceNodeTransfer, error) {
	if h == nil || h.parent == nil || h.operation == nil {
		return nil, errors.New("boot transfer lost its original Node operation")
	}
	if err := h.parent.Current(ctx); err != nil {
		return nil, err
	}
	if _, exists := linuxStandardBootTransfers.Load(h.parent.app); exists {
		return nil, errors.New("finish the original boot protection transfer first")
	}
	p := h.parent.parent
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.gate:
	}
	err := p.currentLocked(false)
	var namespace os.FileInfo
	if err == nil {
		namespace, err = p.networkNamespace.Stat()
	}
	image := p.imageInfo
	p.gate <- struct{}{}
	if err != nil {
		return nil, err
	}
	if err = desktopnetwork.LockContext(ctx, &h.parent.app.mu); err != nil {
		return nil, err
	}
	err = h.parent.app.checkCapturedConnectionOperationLocked(h.operation)
	h.parent.app.mu.Unlock()
	if err != nil {
		return nil, err
	}
	id, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	session, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return nil, errors.New("boot transfer requires original startup deadline")
	}
	if bound := time.Now().Add(120 * time.Second); bound.Before(deadline) {
		deadline = bound
	}
	deadline = deadline.Add(-2 * time.Millisecond)
	if !time.Now().Before(deadline) {
		return nil, context.DeadlineExceeded
	}
	source := &linuxStandardServiceBootTransferSource{app: h.parent.app, parent: h.parent, image: image, namespace: namespace, session: session}
	// Reuse a previously authenticated original service generation when a
	// protection view already retained it. Its owner keeps the peer lifetime.
	if raw, exists := linuxStandardServiceProtectionClients.Load(source.app); exists {
		client, ok := raw.(*linuxStandardServiceProtectionClient)
		if !ok || client == nil || client.app != source.app || client.controller != h.parent.controller {
			return nil, errors.New("boot capture found another protection client")
		}
		if err := desktopnetwork.LockContext(ctx, &client.mu); err != nil {
			return nil, err
		}
		if client.peer != nil {
			source.protection = client
			source.peer = client.peer
		}
		client.mu.Unlock()
	}
	t := &linuxStandardServiceNodeTransfer{boot: source, host: h, operation: h.operation, request: linuxStandardServiceTransferRequest{Boot: true, ID: id, DeadlineNS: deadline.UnixNano(), Destination: h.selection, ProfileID: desktopExternalPathProfileID(h.launch), ProfileRevision: h.revision}}
	t.mu.Lock()
	defer t.mu.Unlock()
	source.mu.Lock()
	defer source.mu.Unlock()
	if _, loaded := linuxStandardBootTransfers.LoadOrStore(source.app, t); loaded {
		return nil, errors.New("boot transfer replaced an unresolved original capture")
	}
	h.standardTransfer = t // Retain before the authenticated request can be sent.
	response, err := t.rpcLocked(ctx, "transfer-reserve", nil, nil)
	// Optional service absence never proves native policy absence. No request
	// was sent, and normal Node admission retains its independent native gate.
	if err != nil && !t.attempted && source.peer == nil && errors.Is(err, os.ErrNotExist) {
		if cleanup := t.finishBootSourceLocked(); cleanup != nil {
			return t, errors.Join(err, cleanup)
		}
		t.resolved.Store(true)
		h.standardTransfer = nil
		return nil, ctx.Err()
	}
	if err == nil && response.NoBoot {
		err = t.finishBootSourceLocked()
		if err == nil {
			t.resolved.Store(true)
			h.standardTransfer = nil
			return nil, ctx.Err()
		}
	}
	return t, err
}

func (t *linuxStandardServiceNodeTransfer) sourceMutex() *sync.Mutex {
	if t.boot != nil {
		return &t.boot.mu
	}
	return &t.owner.mu
}
func (t *linuxStandardServiceNodeTransfer) matchesSourceIntent(intent linuxprotection.StandardNodeTransfer) bool {
	if t.boot != nil {
		return t.owner == nil && t.request.Boot
	}
	return t.owner != nil && !t.request.Boot && intent.SourceSession == t.owner.request.Session && intent.SourceConfigSHA256 == t.owner.request.ConfigSHA256
}
func (t *linuxStandardServiceNodeTransfer) exchangeSourceLocked(ctx context.Context, action string, q *linuxStandardServiceTransferRequest) (linuxStandardServiceResponse, error) {
	request := linuxStandardServiceRequest{Schema: 1, Action: action, Transfer: q}
	if t.boot != nil {
		b := t.boot
		raw, present := linuxStandardBootTransfers.Load(b.app)
		if !present || raw != t || t.owner != nil || !q.Boot || b.parent != t.host.parent {
			return linuxStandardServiceResponse{}, errors.New("boot transfer lost its original controller capture")
		}
		if err := b.parent.retirementCurrent(ctx); err != nil {
			return linuxStandardServiceResponse{}, err
		}
		request.Session = b.session
		if b.protection != nil {
			client := b.protection
			if err := desktopnetwork.LockContext(ctx, &client.mu); err != nil {
				return linuxStandardServiceResponse{}, err
			}
			defer client.mu.Unlock()
			raw, present := linuxStandardServiceProtectionClients.Load(b.app)
			if !present || raw != client || client.peer != b.peer || b.peer == nil {
				return linuxStandardServiceResponse{}, errors.New("boot transfer changed its retained protection-view peer")
			}
			return linuxStandardServiceRPC(ctx, client.image, client.namespace, &client.peer, request, nil, func() { t.attempted = true })
		}
		exchange := b.exchange
		if exchange == nil {
			exchange = func(ctx context.Context, r linuxStandardServiceRequest, _ *os.File, before func()) (linuxStandardServiceResponse, error) {
				return linuxStandardServiceRPC(ctx, b.image, b.namespace, &b.peer, r, nil, before)
			}
		}
		return exchange(ctx, request, nil, func() { t.attempted = true })
	}
	o := t.owner
	if o == nil {
		return linuxStandardServiceResponse{}, errors.New("transfer lost its actual source")
	}
	raw, ok := linuxStandardServiceOwners.Load(o.app)
	if !ok || raw != o || o.transfer != t || o.peer == nil || q.Boot {
		return linuxStandardServiceResponse{}, errors.New("transfer lost its original controller/service owner")
	}
	request.Session = o.request.Session
	exchange := o.exchange
	if exchange == nil {
		exchange = func(ctx context.Context, r linuxStandardServiceRequest, directory *os.File, before func()) (linuxStandardServiceResponse, error) {
			return linuxStandardServiceRPC(ctx, o.image, o.prepared.namespaceInfo, &o.peer, r, directory, before)
		}
	}
	return exchange(ctx, request, nil, func() { t.attempted = true })
}
func (t *linuxStandardServiceNodeTransfer) finishBootSourceLocked() error {
	b := t.boot
	if b == nil {
		return errors.New("boot settlement has no original service capture")
	}
	if b.peer != nil && b.protection == nil {
		if err := b.peer.Close(); err != nil {
			return err
		}
		b.peer = nil
	}
	if !linuxStandardBootTransfers.CompareAndDelete(b.app, t) {
		return errors.New("boot settlement replaced original controller registration")
	}
	return nil
}
