package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MAXEndpointResolver is one host-captured network/DNS owner. Lookup returns
// bounded JSON with owner_id, hostname, and addresses (literal IP strings).
// The receiver must use its captured resolver/network, honor Cancel, and drain
// the lookup before returning. Current and OwnerID must be concurrency-safe;
// Cancel is an idempotent cancellation signal, never a replacement lookup.
// No process-wide resolver is installed or consulted by this contract.
type MAXEndpointResolver interface {
	OwnerID() string
	Current() bool
	Lookup(hostname string) (string, error)
	Cancel()
}

var ErrMAXResolutionOwner = errors.New("MAX endpoint preparation belongs to a retired resolver owner")

// MAXResolveRequest captures one selection and one resolver receiver before a
// platform can start blocking work. Stop/network-loss callbacks cancel this
// request directly; they never consult a newer VPN or resolver instance.
type MAXResolveRequest struct {
	capture   *MAXProfileCapture
	resolver  MAXEndpointResolver
	ownerID   string
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	closed    chan struct{}
	started   atomic.Bool
	succeeded atomic.Bool
	canceled  atomic.Bool
	done      chan struct{}
}

func NewMAXResolveRequest(ctx context.Context, mode, files, metadata string, resolver MAXEndpointResolver) (*MAXResolveRequest, error) {
	if ctx == nil {
		return nil, errors.New("MAX endpoint preparation requires a captured context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	capture, err := CaptureMAXProfile(mode, files, metadata)
	if err != nil {
		return nil, err
	}
	ownerID := ""
	if resolver != nil {
		ownerID = resolver.OwnerID()
		if !exactID.MatchString(ownerID) || !resolver.Current() {
			return nil, ErrMAXResolutionOwner
		}
	} else if capture.RequiresResolution() {
		return nil, errors.New("MAX hostname requires an explicit captured resolver")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	owned, cancel := context.WithCancel(ctx)
	return &MAXResolveRequest{capture: capture, resolver: resolver, ownerID: ownerID, ctx: owned, cancel: cancel, done: make(chan struct{}), closed: make(chan struct{})}, nil
}

func (r *MAXResolveRequest) ownerCurrent() bool {
	return r != nil && !r.canceled.Load() && r.ctx.Err() == nil &&
		(r.resolver == nil || r.resolver.OwnerID() == r.ownerID && r.resolver.Current())
}

func (r *MAXResolveRequest) SourceSHA256() string {
	if r == nil || r.capture == nil {
		return ""
	}
	return r.capture.SourceSHA256()
}

func (r *MAXResolveRequest) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if !r.ownerCurrent() || r.resolver == nil || host != r.capture.Endpoint() {
		return nil, ErrMAXResolutionOwner
	}
	drained := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(drained)
		r.cancelResolver()
		<-r.closed
	})
	defer func() {
		if !stop() {
			<-drained
		}
	}()
	raw, err := r.resolver.Lookup(host)
	if canceled := ctx.Err(); canceled != nil {
		return nil, canceled
	}
	if !r.ownerCurrent() {
		return nil, ErrMAXResolutionOwner
	}
	bad := errors.New("MAX resolver returned an invalid captured-node answer")
	var answer struct {
		OwnerID   string   `json:"owner_id"`
		Hostname  string   `json:"hostname"`
		Addresses []string `json:"addresses"`
	}
	if err != nil || exactJSON([]byte(raw), &answer, 4096) != nil || answer.OwnerID != r.ownerID || answer.Hostname != host || len(answer.Addresses) == 0 || len(answer.Addresses) > 32 {
		return nil, bad
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&answer) != nil {
		return nil, bad
	}
	addresses := make([]netip.Addr, len(answer.Addresses))
	for i, value := range answer.Addresses {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return nil, bad
		}
		addresses[i] = address
	}
	return addresses, nil
}

// Run is single-use and synchronous. It returns a private launch envelope only
// after the actual lookup has drained and the literal-only compiler succeeds.
// A host rechecks Healthy and its pending source digest immediately before
// adopting the launch; neither this envelope nor a source digest is a VPN proof.
func (r *MAXResolveRequest) Run() (result string, failure error) {
	if r == nil || r.capture == nil || !r.started.CompareAndSwap(false, true) {
		return "", errors.New("MAX endpoint request is unavailable or already used")
	}
	defer close(r.done)
	defer func() {
		if failure != nil {
			r.Cancel()
			<-r.closed
		}
	}()
	if !r.ownerCurrent() {
		if err := r.ctx.Err(); err != nil {
			return "", err
		}
		return "", ErrMAXResolutionOwner
	}
	ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
	defer cancel()
	resolved, err := r.capture.Resolve(ctx, r.lookup)
	if err != nil {
		if expired := ctx.Err(); expired != nil {
			return "", expired
		}
		if !r.ownerCurrent() {
			return "", ErrMAXResolutionOwner
		}
		return "", err
	}
	if !r.ownerCurrent() {
		return "", ErrMAXResolutionOwner
	}
	envelope := struct {
		Schema       int    `json:"schema"`
		OwnerID      string `json:"owner_id"`
		SourceSHA256 string `json:"source_sha256"`
		Hostname     string `json:"hostname"`
		Endpoint     string `json:"endpoint"`
		Config       string `json:"config_json"`
		Files        string `json:"files_json"`
		Metadata     string `json:"metadata_json"`
	}{1, r.ownerID, r.SourceSHA256(), r.capture.Endpoint(), resolved.Endpoint(), resolved.Config(), resolved.Files(), resolved.Metadata()}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", errors.New("MAX launch envelope could not be encoded")
	}
	defer clear(encoded)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	r.succeeded.Store(true)
	if !r.Healthy() {
		r.succeeded.Store(false)
		return "", ErrMAXResolutionOwner
	}
	return string(encoded), nil
}

func (r *MAXResolveRequest) cancelResolver() {
	r.closeOnce.Do(func() {
		// Foreign cancellation can itself take time. Keep it in one owned
		// goroutine so the immediate STOP callback never waits on that work;
		// Run/lookup failure and Close explicitly join this exact operation.
		go func() {
			defer close(r.closed)
			if r.resolver != nil {
				r.resolver.Cancel()
			}
		}()
	})
}

func (r *MAXResolveRequest) Cancel() {
	if r != nil && r.cancel != nil && r.canceled.CompareAndSwap(false, true) {
		r.succeeded.Store(false)
		r.cancel()
		r.cancelResolver()
	}
}

// Close belongs on the serialized native worker after the immediate Cancel
// signal. It waits for every in-flight lookup and its cancellation callback;
// no fallback may start before this drain completes.
func (r *MAXResolveRequest) Close() {
	if r == nil || r.cancel == nil {
		return
	}
	r.Cancel()
	r.cancelResolver()
	<-r.closed
	if r.started.Load() {
		<-r.done
	}
}

func (r *MAXResolveRequest) Healthy() bool {
	return r != nil && r.succeeded.Load() && r.ownerCurrent()
}
