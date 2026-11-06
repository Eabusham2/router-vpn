//go:build windows && routervpn_windows_node_composition

package mobiletor

// This file is installed only by the explicit Go test overlay. The production
// constructors have no scope switch. Every native rule here additionally
// matches the actual subject test executable; the separately retained peer
// executable remains outside that scope.
import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

var desktopWindowsNodeComposition struct {
	sync.Mutex
	owner *DesktopWindowsSocketPolicy
	calls int
}

type DesktopWindowsNodeCompositionReadback struct {
	Target      DesktopWindowsProtectionTarget
	Capture     DesktopSocketCapture
	Owner       DesktopSocketKernelOwner
	Options     DesktopWindowsSocketOptions
	Grants      []DesktopSocketGrant
	Calls       int
	Closed      bool
	TunnelName  string
	TunnelIndex uint32
	TunnelLUID  uint64
}

func DesktopWindowsNodeCompositionAppID() ([]byte, error) {
	api, err := desktopWindowsIdentityNativeAPI()
	if err != nil {
		return nil, err
	}
	return api.executableAppID()
}

func desktopWindowsNodeCompositionConstruct(ctx context.Context, capture DesktopSocketCapture, options DesktopWindowsSocketOptions, predecessor *DesktopWindowsProtectionTarget, exact bool) (*DesktopWindowsSocketPolicy, error) {
	return desktopWindowsNodeCompositionCaptured(ctx, capture, options, predecessor, exact, nil)
}

func desktopWindowsNodeCompositionWithBarrier(ctx context.Context, capture DesktopSocketCapture, options DesktopWindowsSocketOptions, predecessor *DesktopWindowsProtectionTarget, barrier DesktopWindowsProtectionCommitBarrier) (*DesktopWindowsSocketPolicy, error) {
	if barrier == nil {
		return nil, errors.New("external composition lost its durable intent capability")
	}
	return desktopWindowsNodeCompositionCaptured(ctx, capture, options, predecessor, true, barrier)
}

func desktopWindowsNodeCompositionCaptured(ctx context.Context, capture DesktopSocketCapture, options DesktopWindowsSocketOptions, predecessor *DesktopWindowsProtectionTarget, exact bool, barrier DesktopWindowsProtectionCommitBarrier) (*DesktopWindowsSocketPolicy, error) {
	scope, err := DesktopWindowsNodeCompositionAppID()
	if err != nil || len(scope) == 0 {
		return nil, errors.Join(err, errors.New("Node composition has no actual executable scope"))
	}
	desktopWindowsNodeComposition.Lock()
	defer desktopWindowsNodeComposition.Unlock()
	if previous := desktopWindowsNodeComposition.owner; previous != nil {
		joined, err := desktopWindowsPolicyCall(previous, ctx, true, func() (bool, error) { return previous.closed, nil })
		if err != nil || !joined {
			return nil, errors.Join(err, errors.New("Node composition cannot replace an unjoined source"))
		}
	}
	var owned *DesktopWindowsSocketPolicy
	if exact && barrier != nil {
		owned, err = newDesktopWindowsSocketPolicySuccessorWithBarrier(ctx, capture, options, predecessor, scope, barrier)
	} else if exact {
		owned, err = newDesktopWindowsSocketPolicySuccessor(ctx, capture, options, predecessor, scope)
	} else {
		// Preserve legacy constructor behavior for a deliberate production
		// mutant without ever allowing that mutant to lose test-only scope.
		owned, err = newDesktopWindowsSocketPolicy(ctx, capture, options, scope)
	}
	if owned != nil {
		desktopWindowsNodeComposition.owner = owned
	}
	desktopWindowsNodeComposition.calls++
	return owned, err
}

func DesktopWindowsNodeCompositionSnapshot(ctx context.Context) (DesktopWindowsNodeCompositionReadback, error) {
	desktopWindowsNodeComposition.Lock()
	p, calls := desktopWindowsNodeComposition.owner, desktopWindowsNodeComposition.calls
	desktopWindowsNodeComposition.Unlock()
	if p == nil {
		return DesktopWindowsNodeCompositionReadback{}, errors.New("Node composition constructor has not run")
	}
	return desktopWindowsPolicyCall(p, ctx, true, func() (DesktopWindowsNodeCompositionReadback, error) {
		result := DesktopWindowsNodeCompositionReadback{Capture: p.capture, Owner: p.owner, Options: p.options, Calls: calls, Closed: p.closed,
			Target:     desktopWindowsProtectionTarget(p.capture, p.options.KillSwitchPolicy, p.metadata),
			TunnelName: p.tunnelName, TunnelIndex: p.tunnelIndex, TunnelLUID: p.tunnelLUID}
		result.Options.Interfaces = append([]DesktopWindowsSocketInterface(nil), p.options.Interfaces...)
		result.Options.PrivateDestinations = append([]DesktopWindowsSocketDestination(nil), p.options.PrivateDestinations...)
		result.Options.LANPrefixes = append(result.Options.LANPrefixes[:0:0], p.options.LANPrefixes...)
		result.Options.DHCP4Servers = append(result.Options.DHCP4Servers[:0:0], p.options.DHCP4Servers...)
		if p.closed {
			if len(p.permits) != 0 || len(p.bindings) != 0 || len(p.tunnel) != 0 || p.locked || !p.installed || !p.baselineDone {
				return result, errors.New("Node composition close did not retain exactly its drained deny baseline")
			}
			return result, readDesktopWindowsRetainedProtection(ctx, result.Target, p.fixtureScope)
		}
		if err := p.assertBaseline(); err != nil {
			return result, err
		}
		for _, permit := range p.permits {
			request := permit.request
			creation, ok := p.bindings[request.SocketID]
			if !ok || creation.Capture != p.capture || request.Capture != p.capture || !time.Now().Before(permit.expires) {
				return result, errors.New("Node composition permit lost its exact live socket")
			}
			protocol := uint8(6)
			if request.Network == "udp" {
				protocol = 17
			} else if request.Network != "tcp" {
				return result, errors.New("Node composition permit has an unknown transport")
			}
			actual, err := p.identity.InspectSocket(ctx, creation)
			if err != nil || actual.Local != request.Local || actual.Protocol != protocol ||
				!desktopWindowsNodeCompositionPeerMatches(request.Network, actual.Remote, request.Remote, actual.PeerConnected) {
				cause := errors.Join(err, errors.New("Node composition permit is not its actual isolated transport endpoint"))
				return result, desktopWindowsNodeFailedInspection(ctx, p.identity, creation, cause)
			}
			result.Grants = append(result.Grants, request)
		}
		return result, nil
	})
}

// This test-only observation runs after the original complete proof failed.
// It preserves that failure and never retries admission, changes a grant,
// connects a socket, or closes an owner. Each read below describes only its
// own observation; observations cannot be combined into a successful proof.
func desktopWindowsNodeFailedInspection(ctx context.Context, identity *DesktopWindowsSocketIdentity, creation DesktopSocketCreation, cause error) error {
	if identity == nil {
		return errors.Join(cause, errors.New("Node failed inspection has no original identity"))
	}
	diagnostic := identity.call(ctx, true, func() error {
		record := identity.sockets[creation.SocketID]
		if record == nil || record.creation != creation {
			return errors.New("Node failed inspection original socket record retired")
		}
		observe := func(raw syscall.RawConn, sourceErr error) string {
			if sourceErr != nil || raw == nil {
				return fmt.Sprintf("source_error=%v", errors.Join(sourceErr, errors.New("no retained raw owner")))
			}
			var protocol syscall.WSAProtocolInfo
			var protocolErr error
			controlErr := raw.Control(func(handle uintptr) {
				protocol, protocolErr = desktopWindowsSocketProtocolInfo(syscall.Handle(handle))
			})
			endpoint, endpointErr := desktopWindowsALEEndpoint(raw)
			return fmt.Sprintf("protocol=%d/%d/%d protocol_error=%v endpoint=%x endpoint_error=%v", protocol.AddressFamily, protocol.SocketType, protocol.Protocol, errors.Join(controlErr, protocolErr), endpoint, endpointErr)
		}
		observeSource := func(source DesktopSocketNative) string {
			if source == nil {
				return "source_absent"
			}
			raw, err := source.SyscallConn()
			return observe(raw, err)
		}
		phase, operation, imported := "none", "none", "absent"
		if connection := record.connect; connection != nil {
			phase = fmt.Sprint(connection.phase)
			if connection.operation != nil {
				operation = fmt.Sprint(connection.operation.Err())
			}
			if connection.io != nil {
				imported = observe(desktopWindowsRaw{connection.io}, nil)
			}
		}
		return fmt.Errorf("Node failed inspection observation network=%s phase=%s operation=%s original={%s} returned={%s} imported={%s}", creation.Network, phase, operation, observeSource(record.original), observeSource(record.returned), imported)
	})
	return errors.Join(cause, diagnostic)
}

func DesktopWindowsNodeCompositionVerifyPrepared(ctx context.Context, target DesktopWindowsProtectionTarget) error {
	scope, err := DesktopWindowsNodeCompositionAppID()
	if err != nil {
		return err
	}
	return readDesktopWindowsPreparedProtection(ctx, target.Capture, target.Policy, target.BaselineSHA256, scope)
}

func DesktopWindowsNodeCompositionVerifyRetained(ctx context.Context, target DesktopWindowsProtectionTarget) error {
	scope, err := DesktopWindowsNodeCompositionAppID()
	if err != nil {
		return err
	}
	return readDesktopWindowsRetainedProtection(ctx, target, scope)
}

func DesktopWindowsNodeCompositionRetainedTarget(ctx context.Context) (DesktopWindowsProtectionTarget, error) {
	desktopWindowsNodeComposition.Lock()
	p := desktopWindowsNodeComposition.owner
	desktopWindowsNodeComposition.Unlock()
	if p == nil {
		return DesktopWindowsProtectionTarget{}, errors.New("Node composition owns no native source")
	}
	return p.RetainedProtectionTarget(ctx)
}

func DesktopWindowsNodeCompositionAbsent(ctx context.Context) error {
	scope, err := DesktopWindowsNodeCompositionAppID()
	if err != nil {
		return err
	}
	absent, err := probeDesktopWindowsProtectionAbsent(ctx, scope)
	if err != nil || !absent {
		return errors.Join(err, errors.New("Node test scope still owns managed native protection"))
	}
	return nil
}

func DesktopWindowsNodeCompositionRetire(ctx context.Context, target DesktopWindowsProtectionTarget) error {
	scope, err := DesktopWindowsNodeCompositionAppID()
	if err != nil {
		return err
	}
	if err := readDesktopWindowsRetainedProtection(ctx, target, scope); err != nil {
		return err
	}
	request, err := newDesktopWindowsProtectionTransactionTarget(ctx, scope, true, &target)
	if request != nil {
		err = errors.Join(err, request.Close(ctx))
	}
	if err != nil {
		return err
	}
	return DesktopWindowsNodeCompositionAbsent(ctx)
}

// This native test capture retains the actual object/endpoint identities before
// a refusal. Grant absence alone is insufficient: the source's descriptor and
// independently queried ALE endpoint must also have retired.
type DesktopWindowsNodeSocketRetirement struct {
	policy             *DesktopWindowsSocketPolicy
	identity           *DesktopWindowsSocketIdentity
	target             DesktopWindowsProtectionTarget
	scope              []byte
	creation           DesktopSocketCreation
	grant              DesktopSocketGrant
	endpoints          []uint64
	rules              []syscall.GUID
	originalRules      []desktopWFPRule
	original, returned DesktopSocketNative
	io                 *desktopWindowsSocket
	held               DesktopSocketNative
}

func DesktopWindowsNodeCompositionCaptureSocketRetirement(ctx context.Context, grant DesktopSocketGrant) (*DesktopWindowsNodeSocketRetirement, error) {
	desktopWindowsNodeComposition.Lock()
	p := desktopWindowsNodeComposition.owner
	desktopWindowsNodeComposition.Unlock()
	if p == nil {
		return nil, errors.New("socket retirement has no captured native policy")
	}
	// Resource acquisition must join entered native calls even on timeout.
	if ctx == nil {
		return nil, errors.New("socket retirement capture has no caller")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.ctx.Done():
		return nil, net.ErrClosed
	case <-p.gate:
	}
	defer func() { p.gate <- struct{}{} }()
	if ctx.Err() != nil || p.ctx.Err() != nil {
		return nil, errors.Join(ctx.Err(), net.ErrClosed)
	}
	capture := func() (*DesktopWindowsNodeSocketRetirement, error) {
		if grant.Capture != p.capture || grant.Binding.Owner != p.owner || grant.Network != "tcp" {
			return nil, errors.New("socket retirement capture changed original owner")
		}
		creation, ok := p.bindings[grant.SocketID]
		permit := p.permits[desktopWindowsPermitKey(grant)]
		if !ok || permit == nil || !desktopSocketSOCKSControlMatches(permit.request, grant) {
			return nil, errors.New("socket retirement capture lacks original live TCP grant")
		}
		if err := p.assertBaseline(); err != nil {
			return nil, err
		}
		actual, err := p.identity.InspectSocket(ctx, creation)
		if err != nil || !actual.PeerConnected || actual.Local != grant.Local || actual.Remote != grant.Remote {
			return nil, errors.Join(err, errors.New("socket retirement capture is not its actual connected tuple"))
		}
		captured := &DesktopWindowsNodeSocketRetirement{policy: p, identity: p.identity, creation: creation, grant: grant,
			target: desktopWindowsProtectionTarget(p.capture, p.options.KillSwitchPolicy, p.metadata),
			scope:  append([]byte(nil), p.fixtureScope...)}
		for _, rule := range permit.rules {
			captured.rules = append(captured.rules, rule.Key)
			// Retain the complete original native rule, not a later permit map's
			// replacement definition, for independent defect classification.
			rule.Metadata = append([]byte(nil), rule.Metadata...)
			rule.Conditions = append([]desktopWFPCondition(nil), rule.Conditions...)
			for i := range rule.Conditions {
				rule.Conditions[i].Bytes = append([]byte(nil), rule.Conditions[i].Bytes...)
			}
			captured.originalRules = append(captured.originalRules, rule)
		}
		if len(captured.rules) == 0 {
			return nil, errors.New("socket retirement capture lacks native permit keys")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.identity.ctx.Done():
			return nil, net.ErrClosed
		case <-p.identity.gate:
		}
		acquire := func() error {
			defer func() { p.identity.gate <- struct{}{} }()
			if ctx.Err() != nil || p.identity.ctx.Err() != nil {
				return errors.Join(ctx.Err(), net.ErrClosed)
			}
			record := p.identity.sockets[creation.SocketID]
			if record == nil || record.creation != creation || record.original == nil || record.returned == nil || record.connect == nil || record.connect.io == nil {
				return errors.New("socket retirement capture lost retained native descriptors")
			}
			captured.original, captured.returned, captured.io = record.original, record.returned, record.connect.io
			for _, endpoint := range []uint64{record.endpoint, actual.EndpointID, record.finalEndpoint, record.connect.boundEndpoint} {
				if endpoint == 0 {
					continue
				}
				found := false
				for _, previous := range captured.endpoints {
					if previous == endpoint {
						found = true
					}
				}
				if !found {
					captured.endpoints = append(captured.endpoints, endpoint)
				}
			}
			// An independent test-owned duplicate deliberately holds the exact kernel
			// endpoint while production closes its own descriptors. It is released only
			// after the fixture observes production blocked on native absence readback.
			raw, err := record.original.SyscallConn()
			if err != nil {
				return err
			}
			captured.held, err = desktopWindowsNativeDuplicate(raw)
			if err != nil {
				return err
			}
			heldRaw, err := captured.held.SyscallConn()
			if err != nil {
				return err
			}
			heldID, err := desktopWindowsALEEndpoint(heldRaw)
			if err != nil || heldID == 0 || heldID != actual.EndpointID {
				return errors.Join(err, errors.New("independent held endpoint differs from captured connected ALE identity"))
			}
			return nil
		}
		err = acquire()
		if err != nil && captured.held == nil {
			return nil, err
		}
		return captured, errors.Join(err, ctx.Err())
	}
	return capture()
}

func (r *DesktopWindowsNodeSocketRetirement) ReleaseHeldEndpoint() error {
	if r == nil || r.held == nil {
		return errors.New("socket retirement lost its independent held endpoint")
	}
	return r.held.Close()
}

func (r *DesktopWindowsNodeSocketRetirement) originalClosed() bool {
	_, original := r.original.SyscallConn()
	_, returned := r.returned.SyscallConn()
	r.io.mu.Lock()
	closed := r.io.closed
	r.io.mu.Unlock()
	return errors.Is(original, net.ErrClosed) && errors.Is(returned, net.ErrClosed) && closed
}

// ReadyToRelease proves the production release reached real descriptor close
// while its independently retained kernel endpoint still exists. It rejects a
// skipped ReleaseSocket or an early source-record deletion as distinct defects.
func (r *DesktopWindowsNodeSocketRetirement) ReadyToRelease(ctx context.Context) (bool, error) {
	if r == nil {
		return false, errors.New("socket retirement capture is missing")
	}
	p := r.policy
	return desktopWindowsPolicyCall(p, ctx, true, func() (bool, error) {
		if err := p.assertBaseline(); err != nil {
			return false, err
		}
		for _, permit := range p.permits {
			if permit.request.SocketID == r.grant.SocketID {
				return false, nil
			}
		}
		ready := false
		err := p.identity.call(ctx, true, func() error {
			record := p.identity.sockets[r.creation.SocketID]
			if record == nil {
				return errors.New("native retirement bypassed independent endpoint readback")
			}
			if record.creation != r.creation {
				return errors.New("native retirement replaced its source record")
			}
			if !r.originalClosed() {
				return nil
			}
			live := false
			for _, endpoint := range r.endpoints {
				_, _, err := p.identity.api.endpointProperties(p.identity.engine, endpoint)
				if err == nil {
					live = true
				} else if !errors.Is(err, desktopWindowsEndpointNotFound) {
					return err
				}
			}
			if !live {
				return errors.New("independent held native endpoint disappeared before release")
			}
			ready = true
			return nil
		})
		if err != nil {
			return false, err
		}
		return ready, nil
	})
}

// RetainedGrant classifies a completed refusal using the original grant and
// independent native filter readback. An observation error cannot witness the
// missing-revocation defect, and this reader grants no retirement authority.
func (r *DesktopWindowsNodeSocketRetirement) RetainedGrant(ctx context.Context) (bool, error) {
	return r.retainedGrant(ctx, false)
}

// A skipped revoke cannot complete the proof: the unchanged ReleaseSocket
// refuses its still-live permit. Observe that defect only after the actual
// imported I/O and returned descriptor close, which occur after broker revoke
// acknowledgement. An ordinary live grant before that boundary is not a defect.
func (r *DesktopWindowsNodeSocketRetirement) RetainedGrantAfterIOClose(ctx context.Context) (bool, error) {
	return r.retainedGrant(ctx, true)
}

func (r *DesktopWindowsNodeSocketRetirement) retainedGrant(ctx context.Context, requireIOClose bool) (bool, error) {
	if r == nil || ctx == nil || len(r.originalRules) == 0 {
		return false, errors.New("socket retirement lacks its original grant observation")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	desktopWindowsNodeComposition.Lock()
	same := desktopWindowsNodeComposition.owner == r.policy
	desktopWindowsNodeComposition.Unlock()
	if !same {
		return false, errors.New("socket retirement observation replaced its original policy")
	}
	p := r.policy
	return desktopWindowsPolicyCall(p, ctx, true, func() (retained bool, failure error) {
		if p.capture != r.grant.Capture || p.owner != r.grant.Binding.Owner ||
			p.identity != r.identity || r.identity == nil || !bytes.Equal(p.fixtureScope, r.scope) ||
			!r.target.matches(p.capture, p.options.KillSwitchPolicy, p.metadata) {
			return false, errors.New("socket retirement observation changed its original owner")
		}
		if err := p.assertBaseline(); err != nil {
			return false, err
		}
		permit := p.permits[desktopWindowsPermitKey(r.grant)]
		if permit == nil {
			return false, nil
		}
		creation, exists := p.bindings[r.creation.SocketID]
		if !exists || creation != r.creation || !desktopSocketSOCKSControlMatches(permit.request, r.grant) {
			return false, errors.New("socket retirement observation lost its original grant binding")
		}
		if requireIOClose {
			if r.original == nil || r.returned == nil || r.io == nil {
				return false, errors.New("retained grant observation omitted original native I/O")
			}
			joined := false
			err := r.identity.call(ctx, true, func() error {
				record := r.identity.sockets[r.creation.SocketID]
				if record == nil || record.creation != r.creation || record.original != r.original || record.returned != r.returned || record.connect == nil || record.connect.io != r.io {
					return errors.New("retained grant observation lost original native I/O ownership")
				}
				_, returnedErr := r.returned.SyscallConn()
				if returnedErr != nil && !errors.Is(returnedErr, net.ErrClosed) {
					return returnedErr
				}
				r.io.mu.Lock()
				closed := r.io.closed
				r.io.mu.Unlock()
				if !errors.Is(returnedErr, net.ErrClosed) || !closed {
					return nil
				}
				// The actual source still retains this original because the
				// permit prevents ReleaseSocket from reaching descriptor close.
				if _, err := r.original.SyscallConn(); err != nil {
					return errors.Join(err, errors.New("retained grant lost its original source descriptor"))
				}
				joined = true
				return nil
			})
			if err != nil || !joined {
				return false, err
			}
		}
		reader, err := desktopWFPOpen(false)
		if reader != nil {
			defer func() { failure = errors.Join(failure, reader.Close()) }()
		}
		if err != nil {
			return false, err
		}
		for _, rule := range r.originalRules {
			if err := reader.Assert(rule); err != nil {
				return false, err
			}
		}
		return true, nil
	})
}

func (r *DesktopWindowsNodeSocketRetirement) RequireRetired(ctx context.Context) error {
	if r == nil {
		return errors.New("socket retirement capture is missing")
	}
	desktopWindowsNodeComposition.Lock()
	same := desktopWindowsNodeComposition.owner == r.policy
	desktopWindowsNodeComposition.Unlock()
	if !same {
		return errors.New("native retirement replaced its original policy")
	}
	p := r.policy
	_, err := desktopWindowsPolicyCall(p, ctx, true, func() (struct{}, error) {
		if p.capture != r.grant.Capture || p.owner != r.grant.Binding.Owner ||
			p.identity != r.identity || r.identity == nil || !bytes.Equal(p.fixtureScope, r.scope) ||
			!r.target.matches(p.capture, p.options.KillSwitchPolicy, p.metadata) {
			return struct{}{}, errors.New("native retirement changed its original captured owner")
		}
		if p.closed {
			// A failed proof can finish the complete policy teardown before this
			// observation. Its active lock and engines are then intentionally gone.
			// Verify the exact retained baseline through a separate native reader;
			// a missing lock alone never proves successful retirement.
			if len(p.permits) != 0 || len(p.bindings) != 0 || len(p.tunnel) != 0 || p.locked || !p.installed || !p.baselineDone {
				return struct{}{}, errors.New("native retirement did not retain its exact drained baseline")
			}
			if err := readDesktopWindowsRetainedProtection(ctx, r.target, r.scope); err != nil {
				return struct{}{}, err
			}
		} else if err := p.assertBaseline(); err != nil {
			return struct{}{}, err
		}
		if _, exists := p.bindings[r.creation.SocketID]; exists {
			return struct{}{}, errors.New("native retirement retained its captured source binding")
		}
		for _, permit := range p.permits {
			if permit.request.SocketID == r.grant.SocketID {
				return struct{}{}, errors.New("native retirement retained its captured socket grant")
			}
		}
		closed := p.closed
		return struct{}{}, r.identity.call(ctx, true, func() (failure error) {
			if closed && !r.identity.closed {
				return errors.New("native retirement did not join its original identity close")
			}
			if _, exists := r.identity.sockets[r.creation.SocketID]; exists {
				return errors.New("native retirement did not join its original socket release")
			}
			if !r.originalClosed() {
				return errors.New("native retirement retained an original descriptor")
			}
			// The read-only observer owns its handle inside this joined native
			// call, independently of both production engines. A caller timeout
			// cannot close it while an entered endpoint query is still running.
			reader, err := desktopWFPOpen(false)
			if reader != nil {
				defer func() { failure = errors.Join(failure, reader.Close()) }()
			}
			if err != nil {
				return err
			}
			for _, key := range r.rules {
				if err := reader.Absent(key); err != nil {
					return errors.Join(err, errors.New("native retirement retained its original WFP permit filter"))
				}
			}
			for _, endpoint := range r.endpoints {
				if _, _, err := r.identity.api.endpointProperties(reader.handle, endpoint); !errors.Is(err, desktopWindowsEndpointNotFound) {
					return errors.Join(err, errors.New("native retirement retained its captured ALE endpoint"))
				}
			}
			return nil
		})
	})
	return err
}

// Cleanup is used only after the case verdict, including deliberate production
// mutants. It cannot satisfy RequireRetired: the fixture calls that before any
// cleanup. The exact captured permit/source may be retired, never another owner.
func (r *DesktopWindowsNodeSocketRetirement) Cleanup(ctx context.Context) error {
	if r == nil {
		return nil
	}
	heldErr := r.ReleaseHeldEndpoint()
	p := r.policy
	_, err := desktopWindowsPolicyCall(p, ctx, true, func() (struct{}, error) {
		if p.capture != r.creation.Capture || p.owner != r.grant.Binding.Owner {
			return struct{}{}, errors.New("socket cleanup replaced its original captured owner")
		}
		if p.closed {
			return struct{}{}, nil
		}
		if permit := p.permits[desktopWindowsPermitKey(r.grant)]; permit != nil {
			if !desktopSocketSOCKSControlMatches(permit.request, r.grant) {
				return struct{}{}, errors.New("socket cleanup changed its exact captured control")
			}
			if err := p.revoke(permit.request); err != nil {
				return struct{}{}, err
			}
		}
		if err := p.identity.ReleaseSocket(ctx, r.creation); err != nil {
			return struct{}{}, err
		}
		delete(p.bindings, r.creation.SocketID)
		return struct{}{}, nil
	})
	return errors.Join(heldErr, err)
}
