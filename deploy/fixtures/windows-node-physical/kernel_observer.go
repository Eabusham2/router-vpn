//go:build windows && routervpn_windows_node_composition

package mobiletor

// This file is installed only by the explicit Go test overlay. The production
// constructors have no scope switch. Every native rule here additionally
// matches the actual subject test executable; the separately retained peer
// executable remains outside that scope.
import (
	"context"
	"errors"
	"sync"
	"time"
)

var desktopWindowsNodeComposition struct {
	sync.Mutex
	owner *DesktopWindowsSocketPolicy
	calls int
}

type DesktopWindowsNodeCompositionReadback struct {
	Target  DesktopWindowsProtectionTarget
	Capture DesktopSocketCapture
	Owner   DesktopSocketKernelOwner
	Options DesktopWindowsSocketOptions
	Grants  []DesktopSocketGrant
	Calls   int
	Closed  bool
}

func DesktopWindowsNodeCompositionAppID() ([]byte, error) {
	api, err := desktopWindowsIdentityNativeAPI()
	if err != nil {
		return nil, err
	}
	return api.executableAppID()
}

func desktopWindowsNodeCompositionConstruct(ctx context.Context, capture DesktopSocketCapture, options DesktopWindowsSocketOptions, predecessor *DesktopWindowsProtectionTarget, exact bool) (*DesktopWindowsSocketPolicy, error) {
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
	if exact {
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
			Target: desktopWindowsProtectionTarget(p.capture, p.options.KillSwitchPolicy, p.metadata)}
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
				return result, errors.Join(err, errors.New("Node composition permit is not its actual isolated transport endpoint"))
			}
			result.Grants = append(result.Grants, request)
		}
		return result, nil
	})
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
