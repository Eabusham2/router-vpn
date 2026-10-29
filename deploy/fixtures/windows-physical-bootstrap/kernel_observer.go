//go:build windows && routervpn_windows_physical_composition

package mobiletor

// This file exists only in an explicit prospective Go test overlay. The
// shipping constructor remains unchanged: no environment, request, or profile
// can select a test scope. Only the exact running test image receives filters.
import (
	"context"
	"errors"
	"sync"
	"time"
)

var desktopWindowsCompositionState struct {
	sync.Mutex
	owner *DesktopWindowsSocketPolicy
	calls int
}

type DesktopWindowsCompositionReadback struct {
	Capture DesktopSocketCapture
	Options DesktopWindowsSocketOptions
	Owner   DesktopSocketKernelOwner
	Grants  []DesktopSocketGrant
	Calls   int
	Closed  bool
}

func desktopWindowsCompositionConstruct(ctx context.Context, capture DesktopSocketCapture, options DesktopWindowsSocketOptions) (*DesktopWindowsSocketPolicy, error) {
	api, err := desktopWindowsIdentityNativeAPI()
	if err != nil {
		return nil, err
	}
	scope, err := api.executableAppID()
	if err != nil || len(scope) == 0 {
		return nil, errors.Join(err, errors.New("composition has no actual executable scope"))
	}
	desktopWindowsCompositionState.Lock()
	defer desktopWindowsCompositionState.Unlock()
	if desktopWindowsCompositionState.owner != nil {
		return nil, errors.New("composition cannot replace its captured constructor owner")
	}
	owned, err := newDesktopWindowsSocketPolicy(ctx, capture, options, scope)
	desktopWindowsCompositionState.owner = owned
	desktopWindowsCompositionState.calls++
	return owned, err
}

// Readback uses the policy's serialized native operation gate, then queries
// actual BFE filters and every connected endpoint independently. It does not
// manufacture an admission receipt or supply a socket to the native factory.
func DesktopWindowsCompositionSnapshot(ctx context.Context) (DesktopWindowsCompositionReadback, error) {
	desktopWindowsCompositionState.Lock()
	p, calls := desktopWindowsCompositionState.owner, desktopWindowsCompositionState.calls
	desktopWindowsCompositionState.Unlock()
	if p == nil {
		return DesktopWindowsCompositionReadback{}, errors.New("composition constructor has not run")
	}
	return desktopWindowsPolicyCall(p, ctx, true, func() (DesktopWindowsCompositionReadback, error) {
		result := DesktopWindowsCompositionReadback{Capture: p.capture, Options: p.options, Owner: p.owner, Calls: calls, Closed: p.closed}
		result.Options.Interfaces = append([]DesktopWindowsSocketInterface(nil), p.options.Interfaces...)
		result.Options.PrivateDestinations = append([]DesktopWindowsSocketDestination(nil), p.options.PrivateDestinations...)
		if p.closed {
			if len(p.permits) != 0 || len(p.bindings) != 0 || p.installed || p.locked {
				return result, errors.New("composition close retained a baseline, token socket or permit")
			}
			absent, err := probeDesktopWindowsProtectionAbsent(ctx, p.fixtureScope)
			if err != nil || !absent {
				return result, errors.Join(err, errors.New("composition baseline/session-lock absence is unproved"))
			}
			return result, nil
		}
		if err := p.assertBaseline(); err != nil {
			return result, err
		}
		for _, permit := range p.permits {
			request := permit.request
			creation, ok := p.bindings[request.SocketID]
			if !ok || creation.Capture != p.capture || request.Capture != p.capture || !time.Now().Before(permit.expires) {
				return result, errors.New("composition permit lost its captured live socket")
			}
			actual, err := p.identity.InspectSocket(ctx, creation)
			if err != nil || actual.Local != request.Local || actual.Remote != request.Remote || !actual.PeerConnected || actual.Protocol != 6 {
				return result, errors.Join(err, errors.New("composition permit is not its actual connected isolated endpoint"))
			}
			result.Grants = append(result.Grants, request)
		}
		return result, nil
	})
}
