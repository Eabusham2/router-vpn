//go:build windows

package mobiletor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

type desktopWindowsPreparedCapture struct {
	capture        DesktopSocketCapture
	policy         string
	baselineSHA256 string
}

// ReadDesktopWindowsPreparedProtection independently proves the exact native
// deny baseline at the pre-TUN handoff barrier. Supplied strings constrain a
// read-only BFE transaction; they grant no permission to change any object.
// Unknown, retained, incomplete or already-active socket policy is rejected.
func ReadDesktopWindowsPreparedProtection(ctx context.Context, capture DesktopSocketCapture, policy, baselineSHA256 string) error {
	return readDesktopWindowsPreparedProtection(ctx, capture, policy, baselineSHA256, nil)
}

func readDesktopWindowsPreparedProtection(ctx context.Context, capture DesktopSocketCapture, policy, baselineSHA256 string, scope []byte) error {
	decoded, err := hex.DecodeString(baselineSHA256)
	if !capture.valid() || policy != "on-connect" && policy != "always" || err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != baselineSHA256 {
		return errors.New("Windows prepared protection requires an exact captured owner and policy")
	}
	_, err = readDesktopWindowsProtectionRequest(ctx, scope, &desktopWindowsPreparedCapture{capture, policy, baselineSHA256})
	return err
}

// VerifyPrepared is the native owner's side of the same barrier. It uses the
// captured policy gate, so an entered socket, tunnel or retirement cannot race
// past this check. The wrapper separately observes BFE before legacy mutation.
func (p *DesktopWindowsSocketPolicy) VerifyPrepared(ctx context.Context, capture DesktopSocketCapture) error {
	_, err := p.PreparedBaselineSHA256(ctx, capture)
	return err
}

// PreparedBaselineSHA256 binds independent handoff readback to the complete
// canonical native baseline, including selected LAN prefixes and maintenance
// exceptions. Matching only the public session identifiers is insufficient.
func (p *DesktopWindowsSocketPolicy) PreparedBaselineSHA256(ctx context.Context, capture DesktopSocketCapture) (string, error) {
	if p == nil || capture != p.capture {
		return "", errors.New("Windows prepared protection has another native owner")
	}
	return desktopWindowsPolicyCall(p, ctx, false, func() (string, error) {
		if p.closed || p.retired.Load() || !p.installed || len(p.permits) != 0 || len(p.bindings) != 0 || len(p.tunnel) != 0 ||
			p.tunnelName != "" || p.tunnelIndex != 0 || p.tunnelLUID != 0 {
			return "", errors.New("Windows prepared protection is no longer at its native handoff barrier")
		}
		if err := p.assertBaseline(); err != nil {
			return "", err
		}
		digest := sha256.Sum256(p.metadata)
		return hex.EncodeToString(digest[:]), nil
	})
}
