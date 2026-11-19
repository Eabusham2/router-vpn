package main

import (
	"context"
	"errors"
)

// Return only an explicitly captured active setting. A missing or zero
// preference uses the originally selected source policy.
func desktopDeviceFixedInput(ctx context.Context) (string, int, error) {
	capture := deviceMTUForContext(ctx)
	if capture == nil {
		return "", 0, nil
	}
	if err := capture.current(); err != nil {
		return "", 0, err
	}
	if capture.policy.FixedMTU == 0 {
		return "", 0, nil
	}
	return capture.policy.Revision, capture.policy.FixedMTU, nil
}

// A device preference is replayed by its own original revision. Historical
// live restoration is reserved for a connection that used its profile policy.
type desktopRestoredMTUPurpose struct {
	Revision string
	Fixed    int
}

func (p desktopRestoredMTUPurpose) historical(observed int) (int, error) {
	if p.Revision == "" && p.Fixed == 0 {
		return observed, nil
	}
	if !desktopMTURequestPattern.MatchString(p.Revision) || p.Fixed < 1280 || p.Fixed > 9000 || observed != p.Fixed {
		return 0, errDeviceMTUReadback
	}
	return 0, nil
}
func (p desktopRestoredMTUPurpose) forOperation(ctx context.Context, observed int) (int, error) {
	revision, mtu, err := desktopDeviceFixedInput(ctx)
	if err != nil || p.Revision != revision || p.Fixed != mtu {
		return 0, errors.Join(err, errDeviceMTUReadback)
	}
	return p.historical(observed)
}
