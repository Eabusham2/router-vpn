package main

import "context"

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
