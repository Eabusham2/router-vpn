package main

import "context"

// Standalone throughput shares Speed Lab's single measurement owner and its
// captured MTU suspension. The handler releases this only after synchronous
// transfers, response delivery and its joined path observer have returned.
// This does not acquire the connection mutation lock: Disconnect stays usable.
func (a *app) beginStandaloneThroughput(ctx context.Context) (func(), error) {
	finish, err := beginSpeedLabRun(a)
	if err != nil {
		return nil, err
	}
	releaseMTU, err := a.holdDesktopMTUForMeasurement(ctx)
	if err != nil {
		finish()
		return nil, err
	}
	return func() { releaseMTU(); finish() }, nil
}
