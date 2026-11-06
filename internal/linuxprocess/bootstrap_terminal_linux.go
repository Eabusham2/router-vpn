//go:build linux

package linuxprocess

import "context"

// SendTerminalReceipt distinguishes a fully written terminal receipt from an
// admission or transport failure. It retains the same original process/channel
// checks as Send. A true written result is NOT a successful completion: callers
// must still join the retained original creation pidfd and prove successful
// natural exit before accepting a terminal verdict. In particular, arbitrary
// write failures may never be explained away by a child's later clean exit.
func (b *Bootstrap) SendTerminalReceipt(ctx context.Context, body []byte) (written bool, failure error) {
	if err := b.enter(ctx); err != nil {
		return false, err
	}
	defer func() { b.gate <- struct{}{} }()
	if err := b.current(ctx); err != nil {
		return false, err
	}
	if err := b.channel.Send(ctx, body, nil); err != nil {
		b.revoked = true
		return false, err
	}
	return true, b.current(ctx)
}
