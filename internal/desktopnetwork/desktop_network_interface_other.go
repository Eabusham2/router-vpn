//go:build !linux

package desktopnetwork

import (
	"context"
	"errors"
	"net"
)

// These OS inventory calls are synchronous. Cancellation prevents accepting
// their result; it does not claim to interrupt a kernel call or detach a worker.
func interfaceContextNative(ctx context.Context, index int) (*net.Interface, []net.Addr, error) {
	current, err := net.InterfaceByIndex(index)
	if err != nil || ctx.Err() != nil {
		return nil, nil, errors.Join(err, ctx.Err())
	}
	addresses, err := current.Addrs()
	if err != nil || ctx.Err() != nil {
		return nil, nil, errors.Join(err, ctx.Err())
	}
	after, err := net.InterfaceByIndex(index)
	if err != nil || ctx.Err() != nil {
		return nil, nil, errors.Join(err, ctx.Err())
	}
	if !sameInterface(current, after) {
		return nil, nil, errors.New("interface changed while reading its addresses")
	}
	return current, addresses, nil
}
