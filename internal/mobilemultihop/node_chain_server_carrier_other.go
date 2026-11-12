//go:build !linux

package mobilemultihop

import "context"

// Ordered Server native carrier acquisition is currently Linux-only.
func NewNodeChainServerCarrierContext(ctx, lifetime context.Context, source string) (*NodeChainServerCarrier, error) {
	return nil, nodeChainServerCarrierError
}
