//go:build !linux

package mobilemultihop

import (
	"context"
	"router-vpn/internal/multihoprelay"
)

func NewNodeChainServerPrefixSessionContext(context.Context, context.Context, *NodeChainServerPrefixPolicy, multihoprelay.NodeChainPrefixCapture) (*NodeChainServerPrefixSession, error) {
	return nil, nodeChainServerCarrierError
}
func NewNodeChainServerPrefixCandidateTargetContext(context.Context, context.Context, *NodeChainServerPrefixSession, multihoprelay.NodeChainPrefixCandidateCapture) (*NodeChainServerPrefixCandidateTarget, error) {
	return nil, nodeChainServerCarrierError
}
