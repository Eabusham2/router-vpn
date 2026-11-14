package mobilemultihop

import (
	"context"
	"errors"

	"router-vpn/internal/mobilemtu"
)

// These accessors reuse the existing complete-prefix planner. Configured
// bounds and source credentials are not a measured PMTU or native TUN receipt.
func (r *NodeChainCONNECTRuntime) MTUProfile() string {
	if r == nil || r.chain == nil || r.source != r.chain.connectSource {
		return ""
	}
	return r.chain.MTUProfile()
}
func (r *NodeChainCONNECTRuntime) MTUPlan() (NodeChainMTUPlan, error) {
	if r == nil || r.chain == nil || r.source != r.chain.connectSource {
		return NodeChainMTUPlan{}, nodeChainCONNECTSourceError
	}
	return r.chain.MTUPlan()
}
func (r *NodeChainCONNECTRuntime) PlanForMTU(config string, actual int) (*mobilemtu.Plan, error) {
	if r == nil || r.chain == nil || r.source != r.chain.connectSource {
		return nil, nodeChainCONNECTSourceError
	}
	return r.chain.PlanForMTU(config, actual)
}

// Native hosts must retain the original TUN owner, serialize its measurement
// activity, join the old proof before a reader change and reprove that exact
// returned reader. The controller does not itself grant native replacement.
func (r *NodeChainCONNECTRuntime) NewMTUControllerContext(ctx context.Context, owner mobilemtu.Owner, cache mobilemtu.Cache) (*mobilemtu.Controller, error) {
	if r == nil || r.chain == nil || r.source != r.chain.connectSource || ctx == nil || owner == nil {
		return nil, nodeChainCONNECTSourceError
	}
	if err := r.HealthyContext(ctx); err != nil {
		return nil, err
	}
	controller, err := r.chain.NewMTUControllerContext(ctx, owner, cache)
	if err != nil {
		return nil, err
	}
	if err := r.HealthyContext(ctx); err != nil {
		return nil, errors.Join(err, controller.Close())
	}
	return controller, nil
}
