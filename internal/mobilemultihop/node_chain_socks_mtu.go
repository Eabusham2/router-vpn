package mobilemultihop

import (
	"context"
	"errors"

	"router-vpn/internal/mobilemtu"
)

// These accessors reuse the existing complete-prefix planner. Configured
// bounds and source credentials are not a measured PMTU or native TUN receipt.
func (r *NodeChainSOCKSRuntime) MTUProfile() string {
	if r == nil || r.chain == nil || r.source != r.chain.socksSource {
		return ""
	}
	return r.chain.MTUProfile()
}
func (r *NodeChainSOCKSRuntime) MTUPlan() (NodeChainMTUPlan, error) {
	if r == nil || r.chain == nil || r.source != r.chain.socksSource {
		return NodeChainMTUPlan{}, nodeChainSOCKSSourceError
	}
	return r.chain.MTUPlan()
}
func (r *NodeChainSOCKSRuntime) PlanForMTU(config string, actual int) (*mobilemtu.Plan, error) {
	if r == nil || r.chain == nil || r.source != r.chain.socksSource {
		return nil, nodeChainSOCKSSourceError
	}
	return r.chain.PlanForMTU(config, actual)
}

// Native hosts must retain the original TUN owner, serialize its measurement
// activity, join the old proof before a reader change and reprove that exact
// returned reader. The controller does not itself grant native replacement.
func (r *NodeChainSOCKSRuntime) NewMTUControllerContext(ctx context.Context, owner mobilemtu.Owner, cache mobilemtu.Cache) (*mobilemtu.Controller, error) {
	if r == nil || r.chain == nil || r.source != r.chain.socksSource || ctx == nil || owner == nil {
		return nil, nodeChainSOCKSSourceError
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
