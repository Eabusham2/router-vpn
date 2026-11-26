package mobilemultihop

import "context"

// NewSelectedRemoteCandidatePlanContext chooses the measurement for a nonentry
// stop from the original Server trial's preparation. Each constructor verifies
// the live trial and its engine before returning a plan.
func (r *NodeChainExecutionRuntime) NewSelectedRemoteCandidatePlanContext(ctx context.Context, position int, inventory string) (*NodeChainExecutionRemoteCandidatePlan, error) {
	if r == nil || r.projection == nil || r.projection.preparation == nil {
		return nil, nodeChainExecutionError
	}
	if r.projection.preparation.SupportsServerPublicResponseCandidate(position) {
		return r.NewRemotePublicResponseCandidatePlanContext(ctx, position, inventory)
	}
	if r.projection.preparation.SupportsServerResponseCandidate(position) {
		return r.NewRemoteResponseCandidatePlanContext(ctx, position, inventory)
	}
	return r.NewRemoteCandidatePlanContext(ctx, position, inventory)
}
