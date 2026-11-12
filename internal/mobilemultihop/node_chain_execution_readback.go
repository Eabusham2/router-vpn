package mobilemultihop

import (
	"context"
	"errors"

	"router-vpn/internal/mobilemtu"
)

// The retained native engine issues this observation from its original reader
// and actual platform interface readback. It returns the same nonce/generation
// only while that exact reader, name, index and effective MTU remain unchanged.
// A caller-created value is not a restore capability.
type NodeChainExecutionTUNReadback struct {
	Identity         NodeChainIdentity
	TargetOS         string
	TUNTag           string
	ReaderNonce      string
	ReaderGeneration uint64
	InterfaceName    string
	InterfaceIndex   int
	MTU              int
}

type NodeChainExecutionTUNReadbackEngine interface {
	CaptureExecutionTUNReadbackContext(context.Context, NodeChainIdentity) (NodeChainExecutionTUNReadback, error)
	// This checks the exact previously issued observation and retained engine,
	// gate and reader retirement facts. It must not query closed Box managers
	// or the OS after host teardown, and never substitutes Box.done for Close.
	ExecutionTUNReadbackRetiredContext(context.Context, NodeChainExecutionTUNReadback) error
}

func (p *NodeChainExecutionProjection) validateTUNReadback(value NodeChainExecutionTUNReadback, identity NodeChainIdentity) error {
	bound, err := p.MTUPlan()
	if err != nil || value.Identity != identity || !nodeChainIdentityText(identity.EngineID) ||
		!nodeChainIdentityText(identity.SessionID) || !nodeChainIdentityText(identity.NetworkID) ||
		identity.SourceSHA256 != p.SourceSHA256() || identity.ConfigSHA256 != p.ConfigSHA256() ||
		value.TUNTag != bound.TUNTag || !proofID.MatchString(value.ReaderNonce) || value.ReaderGeneration == 0 ||
		!exactID.MatchString(value.InterfaceName) || value.InterfaceIndex <= 0 || value.MTU < mobilemtu.MinMTU || value.MTU > bound.Ceiling {
		return errors.Join(err, nodeChainExecutionError)
	}
	if p.preparation.desktop != nil {
		if value.TargetOS != p.preparation.desktop.metadata.TargetOS {
			return nodeChainExecutionError
		}
	} else if value.TargetOS != "android" && value.TargetOS != "ios" {
		return nodeChainExecutionError
	}
	if p.preparation.mobile != nil && value.TargetOS != p.preparation.mobile.readback.TargetOS {
		return nodeChainExecutionError
	}
	final := p.policy.local.nodes[len(p.policy.local.nodes)-1].profile
	fixed, err := fixedMTU(final)
	jumbo, jumboErr := externalJumboPreference(final)
	if err != nil || jumboErr != nil || fixed != 0 && value.MTU != fixed || jumbo && value.MTU != bound.Original {
		return errors.Join(err, jumboErr, nodeChainExecutionError)
	}
	return nil
}

func (r *NodeChainExecutionRuntime) beginTUNReadbackContext(ctx context.Context) (NodeChainExecutionTUNReadbackEngine, func(), error) {
	if r == nil || ctx == nil {
		return nil, nil, nodeChainExecutionError
	}
	engine, ok := r.engine.(NodeChainExecutionTUNReadbackEngine)
	if !ok {
		return nil, nil, nodeChainExecutionError
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return nil, nil, err
	}
	if r.retired.Load() || r.closed || !r.progress.Ready || r.active == nil {
		r.mu.Unlock()
		return nil, nil, nodeChainExecutionError
	}
	r.readbackObservations++
	r.mu.Unlock()
	return engine, func() { r.mu.Lock(); r.readbackObservations--; r.mu.Unlock() }, nil
}

func (r *NodeChainExecutionRuntime) captureTUNReadbackContext(ctx context.Context, engine NodeChainExecutionTUNReadbackEngine) (NodeChainExecutionTUNReadback, error) {
	if err := r.HealthyContext(ctx); err != nil {
		return NodeChainExecutionTUNReadback{}, err
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return NodeChainExecutionTUNReadback{}, err
	}
	identity, trial := r.identity, r.active
	r.mu.Unlock()
	value, err := engine.CaptureExecutionTUNReadbackContext(ctx, identity)
	if err != nil || r.projection.validateTUNReadback(value, identity) != nil {
		return NodeChainExecutionTUNReadback{}, errors.Join(err, nodeChainExecutionError)
	}
	if err := r.current(ctx, trial, true); err != nil {
		return NodeChainExecutionTUNReadback{}, err
	}
	return value, nil
}

// The bridge retains its exact native server/service/Instance/Box and activity
// during attachment. Its platform State strings need not equal native engine
// identifiers; this typed companion binds the actual owner without guessing.
type NodeChainExecutionMTUOwner interface {
	mobilemtu.Owner
	mobilemtu.ContextOwner
	MTUExecutionContext(context.Context) (*NodeChainExecutionRuntime, error)
}

// NewMTUControllerContext derives the current TUN config from the original
// native readback. Reopening Retest after a completed MTU change therefore
// keeps its effective value, full graph and original configured ceiling.
// No caller-supplied MTU or config can select this attachment path.
func (r *NodeChainExecutionRuntime) NewMTUControllerContext(ctx context.Context, owner NodeChainExecutionMTUOwner, cache mobilemtu.Cache) (*mobilemtu.Controller, error) {
	if owner == nil {
		return nil, nodeChainExecutionError
	}
	engine, release, err := r.beginTUNReadbackContext(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	original, err := owner.MTUExecutionContext(ctx)
	if err != nil || original != r {
		return nil, errors.Join(err, nodeChainExecutionError)
	}
	readback, err := r.captureTUNReadbackContext(ctx, engine)
	if err != nil {
		return nil, err
	}
	state, err := owner.CaptureContext(ctx)
	if err != nil || state.MTU != readback.MTU {
		return nil, errors.Join(err, nodeChainExecutionError)
	}
	bound, err := r.projection.MTUPlan()
	if err != nil {
		return nil, err
	}
	plan, err := r.projection.PlanForMTU(r.projection.config, bound.Original)
	if err != nil {
		return nil, err
	}
	config, err := plan.Config(readback.MTU)
	if err != nil {
		return nil, err
	}
	controller, err := mobilemtu.NewCapturedContext(ctx, owner, config, r.projection.MTUProfile(), cache, r.projection)
	if err != nil {
		return nil, err
	}
	accepted := false
	defer func() {
		if !accepted {
			// This private controller has never been published or started, so
			// Close has no native operation/worker to await or abandon.
			_ = controller.Close()
		}
	}()
	again, err := owner.CaptureContext(ctx)
	if err != nil || again != state {
		return nil, errors.Join(err, nodeChainExecutionError)
	}
	original, err = owner.MTUExecutionContext(ctx)
	if err != nil || original != r {
		return nil, errors.Join(err, nodeChainExecutionError)
	}
	current, err := r.captureTUNReadbackContext(ctx, engine)
	if err != nil || current != readback {
		return nil, errors.Join(err, nodeChainExecutionError)
	}
	accepted = true
	return controller, nil
}
