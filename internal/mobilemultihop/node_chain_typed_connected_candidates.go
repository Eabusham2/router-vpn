package mobilemultihop

import (
	"context"
	"errors"
	"router-vpn/internal/hopmeasure"
)

// Connected candidate capability belongs to the complete original typed
// runtime. It never exposes that runtime's private generic chain, and is
// unrelated to the source-only, application-closed saved-prefix preparation.

type NodeChainSOCKSConnectedCandidateOwner interface {
	NodeChainSOCKSMeasurementOwner
	CandidateInventoryCurrentContext(context.Context, string) error
}
type NodeChainSOCKSConnectedCandidatePlan struct {
	original *NodeChainSOCKSRuntime
	source   *NodeChainSOCKSSource
	plan     *NodeChainCandidatePlan
}

func NewNodeChainSOCKSConnectedCandidatePlan(original *NodeChainSOCKSRuntime, position int, inventory string) (*NodeChainSOCKSConnectedCandidatePlan, error) {
	if original == nil || original.connectedCandidateSelf != original || original.source == nil || original.chain == nil || original.chain.socksSource != original.source || position < 0 || position >= len(original.chain.nodes)-2 {
		return nil, errors.New("connected SOCKS candidates require the exact original typed packet prefix")
	}
	plan, err := original.chain.newPacketCandidatePlan(position, inventory)
	if err != nil {
		return nil, err
	}
	result := &NodeChainSOCKSConnectedCandidatePlan{original: original, source: original.source, plan: plan}
	return result, result.validate()
}
func (p *NodeChainSOCKSConnectedCandidatePlan) validate() error {
	if p == nil || p.original == nil || p.original.connectedCandidateSelf != p.original || p.source == nil || p.plan == nil || p.plan.chain == nil || p.original.source != p.source || p.original.chain != p.plan.chain || p.plan.chain.socksSource != p.source {
		return errors.New("connected SOCKS candidate lost its original runtime and complete source")
	}
	return p.plan.validate()
}
func (p *NodeChainSOCKSConnectedCandidatePlan) Metadata() string {
	if p.validate() != nil {
		return ""
	}
	return p.plan.Metadata()
}
func (p *NodeChainSOCKSConnectedCandidatePlan) CaptureSHA256() string {
	if p.validate() != nil {
		return ""
	}
	return p.plan.CaptureSHA256()
}
func (p *NodeChainSOCKSConnectedCandidatePlan) NewMeasurementContext(ctx context.Context, owner NodeChainSOCKSConnectedCandidateOwner) (*hopmeasure.CandidateService, error) {
	if ctx == nil || owner == nil || p.validate() != nil {
		return nil, errors.New("connected SOCKS candidate requires its original typed measurement owner")
	}
	return p.plan.NewMeasurementContext(ctx, nodeChainSOCKSConnectedCandidateOwner{p, owner})
}

type nodeChainSOCKSConnectedCandidateOwner struct {
	plan  *NodeChainSOCKSConnectedCandidatePlan
	owner NodeChainSOCKSConnectedCandidateOwner
}

func (o nodeChainSOCKSConnectedCandidateOwner) MeasurementChainContext(ctx context.Context) (*NodeChain, error) {
	if ctx == nil || o.plan.validate() != nil {
		return nil, hopmeasure.ErrStale
	}
	active, err := o.owner.MeasurementSOCKSContext(ctx)
	if err != nil || active != o.plan.original || o.plan.validate() != nil {
		return nil, errors.Join(err, hopmeasure.ErrStale)
	}
	return o.plan.plan.chain, ctx.Err()
}
func (o nodeChainSOCKSConnectedCandidateOwner) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if _, err := o.MeasurementChainContext(ctx); err != nil {
		return nil, err
	}
	release, err := o.owner.BeginMeasurementContext(ctx)
	if err != nil || release == nil {
		return release, errors.Join(err, errors.New("original typed measurement lease unavailable"))
	}
	if _, err := o.MeasurementChainContext(ctx); err != nil {
		release()
		return nil, err
	}
	return release, nil
}
func (o nodeChainSOCKSConnectedCandidateOwner) CandidateInventoryCurrentContext(ctx context.Context, capture string) error {
	if _, err := o.MeasurementChainContext(ctx); err != nil {
		return err
	}
	if capture != o.plan.CaptureSHA256() {
		return hopmeasure.ErrStale
	}
	if err := o.owner.CandidateInventoryCurrentContext(ctx, capture); err != nil {
		return err
	}
	_, err := o.MeasurementChainContext(ctx)
	return err
}

type NodeChainCONNECTConnectedCandidateOwner interface {
	NodeChainCONNECTMeasurementOwner
	CandidateInventoryCurrentContext(context.Context, string) error
}
type NodeChainCONNECTConnectedCandidatePlan struct {
	original *NodeChainCONNECTRuntime
	source   *NodeChainCONNECTSource
	plan     *NodeChainCandidatePlan
}

func NewNodeChainCONNECTConnectedCandidatePlan(original *NodeChainCONNECTRuntime, position int, inventory string) (*NodeChainCONNECTConnectedCandidatePlan, error) {
	if original == nil || original.connectedCandidateSelf != original || original.source == nil || original.chain == nil || original.chain.connectSource != original.source || position < 0 || position >= len(original.chain.nodes)-2 {
		return nil, errors.New("connected CONNECT candidates require the exact original typed packet prefix")
	}
	plan, err := original.chain.newPacketCandidatePlan(position, inventory)
	if err != nil {
		return nil, err
	}
	result := &NodeChainCONNECTConnectedCandidatePlan{original: original, source: original.source, plan: plan}
	return result, result.validate()
}
func (p *NodeChainCONNECTConnectedCandidatePlan) validate() error {
	if p == nil || p.original == nil || p.original.connectedCandidateSelf != p.original || p.source == nil || p.plan == nil || p.plan.chain == nil || p.original.source != p.source || p.original.chain != p.plan.chain || p.plan.chain.connectSource != p.source {
		return errors.New("connected CONNECT candidate lost its original runtime and complete source")
	}
	return p.plan.validate()
}
func (p *NodeChainCONNECTConnectedCandidatePlan) Metadata() string {
	if p.validate() != nil {
		return ""
	}
	return p.plan.Metadata()
}
func (p *NodeChainCONNECTConnectedCandidatePlan) CaptureSHA256() string {
	if p.validate() != nil {
		return ""
	}
	return p.plan.CaptureSHA256()
}
func (p *NodeChainCONNECTConnectedCandidatePlan) NewMeasurementContext(ctx context.Context, owner NodeChainCONNECTConnectedCandidateOwner) (*hopmeasure.CandidateService, error) {
	if ctx == nil || owner == nil || p.validate() != nil {
		return nil, errors.New("connected CONNECT candidate requires its original typed measurement owner")
	}
	return p.plan.NewMeasurementContext(ctx, nodeChainCONNECTConnectedCandidateOwner{p, owner})
}

type nodeChainCONNECTConnectedCandidateOwner struct {
	plan  *NodeChainCONNECTConnectedCandidatePlan
	owner NodeChainCONNECTConnectedCandidateOwner
}

func (o nodeChainCONNECTConnectedCandidateOwner) MeasurementChainContext(ctx context.Context) (*NodeChain, error) {
	if ctx == nil || o.plan.validate() != nil {
		return nil, hopmeasure.ErrStale
	}
	active, err := o.owner.MeasurementCONNECTContext(ctx)
	if err != nil || active != o.plan.original || o.plan.validate() != nil {
		return nil, errors.Join(err, hopmeasure.ErrStale)
	}
	return o.plan.plan.chain, ctx.Err()
}
func (o nodeChainCONNECTConnectedCandidateOwner) BeginMeasurementContext(ctx context.Context) (func(), error) {
	if _, err := o.MeasurementChainContext(ctx); err != nil {
		return nil, err
	}
	release, err := o.owner.BeginMeasurementContext(ctx)
	if err != nil || release == nil {
		return release, errors.Join(err, errors.New("original typed measurement lease unavailable"))
	}
	if _, err := o.MeasurementChainContext(ctx); err != nil {
		release()
		return nil, err
	}
	return release, nil
}
func (o nodeChainCONNECTConnectedCandidateOwner) CandidateInventoryCurrentContext(ctx context.Context, capture string) error {
	if _, err := o.MeasurementChainContext(ctx); err != nil {
		return err
	}
	if capture != o.plan.CaptureSHA256() {
		return hopmeasure.ErrStale
	}
	if err := o.owner.CandidateInventoryCurrentContext(ctx, capture); err != nil {
		return err
	}
	_, err := o.MeasurementChainContext(ctx)
	return err
}
