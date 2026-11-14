package mobilemultihop

import (
	"context"
	"errors"
	"reflect"

	"router-vpn/internal/hopmeasure"
)

// NodeChainCONNECTEngine adds the mandatory retained middle observation to the
// original complete-chain engine. Native code must check the same source object,
// original Box/outbound manager, middle and preceding packet endpoint objects,
// and the exact final's separately captured UoT-v2 carrier. CONNECT itself
// remains TCP-only; no observer may certify a generic UDP association.
// This observation grants neither complete path proof nor native DOWN.
type NodeChainCONNECTEngine interface {
	NodeChainEngine
	ObserveCONNECTMiddleContext(context.Context, *NodeChainCONNECTSource) error
}

// NodeChainCONNECTRuntime invokes the existing NodeChain controller through one
// distinct typed boundary. Its private chain cannot lend generic launch,
// projection, candidate, Server/Compare or public platform admission.
type NodeChainCONNECTRuntime struct {
	source *NodeChainCONNECTSource
	chain  *NodeChain
}

// NewNodeChainCONNECTRuntime retains the exact source/compiler result. It performs
// no I/O; Run additionally requires the original native middle observer and all
// ordinary private-prefix, public-middle, final DNS and public-exit proofs.
func NewNodeChainCONNECTRuntime(source *NodeChainCONNECTSource) (*NodeChainCONNECTRuntime, error) {
	if source == nil {
		return nil, nodeChainCONNECTSourceError
	}
	config, meta, err := source.ReadValidated()
	if err != nil {
		return nil, err
	}
	chain := &NodeChain{
		sourceJSON: source.sourceJSON, sourceSHA: meta.SourceSHA256, config: config,
		nodes:         []*NodeProfile{source.pair.nodes[0], nil, source.pair.nodes[1]},
		connectSource: source, proofs: meta.Proofs, dns: meta.DNS, physical: meta.Physical,
		originalConfigSHA: source.originalConfigSHA256(), projection: source.runtimeProjection(),
	}
	if err := chain.refreshMetadata(); err != nil {
		return nil, err
	}
	chain.seal = chain.captureSeal()
	if err := chain.validateCapture(); err != nil {
		return nil, err
	}
	return &NodeChainCONNECTRuntime{source: source, chain: chain}, nil
}

func (c *NodeChain) validateCONNECTSource() error {
	if c == nil || c.connectSource == nil || c.importedMiddle != nil || c.socksSource != nil {
		return nodeChainCONNECTSourceError
	}
	source := c.connectSource
	config, meta, err := source.ReadValidated()
	if err != nil || c.sourceJSON != source.sourceJSON || c.sourceSHA != meta.SourceSHA256 ||
		c.config != config || c.originalConfigSHA != source.originalConfigSHA256() ||
		c.projection != source.runtimeProjection() || c.dns != meta.DNS ||
		!reflect.DeepEqual(c.proofs, meta.Proofs) || !reflect.DeepEqual(c.physical, meta.Physical) ||
		len(c.nodes) != 3 || c.nodes[0] != source.pair.nodes[0] ||
		c.nodes[1] != nil || c.nodes[2] != source.pair.nodes[1] {
		return nodeChainCONNECTSourceError
	}
	return nil
}

func (c *NodeChain) observeCONNECTMiddleContext(ctx context.Context, engine NodeChainEngine) error {
	if c.connectSource == nil {
		return nil
	}
	if ctx == nil || c.validateCapture() != nil {
		return nodeChainCONNECTSourceError
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	owned, ok := engine.(NodeChainCONNECTEngine)
	if !ok {
		return errors.New("ordered CONNECT path has no original native middle observer")
	}
	if err := owned.ObserveCONNECTMiddleContext(ctx, c.connectSource); err != nil {
		return err
	}
	if err := c.validateCapture(); err != nil {
		return err
	}
	return ctx.Err()
}

func (r *NodeChainCONNECTRuntime) Run(ctx context.Context, engine NodeChainCONNECTEngine) error {
	if r == nil || r.chain == nil || r.source != r.chain.connectSource {
		return nodeChainCONNECTSourceError
	}
	return r.chain.Run(ctx, engine)
}

func (r *NodeChainCONNECTRuntime) Progress() NodeChainProgress {
	if r == nil || r.chain == nil {
		return NodeChainProgress{}
	}
	return r.chain.Progress()
}

func (r *NodeChainCONNECTRuntime) HealthyContext(ctx context.Context) error {
	if r == nil || r.chain == nil || r.source != r.chain.connectSource {
		return nodeChainCONNECTSourceError
	}
	return r.chain.HealthyContext(ctx)
}

// CloseContext joins the existing shared proof/observer work only. The platform
// must then join its original Box and CONNECT/final UoT owner; this method does
// not certify native service/TUN retirement or expose a native DOWN receipt.
func (r *NodeChainCONNECTRuntime) CloseContext(ctx context.Context) error {
	if r == nil || r.chain == nil {
		return nodeChainCONNECTSourceError
	}
	return r.chain.CloseContext(ctx)
}

// NodeChainCONNECTMeasurementOwner preserves the existing measurement exclusion
// and retained native identity without exposing the private generic chain.
type NodeChainCONNECTMeasurementOwner interface {
	MeasurementCONNECTContext(context.Context) (*NodeChainCONNECTRuntime, error)
	BeginMeasurementContext(context.Context) (func(), error)
}

type nodeChainCONNECTMeasurementOwner struct {
	source *NodeChainCONNECTSource
	owner  NodeChainCONNECTMeasurementOwner
}

func (o nodeChainCONNECTMeasurementOwner) MeasurementChainContext(ctx context.Context) (*NodeChain, error) {
	active, err := o.owner.MeasurementCONNECTContext(ctx)
	if err != nil {
		return nil, err
	}
	if active == nil || active.chain == nil || active.source != o.source ||
		active.chain.connectSource != o.source || active.chain.validateCapture() != nil {
		return nil, errors.New("ordered CONNECT measurement changed its original source owner")
	}
	return active.chain, nil
}

func (o nodeChainCONNECTMeasurementOwner) BeginMeasurementContext(ctx context.Context) (func(), error) {
	return o.owner.BeginMeasurementContext(ctx)
}

func (r *NodeChainCONNECTRuntime) NewHopMeasurementContext(ctx context.Context, owner NodeChainCONNECTMeasurementOwner) (*hopmeasure.Service, error) {
	if r == nil || r.chain == nil || owner == nil || r.source != r.chain.connectSource {
		return nil, nodeChainCONNECTSourceError
	}
	return r.chain.NewHopMeasurementContext(ctx, nodeChainCONNECTMeasurementOwner{r.source, owner})
}
