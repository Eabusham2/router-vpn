package mobilemultihop

import (
	"context"
	"errors"
	"reflect"

	"router-vpn/internal/hopmeasure"
)

// NodeChainSOCKSEngine adds the mandatory retained middle observation to the
// original complete-chain engine. Native code must check the same source object,
// original Box/outbound manager, middle and preceding packet endpoint objects.
// This observation grants neither complete path proof nor native DOWN.
type NodeChainSOCKSEngine interface {
	NodeChainEngine
	ObserveSOCKSMiddleContext(context.Context, *NodeChainSOCKSSource) error
}

// NodeChainSOCKSRuntime invokes the existing NodeChain controller through one
// distinct typed boundary. Its private chain cannot lend generic launch,
// projection, candidate, Server/Compare or public platform admission.
type NodeChainSOCKSRuntime struct {
	source *NodeChainSOCKSSource
	chain  *NodeChain
}

// NewNodeChainSOCKSRuntime retains the exact source/compiler result. It performs
// no I/O; Run additionally requires the original native middle observer and all
// ordinary private-prefix, public-middle, final DNS and public-exit proofs.
func NewNodeChainSOCKSRuntime(source *NodeChainSOCKSSource) (*NodeChainSOCKSRuntime, error) {
	if source == nil {
		return nil, nodeChainSOCKSSourceError
	}
	config, meta, err := source.ReadValidated()
	if err != nil {
		return nil, err
	}
	chain := &NodeChain{
		sourceJSON: source.sourceJSON, sourceSHA: meta.SourceSHA256, config: config,
		nodes: []*NodeProfile{source.pair.nodes[0], nil, source.pair.nodes[1]},
		socksSource: source, proofs: meta.Proofs, dns: meta.DNS, physical: meta.Physical,
		originalConfigSHA: meta.ConfigSHA256,
	}
	if err := chain.refreshMetadata(); err != nil {
		return nil, err
	}
	chain.seal = chain.captureSeal()
	if err := chain.validateCapture(); err != nil {
		return nil, err
	}
	return &NodeChainSOCKSRuntime{source: source, chain: chain}, nil
}

func (c *NodeChain) validateSOCKSSource() error {
	if c == nil || c.socksSource == nil || c.importedMiddle != nil {
		return nodeChainSOCKSSourceError
	}
	source := c.socksSource
	config, meta, err := source.ReadValidated()
	if err != nil || c.sourceJSON != source.sourceJSON || c.sourceSHA != meta.SourceSHA256 ||
		c.config != config || c.originalConfigSHA != meta.ConfigSHA256 ||
		c.projection != (nodeChainProjection{}) || c.dns != meta.DNS ||
		!reflect.DeepEqual(c.proofs, meta.Proofs) || !reflect.DeepEqual(c.physical, meta.Physical) ||
		len(c.nodes) != 3 || c.nodes[0] != source.pair.nodes[0] ||
		c.nodes[1] != nil || c.nodes[2] != source.pair.nodes[1] {
		return nodeChainSOCKSSourceError
	}
	return nil
}

func (c *NodeChain) observeSOCKSMiddleContext(ctx context.Context, engine NodeChainEngine) error {
	if c.socksSource == nil {
		return nil
	}
	if ctx == nil || c.validateCapture() != nil {
		return nodeChainSOCKSSourceError
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	owned, ok := engine.(NodeChainSOCKSEngine)
	if !ok {
		return errors.New("ordered SOCKS path has no original native middle observer")
	}
	if err := owned.ObserveSOCKSMiddleContext(ctx, c.socksSource); err != nil {
		return err
	}
	return ctx.Err()
}

func (c *NodeChain) hasImportedMiddle() bool {
	return c != nil && (c.importedMiddle != nil || c.socksSource != nil)
}

func (c *NodeChain) importedMiddlePublicIP() string {
	if c.socksSource != nil {
		return c.socksSource.middle.selection.ExpectedPublicIP
	}
	return c.importedMiddle.selection.ExpectedPublicIP
}

func (r *NodeChainSOCKSRuntime) Run(ctx context.Context, engine NodeChainSOCKSEngine) error {
	if r == nil || r.chain == nil || r.source != r.chain.socksSource {
		return nodeChainSOCKSSourceError
	}
	return r.chain.Run(ctx, engine)
}

func (r *NodeChainSOCKSRuntime) Progress() NodeChainProgress {
	if r == nil || r.chain == nil {
		return NodeChainProgress{}
	}
	return r.chain.Progress()
}

func (r *NodeChainSOCKSRuntime) HealthyContext(ctx context.Context) error {
	if r == nil || r.chain == nil || r.source != r.chain.socksSource {
		return nodeChainSOCKSSourceError
	}
	return r.chain.HealthyContext(ctx)
}

// CloseContext joins the existing shared proof/observer work only. The platform
// must then join its original Box and SOCKS association owner; this method does
// not certify native service/TUN retirement or expose a native DOWN receipt.
func (r *NodeChainSOCKSRuntime) CloseContext(ctx context.Context) error {
	if r == nil || r.chain == nil {
		return nodeChainSOCKSSourceError
	}
	return r.chain.CloseContext(ctx)
}

// NodeChainSOCKSMeasurementOwner preserves the existing measurement exclusion
// and retained native identity without exposing the private generic chain.
type NodeChainSOCKSMeasurementOwner interface {
	MeasurementSOCKSContext(context.Context) (*NodeChainSOCKSRuntime, error)
	BeginMeasurementContext(context.Context) (func(), error)
}

type nodeChainSOCKSMeasurementOwner struct {
	source *NodeChainSOCKSSource
	owner  NodeChainSOCKSMeasurementOwner
}

func (o nodeChainSOCKSMeasurementOwner) MeasurementChainContext(ctx context.Context) (*NodeChain, error) {
	active, err := o.owner.MeasurementSOCKSContext(ctx)
	if err != nil {
		return nil, err
	}
	if active == nil || active.chain == nil || active.source != o.source ||
		active.chain.socksSource != o.source || active.chain.validateCapture() != nil {
		return nil, errors.New("ordered SOCKS measurement changed its original source owner")
	}
	return active.chain, nil
}

func (o nodeChainSOCKSMeasurementOwner) BeginMeasurementContext(ctx context.Context) (func(), error) {
	return o.owner.BeginMeasurementContext(ctx)
}

func (r *NodeChainSOCKSRuntime) NewHopMeasurementContext(ctx context.Context, owner NodeChainSOCKSMeasurementOwner) (*hopmeasure.Service, error) {
	if r == nil || r.chain == nil || owner == nil || r.source != r.chain.socksSource {
		return nil, nodeChainSOCKSSourceError
	}
	return r.chain.NewHopMeasurementContext(ctx, nodeChainSOCKSMeasurementOwner{r.source, owner})
}
