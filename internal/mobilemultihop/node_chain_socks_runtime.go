package mobilemultihop

import (
	"context"
	"errors"

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
// projection, candidate or public platform admission. A distinct typed
// execution preparation retains this same original source for Server/Compare.
type NodeChainSOCKSRuntime struct {
	connectedCandidateSelf *NodeChainSOCKSRuntime // exact constructor; never exported as generic candidate authority
	source                 *NodeChainSOCKSSource
	chain                  *NodeChain
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
		nodes:       source.runtimeNodes(),
		socksSource: source, proofs: meta.Proofs, dns: meta.DNS, physical: meta.Physical,
		originalConfigSHA: source.originalConfigSHA256(), projection: source.runtimeProjection(),
	}
	if err := chain.refreshMetadata(); err != nil {
		return nil, err
	}
	chain.seal = chain.captureSeal()
	if err := chain.validateCapture(); err != nil {
		return nil, err
	}
	// The constructor just validated every paired node and the exact imported owner.
	// Reuse only their original canonical values; each reader still validates the live source.
	chain.typedOriginal = snapshotOriginalNodeChain(chain)
	original := &NodeChainSOCKSRuntime{source: source, chain: chain}
	original.connectedCandidateSelf = original
	return original, nil
}

// runtimeNodes preserves every original paired pointer and one empty imported
// position. The runtime never reconstructs a same-content substitute owner.
func (s *NodeChainSOCKSSource) runtimeNodes() []*NodeProfile {
	if s == nil || s.pair == nil || len(s.pair.nodes) < 2 {
		return nil
	}
	nodes := append([]*NodeProfile(nil), s.pair.nodes[:len(s.pair.nodes)-1]...)
	return append(nodes, nil, s.pair.nodes[len(s.pair.nodes)-1])
}

func (c *NodeChain) validateSOCKSSource() error {
	if c == nil || c.socksSource == nil || c.importedMiddle != nil || c.openVPNMiddle != nil || c.connectSource != nil {
		return nodeChainSOCKSSourceError
	}
	source := c.socksSource
	meta := &source.metadata
	if source.validate() != nil || c.sourceJSON != source.sourceJSON || c.sourceSHA != meta.SourceSHA256 ||
		c.config != source.config || c.originalConfigSHA != source.originalConfigSHA256() ||
		c.projection != source.runtimeProjection() || c.dns != meta.DNS ||
		!sameTypedSlice(c.proofs, meta.Proofs) || !sameTypedSlice(c.physical, meta.Physical) ||
		len(c.nodes) != len(source.pair.nodes)+1 {
		return nodeChainSOCKSSourceError
	}
	for i, node := range source.runtimeNodes() {
		if c.nodes[i] != node {
			return nodeChainSOCKSSourceError
		}
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
	if err := c.validateCapture(); err != nil {
		return err
	}
	return ctx.Err()
}

func (c *NodeChain) hasImportedMiddle() bool {
	return c != nil && (c.importedMiddle != nil || c.openVPNMiddle != nil || c.socksSource != nil || c.connectSource != nil)
}

// Typed SOCKS, CONNECT and schema-five OpenVPN retain a packet prefix.
// Schema-two imported SS retains its original single-middle position.
func (c *NodeChain) importedMiddlePosition() int {
	if c == nil || !c.hasImportedMiddle() {
		return -1
	}
	if c.connectSource != nil || c.socksSource != nil || c.openVPNMiddle != nil || c.importedMiddle != nil {
		return len(c.nodes) - 2
	}
	return 1
}

func (c *NodeChain) importedMiddlePublicIP() string {
	if c.openVPNMiddle != nil {
		return c.openVPNMiddle.selection.ExpectedPublicIP
	}
	if c.connectSource != nil {
		return c.connectSource.middle.selection.ExpectedPublicIP
	}
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
