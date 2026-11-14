package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"sync"
	"time"

	"router-vpn/internal/multihoprelay"
)

type NodeChainExecutionDiscoveryEngine interface {
	ObserveChainContext(context.Context) (NodeChainIdentity, error)
	Dial(context.Context, string, string) (net.Conn, error)
}

// A discovery owner owns only its original entered control operations. The
// host retains the preparation Box, TUN, entry and closed application gate.
// Close must succeed before that host adopts a final execution projection.
type NodeChainExecutionDiscoveryOwner struct {
	mu       sync.Mutex
	prep     *NodeChainExecutionPreparation
	engine   NodeChainExecutionDiscoveryEngine
	io       *nodeChainExecutionIO
	identity NodeChainIdentity
	raw      string
	planned  bool
}

func NewNodeChainExecutionDiscoveryOwner(prep *NodeChainExecutionPreparation, engine NodeChainExecutionDiscoveryEngine) (*NodeChainExecutionDiscoveryOwner, error) {
	if prep.validateCapture() != nil || engine == nil {
		return nil, nodeChainExecutionError
	}
	discovery, err := prep.Discovery()
	if err != nil {
		return nil, err
	}
	owner := &NodeChainExecutionDiscoveryOwner{prep: prep, engine: engine}
	owner.io, err = newNodeChainExecutionIO(discovery.Entry.Tag, discovery.API, discovery.Token, engine.Dial, owner.current)
	if err != nil {
		return nil, err
	}
	return owner, nil
}

func (o *NodeChainExecutionDiscoveryOwner) current(ctx context.Context) error {
	if o == nil || ctx == nil || ctx.Err() != nil || o.io.closed.Load() || o.prep.validateCapture() != nil {
		return nodeChainExecutionError
	}
	observed, err := o.engine.ObserveChainContext(ctx)
	if err != nil {
		return err
	}
	if ctx.Err() != nil || o.io.closed.Load() || !nodeChainIdentityText(observed.EngineID) || !nodeChainIdentityText(observed.SessionID) || !nodeChainIdentityText(observed.NetworkID) ||
		observed.SourceSHA256 != o.prep.SourceSHA256() || observed.ConfigSHA256 != o.prep.ConfigSHA256() {
		return nodeChainExecutionError
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.io.closed.Load() {
		return nodeChainExecutionError
	}
	if o.identity == (NodeChainIdentity{}) {
		o.identity = observed
	}
	if o.identity != observed {
		return nodeChainExecutionError
	}
	return nil
}

// Identity is the original observed snapshot, not a fresh observation. A zero
// value means no successful native observation has yet been captured.
func (o *NodeChainExecutionDiscoveryOwner) Identity() NodeChainIdentity {
	if o == nil {
		return NodeChainIdentity{}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.identity
}

func parseNodeChainExecutionDiscovery(raw string, entryNodeID string, now time.Time) (NodeChainExecutionDiscovery, error) {
	var d NodeChainExecutionDiscovery
	if now.IsZero() || exactJSON([]byte(raw), &d, multihoprelay.MaxNodeChainCapabilitiesBytes) != nil || d.NodeID != entryNodeID ||
		d.Challenge.Validate() != nil || d.Challenge.ExpiresAt <= now.Unix() || d.Challenge.ExpiresAt > now.Add(time.Minute).Unix() ||
		d.FirstPort < 1024 || d.LastPort > 65535 || d.LastPort < d.FirstPort || d.LastPort-d.FirstPort > 63 ||
		len(d.Sources) < 1 || len(d.Sources) > multihoprelay.MaxPairedExits {
		return NodeChainExecutionDiscovery{}, nodeChainExecutionError
	}
	seen := map[string]bool{}
	for _, source := range d.Sources {
		if source.Validate() != nil || source.EntryNodeID != d.NodeID || seen[source.SourceSHA256] {
			return NodeChainExecutionDiscovery{}, nodeChainExecutionError
		}
		seen[source.SourceSHA256] = true
	}
	return d, nil
}

func (o *NodeChainExecutionDiscoveryOwner) Discover(ctx context.Context) (NodeChainExecutionDiscovery, error) {
	if o == nil || ctx == nil {
		return NodeChainExecutionDiscovery{}, nodeChainExecutionError
	}
	o.mu.Lock()
	already := o.raw != "" || o.planned
	o.mu.Unlock()
	if already {
		return NodeChainExecutionDiscovery{}, nodeChainExecutionError
	}
	data, err := o.io.exchange(ctx, "GET", "/health", nil, 8192)
	if err != nil {
		return NodeChainExecutionDiscovery{}, err
	}
	var proof struct {
		OK     bool   `json:"ok"`
		NodeID string `json:"node_id"`
		Proof  string `json:"proof"`
	}
	entry := o.prep.local.proofs[0]
	if exactJSON(data, &proof, 8192) != nil || !proof.OK || proof.NodeID != entry.NodeID || proof.Proof != "router-vpn-private-agent-v1" {
		return NodeChainExecutionDiscovery{}, nodeChainExecutionError
	}
	data, err = o.io.exchange(ctx, "GET", nodeChainExecutionLeasePath, nil, multihoprelay.MaxNodeChainCapabilitiesBytes)
	if err != nil {
		return NodeChainExecutionDiscovery{}, err
	}
	discovery, err := parseNodeChainExecutionDiscovery(string(data), entry.NodeID, time.Now())
	if err != nil {
		return NodeChainExecutionDiscovery{}, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.io.closed.Load() || ctx.Err() != nil || o.raw != "" || o.planned {
		return NodeChainExecutionDiscovery{}, nodeChainExecutionError
	}
	o.raw = string(data)
	return discovery, nil
}

// PlanContext accepts an explicit source digest or exactly one complete
// identity match. It never picks the first advertised source, changes the
// requested port or silently substitutes different source/DNS/key identities.
// The caller must close this discovery owner before native graph adoption.
func (o *NodeChainExecutionDiscoveryOwner) PlanContext(ctx context.Context, sourceSHA string, port int) (*NodeChainExecutionProjection, error) {
	if o == nil || ctx == nil || sourceSHA != "" && !proofID.MatchString(sourceSHA) {
		return nil, nodeChainExecutionError
	}
	if err := o.io.observe(ctx); err != nil {
		return nil, err
	}
	o.mu.Lock()
	raw, planned := o.raw, o.planned
	o.mu.Unlock()
	if raw == "" || planned {
		return nil, nodeChainExecutionError
	}
	discovery, err := parseNodeChainExecutionDiscovery(raw, o.prep.local.proofs[0].NodeID, time.Now())
	if err != nil || port < discovery.FirstPort || port > discovery.LastPort {
		return nil, nodeChainExecutionError
	}
	var selected *NodeChainExecutionPolicy
	for _, descriptor := range discovery.Sources {
		if ctx.Err() != nil || o.io.closed.Load() {
			return nil, nodeChainExecutionError
		}
		if sourceSHA != "" && sourceSHA != descriptor.SourceSHA256 {
			continue
		}
		policy, err := o.prep.policyForDiscovery(descriptor, discovery, port)
		if err != nil {
			continue
		}
		if selected != nil {
			return nil, errors.New("ordered server source selection is ambiguous")
		}
		selected = policy
	}
	if selected == nil {
		return nil, nodeChainExecutionError
	}
	projection, err := o.prep.BindExecution(selected)
	if err != nil {
		return nil, err
	}
	// All pure compilation work remains outside a native/Home lock; observe
	// again after it so a changed network cannot authorize an old result.
	if err := o.io.observe(ctx); err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.io.closed.Load() || ctx.Err() != nil || o.raw != raw || o.planned {
		return nil, nodeChainExecutionError
	}
	o.planned = true
	return projection, nil
}

func (p *NodeChainExecutionPreparation) policyForDiscovery(descriptor multihoprelay.NodeChainDescriptor, discovery NodeChainExecutionDiscovery, port int) (*NodeChainExecutionPolicy, error) {
	if p.validateCapture() != nil {
		return nil, nodeChainExecutionError
	}
	digest, err := descriptor.Digest()
	if err != nil {
		return nil, err
	}
	request := multihoprelay.NodeChainRequest{Schema: descriptor.Schema, EntryNodeID: descriptor.EntryNodeID, SourceSHA256: descriptor.SourceSHA256,
		DescriptorSHA256: digest, DNSPolicySHA256: descriptor.DNSPolicySHA256, Epoch: discovery.Challenge.Epoch,
		Peer: discovery.Challenge.Peer, AcquireExpiresAt: discovery.Challenge.ExpiresAt, Port: port}
	request.SessionID, err = randomHex(16)
	if err != nil {
		return nil, err
	}
	for position, node := range p.local.nodes[:len(p.local.nodes)-1] {
		if node == nil {
			if position != 1 || p.local.importedMiddle == nil || descriptor.Schema != 2 {
				return nil, nodeChainExecutionError
			}
			continue
		}
		key, err := node.PacketClientPublicKey()
		if err != nil {
			return nil, err
		}
		request.LocalPacketPublicKeys = append(request.LocalPacketPublicKeys, key)
		if descriptor.Schema == 2 {
			request.LocalPacketPositions = append(request.LocalPacketPositions, position)
		}
	}
	for _, member := range descriptor.Members {
		username, err := randomHex(24)
		if err != nil {
			return nil, err
		}
		password, err := randomHex(24)
		if err != nil {
			return nil, err
		}
		request.Users = append(request.Users, multihoprelay.NodeChainUser{Position: member.Position, Username: username, Password: password})
	}
	source := NodeChainExecutionSource{Schema: 1, Execution: p.source.Execution, LocalSource: p.source.LocalSource,
		Server: descriptor.Clone(), Request: request, FirstPort: discovery.FirstPort, LastPort: discovery.LastPort}
	raw, err := json.Marshal(source)
	if err != nil {
		return nil, err
	}
	policy, err := NewNodeChainExecutionPolicy(string(raw))
	if err != nil || !reflect.DeepEqual(policy.Descriptor(), descriptor) {
		return nil, nodeChainExecutionError
	}
	return policy, nil
}

func (o *NodeChainExecutionDiscoveryOwner) Close(ctx context.Context) error {
	if o == nil {
		return nodeChainExecutionError
	}
	return o.io.close(ctx)
}
