package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sync/atomic"

	"router-vpn/internal/awgpolicy"
)

// NodeChainServerCarrier is an original-source-bound native route observation.
// Its fields and acquisition hooks are private: callers cannot supply a numeric
// MTU or turn a saved measurement into current native routing authority.
// InterfaceMTU and RouteMTU are kernel configuration bounds, not measured PMTU.
type NodeChainServerCarrier struct {
	source, sourceSHA, seal string
	target                  PhysicalEgress
	snapshot                nodeChainServerCarrierSnapshot
	read                    func(context.Context) (nodeChainServerCarrierSnapshot, error)
	invalid                 atomic.Bool
	close                   func(context.Context) error
}

type nodeChainServerCarrierSnapshot struct {
	NamespaceDevice, NamespaceInode                             uint64
	InterfaceIndex, InterfaceMTU, RouteMTU                      int
	InterfaceName, InterfaceAddress, SourceAddress, RouteSHA256 string
}

var nodeChainServerCarrierError = errors.New("ordered Server lost its original native carrier")

func (s nodeChainServerCarrierSnapshot) validate(target PhysicalEgress) error {
	source, err := netip.ParseAddr(s.SourceAddress)
	destination, failure := netip.ParseAddr(target.Host)
	if err != nil || failure != nil || source.IsUnspecified() || source.Is4In6() || source.Zone() != "" ||
		source.Is6() != destination.Is6() || s.NamespaceInode == 0 || s.InterfaceIndex <= 0 || s.InterfaceName == "" ||
		s.InterfaceMTU < 1280 || s.RouteMTU < 0 || s.RouteMTU > s.InterfaceMTU || s.RouteMTU > 0 && s.RouteMTU < 1280 ||
		!proofID.MatchString(s.RouteSHA256) || target.Network != "udp" || target.Port < 1 || target.Port > 65535 {
		return nodeChainServerCarrierError
	}
	return nil
}

func (c *NodeChainServerCarrier) digest() string {
	raw, _ := json.Marshal([]any{"routervpn-server-native-carrier-v1", c.sourceSHA, c.target, c.snapshot})
	return externalDigest(raw)
}
func (c *NodeChainServerCarrier) sealed() bool {
	return c != nil && c.read != nil && c.seal != "" && c.digest() == c.seal && !c.invalid.Load() && c.snapshot.validate(c.target) == nil
}

// CurrentContext irreversibly retires this observation after route/source loss.
// A later return to equal route values cannot revive a failed observation.
func (c *NodeChainServerCarrier) CurrentContext(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.Join(nodeChainServerCarrierError, contextError(ctx))
	}
	if !c.sealed() {
		return nodeChainServerCarrierError
	}
	current, err := c.read(ctx)
	if err != nil || current != c.snapshot || current.validate(c.target) != nil {
		c.invalid.Store(true)
		return errors.Join(nodeChainServerCarrierError, err)
	}
	if ctx.Err() != nil || !c.sealed() {
		return errors.Join(nodeChainServerCarrierError, ctx.Err())
	}
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nodeChainServerCarrierError
	}
	return ctx.Err()
}

func nodeChainServerCarrierTarget(p *NodeChainServerPolicy) (PhysicalEgress, error) {
	if p == nil || p.validateCapture() != nil || len(p.nodes) == 0 {
		return PhysicalEgress{}, nodeChainServerCarrierError
	}
	first := p.nodes[0]
	if first.mode != "wg" && first.mode != "awg2-fast" && first.mode != "awg2-strong" {
		return PhysicalEgress{}, nodeChainServerCarrierError
	}
	egress, err := first.PhysicalEgress()
	if err != nil || len(egress) != 1 || egress[0].Network != "udp" {
		return PhysicalEgress{}, nodeChainServerCarrierError
	}
	ip, err := netip.ParseAddr(egress[0].Host)
	if err != nil || ip.Is4In6() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return PhysicalEgress{}, nodeChainServerCarrierError
	}
	return egress[0], nil
}

// The native constructor supplies the route reader. Kept private so external
// callers cannot inject arbitrary route numbers or replacement owners.
func captureNodeChainServerCarrier(ctx context.Context, policy *NodeChainServerPolicy, read func(context.Context) (nodeChainServerCarrierSnapshot, error)) (*NodeChainServerCarrier, error) {
	if ctx == nil || ctx.Err() != nil || read == nil {
		return nil, nodeChainServerCarrierError
	}
	target, err := nodeChainServerCarrierTarget(policy)
	if err != nil {
		return nil, err
	}
	observed, err := read(ctx)
	if err != nil || observed.validate(target) != nil {
		return nil, errors.Join(nodeChainServerCarrierError, err)
	}
	c := &NodeChainServerCarrier{source: policy.sourceJSON, sourceSHA: policy.sourceSHA, target: target, snapshot: observed, read: read}
	c.seal = c.digest()
	if err := c.CurrentContext(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// ProjectContext constructs a new complete policy before config hashing and
// proof binding. The original policy/source stays unchanged. All later packet
// edges are recomputed by the existing complete ordered-graph compiler.
func (c *NodeChainServerCarrier) ProjectContext(ctx context.Context) (*NodeChainServerPolicy, error) {
	if err := c.CurrentContext(ctx); err != nil {
		return nil, err
	}
	policy, err := newNodeChainServerPolicy(c.source, c)
	if err != nil {
		return nil, err
	}
	if err := c.CurrentContext(ctx); err != nil {
		return nil, err
	}
	return policy, nil
}

func (c *NodeChainServerCarrier) apply(first *NodeProfile, closure *externalPredecessor) error {
	if !c.sealed() || first == nil || closure == nil {
		return nodeChainServerCarrierError
	}
	destination := netip.MustParseAddr(c.target.Host)
	var parameters map[string]string
	if first.mode != "wg" {
		encoded, _ := json.Marshal(closure.final)
		var config AmneziaEndpointConfig
		if json.Unmarshal(encoded, &config) != nil {
			return nodeChainServerCarrierError
		}
		parameters = config.Parameters
	}
	base, err := awgpolicy.Envelope(parameters, destination.Is6(), 0)
	if err != nil {
		return err
	}
	layer, err := nodePacketEnvelope(closure, first.mode)
	if err != nil {
		return err
	}
	overhead := 0
	if layer != 0 {
		overhead = layer - base.DataOverhead
	}
	envelope, err := awgpolicy.Envelope(parameters, destination.Is6(), overhead)
	if err != nil {
		return err
	}
	requested, err := mtuNumber(closure.final["mtu"])
	if err != nil {
		return err
	}
	fixed, err := fixedMTU(first.profile)
	if err != nil {
		return err
	}
	if fixed != 0 {
		requested = fixed
	}
	bound := min(c.snapshot.InterfaceMTU, 9000)
	if c.snapshot.RouteMTU != 0 {
		bound = min(bound, c.snapshot.RouteMTU)
	}
	derived, err := envelope.Capacity(bound, requested, fixed != 0)
	if err != nil {
		return err
	}
	closure.final["mtu"], closure.tun["mtu"] = float64(derived), float64(derived)
	return nil
}

// CloseContext retires and joins the original native observation. A timeout is
// not cleanup success: the same owner remains available for a later join.
func (c *NodeChainServerCarrier) CloseContext(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.Join(nodeChainServerCarrierError, contextError(ctx))
	}
	if c == nil {
		return nil
	}
	c.invalid.Store(true)
	if c.close != nil {
		return c.close(ctx)
	}
	return nil
}

// Bind only the exact outer first transport to the captured carrier. A private
// direct dialer lets WG and AWG retain their existing strict option parsers.
// Its source/namespace/route-derived tag binds the config hash to this owner.
func (c *NodeChainServerCarrier) bind(graph map[string]any, firstTag string) error {
	if !c.sealed() {
		return nodeChainServerCarrierError
	}
	nodes := map[string]map[string]any{}
	for _, family := range []string{"endpoints", "outbounds"} {
		rows, ok := graph[family].([]any)
		if !ok {
			return nodeChainServerCarrierError
		}
		for _, raw := range rows {
			node, ok := raw.(map[string]any)
			if !ok {
				return nodeChainServerCarrierError
			}
			tag := predecessorText(node, "tag")
			if tag == "" || nodes[tag] != nil {
				return nodeChainServerCarrierError
			}
			nodes[tag] = node
		}
	}
	outer := nodes[firstTag]
	if outer == nil {
		return nodeChainServerCarrierError
	}
	// A fixed local listen port is outside this client-owned captured flow.
	if port, exists := outer["listen_port"]; exists && port != float64(0) {
		return nodeChainServerCarrierError
	}
	if detour := predecessorText(outer, "detour"); detour != "" {
		outer = nodes[detour]
		if outer == nil || outer["detour"] != nil {
			return nodeChainServerCarrierError
		}
	}
	tag := "routervpn-server-carrier-" + c.seal[:24]
	if nodes[tag] != nil {
		return nodeChainServerCarrierError
	}
	bound := map[string]any{"type": "direct", "tag": tag, "bind_interface": c.snapshot.InterfaceName}
	field := "inet4_bind_address"
	if netip.MustParseAddr(c.snapshot.SourceAddress).Is6() {
		field = "inet6_bind_address"
	}
	bound[field] = c.snapshot.SourceAddress
	outer["detour"] = tag
	graph["outbounds"] = append(graph["outbounds"].([]any), bound)
	return nil
}
