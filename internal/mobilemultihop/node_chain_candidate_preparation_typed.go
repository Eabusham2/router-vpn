package mobilemultihop

import (
	"encoding/json"
	"errors"
)

const (
	nodeChainSOCKSCandidatePreparationKind   = "routervpn-node-chain-socks-candidate-preparation"
	nodeChainCONNECTCandidatePreparationKind = "routervpn-node-chain-connect-candidate-preparation"
)

// This owner retains the complete typed saved source. Its paired chain is
// usable only as that exact owner's prefix compiler input, never as substituted
// schema-one provenance. No imported association or suffix owner is started.
type nodeChainCandidateTypedOriginal struct {
	socks   *NodeChainSOCKSSource
	connect *NodeChainCONNECTSource
}

type nodeChainCandidateTypedRead struct {
	pair                                             *NodeChain
	kind, source, sourceSHA, config, configSHA, seal string
	devices                                          []nodeChainImportedDevicePolicy
}

func (o *nodeChainCandidateTypedOriginal) read() (nodeChainCandidateTypedRead, error) {
	var r nodeChainCandidateTypedRead
	if o == nil || (o.socks == nil) == (o.connect == nil) {
		return r, nodeChainCandidatePreparationError
	}
	if s := o.socks; s != nil {
		if s.validate() != nil || s.desktop != nil {
			return r, nodeChainCandidatePreparationError
		}
		r.pair, r.kind, r.source, r.sourceSHA, r.config, r.configSHA, r.seal = s.pair, nodeChainSOCKSCandidatePreparationKind, s.sourceJSON, s.metadata.SourceSHA256, s.config, s.metadata.ConfigSHA256, s.seal
		for _, d := range s.metadata.Devices {
			r.devices = append(r.devices, nodeChainImportedDevicePolicy{d.KillSwitchPolicy, d.IPv6Mode, d.HomeLANAccess})
		}
	} else {
		s := o.connect
		if s.validate() != nil || s.desktop != nil {
			return r, nodeChainCandidatePreparationError
		}
		r.pair, r.kind, r.source, r.sourceSHA, r.config, r.configSHA, r.seal = s.pair, nodeChainCONNECTCandidatePreparationKind, s.sourceJSON, s.metadata.SourceSHA256, s.config, s.metadata.ConfigSHA256, s.seal
		for _, d := range s.metadata.Devices {
			r.devices = append(r.devices, nodeChainImportedDevicePolicy{d.KillSwitchPolicy, d.IPv6Mode, d.HomeLANAccess})
		}
	}
	if r.pair == nil || len(r.devices) != len(r.pair.nodes)+1 || len(r.devices) < 3 || len(r.devices) > NodeChainMaximumNodes {
		return nodeChainCandidateTypedRead{}, nodeChainCandidatePreparationError
	}
	return r, nil
}

// NewNodeChainSOCKSCandidatePreparation captures the complete schema-three
// source but compiles only its selected original WG/AWG prefix. SOCKS TCP/UDP
// association, authentication and the final remain uncontacted provenance.
func NewNodeChainSOCKSCandidatePreparation(source string, position int, inventory string) (*NodeChainCandidatePreparation, error) {
	original, err := NewNodeChainSOCKSSource(source)
	if err != nil {
		return nil, err
	}
	return newNodeChainTypedCandidatePreparation(&nodeChainCandidateTypedOriginal{socks: original}, position, inventory)
}

// NewNodeChainCONNECTCandidatePreparation retains the complete schema-four
// capture without starting CONNECT, TLS, UoT or any unselected member.
func NewNodeChainCONNECTCandidatePreparation(source string, position int, inventory string) (*NodeChainCandidatePreparation, error) {
	original, err := NewNodeChainCONNECTSource(source)
	if err != nil {
		return nil, err
	}
	return newNodeChainTypedCandidatePreparation(&nodeChainCandidateTypedOriginal{connect: original}, position, inventory)
}

func newNodeChainTypedCandidatePreparation(original *nodeChainCandidateTypedOriginal, position int, inventory string) (*NodeChainCandidatePreparation, error) {
	r, err := original.read()
	if err != nil || position < 0 || position >= len(r.devices)-2 {
		return nil, errors.Join(err, nodeChainCandidatePreparationError)
	}
	// The common compiler receives the original pair pointer, while the
	// complete typed graph supplies the saved TUN/routing restrictions. Its
	// source envelope and every subsequent validation retain this typed owner.
	return newNodeChainCandidatePreparation(r.pair, original, position, inventory)
}

func parseNodeChainTypedCandidatePreparation(input, kind string) (*NodeChainCandidatePreparation, error) {
	var record nodeChainCandidatePreparationSource
	if exactJSON([]byte(input), &record, NodeChainInputLimit) != nil || record.Kind != kind || record.Schema != 1 {
		return nil, nodeChainCandidatePreparationError
	}
	var p *NodeChainCandidatePreparation
	var err error
	switch kind {
	case nodeChainSOCKSCandidatePreparationKind:
		p, err = NewNodeChainSOCKSCandidatePreparation(record.OriginalSource, record.PrefixPosition, record.Inventory)
	case nodeChainCONNECTCandidatePreparationKind:
		p, err = NewNodeChainCONNECTCandidatePreparation(record.OriginalSource, record.PrefixPosition, record.Inventory)
	default:
		return nil, nodeChainCandidatePreparationError
	}
	if err != nil || p == nil || p.source != input {
		return nil, errors.Join(err, nodeChainCandidatePreparationError)
	}
	return p, nil
}

func ParseNodeChainSOCKSCandidatePreparation(input string) (*NodeChainCandidatePreparation, error) {
	return parseNodeChainTypedCandidatePreparation(input, nodeChainSOCKSCandidatePreparationKind)
}

func ParseNodeChainCONNECTCandidatePreparation(input string) (*NodeChainCandidatePreparation, error) {
	return parseNodeChainTypedCandidatePreparation(input, nodeChainCONNECTCandidatePreparationKind)
}

// ParseNodeChainCandidatePreparationCapture is an explicit closed union for
// candidate-only native adapters. Each branch replays its own strict source
// compiler and canonical envelope. Ordinary NodeChain and generic candidate
// parsers remain closed to the typed families.
func ParseNodeChainCandidatePreparationCapture(input string) (*NodeChainCandidatePreparation, error) {
	if len(input) == 0 || len(input) > NodeChainInputLimit {
		return nil, nodeChainCandidatePreparationError
	}
	var header struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal([]byte(input), &header) != nil {
		return nil, nodeChainCandidatePreparationError
	}
	switch header.Kind {
	case "routervpn-node-chain-candidate-preparation":
		return ParseNodeChainCandidatePreparation(input)
	case nodeChainSOCKSCandidatePreparationKind:
		return ParseNodeChainSOCKSCandidatePreparation(input)
	case nodeChainCONNECTCandidatePreparationKind:
		return ParseNodeChainCONNECTCandidatePreparation(input)
	default:
		return nil, nodeChainCandidatePreparationError
	}
}

// Read only after fresh typed validation. This contributes the sealed complete
// owner to the preparation digest without serializing pointers or granting a
// second source authority. Exact retained pair ownership is checked separately.
func (o *nodeChainCandidateTypedOriginal) seal() string {
	if o == nil || (o.socks == nil) == (o.connect == nil) {
		return ""
	}
	if o.socks != nil {
		return nodeChainSOCKSCandidatePreparationKind + ":" + o.socks.seal
	}
	return nodeChainCONNECTCandidatePreparationKind + ":" + o.connect.seal
}
func (p *NodeChainCandidatePreparation) originalSourceSHA() string {
	if p.typedOriginal != nil {
		if p.typedOriginal.socks != nil {
			return p.typedOriginal.socks.metadata.SourceSHA256
		}
		if p.typedOriginal.connect != nil {
			return p.typedOriginal.connect.metadata.SourceSHA256
		}
		return ""
	}
	return p.original.sourceSHA
}
