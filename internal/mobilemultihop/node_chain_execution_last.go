package mobilemultihop

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"

	"router-vpn/internal/multihoprelay"
)

const nodeChainExecutionLastLimit = 16 << 10
const nodeChainExtendedLastMaximum = 64 << 10

// The durable record embeds each registered descriptor row. Its limit
// follows the actual original inventory; small and ordinary records keep the
// historical 16 KiB limit.
func nodeChainLastLimit(schema, count int) int {
	if (schema != 8 && schema != 6) || count <= NodeChainMaximumNodes || count > NodeChainExtendedLocalMaximumNodes {
		return nodeChainExecutionLastLimit
	}
	return min(nodeChainExtendedLastMaximum, max(nodeChainExecutionLastLimit, 1024+640*count))
}

// RequiresRegisteredPrivateFinalObservation identifies the original extended
// schema-six family. It is only a dispatch hint. Both the shared selection
// and its native engine verify the complete source and live owners.
func (p *NodeChainExecutionPreparation) RequiresRegisteredPrivateFinalObservation() bool {
	if p == nil || p.multiple == nil || p.source.Schema != 6 || p.externalFinal != nil || p.local == nil || p.multiple.source != p.local ||
		len(p.local.proofs) <= NodeChainMaximumNodes || len(p.local.proofs) > NodeChainExtendedLocalMaximumNodes {
		return false
	}
	privateMiddle, ok := p.local.selectedStreamLayout()
	return ok && privateMiddle == 0
}

func (p *NodeChainExecutionPreparation) originalDeepPrivateFinalCount() int {
	if !p.RequiresRegisteredPrivateFinalObservation() || p.validateCapture() != nil {
		return 0
	}
	return len(p.local.proofs)
}

func (p *NodeChainExecutionPreparation) LastRecordLimit() int {
	if p != nil && p.multiple != nil {
		return nodeChainLastLimit(6, p.originalDeepPrivateFinalCount())
	}
	if p == nil || p.externalFinal == nil || p.validateCapture() != nil {
		return nodeChainExecutionLastLimit
	}
	return nodeChainLastLimit(p.source.Schema, len(p.local.proofs))
}

// Only independently imported public intermediates followed by a paired private
// exit can use the extended schema-six record. Descriptor.Validate also checks
// every digest, expected address, unique identity, layer and original position.
func nodeChainDescriptorLastLimit(d multihoprelay.NodeChainDescriptor) int {
	if d.Schema == 6 {
		n := len(d.Members)
		if n <= multihoprelay.NodeChainMaximumMembers || n > multihoprelay.NodeChainExtendedMaximumMembers || d.ExternalFinal != nil ||
			d.Members[n-1].NodeKind != "" || d.Members[n-1].ProofKind != "" || d.Members[n-1].Mode != "shadowsocks" || d.Members[n-1].StartLayer != "off" {
			return nodeChainExecutionLastLimit
		}
		for _, m := range d.Members[:n-1] {
			if m.NodeKind != "external" || m.ProofKind != "public-path" {
				return nodeChainExecutionLastLimit
			}
		}
	}
	return nodeChainLastLimit(d.Schema, len(d.Members)+1)
}

// The durable record belongs in the app's private storage. It carries source
// bindings and a concrete choice, never credentials, live proof, stop authority
// or a native owner. Its digest detects changed framing/content; authenticity
// and current authority still come from the original profile and fresh entry
// discovery. Parsing a saved record cannot grant Ready or application traffic.
type nodeChainExecutionLastRecord struct {
	Schema            int                               `json:"schema"`
	LocalSourceSHA256 string                            `json:"local_source_sha256"`
	LocalInputSHA256  string                            `json:"local_input_sha256"`
	Setting           string                            `json:"setting"`
	Execution         string                            `json:"execution"`
	Target            string                            `json:"target"`
	Descriptor        multihoprelay.NodeChainDescriptor `json:"descriptor"`
	DescriptorSHA256  string                            `json:"descriptor_sha256"`
	DNSPolicySHA256   string                            `json:"dns_policy_sha256"`
	EntryHost         string                            `json:"entry_host"`
	Peer              string                            `json:"peer"`
	FirstPort         int                               `json:"first_port"`
	LastPort          int                               `json:"last_port"`
	Port              int                               `json:"listen_port"`
	DesktopTargetOS   string                            `json:"desktop_target_os,omitempty"`
	Digest            string                            `json:"digest"`
}

type NodeChainExecutionLast struct {
	record nodeChainExecutionLastRecord
	raw    string
}

func nodeChainExecutionLastDigest(record nodeChainExecutionLastRecord) string {
	record.Digest = ""
	raw, err := json.Marshal(record)
	if err != nil {
		return ""
	}
	return externalDigest(append([]byte("routervpn-node-chain-execution-last-v1\x00"), raw...))
}

func nodeChainLastPrivateAddress(text string) bool {
	address, err := netip.ParseAddr(text)
	return err == nil && address.String() == text && address.Zone() == "" && !address.Is4In6() && address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
}

func (l NodeChainExecutionLast) validate() error {
	r := l.record
	descriptor, err := r.Descriptor.Digest()
	canonical, marshalErr := json.Marshal(r)
	if err != nil || marshalErr != nil || r.Schema != 1 || !proofID.MatchString(r.LocalSourceSHA256) || !proofID.MatchString(r.LocalInputSHA256) ||
		r.Setting != "server" && r.Setting != "auto" || r.Execution != "server" && r.Execution != "local" || r.Setting == "server" && r.Execution != "server" ||
		!nodeChainExecutionTarget(r.Target) || descriptor != r.DescriptorSHA256 || r.DNSPolicySHA256 != r.Descriptor.DNSPolicySHA256 ||
		!nodeChainLastPrivateAddress(r.EntryHost) || !nodeChainLastPrivateAddress(r.Peer) || r.FirstPort < 1024 || r.LastPort > 65535 ||
		r.LastPort < r.FirstPort || r.LastPort-r.FirstPort > 63 || r.Port < r.FirstPort || r.Port > r.LastPort ||
		r.DesktopTargetOS != "" && r.DesktopTargetOS != "linux" && r.DesktopTargetOS != "windows" && r.DesktopTargetOS != "darwin" ||
		!proofID.MatchString(r.Digest) || nodeChainExecutionLastDigest(r) != r.Digest || len(l.raw) > nodeChainDescriptorLastLimit(r.Descriptor) || string(canonical) != l.raw {
		return nodeChainExecutionError
	}
	return nil
}

func (l NodeChainExecutionLast) JSON() string {
	if l.validate() != nil {
		return ""
	}
	return l.raw
}
func (l NodeChainExecutionLast) Execution() string {
	if l.validate() != nil {
		return ""
	}
	return l.record.Execution
}
func (l NodeChainExecutionLast) Target() string {
	if l.validate() != nil {
		return ""
	}
	return l.record.Target
}
func (l NodeChainExecutionLast) LocalSourceSHA256() string {
	if l.validate() != nil {
		return ""
	}
	return l.record.LocalSourceSHA256
}

func (l NodeChainExecutionLast) ValidatePreparation(preparation *NodeChainExecutionPreparation) error {
	if l.validate() != nil || preparation.validateCapture() != nil ||
		l.record.LocalSourceSHA256 != preparation.LocalSourceSHA256() || l.record.LocalInputSHA256 != externalDigest([]byte(preparation.LocalSource())) ||
		l.record.Setting != preparation.Execution() || l.record.Descriptor.EntryID != preparation.local.proofs[0].ProfileID ||
		l.record.Descriptor.EntryNodeID != preparation.local.proofs[0].NodeID || l.record.Descriptor.EntryMode != preparation.local.proofs[0].Mode {
		return nodeChainExecutionError
	}
	if preparation.externalFinal != nil && !preparation.externalFinal.matches(l.record.Descriptor) {
		return nodeChainExecutionError
	}
	if len(l.raw) > nodeChainExecutionLastLimit && l.record.Descriptor.Schema == 6 {
		d := l.record.Descriptor
		if preparation.multiple == nil || preparation.source.Schema != 6 || d.DNSPolicySHA256 != preparation.dns.DNSPolicySHA256 || len(preparation.local.proofs) != len(d.Members)+1 {
			return nodeChainExecutionError
		}
		for i, member := range d.Members {
			position := i + 1
			proof := preparation.local.proofs[position]
			if member.Position != position || member.ProfileID != proof.ProfileID || member.Mode != proof.Mode || member.StartLayer != proof.StartLayer {
				return nodeChainExecutionError
			}
			if position == len(d.Members) {
				if proof.NodeID == "" || member.NodeID != proof.NodeID {
					return nodeChainExecutionError
				}
				continue
			}
			original := preparation.local.importedSSMemberAt(position)
			if original == nil || member.NodeKind != proof.NodeKind || member.ProofKind != proof.Kind ||
				member.SourceSHA256 != original.source || member.SourceSHA256 != proof.SourceSHA256 || member.ExpectedPublicIP != original.selection.ExpectedPublicIP {
				return nodeChainExecutionError
			}
		}
	}
	api, err := privateAPI(preparation.discovery.API)
	if err != nil || api.Hostname() != l.record.EntryHost {
		return nodeChainExecutionError
	}
	target := ""
	if preparation.desktop != nil {
		target = preparation.desktop.metadata.TargetOS
	} else if preparation.connect != nil && preparation.connect.desktop != nil {
		target = preparation.connect.desktop.metadata.TargetOS
	} else if preparation.socks != nil && preparation.socks.desktop != nil {
		target = preparation.socks.desktop.metadata.TargetOS
	} else if preparation.multiple != nil && preparation.multiple.desktop != nil {
		target = preparation.multiple.desktop.metadata.TargetOS
	} else if preparation.openvpn != nil && preparation.openvpn.desktop != nil {
		target = preparation.openvpn.desktop.metadata.TargetOS
	}
	if target != l.record.DesktopTargetOS {
		return nodeChainExecutionError
	}
	return nil
}

// ValidateStoredDesktopExecutionLast checks the canonical choice before any
// private source is opened. Preparing its replay also requires the exact
// original node sources, platform, descriptor and fresh entry discovery.
func ValidateStoredDesktopExecutionLast(raw, setting string) error {
	last, err := readNodeChainExecutionLast(raw)
	if err != nil || last.record.Setting != setting || last.record.DesktopTargetOS == "" {
		return nodeChainExecutionError
	}
	return last.validate()
}

// ValidateStoredDesktopExternalFinalLast binds the selected registry to the
// independently stored public roster before any original private source is read.
func ValidateStoredDesktopExternalFinalLast(raw, setting, entryNodeID, layer string, ids, modes []string) error {
	last, err := readNodeChainExecutionLast(raw)
	if err != nil || last.validate() != nil || last.record.Setting != setting || last.record.DesktopTargetOS == "" || len(ids) < 3 || len(ids) != len(modes) {
		return nodeChainExecutionError
	}
	d := last.record.Descriptor
	if layer == "" {
		layer = "off"
	}
	if d.Schema != 8 || d.ExternalFinal == nil || d.EntryID != ids[0] || d.EntryNodeID != entryNodeID || d.EntryMode != modes[0] || d.ExternalFinal.EntryStartLayer != layer || len(d.Members)+1 != len(ids) {
		return nodeChainExecutionError
	}
	for i, member := range d.Members {
		if member.ProfileID != ids[i+1] || member.Mode != modes[i+1] {
			return nodeChainExecutionError
		}
	}
	return nil
}

func readNodeChainExecutionLast(raw string) (NodeChainExecutionLast, error) {
	var last NodeChainExecutionLast
	if exactJSON([]byte(raw), &last.record, nodeChainExtendedLastMaximum) != nil || len(raw) > nodeChainDescriptorLastLimit(last.record.Descriptor) {
		return last, nodeChainExecutionError
	}
	last.raw = raw
	return last, nil
}

func ParseNodeChainExecutionLast(raw string, preparation *NodeChainExecutionPreparation) (NodeChainExecutionLast, error) {
	if len(raw) > preparation.LastRecordLimit() {
		return NodeChainExecutionLast{}, nodeChainExecutionError
	}
	last, err := readNodeChainExecutionLast(raw)
	if err != nil {
		return NodeChainExecutionLast{}, err
	}
	if err := last.ValidatePreparation(preparation); err != nil {
		return NodeChainExecutionLast{}, err
	}
	return last, nil
}

func (l NodeChainExecutionLast) validateProjection(p *NodeChainExecutionProjection) error {
	if p.validateCapture() != nil || l.ValidatePreparation(p.preparation) != nil {
		return nodeChainExecutionError
	}
	source := p.policy.source
	if !reflect.DeepEqual(l.record.Descriptor, source.Server) || l.record.DescriptorSHA256 != source.Request.DescriptorSHA256 ||
		l.record.DNSPolicySHA256 != source.Request.DNSPolicySHA256 || l.record.EntryHost != p.policy.front.Host || l.record.Peer != source.Request.Peer ||
		l.record.FirstPort != source.FirstPort || l.record.LastPort != source.LastPort || l.record.Port != source.Request.Port {
		return nodeChainExecutionError
	}
	return nil
}

func (r *NodeChainExecutionRuntime) CaptureLastContext(ctx context.Context) (NodeChainExecutionLast, error) {
	if r == nil || ctx == nil {
		return NodeChainExecutionLast{}, nodeChainExecutionError
	}
	if err := ctx.Err(); err != nil {
		return NodeChainExecutionLast{}, err
	}
	// A source/native observation can return after its HTTP work has joined.
	// Keep this original runtime unacknowledged until the final callback exits;
	// otherwise a late observation could retire an already resumed same Box.
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return NodeChainExecutionLast{}, err
	}
	if r.retired.Load() || r.closed || !r.progress.Ready {
		r.mu.Unlock()
		return NodeChainExecutionLast{}, nodeChainExecutionError
	}
	r.lastCaptures++
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.lastCaptures--; r.mu.Unlock() }()
	if err := r.HealthyContext(ctx); err != nil {
		return NodeChainExecutionLast{}, err
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return NodeChainExecutionLast{}, err
	}
	trial, identity := r.active, r.identity
	r.mu.Unlock()
	if trial == nil {
		return NodeChainExecutionLast{}, nodeChainExecutionError
	}
	// A current server receipt is nonce-bound, never a saved health timestamp.
	if err := trial.Verify(ctx); err != nil {
		return NodeChainExecutionLast{}, err
	}
	if err := externalObservationLock(ctx, &r.mu); err != nil {
		return NodeChainExecutionLast{}, err
	}
	if r.retired.Load() || r.closed || !r.progress.Ready || r.active != trial || r.identity != identity || r.progress.Comparison.Winner == nil || ctx.Err() != nil {
		r.mu.Unlock()
		return NodeChainExecutionLast{}, nodeChainExecutionError
	}
	execution, target := r.progress.Execution, r.progress.Comparison.Target
	r.mu.Unlock()
	last, err := r.projection.executionLastRecord(execution, target)
	if err != nil {
		return NodeChainExecutionLast{}, err
	}
	if err := r.current(ctx, trial, true); err != nil {
		return NodeChainExecutionLast{}, err
	}
	if err := r.HealthyContext(ctx); err != nil {
		return NodeChainExecutionLast{}, err
	}
	return last, nil
}

// Serialization alone confers no measurement or live owner. CaptureLastContext
// separately guards this record with the actual selected trial on both sides.
func (p *NodeChainExecutionProjection) executionLastRecord(execution, target string) (NodeChainExecutionLast, error) {
	source := p.policy.source
	descriptor := p.policy.Descriptor()
	digest, err := descriptor.Digest()
	if err != nil {
		return NodeChainExecutionLast{}, err
	}
	last := NodeChainExecutionLast{record: nodeChainExecutionLastRecord{Schema: 1, LocalSourceSHA256: p.preparation.LocalSourceSHA256(),
		LocalInputSHA256: externalDigest([]byte(p.preparation.LocalSource())), Setting: p.Execution(), Execution: execution, Target: target,
		Descriptor: descriptor, DescriptorSHA256: digest, DNSPolicySHA256: descriptor.DNSPolicySHA256,
		EntryHost: p.policy.front.Host, Peer: source.Request.Peer, FirstPort: source.FirstPort, LastPort: source.LastPort, Port: source.Request.Port}}
	if p.preparation.desktop != nil {
		last.record.DesktopTargetOS = p.preparation.desktop.metadata.TargetOS
	} else if p.preparation.connect != nil && p.preparation.connect.desktop != nil {
		last.record.DesktopTargetOS = p.preparation.connect.desktop.metadata.TargetOS
	} else if p.preparation.socks != nil && p.preparation.socks.desktop != nil {
		last.record.DesktopTargetOS = p.preparation.socks.desktop.metadata.TargetOS
	} else if p.preparation.multiple != nil && p.preparation.multiple.desktop != nil {
		last.record.DesktopTargetOS = p.preparation.multiple.desktop.metadata.TargetOS
	} else if p.preparation.openvpn != nil && p.preparation.openvpn.desktop != nil {
		last.record.DesktopTargetOS = p.preparation.openvpn.desktop.metadata.TargetOS
	}
	last.record.Digest = nodeChainExecutionLastDigest(last.record)
	raw, err := json.Marshal(last.record)
	if err != nil {
		return NodeChainExecutionLast{}, err
	}
	last.raw = string(raw)
	if err := last.validateProjection(p); err != nil {
		return NodeChainExecutionLast{}, err
	}
	return last, nil
}
