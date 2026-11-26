package mobilemultihop

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
)

type nodeChainExecutionLatencyExternalFinal struct {
	Schema                      int                               `json:"schema"`
	OriginalSourceSHA256        string                            `json:"original_source_sha256"`
	EntrySourceSHA256           string                            `json:"entry_source_sha256"`
	EntryStartLayer             string                            `json:"entry_start_layer"`
	DNSOwner                    string                            `json:"dns_owner"`
	FinalTransportSHA256        string                            `json:"final_transport_sha256"`
	RegisteredFinalSourceSHA256 string                            `json:"registered_final_source_sha256"`
	Public                      []nodeChainExecutionLatencyPublic `json:"public"`
	SourceAuthenticator         string                            `json:"source_authenticator"`
}

// The independent operator's standalone source is authenticated by the original
// selected policy before publication. Bind it and every selected capture field
// to the private original client entry so history can be checked after Close.
func (c *NodeChain) externalFinalLatencyAuthenticator(frame nodeChainExecutionLatencyCapture) (string, error) {
	source := *frame.ExternalFinal
	source.SourceAuthenticator = ""
	frame.ExternalFinal = &source
	raw, err := json.Marshal(frame)
	if err != nil {
		return "", err
	}
	key := sha256.New()
	io.WriteString(key, "routervpn-public-exit-selected-history-key-v1\x00")
	io.WriteString(key, c.nodes[0].config)
	derived := key.Sum(nil)
	defer clear(derived)
	mac := hmac.New(sha256.New, derived)
	io.WriteString(mac, "routervpn-public-exit-selected-history-v1\x00")
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (p *NodeChainExecutionProjection) bindExternalFinalLatencyCapture(frame *nodeChainExecutionLatencyCapture) error {
	original, err := p.preparation.OriginalExternalFinalSource()
	if err != nil {
		return err
	}
	d := p.policy.source.Server
	if !p.policy.externalFinal.matches(d) || frame.MultipleImported != nil {
		return nodeChainExecutionError
	}
	members, _, err := p.ExternalFinalPublicMeasurementCaptures(frame.Execution)
	if err != nil || len(members) != len(d.Members) || len(members)+1 != len(frame.Nodes) {
		return nodeChainExecutionError
	}
	frame.ExternalFinal = &nodeChainExecutionLatencyExternalFinal{
		Schema: 8, OriginalSourceSHA256: original.SourceSHA256(), EntrySourceSHA256: d.ExternalFinal.EntrySourceSHA256,
		EntryStartLayer: d.ExternalFinal.EntryStartLayer, DNSOwner: d.ExternalFinal.DNSOwner,
		FinalTransportSHA256: d.ExternalFinal.FinalTransportSHA256, RegisteredFinalSourceSHA256: d.Members[len(d.Members)-1].SourceSHA256,
	}
	for _, m := range members {
		frame.ExternalFinal.Public = append(frame.ExternalFinal.Public, nodeChainExecutionLatencyPublic{m.Position, m.Tag, m.SourceSHA256})
	}
	frame.ExternalFinal.SourceAuthenticator, err = original.externalFinalLatencyAuthenticator(*frame)
	return err
}

// ValidateExternalFinalLatencyCapture checks a stored selected capture against
// the complete original paired entry and literal public suffix. Live history
// publication separately requires the exact joined measurement and trial.
func (c *NodeChain) ValidateExternalFinalLatencyCapture(raw string) error {
	if !c.HasExternalFinal() || c.validateCapture() != nil {
		return nodeChainExecutionError
	}
	var frame nodeChainExecutionLatencyCapture
	if exactJSON([]byte(raw), &frame, 64<<10) != nil || frame.Schema != 1 || frame.ExternalFinal == nil || frame.MultipleImported != nil ||
		!proofID.MatchString(frame.SourceSHA256) || !proofID.MatchString(frame.ConfigSHA256) || !proofID.MatchString(frame.GenerationSHA256) ||
		frame.Execution != "server" && frame.Execution != "local" || len(frame.Nodes) != len(c.proofs) {
		return nodeChainExecutionError
	}
	x := frame.ExternalFinal
	if x.Schema != 8 || x.OriginalSourceSHA256 != c.SourceSHA256() || x.EntryStartLayer != c.proofs[0].StartLayer ||
		!proofID.MatchString(x.RegisteredFinalSourceSHA256) || !proofID.MatchString(x.SourceAuthenticator) || len(x.Public) != len(c.proofs)-1 {
		return nodeChainExecutionError
	}
	canonical, err := json.Marshal(frame)
	if err != nil || string(canonical) != raw {
		return nodeChainExecutionError
	}
	mac, err := c.externalFinalLatencyAuthenticator(frame)
	if err != nil || !hmac.Equal([]byte(x.SourceAuthenticator), []byte(mac)) {
		return nodeChainExecutionError
	}
	b, err := newExternalFinalExecutionBinding(c)
	if err != nil || b.binding.EntrySourceSHA256 != x.EntrySourceSHA256 || b.binding.DNSOwner != x.DNSOwner || b.binding.FinalTransportSHA256 != x.FinalTransportSHA256 {
		return nodeChainExecutionError
	}
	for pos, proof := range c.proofs {
		role, kind := "entry", "private-node"
		if pos > 0 {
			role, kind = "intermediate", "public-path"
			if pos == len(c.proofs)-1 {
				role = "exit"
			}
			tag, source := proof.Tag, proof.SourceSHA256
			if frame.Execution == "server" {
				tag = nodeChainExecutionServerTag(pos, frame.SourceSHA256)
				if role == "exit" {
					source = x.RegisteredFinalSourceSHA256
				}
			}
			if x.Public[pos-1] != (nodeChainExecutionLatencyPublic{pos, tag, source}) {
				return nodeChainExecutionError
			}
		}
		if frame.Nodes[pos] != (nodeChainExecutionLatencyHop{proof.ProfileID, pos, role, kind}) {
			return nodeChainExecutionError
		}
	}
	return nil
}
