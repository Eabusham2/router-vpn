package mobiletor

import "strings"

// MeasurementIdentity is used inside the retained native Tor proof. These
// captured private fields never appear in public proof or measurement JSON.
func (p *PredecessorProof) MeasurementIdentity() (id, api, token, node string) {
	if p == nil {
		return
	}
	return p.id, strings.TrimSuffix(p.target, "/health"), p.token, p.node
}
