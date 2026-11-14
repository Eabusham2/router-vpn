package macosprocess

import "errors"

// Family identifies the concrete child policy before any private input is
// opened. The zero value preserves the original external-child wire contract.
// An ordered child must explicitly opt into its separate manifest and protocol.
type Family string

const (
	ExternalFamily           Family = ""
	NodeChainFamily          Family = "ordered-node-chain-v1"
	NodeChainSOCKSFamily     Family = "ordered-node-chain-socks-v1"
	NodeChainCONNECTFamily   Family = "ordered-node-chain-connect-v1"
	NodeChainExecutionFamily Family = "ordered-node-chain-execution-v1"
	CandidatePrefixFamily    Family = "node-candidate-prefix-v1"
)

// Scope is the expected policy identity, never a substitute for the original
// descriptor and native main-image observations. Source is the semantic policy
// digest; the capture separately binds every exact private input document.
type Scope struct {
	Session, Source, Config, Workspace string
	Family                             Family
}

type scopeInput struct {
	name  string
	limit int64
}

func (family Family) protocolSchema() int {
	switch family {
	case ExternalFamily:
		return 1
	case NodeChainFamily, NodeChainSOCKSFamily, NodeChainCONNECTFamily, NodeChainExecutionFamily, CandidatePrefixFamily:
		return 2
	default:
		return 0
	}
}

func (scope Scope) inputManifest() ([]scopeInput, error) {
	switch scope.Family {
	case ExternalFamily:
		// Keep the original filenames, order and per-document limit unchanged.
		return []scopeInput{{"source.json", 16 << 20}, {"capture.json", 16 << 20}, {"sing-box.json", 16 << 20}}, nil
	case NodeChainFamily:
		// The ordered source is the canonical complete launch input. It already
		// includes its validated capture/projection; no external-policy adapter
		// or fabricated capture.json participates in this family.
		return []scopeInput{{"node-chain-source.json", 40 << 20}, {"sing-box.json", 4 << 20}}, nil
	case NodeChainSOCKSFamily:
		// Typed SOCKS source cannot reuse an ordinary chain input, even when
		// its outer packet prefix and final node have matching identities.
		return []scopeInput{{"node-chain-socks-source.json", 40 << 20}, {"sing-box.json", 4 << 20}}, nil
	case NodeChainCONNECTFamily:
		// The CONNECT source retains the authenticated HTTP(S) middle and its
		// captured final UDP-over-TCP authority. Other family inputs cannot
		// supply this private launch document, even with equal outer nodes.
		return []scopeInput{{"node-chain-connect-source.json", 40 << 20}, {"sing-box.json", 4 << 20}}, nil
	case CandidatePrefixFamily:
		// This sealed input retains the full saved path for provenance while
		// authorizing only its selected packet prefix. Ordinary chain inputs
		// cannot stand in for this independent, application-closed purpose.
		return []scopeInput{{"node-candidate-prefix-source.json", 40 << 20}, {"sing-box.json", 4 << 20}}, nil
	case NodeChainExecutionFamily:
		// Server and Compare retain their complete execution preparation, not
		// an ordinary Local graph with the same physical packet prefix. The
		// inherited input digest binds the requested execution and discovery.
		return []scopeInput{{"node-chain-execution-source.json", 40 << 20}, {"sing-box.json", 4 << 20}}, nil
	default:
		return nil, errors.New("native child scope has an unsupported concrete policy family")
	}
}
