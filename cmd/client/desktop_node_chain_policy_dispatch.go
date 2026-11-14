package main

import (
	"encoding/json"
	"errors"

	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemultihop"
)

// Dispatch is limited to exactly one retained concrete family. Typed proxy
// sources never become generic NodeChains, nor can equal bytes replace owners.
func (c *desktopNodeChainLaunch) hasPolicy() bool {
	if c == nil {
		return false
	}
	return desktopNodeChainConcretePolicyCount(c.policy, c.socksPolicy, c.connectPolicy) == 1
}

func desktopNodeChainConcretePolicyCount(chain *mobilemultihop.DesktopNodeChainPolicy, socks *mobilemultihop.DesktopNodeChainSOCKSPolicy, connect *mobilemultihop.DesktopNodeChainCONNECTPolicy) int {
	count := 0
	for _, present := range []bool{chain != nil, socks != nil, connect != nil} {
		if present {
			count++
		}
	}
	return count
}
func (c *desktopNodeChainLaunch) readPolicy() (string, mobilemultihop.DesktopNodeChainMetadata, mobilemultihop.DesktopPhysicalCapture, error) {
	if !c.hasPolicy() {
		return "", mobilemultihop.DesktopNodeChainMetadata{}, mobilemultihop.DesktopPhysicalCapture{}, errors.New("ordered parent lost its exclusive concrete policy")
	}
	if c.socksPolicy != nil {
		config, meta, capture, err := c.socksPolicy.ReadValidated()
		return config, meta.DesktopNodeChainMetadata, capture, err
	}
	if c.connectPolicy != nil {
		config, meta, capture, err := c.connectPolicy.ReadValidated()
		return config, meta.DesktopNodeChainMetadata, capture, err
	}
	return c.policy.ReadValidated()
}

// Read all immutable launch fields from one full canonical validation. Keep
// the exact original source comparison here; equal bytes are not an owner.
func (c *desktopNodeChainLaunch) readLaunchPolicy() (string, mobilemultihop.DesktopNodeChainMetadata, string, error) {
	bad := errors.New("ordered launch lost its exact concrete original source")
	if !c.hasPolicy() || c.selection.Native == nil || c.selection.Native.chain == nil {
		return "", mobilemultihop.DesktopNodeChainMetadata{}, "", bad
	}
	original := c.selection.Native.chain
	if c.connectPolicy != nil {
		if original.connect == nil || original.chain != nil || original.socks != nil {
			return "", mobilemultihop.DesktopNodeChainMetadata{}, "", bad
		}
		capture, err := c.connectPolicy.ReadValidatedLaunch()
		if err != nil || capture.Original != original.connect.source {
			return "", mobilemultihop.DesktopNodeChainMetadata{}, "", errors.Join(err, bad)
		}
		return capture.Config, capture.Metadata.DesktopNodeChainMetadata, capture.Input, nil
	}
	if c.socksPolicy != nil {
		if original.socks == nil || original.chain != nil || original.connect != nil {
			return "", mobilemultihop.DesktopNodeChainMetadata{}, "", bad
		}
		capture, err := c.socksPolicy.ReadValidatedLaunch()
		if err != nil || capture.Original != original.socks.source {
			return "", mobilemultihop.DesktopNodeChainMetadata{}, "", errors.Join(err, bad)
		}
		return capture.Config, capture.Metadata.DesktopNodeChainMetadata, capture.Input, nil
	}
	if original.socks != nil || original.connect != nil || original.chain == nil {
		return "", mobilemultihop.DesktopNodeChainMetadata{}, "", bad
	}
	capture, err := c.policy.ReadValidatedLaunch()
	if err != nil || capture.Original != original.chain {
		return "", mobilemultihop.DesktopNodeChainMetadata{}, "", errors.Join(err, bad)
	}
	return capture.Config, capture.Metadata, capture.Input, nil
}

func (c *desktopNodeChainLaunch) policyMetadata() mobilemultihop.DesktopNodeChainMetadata {
	_, meta, _, _ := c.readPolicy()
	return meta
}
func (c *desktopNodeChainLaunch) policyConfig() string {
	config, _, _, _ := c.readPolicy()
	return config
}
func (c *desktopNodeChainLaunch) launchInput() (string, error) {
	if !c.hasPolicy() {
		return "", errors.New("ordered input lost its exclusive concrete policy")
	}
	// Concrete accessors below fully validate their sealed policy. Do not
	// rederive the complete graph once more merely to select the family.
	if c.socksPolicy != nil {
		return c.socksPolicy.LaunchInput()
	}
	if c.connectPolicy != nil {
		return c.connectPolicy.LaunchInput()
	}
	chain := c.policy.NodeChain()
	if chain == nil {
		return "", errors.New("ordered input lost its sealed original policy")
	}
	return chain.LaunchInput()
}
func (c *desktopNodeChainLaunch) originalPolicyCurrent() bool {
	if !c.hasPolicy() || c.selection.Native == nil || c.selection.Native.chain == nil {
		return false
	}
	original := c.selection.Native.chain
	if c.connectPolicy != nil {
		if original.connect == nil || original.socks != nil || original.chain != nil {
			return false
		}
		source, err := c.connectPolicy.OriginalSource()
		return err == nil && source == original.connect.source
	}
	if c.socksPolicy != nil {
		if original.socks == nil || original.chain != nil || original.connect != nil {
			return false
		}
		source, err := c.socksPolicy.OriginalSource()
		return err == nil && source == original.socks.source
	}
	return original.socks == nil && original.connect == nil && original.chain != nil && c.policy.OriginalChain() == original.chain
}
func (c *desktopNodeChainLaunch) sourceName() string {
	if !c.hasPolicy() {
		return ""
	}
	if c.connectPolicy != nil {
		return "node-chain-connect-source.json"
	}
	if c != nil && c.socksPolicy != nil {
		return "node-chain-socks-source.json"
	}
	return "node-chain-source.json"
}
func (c *desktopNodeChainLaunch) readyName() string {
	if !c.hasPolicy() {
		return ""
	}
	if c.connectPolicy != nil {
		return "node-chain-connect-ready.json"
	}
	if c != nil && c.socksPolicy != nil {
		return "node-chain-socks-ready.json"
	}
	return "node-chain-ready.json"
}
func (c *desktopNodeChainLaunch) macOSFamily() macosprocess.Family {
	if !c.hasPolicy() {
		return ""
	}
	if c.connectPolicy != nil {
		return macosprocess.NodeChainCONNECTFamily
	}
	if c != nil && c.socksPolicy != nil {
		return macosprocess.NodeChainSOCKSFamily
	}
	return macosprocess.NodeChainFamily
}
func (c *desktopNodeChainLaunch) macOSTransfer(selection macosprocess.Selection) (string, error) {
	if !c.hasPolicy() {
		return "", errors.New("ordered transfer has no original policy")
	}
	if c.connectPolicy != nil {
		return macosprocess.NodeChainCONNECTTransferSHA256(selection)
	}
	if c.socksPolicy != nil {
		return macosprocess.NodeChainSOCKSTransferSHA256(selection)
	}
	return macosprocess.NodeChainTransferSHA256(selection)
}
func (c *desktopNodeChainLaunch) parseReady(raw []byte, transfer string) (mobilemultihop.DesktopNodeChainReadyRecord, error) {
	if !c.hasPolicy() {
		return mobilemultihop.DesktopNodeChainReadyRecord{}, errors.New("ordered readiness has no original policy")
	}
	if c.connectPolicy != nil {
		record, err := mobilemultihop.ParseDesktopNodeChainCONNECTReadyRecord(raw, c.connectPolicy, transfer)
		return mobilemultihop.DesktopNodeChainReadyRecord(record), err
	}
	if c.socksPolicy != nil {
		record, err := mobilemultihop.ParseDesktopNodeChainSOCKSReadyRecord(raw, c.socksPolicy, transfer)
		return mobilemultihop.DesktopNodeChainReadyRecord(record), err
	}
	return mobilemultihop.ParseDesktopNodeChainReadyRecord(raw, c.policy, transfer)
}

func newDesktopSOCKSNodeChainLaunch(selection multihopSelection, session, target string) (*desktopNodeLaunch, error) {
	if (target != "darwin" && target != "windows" && target != "linux") || selection.Native == nil || selection.Native.chain == nil || selection.Native.chain.socks == nil || selection.Native.validate(selection) != nil {
		return nil, errors.New("typed SOCKS retained host requires its original supported platform source")
	}
	policy, err := mobilemultihop.NewDesktopNodeChainSOCKSPolicy(selection.Native.chain.socks.source, session, target, selection.restoreMTU)
	if err != nil {
		return nil, err
	}
	config, meta, _, err := policy.ReadValidated()
	if err != nil || meta.ProfileID != selection.Control.ID || meta.NodeID != selection.Exit.NodeProofID || meta.Mode != selection.ExitMode || meta.OriginalSourceSHA256 != selection.Native.source {
		return nil, errors.Join(err, errors.New("typed SOCKS projection changed its original final authority"))
	}
	input, err := policy.LaunchInput()
	if err != nil {
		return nil, err
	}
	receipt, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	selection.Control, selection.Entry, selection.Exit = cloneRouterProfile(selection.Control), cloneRouterProfile(selection.Entry), cloneRouterProfile(selection.Exit)
	selection.Nodes = cloneDesktopNodeChainMembers(selection.Nodes)
	return &desktopNodeLaunch{root: selection.Native.root, endpoint: selection.Native.endpoint,
		profileID: selection.Exit.ID, policyProfileID: selection.Control.ID, mode: selection.ExitMode,
		config: []byte(config), metadata: receipt, configSHA256: meta.ConfigSHA256, mtuSession: session,
		nodePhysicalEgress: append([]mobilemultihop.PhysicalEgress(nil), selection.Native.entryPhysical...),
		chain:              &desktopNodeChainLaunch{socksPolicy: policy, selection: selection, input: input}}, nil
}

func newDesktopCONNECTNodeChainLaunch(selection multihopSelection, session, target string) (*desktopNodeLaunch, error) {
	if (target != "darwin" && target != "windows" && target != "linux") || selection.Native == nil || selection.Native.chain == nil || selection.Native.chain.connect == nil || selection.Native.validate(selection) != nil {
		return nil, errors.New("typed CONNECT retained host requires its original supported platform source")
	}
	policy, err := mobilemultihop.NewDesktopNodeChainCONNECTPolicy(selection.Native.chain.connect.source, session, target, selection.restoreMTU)
	if err != nil {
		return nil, err
	}
	config, meta, _, err := policy.ReadValidated()
	if err != nil || meta.ProfileID != selection.Control.ID || meta.NodeID != selection.Exit.NodeProofID || meta.Mode != selection.ExitMode || meta.OriginalSourceSHA256 != selection.Native.source {
		return nil, errors.Join(err, errors.New("typed CONNECT projection changed its original final authority"))
	}
	input, err := policy.LaunchInput()
	if err != nil {
		return nil, err
	}
	receipt, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	selection.Control, selection.Entry, selection.Exit = cloneRouterProfile(selection.Control), cloneRouterProfile(selection.Entry), cloneRouterProfile(selection.Exit)
	selection.Nodes = cloneDesktopNodeChainMembers(selection.Nodes)
	return &desktopNodeLaunch{root: selection.Native.root, endpoint: selection.Native.endpoint,
		profileID: selection.Exit.ID, policyProfileID: selection.Control.ID, mode: selection.ExitMode,
		config: []byte(config), metadata: receipt, configSHA256: meta.ConfigSHA256, mtuSession: session,
		nodePhysicalEgress: append([]mobilemultihop.PhysicalEgress(nil), selection.Native.entryPhysical...),
		chain:              &desktopNodeChainLaunch{connectPolicy: policy, selection: selection, input: input}}, nil
}

// The physical-policy boundary accepts only the original sealed concrete family.
func (c *desktopNodeChainLaunch) physicalPolicy() (mobilemultihop.DesktopPhysicalPolicy, error) {
	if !c.hasPolicy() || !c.originalPolicyCurrent() {
		return nil, errors.New("ordered physical policy lost its original concrete source")
	}
	// originalPolicyCurrent already performs full concrete validation while
	// matching the exact original source pointer. Physical readers and ready
	// parsers subsequently retain their own canonical policy validation.
	if c.socksPolicy != nil {
		return c.socksPolicy, nil
	}
	if c.connectPolicy != nil {
		return c.connectPolicy, nil
	}
	return c.policy, nil
}
func (c *desktopNodeChainLaunch) commandName() string {
	if !c.hasPolicy() {
		return ""
	}
	if c.connectPolicy != nil {
		return "routervpn-node-chain-connect"
	}
	if c != nil && c.socksPolicy != nil {
		return "routervpn-node-chain-socks"
	}
	return "routervpn-node-chain"
}

// Public admission follows installed native WFP/nft acceptance, not compilation.
// Native fixtures use the explicit internal retained-parent constructors.
func nativeNodeChainSOCKSPlatformSupported() bool { return false }

func desktopNodeChainSelectionHasSOCKS(selection multihopSelection) bool {
	for _, member := range selection.Nodes {
		if member.Mode == "socks5" {
			return true
		}
	}
	return false
}

// Physical WFP/nft/PF acceptance is a separate gate from typed compilation.
func nativeNodeChainCONNECTPlatformSupported() bool { return false }

func desktopNodeChainSelectionHasCONNECT(selection multihopSelection) bool {
	for _, member := range selection.Nodes {
		if member.Mode == "http-connect" || member.Mode == "https-connect" {
			return true
		}
	}
	return false
}
