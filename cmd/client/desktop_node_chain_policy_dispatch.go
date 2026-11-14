package main

import (
	"encoding/json"
	"errors"

	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemultihop"
)

// Dispatch is limited to the two retained concrete families. A SOCKS policy
// never becomes a generic NodeChain, nor can equal bytes replace its owner.
func (c *desktopNodeChainLaunch) hasPolicy() bool {
	return c != nil && (c.policy != nil) != (c.socksPolicy != nil)
}
func (c *desktopNodeChainLaunch) readPolicy() (string, mobilemultihop.DesktopNodeChainMetadata, mobilemultihop.DesktopPhysicalCapture, error) {
	if !c.hasPolicy() {
		return "", mobilemultihop.DesktopNodeChainMetadata{}, mobilemultihop.DesktopPhysicalCapture{}, errors.New("ordered parent lost its exclusive concrete policy")
	}
	if c.socksPolicy != nil {
		config, meta, capture, err := c.socksPolicy.ReadValidated()
		return config, meta.DesktopNodeChainMetadata, capture, err
	}
	return c.policy.ReadValidated()
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
	if _, _, _, err := c.readPolicy(); err != nil {
		return "", err
	}
	if c.socksPolicy != nil {
		return c.socksPolicy.LaunchInput()
	}
	return c.policy.NodeChain().LaunchInput()
}
func (c *desktopNodeChainLaunch) originalPolicyCurrent() bool {
	if !c.hasPolicy() || c.selection.Native == nil || c.selection.Native.chain == nil {
		return false
	}
	original := c.selection.Native.chain
	if c.socksPolicy != nil {
		if original.socks == nil || original.chain != nil {
			return false
		}
		source, err := c.socksPolicy.OriginalSource()
		return err == nil && source == original.socks.source
	}
	return original.socks == nil && original.chain != nil && c.policy.OriginalChain() == original.chain
}
func (c *desktopNodeChainLaunch) sourceName() string {
	if c != nil && c.socksPolicy != nil {
		return "node-chain-socks-source.json"
	}
	return "node-chain-source.json"
}
func (c *desktopNodeChainLaunch) readyName() string {
	if c != nil && c.socksPolicy != nil {
		return "node-chain-socks-ready.json"
	}
	return "node-chain-ready.json"
}
func (c *desktopNodeChainLaunch) macOSFamily() macosprocess.Family {
	if c != nil && c.socksPolicy != nil {
		return macosprocess.NodeChainSOCKSFamily
	}
	return macosprocess.NodeChainFamily
}
func (c *desktopNodeChainLaunch) macOSTransfer(selection macosprocess.Selection) (string, error) {
	if !c.hasPolicy() {
		return "", errors.New("ordered transfer has no original policy")
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
	if c.socksPolicy != nil {
		record, err := mobilemultihop.ParseDesktopNodeChainSOCKSReadyRecord(raw, c.socksPolicy, transfer)
		return mobilemultihop.DesktopNodeChainReadyRecord(record), err
	}
	return mobilemultihop.ParseDesktopNodeChainReadyRecord(raw, c.policy, transfer)
}

func newDesktopSOCKSNodeChainLaunch(selection multihopSelection, session, target string) (*desktopNodeLaunch, error) {
	if target != "darwin" || selection.Native == nil || selection.Native.chain == nil || selection.Native.chain.socks == nil || selection.Native.validate(selection) != nil {
		return nil, errors.New("typed SOCKS retained host requires its original Darwin source")
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
