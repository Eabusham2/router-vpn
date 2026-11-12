package main

import (
	"encoding/json"
	"errors"
)

const mtuDarwinOrderedInterfacePolicy = "darwin-ordered-reader-v1"

// Only the retained Darwin ordered wrapper implements this capability. It
// confirms exact native reader/kernel receipts, including a separately joined
// cleanup receipt; an interface name is never mutation authority.
type mtuInterfaceSuccessionOwner interface {
	validateMTUInterfaceSuccession(initial, previous, next mtuKernelState, cleanup bool) error
}

func (owner *mtuLiveOwner) interfaceSuccessionCapabilityLocked() (mtuInterfaceSuccessionOwner, error) {
	capability, present := owner.kernel.(mtuInterfaceSuccessionOwner)
	if !present {
		return nil, nil
	}
	path := owner.snapshot.Multihop
	if path == nil || path.Chain == nil || path.Native == nil {
		return nil, errors.New("MTU interface succession lost its original ordered snapshot")
	}
	chain := path.Chain
	if chain.Launch == nil || chain.Chain == nil || chain.Platform == nil || chain.Policy == nil ||
		chain.Policy.Validate() != nil || chain.Policy.Metadata().TargetOS != "darwin" ||
		chain.Launch.chain != chain.Chain || chain.Chain.platform != chain.Platform ||
		chain.Chain.policy != chain.Policy || path.Native.launch != chain.Launch ||
		path.Command == nil || path.Command != owner.command || chain.Launch.command != owner.command ||
		path.Graph.Execution != "local" || path.Graph.ChainNodes < 2 || path.Graph.ChainNodes > 8 ||
		!desktopNodeChainDarwinInterfaceName(owner.initial.Interface) {
		return nil, errors.New("MTU interface succession substituted its original Darwin owner")
	}
	return capability, nil
}

// Caller holds the outer operation lock. A typed native Change/Read has already
// produced the next receipt. No failed validation advances outer ownership.
func (owner *mtuLiveOwner) validateInterfaceReadbackLocked(previous, next mtuKernelState, cleanup bool) error {
	if !validMTUKernelState(owner.initial) || !validMTUKernelState(previous) || !validMTUKernelState(next) ||
		previous.Family != owner.initial.Family || next.Family != owner.initial.Family {
		return errors.New("MTU interface succession changed its captured family or valid readback")
	}
	capability, err := owner.interfaceSuccessionCapabilityLocked()
	if err != nil {
		return err
	}
	if capability == nil {
		if previous.Interface != owner.initial.Interface || next.Interface != owner.initial.Interface {
			return errors.New("fixed-name MTU owner changed its original interface")
		}
		return nil
	}
	if !desktopNodeChainDarwinInterfaceName(previous.Interface) || !desktopNodeChainDarwinInterfaceName(next.Interface) {
		return errors.New("ordered Darwin MTU returned another interface family")
	}
	return capability.validateMTUInterfaceSuccession(owner.initial, previous, next, cleanup)
}

func (owner *mtuLiveOwner) interfaceReplyLocked(state mtuKernelState) (mtuOwnerReply, error) {
	capability, err := owner.interfaceSuccessionCapabilityLocked()
	if err != nil || state != owner.current {
		return mtuOwnerReply{}, errors.Join(err, errors.New("MTU reply lost its exact captured readback"))
	}
	reply := mtuOwnerReply{Owner: owner.token, Interface: state.Interface, Family: state.Family,
		Index: state.Index, MTU: state.MTU, Identity: state.Identity}
	if capability != nil {
		reply.OriginalInterface = owner.initial.Interface
		reply.InterfacePolicy = mtuDarwinOrderedInterfacePolicy
	}
	return reply, nil
}

// The utility compares the optional scope with the environment supplied by the
// original controller. Legacy/fixed-name owners cannot silently opt into it.
func validateMTUInterfaceScope(original, policy string) error {
	if original == "" && policy == "" {
		return nil
	}
	if policy != mtuDarwinOrderedInterfacePolicy || !desktopNodeChainDarwinInterfaceName(original) {
		return errors.New("invalid original MTU interface succession scope")
	}
	return nil
}

func validateMTUOwnerReplyFields(raw []byte, scoped bool) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return errors.New("MTU reply has no exact original field inventory")
	}
	expected := []string{"owner_token", "interface", "family", "index", "mtu", "identity"}
	if scoped {
		expected = append(expected, "original_interface", "interface_policy")
	}
	if len(fields) != len(expected) {
		return errors.New("MTU reply changed its exact original field inventory")
	}
	for _, name := range expected {
		if _, present := fields[name]; !present {
			return errors.New("MTU reply omitted an original field")
		}
	}
	return nil
}

func validateMTUOwnerReplyScope(reply mtuOwnerReply, original, policy string) error {
	if err := validateMTUInterfaceScope(original, policy); err != nil {
		return err
	}
	if original == "" && policy == "" {
		if reply.OriginalInterface != "" || reply.InterfacePolicy != "" {
			return errors.New("unrequested MTU interface succession scope")
		}
		return nil
	}
	if policy != mtuDarwinOrderedInterfacePolicy || reply.InterfacePolicy != policy ||
		!desktopNodeChainDarwinInterfaceName(original) || reply.OriginalInterface != original ||
		!desktopNodeChainDarwinInterfaceName(reply.Interface) {
		return errors.New("MTU interface succession scope changed")
	}
	return nil
}

func (owner *mtuLiveOwner) validateMeasurementInterface(measurement mtuMeasurementResult, live mtuLiveSnapshot) error {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || live.Interface != owner.initial.Interface || live.Family != owner.initial.Family ||
		live.OriginalMTU != owner.initial.MTU || measurement.Interface != owner.current.Interface {
		return errors.New("MTU measurement lost its original operation or current interface")
	}
	capability, err := owner.interfaceSuccessionCapabilityLocked()
	if err != nil {
		return err
	}
	if capability == nil {
		if measurement.OriginalInterface != "" || measurement.InterfacePolicy != "" {
			return errors.New("fixed-name MTU measurement invented interface succession")
		}
	} else if measurement.OriginalInterface != owner.initial.Interface ||
		measurement.InterfacePolicy != mtuDarwinOrderedInterfacePolicy {
		return errors.New("MTU measurement lost its original Darwin interface scope")
	}
	return owner.validateInterfaceReadbackLocked(owner.current, owner.current, false)
}
