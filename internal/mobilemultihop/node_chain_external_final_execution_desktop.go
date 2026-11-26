package mobilemultihop

import "reflect"

// The selected projection and the Local user path share the one sealed desktop
// physical policy. The imported suffix cannot introduce an additional host
// permission, even when a worker serves the prefix through an authenticated front.
func NewDesktopNodeChainExternalFinalExecutionPreparation(original *DesktopNodeChainPolicy, execution string) (*NodeChainExecutionPreparation, error) {
	if original == nil || execution != "server" && execution != "auto" {
		return nil, nodeChainExecutionError
	}
	_, meta, _, err := original.ReadValidated()
	source := original.original
	if err != nil || !source.HasExternalFinal() || source.projection != (nodeChainProjection{}) || original.chain == nil || !original.chain.HasExternalFinal() || meta.ExternalFinal == nil {
		return nil, nodeChainExecutionError
	}
	b, err := newExternalFinalExecutionBinding(source)
	if err != nil {
		return nil, err
	}
	return newNodeChainExecutionPreparationOwnedFamilies(source.sourceJSON, execution, original, nil, source, nil, nil, nil, nil, nil, nil, nil, nil, b)
}

func NewDesktopNodeChainExternalFinalExecutionLastPreparation(original *DesktopNodeChainPolicy, execution, saved string) (*NodeChainExecutionPreparation, error) {
	p, err := NewDesktopNodeChainExternalFinalExecutionPreparation(original, execution)
	if err != nil {
		return nil, err
	}
	return p.withDesktopExecutionLast(saved)
}

func ParseDesktopNodeChainExternalFinalExecutionPreparation(input string) (*NodeChainExecutionPreparation, error) {
	var source NodeChainExecutionPreparationSource
	if exactJSON([]byte(input), &source, NodeChainInputLimit) != nil || source.Schema != 8 || source.Desktop == nil || source.Desktop.ExternalFinal == nil || source.ExternalFinalLocalLaunch == "" {
		return nil, nodeChainExecutionError
	}
	local, err := ParseNodeChainLaunchInput(source.ExternalFinalLocalLaunch)
	if err != nil || !local.HasExternalFinal() || local.sourceJSON != source.LocalSource {
		return nil, nodeChainExecutionError
	}
	m := source.Desktop
	original, err := NewDesktopNodeChainPolicyWithDevicePreference(local, m.SessionID, m.TargetOS, m.RestoredMTU, m.DeviceRevision, m.DeviceFixedMTU)
	if err != nil || !reflect.DeepEqual(original.metadata, *m) {
		return nil, nodeChainExecutionError
	}
	p, err := NewDesktopNodeChainExternalFinalExecutionPreparation(original, source.Execution)
	if err == nil && source.DesktopLast != "" {
		p, err = p.withDesktopExecutionLast(source.DesktopLast)
	}
	if err != nil || p.Source() != input {
		return nil, nodeChainExecutionError
	}
	return p, nil
}

func (p *NodeChainExecutionPreparation) RequiresDesktopExternalFinalExecutionObserver() bool {
	return p != nil && p.RequiresExternalFinalExecutionObserver() && (p.desktop != nil || p.source.Desktop != nil)
}

func (p *NodeChainExecutionPreparation) bindExternalFinalDesktopProjected(policy *NodeChainExecutionPolicy) (*NodeChainExecutionProjection, error) {
	if !p.RequiresDesktopExternalFinalExecutionObserver() || p.validateDesktopCapture() != nil || policy.externalFinal != p.externalFinal {
		return nil, nodeChainExecutionError
	}
	original, err := NewNodeChainExternalFinalExecutionPreparation(p.externalFinal.local, p.Execution())
	if err != nil {
		return nil, err
	}
	exact, err := NewNodeChainExternalFinalExecutionPolicy(original, policy.Source())
	if err != nil {
		return nil, err
	}
	addition, err := original.BindExecution(exact)
	if err != nil {
		return nil, err
	}
	return p.bindProjectedExecutionAddition(policy, addition)
}
