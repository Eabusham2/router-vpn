package main

import (
	"errors"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

// This is only the controller's immutable descriptor. It has no native engine
// and cannot perform a measurement. The child constructs the same plan using
// its original proved typed runtime and retains that runtime through drain.
type desktopTypedCandidateDescriptor struct {
	launch        *desktopNodeLaunch
	socksPolicy   *mobilemultihop.DesktopNodeChainSOCKSPolicy
	connectPolicy *mobilemultihop.DesktopNodeChainCONNECTPolicy
	socksSource   *mobilemultihop.NodeChainSOCKSSource
	connectSource *mobilemultihop.NodeChainCONNECTSource
	socksPlan     *mobilemultihop.NodeChainSOCKSConnectedCandidatePlan
	connectPlan   *mobilemultihop.NodeChainCONNECTConnectedCandidatePlan
}

func desktopTypedCandidateSourceAllowed(launch *desktopNodeLaunch) bool {
	if launch == nil || launch.chain == nil || !launch.chain.hasPolicy() || launch.chain.policy != nil ||
		launch.chain.execution != nil || launch.chain.preparation != nil || launch.command == nil {
		return false
	}
	// This permits only a source descriptor for a staged concrete typed host.
	// Catalog currentness and the exchange still require the original proved
	// connected identity and its concrete Ready parser before any native work.
	return launch.chain.socksPolicy != nil || launch.chain.connectPolicy != nil
}

func captureDesktopTypedCandidateDescriptor(launch *desktopNodeLaunch, position int, inventory string) (*desktopTypedCandidateDescriptor, error) {
	if !desktopTypedCandidateSourceAllowed(launch) {
		return nil, errors.New("typed connected candidates require their original full-path capture")
	}
	d := &desktopTypedCandidateDescriptor{launch: launch}
	var err error
	if launch.chain.socksPolicy != nil {
		d.socksPolicy = launch.chain.socksPolicy
		d.socksSource, err = d.socksPolicy.NativeSource()
		if err != nil {
			return nil, err
		}
		original, err := mobilemultihop.NewNodeChainSOCKSRuntime(d.socksSource)
		if err != nil {
			return nil, err
		}
		d.socksPlan, err = mobilemultihop.NewNodeChainSOCKSConnectedCandidatePlan(original, position, inventory)
	} else {
		d.connectPolicy = launch.chain.connectPolicy
		d.connectSource, err = d.connectPolicy.NativeSource()
		if err != nil {
			return nil, err
		}
		original, err := mobilemultihop.NewNodeChainCONNECTRuntime(d.connectSource)
		if err != nil {
			return nil, err
		}
		d.connectPlan, err = mobilemultihop.NewNodeChainCONNECTConnectedCandidatePlan(original, position, inventory)
	}
	if err != nil {
		return nil, err
	}
	return d, d.current()
}

// The native policy and typed source are immutable constructor objects. A live
// pulse checks their exact retained pointers without rebuilding the graph for
// every sample; current performs the full sealed validation at admission and
// result adoption, and the child checks its actual proof/reader and source files.
func (d *desktopTypedCandidateDescriptor) ownsOriginalFamily() bool {
	if d == nil || !desktopTypedCandidateSourceAllowed(d.launch) {
		return false
	}
	chain := d.launch.chain
	return d.socksPolicy != nil && d.socksSource != nil && d.socksPlan != nil &&
		d.connectPolicy == nil && d.connectSource == nil && d.connectPlan == nil && chain.socksPolicy == d.socksPolicy ||
		d.connectPolicy != nil && d.connectSource != nil && d.connectPlan != nil &&
			d.socksPolicy == nil && d.socksSource == nil && d.socksPlan == nil && chain.connectPolicy == d.connectPolicy
}

func (d *desktopTypedCandidateDescriptor) current() error {
	bad := errors.New("typed candidate descriptor changed its original native source family")
	if !d.ownsOriginalFamily() {
		return bad
	}
	chain := d.launch.chain
	if d.socksPolicy != nil && d.socksSource != nil && d.socksPlan != nil &&
		d.connectPolicy == nil && d.connectSource == nil && d.connectPlan == nil && chain.socksPolicy == d.socksPolicy {
		source, err := d.socksPolicy.NativeSource()
		if err == nil && source == d.socksSource && d.socksPlan.Metadata() != "" && d.socksPlan.CaptureSHA256() != "" {
			return nil
		}
	}
	if d.connectPolicy != nil && d.connectSource != nil && d.connectPlan != nil &&
		d.socksPolicy == nil && d.socksSource == nil && d.socksPlan == nil && chain.connectPolicy == d.connectPolicy {
		source, err := d.connectPolicy.NativeSource()
		if err == nil && source == d.connectSource && d.connectPlan.Metadata() != "" && d.connectPlan.CaptureSHA256() != "" {
			return nil
		}
	}
	return bad
}

func (d *desktopTypedCandidateDescriptor) Metadata() string {
	if d.current() != nil {
		return ""
	}
	if d.socksPlan != nil {
		return d.socksPlan.Metadata()
	}
	return d.connectPlan.Metadata()
}

func (d *desktopTypedCandidateDescriptor) CaptureSHA256() string {
	if d.current() != nil {
		return ""
	}
	if d.socksPlan != nil {
		return d.socksPlan.CaptureSHA256()
	}
	return d.connectPlan.CaptureSHA256()
}

func (c *desktopNodeChainCandidateCatalog) hasConnectedPlan() bool {
	if c == nil || c.prefixPreparation != nil {
		return false
	}
	if c.selectedPlan != nil {
		return c.plan == nil && c.typedPlan == nil && c.selectedPlan.launch == c.launch && c.selectedPlan.ownsOriginalFamily()
	}
	if c.plan != nil {
		return c.typedPlan == nil
	}
	return c.typedPlan != nil && c.typedPlan.launch == c.launch && c.typedPlan.ownsOriginalFamily()
}

func validateDesktopCandidateCatalogStatus(c *desktopNodeChainCandidateCatalog, id string, status hopmeasure.CandidateStatus, now time.Time) error {
	if !c.hasConnectedPlan() {
		return errors.New("candidate receipt lost its exact connected source family")
	}
	if c.selectedPlan != nil {
		return validateDesktopSelectedCandidateStatus(c.selectedPlan, id, status, now)
	}
	if c.typedPlan != nil {
		return validateDesktopNodeChainCandidateStatus(c.typedPlan, id, status, now)
	}
	return validateDesktopNodeChainCandidateStatus(c.plan, id, status, now)
}
