package main

import (
	"errors"

	"router-vpn/internal/mobilemultihop"
)

// The snapshot retains the exact ordered native objects; no profile, graph
// label, or interface alias can reconstruct this ownership after replacement.
type mtuNodeChainSnapshot struct {
	Launch   *desktopNodeLaunch
	Chain    *desktopNodeChainLaunch
	Native   *nativeMultihopCapture
	Capture  *desktopNodeChainHostCapture
	Sources  *desktopNodeChainSources
	Platform *desktopNodeChainPlatformRuntime
	Policy   *mobilemultihop.DesktopNodeChainPolicy
	Network  string
	Source   string
	Config   string
	Session  string
}

func captureMTUNodeChainSnapshot(owner *nativeMultihopRuntime) (*mtuNodeChainSnapshot, error) {
	if owner == nil || owner.launch == nil {
		return nil, errors.New("ordered MTU snapshot lost its original native launch")
	}
	launch := owner.launch
	if launch.chain == nil {
		if owner.graph.ChainNodes != 0 || len(owner.selection.Nodes) != 0 {
			return nil, errors.New("ordered MTU snapshot cannot borrow a paired launch")
		}
		return nil, nil
	}
	chain, native := launch.chain, owner.selection.Native
	capture := chain.capture
	if native == nil || native.chain == nil || chain.policy == nil || capture == nil || capture.sources == nil ||
		chain.selection.Native != native || native.chain.host != capture || capture.sources.selection.Native != native ||
		owner.graph.ChainNodes != len(owner.selection.Nodes) || owner.graph.ChainNodes < 2 || owner.graph.ChainNodes > 8 ||
		owner.graph.Execution != "local" || owner.graph.ImportedEntry || owner.graph.SourceSHA != native.source ||
		capture.network == "" || owner.network != capture.network || launch.command == nil ||
		(chain.platform == nil) != (capture.windows != nil) || (capture.windows == nil) == (capture.platform == nil) {
		return nil, errors.New("ordered MTU snapshot changed its full source or original platform")
	}
	return &mtuNodeChainSnapshot{Launch: launch, Chain: chain, Native: native, Capture: capture, Sources: capture.sources,
		Platform: chain.platform, Policy: chain.policy, Network: owner.network, Source: native.source,
		Config: launch.configSHA256, Session: launch.mtuSession}, nil
}

// Caller holds app.mu. This checks only retained object associations and the
// complete saved-member inventory. Native Current and full source-file reads
// happen outside app.mu, or through the platform's already-entered host.
func validateMTUNodeChainLocked(a *app, path *mtuMultihopSnapshot) error {
	captured := path.Chain
	owner := path.Native
	if captured == nil || owner == nil || captured.Launch == nil || captured.Chain == nil || captured.Native == nil ||
		captured.Capture == nil || captured.Sources == nil || captured.Policy == nil ||
		owner.launch != captured.Launch || owner.selection.Native != captured.Native ||
		captured.Launch.chain != captured.Chain || captured.Chain.selection.Native != captured.Native ||
		captured.Chain.policy != captured.Policy || captured.Chain.platform != captured.Platform ||
		captured.Chain.capture != captured.Capture || captured.Native.chain == nil ||
		captured.Native.chain.host != captured.Capture || captured.Capture.sources != captured.Sources ||
		captured.Sources.selection.Native != captured.Native || captured.Capture.app != a ||
		captured.Network == "" || owner.network != captured.Network || captured.Capture.network != captured.Network ||
		captured.Native.source != captured.Source || path.Graph.SourceSHA != captured.Source ||
		captured.Launch.configSHA256 != captured.Config || captured.Launch.mtuSession != captured.Session ||
		captured.Launch.command != path.Command || path.Graph.ChainNodes != len(owner.selection.Nodes) ||
		path.Graph.ChainNodes != len(captured.Native.chain.members) || path.Graph.Execution != "local" || path.Relay != nil {
		return errors.New("ordered MTU retained source, command, or native capture was replaced")
	}
	if err := captured.Sources.currentLocked(a); err != nil {
		return err
	}
	if captured.Platform != nil {
		if captured.Capture.platform == nil || captured.Capture.windows != nil || captured.Launch.ownedNode != nil {
			return errors.New("ordered MTU platform borrowed another native owner")
		}
		if _, conflict := desktopNodeOwners.Load(a); conflict {
			return errors.New("ordered MTU platform has conflicting native process ownership")
		}
		return nil
	}
	if captured.Capture.windows == nil || captured.Capture.platform != nil || captured.Launch.ownedNode == nil ||
		captured.Launch.ownedNode.chain != captured.Chain {
		return errors.New("ordered MTU Windows capture lost its original concrete owner")
	}
	if raw, found := desktopNodeOwners.Load(a); !found || raw != captured.Launch {
		return errors.New("ordered MTU Windows TUN was replaced")
	}
	return nil
}

func mtuNodeChainPlatformSnapshot(snapshot mtuRetestSnapshot) bool {
	return snapshot.Multihop != nil && snapshot.Multihop.Chain != nil && snapshot.Multihop.Chain.Platform != nil
}
