package main

import (
	"context"
	"errors"
	"time"

	"router-vpn/internal/desktopnetwork"
)

// The native platform capture is separate from the portable ordered source.
// Restoration retains this original controller/package and all saved members;
// each successor still receives a fresh native session and latest predecessor.
type desktopNodeChainHostCapture struct {
	app         *app
	windows     *desktopNodeConnectionOwner
	platform    *desktopNodeChainPlatformCapture
	sources     *desktopNodeChainSources
	network     string
	readNetwork func(context.Context) (string, error)
}

type desktopNodeChainSources struct {
	selection multihopSelection
	selected  string
	options   [3]bool
}

func captureDesktopNodeChainSourcesLocked(a *app, selection multihopSelection) (*desktopNodeChainSources, error) {
	if a == nil || selection.Native == nil || selection.Native.chain == nil || selection.Native.validate(selection) != nil {
		return nil, errors.New("ordered host capture lost its complete source")
	}
	selection.Control, selection.Entry, selection.Exit = cloneRouterProfile(selection.Control), cloneRouterProfile(selection.Entry), cloneRouterProfile(selection.Exit)
	selection.Nodes = cloneDesktopNodeChainMembers(selection.Nodes)
	s := &desktopNodeChainSources{selection: selection, selected: a.profiles.SelectedID,
		options: [3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks}}
	return s, s.currentLocked(a)
}

func (s *desktopNodeChainSources) currentLocked(a *app) error {
	if s == nil || a == nil || s.selection.Native == nil || s.selection.Native.chain == nil ||
		s.selected != s.selection.Control.ID || a.profiles.SelectedID != s.selected ||
		[3]bool{a.state.DAITA, a.state.Jumbo, a.state.Socks} != s.options ||
		s.options != [3]bool{s.selection.Control.DAITAEnabled, s.selection.Control.JumboTUN, s.selection.Control.SocksEnabled} {
		return errors.New("ordered host changed its final control or runtime options")
	}
	if !s.selection.Native.chain.profilesCurrent(s.selection.Control, a.profiles.Profiles) {
		return errors.New("ordered host changed a selected member's complete saved source")
	}
	return nil
}

func captureDesktopNodeChainHostContext(ctx context.Context, a *app, selection multihopSelection) (*desktopNodeChainHostCapture, error) {
	return captureDesktopNodeChainHostContextWith(ctx, a, selection, physicalNetworkIdentityContext)
}

// The modeled tests supply only the physical inventory boundary. Shipping
// captures the original native observer above and retains it for all reads.
func captureDesktopNodeChainHostContextWith(ctx context.Context, a *app, selection multihopSelection,
	observe func(context.Context) (string, error)) (*desktopNodeChainHostCapture, error) {
	if ctx == nil || ctx.Err() != nil || a == nil || observe == nil || selection.Native == nil || selection.Native.chain == nil || selection.Native.validate(selection) != nil {
		return nil, errors.New("ordered host requires its original caller and full captured source")
	}
	if captured := selection.Native.chain.host; captured != nil {
		if captured.app != a || captured.sources == nil || captured.sources.selection.Native != selection.Native {
			return nil, errors.New("ordered source belongs to another retained controller")
		}
		return captured, captured.current(ctx)
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	sources, err := captureDesktopNodeChainSourcesLocked(a, selection)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	network, err := observe(ctx)
	if err != nil || network == "" {
		return nil, errors.Join(err, errors.New("ordered host has no captured physical network"))
	}
	capture := &desktopNodeChainHostCapture{app: a, sources: sources, network: network, readNetwork: observe}
	host, err := a.desktopNodeConnectionHostContext(ctx)
	if err != nil {
		return nil, err
	}
	if host != nil {
		if host.capture == nil || host.verify == nil || host.start == nil {
			return nil, errors.New("ordered Windows host lost its original controller capabilities")
		}
		captured, err := host.capture(a)
		if err != nil {
			return nil, err
		}
		capture.windows = &desktopNodeConnectionOwner{host: *host, capture: captured}
		if captured.dataRoot != selection.Native.root {
			return nil, errors.New("ordered Windows source belongs to another private root")
		}
	} else {
		capture.platform, err = captureDesktopNodeChainPlatform(ctx, a, selection)
		if err != nil {
			return nil, err
		}
	}
	if err := capture.current(ctx); err != nil {
		return nil, err
	}
	selection.Native.chain.host = capture
	return capture, nil
}

func (capture *desktopNodeChainHostCapture) current(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || capture == nil || capture.app == nil || capture.sources == nil ||
		capture.readNetwork == nil || (capture.windows == nil) == (capture.platform == nil) {
		return errors.New("ordered host lost its one concrete original controller")
	}
	var err error
	if capture.windows != nil {
		err = capture.windows.currentContext(ctx)
	} else {
		err = capture.platform.current(ctx)
	}
	if err != nil {
		return err
	}
	network, err := capture.readNetwork(ctx)
	if err != nil || network != capture.network || network == "" {
		return errors.Join(err, errors.New("ordered host changed its original physical network"))
	}
	if err := desktopnetwork.LockContext(ctx, &capture.app.mu); err != nil {
		return err
	}
	defer capture.app.mu.Unlock()
	return capture.sources.currentLocked(capture.app)
}

func prepareDesktopNodeChainHost(ctx context.Context, a *app, selection multihopSelection) (*desktopNodeLaunch, string, error) {
	return prepareDesktopNodeChainHostForPurpose(ctx, a, selection, nil)
}

func prepareDesktopNodeChainHostForPurpose(ctx context.Context, a *app, selection multihopSelection, purpose *orderedCandidatePreparation) (*desktopNodeLaunch, string, error) {
	if purpose != nil && (purpose.app != a || purpose.selection.Native != selection.Native) {
		return nil, "", errors.New("ordered preparation purpose belongs to another original source")
	}
	capture, err := captureDesktopNodeChainHostContext(ctx, a, selection)
	if err != nil {
		return nil, "", err
	}
	return prepareDesktopNodeChainCapturedHost(ctx, capture, selection, purpose, nil)
}

func prepareDesktopNodeChainCapturedHost(ctx context.Context, capture *desktopNodeChainHostCapture, selection multihopSelection, purpose *orderedCandidatePreparation, execution *desktopNodeChainExecutionRequest) (*desktopNodeLaunch, string, error) {
	if capture == nil || capture.current(ctx) != nil || execution != nil && (purpose != nil || execution.capture != capture || execution.native != selection.Native) {
		return nil, "", errors.New("ordered native preparation lost its retained source and host")
	}
	if capture.windows != nil {
		binary, err := verifiedDesktopImportedPackage(ctx, capture.windows)
		if err != nil {
			return nil, "", err
		}
		launch, err := prepareDesktopOwnedNodeChainLaunchForPurposeAndExecution(ctx, capture, selection, purpose, execution)
		return launch, binary, err
	}
	if execution != nil {
		return prepareDesktopNodeChainExecutionPlatform(ctx, capture, selection, execution)
	}
	return capture.platform.prepareForPurpose(ctx, capture, selection, purpose)
}

func closeDesktopNodeChainLaunch(ctx context.Context, a *app, launch *desktopNodeLaunch) error {
	if ctx == nil || launch == nil || launch.chain == nil {
		return errors.New("ordered retirement lost its original launch")
	}
	if launch.chain.platform != nil {
		return launch.chain.platform.close(ctx)
	}
	if a == nil || launch.ownedNode == nil || launch.ownedNode.chain != launch.chain {
		return errors.New("ordered retirement changed its original native owner")
	}
	return a.retireDesktopOwnedNode(ctx, launch)
}

func desktopNodeChainCurrent(ctx context.Context, a *app, launch *desktopNodeLaunch) error {
	if launch == nil || launch.chain == nil {
		return errors.New("ordered observation lost its original launch")
	}
	if launch.chain.platform != nil {
		return launch.chain.platform.current(ctx)
	}
	if a == nil || launch.ownedNode == nil || launch.ownedNode.chain != launch.chain {
		return errors.New("ordered observation changed its original native owner")
	}
	if err := a.desktopOwnedNodeCurrentContext(ctx, launch, true); err != nil {
		return err
	}
	launch.workspaceMu.Lock()
	ready := launch.ownedNode.ready != nil
	launch.workspaceMu.Unlock()
	if ready {
		_, err := a.readDesktopOwnedNodeReadyContext(ctx, launch, false)
		return err
	}
	return nil
}

func desktopNodeChainRetirementContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}
