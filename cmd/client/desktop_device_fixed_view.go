package main

import (
	"context"
	"errors"
	"net/http"
	"os/exec"

	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

var errDeviceMTUReadback = errors.New("the original native interface no longer proves the captured device MTU")

type desktopDeviceMTUView struct {
	identity      mtuViewIdentity
	revision      string
	actual, fixed int
}

func (v desktopDeviceMTUView) verify(c *deviceMTUCapture) error {
	if c == nil || v.identity.Session == "" || v.identity.Profile == "" || v.revision != c.policy.Revision || v.fixed != c.policy.FixedMTU || v.fixed < 1280 || v.actual != v.fixed {
		return errDeviceMTUReadback
	}
	return nil
}

func desktopNodeDeviceMTUView(policy mobilemultihop.DesktopPhysicalPolicy, live desktopNodeMTURecord, profile string) (desktopDeviceMTUView, error) {
	_, meta, _, err := mobilemultihop.ReadDesktopPhysicalPolicy(policy)
	if err != nil || live.Session != meta.SessionID || live.Config != meta.ConfigSHA256 || live.Reader < 1 || live.Index < 1 || live.Interface == "" || live.Failure != "" || live.Active {
		return desktopDeviceMTUView{}, errors.Join(err, errDeviceMTUReadback)
	}
	return desktopDeviceMTUView{mtuViewIdentity{Session: meta.SessionID, Profile: profile, Native: true}, meta.DeviceRevision, live.MTU, meta.DeviceFixedMTU}, nil
}

func (a *app) readPublicDeviceMTUView(ctx context.Context, launch *desktopNodeLaunch) (desktopDeviceMTUView, error) {
	id, err := desktopMeasurementViewIdentityContext(ctx, launch)
	if err != nil {
		return desktopDeviceMTUView{}, err
	}
	if launch.tor != nil {
		p, err := a.readDesktopTorProofContext(ctx, launch)
		return desktopDeviceMTUView{id, p.Policy.DeviceMTURevision, p.EffectiveMTU, p.Policy.DeviceFixedMTU}, err
	}
	p, err := a.readDesktopExternalProofContext(ctx, launch)
	if err != nil {
		return desktopDeviceMTUView{}, err
	}
	if p.DevicePreference != nil && p.Physical == nil {
		return desktopDeviceMTUView{id, p.DevicePreference.Revision, p.DevicePreference.MTU, p.DevicePreference.MTU}, nil
	}
	if p.Physical == nil || p.DevicePreference != nil {
		return desktopDeviceMTUView{}, errDeviceMTUReadback
	}
	read, err := desktopnetwork.ParseDesktopNetworkReceipt(p.NetworkReceipt)
	if err != nil || read.TargetOS != p.Physical.TargetOS {
		return desktopDeviceMTUView{}, errors.Join(err, errDeviceMTUReadback)
	}
	return desktopDeviceMTUView{id, p.Physical.DeviceRevision, read.MTU, p.Physical.DeviceFixedMTU}, nil
}

// Fixed settings have no measurement/Retest owner. Publish an observed size
// only while the original command, device revision and native proof survive.
func (a *app) writeDeviceFixedMTUStatus(w http.ResponseWriter, r *http.Request, request, session string) bool {
	ctx := r.Context()
	if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	c, command, connected := a.deviceMTU, a.cmd, a.state.Connected && a.state.Phase == "connected"
	a.mu.Unlock()
	if c == nil || c.policy.FixedMTU == 0 {
		return false
	}
	var view desktopDeviceMTUView
	var err error
	if command == nil || !connected {
		err = errDeviceMTUReadback
	} else {
		view, err = a.readDeviceFixedMTUView(ctx, c, command)
	}
	if err == nil {
		err = view.verify(c)
	}
	if err == nil {
		err = c.current()
	}
	if err == nil {
		err = mobilemtu.LockContext(ctx, &a.mu)
		if err == nil {
			if a.cmd != command || a.deviceMTU != c || !a.state.Connected || a.state.Phase != "connected" {
				err = errDeviceMTUReadback
			}
			a.mu.Unlock()
		}
	}
	if err != nil || session != "" && session != view.identity.Session {
		http.Error(w, errDeviceMTUReadback.Error(), http.StatusConflict)
		return true
	}
	if request != "" {
		http.Error(w, "there is no MTU measurement for this device-fixed connection", http.StatusNotFound)
		return true
	}
	writeMTUViewStatus(w, view.identity, false, false, false, mobilemtu.Status{Phase: "idle", Source: "device-fixed", EffectiveMTU: view.actual, Candidates: []mobilemtu.Candidate{}})
	return true
}

func (a *app) readDeviceFixedMTUView(ctx context.Context, c *deviceMTUCapture, command *exec.Cmd) (desktopDeviceMTUView, error) {
	var launch *desktopNodeLaunch
	if raw, found := lookupDesktopNativeLaunch(a); found {
		launch, _ = raw.(*desktopNodeLaunch)
	}
	if launch != nil && launch.command == command && (launch.external != nil || launch.tor != nil) {
		return a.readPublicDeviceMTUView(ctx, launch)
	}
	if raw, found := nativeMultihopOwners.Load(a); found {
		native, ok := raw.(*nativeMultihopRuntime)
		if !ok || native == nil || native.launch == nil || native.launch.command != command {
			return desktopDeviceMTUView{}, errDeviceMTUReadback
		}
		_, err := capturedNativeMultihopRuntimeContext(ctx, a, command, native.graph)
		if err != nil {
			return desktopDeviceMTUView{}, err
		}
		launch = native.launch
		if launch.chain == nil && launch.ownedNode == nil && launch.importedPlatform == nil {
			if c != launch.multihopDeviceMTU || native.selection.deviceRevision != c.policy.Revision || native.selection.deviceFixed != c.policy.FixedMTU {
				return desktopDeviceMTUView{}, errDeviceMTUReadback
			}
			live, err := readDesktopNodeMTUContext(ctx, launch)
			if err != nil || live.Active || live.Failure != "" {
				return desktopDeviceMTUView{}, errors.Join(err, errDeviceMTUReadback)
			}
			if _, err := capturedNativeMultihopRuntimeContext(ctx, a, command, native.graph); err != nil {
				return desktopDeviceMTUView{}, err
			}
			return desktopDeviceMTUView{mtuViewIdentity{Session: live.Session, Profile: launch.profileID, Native: true}, native.selection.deviceRevision, live.MTU, native.selection.deviceFixed}, nil
		}
	}
	if launch != nil && launch.command == command && launch.ownedNode != nil {
		if _, err := a.readDesktopOwnedNodeReadyContext(ctx, launch, false); err != nil {
			return desktopDeviceMTUView{}, err
		}
		policy, err := launch.ownedNode.physicalPolicy()
		if err != nil {
			return desktopDeviceMTUView{}, err
		}
		live, err := readDesktopNodeMTUContext(ctx, launch)
		if err != nil {
			return desktopDeviceMTUView{}, err
		}
		if err := a.desktopOwnedNodeCurrentContext(ctx, launch, true); err != nil {
			return desktopDeviceMTUView{}, err
		}
		return desktopNodeDeviceMTUView(policy, live, desktopExternalPathProfileID(launch))
	}
	return a.readPlatformDeviceMTUView(ctx, c, command, launch)
}
