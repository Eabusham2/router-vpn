package main

import (
	"context"
	"errors"
	"os/exec"
)

func (a *app) readPlatformDeviceMTUView(ctx context.Context, c *deviceMTUCapture, command *exec.Cmd, _ *desktopNodeLaunch) (desktopDeviceMTUView, error) {
	if launch, handled, err := linuxStandardMTULaunch(a); handled {
		if err != nil || launch == nil || launch.prepared == nil || launch.prepared.deviceMTU != c {
			return desktopDeviceMTUView{}, errors.Join(err, errDeviceMTUReadback)
		}
		live, profile, _, err := captureLinuxStandardServiceMTUReadback(ctx, launch)
		return desktopDeviceMTUView{mtuViewIdentity{Session: live.Session, Profile: profile.ID, Native: true}, c.policy.Revision, live.MTU, c.policy.FixedMTU}, err
	}
	var view desktopDeviceMTUView
	handled, err := withDesktopLinuxNodeMTUHost(ctx, a, func(_ *desktopLinuxNodeSession, h *desktopLinuxNodeHost) error {
		if h.launch == nil || h.launch.command != command {
			return errDeviceMTUReadback
		}
		_, live, err := h.readReadyLocked(ctx, false)
		if err != nil {
			return err
		}
		policy, err := h.readyPolicySource()
		if err != nil {
			return err
		}
		view, err = desktopNodeDeviceMTUView(policy, live, desktopExternalPathProfileID(h.launch))
		return err
	})
	if !handled {
		return view, errDeviceMTUReadback
	}
	return view, err
}
