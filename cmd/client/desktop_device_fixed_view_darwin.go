package main

import (
	"context"
	"os/exec"
)

func (a *app) readPlatformDeviceMTUView(ctx context.Context, c *deviceMTUCapture, command *exec.Cmd, launch *desktopNodeLaunch) (desktopDeviceMTUView, error) {
	if launch == nil || launch.command != command {
		return desktopDeviceMTUView{}, errDeviceMTUReadback
	}
	if h, ok := launch.pairedNode.(*desktopMacOSPairedNodeHost); ok && h != nil && h.launch == launch && h.parent != nil && h.parent.app == a {
		if err := h.enter(ctx); err != nil {
			return desktopDeviceMTUView{}, err
		}
		defer func() { h.gate <- struct{}{} }()
		if !h.activated || !h.proved {
			return desktopDeviceMTUView{}, errDeviceMTUReadback
		}
		_, live, err := h.readReadyLocked(ctx, false)
		if err != nil {
			return desktopDeviceMTUView{}, err
		}
		return desktopNodeDeviceMTUView(h.policy, live, desktopExternalPathProfileID(launch))
	}
	if launch.chain == nil || launch.chain.platform == nil || launch.chain.platform.host == nil {
		return desktopDeviceMTUView{}, errDeviceMTUReadback
	}
	h := launch.chain.platform.host
	if h.launch != launch || h.parent == nil || h.parent.app != a {
		return desktopDeviceMTUView{}, errDeviceMTUReadback
	}
	if err := h.enter(ctx); err != nil {
		return desktopDeviceMTUView{}, err
	}
	defer func() { h.gate <- struct{}{} }()
	if err := h.readReadyLocked(ctx, false); err != nil {
		return desktopDeviceMTUView{}, err
	}
	policy, err := launch.chain.physicalPolicy()
	if err != nil {
		return desktopDeviceMTUView{}, err
	}
	live, err := readDesktopNodeMTUContext(ctx, launch)
	if err != nil {
		return desktopDeviceMTUView{}, err
	}
	return desktopNodeDeviceMTUView(policy, live, desktopExternalPathProfileID(launch))
}
