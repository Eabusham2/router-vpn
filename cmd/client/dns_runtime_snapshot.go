package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type activeDNSRuntimeOwner struct {
	command                                *exec.Cmd
	connected                              bool
	phase, routerID, mode, runtimeID, base string
	profileFound                           bool
	profileToken                           string
	node                                   *desktopNodeLaunch
	multihop                               *nativeMultihopRuntime
	nodeSession, nodeConfig                string
}

func captureActiveDNSRuntimeOwner(a *app, profileID string) (activeDNSRuntimeOwner, error) {
	if a == nil {
		return activeDNSRuntimeOwner{}, errors.New("active DNS runtime has no application owner")
	}
	a.mu.Lock()
	st, command := a.state, a.cmd
	profile, found := a.profileByIDLocked(profileID)
	token := ""
	if found {
		token = asyncMeasurementProfileToken(profile)
	}
	a.mu.Unlock()
	owner := activeDNSRuntimeOwner{command: command, connected: st.Connected, phase: st.Phase, routerID: st.RouterID,
		mode: st.Mode, runtimeID: st.RuntimeMode, base: st.Base, profileFound: found, profileToken: token}
	if raw, found := desktopNodeOwners.Load(a); found {
		var ok bool
		owner.node, ok = raw.(*desktopNodeLaunch)
		if !ok || owner.node == nil {
			return activeDNSRuntimeOwner{}, errors.New("active DNS runtime has an invalid native owner")
		}
		owner.nodeSession, owner.nodeConfig = owner.node.mtuSession, owner.node.configSHA256
	}
	if raw, found := nativeMultihopOwners.Load(a); found {
		var ok bool
		owner.multihop, ok = raw.(*nativeMultihopRuntime)
		if !ok || owner.multihop == nil {
			return activeDNSRuntimeOwner{}, errors.New("active DNS runtime has an invalid multihop owner")
		}
	}
	return owner, nil
}

type activeDNSRuntimeSource struct {
	app      *app
	identity activeDNSRuntimeIdentity
	kind     string
	owner    activeDNSRuntimeOwner
	path     string
	runRoot  string
	fileInfo os.FileInfo
}

func (source *activeDNSRuntimeSource) current() error {
	if source == nil {
		return errors.New("active DNS runtime has no captured source")
	}
	owner, err := captureActiveDNSRuntimeOwner(source.app, source.identity.ProfileID)
	if err != nil || owner != source.owner {
		return errors.New("active DNS runtime owner or node policy changed")
	}
	var identity activeDNSRuntimeIdentity
	var owned bool
	switch source.kind {
	case "registered":
		raw, found := activeDNSRuntimeIdentities.Load(source.app)
		identity, owned = raw.(activeDNSRuntimeIdentity)
		owned = owned && found
	case "linux-multihop":
		identity, owned, err = deterministicLinuxMultihopDNSRuntime(source.app, source.identity.ProfileID, source.identity.RuntimeID)
	case "external":
		identity, owned, err = deterministicExternalDNSRuntime(source.app, source.identity.ProfileID, source.identity.RuntimeID)
	}
	if err != nil || !owned || identity != source.identity {
		return errors.New("active DNS runtime registration or captured path changed")
	}
	path, err := runtimeConfigUnderPrivateRun(source.app, identity.Config)
	if err != nil || path != source.path {
		return errors.New("active DNS runtime left its captured private root")
	}
	if source.owner.node != nil {
		launch := source.owner.node
		if launch.command != source.owner.command || filepath.Clean(source.path) != filepath.Clean(filepath.Join(launch.directory, "sing-box.json")) {
			return errors.New("active DNS configuration belongs to another native owner")
		}
		if err := desktopExternalDirectoryCurrent(launch); err != nil {
			return err
		}
	}
	info, err := os.Lstat(source.path)
	if err != nil || source.fileInfo == nil || !os.SameFile(source.fileInfo, info) || info.Size() != source.fileInfo.Size() || !info.ModTime().Equal(source.fileInfo.ModTime()) {
		return errors.New("active DNS runtime configuration changed after source capture")
	}
	return validateExistingRuntimeAncestors(source.runRoot, source.path)
}

type activeDNSRuntimeSnapshot struct {
	source *activeDNSRuntimeSource
	body   []byte
}

func (source *activeDNSRuntimeSource) read() (*activeDNSRuntimeSnapshot, error) {
	if err := source.current(); err != nil {
		return nil, err
	}
	body, err := readPrivateRuntimeSnapshotFrom(source.path, source.fileInfo, maxPrivateStoreBytes)
	if err != nil {
		return nil, err
	}
	if source.owner.nodeConfig != "" && fmt.Sprintf("%x", sha256.Sum256(body)) != source.owner.nodeConfig {
		return nil, errors.New("active DNS runtime bytes differ from the captured native graph")
	}
	if err := source.current(); err != nil {
		return nil, err
	}
	return &activeDNSRuntimeSnapshot{source: source, body: body}, nil
}

func activeDNSRuntimeSnapshotFor(a *app, profileID, runtimeID string) (*activeDNSRuntimeSnapshot, bool, error) {
	source, owned, err := captureActiveDNSRuntimeSource(a, profileID, runtimeID)
	if err != nil || !owned {
		return nil, owned, err
	}
	snapshot, err := source.read()
	return snapshot, true, err
}
