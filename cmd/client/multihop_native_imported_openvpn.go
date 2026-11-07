package main

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/nativeopenvpn"
)

type desktopImportedOpenVPNSpec struct {
	Remote  nativeopenvpn.Remote
	Minimum uint32
}

type desktopImportedOpenVPNRuntime struct {
	spec      desktopImportedOpenVPNSpec
	notBefore int64
	mu        sync.Mutex
	original  *nativeopenvpn.PacketObservation
	retired   atomic.Bool
}

func captureDesktopImportedOpenVPNRuntime(ctx context.Context, a *app, command *exec.Cmd, graph activeMultihopGraph) (*nativeMultihopRuntime, error) {
	if !graph.ImportedEntry || graph.EntryMode != "openvpn" {
		return nil, nil
	}
	owner, err := capturedNativeMultihopRuntimeContext(ctx, a, command, graph)
	if err != nil {
		return nil, err
	}
	if err := validateDesktopImportedOpenVPNRuntime(ctx, a, owner); err != nil {
		return nil, err
	}
	return owner, nil
}

func validateDesktopImportedOpenVPNRuntime(ctx context.Context, a *app, expected *nativeMultihopRuntime) error {
	if expected == nil || expected.launch == nil || expected.selection.Native == nil || !expected.selection.Native.imported || expected.selection.EntryMode != "openvpn" {
		return errors.New("imported OpenVPN measurement has no original captured native child")
	}
	current, err := capturedNativeMultihopRuntimeContext(ctx, a, expected.launch.command, expected.graph)
	if err != nil || current != expected {
		return errors.New("imported OpenVPN measurement owner was replaced")
	}
	return a.observeImportedOpenVPN(ctx, expected.selection, expected.launch.command)
}

func desktopImportedOpenVPNProfile(profile common.RouterProfile) (*desktopImportedOpenVPNSpec, error) {
	bad := errors.New("desktop imported OpenVPN requires one original literal TCP or UDP remote and a complete inline authenticated userspace profile")
	if profile.NodeKind != "external" || profile.External == nil || profile.External.Protocol != "openvpn" || profile.External.OpenVPN == nil {
		return nil, bad
	}
	p := profile.External.OpenVPN
	raw, err := nativeopenvpn.CompileEndpoint(p.Config, p.Username, p.Password, "entry-wg", "")
	if err != nil {
		return nil, errors.Join(bad, err)
	}
	var endpoint map[string]any
	if json.Unmarshal([]byte(raw), &endpoint) != nil {
		return nil, bad
	}
	if endpoint["mtu"] == nil {
		// The pinned userspace endpoint and shared source compiler default to
		// 1500. This is only required capacity, never a connected readback.
		endpoint["mtu"] = float64(1500)
	}
	return desktopImportedOpenVPNEndpoint(endpoint)
}

func desktopImportedOpenVPNEndpoint(endpoint map[string]any) (*desktopImportedOpenVPNSpec, error) {
	bad := errors.New("imported OpenVPN lost its single captured remote or original packet capacity")
	remotes, err := nativeopenvpn.Remotes(endpoint)
	mtu, ok := endpoint["mtu"].(float64)
	if err != nil || len(remotes) != 1 || endpoint["type"] != "openvpn-client" || endpoint["system"] != false || !ok || mtu < 1280 || mtu > 65535 || mtu != float64(uint32(mtu)) {
		return nil, bad
	}
	return &desktopImportedOpenVPNSpec{Remote: remotes[0], Minimum: uint32(mtu)}, nil
}

func capturedDesktopImportedOpenVPN(config string, expected *desktopImportedOpenVPNSpec) error {
	var graph map[string]any
	if expected == nil || json.Unmarshal([]byte(config), &graph) != nil {
		return errors.New("imported OpenVPN has no original compiled endpoint")
	}
	rows, _ := graph["endpoints"].([]any)
	var actual *desktopImportedOpenVPNSpec
	for _, raw := range rows {
		endpoint, ok := raw.(map[string]any)
		if !ok || endpoint["tag"] != "entry-wg" {
			continue
		}
		if actual != nil {
			return errors.New("imported OpenVPN has duplicate original endpoints")
		}
		var err error
		actual, err = desktopImportedOpenVPNEndpoint(endpoint)
		if err != nil {
			return err
		}
	}
	if actual == nil || actual.Remote != expected.Remote {
		return errors.New("compiled OpenVPN replaced its original remote or packet capacity")
	}
	// NewImportedEntry has validated the entire original inline profile and
	// its independent device policy. Retain that actual compiled capacity;
	// the native endpoint must still demonstrate it after authentication.
	expected.Minimum = actual.Minimum
	return nil
}

// A live original receipt is requested at every boundary. Merely recognizing
// the protocol or retaining the old process cannot bless a reconnected peer.
func (a *app) observeImportedOpenVPN(ctx context.Context, selection multihopSelection, command *exec.Cmd) error {
	if selection.Native == nil || !selection.Native.imported || selection.EntryMode != "openvpn" {
		return nil
	}
	if ctx == nil || ctx.Err() != nil || selection.Native.openVPN == nil {
		return errors.New("imported OpenVPN observation has no original caller or source")
	}
	graph, ok := getActiveMultihopGraph(a)
	owner, err := capturedNativeMultihopRuntimeContext(ctx, a, command, graph)
	if !ok || err != nil || owner.selection.Native != selection.Native || owner.launch.importedOpenVPN == nil ||
		owner.launch.importedOpenVPN.spec != *selection.Native.openVPN {
		return errors.New("imported OpenVPN observation lost its retained child")
	}
	current := func(call context.Context) error {
		if call.Err() != nil || !a.nativeMultihopProofOwnerCurrentContext(call, selection, command) || desktopNodeProcessExited(owner.launch) {
			return errors.New("imported OpenVPN source or process retired")
		}
		actual, err := capturedNativeMultihopRuntimeContext(call, a, command, graph)
		if err != nil || actual != owner {
			return errors.New("imported OpenVPN original network generation changed")
		}
		return call.Err()
	}
	return exchangeDesktopImportedOpenVPN(ctx, owner.launch, current)
}

func exchangeDesktopImportedOpenVPN(ctx context.Context, launch *desktopNodeLaunch, current func(context.Context) error) error {
	if launch == nil || launch.importedOpenVPN == nil {
		return errors.New("imported OpenVPN has no owned native observation")
	}
	owner := launch.importedOpenVPN
	if err := mobilemtu.LockContext(ctx, &owner.mu); err != nil {
		return err
	}
	defer owner.mu.Unlock()
	if owner.retired.Load() {
		return errors.New("original imported OpenVPN observation retired")
	}
	result, err := exchangeDesktopImportedNativeWithPublisher(ctx, launch, current, "openvpn-observe", publishDesktopImportedDNSMessage)
	if err != nil {
		return err
	}
	if result.OpenVPN == nil || result.OpenVPN.Validate() != nil || result.OpenVPN.Remote.Remote != owner.spec.Remote || result.OpenVPN.MTU < owner.spec.Minimum ||
		owner.notBefore <= 0 || result.OpenVPN.Remote.ConnectedAt < owner.notBefore || result.OpenVPN.Remote.ConnectedAt > time.Now().Add(time.Second).UnixMilli() {
		owner.retired.Store(true)
		return errors.New("actual OpenVPN remote or negotiated capacity differs from its original source")
	}
	if owner.original == nil {
		state := *result.OpenVPN
		owner.original = &state
	} else if *owner.original != *result.OpenVPN {
		owner.retired.Store(true)
		return errors.New("actual OpenVPN connection generation or negotiated capacity changed")
	}
	return ctx.Err()
}
