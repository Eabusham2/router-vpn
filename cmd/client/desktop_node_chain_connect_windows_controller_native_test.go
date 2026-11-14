//go:build windows && routervpn_windows_candidate_prefix_native && go1.25

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowsprotection"
)

type windowsCONNECTInspection struct {
	PublicConnectCalls      int                                         `json:"public_connect_calls"`
	PublicProfileCapability bool                                        `json:"public_profile_capability"`
	Connected               bool                                        `json:"connected"`
	OriginalSources         bool                                        `json:"original_sources"`
	NativeJoined            bool                                        `json:"native_joined"`
	JournalSettled          bool                                        `json:"journal_settled"`
	WFPAbsent               bool                                        `json:"wfp_absent"`
	TUNAbsent               bool                                        `json:"tun_absent"`
	MeasurementRows         int                                         `json:"measurement_rows"`
	Proof                   *mobilemultihop.DesktopNodeChainReadyRecord `json:"proof,omitempty"`
}

func windowsCONNECTRegisterRoutes(mux *http.ServeMux, a *app, original common.RouterProfileStore) (func(), error) {
	selected, found := a.profileByIDLocked(original.SelectedID)
	if !found || !desktopNodeChainHasCONNECT(selected.MultihopNodes) {
		return func() {}, nil
	}
	if !nativeNodeChainCONNECTPlatformSupported() || len(selected.MultihopNodes) != 3 {
		return nil, errors.New("installed CONNECT requires the original public ordered host")
	}
	middle, found := a.profileByIDLocked(selected.MultihopNodes[1].ID)
	view := publicProfileFor(middle)
	if !found || view.External == nil || !view.External.OrderedMiddle || !desktopNodeChainCONNECTMiddle(middle, selected.MultihopNodes[1].Mode) {
		return nil, errors.New("installed CONNECT requires its original public profile capability")
	}
	hold, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	release, err := a.holdCapturedMTU(hold)
	cancel()
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	var launch *desktopNodeLaunch
	var proof *mobilemultihop.DesktopNodeChainReadyRecord
	var configuredTUN string
	publicConnectCalls := 0
	driver := nativeMultihopConnectRuntime{capture: captureNativeMultihopForApp, stage: stageOwnedNativeMultihopCommand, proof: (*app).proveNativeMultihop,
		preflight: func(owner *app, selection multihopSelection, descriptor *desktopExecutionDescriptor) (*desktopNodeLaunch, error) {
			candidate, err := preflightOwnedNativeMultihopCommand(owner, selection, descriptor)
			if candidate != nil {
				mu.Lock()
				defer mu.Unlock()
				if launch != nil || candidate.chain == nil || candidate.chain.connectPolicy == nil || candidate.chain.policy != nil || candidate.chain.socksPolicy != nil || !candidate.chain.originalPolicyCurrent() {
					return candidate, errors.New("typed native fixture replaced its original concrete parent")
				}
				name, nameErr := windowsCONNECTConfiguredTUN(candidate.chain.connectPolicy)
				if nameErr != nil {
					return candidate, nameErr
				}
				interfaces, inventoryErr := net.Interfaces()
				if inventoryErr != nil {
					return candidate, inventoryErr
				}
				for _, iface := range interfaces {
					if iface.Name == name {
						return candidate, errors.New("typed fixture refuses preexisting configured TUN")
					}
				}
				configuredTUN = name
				launch = candidate
			}
			return candidate, err
		}}
	mux.HandleFunc("/api/native-connect/request", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		control, found := a.profileByIDLocked(a.profiles.SelectedID)
		tokens, err := a.connectionProfileTokensLocked(control)
		if !found || err != nil {
			http.Error(w, "original typed source unavailable", 409)
			return
		}
		id := a.profiles.SelectedID
		_ = json.NewEncoder(w).Encode(multihopConnectRequest{Nodes: control.MultihopNodes, Execution: "local", desktopProfileExpectations: desktopProfileExpectations{ExpectedSelectedNodeID: &id, ExpectedProfileTokens: tokens}})
	})
	mux.HandleFunc("/api/multihop/connect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/multihop/connect" || !nativeNodeChainCONNECTPlatformSupported() {
			http.Error(w, "original public CONNECT request required", http.StatusNotImplemented)
			return
		}
		mu.Lock()
		publicConnectCalls++
		mu.Unlock()
		a.nativeMultihopConnectOwned(w, r, driver)
	})
	mux.HandleFunc("/api/disconnect", a.disconnect)
	mux.HandleFunc("/api/native-connect/middle-source", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", 405)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if len(a.profiles.Profiles) != 3 || a.profiles.Profiles[1].External == nil {
			http.Error(w, "original imported CONNECT middle unavailable", 409)
			return
		}
		external := a.profiles.Profiles[1].External
		proxy := external.HTTPConnect
		if external.Protocol == "https-connect" {
			proxy = external.HTTPSConnect
		}
		if proxy == nil {
			http.Error(w, "original imported CONNECT credential unavailable", 409)
			return
		}
		proxy.Password += "-replaced-after-admission"
		w.WriteHeader(204)
	})
	mux.HandleFunc("/api/native-connect/inspect", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		owner := launch
		initial := proof
		tunName := configuredTUN
		publicCalls := publicConnectCalls
		mu.Unlock()
		result, err := windowsCONNECTInspect(r.Context(), a, owner, original, initial, tunName, r.URL.Query().Get("retired") == "1")
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		result.PublicConnectCalls = publicCalls
		result.PublicProfileCapability = view.External.OrderedMiddle
		if result.Proof != nil {
			mu.Lock()
			if proof == nil {
				copy := *result.Proof
				proof = &copy
			}
			mu.Unlock()
		}
		_ = json.NewEncoder(w).Encode(result)
	})
	return release, nil
}

func windowsCONNECTInspect(ctx context.Context, a *app, launch *desktopNodeLaunch, original common.RouterProfileStore, initial *mobilemultihop.DesktopNodeChainReadyRecord, configuredTUN string, retired bool) (windowsCONNECTInspection, error) {
	var result windowsCONNECTInspection
	if launch == nil || launch.chain == nil || launch.chain.connectPolicy == nil || launch.chain.policy != nil || launch.chain.socksPolicy != nil || launch.ownedNode == nil || launch.ownedNode.chain != launch.chain {
		return result, errors.New("typed native inspection lost original retained parent")
	}
	name, err := windowsCONNECTConfiguredTUN(launch.chain.connectPolicy)
	if err != nil || name != configuredTUN {
		return result, errors.Join(err, errors.New("typed fixture lost configured TUN capture"))
	}
	a.mu.Lock()
	result.Connected = a.state.Connected
	result.OriginalSources = len(original.Profiles) == len(a.profiles.Profiles) && original.SelectedID == a.profiles.SelectedID
	for i, p := range original.Profiles {
		if i >= len(a.profiles.Profiles) || liveMeasurementProfileToken(p) != liveMeasurementProfileToken(a.profiles.Profiles[i]) {
			result.OriginalSources = false
		}
	}
	a.mu.Unlock()
	if !retired {
		if !result.Connected || !result.OriginalSources {
			return result, errors.New("typed native activation changed its original saved sources")
		}
		if err := desktopNodeChainCurrent(ctx, a, launch); err != nil {
			return result, err
		}
		graph, found := getActiveMultihopGraph(a)
		runtime, err := capturedNativeMultihopRuntimeContext(ctx, a, launch.command, graph)
		if err != nil || !found || runtime == nil || runtime.launch != launch || graph.ChainNodes != 3 {
			return result, errors.Join(err, errors.New("typed native activation lost full original graph"))
		}
		finish, err := beginDesktopNodeChainMeasurementHold(ctx, a, launch)
		if err != nil {
			return result, err
		}
		status, err := exchangeDesktopNodeChainMeasurement(ctx, launch, func(call context.Context) error { return desktopNodeChainCurrent(call, a, launch) })
		finish(!errors.Is(err, errDesktopNodeChainMeasurementPending))
		if err != nil {
			return result, err
		}
		rows, err := desktopNodeChainMeasurementRows(status, runtime.selection.Nodes, 8<<20)
		if err != nil || len(rows) != 3 {
			return result, errors.Join(err, errors.New("typed native measurement omitted original prefix"))
		}
		result.MeasurementRows = len(rows)
		launch.chain.mu.Lock()
		if launch.chain.ready != nil {
			copy := *launch.chain.ready
			result.Proof = &copy
		}
		launch.chain.mu.Unlock()
		if result.Proof == nil || result.Proof.Kind != "routervpn-node-chain-connect-ready-v1" || result.Proof.Generation != 1 || result.Proof.Identity.SourceSHA256 != launch.chain.selection.Native.source {
			return result, errors.New("typed native readiness changed original family or source")
		}
		return result, nil
	}
	if result.Connected {
		return result, errors.New("typed native retirement remained Connected")
	}
	launch.workspaceMu.Lock()
	closed := launch.ownedNode.retired
	launch.workspaceMu.Unlock()
	process, ok := desktopOwnedNodeProcess(launch).(*desktopNodeWindowsJournalProcess)
	if !closed || !ok || process == nil || launch.ownedNode.attempt == nil || launch.ownedNode.slot == nil || process.capture.ProfileID != original.SelectedID || launch.ownedNode.attempt.connectChain != launch.chain.connectPolicy || launch.ownedNode.attempt.chain != nil || launch.ownedNode.attempt.socksChain != nil {
		return result, errors.New("typed native retirement lost original joined process/policy")
	}
	record, err := process.JournalOutcome()
	if err != nil || record.Validate() != nil || !launch.ownedNode.slot.provedEmpty() {
		return result, errors.Join(err, errors.New("typed native retirement omitted authenticated outcome and empty original slot"))
	}
	result.NativeJoined = true
	capture := process.controller
	if capture == nil || len(capture.directories) != 1 {
		return result, errors.New("typed native retirement lost original journal directory")
	}
	journal, err := windowsprotection.OpenProtectionJournal(ctx, capture.parent, capture.directories[0])
	if err != nil {
		if journal != nil {
			err = errors.Join(err, journal.Close())
		}
		return result, err
	}
	head, err := journal.Snapshot(ctx)
	err = errors.Join(err, journal.Close())
	if err != nil || head.Incomplete || head.Record.Phase != "settled" || head.Record.Committed.Engine != nil || head.Record.Committed.Target != nil {
		return result, errors.Join(err, errors.New("typed native retirement retained durable engine or on-connect protection"))
	}
	result.JournalSettled = true
	result.WFPAbsent, err = mobiletor.ProbeDesktopWindowsProtectionAbsent(ctx)
	if err != nil || !result.WFPAbsent {
		return result, errors.Join(err, errors.New("typed native retirement retained scoped WFP rules"))
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return result, err
	}
	for _, iface := range interfaces {
		if iface.Name == configuredTUN || initial != nil && (uint32(iface.Index) == initial.InterfaceIndex || iface.Name == initial.InterfaceName) {
			return result, errors.New("typed native retirement retained original TUN")
		}
	}
	if initial != nil {
		if initial.InterfaceName != configuredTUN {
			return result, errors.New("typed native readiness changed configured TUN")
		}
		result.Proof = initial
	}
	result.TUNAbsent = true
	return result, nil
}

// Read the original sealed typed configuration, never a generic chain or a
// discovered adapter. Enumeration below supplies absence evidence only.
func windowsCONNECTConfiguredTUN(policy *mobilemultihop.DesktopNodeChainCONNECTPolicy) (string, error) {
	config, metadata, capture, err := policy.ReadValidated()
	if err != nil || metadata.TargetOS != "windows" {
		return "", errors.Join(err, errors.New("typed fixture lost original Windows policy"))
	}
	var graph struct {
		Inbounds []struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
			Name string `json:"interface_name"`
		} `json:"inbounds"`
	}
	if json.Unmarshal([]byte(config), &graph) != nil {
		return "", errors.New("typed fixture lost original TUN configuration")
	}
	name := ""
	for _, inbound := range graph.Inbounds {
		if inbound.Type == "tun" {
			if name != "" || inbound.Tag != capture.TUNTag || inbound.Name != "router-vpn" {
				return "", errors.New("typed fixture changed original TUN identity")
			}
			name = inbound.Name
		}
	}
	if name == "" {
		return "", errors.New("typed fixture omitted original TUN identity")
	}
	return name, nil
}
