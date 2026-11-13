package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"reflect"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
)

const startupNodeChainPathKind = "node-chain-v1"

// A delayed intent retains every original profile and private asset digest.
// It owns no native process or permission; the normal native transaction must
// still acquire its original protected host and prove every selected prefix.
type startupNodeChainCapture struct {
	root      string
	selection multihopSelection
	tokens    []string
	assets    []viaEntryAsset
	last      *startupSelection
}

// Last contains only references, modes and digests. Neither a transport key nor
// an API credential is copied out of the original private node stores.
type startupNodeChainSelection struct {
	Schema     int                      `json:"schema"`
	Execution  string                   `json:"execution"`
	RootSHA256 string                   `json:"root_sha256"`
	Nodes      []startupNodeChainMember `json:"nodes"`
}

type startupNodeChainMember struct {
	ID           string                        `json:"id"`
	NodeKind     string                        `json:"node_kind,omitempty"`
	Mode         string                        `json:"mode"`
	NodeProofID  string                        `json:"node_proof_id"`
	ProfileToken string                        `json:"profile_token"`
	Sources      []connectionProfileNodeSource `json:"sources"`
}

func startupNodeChainRootToken(root string) string {
	sum := sha256.Sum256([]byte(root))
	return hex.EncodeToString(sum[:])
}

func startupStrictObject(data []byte, names ...string) (map[string]json.RawMessage, error) {
	fields, err := externalConnectJSONObject(data)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	for name := range fields {
		if !allowed[name] {
			return nil, errors.New("startup receipt contains an unknown or noncanonical field")
		}
	}
	return fields, nil
}

func (selection *startupSelection) UnmarshalJSON(data []byte) error {
	fields, err := startupStrictObject(data, "router_id", "runtime_mode", "logical_mode", "base", "profile_token", "updated_at", "external", "node_chain", "path_kind")
	if err != nil {
		return err
	}
	if kind, present := fields["path_kind"]; present {
		var value string
		if json.Unmarshal(kind, &value) != nil || value != startupNodeChainPathKind {
			return errors.New("ordered Last receipt requires its exact nonempty path kind")
		}
	}
	if chain, present := fields["node_chain"]; present && (string(chain) == "null" || fields["external"] != nil) {
		return errors.New("ordered Last receipt cannot contain another path family or a null capture")
	}
	type wire startupSelection
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*selection = startupSelection(decoded)
	return validateStartupNodeChainSelection(*selection)
}

func (capture *startupNodeChainSelection) UnmarshalJSON(data []byte) error {
	if _, err := startupStrictObject(data, "schema", "execution", "root_sha256", "nodes"); err != nil {
		return err
	}
	type wire startupNodeChainSelection
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*capture = startupNodeChainSelection(decoded)
	return nil
}

func (member *startupNodeChainMember) UnmarshalJSON(data []byte) error {
	fields, err := startupStrictObject(data, "id", "mode", "node_proof_id", "profile_token", "sources", "node_kind")
	if err != nil || len(fields) != 5 && len(fields) != 6 {
		return errors.Join(err, errors.New("ordered Last member requires its complete original identity"))
	}
	var sources []json.RawMessage
	if json.Unmarshal(fields["sources"], &sources) != nil || len(sources) < 1 || len(sources) > 3 {
		return errors.New("ordered Last member requires a bounded complete source inventory")
	}
	for _, source := range sources {
		fields, err := startupStrictObject(source, "mode", "sha256")
		if err != nil || len(fields) != 2 {
			return errors.Join(err, errors.New("ordered Last source contains an invalid digest record"))
		}
	}
	type wire startupNodeChainMember
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*member = startupNodeChainMember(decoded)
	return nil
}

func validateStartupNodeChainSelection(selection startupSelection) error {
	capture := selection.NodeChain
	bad := errors.New("ordered Last receipt lost its complete proved Local path")
	if capture == nil {
		if selection.PathKind != "" {
			return bad
		}
		return nil
	}
	if selection.PathKind != startupNodeChainPathKind || (capture.Schema != 1 && capture.Schema != 2) || capture.Execution != "local" || selection.External != nil ||
		!desktopNodeChainFinalSupported(selection.RuntimeMode, "off") || capture.Schema == 2 && selection.RuntimeMode != "shadowsocks" || selection.LogicalMode != "multihop" || selection.UpdatedAt.IsZero() ||
		!savedNodeChainDigest(capture.RootSHA256) || len(capture.Nodes) < 2 || len(capture.Nodes) > common.MultihopMaximumNodes {
		return bad
	}
	refs := make([]common.MultihopNodeSelection, len(capture.Nodes))
	proofs := make(map[string]bool, len(capture.Nodes))
	for i, member := range capture.Nodes {
		refs[i] = common.MultihopNodeSelection{ID: member.ID, Mode: member.Mode}
		if member.NodeKind == "external" {
			if capture.Schema != 2 || len(capture.Nodes) != 3 || i != 1 || member.Mode != "shadowsocks" || member.NodeProofID != "" || !savedNodeChainDigest(member.ProfileToken) || len(member.Sources) != 1 || member.Sources[0].Mode != "external-shadowsocks" || !savedNodeChainDigest(member.Sources[0].SHA256) {
				return bad
			}
			continue
		}
		if member.NodeKind != "" || capture.Schema == 2 && i == 1 {
			return bad
		}
		if !common.ValidNodeProofID(member.NodeProofID) || proofs[member.NodeProofID] || !savedNodeChainDigest(member.ProfileToken) ||
			i < len(capture.Nodes)-1 && !mobilemultihop.NodeChainPrefixMode(member.Mode) ||
			i == len(capture.Nodes)-1 && !desktopNodeChainFinalSupported(member.Mode, "off") {
			return bad
		}
		proofs[member.NodeProofID] = true
		modes, err := savedNodeChainSourceModes(member.Mode, "off")
		if mobilemultihop.NodeChainPrefixMode(member.Mode) && len(member.Sources) == len(modes)+1 {
			modes = append(modes, "shadowsocks")
		}
		if err != nil || len(member.Sources) != len(modes) {
			return bad
		}
		for j, source := range member.Sources {
			if source.Mode != modes[j] || !savedNodeChainDigest(source.SHA256) {
				return bad
			}
		}
	}
	final := capture.Nodes[len(capture.Nodes)-1]
	if common.ValidateMultihopNodes(refs) != nil || selection.RouterID != final.ID || selection.RuntimeMode != final.Mode || selection.ProfileToken != final.ProfileToken ||
		selection.Base != desktopExternalEntryBase(capture.Nodes[0].Mode) {
		return bad
	}
	return nil
}

func (a *app) loadStartupNodeChainReceipt(selected string) (*startupSelection, bool, error) {
	raw, err := readPrivateRegular(a.startupStatePath(), 64<<10)
	if err != nil {
		return nil, false, err
	}
	// This first parse is a refusal-only family observation. Only the strict
	// decoder below may supply an actual receipt. Duplicate, aliased and broken
	// ordered records must not turn into an ordinary Last/AUTO fallback.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, true, err
	}
	ordered := false
	for key := range fields {
		ordered = ordered || strings.EqualFold(key, "node_chain") || strings.EqualFold(key, "path_kind")
	}
	var selection startupSelection
	if err := json.Unmarshal(raw, &selection); err != nil {
		return nil, ordered, err
	}
	if selection.RouterID != selected {
		if ordered {
			return nil, true, errors.New("ordered Last receipt belongs to another selected control")
		}
		return nil, false, nil
	}
	if selection.NodeChain == nil {
		return nil, false, nil
	}
	return &selection, true, nil
}

func captureStartupNodeChain(a *app, profile common.RouterProfile, profiles []common.RouterProfile, last *startupSelection) (*startupNodeChainCapture, error) {
	if !nativeNodeChainPlatformSupported() {
		return nil, errors.New("startup ordered path requires its protected native platform host")
	}
	refs := append([]common.MultihopNodeSelection(nil), profile.MultihopNodes...)
	execution := profile.MultihopExecution
	if last == nil && (!profile.MultihopEnabled || profile.MultihopEntryID != "" || profile.MultihopExitID != "" || profile.MultihopEntryMode != "") {
		return nil, errors.New("scheduled ordered path has conflicting saved pair references")
	}
	if last != nil {
		if validateStartupNodeChainSelection(*last) != nil || last.NodeChain == nil || last.RouterID != profile.ID ||
			last.ProfileToken != startupExternalProfileToken(profile) {
			return nil, errors.New("startup Last changed its original ordered control or path policy")
		}
		refs = make([]common.MultihopNodeSelection, len(last.NodeChain.Nodes))
		for i, node := range last.NodeChain.Nodes {
			refs[i] = common.MultihopNodeSelection{ID: node.ID, Mode: node.Mode}
		}
		execution = last.NodeChain.Execution
	}
	selection, err := resolveDesktopNodeChainSelection(profile, profiles, refs, execution)
	if err != nil {
		return nil, err
	}
	root, err := canonicalBundleRoot(clientRoot(a))
	if err != nil {
		return nil, err
	}
	capture := &startupNodeChainCapture{root: root, selection: selection, last: last}
	for _, member := range selection.Nodes {
		sources, err := captureSavedNodeChainSources(root, member.Profile, member.Mode)
		if err != nil {
			return nil, err
		}
		capture.tokens = append(capture.tokens, startupProfileToken(member.Profile))
		for _, source := range sources {
			capture.assets = append(capture.assets, viaEntryAsset{member.Profile.ID, source.Mode, source.SHA256})
		}
	}
	if last != nil && !reflect.DeepEqual(capture.receipt(), last.NodeChain) {
		return nil, errors.New("startup Last changed an original ordered member, mode, root or private source")
	}
	return capture, nil
}

func (capture *startupNodeChainCapture) receipt() *startupNodeChainSelection {
	result := &startupNodeChainSelection{Schema: 1, Execution: "local", RootSHA256: startupNodeChainRootToken(capture.root)}
	for _, member := range capture.selection.Nodes {
		node := startupNodeChainMember{ID: member.Profile.ID, Mode: member.Mode, NodeProofID: member.Profile.NodeProofID,
			ProfileToken: startupExternalProfileToken(member.Profile)}
		if member.Profile.NodeKind == "external" {
			node.NodeKind = "external"
			result.Schema = 2
		}
		for _, source := range capture.assets {
			if source.id == node.ID {
				node.Sources = append(node.Sources, connectionProfileNodeSource{Mode: source.mode, SHA256: source.digest})
			}
		}
		result.Nodes = append(result.Nodes, node)
	}
	return result
}

func (capture *startupNodeChainCapture) currentProfilesLocked(a *app) error {
	if capture == nil || len(capture.tokens) != len(capture.selection.Nodes) {
		return errors.New("scheduled ordered startup lost its captured profiles")
	}
	seen := make(map[string]bool, len(a.profiles.Profiles))
	for _, profile := range a.profiles.Profiles {
		if seen[profile.ID] {
			return errors.New("scheduled ordered startup catalog has duplicate identities")
		}
		seen[profile.ID] = true
	}
	for i, member := range capture.selection.Nodes {
		profile, found := a.profileByIDLocked(member.Profile.ID)
		if !found || startupProfileToken(profile) != capture.tokens[i] || startupProfileToken(member.Profile) != capture.tokens[i] {
			return errors.New("scheduled ordered startup changed an original member or its complete policy")
		}
	}
	return nil
}

func (capture *startupNodeChainCapture) currentSourcesContext(ctx context.Context, a *app, owner *startupPolicyCapture) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("scheduled ordered startup lost its original caller")
	}
	root, err := canonicalBundleRoot(clientRoot(a))
	if err != nil || root != capture.root {
		return errors.Join(err, errors.New("scheduled ordered startup changed its canonical private root"))
	}
	var assets []viaEntryAsset
	for _, member := range capture.selection.Nodes {
		if err := ctx.Err(); err != nil {
			return err
		}
		sources, err := captureSavedNodeChainSources(root, member.Profile, member.Mode)
		if err != nil {
			return err
		}
		for _, source := range sources {
			assets = append(assets, viaEntryAsset{member.Profile.ID, source.Mode, source.SHA256})
		}
	}
	if !reflect.DeepEqual(assets, capture.assets) {
		return errors.New("scheduled ordered startup changed an original private source")
	}
	if capture.last != nil {
		last, err := a.loadStartupSelection()
		if err != nil || !reflect.DeepEqual(last, *capture.last) {
			return errors.New("scheduled ordered Last receipt was replaced")
		}
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	return errors.Join(owner.currentLocked(a), ctx.Err())
}

func (capture *startupPolicyCapture) nodeChainSelectionCurrent(ctx context.Context, a *app, selection multihopSelection) error {
	if capture == nil || capture.nodeChain == nil || a.checkCapturedConnectionOperation(ctx) != nil {
		return errors.New("ordered startup lost its original transaction")
	}
	if err := capture.currentContext(ctx, a); err != nil {
		return err
	}
	original := capture.nodeChain
	if startupProfileToken(selection.Control) != capture.profileToken || len(selection.Nodes) != len(original.selection.Nodes) ||
		selection.Base != original.selection.Base || selection.EntryMode != original.selection.EntryMode || selection.ExitMode != original.selection.ExitMode {
		return errors.New("ordered startup replaced its original resolved path")
	}
	for i, member := range selection.Nodes {
		if member.Mode != original.selection.Nodes[i].Mode || startupProfileToken(member.Profile) != original.tokens[i] {
			return errors.New("ordered startup substituted a captured member")
		}
	}
	if selection.Native != nil {
		if selection.Native.chain == nil || selection.Native.root != original.root ||
			!reflect.DeepEqual(selection.Native.chain.assets, original.assets) || selection.Native.validate(selection) != nil {
			return errors.New("ordered native compilation differs from its original scheduled asset capture")
		}
	}
	return ctx.Err()
}

func startupNodeChainRuntime() nativeMultihopConnectRuntime {
	return nativeMultihopConnectRuntime{capture: captureNativeMultihopForApp, preflight: preflightOwnedNativeMultihopCommand,
		stage: stageOwnedNativeMultihopCommand, proof: (*app).proveNativeMultihop}
}

func (a *app) nodeChainStartupDriver(ctx context.Context, capture *startupPolicyCapture, driver nativeMultihopConnectRuntime) (nativeMultihopConnectRuntime, error) {
	empty := nativeMultihopConnectRuntime{}
	if capture == nil || capture.nodeChain == nil || !nativeNodeChainPlatformSupported() ||
		driver.capture == nil || driver.preflight == nil || driver.stage == nil || driver.proof == nil {
		return empty, errors.New("ordered startup has no complete protected native adapter")
	}
	mode := strings.ToLower(strings.TrimSpace(capture.profile.StartupMode))
	if mode != "auto" && mode != "smart-auto" && mode != "last" || mode == "last" && capture.nodeChain.last == nil {
		return empty, errors.New("ordered startup has no supported original policy or proved Last receipt")
	}
	selection := capture.nodeChain.selection
	if err := capture.nodeChainSelectionCurrent(ctx, a, selection); err != nil {
		return empty, err
	}
	var compiled *nativeMultihopCapture
	var prepared *desktopNodeLaunch
	guard := func(selection multihopSelection) error {
		if err := capture.nodeChainSelectionCurrent(ctx, a, selection); err != nil {
			return err
		}
		if compiled != nil && selection.Native != compiled {
			return errors.New("ordered startup replaced its original compiled owner")
		}
		return nil
	}
	wrapped := nativeMultihopConnectRuntime{
		capture: func(owner *app, selection multihopSelection, modes []string) (multihopSelection, error) {
			if owner != a || compiled != nil || !reflect.DeepEqual(modes, []string{capture.nodeChain.selection.ExitMode}) {
				return selection, errors.New("ordered startup changed its original native capture call")
			}
			if err := guard(selection); err != nil {
				return selection, err
			}
			captured, err := driver.capture(owner, selection, modes)
			if err != nil {
				return captured, err
			}
			if captured.Native == nil || captured.Native.chain == nil {
				return captured, errors.New("ordered startup returned no complete native graph")
			}
			compiled = captured.Native
			return captured, guard(captured)
		},
		preflight: func(owner *app, selection multihopSelection, descriptor *desktopExecutionDescriptor) (*desktopNodeLaunch, error) {
			if owner != a || descriptor != nil || prepared != nil || compiled == nil {
				return nil, errors.New("ordered startup changed its original Local preflight")
			}
			if err := guard(selection); err != nil {
				return nil, err
			}
			launch, err := driver.preflight(owner, selection, descriptor)
			if err == nil {
				err = guard(selection)
			}
			if err == nil && (launch == nil || launch.chain == nil || launch.chain.selection.Native != compiled) {
				err = errors.New("ordered startup preflight returned another native owner")
			}
			if err != nil {
				// The outer handler has not installed its deferred retirement yet.
				// Join this exact prepared owner even when the caller was canceled.
				return nil, errors.Join(err, retireUnstartedNativeMultihop(launch))
			}
			prepared = launch
			return launch, nil
		},
		stage: func(owner *app, selection multihopSelection, launch *desktopNodeLaunch) error {
			if owner != a || launch == nil || launch != prepared {
				return errors.New("ordered startup staging changed its prepared owner")
			}
			if err := guard(selection); err != nil {
				return err
			}
			if err := driver.stage(owner, selection, launch); err != nil {
				return err
			}
			return guard(selection)
		},
		proof: func(owner *app, selection multihopSelection, command *exec.Cmd) error {
			if owner != a || prepared == nil || command == nil || command != prepared.command {
				return errors.New("ordered startup proof changed its original process")
			}
			if err := guard(selection); err != nil {
				return err
			}
			if err := driver.proof(owner, selection, command); err != nil {
				return err
			}
			return guard(selection)
		},
	}
	return wrapped, nil
}

func (a *app) startNodeChainStartupOwned(ctx context.Context, capture *startupPolicyCapture, driver nativeMultihopConnectRuntime) error {
	wrapped, err := a.nodeChainStartupDriver(ctx, capture, driver)
	if err != nil {
		return err
	}
	result := &startupConnectResponse{header: make(http.Header)}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "/api/multihop/connect", nil)
	if err != nil {
		return err
	}
	// Invoke the existing owned Local transaction directly: no HTTP reentry,
	// second connection operation, ordinary strategy, pair fallback or Compare.
	a.nativeMultihopConnectLocalOwned(result, request, ctx, capture.nodeChain.selection, wrapped)
	return result.err()
}

func (a *app) saveNodeChainStartupSelection(ctx context.Context, launch *desktopNodeLaunch, selection multihopSelection) error {
	if launch == nil || launch.chain == nil || selection.Native == nil || selection.Native.chain == nil ||
		launch.chain.selection.Native != selection.Native || a.checkCapturedConnectionOperation(ctx) != nil {
		return errors.New("ordered Last recording lost its original proved transaction")
	}
	if err := selection.Native.validate(selection); err != nil {
		return errors.Join(err, errors.New("ordered Last recording changed its originally proved member order or source"))
	}
	graph, found := getActiveMultihopGraph(a)
	owner, err := capturedNativeMultihopRuntimeContext(ctx, a, launch.command, graph)
	if err != nil || !found || owner.launch != launch || owner.selection.Native != selection.Native || graph.Execution != "local" || graph.ChainNodes != len(selection.Nodes) {
		return errors.Join(err, errors.New("ordered Last recording lost its full native proof owner"))
	}
	if err := desktopNodeChainCurrent(ctx, a, launch); err != nil {
		return err
	}
	capture := &startupNodeChainCapture{root: selection.Native.root, selection: selection, assets: selection.Native.chain.assets}
	last := startupSelection{RouterID: selection.Control.ID, RuntimeMode: selection.ExitMode, LogicalMode: "multihop", Base: selection.Base,
		ProfileToken: startupExternalProfileToken(selection.Control), UpdatedAt: time.Now().UTC(), NodeChain: capture.receipt(), PathKind: startupNodeChainPathKind}
	if err := validateStartupNodeChainSelection(last); err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	current, retained := nativeMultihopOwners.Load(a)
	st := a.state
	if !retained || current != owner || a.checkCapturedConnectionOperationLocked(ctx) != nil || a.cmd != launch.command ||
		!st.Connected || st.Phase != "connected" || st.Mode != "multihop" || st.RouterID != last.RouterID ||
		st.RuntimeMode != last.RuntimeMode || st.LogicalMode != last.LogicalMode || st.Base != last.Base ||
		!selection.Native.chain.profilesCurrent(selection.Control, a.profiles.Profiles) {
		return errors.New("ordered Last recording changed its current connected owner")
	}
	return a.saveStartupSelection(last)
}

// The caller holds a.mu; this is only a cheap path-family/owner classification.
// Existing Connected, session proof and operation checks still authorize writes.
func ordinaryStartupRecordAllowed(a *app, profile common.RouterProfile, st state) bool {
	if a == nil || profile.MultihopEnabled && len(profile.MultihopNodes) > 0 {
		return false
	}
	if st.Mode != "multihop" {
		return true
	}
	graph, found := getActiveMultihopGraph(a)
	if !found || graph.ChainNodes != 0 || graph.ExitID != st.RouterID || graph.Base != st.Base || graph.ExitMode != st.RuntimeMode {
		return false
	}
	if raw, retained := nativeMultihopOwners.Load(a); retained {
		owner, valid := raw.(*nativeMultihopRuntime)
		return valid && owner != nil && owner.launch != nil && owner.launch.command != nil &&
			owner.launch.command == a.cmd && owner.launch.chain == nil && owner.selection.Native != nil &&
			owner.selection.Native.chain == nil && sameMTUMultihopGraph(owner.graph, graph) &&
			owner.selection.Exit.ID == st.RouterID && owner.selection.ExitMode == st.RuntimeMode && owner.selection.Base == st.Base
	}
	// A retained native platform cannot downgrade a missing/retired owner into
	// a legacy pair. The legacy host must still retain its nonordered graph.
	return !retainedNativeMultihopSelected()
}

func orderedStartupError(err error) error {
	return errors.Join(errOrderedNodeChainDispatch, fmt.Errorf("ordered startup capture refused: %w", err))
}
