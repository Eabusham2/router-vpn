package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

const (
	orderedCandidateSavedCompleteScope   = "saved-complete-local"
	orderedCandidateSavedPrefixScope     = "saved-prefix-local"
	orderedCandidateSelectedDraftScope   = "draft-complete-selected"
	orderedCandidateAppendScope          = "draft-prefix-append"
	orderedCandidateAppendExecutionScope = "draft-prefix-append-execution"
)

func orderedCandidateAppendPurpose(scope string) bool {
	return scope == orderedCandidateAppendScope || scope == orderedCandidateAppendExecutionScope
}

func normalizedOrderedCandidateSavedScope(scope string) (string, error) {
	if scope == "" {
		return orderedCandidateSavedCompleteScope, nil
	}
	if scope != orderedCandidateSavedCompleteScope && scope != orderedCandidateSavedPrefixScope && scope != orderedCandidateSelectedDraftScope && !orderedCandidateAppendPurpose(scope) {
		return "", errors.New("saved candidates require an exact captured preparation purpose")
	}
	return scope, nil
}

// This source-only query cannot borrow a connected or selected runtime. The
// distinct closed preparation seals the complete replacement and native owner.
func desktopPreparedCandidateMode(launch *desktopNodeLaunch, position int) string {
	if launch == nil || launch.command != nil || launch.chain == nil || launch.chain.preparation != nil ||
		launch.chain.execution != nil || launch.chain.policy == nil {
		return ""
	}
	return launch.chain.policy.OriginalChain().PreparedCandidateResponseMode(position)
}

func publishOrderedCandidateResponseSource(response map[string]any, mode string, nodes []orderedCandidateResponseSourceNode, final *common.MultihopNodeSelection) {
	if mode != "" {
		response["candidate_mode"] = mode
		if final != nil {
			response["original_final"] = final
		} else {
			response["response_source_nodes"] = nodes
		}
	}
}

func captureDesktopNodeCandidatePrefixSource(ctx context.Context, selection multihopSelection, position int, inventory string) (*mobilemultihop.NodeChainCandidatePreparation, error) {
	if ctx == nil || ctx.Err() != nil || selection.Native == nil || selection.Native.chain == nil || selection.Native.validate(selection) != nil || position < 0 || position >= len(selection.Nodes)-1 {
		return nil, errors.New("candidate prefix requires its complete original saved source and a non-final position")
	}
	original := selection.Native.chain.chain
	metric := ""
	if original != nil {
		metric = original.CandidatePrefixMeasurement(position)
	}
	prep, err := captureDesktopNodeCandidatePrefixOriginal(selection.Native.chain, position, inventory)
	if err != nil {
		return nil, err
	}
	if prep.OriginalSourceSHA256() != selection.Native.source || prep.PrefixPosition() != position || prep.CaptureSHA256() == "" {
		return nil, errors.New("candidate prefix changed original saved provenance")
	}
	// A tagged native response uses the complete source-family compiler above,
	// including its imported UDP/layer closure. A generic TCP metric cannot
	// stand in for that separately sealed preparation purpose.
	nativeMode := prep.CandidateMode()
	if nativeMode != "" && (original == nil || original.PreparedCandidateResponseMode(position) != nativeMode) {
		return nil, errors.New("candidate prefix changed its original native response purpose")
	}
	for i, member := range selection.Nodes[:position+1] {
		if i > 0 && (nativeMode != "" || desktopCandidateResponseMetric(metric) || i < position && metric == hopmeasure.CandidateTCPMeasurement && desktopNodeChainImportedExecutionMiddle(member.Profile)) {
			continue
		}
		if !mobilemultihop.NodeChainPrefixMode(member.Mode) || !mobilemultihop.DesktopNodePhysicalGraphSupported(member.Mode, member.Profile.StartLayer) {
			return nil, errors.New("selected candidate prefix contains an unsupported paired native packet member")
		}
	}
	return prep, ctx.Err()
}

// These are distinct full-source constructors. A typed saved route supplies no
// generic connected path or runnable proxy suffix merely by preparing a prefix.
func captureDesktopNodeCandidatePrefixOriginal(original *desktopNodeChainCapture, position int, inventory string) (*mobilemultihop.NodeChainCandidatePreparation, error) {
	bad := errors.New("candidate prefix lost its exact original full source family")
	if original == nil {
		return nil, bad
	}
	switch {
	case original.socks != nil && original.socks.source != nil && original.chain == nil && original.connect == nil:
		input, err := original.socks.source.Source()
		if err != nil || input != original.input {
			return nil, bad
		}
		return mobilemultihop.NewNodeChainSOCKSCandidatePreparation(input, position, inventory)
	case original.connect != nil && original.connect.source != nil && original.chain == nil && original.socks == nil:
		input, err := original.connect.source.Source()
		if err != nil || input != original.input {
			return nil, bad
		}
		return mobilemultihop.NewNodeChainCONNECTCandidatePreparation(input, position, inventory)
	case original.chain != nil && original.socks == nil && original.connect == nil:
		// The original generic capture has already validated this launch input.
		// Project its typed source fields; never strip an arbitrary envelope.
		input, err := original.chain.LaunchInput()
		if err != nil || input != original.input {
			return nil, bad
		}
		if position > 0 && original.chain.HasExternalFinal() {
			return original.chain.NewPublicCandidatePreparation(position, inventory)
		}
		var source mobilemultihop.NodeChainSource
		if json.Unmarshal([]byte(input), &source) != nil {
			return nil, bad
		}
		raw, err := json.Marshal(source)
		if err != nil {
			return nil, err
		}
		defer clear(raw)
		return mobilemultihop.NewCapturedNodeChainCandidatePreparation(string(raw), position, inventory)
	default:
		return nil, bad
	}
}

// This private source capture deliberately has no core NodeChain. Its parsed
// append source and original request can be used only by the closed purpose.
type desktopNodeCandidateAppendCapture struct {
	original   *desktopNodeChainCapture
	native     *nativeMultihopCapture
	selection  multihopSelection
	request    *orderedCandidateAppendRequest
	requestSHA string
	source     *mobilemultihop.NodeChainCandidateAppendSource
	deviceMTU  *deviceMTUCapture
}

func desktopCandidateAppendCapture(selection multihopSelection) *desktopNodeCandidateAppendCapture {
	if selection.Native == nil || selection.Native.chain == nil {
		return nil
	}
	return selection.Native.chain.append
}

func captureDesktopCandidateAppendSelection(ctx context.Context, root string, control common.RouterProfile, profiles []common.RouterProfile,
	q *orderedCandidateAppendRequest, mtu *deviceMTUCapture) (multihopSelection, error) {
	var empty multihopSelection
	if ctx == nil || ctx.Err() != nil || q.validate() != nil || mtu == nil || mtu.current() != nil ||
		control.ID != *q.ExpectedSelectedNodeID || control.External != nil || control.NodeKind != "" && control.NodeKind != "router-vpn" ||
		!common.ValidNodeProofID(control.NodeProofID) || q.ExpectedProfileTokens[control.ID] != publicProfileToken(control) {
		return empty, errors.New("append source lost its independent original device control")
	}
	root, err := canonicalBundleRoot(root)
	if err != nil {
		return empty, err
	}
	byID := make(map[string]common.RouterProfile, len(profiles))
	for _, profile := range profiles {
		if _, found := byID[profile.ID]; found {
			return empty, errors.New("append source catalog repeats a saved identity")
		}
		byID[profile.ID] = profile
	}
	current, found := byID[control.ID]
	if !found || liveMeasurementProfileToken(current) != liveMeasurementProfileToken(control) {
		return empty, errors.New("append device source changed in its saved catalog")
	}
	capture := &desktopNodeChainCapture{root: root, control: cloneRouterProfile(control), controlToken: liveMeasurementProfileToken(control)}
	sourceSchema := 1
	pairedProxyEntry := q.pairedProxyEntry()
	if pairedProxyEntry {
		sourceSchema = 3
	}
	for i, node := range q.Nodes {
		profile, found := byID[node.ID]
		if !found || q.ExpectedProfileTokens[node.ID] != publicProfileToken(profile) {
			return empty, errors.New("append prefix lost an original saved member")
		}
		if profile.NodeKind == "external" || profile.External != nil {
			if pairedProxyEntry || i == 0 || !desktopNodeChainImported(profile, node.Mode) {
				return empty, errors.New("append imported member requires its original SS2022 capture and saved resolver")
			}
			sourceSchema = 2
		} else {
			if profile.NodeKind != "" && profile.NodeKind != "router-vpn" || !common.ValidNodeProofID(profile.NodeProofID) ||
				!desktopCONNECTExecutionPairedLayer(profile.StartLayer) || pairedProxyEntry && profile.StartLayer != "" && profile.StartLayer != "off" {
				return empty, errors.New("append prefix lost its original paired identity or captured layer")
			}
			if node.Mode == "shadowsocks" || node.Mode == "hysteria2" {
				if i == 0 && !pairedProxyEntry || profile.StartLayer != "" && profile.StartLayer != "off" {
					return empty, errors.New("append paired proxy requires its original captured prefix with Start Layer off")
				}
				if !pairedProxyEntry {
					sourceSchema = 2
				}
			} else if !mobilemultihop.NodeChainPrefixMode(node.Mode) {
				return empty, errors.New("append prefix member has no captured UDP carrier")
			}
		}
		// The imported constructor above captures hostname DNS through the
		// prefix. Paired members retain their original literal-only boundary.
		if (i > 0 || pairedProxyEntry) && profile.NodeKind != "external" {
			if _, err := netip.ParseAddr(profile.Endpoint); err != nil {
				return empty, errors.New("this paired append member requires its original literal endpoint")
			}
		}
		capture.members = append(capture.members, desktopNodeChainMember{Profile: cloneRouterProfile(profile), Mode: node.Mode})
		capture.tokens = append(capture.tokens, liveMeasurementProfileToken(profile))
	}
	total := 0
	device, _, _, err := capture.compileMember(ctx, desktopNodeChainMember{Profile: control, Mode: "wg"}, &total, nil)
	if err != nil {
		return empty, err
	}
	nodes, identities := make([]string, len(capture.members)), make([]string, len(capture.members))
	for i, member := range capture.members {
		input, endpoint, identity, err := capture.compileMember(ctx, member, &total, nil)
		if err != nil {
			return empty, err
		}
		nodes[i], identities[i] = input, identity
		if i == 0 {
			capture.endpoint = endpoint
		}
	}
	appendInput := map[string]any{"kind": "routervpn-node-chain-candidate-append-source", "schema": sourceSchema, "execution": "local",
		"draft_revision": q.DraftRevision, "device_revision": q.ExpectedProfileTokens[control.ID], "device_source": device,
		"device_mtu_revision": mtu.token, "device_fixed_mtu": mtu.policy.FixedMTU,
		"next_mode": q.NextMode, "append_position": q.AppendPosition, "nodes": nodes, "identity_sources": identities}
	if q.NextKind != "" {
		appendInput["next_kind"] = q.NextKind
	}
	raw, err := json.Marshal(appendInput)
	if err != nil || len(raw) > mobilemultihop.NodeChainInputLimit {
		clear(raw)
		return empty, errors.New("append source exceeds its original aggregate bound")
	}
	source, err := mobilemultihop.NewNodeChainCandidateAppendSource(string(raw))
	clear(raw)
	if err != nil {
		return empty, err
	}
	capture.input = source.Source()
	capture.seal = capture.digest()
	first := capture.members[0]
	selection := multihopSelection{Control: cloneRouterProfile(control), Entry: cloneRouterProfile(first.Profile), EntryMode: first.Mode,
		Base: desktopExternalEntryBase(first.Mode), Nodes: cloneDesktopNodeChainMembers(capture.members)}
	native := &nativeMultihopCapture{root: root, endpoint: capture.endpoint, source: source.SourceSHA256(), chain: capture,
		base: selection.Base, entryID: first.Profile.ID, entryMode: first.Mode, entrySelection: first.Mode,
		controlToken: capture.controlToken, entryToken: liveMeasurementProfileToken(first.Profile),
		configs: map[string]string{orderedCandidateAppendScope: source.Config()}, assets: append([]viaEntryAsset(nil), capture.assets...)}
	appendCapture := &desktopNodeCandidateAppendCapture{original: capture, native: native, request: q, requestSHA: q.digest(), source: source, deviceMTU: mtu}
	capture.append, selection.Native = appendCapture, native
	appendCapture.selection = selection
	if err := appendCapture.validate(ctx, selection); err != nil {
		return empty, err
	}
	return selection, nil
}

func (c *desktopNodeCandidateAppendCapture) profilesCurrent(profiles []common.RouterProfile) bool {
	if c == nil || c.original == nil {
		return false
	}
	control, found := profileByID(profiles, c.original.control.ID)
	return found && c.original.profilesCurrent(control, profiles)
}

func (c *desktopNodeCandidateAppendCapture) validate(ctx context.Context, selection multihopSelection) error {
	bad := errors.New("append source lost its original prefix, device policy or distinct owner")
	if ctx == nil || ctx.Err() != nil || c == nil || c.original == nil || c.native == nil || c.source == nil ||
		c.request.validate() != nil || c.requestSHA == "" || c.requestSHA != c.request.digest() || c.deviceMTU == nil || c.deviceMTU.current() != nil ||
		c.original.append != c || c.original.chain != nil || c.original.socks != nil || c.original.connect != nil ||
		c.original.seal == "" || c.original.seal != c.original.digest() || c.original.input != c.source.Source() ||
		c.native.chain != c.original || selection.Native != c.native || c.native.imported || c.native.importedHost != nil || c.native.importedPlatform != nil || c.native.openVPN != nil ||
		c.native.importedInput != "" || c.native.importedOriginalSource != "" || len(c.native.localPacketPublic) != 0 || len(c.native.localPQIdentity) != 0 || len(c.native.entryPhysical) != 0 ||
		c.native.root != c.original.root || c.native.endpoint != c.original.endpoint || c.native.source != c.source.SourceSHA256() || c.native.source == "" ||
		c.source.CandidateMode() != c.request.NextMode || c.source.CandidateKind() != c.request.candidateKind() || c.source.AppendPosition() != len(selection.Nodes) ||
		len(c.native.configs) != 1 || c.native.configs[orderedCandidateAppendScope] != c.source.Config() || c.source.ConfigSHA256() == "" ||
		selection.Control.ID != *c.request.ExpectedSelectedNodeID || liveMeasurementProfileToken(selection.Control) != c.original.controlToken ||
		c.native.controlToken != c.original.controlToken || !reflect.DeepEqual(selection.Exit, common.RouterProfile{}) || selection.ExitMode != "" || c.native.exitID != "" || c.native.exitToken != "" ||
		selection.serverPacketPublic != "" || selection.serverPQIdentity != "" || len(selection.Nodes) != len(c.original.members) ||
		len(selection.Nodes) != len(c.request.Nodes) || len(selection.Nodes) < 1 {
		return bad
	}
	first := selection.Nodes[0]
	if selection.EntryMode != first.Mode || selection.Base != desktopExternalEntryBase(first.Mode) ||
		liveMeasurementProfileToken(selection.Entry) != liveMeasurementProfileToken(first.Profile) ||
		c.native.entryID != first.Profile.ID || c.native.entryMode != first.Mode || c.native.entrySelection != first.Mode || c.native.base != selection.Base ||
		c.native.entryToken != liveMeasurementProfileToken(first.Profile) {
		return bad
	}
	for i, member := range selection.Nodes {
		original := c.original.members[i]
		if member.Mode != original.Mode || member.Mode != c.request.Nodes[i].Mode || member.Profile.ID != c.request.Nodes[i].ID ||
			liveMeasurementProfileToken(member.Profile) != liveMeasurementProfileToken(original.Profile) {
			return bad
		}
	}
	for _, asset := range c.original.assets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		files, err := readDesktopNodeAssets(c.original.root, asset.id, asset.mode)
		same := err == nil && viaEntryAssetDigest(files) == asset.digest
		clearViaEntryAssets(files)
		if !same {
			return bad
		}
	}
	return ctx.Err()
}

func validateDesktopCandidatePurposeSelection(ctx context.Context, selection multihopSelection, preparation *mobilemultihop.NodeChainCandidatePreparation) error {
	if c := desktopCandidateAppendCapture(selection); c != nil {
		if preparation == nil || !preparation.IsAppend() || preparation.OriginalSourceSHA256() != c.source.SourceSHA256() ||
			preparation.AppendPosition() != c.request.AppendPosition || preparation.CandidateMode() != c.request.NextMode ||
			preparation.CandidateKind() != c.source.CandidateKind() || preparation.CandidateMeasurement() != c.source.CandidateMeasurement() {
			return errors.New("append source cannot borrow another closed preparation")
		}
		return c.validate(ctx, selection)
	}
	if preparation != nil && preparation.IsAppend() || selection.Native == nil {
		return errors.New("append preparation lost its exclusive source")
	}
	return selection.Native.validate(selection)
}

func orderedCandidateClosedScope(scope string) bool {
	return scope == orderedCandidateSavedPrefixScope || orderedCandidateAppendPurpose(scope)
}

func (p *orderedCandidatePreparation) closedPurposeCurrent() bool {
	if p == nil || p.prefixPreparation == nil || !orderedCandidateClosedScope(p.request.Scope) {
		return false
	}
	if orderedCandidateAppendPurpose(p.request.Scope) {
		if !p.appendExecutionSourceCurrent() {
			return false
		}
		c := desktopCandidateAppendCapture(p.selection)
		return p.request.draft == nil && !p.request.serverResponse && p.request.append != nil && p.request.append.Purpose == p.request.Scope && c != nil && c.request == p.request.append &&
			p.prefixPreparation.IsAppend() && p.prefixPreparation.AppendPosition() == p.request.append.AppendPosition &&
			p.prefixPreparation.CandidateKind() == c.source.CandidateKind() && p.prefixPreparation.CandidateMeasurement() == c.source.CandidateMeasurement() &&
			p.request.Position == p.request.append.AppendPosition-1 && p.prefixPreparation.OriginalSourceSHA256() == c.source.SourceSHA256()
	}
	return p.request.append == nil && !p.prefixPreparation.IsAppend() && desktopCandidateAppendCapture(p.selection) == nil
}

// Source compilation reuses the same private asset parser and file inventory
// as complete-route candidates, but its only seal is this append preparation.
func captureDesktopAppendCandidateSourceProfiles(ctx context.Context, a *app, selection multihopSelection, launch *desktopNodeLaunch,
	profiles []common.RouterProfile, revision string, seal bool) (*desktopNodeChainCandidateCatalog, error) {
	c := desktopCandidateAppendCapture(selection)
	if c == nil || c.validate(ctx, selection) != nil || launch == nil || launch.chain != nil || launch.candidatePrefix != nil || launch.command != nil ||
		launch.root != selection.Native.root || launch.endpoint != selection.Native.endpoint || candidateServerRequested(ctx) {
		return nil, errors.New("append catalog cannot borrow a complete or selected launch")
	}
	result, err := captureDesktopCandidateSourceInventory(ctx, a, launch, profiles, revision, c.source.CandidateMode(), c.source)
	if err != nil {
		return nil, err
	}
	result.appendCapture = c
	if seal {
		if err = result.sealSourcePlan(ctx, len(selection.Nodes)-1, c.request.Purpose); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func captureDesktopAppendCandidateSources(ctx context.Context, a *app, selection multihopSelection, launch *desktopNodeLaunch, ids []string) (*desktopNodeChainCandidateCatalog, error) {
	if ctx == nil || ctx.Err() != nil || a == nil || len(ids) == 0 {
		return nil, errors.New("append inventory requires its captured saved candidates")
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	revision, err := a.candidateCatalogRevisionLocked()
	profiles := make([]common.RouterProfile, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		p, found := a.profileByIDLocked(id)
		if !found || !validProfileID(id) || seen[id] {
			err = errors.New("append candidate is not a distinct original saved node")
			break
		}
		seen[id] = true
		profiles = append(profiles, cloneRouterProfile(p))
	}
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return captureDesktopAppendCandidateSourceProfiles(ctx, a, selection, launch, profiles, revision, true)
}

func newDesktopCandidateAppendSourceLaunch(selection multihopSelection) (*desktopNodeLaunch, error) {
	c := desktopCandidateAppendCapture(selection)
	if c == nil || c.validate(context.Background(), selection) != nil {
		return nil, errors.New("append source projection lost its original capture")
	}
	// Deliberately no chain, policy, runtime, tracker, native process or Ready.
	return &desktopNodeLaunch{root: selection.Native.root, endpoint: selection.Native.endpoint}, nil
}

func (p *orderedCandidatePreparation) recaptureCandidateSources(ctx context.Context) (*desktopNodeChainCandidateCatalog, error) {
	if orderedCandidateAppendPurpose(p.request.Scope) {
		if !p.closedPurposeCurrent() {
			return nil, errors.New("append catalog lost its original closed purpose")
		}
		return captureDesktopAppendCandidateSources(ctx, p.app, p.selection, p.inventory.launch, p.originalCandidateInventoryIDs())
	}
	return captureDesktopNodeChainCandidateSourcesForScope(candidateServerIntent(ctx, p.request.serverResponse), p.app, p.inventory.launch, p.request.Position, p.request.CandidateIDs, p.request.Scope)
}

func desktopCandidateSavedProfilesCurrent(selection multihopSelection, profiles []common.RouterProfile) bool {
	if c := desktopCandidateAppendCapture(selection); c != nil {
		return c.native == selection.Native && c.profilesCurrent(profiles)
	}
	return selection.Native != nil && selection.Native.chain != nil && selection.Native.chain.profilesCurrent(selection.Control, profiles)
}
func validateDesktopCandidateSavedSelection(ctx context.Context, selection multihopSelection, profiles []common.RouterProfile) error {
	if c := desktopCandidateAppendCapture(selection); c != nil {
		if !c.profilesCurrent(profiles) {
			return errors.New("append source changed its original device or prefix profile")
		}
		return c.validate(ctx, selection)
	}
	if selection.Native == nil || selection.Native.chain == nil {
		return errors.New("candidate source lost its original complete capture")
	}
	return selection.Native.chain.validate(ctx, selection.Control, profiles)
}
