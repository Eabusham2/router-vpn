package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

// Called under a.mu by every saved-profile transaction and every observation.
// A -> B -> A is a new catalog generation even when the last bytes match. Saved
// throughput, usage, and effective-MTU readback do not change source policy.
func (a *app) candidateCatalogRevisionLocked() (string, error) {
	if a == nil {
		return "", errors.New("candidate catalog owner is unavailable")
	}
	type entry struct{ ID, Token string }
	items := make([]entry, len(a.profiles.Profiles))
	seen := map[string]bool{}
	for i, p := range a.profiles.Profiles {
		if p.ID == "" || seen[p.ID] {
			return "", errors.New("candidate catalog has ambiguous node identities")
		}
		seen[p.ID] = true
		items[i] = entry{p.ID, publicProfileToken(p)}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	raw, err := json.Marshal([]any{a.profiles.SelectedID, items})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	clear(raw)
	digest := hex.EncodeToString(sum[:])
	if digest != a.profileCatalogDigest {
		if a.profileCatalogEpoch == ^uint64(0) {
			return "", errors.New("candidate catalog generation exhausted")
		}
		a.profileCatalogEpoch++
		a.profileCatalogDigest = digest
	}
	return fmt.Sprintf("%d:%s", a.profileCatalogEpoch, digest), nil
}

type desktopCandidateSourceFile struct {
	path string
	info os.FileInfo
}

type desktopNodeChainCandidateCatalog struct {
	serverResponse                    bool
	parsedInputs                      []*mobilemultihop.NodeChainCandidateInput
	app                               *app
	launch                            *desktopNodeLaunch
	identity                          speedLabPathIdentity
	revision, inventory, inventorySHA string
	candidateMode                     string
	plan                              *mobilemultihop.NodeChainCandidatePlan
	typedPlan                         *desktopTypedCandidateDescriptor
	typedEntryPreview                 *mobilemultihop.DesktopTypedEntryCandidateDescription
	selectedPlan                      *desktopSelectedCandidateDescriptor
	prefixPreparation                 *mobilemultihop.NodeChainCandidatePreparation
	appendCapture                     *desktopNodeCandidateAppendCapture
	profiles                          map[string]string
	assets                            []viaEntryAsset
	files                             []desktopCandidateSourceFile
}

func captureDesktopNodeChainCandidates(ctx context.Context, a *app, identity speedLabPathIdentity, position int, ids []string) (*desktopNodeChainCandidateCatalog, error) {
	if ctx == nil || ctx.Err() != nil || a == nil || identity.Ordered == nil || identity.Ordered.launch == nil ||
		identity.Ordered.launch.chain == nil || len(ids) == 0 {
		return nil, errors.New("candidate timing requires an original connected ordered path and saved nodes")
	}
	launch := identity.Ordered.launch
	result, err := captureDesktopNodeChainCandidateSources(ctx, a, launch, position, ids)
	if err != nil {
		return nil, err
	}
	result.identity = identity
	if err := result.current(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

// Capture the exact private source inventory without granting live-path
// authority. Only captureDesktopNodeChainCandidates admits this inventory to
// an original connected owner after the full identity check above.
func captureDesktopNodeChainCandidateSources(ctx context.Context, a *app, launch *desktopNodeLaunch, position int, ids []string) (*desktopNodeChainCandidateCatalog, error) {
	return captureDesktopNodeChainCandidateSourcesForScope(ctx, a, launch, position, ids, orderedCandidateSavedCompleteScope)
}

// A saved prefix captures its own closed preparation instead of borrowing the
// connected full-path plan. The ordinary caller above keeps that separate gate.
func captureDesktopNodeChainCandidateSourcesForScope(ctx context.Context, a *app, launch *desktopNodeLaunch, position int, ids []string, scope string) (*desktopNodeChainCandidateCatalog, error) {
	if ctx == nil || ctx.Err() != nil || a == nil || len(ids) == 0 {
		return nil, errors.New("candidate timing requires complete captured saved sources")
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	revision, err := a.candidateCatalogRevisionLocked()
	profiles := make([]common.RouterProfile, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		p, found := a.profileByIDLocked(id)
		if !validProfileID(id) || seen[id] || !found {
			err = errors.New("candidate is not a distinct saved node")
			break
		}
		seen[id] = true
		profiles = append(profiles, cloneRouterProfile(p))
	}
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return captureDesktopNodeChainCandidateSourceProfiles(ctx, a, launch, position, profiles, revision, scope)
}

// Enumerating a saved view uses one deep-cloned store revision, then checks that
// revision again before delivery. Rehashing every saved private profile once for
// each row made catalog construction quadratic. This source-only helper keeps
// the same compiler, file pinning and plan validation for every chosen member;
// it cannot grant measurement authority or replace the final current check.
func captureDesktopNodeChainCandidateSourceProfiles(ctx context.Context, a *app, launch *desktopNodeLaunch, position int, profiles []common.RouterProfile, revision, scope string) (*desktopNodeChainCandidateCatalog, error) {
	return captureDesktopCandidateSourceProfiles(ctx, a, launch, position, profiles, revision, scope, true)
}

func captureDesktopCandidateSourceProfiles(ctx context.Context, a *app, launch *desktopNodeLaunch, position int, profiles []common.RouterProfile, revision, scope string, seal bool) (*desktopNodeChainCandidateCatalog, error) {
	scope, scopeErr := normalizedOrderedCandidateSavedScope(scope)
	if scopeErr != nil {
		return nil, scopeErr
	}
	if ctx == nil || ctx.Err() != nil || a == nil || launch == nil || !launch.chain.hasPolicy() || len(profiles) == 0 || revision == "" {
		return nil, errors.New("candidate timing requires complete captured saved sources")
	}
	if scope == orderedCandidateSavedPrefixScope {
		if launch.chain.execution != nil || validateDesktopNodeChainLaunch(ctx, launch) != nil {
			return nil, errors.New("candidate prefix requires its original Local source projection")
		}
	} else if scope == orderedCandidateSelectedDraftScope {
		e := desktopNodeChainLaunchExecution(launch)
		if e == nil || launch.command != nil && !launch.chain.preparation.ownsSelectedDraft(launch, e) {
			return nil, errors.New("selected candidate source requires the original draft launch")
		}
	} else if launch.chain.execution != nil && !desktopSelectedCandidateSourceAllowed(launch) ||
		launch.chain.execution == nil && launch.chain.policy == nil && !desktopTypedCandidateSourceAllowed(launch) {
		return nil, errors.New("connected candidate timing requires its independently supported full-path plan")
	}
	candidateMode := ""
	if scope == orderedCandidateSavedCompleteScope {
		candidateMode = desktopCandidateSourceMode(launch, position)
	} else if scope == orderedCandidateSavedPrefixScope {
		candidateMode = desktopPreparedCandidateMode(launch, position)
	} else if scope == orderedCandidateSelectedDraftScope {
		candidateMode = desktopSelectedPacketCandidateMode(launch, position)
	}
	result, err := captureDesktopCandidateSourceInventory(ctx, a, launch, profiles, revision, candidateMode)
	if err != nil {
		return nil, err
	}
	result.serverResponse = candidateServerRequested(ctx)
	if seal {
		err = result.sealSourcePlan(ctx, position, scope)
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

// This shared parser grants no runtime or source purpose; callers seal the
// resulting inventory against their exact complete-route or append owner.
func captureDesktopCandidateSourceInventory(ctx context.Context, a *app, launch *desktopNodeLaunch, profiles []common.RouterProfile, revision, mode string) (*desktopNodeChainCandidateCatalog, error) {
	if ctx == nil || ctx.Err() != nil || a == nil || launch == nil || len(profiles) == 0 || revision == "" {
		return nil, errors.New("candidate source inventory lost its original caller")
	}
	seen := map[string]bool{}
	for _, profile := range profiles {
		if !validProfileID(profile.ID) || seen[profile.ID] {
			return nil, errors.New("candidate is not a distinct captured saved node")
		}
		seen[profile.ID] = true
	}
	result := &desktopNodeChainCandidateCatalog{app: a, launch: launch, revision: revision, candidateMode: mode, profiles: map[string]string{}}
	capture := &desktopNodeChainCapture{root: launch.root}
	// Pin each original asset directory before and after compilation, including
	// inodes and modification times. Replacing then restoring a source cannot
	// revive a previously measured catalog through an unchanged content hash.
	for _, p := range profiles {
		if result.candidateMode != "" && (p.External != nil || p.NodeKind != "" && p.NodeKind != "router-vpn" || p.StartLayer != "" && p.StartLayer != "off") {
			return nil, errors.New("candidate response requires an original paired node with Start Layer off")
		}
		switch p.StartLayer {
		case "", "off":
		case "aes-256-gcm", "aes-256-gcm+xor-whitening":
			if p.NodeKind != "" && p.NodeKind != "router-vpn" || p.External != nil {
				return nil, errors.New("imported candidate TCP timing requires its captured Off layer")
			}
		default:
			return nil, errors.New("candidate TCP timing requires an exact supported Start Layer")
		}
		if p.NodeKind != "external" {
			candidateMode := "shadowsocks"
			if result.candidateMode != "" {
				candidateMode = result.candidateMode
			}
			modes := []string{"wg"}
			if candidateMode != "wg" {
				modes = append(modes, candidateMode)
			}
			for _, mode := range modes {
				dir, err := nativeGeneratedDir(launch.root, p.ID, mode)
				if err != nil {
					return nil, err
				}
				info, err := os.Lstat(dir)
				if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
					return nil, errors.New("candidate saved source directory is unavailable")
				}
				result.files = append(result.files, desktopCandidateSourceFile{dir, info})
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) == 0 || len(entries) > 32 {
					return nil, errors.New("candidate saved source inventory is unavailable")
				}
				for _, entry := range entries {
					info, err := entry.Info()
					if err != nil || !info.Mode().IsRegular() {
						return nil, errors.New("candidate source is not a regular file")
					}
					result.files = append(result.files, desktopCandidateSourceFile{filepath.Join(dir, entry.Name()), info})
				}
			}
		}
		result.profiles[p.ID] = publicProfileToken(p)
	}
	inventory := mobilemultihop.NodeChainCandidateInventory{Schema: 1, Revision: revision, ResponseMode: result.candidateMode}
	total := 0
	for _, p := range profiles {
		var input string
		var parsed *mobilemultihop.NodeChainCandidateInput
		var err error
		if result.candidateMode != "" {
			input, _, _, err = capture.compileMember(ctx, desktopNodeChainMember{Profile: p, Mode: result.candidateMode}, &total, nil)
			if err == nil {
				parsed, err = mobilemultihop.ParseNodeChainResponseCandidateInput(input, result.candidateMode)
			}
		} else if p.NodeKind == "external" && desktopNodeChainImported(p, "shadowsocks") {
			input, parsed, err = compileDesktopOriginalImportedCandidate(ctx, p)
			total += len(input)
			if total > mobilemultihop.NodeChainInputLimit {
				return nil, errors.New("candidate source exceeds aggregate capture bound")
			}
		} else {
			input, err = capture.compileCandidateMember(ctx, p, &total)
			if err == nil {
				parsed, err = mobilemultihop.ParseNodeChainCandidateInput(input)
			}
		}
		if err != nil {
			return nil, err
		}
		inventory.Inputs = append(inventory.Inputs, input)
		result.parsedInputs = append(result.parsedInputs, parsed)
	}
	raw, err := json.Marshal(inventory)
	if err != nil || len(raw) > mobilemultihop.NodeChainInputLimit {
		clear(raw)
		return nil, errors.New("candidate source capture exceeds its bound")
	}
	result.inventory = string(raw)
	sum := sha256.Sum256(raw)
	clear(raw)
	result.inventorySHA = hex.EncodeToString(sum[:])
	result.assets = append([]viaEntryAsset(nil), capture.assets...)
	if err := result.pinPrivateReadPermissions(ctx); err != nil {
		return nil, err
	}

	return result, nil
}

func (result *desktopNodeChainCandidateCatalog) sealSourcePlan(ctx context.Context, position int, scope string) error {
	if ctx == nil || ctx.Err() != nil || result == nil || result.launch == nil {
		return errors.New("candidate source plan lost its original caller")
	}
	launch := result.launch
	var err error
	if scope == orderedCandidateAppendScope {
		c := result.appendCapture
		if c == nil || c.validate(ctx, c.selection) != nil || position != c.request.AppendPosition-1 || result.serverResponse || launch.chain != nil || launch.candidatePrefix != nil || launch.command != nil || result.candidateMode != c.source.CandidateMode() {
			return errors.New("append inventory lost its distinct original source")
		}
		result.prefixPreparation, err = mobilemultihop.NewNodeChainCandidateAppendPreparation(c.source.Source(), result.inventory)
	} else if result.appendCapture != nil {
		return errors.New("append inventory cannot enter a complete-route purpose")
	} else if scope == orderedCandidateSavedPrefixScope {
		result.prefixPreparation, err = captureDesktopNodeCandidatePrefixSource(ctx, launch.chain.selection, position, result.inventory)
	} else if scope == orderedCandidateSelectedDraftScope && launch.command == nil {
		err = captureSelectedDraftPreview(result, position)
	} else if scope == orderedCandidateSelectedDraftScope {
		result.selectedPlan, err = captureDesktopSelectedCandidateDescriptorForPurpose(launch, position, result.inventory, launch.chain.preparation)
	} else if launch.chain.execution != nil {
		result.selectedPlan, err = captureDesktopSelectedCandidateForIntent(launch, position, result.inventory, nil, result.serverResponse)
	} else if launch.chain.policy == nil {
		result.typedPlan, err = captureDesktopTypedCandidateDescriptor(launch, position, result.inventory)
	} else {
		result.plan, err = launch.chain.policy.NodeChain().NewCandidatePlanFromInputs(position, result.inventory, result.parsedInputs)
	}
	if err == nil && (result.plan != nil && result.plan.CandidateMode() != result.candidateMode ||
		result.prefixPreparation != nil && result.prefixPreparation.CandidateMode() != result.candidateMode ||
		result.selectedPlan != nil && result.selectedPlan.candidateMode() != result.candidateMode ||
		result.candidateMode != "" && result.plan == nil && result.prefixPreparation == nil && result.selectedPlan == nil) {
		return errors.New("candidate source plan changed its authenticated protocol")
	}
	return err
}

// A view needs each independent source's TCP eligibility, then one complete
// sealed inventory. Building and validating the same full chain for every row
// consumed the admission deadline before a large linked catalog could open.
func captureDesktopCandidateViewSource(ctx context.Context, a *app, launch *desktopNodeLaunch, position int, profile common.RouterProfile, revision, scope string, catalogMetric func(int) string) (*desktopNodeChainCandidateCatalog, error) {
	if catalogMetric == nil || launch == nil || launch.chain == nil || position < 0 || position >= len(launch.chain.selection.Nodes) {
		return nil, errors.New("candidate view lost its original prefix")
	}
	members := launch.chain.selection.Nodes
	sameNode := func(member desktopNodeChainMember) bool {
		return member.Profile.ID == profile.ID || profile.NodeProofID != "" && member.Profile.NodeProofID == profile.NodeProofID
	}
	if slices.ContainsFunc(members[:position+1], sameNode) {
		return nil, errors.New("candidate duplicates its original prefix")
	}
	if slices.ContainsFunc(members[position+1:], sameNode) {
		execution := desktopNodeChainLaunchExecution(launch)
		if desktopCandidateSourceMode(launch, position) != "" || scope == orderedCandidateSavedPrefixScope && desktopPreparedCandidateMode(launch, position) != "" || catalogMetric(position) == hopmeasure.CandidatePublicResponseMeasurement || execution != nil && (execution.preparation.SupportsCompareLocalResponseCandidate(position) || candidateServerRequested(ctx) && execution.preparation.SupportsServerResponseCandidate(position)) {
			return nil, errors.New("candidate duplicates a retained route member")
		}
	}
	part, err := captureDesktopCandidateSourceProfiles(ctx, a, launch, position, []common.RouterProfile{profile}, revision, scope, false)
	if err != nil {
		return nil, err
	}
	var inventory mobilemultihop.NodeChainCandidateInventory
	if json.Unmarshal([]byte(part.inventory), &inventory) != nil || inventory.ResponseMode != part.candidateMode || len(inventory.Inputs) != 1 || len(part.parsedInputs) != 1 || part.parsedInputs[0] == nil {
		return nil, errors.New("candidate has no original supported measurement source")
	}
	metric := catalogMetric(position)
	if part.candidateMode != "" {
		if metric != hopmeasure.CandidatePrivateResponseMeasurement || !mobilemultihop.NodeChainResponseCandidateInputSupported(inventory.Inputs[0], part.candidateMode) {
			return nil, errors.New("candidate has no original authenticated response source for its captured transport")
		}
		// Independently seal peer identity and derived route policy so one
		// aliased saved node cannot invalidate the other eligible choices.
		if err := part.sealSourcePlan(ctx, position, scope); err != nil {
			return nil, err
		}
	} else if metric == "" || desktopCandidateResponseMetric(metric) && !mobilemultihop.NodeChainCandidateInputSupportedForMeasurement(inventory.Inputs[0], metric) {
		return nil, errors.New("candidate has no attributable response through the selected prefix")
	}
	return part, nil
}

func combineDesktopCandidateViewSources(ctx context.Context, parts []*desktopNodeChainCandidateCatalog, position int, scope string) (*desktopNodeChainCandidateCatalog, error) {
	if ctx == nil || ctx.Err() != nil || len(parts) == 0 || parts[0] == nil {
		return nil, errors.New("candidate view has no complete source inventory")
	}
	first := parts[0]
	result := &desktopNodeChainCandidateCatalog{serverResponse: first.serverResponse, app: first.app, launch: first.launch, revision: first.revision, candidateMode: first.candidateMode, appendCapture: first.appendCapture, profiles: map[string]string{}}
	inventory := mobilemultihop.NodeChainCandidateInventory{Schema: 1, Revision: first.revision, ResponseMode: first.candidateMode}
	total := 0
	for _, part := range parts {
		if ctx.Err() != nil || part == nil || part.app != first.app || part.launch != first.launch || part.serverResponse != first.serverResponse || part.revision != first.revision || part.candidateMode != first.candidateMode || part.appendCapture != first.appendCapture {
			return nil, errors.New("candidate view mixed source generations")
		}
		captured := sha256.Sum256([]byte(part.inventory))
		if part.inventorySHA != hex.EncodeToString(captured[:]) {
			return nil, errors.New("candidate view changed an original captured inventory")
		}
		var source mobilemultihop.NodeChainCandidateInventory
		if json.Unmarshal([]byte(part.inventory), &source) != nil || source.Schema != 1 || source.Revision != first.revision || source.ResponseMode != first.candidateMode || len(source.Inputs) != 1 {
			return nil, errors.New("candidate view changed a captured source")
		}
		for id, token := range part.profiles {
			if _, exists := result.profiles[id]; exists {
				return nil, errors.New("candidate view repeats a saved identity")
			}
			result.profiles[id] = token
		}
		total += len(part.inventory)
		if total > mobilemultihop.NodeChainInputLimit {
			return nil, errors.New("candidate source capture exceeds its bound")
		}
		inventory.Inputs = append(inventory.Inputs, source.Inputs...)
		result.parsedInputs = append(result.parsedInputs, part.parsedInputs...)
		result.assets = append(result.assets, part.assets...)
		result.files = append(result.files, part.files...)
	}
	raw, err := json.Marshal(inventory)
	if err != nil || len(raw) > mobilemultihop.NodeChainInputLimit {
		clear(raw)
		return nil, errors.New("candidate source capture exceeds its bound")
	}
	result.inventory = string(raw)
	sum := sha256.Sum256(raw)
	clear(raw)
	result.inventorySHA = hex.EncodeToString(sum[:])
	if err := result.sealSourcePlan(ctx, position, scope); err != nil {
		return nil, err
	}
	if err := result.sourceFilesCurrent(ctx); err != nil {
		return nil, err
	}
	return result, ctx.Err()
}

// A candidate can use only its original literal standalone transport. Build
// the same source graph as a normal imported member, then validate it exactly
// once using the shared native compiler. No TUN or standalone policy is run.
func compileDesktopOriginalImportedCandidate(ctx context.Context, profile common.RouterProfile) (string, *mobilemultihop.NodeChainCandidateInput, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if _, err := netip.ParseAddr(profile.Endpoint); err != nil {
		return "", nil, errors.New("candidate requires an original literal endpoint")
	}
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		return "", nil, err
	}
	if exit.Server != profile.Endpoint {
		return "", nil, errors.New("candidate lost its original transport endpoint")
	}
	projection := cloneRouterProfile(profile)
	projection.DNSMode, projection.DNSProtocol, projection.DNSHost, projection.DNSPort = "rescue", "", "", 0
	projection.DNSServerName, projection.DNSPath = "", ""
	graph, err := buildDirectStandardExitConfig(projection, exit)
	if err != nil {
		return "", nil, err
	}
	if err = normalizeDesktopExternalSourceTUN(graph); err != nil {
		return "", nil, err
	}
	config, err := json.Marshal(graph)
	if err != nil {
		return "", nil, err
	}
	original, err := json.Marshal(map[string]any{"schema": 1, "exit_id": profile.ID, "protocol": profile.External.Protocol, "expected_public_ip": profile.External.ExpectedPublicIP, "profile": profile})
	if err != nil {
		return "", nil, err
	}
	return mobilemultihop.NewNodeChainImportedCandidateInput(string(config), string(original))
}

// Candidates retain their original protocol even though this operation only
// measures TCP establishment. The typed source compiler remains responsible
// for credentials, TLS and policy validation; no inferred port or hostname
// lookup can gain access to the retained packet prefix.
func (capture *desktopNodeChainCapture) compileCandidateMember(ctx context.Context, profile common.RouterProfile, total *int) (string, error) {
	if ctx == nil {
		return "", errors.New("candidate source has no current caller")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if profile.NodeKind != "external" || profile.External == nil ||
		profile.External.Protocol != "socks5" && profile.External.Protocol != "http-connect" && profile.External.Protocol != "https-connect" {
		mode := "shadowsocks"
		if profile.External != nil && profile.External.Protocol == "openvpn" {
			mode = "openvpn"
		}
		input, _, _, err := capture.compileMember(ctx, desktopNodeChainMember{Profile: profile, Mode: mode}, total, nil)
		if err == nil && mode == "openvpn" && !mobilemultihop.NodeChainCandidateInputSupported(input) {
			return "", errors.New("OpenVPN candidate timing requires one original literal TCP remote")
		}
		return input, err
	}
	var host string
	switch profile.External.Protocol {
	case "socks5":
		if proxy := profile.External.SOCKS5; proxy != nil {
			host = proxy.Host
		}
	case "http-connect":
		if proxy := profile.External.HTTPConnect; proxy != nil {
			host = proxy.Host
		}
	case "https-connect":
		if proxy := profile.External.HTTPSConnect; proxy != nil {
			host = proxy.Host
		}
	}
	if host == "" {
		return "", errors.New("proxy candidate lost its original transport")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || host != profile.Endpoint {
		return "", errors.New("proxy candidate requires its original literal endpoint")
	}
	config, policy, endpoint, err := desktopImportedEntrySource(ctx, profile, nil)
	if err != nil {
		return "", err
	}
	if endpoint != profile.Endpoint {
		return "", errors.New("proxy candidate replaced its captured endpoint")
	}
	var input string
	if profile.External.Protocol == "socks5" {
		input, err = mobilemultihop.NodeChainImportedSOCKSMemberInput(config, policy)
	} else {
		input, err = mobilemultihop.NodeChainImportedCONNECTMemberInput(config, policy)
	}
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	*total += len(input)
	if *total > mobilemultihop.NodeChainInputLimit {
		return "", errors.New("candidate source exceeds aggregate capture bound")
	}
	return input, nil
}

func (c *desktopNodeChainCandidateCatalog) current(ctx context.Context) error {
	bad := errors.New("candidate catalog, saved source, or original ordered path changed; retest")
	if ctx == nil || ctx.Err() != nil || c == nil || c.app == nil || c.launch == nil || !c.hasConnectedPlan() {
		return bad
	}
	if c.typedPlan != nil {
		if err := c.typedPlan.current(); err != nil {
			return err
		}
	}
	if c.selectedPlan != nil {
		if err := c.selectedPlan.current(ctx); err != nil {
			return err
		}
	}
	if err := validateSpeedLabIdentityContext(ctx, c.app, c.identity); err != nil {
		return err
	}
	return c.pulseCurrent(ctx)
}

// The full sealed native graph is checked at admission and adoption. Between
// them the child owns native proof/reader checks, while these pulses observe
// the actual parent session, catalog generation and private source files. Do
// not recompile the entire immutable graph for each of fifty TCP connections.
func (c *desktopNodeChainCandidateCatalog) pulseCurrent(ctx context.Context) error {
	bad := errors.New("candidate catalog, saved source, or original ordered path changed; retest")
	if ctx == nil || ctx.Err() != nil || c == nil || c.app == nil || c.launch == nil || !c.hasConnectedPlan() || c.identity.Ordered == nil {
		return bad
	}
	if owner, ok := nativeMultihopOwners.Load(c.app); !ok || owner != c.identity.Ordered || c.identity.Ordered.launch != c.launch {
		return bad
	}
	if graph, ok := getActiveMultihopGraph(c.app); !ok || graph != c.identity.Graph {
		return bad
	}
	_, session, err := measurementSessionContext(ctx, c.app, c.identity.Tracker)
	if err != nil || session.ID != c.identity.SessionID || !session.Connected || session.Phase != "connected" || session.PathProof != "passed" || session.RouterID != c.identity.RouterID {
		return errors.Join(err, bad)
	}
	network, err := c.identity.Ordered.physicalNetworkContext(ctx)
	if err != nil || network != c.identity.Network {
		return errors.Join(err, bad)
	}
	if err := desktopnetwork.LockContext(ctx, &c.app.mu); err != nil {
		return err
	}
	revision, err := c.app.candidateCatalogRevisionLocked()
	valid := err == nil && revision == c.revision && !c.app.controllerClosingLocked() && c.app.cmd == c.identity.Command &&
		c.app.state.Connected && c.app.state.Phase == "connected" && mtuStateSnapshotToken(c.app.state) == c.identity.StateToken
	for id, token := range c.profiles {
		p, found := c.app.profileByIDLocked(id)
		if !found || publicProfileToken(p) != token {
			valid = false
		}
	}
	c.app.mu.Unlock()
	if !valid {
		return bad
	}
	return c.sourceFilesCurrent(ctx)
}

// Reading a legacy private source may tighten its permissions to 0600.
// Adopt that result only for the identical original file. From here onward
// its mode, inode, size, modification time and compiled content remain pinned.
func (c *desktopNodeChainCandidateCatalog) pinPrivateReadPermissions(ctx context.Context) error {
	changed := false
	for index := range c.files {
		source := &c.files[index]
		before := source.info
		if !before.Mode().IsRegular() || before.Mode().Perm()&0o077 == 0 {
			continue
		}
		after, err := os.Lstat(source.path)
		if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			return errors.New("candidate saved source changed during its private read")
		}
		if after.Mode() == before.Mode() {
			continue
		}
		if after.Mode() != 0o600 {
			return errors.New("candidate saved source permissions changed during its private read")
		}
		source.info = after
		changed = true
	}
	if changed {
		return c.sourceFilesCurrent(ctx)
	}
	return ctx.Err()
}

func (c *desktopNodeChainCandidateCatalog) sourceFilesCurrent(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || c == nil || c.launch == nil {
		return errors.New("candidate source files lost their original caller")
	}
	bad := errors.New("candidate saved source files changed; retest")
	for _, file := range c.files {
		info, err := os.Lstat(file.path)
		if err != nil || !os.SameFile(file.info, info) || info.Mode() != file.info.Mode() ||
			info.Size() != file.info.Size() || !info.ModTime().Equal(file.info.ModTime()) {
			return bad
		}
	}
	for _, asset := range c.assets {
		if err := ctx.Err(); err != nil {
			return err
		}
		files, err := readDesktopNodeAssets(c.launch.root, asset.id, asset.mode)
		valid := err == nil && viaEntryAssetDigest(files) == asset.digest
		clearViaEntryAssets(files)
		if !valid {
			return bad
		}
	}
	return ctx.Err()
}
