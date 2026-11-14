package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

type desktopNodeChainMember struct {
	Profile common.RouterProfile
	Mode    string
}

// This is an immutable input capture retained by the existing native launch.
// It owns no process, TUN, protection rule, session, or independent registry.
type desktopNodeChainCapture struct {
	root, endpoint, controlToken, seal string
	control                            common.RouterProfile
	members                            []desktopNodeChainMember
	tokens                             []string
	assets                             []viaEntryAsset
	input                              string
	chain                              *mobilemultihop.NodeChain
	socks                              *desktopNodeChainSOCKSCapture
	host                               *desktopNodeChainHostCapture
}

// The imported middle retains its original external identity. It has no paired
// Router API, token or WireGuard identity inventory.
func desktopNodeChainImported(profile common.RouterProfile, mode string) bool {
	if profile.NodeKind != "external" || profile.External == nil || profile.External.Protocol != "shadowsocks" || mode != "shadowsocks" || profile.NodeProofID != "" || profile.APIToken != "" || profile.RouterAPI != "" || profile.StartLayer != "" && profile.StartLayer != "off" {
		return false
	}
	ss := profile.External.Shadowsocks
	if ss == nil || ss.Port < 1 || ss.Port > 65535 {
		return false
	}
	keyBytes := 32
	switch ss.Method {
	case "2022-blake3-aes-128-gcm":
		keyBytes = 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
	default:
		return false
	}
	key, err := base64.StdEncoding.DecodeString(ss.Password)
	if err != nil || len(key) != keyBytes {
		clear(key)
		return false
	}
	clear(key)
	address, err := netip.ParseAddr(ss.Server)
	if err == nil {
		return address.Zone() == "" && !address.Is4In6() && !address.IsUnspecified() && !address.IsMulticast() && ss.Server == profile.Endpoint
	}
	// A middle hostname has no physical bootstrap authority. Eligibility uses
	// the same sealed source constructor that will bind its saved TCP resolver
	// to the preceding packet prefix at launch.
	_, err = desktopNodeChainImportedHostnameInput(profile)
	return err == nil
}

func resolveDesktopNodeChainMembers(control common.RouterProfile, profiles []common.RouterProfile, nodes []common.MultihopNodeSelection, execution string) ([]desktopNodeChainMember, error) {
	if err := common.ValidateMultihopNodes(nodes); err != nil {
		return nil, err
	}
	if execution != "local" || control.NodeKind != "" && control.NodeKind != "router-vpn" || control.External != nil {
		return nil, errors.New("ordered selection requires an unambiguous Local Router control profile")
	}
	// Explicit ordered references describe this operation, including an edited
	// draft. Saved pair/order preferences remain in the original control token;
	// do not rewrite that private snapshot to make a different draft look saved.
	// Public admission separately requires the exact original catalog revisions.
	byID := make(map[string]common.RouterProfile, len(profiles))
	for _, profile := range profiles {
		if _, duplicate := byID[profile.ID]; duplicate {
			return nil, errors.New("ordered selection catalog has a duplicate identity")
		}
		byID[profile.ID] = profile
	}
	currentControl, found := byID[control.ID]
	if !found || liveMeasurementProfileToken(currentControl) != liveMeasurementProfileToken(control) {
		return nil, errors.New("ordered control capture differs from its linked catalog source")
	}
	var result []desktopNodeChainMember
	for i, selected := range nodes {
		profile, found := byID[selected.ID]
		imported := found && desktopNodeChainImported(profile, selected.Mode)
		paired := found && (profile.NodeKind == "" || profile.NodeKind == "router-vpn") && profile.External == nil && common.ValidNodeProofID(profile.NodeProofID)
		if imported {
			if len(nodes) != 3 || i != 1 || nodes[len(nodes)-1].Mode != "shadowsocks" {
				return nil, errors.New("imported ordered member requires exactly one middle between a paired physical entry and paired SS2022 final")
			}
		} else if !paired || i < len(nodes)-1 && !mobilemultihop.NodeChainPrefixMode(selected.Mode) || i == len(nodes)-1 && !desktopNodeChainFinalSupported(selected.Mode, profile.StartLayer) {
			return nil, errors.New("ordered selection requires paired WireGuard or AWG2 prefixes and a paired SS2022 or unlayered Hysteria2 final")
		}
		// Only the first closure owns physical bootstrap. An ambient lookup of
		// any later transport would bypass its preceding selected prefix.
		if i > 0 && !imported {
			if _, err := netip.ParseAddr(profile.Endpoint); err != nil {
				return nil, errors.New("later ordered nodes require a captured literal transport endpoint")
			}
		}
		result = append(result, desktopNodeChainMember{Profile: common.CloneRouterProfile(profile), Mode: selected.Mode})
	}
	return result, nil
}

func captureDesktopNodeChain(ctx context.Context, root string, control common.RouterProfile, profiles []common.RouterProfile, nodes []common.MultihopNodeSelection, execution string, lookup applexray.Lookup) (*desktopNodeChainCapture, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("ordered capture has no live original caller")
	}
	members, err := resolveDesktopNodeChainMembers(control, profiles, nodes, execution)
	if err != nil {
		return nil, err
	}
	root, err = canonicalBundleRoot(root)
	if err != nil {
		return nil, err
	}
	capture := &desktopNodeChainCapture{root: root, control: common.CloneRouterProfile(control), controlToken: liveMeasurementProfileToken(control), members: members}
	source := mobilemultihop.NodeChainSource{Schema: 1, Execution: "local"}
	total := 0
	for i, member := range members {
		if member.Profile.NodeKind == "external" {
			source.Schema = 2
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		input, endpoint, identity, err := capture.compileMember(ctx, member, &total, func() applexray.Lookup {
			if i == 0 {
				return lookup
			}
			return nil
		}())
		if err != nil {
			return nil, err
		}
		if i == 0 {
			capture.endpoint = endpoint
		}
		source.Nodes = append(source.Nodes, input)
		source.IdentitySources = append(source.IdentitySources, identity)
		capture.tokens = append(capture.tokens, liveMeasurementProfileToken(member.Profile))
	}
	raw, err := json.Marshal(source)
	if err != nil || len(raw) > mobilemultihop.NodeChainInputLimit {
		clear(raw)
		return nil, errors.New("complete ordered launch source exceeds its aggregate bound")
	}
	capture.chain, err = mobilemultihop.NewNodeChain(string(raw))
	clear(raw)
	if err != nil {
		return nil, err
	}
	capture.input, err = capture.chain.LaunchInput()
	if err != nil {
		return nil, err
	}
	capture.seal = capture.digest()
	if err := capture.validate(ctx, control, profiles); err != nil {
		return nil, err
	}
	return capture, nil
}

func (capture *desktopNodeChainCapture) compileMember(ctx context.Context, member desktopNodeChainMember, total *int, lookup applexray.Lookup) (string, string, string, error) {
	if member.Profile.NodeKind == "external" {
		if !desktopNodeChainImported(member.Profile, member.Mode) {
			return "", "", "", errors.New("ordered imported source changed kind or transport")
		}
		var input, endpoint string
		var err error
		if _, literalErr := netip.ParseAddr(member.Profile.Endpoint); literalErr != nil {
			// Do not use the standalone entry's bootstrap, resolver projection or
			// endpoint freezing for a transport below an existing packet prefix.
			input, err = desktopNodeChainImportedHostnameInput(member.Profile)
			endpoint = member.Profile.Endpoint
		} else {
			var config, policy string
			config, policy, endpoint, err = desktopImportedEntrySource(ctx, member.Profile, nil)
			if err == nil {
				input, err = mobilemultihop.NodeChainImportedMemberInput(config, policy)
			}
		}
		*total += len(input)
		if *total > mobilemultihop.NodeChainInputLimit {
			return "", "", "", errors.New("ordered imported source exceeds aggregate capture bound")
		}
		return input, endpoint, "", err
	}
	owned := map[string]map[string][]byte{}
	defer func() {
		for _, files := range owned {
			clearViaEntryAssets(files)
		}
	}()
	read := func(mode string) (map[string][]byte, error) {
		if files, found := owned[mode]; found {
			return files, nil
		}
		files, err := readDesktopNodeAssets(capture.root, member.Profile.ID, mode)
		if err != nil {
			return nil, err
		}
		owned[mode] = files
		for _, raw := range files {
			*total += len(raw)
		}
		if *total > mobilemultihop.NodeChainInputLimit {
			return nil, errors.New("ordered private sources exceed the aggregate capture bound")
		}
		capture.assets = append(capture.assets, viaEntryAsset{member.Profile.ID, mode, viaEntryAssetDigest(files)})
		return files, nil
	}
	wg, err := read("wg")
	if err != nil {
		return "", "", "", err
	}
	base, baseErr := mobilemultihop.NativeBaseSourceForEndpoint("wg", wg, member.Profile.Endpoint)
	identity, identityErr := nodeProofIDFromWGConfig(base)
	if baseErr != nil || identityErr != nil || identity != member.Profile.NodeProofID {
		return "", "", "", errors.New("ordered node identity differs from its original saved standard peer")
	}
	files, err := read(member.Mode)
	if err != nil {
		return "", "", "", err
	}
	var start map[string][]byte
	if member.Profile.StartLayer != "" && member.Profile.StartLayer != "off" && member.Mode != "shadowsocks" {
		start, err = read("shadowsocks")
		if err != nil {
			return "", "", "", err
		}
	}
	node, endpoint, err := compileDesktopNode(ctx, member.Profile, member.Mode, files, start, lookup)
	if err != nil {
		return "", "", "", err
	}
	// The original files are already retained by the captured asset digest.
	// Reuse this member's one captured bootstrap result when preparing its native
	// identity inventory, exactly as for its selected transport. Never look up
	// the identity separately, or rewrite the saved profile/asset maps.
	identityFiles := wg
	if endpoint != member.Profile.Endpoint {
		identityFiles, err = freezeDesktopNodeAssets(wg, member.Profile.Endpoint, endpoint)
		if err != nil {
			return "", "", "", err
		}
		defer clearViaEntryAssets(identityFiles)
	}
	input, err := node.LaunchInput()
	return input, endpoint, encodeDesktopNodeAssets(identityFiles), err
}

func (capture *desktopNodeChainCapture) digest() string {
	if capture == nil {
		return ""
	}
	assets := make([][3]string, len(capture.assets))
	for i, asset := range capture.assets {
		assets[i] = [3]string{asset.id, asset.mode, asset.digest}
	}
	modes := make([]string, len(capture.members))
	for i, member := range capture.members {
		modes[i] = member.Mode
	}
	raw, _ := json.Marshal([]any{capture.root, capture.endpoint, capture.controlToken, capture.tokens, modes, assets, capture.input})
	sum := sha256.Sum256(raw)
	clear(raw)
	return hex.EncodeToString(sum[:])
}

func (capture *desktopNodeChainCapture) profilesCurrent(control common.RouterProfile, profiles []common.RouterProfile) bool {
	if capture == nil || mtuProfileSnapshotToken(control) != mtuProfileSnapshotToken(capture.control) || liveMeasurementProfileToken(capture.control) != capture.controlToken || len(capture.members) != len(capture.tokens) {
		return false
	}
	seen := make(map[string]bool, len(profiles))
	for _, profile := range profiles {
		if seen[profile.ID] {
			return false
		}
		seen[profile.ID] = true
	}
	for i, member := range capture.members {
		current, found := profileByID(profiles, member.Profile.ID)
		if !found || mtuProfileSnapshotToken(current) != mtuProfileSnapshotToken(member.Profile) || liveMeasurementProfileToken(member.Profile) != capture.tokens[i] {
			return false
		}
	}
	return true
}

func (capture *desktopNodeChainCapture) validate(ctx context.Context, control common.RouterProfile, profiles []common.RouterProfile) error {
	if capture != nil && capture.socks != nil {
		if capture.chain != nil || capture.socks.original == nil || capture == capture.socks.original || capture.digest() != capture.socks.original.digest() || capture.seal != capture.socks.original.seal {
			return errors.New("typed SOCKS host inventory changed its original capture")
		}
		return capture.socks.validate(ctx, control, profiles)
	}
	bad := errors.New("ordered source, catalog, or captured forwarding order changed")
	if ctx == nil || ctx.Err() != nil || capture == nil || capture.chain == nil || capture.seal == "" || capture.seal != capture.digest() || !capture.profilesCurrent(control, profiles) {
		return bad
	}
	input, err := capture.chain.LaunchInput()
	if err != nil || input != capture.input {
		return bad
	}
	for _, asset := range capture.assets {
		if err := ctx.Err(); err != nil {
			return err
		}
		files, err := readDesktopNodeAssets(capture.root, asset.id, asset.mode)
		if err != nil {
			return bad
		}
		matches := viaEntryAssetDigest(files) == asset.digest
		clearViaEntryAssets(files)
		if !matches {
			return bad
		}
	}
	return ctx.Err()
}

func (capture *desktopNodeChainCapture) currentContext(ctx context.Context, a *app) error {
	if capture == nil || a == nil || ctx == nil {
		return errors.New("ordered capture lost its original catalog owner")
	}
	read := func() (common.RouterProfile, []common.RouterProfile, error) {
		if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
			return common.RouterProfile{}, nil, err
		}
		defer a.mu.Unlock()
		control, found := a.profileByIDLocked(capture.control.ID)
		if !found || a.profiles.SelectedID != capture.control.ID || a.closing {
			return common.RouterProfile{}, nil, errors.New("ordered control selection changed")
		}
		profiles := make([]common.RouterProfile, len(a.profiles.Profiles))
		for i, profile := range a.profiles.Profiles {
			profiles[i] = common.CloneRouterProfile(profile)
		}
		return common.CloneRouterProfile(control), profiles, nil
	}
	control, profiles, err := read()
	if err != nil {
		return err
	}
	if err := capture.validate(ctx, control, profiles); err != nil {
		return err
	}
	control, profiles, err = read()
	if err != nil || !capture.profilesCurrent(control, profiles) {
		return errors.Join(err, errors.New("ordered catalog changed during private source validation"))
	}
	return ctx.Err()
}

func (capture *desktopNodeChainCapture) project(ctx context.Context, targetOS string, restoreMTU int) (*mobilemultihop.NodeChain, error) {
	if capture == nil {
		return nil, errors.New("ordered projection lost its original capture")
	}
	profiles := make([]common.RouterProfile, len(capture.members))
	for i, member := range capture.members {
		profiles[i] = member.Profile
	}
	if err := capture.validate(ctx, capture.control, profiles); err != nil {
		return nil, err
	}
	return mobilemultihop.ProjectNodeChain(capture.chain, targetOS, restoreMTU)
}
