package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobilemultihop"
)

// desktopNodeChainSOCKSCapture retains the original saved sources for one
// typed Local graph. The shared paired-source reader owns no native runtime;
// its generic chain/host fields must remain empty throughout this capture.
// A later typed desktop policy, not a generic NodeChain cast, owns projection.
type desktopNodeChainSOCKSCapture struct {
	original *desktopNodeChainCapture
	source   *mobilemultihop.NodeChainSOCKSSource
	config   string
	metadata string
	seal     string
}

func desktopNodeChainSOCKSMiddle(profile common.RouterProfile, mode string) bool {
	if mode != "socks5" || profile.NodeKind != "external" || profile.External == nil ||
		profile.External.Protocol != "socks5" || profile.External.SOCKS5 == nil ||
		profile.NodeProofID != "" || profile.APIToken != "" || profile.RouterAPI != "" ||
		profile.StartLayer != "" && profile.StartLayer != "off" {
		return false
	}
	socks := profile.External.SOCKS5
	address, err := netip.ParseAddr(socks.Host)
	return err == nil && address.Zone() == "" && !address.Is4In6() &&
		!address.IsUnspecified() && !address.IsMulticast() &&
		socks.Host == profile.Endpoint && socks.Port >= 1 && socks.Port <= 65535 &&
		len(socks.Username) <= 255 && len(socks.Password) <= 255 &&
		(socks.Username == "") == (socks.Password == "")
}

func resolveDesktopNodeChainSOCKSMembers(control common.RouterProfile, profiles []common.RouterProfile, nodes []common.MultihopNodeSelection, execution string) ([]desktopNodeChainMember, error) {
	bad := errors.New("ordered SOCKS capture requires its original three-member Local WG/AWG, literal SOCKS and paired SS path")
	if err := common.ValidateMultihopNodes(nodes); err != nil {
		return nil, err
	}
	if execution != "local" || len(nodes) != 3 || control.External != nil ||
		control.NodeKind != "" && control.NodeKind != "router-vpn" ||
		nodes[2].ID != control.ID || nodes[2].Mode != "shadowsocks" ||
		!mobilemultihop.NodeChainPrefixMode(nodes[0].Mode) {
		return nil, bad
	}
	byID := make(map[string]common.RouterProfile, len(profiles))
	for _, profile := range profiles {
		if _, duplicate := byID[profile.ID]; duplicate {
			return nil, bad
		}
		byID[profile.ID] = profile
	}
	currentControl, found := byID[control.ID]
	if !found || liveMeasurementProfileToken(currentControl) != liveMeasurementProfileToken(control) {
		return nil, bad
	}
	members := make([]desktopNodeChainMember, 0, 3)
	for i, selected := range nodes {
		profile, found := byID[selected.ID]
		if !found {
			return nil, bad
		}
		if i == 1 {
			if !desktopNodeChainSOCKSMiddle(profile, selected.Mode) {
				return nil, bad
			}
		} else {
			if profile.External != nil || profile.NodeKind != "" && profile.NodeKind != "router-vpn" ||
				!common.ValidNodeProofID(profile.NodeProofID) {
				return nil, bad
			}
			if i == 2 {
				address, err := netip.ParseAddr(profile.Endpoint)
				if err != nil || address.Zone() != "" || address.Is4In6() ||
					address.IsUnspecified() || address.IsMulticast() {
					return nil, bad
				}
			}
		}
		members = append(members, desktopNodeChainMember{Profile: common.CloneRouterProfile(profile), Mode: selected.Mode})
	}
	return members, nil
}

func captureDesktopNodeChainSOCKS(ctx context.Context, root string, control common.RouterProfile, profiles []common.RouterProfile, nodes []common.MultihopNodeSelection, execution string, lookup applexray.Lookup) (*desktopNodeChainSOCKSCapture, error) {
	if ctx == nil {
		return nil, errors.New("ordered SOCKS capture has no original caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	members, err := resolveDesktopNodeChainSOCKSMembers(control, profiles, nodes, execution)
	if err != nil {
		return nil, err
	}
	root, err = canonicalBundleRoot(root)
	if err != nil {
		return nil, err
	}
	original := &desktopNodeChainCapture{
		root: root, control: common.CloneRouterProfile(control),
		controlToken: liveMeasurementProfileToken(control), members: members,
	}
	wire := mobilemultihop.NodeChainSource{Schema: 3, Execution: "local"}
	total := 0
	for i, member := range members {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var input, endpoint, identity string
		if i == 1 {
			var config, capture string
			config, capture, endpoint, err = desktopImportedEntrySource(ctx, member.Profile, nil)
			if err == nil && endpoint != member.Profile.Endpoint {
				err = errors.New("ordered SOCKS source replaced its original literal endpoint")
			}
			if err == nil {
				input, err = mobilemultihop.NodeChainImportedSOCKSMemberInput(config, capture)
			}
			total += len(input)
		} else {
			var selectedLookup applexray.Lookup
			if i == 0 {
				selectedLookup = lookup
			}
			input, endpoint, identity, err = original.compileMember(ctx, member, &total, selectedLookup)
		}
		if err != nil {
			return nil, err
		}
		if total > mobilemultihop.NodeChainInputLimit {
			return nil, errors.New("ordered SOCKS source exceeds its original aggregate bound")
		}
		if i == 0 {
			original.endpoint = endpoint
		}
		wire.Nodes = append(wire.Nodes, input)
		wire.IdentitySources = append(wire.IdentitySources, identity)
		original.tokens = append(original.tokens, liveMeasurementProfileToken(member.Profile))
	}
	raw, err := json.Marshal(wire)
	if err != nil || len(raw) > mobilemultihop.NodeChainInputLimit {
		clear(raw)
		return nil, errors.New("complete ordered SOCKS source exceeds its original aggregate bound")
	}
	source, err := mobilemultihop.NewNodeChainSOCKSSource(string(raw))
	clear(raw)
	if err != nil {
		return nil, err
	}
	original.input, err = source.Source()
	if err != nil {
		return nil, err
	}
	config, metadata, err := source.ReadValidated()
	if err != nil {
		return nil, err
	}
	meta, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	capture := &desktopNodeChainSOCKSCapture{original: original, source: source, config: config, metadata: string(meta)}
	original.seal = original.digest()
	capture.seal = capture.digest()
	if err := capture.validate(ctx, control, profiles); err != nil {
		return nil, err
	}
	return capture, nil
}

func (capture *desktopNodeChainSOCKSCapture) digest() string {
	if capture == nil || capture.original == nil {
		return ""
	}
	raw, _ := json.Marshal([]string{"routervpn-desktop-socks-original-v1", capture.original.digest(), capture.config, capture.metadata})
	sum := sha256.Sum256(raw)
	clear(raw)
	return hex.EncodeToString(sum[:])
}

func (capture *desktopNodeChainSOCKSCapture) validate(ctx context.Context, control common.RouterProfile, profiles []common.RouterProfile) error {
	bad := errors.New("ordered SOCKS capture lost its original source, catalog or paired assets")
	if ctx == nil {
		return bad
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if capture == nil || capture.original == nil || capture.source == nil {
		return bad
	}
	original := capture.original
	if original.chain != nil || original.socks != nil || original.host != nil || original.seal == "" ||
		original.seal != original.digest() || capture.seal == "" || capture.seal != capture.digest() ||
		!original.profilesCurrent(control, profiles) {
		return bad
	}
	input, err := capture.source.Source()
	if err != nil || input != original.input {
		return bad
	}
	config, metadata, err := capture.source.ReadValidated()
	if err != nil {
		return bad
	}
	meta, err := json.Marshal(metadata)
	if err != nil || config != capture.config || string(meta) != capture.metadata {
		return bad
	}
	for _, asset := range original.assets {
		if err := ctx.Err(); err != nil {
			return err
		}
		files, err := readDesktopNodeAssets(original.root, asset.id, asset.mode)
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

func (capture *desktopNodeChainSOCKSCapture) currentContext(ctx context.Context, a *app) error {
	if capture == nil || capture.original == nil || a == nil || ctx == nil {
		return errors.New("ordered SOCKS capture lost its original catalog owner")
	}
	original := capture.original
	read := func() (common.RouterProfile, []common.RouterProfile, error) {
		if err := mobilemtu.LockContext(ctx, &a.mu); err != nil {
			return common.RouterProfile{}, nil, err
		}
		defer a.mu.Unlock()
		control, found := a.profileByIDLocked(original.control.ID)
		if !found || a.profiles.SelectedID != original.control.ID || a.closing {
			return common.RouterProfile{}, nil, errors.New("ordered SOCKS control selection changed")
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
	if err != nil || !original.profilesCurrent(control, profiles) {
		return errors.Join(err, errors.New("ordered SOCKS catalog changed during private source validation"))
	}
	return ctx.Err()
}
