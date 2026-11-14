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
	app                               *app
	launch                            *desktopNodeLaunch
	identity                          speedLabPathIdentity
	revision, inventory, inventorySHA string
	plan                              *mobilemultihop.NodeChainCandidatePlan
	profiles                          map[string]string
	assets                            []viaEntryAsset
	files                             []desktopCandidateSourceFile
}

func captureDesktopNodeChainCandidates(ctx context.Context, a *app, identity speedLabPathIdentity, position int, ids []string) (*desktopNodeChainCandidateCatalog, error) {
	if ctx == nil || ctx.Err() != nil || a == nil || identity.Ordered == nil || identity.Ordered.launch == nil ||
		identity.Ordered.launch.chain == nil || len(ids) == 0 || len(ids) > hopmeasure.CandidateMaximumTargets {
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
	if ctx == nil || ctx.Err() != nil || a == nil || launch == nil || launch.chain == nil || launch.chain.policy == nil || len(ids) == 0 || len(ids) > hopmeasure.CandidateMaximumTargets {
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
	result := &desktopNodeChainCandidateCatalog{app: a, launch: launch, revision: revision, profiles: map[string]string{}}
	capture := &desktopNodeChainCapture{root: launch.root}
	// Pin each original asset directory before and after compilation, including
	// inodes and modification times. Replacing then restoring a source cannot
	// revive a previously measured catalog through an unchanged content hash.
	for _, p := range profiles {
		if p.StartLayer != "" && p.StartLayer != "off" {
			return nil, errors.New("candidate TCP timing requires this source's Start Layer Off")
		}
		if p.NodeKind != "external" {
			for _, mode := range []string{"wg", "shadowsocks"} {
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
	inventory := mobilemultihop.NodeChainCandidateInventory{Schema: 1, Revision: revision}
	total := 0
	for _, p := range profiles {
		input, err := capture.compileCandidateMember(ctx, p, &total)
		if err != nil {
			return nil, err
		}
		inventory.Inputs = append(inventory.Inputs, input)
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
	result.plan, err = launch.chain.policy.NodeChain().NewCandidatePlan(position, result.inventory)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Candidates retain their original protocol even though this operation only
// measures TCP establishment. The typed source compiler remains responsible
// for credentials, TLS and policy validation; no inferred port or hostname
// lookup can gain access to the retained packet prefix.
func (capture *desktopNodeChainCapture) compileCandidateMember(ctx context.Context, profile common.RouterProfile, total *int) (string, error) {
	if profile.NodeKind != "external" || profile.External == nil ||
		profile.External.Protocol != "http-connect" && profile.External.Protocol != "https-connect" {
		input, _, _, err := capture.compileMember(ctx, desktopNodeChainMember{Profile: profile, Mode: "shadowsocks"}, total, nil)
		return input, err
	}
	if ctx == nil {
		return "", errors.New("candidate source has no original caller")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	proxy := profile.External.HTTPConnect
	if profile.External.Protocol == "https-connect" {
		proxy = profile.External.HTTPSConnect
	}
	if proxy == nil {
		return "", errors.New("CONNECT candidate lost its original transport")
	}
	address, err := netip.ParseAddr(proxy.Host)
	if err != nil || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || proxy.Host != profile.Endpoint {
		return "", errors.New("CONNECT candidate requires its original literal endpoint")
	}
	config, policy, endpoint, err := desktopImportedEntrySource(ctx, profile, nil)
	if err != nil {
		return "", err
	}
	if endpoint != profile.Endpoint {
		return "", errors.New("CONNECT candidate replaced its captured endpoint")
	}
	input, err := mobilemultihop.NodeChainImportedCONNECTMemberInput(config, policy)
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
	if ctx == nil || ctx.Err() != nil || c == nil || c.app == nil || c.launch == nil || c.plan == nil {
		return bad
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
	if ctx == nil || ctx.Err() != nil || c == nil || c.app == nil || c.launch == nil || c.plan == nil || c.identity.Ordered == nil {
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
