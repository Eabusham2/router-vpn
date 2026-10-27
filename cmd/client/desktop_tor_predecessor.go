package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

// The original saved identity stays separate from the literal private launch
// copy. Relinking a mode file must retire this entry even if its label survives.
type desktopTorPredecessorCapture struct {
	entry        common.RouterProfile
	profileToken string
	assetsSHA256 string
	mode         string
	endpoint     string
	native       *mobiletor.DesktopPredecessor
}

func desktopNodeAssetsIdentity(mode string, files, start map[string][]byte) (string, error) {
	raw, err := json.Marshal(struct {
		Mode         string
		Files, Start map[string][]byte
	}{mode, files, start})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	clear(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Both preparation and native reconstruction validate the complete selected
// graph. Saved credentials, endpoints, mode files and MTU history stay intact.
func compileDesktopTorPredecessor(ctx context.Context, entry common.RouterProfile, mode string, files, start map[string][]byte, lookup applexray.Lookup) (*desktopTorPredecessorCapture, error) {
	if entry.ID == "" || entry.External != nil || entry.NodeKind != "" && entry.NodeKind != "router-vpn" {
		return nil, errors.New("desktop Tor Local entry requires its private Router node")
	}
	entry = cloneRouterProfile(entry)
	assets, err := desktopNodeAssetsIdentity(mode, files, start)
	if err != nil {
		return nil, err
	}
	compiled, endpoint, err := compileDesktopNode(ctx, entry, mode, files, start, lookup)
	if err != nil {
		return nil, err
	}
	frozen := cloneRouterProfile(entry)
	frozen.NodeKind, frozen.Endpoint = "router-vpn", endpoint
	raw, err := json.Marshal(frozen)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	native, err := mobiletor.NewDesktopPredecessor(mode, string(raw), compiled.Config(), assets)
	if err != nil {
		return nil, err
	}
	return &desktopTorPredecessorCapture{entry: entry, profileToken: desktopTorSourceIdentityToken(entry), assetsSHA256: assets, mode: mode, endpoint: endpoint, native: native}, nil
}

func captureDesktopTorPredecessor(a *app, profile common.RouterProfile, lookup applexray.Lookup) (*desktopTorPredecessorCapture, error) {
	if !profile.MultihopEnabled {
		return nil, nil
	}
	if a == nil || profile.External == nil || profile.External.Protocol != "tor-bridge" || profile.MultihopExitID != profile.ID || !validProfileID(profile.MultihopEntryID) || profile.MultihopEntryID == profile.ID {
		return nil, errors.New("desktop Tor requires the exact saved entry and exit references")
	}
	if profile.MultihopExecution != "" && profile.MultihopExecution != "local" {
		return nil, errors.New("desktop Tor Server and Compare require their authenticated execution owners; the saved choice cannot be replaced by Local")
	}
	a.mu.Lock()
	entry, found := a.profileByIDLocked(profile.MultihopEntryID)
	entry = cloneRouterProfile(entry)
	a.mu.Unlock()
	if !found {
		return nil, errors.New("desktop Tor Local entry is not a linked node")
	}
	mode, err := desktopTorEntryMode(profile, entry, "", "")
	if err != nil {
		return nil, err
	}
	if entry.External != nil {
		captured, err := compileDesktopTorExternalPredecessor(a.connectionOperationContextOrBackground(), entry, profile, mode, lookup)
		if err != nil {
			return nil, err
		}
		if err = captured.current(a); err != nil {
			return nil, err
		}
		return captured, nil
	}
	files, err := readDesktopNodeAssets(clientRoot(a), entry.ID, mode)
	if err != nil {
		return nil, err
	}
	defer eraseDesktopTorAssets(files)
	var start map[string][]byte
	if entry.StartLayer != "" && entry.StartLayer != "off" && !mobilemultihop.MAXMode(mode) && mode != "shadowsocks" {
		start, err = readDesktopNodeAssets(clientRoot(a), entry.ID, "shadowsocks")
		if err != nil {
			return nil, err
		}
		defer eraseDesktopTorAssets(start)
	}
	captured, err := compileDesktopTorPredecessor(a.connectionOperationContextOrBackground(), entry, mode, files, start, lookup)
	if err != nil {
		return nil, err
	}
	if err := captured.current(a); err != nil {
		return nil, err
	}
	return captured, nil
}

func eraseDesktopTorAssets(files map[string][]byte) {
	for _, raw := range files {
		clear(raw)
	}
}

func (captured *desktopTorPredecessorCapture) currentLocked(a *app) error {
	if captured == nil {
		return nil
	}
	if a == nil || captured.native == nil || captured.profileToken == "" || captured.assetsSHA256 != captured.native.AssetsSHA256() || captured.entry.ID != captured.native.ID() || captured.mode != captured.native.Mode() {
		return errors.New("Tor predecessor lost its immutable source owner")
	}
	entry, found := a.profileByIDLocked(captured.entry.ID)
	if !found || desktopTorSourceIdentityToken(entry) != captured.profileToken {
		return errors.New("Tor predecessor profile or credentials changed")
	}
	return nil
}

func (captured *desktopTorPredecessorCapture) current(a *app) error {
	if captured == nil {
		return nil
	}
	if a == nil {
		return errors.New("Tor predecessor has no application owner")
	}
	a.mu.Lock()
	err := captured.currentLocked(a)
	a.mu.Unlock()
	if err != nil {
		return err
	}
	assets, err := startupExternalSourceToken(a, captured.entry, captured.mode)
	if err != nil || assets != captured.assetsSHA256 {
		return errors.New("Tor predecessor private mode or Start Layer source changed")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return captured.currentLocked(a)
}

func (owner *desktopTorRuntime) entryCurrentLocked(a *app) error {
	if owner == nil {
		return errors.New("Tor has no captured runtime owner")
	}
	entry := owner.predecessor
	meta := owner.expected
	if meta.EntryID == "" {
		if entry != nil {
			return errors.New("direct Tor acquired an unrelated predecessor")
		}
		return nil
	}
	if entry == nil || entry.native == nil || meta.EntryID != entry.entry.ID || meta.EntryMode != entry.mode || meta.EntryTag != entry.native.Tag() || meta.EntrySHA256 != entry.native.Fingerprint() || meta.EntryAssetsSHA256 != entry.assetsSHA256 ||
		entry.native.IsExternal() && meta.EntryProofKind != mobiletor.ExternalPredecessorProofKind || entry.native.IsRouter() && meta.EntryProofKind != "" && meta.EntryProofKind != mobiletor.RouterPredecessorProofKind {
		return errors.New("Tor predecessor no longer matches its typed native capture")
	}
	return entry.currentLocked(a)
}

func (owner *desktopTorRuntime) entryCurrent(a *app) error {
	if a == nil {
		return errors.New("Tor has no application owner")
	}
	a.mu.Lock()
	err := owner.entryCurrentLocked(a)
	a.mu.Unlock()
	if err != nil {
		return err
	}
	return owner.predecessor.current(a)
}

// Only the nested complete entry capture gets the larger bound. Direct
// decoding still enforces 16 KiB and other inputs keep their existing bound.
func desktopTorInputLimit(name string) int64 {
	if name == "tor-capture.json" {
		return 8 << 20
	}
	return 4 << 20
}
