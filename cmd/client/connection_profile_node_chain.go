package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// Ordered captures retain references and policy, never transport credentials.
// Hops remains the legacy pair's unordered, optional policy inventory.
type connectionProfileNodeChainCapture struct {
	ID           string                        `json:"id"`
	Mode         string                        `json:"mode"`
	NodeProofID  string                        `json:"node_proof_id"`
	ProfileToken string                        `json:"profile_token"`
	Preferences  *connectionProfilePreferences `json:"preferences"`
	Sources      []connectionProfileNodeSource `json:"sources"`
}

type connectionProfileNodeSource struct {
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256"`
}

func (capture *connectionProfileNodeChainCapture) UnmarshalJSON(data []byte) error {
	type wire connectionProfileNodeChainCapture
	var decoded wire
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return errors.New("saved ordered member contains invalid or unsupported fields")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("saved ordered member requires one complete object")
	}
	*capture = connectionProfileNodeChainCapture(decoded)
	return nil
}

func savedNodeChainDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

// The standard peer remains this node's identity source even when its selected
// AWG transport uses independent packet keys. Retain only the exact chosen raw
// transport and, when needed, its separately captured Start Layer source.
func savedNodeChainSourceModes(mode, startLayer string) ([]string, error) {
	if !mobilemultihop.NodeChainPrefixMode(mode) && mode != "shadowsocks" {
		return nil, errors.New("ordered path requires an exact WireGuard, AWG2 or SS2022 source")
	}
	modes := []string{"wg"}
	if mode != "wg" && mode != "shadowsocks" {
		modes = append(modes, mode)
	}
	if mode == "shadowsocks" || startLayer != "" && startLayer != "off" {
		modes = append(modes, "shadowsocks")
	}
	return modes, nil
}

func validateSavedNodeChain(record connectionProfileRecord) error {
	if len(record.NodeChain) == 0 {
		if record.Prefs != nil && len(record.Prefs.MultihopNodes) != 0 {
			return errors.New("saved ordered selection lost its complete member captures")
		}
		return nil
	}
	if record.Prefs == nil || record.External != nil || len(record.Hops) != 0 || !record.Prefs.MultihopEnabled ||
		record.Prefs.MultihopExecution != "local" || len(record.NodeChain) != len(record.Prefs.MultihopNodes) ||
		record.Prefs.MultihopEntryID != "" || record.Prefs.MultihopExitID != "" || record.Prefs.MultihopEntryMode != "" {
		return errors.New("saved ordered path has conflicting or incomplete selection records")
	}
	if err := common.ValidateMultihopNodes(record.Prefs.MultihopNodes); err != nil {
		return err
	}
	for i, captured := range record.NodeChain {
		selected := record.Prefs.MultihopNodes[i]
		if captured.ID != selected.ID || captured.Mode != selected.Mode || captured.Preferences == nil ||
			!common.ValidNodeProofID(captured.NodeProofID) || !savedNodeChainDigest(captured.ProfileToken) {
			return errors.New("saved ordered member differs from its selected position or source identity")
		}
		if i < len(record.NodeChain)-1 && !mobilemultihop.NodeChainPrefixMode(captured.Mode) || i == len(record.NodeChain)-1 && captured.Mode != "shadowsocks" {
			return errors.New("saved ordered path requires WireGuard or AWG2 prefixes and an SS2022 final")
		}
		modes, err := savedNodeChainSourceModes(captured.Mode, captured.Preferences.StartLayer)
		if err != nil || len(captured.Sources) != len(modes) {
			return errors.New("saved ordered member lost its selected transport or Start Layer source")
		}
		for j, source := range captured.Sources {
			if source.Mode != modes[j] || !savedNodeChainDigest(source.SHA256) {
				return errors.New("saved ordered member source inventory is incomplete or noncanonical")
			}
		}
	}
	return nil
}

func captureSavedNodeChainSources(root string, node common.RouterProfile, mode string) ([]connectionProfileNodeSource, error) {
	if node.NodeKind != "" && node.NodeKind != "router-vpn" || node.External != nil || !common.ValidNodeProofID(node.NodeProofID) {
		return nil, errors.New("ordered path requires linked Router WireGuard, AWG2 or SS2022 sources")
	}
	modes, err := savedNodeChainSourceModes(mode, node.StartLayer)
	if err != nil {
		return nil, err
	}
	var result []connectionProfileNodeSource
	for _, sourceMode := range modes {
		files, err := readDesktopNodeAssets(root, node.ID, sourceMode)
		if err != nil {
			return nil, errors.New("ordered path lost a linked private source")
		}
		if sourceMode == "wg" {
			base, baseErr := mobilemultihop.NativeBaseSourceForEndpoint("wg", files, node.Endpoint)
			identity, identityErr := nodeProofIDFromWGConfig(base)
			if baseErr != nil || identityErr != nil || identity != node.NodeProofID {
				clearViaEntryAssets(files)
				return nil, errors.New("ordered member differs from its saved standard peer identity")
			}
		}
		result = append(result, connectionProfileNodeSource{Mode: sourceMode, SHA256: viaEntryAssetDigest(files)})
		clearViaEntryAssets(files)
	}
	return result, nil
}

func (a *app) snapshotConnectionNodeChainLocked(selected common.RouterProfile, prefs *connectionProfilePreferences) ([]connectionProfileNodeChainCapture, error) {
	if len(selected.MultihopNodes) == 0 || !selected.MultihopEnabled {
		return nil, nil
	}
	if err := common.NormalizeRouterProfile(&selected); err != nil {
		return nil, err
	}
	var result []connectionProfileNodeChainCapture
	for _, selection := range selected.MultihopNodes {
		node, found := a.profileByIDLocked(selection.ID)
		if !found {
			return nil, errors.New("ordered path references an unlinked node")
		}
		policy, err := snapshotConnectionPreferences(node, node.CustomLayers)
		if node.ID == selected.ID {
			policy = prefs
		}
		if err != nil || policy == nil {
			return nil, errors.New("ordered path member has no Router policy capture")
		}
		restored, err := applySavedRouterConnectionPolicy(node, policy)
		if err != nil {
			return nil, err
		}
		sources, err := captureSavedNodeChainSources(clientRoot(a), restored, selection.Mode)
		if err != nil {
			return nil, err
		}
		result = append(result, connectionProfileNodeChainCapture{ID: selection.ID, Mode: selection.Mode, NodeProofID: node.NodeProofID,
			ProfileToken: mtuProfileSnapshotToken(restored), Preferences: policy, Sources: sources})
	}
	if err := validateSavedNodeChain(connectionProfileRecord{Prefs: prefs, NodeChain: result}); err != nil {
		return nil, err
	}
	return result, nil
}

func (a *app) restoreConnectionNodeChainLocked(saved connectionProfileRecord, selected common.RouterProfile) (map[string]common.RouterProfile, error) {
	if err := validateSavedNodeChain(saved); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(selected.MultihopNodes, saved.Prefs.MultihopNodes) || !selected.MultihopEnabled || selected.MultihopExecution != "local" {
		return nil, errors.New("saved ordered path differs from the requested restoration")
	}
	updates := make(map[string]common.RouterProfile, len(saved.NodeChain))
	for _, captured := range saved.NodeChain {
		node, found := a.profileByIDLocked(captured.ID)
		if !found || node.NodeProofID != captured.NodeProofID {
			return nil, errors.New("saved ordered member identity was removed or relinked")
		}
		restored, err := applySavedRouterConnectionPolicy(node, captured.Preferences)
		if err != nil || mtuProfileSnapshotToken(restored) != captured.ProfileToken {
			return nil, errors.New("saved ordered member credentials or uncaptured policy changed")
		}
		sources, err := captureSavedNodeChainSources(clientRoot(a), restored, captured.Mode)
		if err != nil || !reflect.DeepEqual(sources, captured.Sources) {
			return nil, errors.New("saved ordered member private source was replaced")
		}
		if node.ID == selected.ID && mtuProfileSnapshotToken(selected) != captured.ProfileToken {
			return nil, errors.New("saved control policy differs from its ordered member capture")
		}
		updates[node.ID] = restored
	}
	return updates, nil
}
