package main

import (
	"bytes"
	"crypto/sha256"
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
	ID           string                            `json:"id"`
	NodeKind     string                            `json:"node_kind,omitempty"`
	External     *connectionProfileExternalCapture `json:"external,omitempty"`
	Mode         string                            `json:"mode"`
	NodeProofID  string                            `json:"node_proof_id"`
	ProfileToken string                            `json:"profile_token"`
	Preferences  *connectionProfilePreferences     `json:"preferences"`
	Sources      []connectionProfileNodeSource     `json:"sources"`
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
	if !mobilemultihop.NodeChainPrefixMode(mode) && !desktopNodeChainFinalSupported(mode, startLayer) {
		return nil, errors.New("ordered path requires an exact WireGuard, AWG2, SS2022 or Hysteria2 source with its captured Start Layer")
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
		!validDesktopOrderedExecution(record.Prefs.MultihopExecution) || len(record.NodeChain) != len(record.Prefs.MultihopNodes) ||
		record.Prefs.MultihopEntryID != "" || record.Prefs.MultihopExitID != "" || record.Prefs.MultihopEntryMode != "" {
		return errors.New("saved ordered path has conflicting or incomplete selection records")
	}
	if err := common.ValidateMultihopNodes(record.Prefs.MultihopNodes); err != nil {
		return err
	}
	paired := common.ExtendedPairedLocalMultihopSelection(record.Prefs.MultihopNodes)
	mixed := common.ExtendedMixedLocalPacketCount(record.Prefs.MultihopNodes)
	if (paired || mixed > 0) && record.Prefs.MultihopExecution != "local" {
		return errors.New("saved extended paired route requires Local execution")
	}
	independent, err := savedNodeChainIndependentImports(record)
	if err != nil {
		return err
	}
	for i, captured := range record.NodeChain {
		selected := record.Prefs.MultihopNodes[i]
		if mixed > 0 && ((i >= mixed && i < len(record.NodeChain)-1) != (captured.NodeKind == "external")) {
			return errors.New("saved mixed route changed an original paired or imported position")
		}
		if (paired || mixed > 0 && (i < mixed || i == len(record.NodeChain)-1)) && (captured.NodeKind != "" || captured.Preferences == nil || captured.Preferences.StartLayer != "" && captured.Preferences.StartLayer != "off") {
			return errors.New("saved extended paired route lost its original Off member")
		}
		if captured.ID != selected.ID || captured.Mode != selected.Mode || !savedNodeChainDigest(captured.ProfileToken) {
			return errors.New("saved ordered member differs from its selected position or source identity")
		}
		if captured.NodeKind == "external" {
			if record.Prefs.MultihopExecution != "local" && !independent {
				connect := captured.Mode == "http-connect" || captured.Mode == "https-connect"
				socks := captured.Mode == "socks5"
				openvpn := captured.Mode == "openvpn"
				typed := connect || socks || openvpn
				count := len(record.NodeChain)
				if count < 3 || count > 8 || i != count-2 || (!typed && captured.Mode != "shadowsocks") || !mobilemultihop.NodeChainPrefixMode(record.NodeChain[0].Mode) || record.NodeChain[count-1].Mode != "shadowsocks" {
					return errors.New("saved imported execution requires its original complete literal SS2022, CONNECT, SOCKS or independently paired OpenVPN path")
				}
				if typed {
					final := record.NodeChain[count-1].Preferences
					if final == nil {
						return errors.New("saved typed proxy execution lost its original SS final")
					}
					if openvpn {
						if !desktopOpenVPNExecutionPairedLayer(final.StartLayer) {
							return errors.New("saved OpenVPN execution lost its original final Start Layer")
						}
					} else if socks {
						if !desktopSOCKSExecutionPairedLayer(final.StartLayer) {
							return errors.New("saved SOCKS execution lost its original final Start Layer")
						}
					} else if !desktopCONNECTExecutionPairedLayer(final.StartLayer) {
						return errors.New("saved CONNECT execution lost its original final Start Layer")
					}
				}
			}
			count, middle := len(record.NodeChain), 1
			bounded := count == 3
			if captured.Mode == "shadowsocks" || captured.Mode == "socks5" || captured.Mode == "http-connect" || captured.Mode == "https-connect" || captured.Mode == "openvpn" {
				bounded = count >= 3 && (count <= common.MultihopMaximumNodes || independent)
				middle = count - 2
			}
			placed := i == middle
			if independent {
				customEntry := count == 3 && record.NodeChain[0].NodeKind == "external" && record.NodeChain[1].NodeKind == "external"
				placed = (i > 0 && i < count-1 || i == 0 && customEntry) && captured.Mode == "shadowsocks"
			}
			if !bounded || !placed || record.NodeChain[len(record.NodeChain)-1].Mode != "shadowsocks" ||
				(captured.Mode != "openvpn" && captured.Mode != "shadowsocks" && captured.Mode != "socks5" && captured.Mode != "http-connect" && captured.Mode != "https-connect") ||
				captured.NodeProofID != "" || captured.Preferences != nil || captured.External == nil || captured.External.Protocol != captured.Mode || captured.External.validate() != nil || captured.External.StartLayer != "" && captured.External.StartLayer != "off" || len(captured.Sources) != 1 || captured.Sources[0].Mode != "external-"+captured.Mode || !savedNodeChainDigest(captured.Sources[0].SHA256) {
				return errors.New("saved imported middle lost its original external policy or source")
			}
			continue
		}
		if captured.NodeKind != "" || captured.External != nil || captured.Preferences == nil || !common.ValidNodeProofID(captured.NodeProofID) {
			return errors.New("saved paired member lost its original Router identity")
		}
		if i < len(record.NodeChain)-1 && !mobilemultihop.NodeChainPrefixMode(captured.Mode) || i == len(record.NodeChain)-1 && !desktopNodeChainFinalSupported(captured.Mode, captured.Preferences.StartLayer) {
			return errors.New("saved ordered path requires WireGuard or AWG2 prefixes and an SS2022 or unlayered Hysteria2 final")
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

// Policy-only saved records do not contain endpoint credentials. Independent
// shapes retain every external reference here; restoration must then validate
// the real linked literal SS sources before publishing the combined update.
func savedNodeChainIndependentImports(record connectionProfileRecord) (bool, error) {
	if record.Prefs == nil || !validDesktopOrderedExecution(record.Prefs.MultihopExecution) {
		return false, nil
	}
	var positions []int
	for i, member := range record.NodeChain {
		if member.NodeKind == "external" {
			positions = append(positions, i)
		}
	}
	if len(positions) == 0 || len(record.NodeChain) <= common.MultihopMaximumNodes && len(positions) == 1 && positions[0] == len(record.NodeChain)-2 {
		return false, nil
	}
	extended := len(record.NodeChain) > common.MultihopMaximumNodes
	if extended {
		last := len(record.NodeChain) - 1
		packets := common.ExtendedMixedLocalPacketCount(record.Prefs.MultihopNodes)
		if packets == 0 && common.ExtendedLocalMultihopSelection(record.Prefs.MultihopNodes) {
			packets = 1
		}
		if packets == 0 || len(positions) != last-packets || record.NodeChain[0].NodeKind == "external" || record.NodeChain[last].NodeKind == "external" {
			return false, errors.New("saved extended route requires its original entry, imported interiors and paired final")
		}
		for _, boundary := range []int{0, last} {
			p := record.NodeChain[boundary].Preferences
			if p == nil || p.StartLayer != "" && p.StartLayer != "off" {
				return false, errors.New("extended route lost its original boundary layer")
			}
		}
	}
	if len(record.NodeChain) < 3 || record.NodeChain[len(record.NodeChain)-1].Mode != "shadowsocks" {
		return false, errors.New("saved multiple imports lost their complete ordered path")
	}
	selected := record.Prefs.MultihopExecution != "local"
	if selected && len(record.NodeChain) < 4 {
		return false, errors.New("saved selected independent imports require their original paired entry and final")
	}
	for _, i := range positions {
		customEntry := !selected && len(record.NodeChain) == 3 && len(positions) == 2 && positions[0] == 0 && positions[1] == 1
		if i == 0 && !customEntry || i == len(record.NodeChain)-1 || record.NodeChain[i].Mode != "shadowsocks" {
			return false, errors.New("saved independent interiors require their original literal SS sources")
		}
	}
	if selected {
		for _, member := range record.NodeChain {
			if member.NodeKind != "external" && (member.Preferences == nil || !desktopOpenVPNExecutionPairedLayer(member.Preferences.StartLayer)) {
				return false, errors.New("saved selected independent imports lost an original paired Start Layer")
			}
		}
	}
	return true, nil
}

func captureSavedNodeChainSources(root string, node common.RouterProfile, mode string) ([]connectionProfileNodeSource, error) {
	if desktopNodeChainOpenVPNMiddle(node, mode) || desktopNodeChainImported(node, mode) || desktopNodeChainSOCKSMiddle(node, mode) || desktopNodeChainCONNECTMiddle(node, mode) {
		raw, err := json.Marshal(node.External)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(raw)
		clear(raw)
		return []connectionProfileNodeSource{{Mode: "external-" + mode, SHA256: hex.EncodeToString(digest[:])}}, nil
	}
	if node.NodeKind != "" && node.NodeKind != "router-vpn" || node.External != nil || !common.ValidNodeProofID(node.NodeProofID) {
		return nil, errors.New("ordered path requires linked Router WireGuard, AWG2, SS2022 or Hysteria2 sources")
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
	var executionMembers []desktopNodeChainMember
	for _, selection := range selected.MultihopNodes {
		node, found := a.profileByIDLocked(selection.ID)
		if !found {
			return nil, errors.New("ordered path references an unlinked node")
		}
		if node.NodeKind == "external" {
			policy, err := snapshotExternalConnectionPolicy(node)
			if err != nil {
				return nil, err
			}
			restored, err := policy.apply(node)
			if err != nil {
				return nil, err
			}
			sources, err := captureSavedNodeChainSources(clientRoot(a), restored, selection.Mode)
			if err != nil {
				return nil, err
			}
			executionMembers = append(executionMembers, desktopNodeChainMember{Profile: restored, Mode: selection.Mode})
			result = append(result, connectionProfileNodeChainCapture{ID: selection.ID, Mode: selection.Mode, NodeKind: "external", External: policy, ProfileToken: mtuProfileSnapshotToken(restored), Sources: sources})
			continue
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
		executionMembers = append(executionMembers, desktopNodeChainMember{Profile: restored, Mode: selection.Mode})
		result = append(result, connectionProfileNodeChainCapture{ID: selection.ID, Mode: selection.Mode, NodeProofID: node.NodeProofID,
			ProfileToken: mtuProfileSnapshotToken(restored), Preferences: policy, Sources: sources})
	}
	if err := desktopOrderedExecutionMembers(executionMembers, selected.MultihopExecution); err != nil {
		return nil, err
	}
	if selected.MultihopExecution == "local" {
		if _, err := desktopNodeChainSourceSchema(executionMembers); err != nil {
			return nil, err
		}
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
	if !reflect.DeepEqual(selected.MultihopNodes, saved.Prefs.MultihopNodes) || !selected.MultihopEnabled || selected.MultihopExecution != saved.Prefs.MultihopExecution {
		return nil, errors.New("saved ordered path differs from the requested restoration")
	}
	updates := make(map[string]common.RouterProfile, len(saved.NodeChain))
	var executionMembers []desktopNodeChainMember
	for _, captured := range saved.NodeChain {
		node, found := a.profileByIDLocked(captured.ID)
		if !found || node.NodeProofID != captured.NodeProofID {
			return nil, errors.New("saved ordered member identity was removed or relinked")
		}
		var restored common.RouterProfile
		var err error
		if captured.NodeKind == "external" {
			restored, err = captured.External.apply(node)
		} else {
			restored, err = applySavedRouterConnectionPolicy(node, captured.Preferences)
		}
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
		executionMembers = append(executionMembers, desktopNodeChainMember{Profile: restored, Mode: captured.Mode})
	}
	if err := desktopOrderedExecutionMembers(executionMembers, selected.MultihopExecution); err != nil {
		return nil, err
	}
	if selected.MultihopExecution == "local" {
		if _, err := desktopNodeChainSourceSchema(executionMembers); err != nil {
			return nil, err
		}
	}
	return updates, nil
}
