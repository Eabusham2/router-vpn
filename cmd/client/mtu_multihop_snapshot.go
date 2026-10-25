package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/multihoprelay"
)

type mtuMultihopSnapshot struct {
	Graph                           activeMultihopGraph
	Control, Entry                  common.RouterProfile
	ControlToken, EntryToken, Token string
	PhysicalEntry                   string
	Native                          *nativeMultihopRuntime
	Relay                           *desktopRelayOwner
	RelayToken                      string
	Command                         *exec.Cmd
}

// Accessed with app.mu. A failed final adoption may restore only the exact
// measurement fields that this operation itself successfully persisted.
type mtuMeasurementPersistence struct{ applied string }

func captureMTUMultihopSnapshot(a *app, selected common.RouterProfile, st state, command *exec.Cmd) (mtuRetestSnapshot, error) {
	graph, present := getActiveMultihopGraph(a)
	if !present || !st.Connected || st.Phase != "connected" || st.RouterID != graph.ExitID ||
		st.RuntimeMode != graph.ExitMode || st.Base != graph.Base || graph.Started.IsZero() ||
		(graph.Execution != "local" && graph.Execution != "server") {
		return mtuRetestSnapshot{}, errors.New("MTU Retest requires the exact connected entry, exit and proved Local/Server execution")
	}
	a.mu.Lock()
	entry, entryOK := a.profileByIDLocked(graph.EntryID)
	exit, exitOK := a.profileByIDLocked(graph.ExitID)
	entry, exit = common.CloneRouterProfile(entry), common.CloneRouterProfile(exit)
	a.mu.Unlock()
	if !entryOK || !exitOK || entry.External != nil || exit.External != nil || entry.NodeKind == "external" || exit.NodeKind == "external" ||
		entry.ID == exit.ID || !common.ValidNodeProofID(entry.NodeProofID) || !common.ValidNodeProofID(exit.NodeProofID) || entry.NodeProofID == exit.NodeProofID {
		return mtuRetestSnapshot{}, errors.New("multihop MTU requires both distinct captured Router node identities")
	}
	if !strings.EqualFold(strings.TrimSpace(exit.MTUPolicy), "auto") {
		return mtuRetestSnapshot{}, errors.New("set the active exit node MTU policy to Auto before Retest")
	}
	session := sessionTrackerFor(a).snapshot(0)
	if session.ID == "" || !session.Connected || session.Phase != "connected" || session.PathProof != "passed" ||
		session.RouterID != exit.ID || session.ActualMode != graph.ExitMode || session.ActualBase != graph.Base {
		return mtuRetestSnapshot{}, errors.New("multihop MTU session has not proved this exact exit path")
	}
	owner, err := capturedNativeMultihopRuntime(a, command, graph)
	if err != nil {
		return mtuRetestSnapshot{}, err
	}
	if mtuProfileSnapshotToken(owner.selection.Control) != mtuProfileSnapshotToken(selected) ||
		mtuProfileSnapshotToken(owner.selection.Entry) != mtuProfileSnapshotToken(entry) ||
		mtuProfileSnapshotToken(owner.selection.Exit) != mtuProfileSnapshotToken(exit) {
		return mtuRetestSnapshot{}, errors.New("multihop MTU profiles differ from the running captured graph")
	}
	path := &mtuMultihopSnapshot{Graph: graph, Control: common.CloneRouterProfile(selected), Entry: entry,
		ControlToken: mtuProfileSnapshotToken(selected), EntryToken: mtuProfileSnapshotToken(entry),
		PhysicalEntry: owner.launch.endpoint, Native: owner, Command: command}
	if graph.Execution == "server" {
		raw, found := desktopRelays.Load(a)
		path.Relay, _ = raw.(*desktopRelayOwner)
		if !found || path.Relay == nil || path.Relay.command != command || path.Relay.request.ExitID != graph.ExitID ||
			path.Relay.request.ExitMode != graph.ExitMode || path.Relay.request.EntryNodeID != entry.NodeProofID {
			return mtuRetestSnapshot{}, errors.New("multihop MTU server execution lost its authenticated lease owner")
		}
		path.Relay.mu.Lock()
		valid := path.Relay.expected.ExitNodeID == exit.NodeProofID && path.Relay.expected.NodeID == entry.NodeProofID && path.Relay.expected.Request == path.Relay.request
		path.RelayToken = mtuRelayIdentityToken(path.Relay.expected)
		path.Relay.mu.Unlock()
		if !valid {
			return mtuRetestSnapshot{}, errors.New("multihop MTU server exit identity changed")
		}
	}
	snapshot := mtuRetestSnapshot{SessionID: session.ID, SelectedID: selected.ID, ProfileToken: mtuProfileSnapshotToken(exit),
		StateToken: mtuStateSnapshotToken(st), Profile: exit, State: st, Mode: graph.ExitMode, Multihop: path, persistence: &mtuMeasurementPersistence{}}
	encoded, _ := json.Marshal([]any{snapshot.SessionID, graph, selected.ID, path.ControlToken, path.EntryToken, snapshot.ProfileToken,
		owner.network, owner.launch.mtuSession, owner.launch.configSHA256, path.PhysicalEntry, path.RelayToken})
	digest := sha256.Sum256(encoded)
	path.Token = hex.EncodeToString(digest[:])
	if err := validateMTURetestSnapshot(a, snapshot); err != nil {
		return mtuRetestSnapshot{}, err
	}
	return snapshot, nil
}

func validateMTUMultihopSource(a *app, snapshot mtuRetestSnapshot) error {
	path := snapshot.Multihop
	if path == nil {
		return nil
	}
	current, err := capturedNativeMultihopRuntime(a, path.Command, path.Graph)
	if err != nil || current == nil || current != path.Native || path.PhysicalEntry != current.launch.endpoint {
		return errors.New("MTU multihop source or native interface owner changed")
	}
	if path.Relay != nil {
		if raw, found := desktopRelays.Load(a); !found || raw != path.Relay {
			return errors.New("MTU server lease was replaced")
		}
		path.Relay.mu.Lock()
		valid := path.Relay.renewed && path.Relay.expected.ExpiresAt.After(time.Now()) && path.Relay.command == path.Command && mtuRelayIdentityToken(path.Relay.expected) == path.RelayToken
		path.Relay.mu.Unlock()
		if !valid {
			return errors.New("MTU server lease is no longer current")
		}
	}
	return nil
}

// Caller holds app.mu; no helper may reenter app/session locking here.
func validateMTUMultihopLocked(a *app, snapshot mtuRetestSnapshot) error {
	path := snapshot.Multihop
	if path == nil {
		return nil
	}
	graph, ok := getActiveMultihopGraph(a)
	if !ok || !sameMTUMultihopGraph(graph, path.Graph) || a.cmd != path.Command || a.profiles.SelectedID != snapshot.SelectedID {
		return errors.New("captured multihop execution or runtime changed during MTU Retest")
	}
	control, c := a.profileByIDLocked(snapshot.SelectedID)
	entry, e := a.profileByIDLocked(path.Entry.ID)
	exit, x := a.profileByIDLocked(snapshot.Profile.ID)
	if !c || !e || !x || mtuProfileSnapshotToken(control) != path.ControlToken || mtuProfileSnapshotToken(entry) != path.EntryToken ||
		mtuProfileSnapshotToken(exit) != snapshot.ProfileToken || !strings.EqualFold(strings.TrimSpace(exit.MTUPolicy), "auto") {
		return errors.New("multihop control, entry or exit policy changed during MTU Retest")
	}
	if raw, found := nativeMultihopOwners.Load(a); !found || raw != path.Native {
		return errors.New("retained multihop graph owner was replaced")
	}
	if raw, found := desktopNodeOwners.Load(a); !found || raw != path.Native.launch {
		return errors.New("retained multihop system TUN was replaced")
	}
	return nil
}

func mtuRelayIdentityToken(lease multihoprelay.Lease) string {
	// A renewal may extend expiry, never change the authenticated listener,
	// selected exit, session, transport, layer or credentials.
	lease.ExpiresAt = time.Time{}
	encoded, _ := json.Marshal(lease)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func mtuMeasurementFieldsDigest(p common.RouterProfile) string {
	values := []any{p.EffectiveMTU, p.EffectiveMTUSource, p.EffectiveMTUPathKey, p.EffectiveUnderlayPMTU,
		p.EffectiveMTUNetworkFingerprint, p.EffectiveMTUProfileFingerprint, p.EffectiveMTUTestedAt,
		p.EffectiveMTUMbps, p.EffectiveMTUMedianRTTMs, p.EffectiveMTUSuccessRatio}
	raw, _ := json.Marshal(values)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
