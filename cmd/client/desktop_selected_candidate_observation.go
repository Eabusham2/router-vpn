package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"router-vpn/internal/mobilemultihop"
)

// Candidate connection handshakes have their own selected-execution capture.
// The ordinary throughput preflight keeps its existing independent admission.
func captureOrderedCandidateContext(ctx context.Context, a *app) (speedLabPathIdentity, string, int, error) {
	raw, _ := nativeMultihopOwners.Load(a)
	owner, _ := raw.(*nativeMultihopRuntime)
	if owner == nil || owner.execution == nil {
		return captureOrderedPerformanceContext(ctx, a)
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	identity, _, err := captureSpeedLabIdentityContext(ctx, a)
	if err != nil || identity.Ordered != owner || !desktopSelectedCandidateSourceAllowed(owner.launch) {
		return identity, "", 0, errors.Join(err, errors.New("selected candidate preflight requires its retained original native owner"))
	}
	publication, ready, _, nodes, err := readDesktopSelectedLatencyCapture(ctx, owner.launch)
	if err != nil {
		return identity, "", 0, err
	}
	token, err := orderedSelectedCandidateCapture(identity, ready, publication.Selected)
	return identity, token, len(nodes), errors.Join(err, ctx.Err())
}

func orderedSelectedCandidateCapture(identity speedLabPathIdentity, ready mobilemultihop.DesktopNodeChainExecutionReadyRecord, selected string) (string, error) {
	bad := errors.New("selected candidate preflight changed its original complete capture")
	if identity.Ordered == nil || !identity.GraphOK || !desktopSelectedCandidateSourceAllowed(identity.Ordered.launch) ||
		ready.Generation == 0 || ready.Reader == 0 || ready.SelectionEpoch == 0 || ready.Identity.SessionID == "" ||
		ready.Progress.Execution != identity.Graph.Execution {
		return "", bad
	}
	capture, nodes, err := decodeDesktopSelectedLatencyCapture(selected)
	if err != nil || capture.Execution != ready.Progress.Execution || capture.SourceSHA256 != ready.Identity.SourceSHA256 ||
		capture.ConfigSHA256 != ready.Identity.ConfigSHA256 || len(nodes) != identity.Graph.ChainNodes {
		return "", bad
	}
	// Refreshing a response duration does not replace a native owner. Source,
	// reader, proof generation, selection epoch and complete member identities
	// remain in this token and must match again at admission and result adoption.
	ready.ObservedAt = 0
	ready.Progress.Prefixes = append([]mobilemultihop.NodeChainPrefixProgress(nil), ready.Progress.Prefixes...)
	for index := range ready.Progress.Prefixes {
		ready.Progress.Prefixes[index].ResponseMS = 0
	}
	raw, err := json.Marshal([]any{"routervpn-selected-packet-candidate-view-v1", ready, selected,
		identity.SessionID, identity.Network, identity.StateToken, identity.Graph})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func captureOrderedSelectedCandidateObservation(ctx context.Context, job *orderedCandidateJob) (*orderedCandidateObservation, error) {
	publication, ready, _, _, err := readDesktopSelectedLatencyCapture(ctx, job.catalog.launch)
	if err != nil {
		return nil, err
	}
	live, err := readDesktopNodeMTUContext(ctx, job.catalog.launch)
	if err != nil || live.Active || live.Failure != "" || live.Reader != ready.Reader || live.MTU != ready.MTU ||
		live.Interface != ready.InterfaceName || live.Index != int(ready.InterfaceIndex) || live.Session != ready.Identity.SessionID || live.Config != ready.PreparationConfigSHA256 {
		return nil, errors.Join(err, errors.New("selected candidate observation changed its original TUN reader"))
	}
	token, err := orderedSelectedCandidateCapture(job.view.identity, ready, publication.Selected)
	if err != nil || token != job.view.capture {
		return nil, errors.Join(err, errors.New("selected candidate observation changed after its catalog capture"))
	}
	return &orderedCandidateObservation{live: live, selected: &ready, selectedCapture: publication.Selected}, nil
}

func (o *orderedCandidateObservation) currentSelected(ctx context.Context, catalog *desktopNodeChainCandidateCatalog) error {
	if o == nil || o.selected == nil || catalog == nil || catalog.selectedPlan == nil {
		return errors.New("selected candidate status has no original observation")
	}
	if err := catalog.pulseCurrent(ctx); err != nil {
		return err
	}
	publication, ready, _, _, err := readDesktopSelectedLatencyCapture(ctx, catalog.launch)
	if err != nil || publication.Selected != o.selectedCapture || !sameDesktopSelectedLatencyReady(*o.selected, ready) {
		return errors.Join(err, errors.New("selected candidate status lost its original selected epoch"))
	}
	live, err := readDesktopNodeMTUContext(ctx, catalog.launch)
	if err != nil || live.Active || live.Failure != "" || live.Session != o.live.Session || live.Config != o.live.Config ||
		live.Path != o.live.Path || live.Reader != o.live.Reader || live.Interface != o.live.Interface || live.Index != o.live.Index || live.MTU != o.live.MTU {
		return errors.Join(err, errors.New("selected candidate status changed its original TUN reader"))
	}
	return catalog.pulseCurrent(ctx)
}
