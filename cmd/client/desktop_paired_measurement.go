package main

import (
	"context"
	"errors"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
)

// The native implementation captures its original utun reader and measurement
// epoch. Current performs the full retained parent/process/PF/TUN observation.
// Identity and MatchesOriginal must be pure, nonblocking and safe while the
// tracker and application locks are held; neither may enter a native gate.
type desktopMacOSPairedNodeMeasurement interface {
	Identity() desktopMacOSPairedNodeMeasurementIdentity
	Current(context.Context) error
	MatchesOriginal() bool
	HTTPClient(context.Context, time.Duration) (*http.Client, error)
}

type desktopMacOSPairedNodeMeasurementIdentity struct {
	launch                                                                  *desktopNodeLaunch
	host                                                                    desktopMacOSPairedNodeRuntime
	command                                                                 *exec.Cmd
	profileID, mode, nodeID, session, source, config, network, profileToken string
}

type desktopPairedMeasurementContextKey struct{}

type desktopPairedMeasurementBinding struct {
	owner        *app
	measurement  desktopMacOSPairedNodeMeasurement
	identity     desktopMacOSPairedNodeMeasurementIdentity
	stateToken   string
	profileToken string
}

func (i desktopMacOSPairedNodeMeasurementIdentity) valid() bool {
	l := i.launch
	return l != nil && i.host != nil && i.command != nil && l.pairedNode == i.host && l.command == i.command &&
		l.ownedNode == nil && l.external == nil && l.tor == nil && l.chain == nil && l.candidatePrefix == nil &&
		!l.importedEntry && l.importedPlatform == nil && l.importedOpenVPN == nil &&
		i.profileID != "" && i.profileID == l.profileID && i.profileID == l.policyProfileID &&
		i.mode != "" && i.mode == l.mode && common.ValidNodeProofID(i.nodeID) &&
		desktopMTURequestPattern.MatchString(i.session) && i.session == l.mtuSession &&
		desktopMTUPathPattern.MatchString(i.source) && desktopMTUPathPattern.MatchString(i.config) && i.config == l.configSHA256 &&
		i.network != "" && desktopMTUPathPattern.MatchString(i.profileToken)
}

// This check reads only the existing controller/registry. An absent or damaged
// required Darwin owner cannot turn a routed observation into a legacy probe.
// The caller holds app.mu and supplies the exact saved profile being observed.
func desktopPairedMeasurementRequiredLocked(a *app, p common.RouterProfile, st state) bool {
	if raw, found := desktopNodeOwners.Load(a); found {
		if launch, ok := raw.(*desktopNodeLaunch); ok && launch != nil && launch.pairedNode != nil {
			return true
		}
	}
	mode := strings.TrimSpace(st.RuntimeMode)
	if mode == "" {
		mode = strings.TrimSpace(st.Mode)
	}
	if st.Mode == "multihop" || st.Mode == "external-node" || p.External != nil || p.NodeKind != "" && p.NodeKind != "router-vpn" ||
		!mobilemultihop.DesktopLinuxNodePhysicalGraphSupported(mode, p.StartLayer) {
		return false
	}
	if runtime.GOOS == "darwin" {
		return true
	}
	if a.localController != nil {
		_, originalDarwin := a.localController.nodeParent.(*desktopMacOSParent)
		return originalDarwin
	}
	return false
}

func captureDesktopPairedMeasurement(ctx context.Context, a *app, p common.RouterProfile, st state) (*desktopPairedMeasurementBinding, error) {
	if ctx == nil || a == nil {
		return nil, errors.New("paired Router measurement requires its original caller and application")
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return nil, err
	}
	required := desktopPairedMeasurementRequiredLocked(a, p, st)
	raw, found := desktopNodeOwners.Load(a)
	launch, typed := raw.(*desktopNodeLaunch)
	var host desktopMacOSPairedNodeRuntime
	if found && typed && launch != nil {
		host = launch.pairedNode
	}
	a.mu.Unlock()
	if !required {
		return nil, ctx.Err()
	}
	if host == nil || launch == nil {
		return nil, errors.New("paired Router measurement lost its required retained native host")
	}
	measurement, err := host.CaptureMeasurement(ctx)
	if err != nil || measurement == nil {
		return nil, errors.Join(err, errors.New("paired Router measurement could not capture its original native path"))
	}
	identity := measurement.Identity()
	if !identity.valid() || identity.host != host || identity.launch != launch || identity.profileID != p.ID || identity.nodeID != p.NodeProofID ||
		identity.profileToken != desktopOwnedNodeProfileToken(p) {
		return nil, errors.New("paired Router measurement substituted another original source")
	}
	b := &desktopPairedMeasurementBinding{owner: a, measurement: measurement, identity: identity,
		stateToken: mtuStateSnapshotToken(st), profileToken: asyncMeasurementProfileToken(p)}
	return b, b.current(ctx)
}

func (b *desktopPairedMeasurementBinding) currentLocked(a *app) error {
	if b == nil {
		return nil
	}
	if a == nil || b.owner != a || b.measurement == nil || !b.identity.valid() || b.measurement.Identity() != b.identity || !b.measurement.MatchesOriginal() {
		return errors.New("paired Router measurement lost its original native capture")
	}
	i := b.identity
	value, found := desktopNodeOwners.Load(a)
	p, saved := a.profileByIDLocked(i.profileID)
	if !found || value != i.launch || !saved || a.closing || a.cmd != i.command || !a.state.Connected || a.state.Phase != "connected" ||
		a.state.RouterID != i.profileID || a.state.RuntimeMode != i.mode || mtuStateSnapshotToken(a.state) != b.stateToken ||
		p.NodeProofID != i.nodeID || desktopOwnedNodeProfileToken(p) != i.profileToken || asyncMeasurementProfileToken(p) != b.profileToken {
		return errors.New("paired Router measurement belongs to a replaced connection or saved policy")
	}
	return nil
}

func (b *desktopPairedMeasurementBinding) current(ctx context.Context) error {
	if b == nil {
		return nil
	}
	if ctx == nil || b.owner == nil || b.measurement == nil {
		return errors.New("paired Router measurement has no bounded original owner")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.measurement.Current(ctx); err != nil {
		return err
	}
	if err := desktopnetwork.LockContext(ctx, &b.owner.mu); err != nil {
		return err
	}
	defer b.owner.mu.Unlock()
	return errors.Join(b.currentLocked(b.owner), ctx.Err())
}

func withDesktopPairedMeasurement(ctx context.Context, b *desktopPairedMeasurementBinding) context.Context {
	if b == nil {
		return ctx
	}
	return context.WithValue(ctx, desktopPairedMeasurementContextKey{}, b)
}

func (b *desktopPairedMeasurementBinding) httpClient(ctx context.Context, timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		return nil, errors.New("paired Router HTTP measurement requires a bounded timeout")
	}
	if err := b.current(ctx); err != nil {
		return nil, err
	}
	client, err := b.measurement.HTTPClient(ctx, timeout)
	if err != nil || client == nil || client.Transport == nil || client.CheckRedirect == nil || client.Timeout <= 0 || client.Timeout > timeout {
		if client != nil {
			client.CloseIdleConnections()
		}
		return nil, errors.Join(err, errors.New("paired Router HTTP measurement has no bounded native transport"))
	}
	if err := b.current(ctx); err != nil {
		client.CloseIdleConnections()
		return nil, err
	}
	return client, nil
}

func newAsyncMeasurementHTTPClientContext(ctx context.Context, st state, timeout time.Duration) (*http.Client, error) {
	if ctx == nil {
		return nil, errors.New("live HTTP measurement has no original caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if raw := ctx.Value(desktopPairedMeasurementContextKey{}); raw != nil {
		b, ok := raw.(*desktopPairedMeasurementBinding)
		if !ok || b == nil || timeout <= 0 || st.Mode == "multihop" || mtuStateSnapshotToken(st) != b.stateToken {
			return nil, errors.New("live HTTP measurement changed its captured paired Router path")
		}
		return b.httpClient(ctx, timeout)
	}
	return newAsyncMeasurementHTTPClient(st, timeout)
}

func newPrivateBenchmarkHTTPClientContext(ctx context.Context, p common.RouterProfile, timeout time.Duration) (*http.Client, error) {
	if ctx == nil {
		return nil, errors.New("private benchmark requires its original caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if raw := ctx.Value(desktopPairedMeasurementContextKey{}); raw != nil {
		b, ok := raw.(*desktopPairedMeasurementBinding)
		if !ok || b == nil || p.ID != b.identity.profileID || p.NodeProofID != b.identity.nodeID || asyncMeasurementProfileToken(p) != b.profileToken {
			return nil, errors.New("private benchmark changed its captured paired Router source")
		}
		return b.httpClient(ctx, timeout)
	}
	return newPrivateBenchmarkHTTPClient(timeout), nil
}

// Return the original native selected-DNS query, explicitly as startup proof.
// It is not a fresh resolver Retest and cannot fall through to an OS lookup.
func proveDesktopPairedNodeDNS(ctx context.Context, a *app, observed observedConnection, runtimeID string, selected dnsSelection) (dnsProofState, bool) {
	result := dnsProofState{Mode: selected.Mode, Host: selected.Host, Status: "failed"}
	if ctx == nil || a == nil {
		result.Reason = "selected paired Router DNS proof has no original caller"
		return result, true
	}
	st := state{Connected: observed.Connected, Phase: observed.Phase, Mode: observed.Mode, LogicalMode: observed.LogicalMode,
		RuntimeMode: observed.RuntimeMode, Base: observed.Base, RouterID: observed.RouterID}
	b, err := captureDesktopPairedMeasurement(ctx, a, observed.Profile, st)
	if err != nil {
		result.Reason = err.Error()
		return result, true
	}
	if b == nil {
		return result, false
	}
	wanted, err := expectedDNSSelection(observed.Profile)
	if err != nil || wanted != selected || runtimeID != b.identity.mode || !observed.Connected || observed.Phase != "connected" {
		result.Reason = "selected paired Router DNS proof changed its original resolver or connection"
		return result, true
	}
	record, err := b.identity.host.Ready(ctx)
	if err != nil || record.SessionID != b.identity.session || record.SourceSHA256 != b.identity.source || record.ConfigSHA256 != b.identity.config {
		result.Reason = "selected paired Router DNS query lost its exact original native readiness"
		return result, true
	}
	if err := b.current(ctx); err != nil {
		result.Reason = err.Error()
		return result, true
	}
	result.Status, result.LatencyMs = "passed", record.DNSMilliseconds
	result.Reason = "the original native selected-DNS query passed before connection; its retained macOS process, PF policy and tunnel remain current"
	return result, true
}
