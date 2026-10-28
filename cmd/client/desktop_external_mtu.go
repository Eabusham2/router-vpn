package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/mobiletor"
)

// The controller and child use a bounded, single-operation mailbox. Every
// record identifies the exact session, immutable source/config and generation.
// The child removes only the exact consumed inputs; a new request cannot
// replace an in-flight request, cancel another generation or grow a journal.
type desktopMTURequest struct {
	Schema       int               `json:"schema"`
	Session      string            `json:"session_id"`
	SourceSHA256 string            `json:"source_sha256"`
	ConfigSHA256 string            `json:"config_sha256"`
	Generation   uint64            `json:"generation"`
	Request      string            `json:"request_id"`
	Force        bool              `json:"force"`
	Cache        *desktopMTUCached `json:"cache,omitempty"`
	RestoreMTU   int               `json:"restore_mtu,omitempty"`
}
type desktopMTUCached struct {
	PathKey  string `json:"path_key"`
	MTU      int    `json:"mtu"`
	TestedAt int64  `json:"tested_at"`
}
type desktopMTUControl struct {
	Schema       int    `json:"schema"`
	Session      string `json:"session_id"`
	SourceSHA256 string `json:"source_sha256"`
	ConfigSHA256 string `json:"config_sha256"`
	Generation   uint64 `json:"generation"`
	Request      string `json:"request_id"`
	PathKey      string `json:"path_key,omitempty"`
	MTU          int    `json:"mtu,omitempty"`
}
type desktopMTURecord struct {
	Schema          int                                 `json:"schema"`
	Session         string                              `json:"session_id"`
	SourceSHA256    string                              `json:"source_sha256"`
	ConfigSHA256    string                              `json:"config_sha256"`
	Generation      uint64                              `json:"generation"`
	Requested       bool                                `json:"requested"`
	WaitingCommit   bool                                `json:"waiting_commit"`
	PreparedMTU     int                                 `json:"prepared_mtu,omitempty"`
	PreparedPathKey string                              `json:"prepared_path_key,omitempty"`
	RestoredMTU     int                                 `json:"restored_mtu,omitempty"`
	Status          mobilemtu.Status                    `json:"status"`
	MTUReadback     *mobiletor.DesktopBridgeMTUReadback `json:"mtu_readback,omitempty"`
}
type desktopMTUSession struct {
	restoreMTU                                   int
	mu                                           sync.Mutex
	profileID, profileToken, entryID, entryToken string
	generation                                   uint64
	active                                       string
	activeAutomatic                              bool
	cancel                                       context.CancelFunc
	automatic                                    bool
}
type desktopMTUSnapshot struct {
	launch     *desktopNodeLaunch
	session    *desktopMTUSession
	profile    common.RouterProfile
	selected   string
	stateToken string
}

// The caller has already persisted and re-proved the exact retained reader.
// Complete its Auto policy before the operation's final drain: a concurrent
// transition may cancel that drain, but it must not discard the proved result.
func (owner *desktopMTUSession) retainCompletedMTU(ctx context.Context, identifier string, generation uint64) error {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if owner.active != identifier || owner.generation != generation {
		return errors.New("native MTU completion lost its captured operation")
	}
	owner.automatic = true
	owner.activeAutomatic = false
	return nil
}

var desktopMTURequestPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var desktopMTUPathPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Caller holds a.mu after its successful connection persistence transaction.
// Measured fields are excluded, but credentials, entry mode, resolver, layers,
// protection and every saved path choice are captured before any later edit.
func captureDesktopMTUBaselineLocked(a *app, launch *desktopNodeLaunch) {
	identity, err := capturedDesktopMeasurementRuntime(launch)
	if err != nil || a.cmd != launch.command {
		return
	}
	profile, ok := a.profileByIDLocked(identity.node)
	if !ok {
		return
	}
	baseline := &desktopMTUSession{profileID: profile.ID, profileToken: mtuProfileSnapshotToken(profile), entryID: identity.entry}
	if baseline.entryID != "" {
		entry, found := a.profileByIDLocked(baseline.entryID)
		if !found {
			return
		}
		baseline.entryToken = mtuProfileSnapshotToken(entry)
	}
	identity.mu.Lock()
	if prior := *identity.mtu; prior != nil && prior.profileID == "" {
		baseline.restoreMTU, baseline.generation = prior.restoreMTU, prior.generation
		*identity.mtu = nil
	}
	if *identity.mtu == nil {
		*identity.mtu = baseline
	}
	identity.mu.Unlock()
}

func desktopExternalMTULaunch(a *app) *desktopNodeLaunch {
	value, ok := desktopNodeOwners.Load(a)
	if !ok {
		return nil
	}
	launch, ok := value.(*desktopNodeLaunch)
	if !ok || launch == nil || !a.ownsConnectionRuntime(launch.command) {
		return nil
	}
	if _, err := capturedDesktopMeasurementRuntime(launch); err != nil {
		return nil
	}
	return launch
}

func captureDesktopMTUSnapshot(a *app, launch *desktopNodeLaunch) (desktopMTUSnapshot, error) {
	if speedLabTemporaryPersistenceSuppressed(a) {
		return desktopMTUSnapshot{}, errors.New("temporary Speed Lab owns MTU and durable profile state")
	}
	if _, busy := speedLabTemporaryOwners.Load(a); busy {
		return desktopMTUSnapshot{}, errors.New("temporary Speed Lab owns the current native path")
	}
	if _, err := capturedDesktopMeasurementRuntime(launch); err != nil {
		return desktopMTUSnapshot{}, errors.New("active path has no native MTU owner")
	}
	if err := a.desktopMeasurementCurrentProof(launch); err != nil {
		return desktopMTUSnapshot{}, err
	}
	owner := desktopMeasurementMTUSession(launch)
	if owner == nil {
		return desktopMTUSnapshot{}, errors.New("native MTU has no captured saved profile identity")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	profile, ok := a.profileByIDLocked(owner.profileID)
	if !ok || a.cmd != launch.command || !a.state.Connected || a.state.Phase != "connected" || a.state.RouterID != owner.profileID || mtuProfileSnapshotToken(profile) != owner.profileToken {
		return desktopMTUSnapshot{}, errors.New("active native MTU path or saved profile changed")
	}
	if owner.entryID != "" {
		entry, ok := a.profileByIDLocked(owner.entryID)
		if !ok || mtuProfileSnapshotToken(entry) != owner.entryToken {
			return desktopMTUSnapshot{}, errors.New("captured MTU entry credentials or policy changed")
		}
	}
	if strings.ToLower(strings.TrimSpace(profile.MTUPolicy)) != "auto" || profile.JumboTUN {
		return desktopMTUSnapshot{}, errors.New("choose Auto MTU without Jumbo before Retest")
	}
	return desktopMTUSnapshot{launch: launch, session: owner, profile: common.CloneRouterProfile(profile), selected: a.profiles.SelectedID, stateToken: mtuStateSnapshotToken(a.state)}, nil
}
func (s desktopMTUSnapshot) current(a *app) error {
	if err := a.desktopMeasurementCurrentProof(s.launch); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return s.currentLocked(a)
}

func (s desktopMTUSnapshot) currentContext(ctx context.Context, a *app) error {
	if err := a.waitDesktopMeasurementProof(ctx, s.launch); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return s.currentLocked(a)
}
func (s desktopMTUSnapshot) currentLocked(a *app) error {
	if speedLabTemporaryPersistenceSuppressed(a) {
		return errors.New("temporary Speed Lab retired MTU result adoption")
	}
	if _, busy := speedLabTemporaryOwners.Load(a); busy {
		return errors.New("temporary Speed Lab owns this path")
	}
	profile, ok := a.profileByIDLocked(s.session.profileID)
	if a.cmd != s.launch.command || a.profiles.SelectedID != s.selected || mtuStateSnapshotToken(a.state) != s.stateToken || !ok || mtuProfileSnapshotToken(profile) != s.session.profileToken {
		return errors.New("MTU result belongs to a retired connection, selection or profile")
	}
	if s.session.entryID != "" {
		entry, found := a.profileByIDLocked(s.session.entryID)
		if !found || mtuProfileSnapshotToken(entry) != s.session.entryToken {
			return errors.New("MTU entry changed during measurement")
		}
	}
	return nil
}

func readDesktopMTURecord(launch *desktopNodeLaunch) (desktopMTURecord, error) {
	raw, err := readDesktopRuntimeFile(launch, "mtu-status.json", 64<<10)
	if err != nil {
		return desktopMTURecord{}, err
	}
	if _, err := applexray.Object(raw); err != nil {
		return desktopMTURecord{}, errors.New("native MTU record is malformed")
	}
	var record desktopMTURecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil {
		return record, errors.New("native MTU record has unrecognized fields")
	}
	identity, identityErr := capturedDesktopMeasurementRuntime(launch)
	if identityErr != nil || record.Schema != 1 || record.Session != identity.session || record.SourceSHA256 != identity.source || record.ConfigSHA256 != identity.config {
		return record, errors.New("native MTU record belongs to another session or graph")
	}
	if err := validateDesktopMTURecordForSource(record, identity.measuredSource); err != nil {
		return record, err
	}
	if err := validateDesktopTorMTURecord(launch, record); err != nil {
		return record, err
	}
	return record, nil
}

func desktopMTUFinite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}
func desktopMTUTransfer(value *hopmeasure.Transfer) bool {
	if value == nil || value.Bytes != 256<<10 || !desktopMTUFinite(value.Seconds) || value.Seconds <= 0 || !desktopMTUFinite(value.Mbps) || value.Mbps <= 0 {
		return false
	}
	expected := float64(value.Bytes) * 8 / value.Seconds / 1e6
	return math.Abs(expected-value.Mbps) <= math.Max(1e-6, expected*1e-6)
}
func validateDesktopMTURecord(record desktopMTURecord) error {
	return validateDesktopMTURecordForSource(record, "measured-public-system-tun-transfer")
}

func validateDesktopMTURecordForSource(record desktopMTURecord, measuredSource string) error {
	status := record.Status
	bad := errors.New("native MTU status has invalid or mislabeled measurement evidence")
	if len(status.Candidates) > 32 || status.Running && status.Complete || len(status.Request) != 0 && !desktopMTURequestPattern.MatchString(status.Request) {
		return bad
	}
	if status.OriginalMTU != 0 && (status.OriginalMTU < 1280 || status.OriginalMTU > 9000) || status.EffectiveMTU != 0 && (status.EffectiveMTU < 1280 || status.EffectiveMTU > 9000) {
		return bad
	}
	eligible := map[int]bool{}
	for _, candidate := range status.Candidates {
		if candidate.MTU < 1280 || candidate.MTU > 9000 || !desktopMTUFinite(candidate.MedianRTT) {
			return bad
		}
		if candidate.Working {
			if candidate.LatencyKind != "https-response" || candidate.PacketsSent != 0 || candidate.PacketsReceived != 0 || candidate.DatagramBytes != 0 || !desktopMTUTransfer(candidate.Download) || !desktopMTUTransfer(candidate.Upload) || candidate.Failure != "" {
				return bad
			}
			eligible[candidate.MTU] = true
		}
	}
	if record.WaitingCommit && (!status.Running || status.Complete || status.OriginalMTU == 0 || !eligible[record.PreparedMTU] || !desktopMTUPathPattern.MatchString(record.PreparedPathKey) || record.PreparedPathKey != status.PathKey) {
		return bad
	}
	if !record.WaitingCommit && (record.PreparedMTU != 0 || record.PreparedPathKey != "") {
		return bad
	}
	if status.Measured && (!status.Complete || status.Running || status.Restored || status.Source != measuredSource || !eligible[status.EffectiveMTU] || !desktopMTUPathPattern.MatchString(status.PathKey) || status.Failure != "") {
		return bad
	}
	if status.Restored {
		if status.Running || !status.Complete || status.Measured {
			return bad
		}
		if status.Source == "restored-captured-system-tun" {
			if record.RestoredMTU < 1280 || record.RestoredMTU > 9000 || status.EffectiveMTU != record.RestoredMTU || !eligible[record.RestoredMTU] || status.Failure != "" {
				return bad
			}
		} else if status.Source != "restored-unmeasured" || status.EffectiveMTU != status.OriginalMTU {
			return bad
		}
	}
	return nil
}

func writeDesktopMTUControl(launch *desktopNodeLaunch, name string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > 4096 {
		return errors.New("invalid native MTU command")
	}
	if name == "mtu-request.json" && launch != nil && launch.tor != nil {
		request, ok := value.(desktopMTURequest)
		if !ok {
			return errors.New("Tor MTU request has no typed captured identity")
		}
		if err := authorizeDesktopTorMTURequest(launch, request); err != nil {
			return err
		}
	}
	writeErr := writeDesktopRuntimeFile(launch, name, encoded, true)
	if writeErr == nil {
		return nil
	}
	// The child may consume a complete input before the parent's final file
	// identity read. Accept that race only with its exact, validated native
	// acknowledgement; never retry by overwriting another input or directory.
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		record, err := readDesktopMTURecord(launch)
		if err == nil {
			accepted := false
			switch command := value.(type) {
			case desktopMTURequest:
				accepted = name == "mtu-request.json" && record.Schema == command.Schema && record.Session == command.Session && record.SourceSHA256 == command.SourceSHA256 && record.ConfigSHA256 == command.ConfigSHA256 && record.Generation == command.Generation && record.Status.Request == command.Request
			case desktopMTUControl:
				if record.Schema == command.Schema && record.Session == command.Session && record.SourceSHA256 == command.SourceSHA256 && record.ConfigSHA256 == command.ConfigSHA256 && record.Generation == command.Generation && record.Status.Request == command.Request && record.Status.Complete && !record.Status.Running {
					if name == "mtu-commit.json" {
						accepted = record.Status.Measured && record.Status.EffectiveMTU == command.MTU && record.Status.PathKey == command.PathKey
					} else if name == "mtu-cancel.json" {
						accepted = !record.Status.Measured && record.Status.Source != "restored-captured-system-tun" && record.Status.EffectiveMTU > 0 && record.Status.EffectiveMTU == record.Status.OriginalMTU
					}
				}
			}
			if accepted {
				return nil
			}
		}
		if desktopExternalDirectoryCurrent(launch) != nil {
			return writeErr
		}
		select {
		case <-deadline.C:
			return writeErr
		case <-ticker.C:
		}
	}
}

func desktopMTUControlFor(request desktopMTURequest) desktopMTUControl {
	return desktopMTUControl{Schema: 1, Session: request.Session, SourceSHA256: request.SourceSHA256, ConfigSHA256: request.ConfigSHA256, Generation: request.Generation, Request: request.Request}
}

func (a *app) runDesktopExternalMTU(parent context.Context, launch *desktopNodeLaunch, force bool) (result desktopMTURecord, failure error) {
	snapshot, err := captureDesktopMTUSnapshot(a, launch)
	if err != nil {
		return result, err
	}
	budget := mtuRetestTimeout
	if launch.tor != nil {
		budget = 5 * time.Minute // Shared Tor optimizer is bounded to four minutes.
	}
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	identifier, err := randomHex(16)
	if err != nil {
		return result, err
	}
	if operation := mtuViewOperationFrom(parent); operation != nil {
		identifier = operation.request
	}
	updateMTUViewPhase(ctx, "waiting-native-mtu", 0)
	initial, err := a.waitDesktopMTUIdle(ctx, launch)
	if err != nil {
		return result, err
	}
	snapshot.session.mu.Lock()
	if snapshot.session.active != "" {
		snapshot.session.mu.Unlock()
		return result, errors.New("native MTU operation is already active")
	}
	snapshot.session.generation = initial.Generation + 1
	generation := snapshot.session.generation
	snapshot.session.active, snapshot.session.cancel = identifier, cancel
	snapshot.session.activeAutomatic = !force
	snapshot.session.mu.Unlock()
	defer func() {
		snapshot.session.mu.Lock()
		if snapshot.session.active == identifier {
			snapshot.session.active, snapshot.session.cancel = "", nil
			snapshot.session.activeAutomatic = false
		}
		snapshot.session.mu.Unlock()
	}()
	identity, err := capturedDesktopMeasurementRuntime(launch)
	if err != nil {
		return result, err
	}
	request := desktopMTURequest{Schema: 1, Session: identity.session, SourceSHA256: identity.source, ConfigSHA256: identity.config, Generation: generation, Request: identifier, Force: force}
	if tested, e := time.Parse(time.RFC3339Nano, snapshot.profile.EffectiveMTUTestedAt); e == nil && len(snapshot.profile.EffectiveMTUPathKey) == 64 && snapshot.profile.EffectiveMTU >= 1280 && snapshot.profile.EffectiveMTU <= 9000 {
		request.Cache = &desktopMTUCached{PathKey: snapshot.profile.EffectiveMTUPathKey, MTU: snapshot.profile.EffectiveMTU, TestedAt: tested.Unix()}
	}
	if err := snapshot.currentContext(ctx, a); err != nil {
		return result, err
	}
	if err := writeDesktopMTUControl(launch, "mtu-request.json", request); err != nil {
		return result, err
	}
	updateMTUViewPhase(ctx, "measuring", initial.Status.EffectiveMTU)
	var written *common.RouterProfile
	adopted := false
	defer func() {
		if adopted {
			return
		}
		rollbackErr := a.cancelDesktopMTU(launch, desktopMTUControlFor(request))
		if written != nil {
			rollbackErr = errors.Join(rollbackErr, restoreDesktopMTUDurable(a, snapshot, *written))
		}
		if rollbackErr != nil {
			failure = errors.Join(failure, rollbackErr)
		}
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if err := snapshot.currentContext(ctx, a); err != nil {
			return result, err
		}
		record, err := readDesktopMTURecord(launch)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return result, err
		}
		if err == nil && record.Generation == generation && record.Status.Request == identifier {
			result = record
			if record.WaitingCommit && written == nil {
				updateMTUViewPhase(ctx, "saving", 0)
				if !a.operationMu.TryLock() {
					return result, errors.New("connection transition started before MTU adoption")
				}
				if err := snapshot.verifyCurrentPath(ctx, a); err != nil {
					a.operationMu.Unlock()
					return result, err
				}
				if err := a.waitDesktopTorMTUReadback(ctx, launch, record); err != nil {
					a.operationMu.Unlock()
					return result, err
				}
				updated, err := persistDesktopMTU(a, snapshot, record)
				if err == nil {
					written = &updated
				}
				if err == nil {
					err = snapshot.verifyCurrentPath(ctx, a)
				}
				if err == nil && ctx.Err() == nil {
					commit := desktopMTUControlFor(request)
					commit.MTU, commit.PathKey = record.PreparedMTU, record.PreparedPathKey
					err = writeDesktopMTUControl(launch, "mtu-commit.json", commit)
				}
				a.operationMu.Unlock()
				if err != nil {
					return result, err
				}
			}
			if record.Status.Complete && !record.Status.Running {
				updateMTUViewPhase(ctx, "verifying", 0)
				if !record.Status.Measured || written == nil || record.Status.EffectiveMTU != written.EffectiveMTU || record.Status.PathKey != written.EffectiveMTUPathKey {
					return result, errors.New("native MTU did not adopt a freshly verified result")
				}
				if err := snapshot.verifyCurrentPath(ctx, a); err != nil {
					return result, err
				}
				if err := a.waitDesktopTorMTUReadback(ctx, launch, record); err != nil {
					return result, err
				}
				// A successful explicit Retest has also satisfied this connection's
				// initial Auto comparison. DNS/Speed Lab hold release must retain
				// its proved reader instead of launching a second Auto operation.
				// Failed or cancelled attempts never reach this adoption boundary.
				if err := snapshot.session.retainCompletedMTU(ctx, identifier, generation); err != nil {
					return result, err
				}
				adopted = true
				return result, nil
			}
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (a *app) cancelDesktopMTU(launch *desktopNodeLaunch, control desktopMTUControl) error {
	if err := writeDesktopMTUControl(launch, "mtu-cancel.json", control); err != nil {
		return err
	}
	drainBudget := 12 * time.Second
	if launch != nil && launch.tor != nil {
		drainBudget = 40 * time.Second // Native Tor rollback owns up to 30s.
	}
	deadline := time.NewTimer(drainBudget)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		record, err := readDesktopMTURecord(launch)
		if err == nil && record.Generation == control.Generation && record.Status.Request == control.Request && record.Status.Complete && !record.Status.Running && !record.Status.Measured && record.Status.Source != "restored-captured-system-tun" {
			if record.Status.EffectiveMTU > 0 && record.Status.OriginalMTU == record.Status.EffectiveMTU {
				return a.waitDesktopTorMTUReadback(context.Background(), launch, record)
			}
			return errors.New("native MTU canceled, but exact interface rollback could not be verified")
		}
		if !a.ownsConnectionRuntime(launch.command) {
			return errors.New("MTU session retired; no replacement interface was touched")
		}
		if desktopMeasurementProcessExited(launch) {
			return errors.New("native MTU process exited before rollback acknowledgement")
		}
		select {
		case <-deadline.C:
			return errors.New("native MTU rollback is still pending")
		case <-ticker.C:
		}
	}
}

func persistDesktopMTU(a *app, snapshot desktopMTUSnapshot, record desktopMTURecord) (common.RouterProfile, error) {
	identity, err := capturedDesktopMeasurementRuntime(snapshot.launch)
	if err != nil || !record.WaitingCommit || validateDesktopMTURecordForSource(record, identity.measuredSource) != nil {
		return common.RouterProfile{}, errors.New("MTU winner has no fresh transfer evidence")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := snapshot.currentLocked(a); err != nil {
		return common.RouterProfile{}, err
	}
	for i := range a.profiles.Profiles {
		current := &a.profiles.Profiles[i]
		if current.ID != snapshot.session.profileID {
			continue
		}
		before := common.CloneRouterProfile(*current)
		current.EffectiveMTU, current.EffectiveMTUSource = record.PreparedMTU, identity.measuredSource
		current.EffectiveMTUPathKey, current.EffectiveMTUNetworkFingerprint, current.EffectiveMTUProfileFingerprint = record.PreparedPathKey, identity.network, snapshot.session.profileToken
		current.EffectiveMTUTestedAt = time.Now().UTC().Format(time.RFC3339Nano)
		current.EffectiveUnderlayPMTU, current.EffectiveMTUSuccessRatio = 0, 0 // No authenticated UDP PMTU/loss claim for a public transfer.
		for _, candidate := range record.Status.Candidates {
			if candidate.MTU == record.PreparedMTU && candidate.Working {
				current.EffectiveMTUMbps = math.Min(candidate.Download.Mbps, candidate.Upload.Mbps)
				current.EffectiveMTUMedianRTTMs = candidate.MedianRTT
			}
		}
		if err := a.persistProfilesLocked(); err != nil {
			*current = before
			return common.RouterProfile{}, err
		}
		return common.CloneRouterProfile(*current), nil
	}
	return common.RouterProfile{}, errors.New("captured MTU profile disappeared")
}
func restoreDesktopMTUDurable(a *app, snapshot desktopMTUSnapshot, written common.RouterProfile) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.profiles.Profiles {
		current := &a.profiles.Profiles[i]
		if current.ID != snapshot.session.profileID {
			continue
		}
		if mtuProfileSnapshotToken(*current) != snapshot.session.profileToken || current.EffectiveMTUTestedAt != written.EffectiveMTUTestedAt || current.EffectiveMTUPathKey != written.EffectiveMTUPathKey || current.EffectiveMTU != written.EffectiveMTU {
			return errors.New("newer MTU profile state retained during canceled result rollback")
		}
		old := snapshot.profile
		current.EffectiveMTU, current.EffectiveMTUSource, current.EffectiveMTUPathKey = old.EffectiveMTU, old.EffectiveMTUSource, old.EffectiveMTUPathKey
		current.EffectiveMTUNetworkFingerprint, current.EffectiveMTUProfileFingerprint, current.EffectiveMTUTestedAt = old.EffectiveMTUNetworkFingerprint, old.EffectiveMTUProfileFingerprint, old.EffectiveMTUTestedAt
		current.EffectiveMTUMbps, current.EffectiveMTUMedianRTTMs, current.EffectiveMTUSuccessRatio, current.EffectiveUnderlayPMTU = old.EffectiveMTUMbps, old.EffectiveMTUMedianRTTMs, old.EffectiveMTUSuccessRatio, old.EffectiveUnderlayPMTU
		return a.persistProfilesLocked()
	}
	return errors.New("captured MTU profile disappeared during rollback")
}

func (a *app) startDesktopExternalAutomaticMTU(launch *desktopNodeLaunch) {
	if _, err := capturedDesktopMeasurementRuntime(launch); err != nil {
		return
	}
	if launch.tor != nil && desktopMeasurementMTUSession(launch) == nil {
		return // The successful Tor connection transaction installs its baseline.
	}
	a.mu.Lock()
	captureDesktopMTUBaselineLocked(a, launch)
	a.mu.Unlock()
	owner := desktopMeasurementMTUSession(launch)
	if owner == nil {
		return
	}
	// Fixed/Jumbo policies and retired captures do not have an automatic
	// optimization to start. Reject them before a background worker can claim
	// operationMu and briefly block the user's next connection transaction.
	if _, err := captureDesktopMTUSnapshot(a, launch); err != nil {
		return
	}
	go func() {
		// Connect still holds operationMu while it publishes the monitor. Do not
		// let a quick first candidate race that original connection transaction.
		ready := time.NewTimer(30 * time.Second)
		defer ready.Stop()
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for !a.operationMu.TryLock() {
			if _, err := captureDesktopMTUSnapshot(a, launch); err != nil {
				return
			}
			select {
			case <-ready.C:
				return
			case <-tick.C:
			}
		}
		a.operationMu.Unlock()
		if _, err := captureDesktopMTUSnapshot(a, launch); err != nil {
			return
		}
		lock := mtuRetestLockFor(a)
		if !lock.TryLock() {
			return
		}
		defer lock.Unlock()
		if mtuSuspended(a) {
			return
		}
		owner.mu.Lock()
		if owner.automatic {
			owner.mu.Unlock()
			return
		}
		owner.automatic = true
		owner.mu.Unlock()
		_, _ = a.runDesktopExternalMTU(context.Background(), launch, false)
	}()
}

// Speed Lab holds this before capturing the previous connection and until all
// measurements and restoration have drained. Automatic/Retest work cannot
// change the interface halfway through a throughput or restoration snapshot.
func (a *app) holdDesktopMTUForMeasurement(ctx context.Context) (func(), error) {
	return a.holdCapturedMTU(ctx)
}

func (a *app) retestDesktopExternalMTU(w http.ResponseWriter, r *http.Request, launch *desktopNodeLaunch) {
	result, err := a.runDesktopExternalMTU(r.Context(), launch, true)
	if err != nil {
		if operation := mtuViewOperationFrom(r.Context()); operation != nil {
			if restored, readErr := readDesktopMTURecord(launch); readErr == nil && restored.Status.Request == operation.request && restored.Status.Restored && restored.Status.Complete {
				operation.mu.Lock()
				operation.status = restored.Status
				operation.mu.Unlock()
			}
		}
		http.Error(w, "Native MTU Retest: "+err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("content-type", "application/json")
	note := "Selected-path HTTPS response and transferred-byte throughput through the owned system TUN; interface MTU readback is separate from an authenticated UDP path-MTU measurement."
	if launch.tor != nil {
		note = "Tor HTTPS response time and transferred-byte download/upload throughput through the captured Tor path, with fresh Tor and selected-DNS proof. The reported MTU is the verified virtual-interface value, not an authenticated UDP path-MTU measurement."
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "effective_mtu": result.Status.EffectiveMTU, "effective_mtu_source": result.Status.Source, "result": result.Status, "note": note})
}
func (a *app) desktopMTUStatus(w http.ResponseWriter, r *http.Request) {
	a.writeDesktopMTUViewStatus(w, r)
}
func (a *app) cancelDesktopMTURoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	request, err := readMTUViewRequest(w, r)
	if err != nil || !desktopMTURequestPattern.MatchString(request.Request) {
		http.Error(w, "a captured MTU request_id is required", http.StatusBadRequest)
		return
	}
	if cancelMTUViewOperation(a, w, request) {
		return
	}
	launch := desktopExternalMTULaunch(a)
	if launch == nil {
		http.Error(w, "native MTU session retired", http.StatusConflict)
		return
	}
	identity, err := capturedDesktopMeasurementRuntime(launch)
	if err != nil || request.Session != "" && request.Session != identity.session || request.Profile != "" && request.Profile != identity.node {
		http.Error(w, "MTU cancellation belongs to another connection", http.StatusConflict)
		return
	}
	owner := desktopMeasurementMTUSession(launch)
	if owner == nil {
		http.Error(w, "native MTU owner is missing", http.StatusConflict)
		return
	}
	owner.mu.Lock()
	matches := owner.active == request.Request && owner.cancel != nil
	if matches {
		owner.cancel()
	}
	owner.mu.Unlock()
	if !matches {
		http.Error(w, "MTU request already ended or was replaced", http.StatusConflict)
		return
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "request_id": request.Request, "phase": "canceling", "note": "Cancellation is pending until the captured native rollback finishes."})
}
