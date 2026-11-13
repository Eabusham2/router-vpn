package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/mobilemultihop"
)

const viaEntryReceiptLifetime = 120 * time.Second
const viaEntryRequestTimeout = 165 * time.Second
const viaEntryBenchmarkSamples = 50

var viaEntryProbePorts = []int{443, 8388, 10443, 11443, 12443, 13443, 14443, 15443, 51820, 51822}

// A candidate test owns a private userspace entry, never app.cmd, the system
// route table, Home connection state, or the durable direct-latency cache.
type viaEntryLane interface {
	AliveContext(context.Context) bool
	DialContext(context.Context, string, string) (net.Conn, error)
	Close(context.Context) error
}

type viaEntryDependencies struct {
	network func(context.Context) (string, error)
	start   func(context.Context, string, string, common.RouterProfile, map[string][]byte, map[string][]byte, []common.RouterProfile) (viaEntryLane, error)
}

type viaEntryRequest struct {
	RequestID    string   `json:"request_id"`
	EntryID      string   `json:"entry_id"`
	Base         string   `json:"base,omitempty"`
	CandidateIDs []string `json:"candidate_ids"`
	Samples      int      `json:"samples"`
}

type viaEntryCandidateError struct {
	ID    string `json:"id"`
	Error string `json:"error"`
}

type viaEntryReceipt struct {
	Schema     int                      `json:"schema"`
	RequestID  string                   `json:"request_id"`
	EntryID    string                   `json:"entry_id"`
	EntryBase  string                   `json:"entry_base"`
	EntryMode  string                   `json:"entry_mode"`
	Drained    bool                     `json:"drained"`
	MeasuredAt time.Time                `json:"measured_at"`
	ExpiresAt  time.Time                `json:"expires_at"`
	Results    []liveLatencyResult      `json:"results"`
	Errors     []viaEntryCandidateError `json:"errors"`
	FastestID  string                   `json:"fastest_id"`
}

type viaEntryAsset struct{ id, mode, digest string }
type viaEntrySnapshot struct {
	root, network, state, selected string
	entry, base, mode              string
	profiles                       map[string]string
	assets                         []viaEntryAsset
	candidates                     map[string]bool
}

type viaEntryOwner struct {
	id          string
	entry       string
	cancel      context.CancelFunc
	done        chan struct{}
	running     bool
	cancelled   bool
	drained     bool
	lane        viaEntryLane
	snapshot    viaEntrySnapshot
	receipt     *viaEntryReceipt
	network     func(context.Context) (string, error)
	closeMu     sync.Mutex
	ordered     *orderedCandidateJob
	prepared    *orderedCandidatePreparedJob
	preparation *orderedCandidatePreparation // bound at original admission, before HTTP worker handoff
	cleanup     func(context.Context) error
}

type viaEntryControl struct {
	mu                 sync.Mutex
	owner              *viaEntryOwner
	seen               map[string]time.Time
	orderedView        *orderedCandidateView
	preparedView       *orderedCandidatePreparedView
	preparedAdmissions map[string]*orderedCandidatePreparedAdmission
	preparedViews      map[string]*orderedCandidatePreparedAdmission
}

var viaEntryControls sync.Map // map[*app]*viaEntryControl; failed cleanup retains its owner

func viaEntryControlFor(a *app) *viaEntryControl {
	v, _ := viaEntryControls.LoadOrStore(a, &viaEntryControl{seen: map[string]time.Time{}})
	return v.(*viaEntryControl)
}

func validViaEntryRequestID(id string) bool {
	value, err := hex.DecodeString(id)
	return err == nil && len(value) == 16 && id == strings.ToLower(id)
}

func (c *viaEntryControl) pruneNoncesLocked() {
	for token, record := range c.preparedViews {
		if time.Since(record.created) > 5*time.Minute {
			delete(c.preparedViews, token)
		}
	}
	for id, record := range c.preparedAdmissions {
		if time.Since(record.created) > 5*time.Minute && (c.owner == nil || c.owner.id != id) {
			delete(c.preparedAdmissions, id)
		}
	}
	for id, created := range c.seen {
		if time.Since(created) > 5*time.Minute && (c.owner == nil || c.owner.id != id) {
			delete(c.seen, id)
		}
	}
}

func viaEntryJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

func viaEntryDecode(w http.ResponseWriter, r *http.Request, out any) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil || decodeRelayControlJSON(body, out) != nil {
		http.Error(w, "bounded unambiguous JSON is required", http.StatusBadRequest)
		return false
	}
	return true
}

func clearViaEntryAssets(files map[string][]byte) {
	for _, body := range files {
		clear(body)
	}
}

func viaEntryAssetDigest(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	hash := sha256.New()
	for _, name := range names {
		_, _ = fmt.Fprintf(hash, "%s\x00%d\x00", name, len(files[name]))
		_, _ = hash.Write(files[name])
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func viaEntrySourceMode(root, entryID, base string) (string, error) {
	if base == "wg" {
		return "wg", nil
	}
	if base != "awg" {
		return "", errors.New("unsupported captured candidate entry base")
	}
	// modes/multihop.py entry_source chooses the first saved split source in
	// this same order. Preserve that actual raw variant and every AWG option.
	for _, mode := range []string{"awg2-fast", "awg2-strong"} {
		dir, err := nativeGeneratedDir(root, entryID, mode)
		if err != nil {
			return "", err
		}
		info, err := os.Lstat(filepath.Join(dir, "awg-socks.conf"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("captured AWG split source is unsafe")
		}
		return mode, nil
	}
	return "", errors.New("selected AWG entry has no saved split source")
}

func captureViaEntrySnapshot(ctx context.Context, a *app, q viaEntryRequest, network func(context.Context) (string, error)) (viaEntrySnapshot, common.RouterProfile, []common.RouterProfile, map[string][]byte, map[string][]byte, error) {
	var snap viaEntrySnapshot
	var entry common.RouterProfile
	var candidates []common.RouterProfile
	fail := func(err error) (viaEntrySnapshot, common.RouterProfile, []common.RouterProfile, map[string][]byte, map[string][]byte, error) {
		return snap, entry, nil, nil, nil, err
	}
	root, err := filepath.Abs(clientRoot(a))
	if err != nil {
		return fail(err)
	}
	identity, err := network(ctx)
	if err != nil || ctx.Err() != nil || identity == "" {
		return fail(errors.Join(err, ctx.Err(), errors.New("physical network identity is unavailable")))
	}
	snap = viaEntrySnapshot{root: root, profiles: map[string]string{}, candidates: map[string]bool{}, network: identity}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return fail(err)
	}
	if profileSettingsBusy(a.state.Connected, a.state.Phase) {
		a.mu.Unlock()
		return fail(errors.New("disconnect and wait for Home to be idle before testing candidates"))
	}
	snap.state, snap.selected = mtuStateSnapshotToken(a.state), a.profiles.SelectedID
	control, controlOK := a.profileByIDLocked(snap.selected)
	if !controlOK {
		a.mu.Unlock()
		return fail(errors.New("candidate measurement has no captured control profile"))
	}
	snap.profiles[control.ID] = liveMeasurementProfileToken(control)
	for i, id := range append([]string{q.EntryID}, q.CandidateIDs...) {
		p, exists := a.profileByIDLocked(id)
		if !exists || p.External != nil || (p.NodeKind != "" && p.NodeKind != "router-vpn") {
			a.mu.Unlock()
			return fail(errors.New("candidate tests require exact saved Router VPN nodes"))
		}
		snap.profiles[id] = liveMeasurementProfileToken(p)
		p = cloneRouterProfile(p)
		if i == 0 {
			entry = p
		} else {
			candidates = append(candidates, p)
			snap.candidates[id] = true
		}
	}
	a.mu.Unlock()
	requested := q.Base
	if requested == "" {
		requested = "wg"
	}
	snap.entry, snap.base = entry.ID, resolveMultihopEntryBase(control, entry, requested)
	snap.mode, err = viaEntrySourceMode(root, entry.ID, snap.base)
	if err != nil {
		return fail(err)
	}
	files, err := readDesktopNodeAssets(root, entry.ID, snap.mode)
	if err != nil {
		return fail(errors.New("entry has no safe captured base source"))
	}
	var start map[string][]byte
	keep := false
	defer func() {
		if !keep {
			clearViaEntryAssets(files)
			clearViaEntryAssets(start)
		}
	}()
	if _, err := mobilemultihop.NativeBaseSource(snap.mode, files); err != nil {
		return fail(err)
	}
	snap.assets = append(snap.assets, viaEntryAsset{entry.ID, snap.mode, viaEntryAssetDigest(files)})
	if snap.mode != "wg" {
		// Router VPN identity is anchored to the saved standard WG peer even
		// though an AWG handshake uses a separate transport public key.
		identityAssets, err := readDesktopNodeAssets(root, entry.ID, "wg")
		if err != nil {
			return fail(errors.New("AWG entry has no captured standard node identity"))
		}
		base, baseErr := mobilemultihop.NativeBaseSource("wg", identityAssets)
		identity, identityErr := nodeProofIDFromWGConfig(base)
		valid := baseErr == nil && identityErr == nil && identity == entry.NodeProofID
		snap.assets = append(snap.assets, viaEntryAsset{entry.ID, "wg", viaEntryAssetDigest(identityAssets)})
		clearViaEntryAssets(identityAssets)
		if !valid {
			return fail(errors.New("AWG entry node identity differs from its saved standard WG peer"))
		}
	}
	if entry.StartLayer != "" && entry.StartLayer != "off" {
		start, err = readDesktopNodeAssets(root, entry.ID, "shadowsocks")
		if err != nil {
			return fail(errors.New("selected entry Start Layer source is unavailable"))
		}
		snap.assets = append(snap.assets, viaEntryAsset{entry.ID, "shadowsocks", viaEntryAssetDigest(start)})
	}
	for i := range candidates {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		p := &candidates[i]
		host, e := normalizeEndpoint(p.Endpoint)
		if e != nil || host != p.Endpoint {
			return fail(errors.New("candidate endpoint must be its saved normalized address"))
		}
		assets, e := readDesktopNodeAssets(root, p.ID, "wg")
		if e != nil {
			return fail(errors.New("candidate has no safe saved WireGuard identity"))
		}
		base, baseErr := mobilemultihop.NativeBaseSource("wg", assets)
		identity, e := nodeProofIDFromWGConfig(base)
		valid := baseErr == nil && e == nil && identity == p.NodeProofID
		snap.assets = append(snap.assets, viaEntryAsset{p.ID, "wg", viaEntryAssetDigest(assets)})
		clearViaEntryAssets(assets)
		if !valid {
			return fail(errors.New("candidate identity differs from its saved WireGuard peer"))
		}
	}
	if err := snap.validate(ctx, a, network); err != nil {
		return fail(err)
	}
	keep = true
	return snap, entry, candidates, files, start, nil
}

func (s viaEntrySnapshot) validate(ctx context.Context, a *app, network func(context.Context) (string, error)) error {
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	err := validateMeasurementProfilesLocked(a, s.profiles)
	current := !profileSettingsBusy(a.state.Connected, a.state.Phase) && s.state == mtuStateSnapshotToken(a.state) && s.selected == a.profiles.SelectedID
	a.mu.Unlock()
	if err != nil || !current {
		return errors.New("candidate source, Home decision, or physical network changed; retest required")
	}
	identity, err := network(ctx)
	if err != nil || ctx.Err() != nil || identity != s.network {
		return errors.Join(err, ctx.Err(), errors.New("candidate source, Home decision, or physical network changed; retest required"))
	}
	if mode, err := viaEntrySourceMode(s.root, s.entry, s.base); err != nil || mode != s.mode {
		return errors.New("selected entry raw base changed; retest required")
	}
	for _, asset := range s.assets {
		if err := ctx.Err(); err != nil {
			return err
		}
		files, err := readDesktopNodeAssets(s.root, asset.id, asset.mode)
		if err != nil {
			return errors.New("captured candidate source is no longer available")
		}
		matches := viaEntryAssetDigest(files) == asset.digest
		clearViaEntryAssets(files)
		if !matches {
			return errors.New("saved candidate credentials changed; retest required")
		}
	}
	return ctx.Err()
}

func (a *app) viaEntryCandidates(w http.ResponseWriter, r *http.Request) {
	a.viaEntryCandidatesWith(w, r, viaEntryDependencies{network: physicalNetworkIdentityContext, start: startViaEntryNativeLane})
}

func (a *app) viaEntryCandidatesWith(w http.ResponseWriter, r *http.Request, deps viaEntryDependencies) {
	var q viaEntryRequest
	if !viaEntryDecode(w, r, &q) {
		return
	}
	if !validViaEntryRequestID(q.RequestID) || !validProfileID(q.EntryID) || len(q.CandidateIDs) < 1 || len(q.CandidateIDs) > 64 || (q.Samples != 0 && q.Samples != viaEntryBenchmarkSamples) || (q.Base != "" && q.Base != "wg" && q.Base != "awg" && q.Base != "auto") {
		http.Error(w, "invalid candidate request identity, count, or sample bound", http.StatusBadRequest)
		return
	}
	ids := map[string]bool{q.EntryID: true}
	for _, id := range q.CandidateIDs {
		if !validProfileID(id) || ids[id] {
			http.Error(w, "candidate identities must be distinct saved nodes", http.StatusBadRequest)
			return
		}
		ids[id] = true
	}
	if q.Samples == 0 {
		q.Samples = viaEntryBenchmarkSamples
	}
	ctx, cancel := context.WithTimeout(r.Context(), viaEntryRequestTimeout)
	defer cancel()
	if ctx.Err() != nil || deps.network == nil || deps.start == nil {
		http.Error(w, "candidate request has no current captured measurement caller", http.StatusConflict)
		return
	}
	if !a.operationMu.TryLock() {
		http.Error(w, "another connection or candidate transaction is in progress", http.StatusConflict)
		return
	}
	defer a.operationMu.Unlock()
	c := viaEntryControlFor(a)
	releaseAdmission, err := a.lockCandidatePublicationContext(ctx, c)
	if err != nil {
		if errors.Is(err, errControllerClosing) {
			http.Error(w, "candidate request lost its controller or caller", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "candidate request was cancelled before ownership", http.StatusConflict)
		return
	}
	c.pruneNoncesLocked()
	_, repeated := c.seen[q.RequestID]
	if repeated || len(c.seen) >= 1024 || (c.owner != nil && (c.owner.running || !c.owner.drained)) {
		releaseAdmission()
		http.Error(w, "candidate request was cancelled, reused, or still owns pending cleanup", http.StatusConflict)
		return
	}
	owner := &viaEntryOwner{id: q.RequestID, entry: q.EntryID, cancel: cancel, done: make(chan struct{}), running: true, network: deps.network}
	c.owner, c.seen[q.RequestID] = owner, time.Now()
	releaseAdmission()

	receipt, runErr := a.runViaEntryCandidates(ctx, owner, q, deps)
	cleanupErr := cleanupViaEntryOwner(c, owner)
	// Observers may wait for native metadata or app state. They use the
	// measurement caller outside the control lock, so Cancel can retire its
	// exact owner while revalidation is in flight.
	if runErr == nil && cleanupErr == nil {
		runErr = owner.snapshot.validate(ctx, a, deps.network)
	}
	c.mu.Lock()
	if runErr == nil && cleanupErr == nil && c.owner == owner && !owner.cancelled && ctx.Err() == nil {
		// Cleanup is part of the measurement boundary. A result becomes selectable
		// only after every socket and the exact temporary process have retired.
		receipt.Drained = true
		receipt.ExpiresAt = time.Now().UTC().Add(viaEntryReceiptLifetime)
		owner.receipt = &receipt
	} else if runErr == nil {
		runErr = errors.New("candidate test was cancelled or its cleanup is pending")
	}
	owner.running = false
	close(owner.done)
	accepted := owner.receipt != nil
	c.mu.Unlock()
	if cleanupErr != nil {
		http.Error(w, "candidate cleanup has not completed; Cancel must finish the owned session before another operation", http.StatusServiceUnavailable)
		return
	}
	if !accepted {
		if runErr == nil {
			runErr = errors.New("candidate measurement did not produce a current receipt")
		}
		http.Error(w, runErr.Error(), http.StatusConflict)
		return
	}
	viaEntryJSON(w, receipt)
}

func (a *app) runViaEntryCandidates(ctx context.Context, owner *viaEntryOwner, q viaEntryRequest, deps viaEntryDependencies) (viaEntryReceipt, error) {
	receipt := viaEntryReceipt{Schema: 1, RequestID: q.RequestID, EntryID: q.EntryID, Results: []liveLatencyResult{}, Errors: []viaEntryCandidateError{}}
	snap, entry, candidates, files, start, err := captureViaEntrySnapshot(ctx, a, q, deps.network)
	if err != nil {
		return receipt, err
	}
	defer clearViaEntryAssets(files)
	defer clearViaEntryAssets(start)
	owner.snapshot = snap // cancellation only reads snapshots after done closes
	receipt.EntryBase, receipt.EntryMode = snap.base, snap.mode
	path, stop, err := speedLabPathContextWithCaller(ctx, func(caller context.Context) error { return snap.validate(caller, a, deps.network) })
	if err != nil {
		return receipt, err
	}
	defer stop()
	lane, err := deps.start(path, snap.root, snap.mode, entry, files, start, candidates)
	owner.lane = lane // even a failed launch transfers any retained cleanup owner
	if err != nil {
		return receipt, errors.New("captured entry proof lane could not start")
	}
	if lane == nil || !lane.AliveContext(path) {
		return receipt, errors.New("captured entry proof lane is unavailable")
	}
	if err = proveViaEntryLane(path, lane, entry); err != nil {
		return receipt, err
	}
	// Bounded parallelism prevents a list of unreachable candidates from
	// outliving the owned transaction. Each result still uses fresh TCP handshakes.
	type outcome struct {
		value liveLatencyResult
		err   error
	}
	outcomes := make([]outcome, len(candidates))
	work := make(chan int)
	var workers sync.WaitGroup
	for n := 0; n < 4; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range work {
				outcomes[i].value, outcomes[i].err = measureViaEntryCandidate(path, lane, candidates[i], q.Samples)
			}
		}()
	}
dispatch:
	for i := range candidates {
		select {
		case work <- i:
		case <-path.Done():
			break dispatch
		}
	}
	close(work)
	workers.Wait()
	if err := context.Cause(path); err != nil {
		return receipt, errors.New("candidate measurement was cancelled or its captured path changed")
	}
	if err := proveViaEntryLane(path, lane, entry); err != nil {
		return receipt, err
	}
	for i, outcome := range outcomes {
		if outcome.err != nil {
			receipt.Errors = append(receipt.Errors, viaEntryCandidateError{ID: candidates[i].ID, Error: "unavailable routed TCP response through selected entry"})
			continue
		}
		receipt.Results = append(receipt.Results, outcome.value)
	}
	receipt.FastestID = fastestViaEntryCandidate(receipt.Results)
	receipt.MeasuredAt = time.Now().UTC()
	return receipt, snap.validate(ctx, a, deps.network)
}

func eligibleViaEntryResult(value liveLatencyResult) bool {
	if value.Samples != viaEntryBenchmarkSamples || value.Failed != 0 {
		return false
	}
	for _, number := range []float64{value.MinMs, value.MedianMs, value.TrimmedMs, value.AverageMs, value.P90Ms, value.MaxMs} {
		if math.IsNaN(number) || math.IsInf(number, 0) || number <= 0 || number > 60000 {
			return false
		}
	}
	return value.MinMs <= value.MedianMs && value.MedianMs <= value.P90Ms && value.P90Ms <= value.MaxMs &&
		value.MinMs <= value.TrimmedMs && value.TrimmedMs <= value.MaxMs &&
		value.MinMs <= value.AverageMs && value.AverageMs <= value.MaxMs
}

func fastestViaEntryCandidate(values []liveLatencyResult) string {
	winner, score := "", math.Inf(1)
	for _, value := range values {
		if eligibleViaEntryResult(value) && (value.TrimmedMs < score || (value.TrimmedMs == score && (winner == "" || value.ID < winner))) {
			winner, score = value.ID, value.TrimmedMs
		}
	}
	return winner
}

var errViaEntryMeasurementClock = errors.New("captured entry measurement clock failed")

func measureViaEntryCandidate(ctx context.Context, lane viaEntryLane, p common.RouterProfile, samples int) (liveLatencyResult, error) {
	return measureViaEntryCandidateWithClock(ctx, lane, p, samples, startClientMeasurementInterval)
}

func measureViaEntryCandidateWithClock(ctx context.Context, lane viaEntryLane, p common.RouterProfile, samples int, startClock clientMeasurementClock) (liveLatencyResult, error) {
	port := 0
	dial := func(port int, timeout time.Duration) (float64, error) {
		if ctx.Err() != nil || !lane.AliveContext(ctx) {
			return 0, errors.Join(context.Cause(ctx), errors.New("captured entry is no longer alive"))
		}
		request, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		interval, err := startClock()
		if err != nil {
			return 0, errors.Join(errViaEntryMeasurementClock, err)
		}
		conn, err := lane.DialContext(request, "tcp", net.JoinHostPort(p.Endpoint, strconv.Itoa(port)))
		var elapsed float64
		var clockErr error
		if err == nil && conn != nil {
			elapsed, clockErr = clientMeasurementMilliseconds(request, interval)
		}
		if conn != nil {
			_ = conn.Close()
		}
		if clockErr != nil {
			return 0, errors.Join(errViaEntryMeasurementClock, clockErr)
		}
		if err != nil || conn == nil || request.Err() != nil || !lane.AliveContext(request) {
			return 0, errors.Join(err, context.Cause(request), errors.New("routed TCP handshake did not complete"))
		}
		return elapsed, nil
	}
	for _, candidate := range viaEntryProbePorts {
		if _, err := dial(candidate, 450*time.Millisecond); err == nil {
			port = candidate
			break
		} else if errors.Is(err, errViaEntryMeasurementClock) {
			return liveLatencyResult{}, err
		}
		if ctx.Err() != nil {
			return liveLatencyResult{}, ctx.Err()
		}
	}
	if port == 0 {
		return liveLatencyResult{}, errors.New("no routed response port")
	}
	values := make([]float64, 0, samples)
	failed := 0
	for i := 0; i < samples; i++ {
		value, err := dial(port, 900*time.Millisecond)
		if errors.Is(err, errViaEntryMeasurementClock) {
			return liveLatencyResult{}, err
		}
		if err != nil {
			failed++
		} else {
			values = append(values, value)
		}
		if i+1 < samples {
			select {
			case <-ctx.Done():
				return liveLatencyResult{}, ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	if ctx.Err() != nil || !lane.AliveContext(ctx) || len(values) == 0 {
		return liveLatencyResult{}, errors.New("no current routed response samples")
	}
	result := profileLatencySummary(p, port, values, failed)
	result.NodeKind = "router-vpn"
	result.Description = "actual routed TCP handshake responses through captured entry; ranked by 10% trimmed mean, not direct client latency"
	return result, nil
}

func cleanupViaEntryOwner(c *viaEntryControl, owner *viaEntryOwner) error {
	return cleanupViaEntryOwnerContext(context.Background(), c, owner)
}

func cleanupViaEntryOwnerContext(caller context.Context, c *viaEntryControl, owner *viaEntryOwner) error {
	if caller == nil {
		return errors.New("candidate cleanup requires its original caller")
	}
	ctx, cancel := context.WithTimeout(caller, 10*time.Second)
	defer cancel()
	if err := desktopnetwork.LockContext(ctx, &owner.closeMu); err != nil {
		return err
	}
	defer owner.closeMu.Unlock()
	var err error
	if owner.cleanup != nil {
		err = owner.cleanup(ctx)
	} else if owner.lane != nil {
		err = owner.lane.Close(ctx)
	}
	if lockErr := desktopnetwork.LockContext(ctx, &c.mu); lockErr != nil {
		return errors.Join(err, lockErr)
	}
	owner.drained = err == nil
	c.mu.Unlock()
	return errors.Join(err, ctx.Err())
}

func viaEntryControllerClosing(ctx context.Context, a *app) (bool, error) {
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return false, err
	}
	defer a.mu.Unlock()
	return a.controllerClosingLocked(), nil
}

func (a *app) viaEntryCandidatesCancel(w http.ResponseWriter, r *http.Request) {
	var q struct {
		RequestID string `json:"request_id"`
	}
	if !viaEntryDecode(w, r, &q) {
		return
	}
	if !validViaEntryRequestID(q.RequestID) {
		http.Error(w, "invalid candidate request identity", http.StatusBadRequest)
		return
	}
	a.cancelViaEntryCandidate(w, r, q.RequestID, nil)
}

func (a *app) cancelViaEntryCandidate(w http.ResponseWriter, r *http.Request, requestID string, admission *orderedCandidatePreparedAdmission) {
	c := viaEntryControlFor(a)
	if err := desktopnetwork.LockContext(r.Context(), &c.mu); err != nil {
		http.Error(w, "candidate cancellation could not enter its original control", http.StatusRequestTimeout)
		return
	}
	c.pruneNoncesLocked()
	if admission != nil && (c.preparedAdmissions[requestID] != admission || c.owner != nil && c.owner.id == requestID && c.owner.preparation == nil) {
		c.mu.Unlock()
		http.Error(w, "saved cancellation cannot adopt another original purpose", http.StatusConflict)
		return
	}
	if _, exists := c.seen[requestID]; !exists && len(c.seen) >= 1024 {
		c.mu.Unlock()
		http.Error(w, "candidate cancellation history is full; retry shortly", http.StatusTooManyRequests)
		return
	}
	// Remember cancellation even if its start POST has not arrived yet.
	c.seen[requestID] = time.Now()
	owner := c.owner
	if owner != nil && owner.id == requestID {
		owner.cancelled, owner.receipt = true, nil
		owner.cancel()
	} else {
		owner = nil
	}
	c.mu.Unlock()
	if owner != nil {
		select {
		case <-owner.done:
		case <-r.Context().Done():
			if admission != nil {
				viaEntryJSON(w, orderedCandidatePreparedAdmissionCancelResponse(c, owner, requestID, admission, errors.New("original candidate is still draining")))
				return
			}
			http.Error(w, "candidate cancellation is still draining", http.StatusRequestTimeout)
			return
		case <-time.After(15 * time.Second):
			if admission != nil {
				viaEntryJSON(w, orderedCandidatePreparedAdmissionCancelResponse(c, owner, requestID, admission, errors.New("original candidate is still draining")))
				return
			}
			http.Error(w, "candidate cancellation is still draining", http.StatusServiceUnavailable)
			return
		}
		if err := cleanupViaEntryOwner(c, owner); err != nil {
			if admission != nil {
				viaEntryJSON(w, orderedCandidatePreparedAdmissionCancelResponse(c, owner, requestID, admission, err))
				return
			}
			if response := orderedCandidatePreparedCancelResponse(c, owner, err); response != nil {
				viaEntryJSON(w, response)
				return
			}
			http.Error(w, "candidate cleanup is pending; protection and ownership retained", http.StatusServiceUnavailable)
			return
		}
	}
	if admission != nil {
		viaEntryJSON(w, orderedCandidatePreparedAdmissionCancelResponse(c, owner, requestID, admission, nil))
		return
	}
	if response := orderedCandidatePreparedCancelResponse(c, owner, nil); response != nil {
		viaEntryJSON(w, response)
		return
	}
	viaEntryJSON(w, map[string]any{"ok": true, "request_id": requestID, "drained": true})
}

func (a *app) viaEntryCandidatesValidate(w http.ResponseWriter, r *http.Request) {
	var q struct {
		RequestID string `json:"request_id"`
		EntryID   string `json:"entry_id"`
		ExitID    string `json:"exit_id"`
	}
	if !viaEntryDecode(w, r, &q) {
		return
	}
	if !a.operationMu.TryLock() {
		http.Error(w, "candidate selection is stale or another operation is active", http.StatusConflict)
		return
	}
	defer a.operationMu.Unlock()
	c := viaEntryControlFor(a)
	if err := desktopnetwork.LockContext(r.Context(), &c.mu); err != nil {
		http.Error(w, "candidate validation was cancelled before ownership", http.StatusConflict)
		return
	}
	owner := c.owner
	current := func() bool {
		return r.Context().Err() == nil && owner != nil && c.owner == owner && owner.id == q.RequestID && owner.entry == q.EntryID && !owner.running && !owner.cancelled && owner.drained && owner.receipt != nil && time.Now().Before(owner.receipt.ExpiresAt) && owner.snapshot.candidates[q.ExitID]
	}
	if !current() {
		c.mu.Unlock()
		http.Error(w, "candidate receipt is stale; retest before adopting a measured selection", http.StatusConflict)
		return
	}
	receipt := owner.receipt
	c.mu.Unlock()
	closing, err := viaEntryControllerClosing(r.Context(), a)
	if err == nil && !closing {
		err = owner.snapshot.validate(r.Context(), a, owner.network)
	}
	if err != nil || closing {
		http.Error(w, "candidate receipt is stale; retest before adopting a measured selection", http.StatusConflict)
		return
	}
	if err := desktopnetwork.LockContext(r.Context(), &c.mu); err != nil {
		http.Error(w, "candidate validation was cancelled before adoption", http.StatusConflict)
		return
	}
	defer c.mu.Unlock()
	if !current() || owner.receipt != receipt {
		http.Error(w, "candidate receipt is stale; retest before adopting a measured selection", http.StatusConflict)
		return
	}
	measured := false
	for _, value := range owner.receipt.Results {
		if value.ID == q.ExitID && eligibleViaEntryResult(value) {
			measured = true
		}
	}
	viaEntryJSON(w, map[string]any{"ok": true, "request_id": q.RequestID, "entry_id": q.EntryID, "exit_id": q.ExitID, "entry_base": owner.receipt.EntryBase, "entry_mode": owner.receipt.EntryMode, "measured": measured})
}

// Called only after operationMu is acquired. A successful new decision expires
// old receipts; a failed temporary cleanup blocks replacement until Cancel has
// retired that exact owner. These helpers never acquire app.mu before c.mu.
func guardViaEntryDecision(a *app) error {
	return guardViaEntryDecisionContext(context.Background(), a)
}

func guardViaEntryDecisionContext(ctx context.Context, a *app) error {
	c := viaEntryControlFor(a)
	if err := desktopnetwork.LockContext(ctx, &c.mu); err != nil {
		return err
	}
	defer c.mu.Unlock()
	if c.owner != nil {
		if c.owner.running || !c.owner.drained {
			return errors.New("candidate entry cleanup is pending; finish Cancel before another operation")
		}
		c.owner.receipt = nil
		if c.owner.ordered != nil {
			invalidateOrderedCandidateLocked(c.owner, "Another operation retired this candidate receipt; retest.")
		}
	}
	return nil
}

func cancelViaEntryOperation(a *app) {
	_ = cancelViaEntryOperationContext(context.Background(), a)
}

func cancelViaEntryOperationContext(ctx context.Context, a *app) error {
	c := viaEntryControlFor(a)
	if err := desktopnetwork.LockContext(ctx, &c.mu); err != nil {
		return err
	}
	defer c.mu.Unlock()
	if c.owner != nil {
		c.owner.cancelled, c.owner.receipt = true, nil
		c.owner.cancel()
	}
	return ctx.Err()
}

func finishViaEntryCancellation(a *app) error {
	return finishViaEntryCancellationContext(context.Background(), a)
}

func finishViaEntryCancellationContext(ctx context.Context, a *app) error {
	c := viaEntryControlFor(a)
	if err := desktopnetwork.LockContext(ctx, &c.mu); err != nil {
		return err
	}
	owner := c.owner
	c.mu.Unlock()
	if owner == nil {
		return ctx.Err()
	}
	// Disconnect owns operationMu here; the measurement handler has joined all
	// workers and closed done before releasing that same transaction lock.
	return cleanupViaEntryOwnerContext(ctx, c, owner)
}
