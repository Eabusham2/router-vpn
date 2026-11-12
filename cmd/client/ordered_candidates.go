package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"sync/atomic"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

// A view is a bounded UI selection snapshot, never a successful path proof.
// Its private catalog retains original source bytes; none are sent to the UI.
type orderedCandidateView struct {
	token, capture string
	expires        time.Time
	position       int
	identity       speedLabPathIdentity
	catalog        *desktopNodeChainCandidateCatalog
	candidates     []orderedCandidateChoice
	prefixes       []orderedCandidatePrefix
}
type orderedCandidateChoice struct {
	ID         string                         `json:"id"`
	Name       string                         `json:"name"`
	Kind       string                         `json:"kind"`
	Proposal   []common.MultihopNodeSelection `json:"proposed_path,omitempty"`
	SaveReason string                         `json:"save_reason,omitempty"`
}
type orderedCandidatePrefix struct {
	Position int    `json:"position"`
	ID       string `json:"id"`
	Name     string `json:"name"`
	Mode     string `json:"mode"`
}
type orderedCandidateJob struct {
	view        *orderedCandidateView
	catalog     *desktopNodeChainCandidateCatalog
	results     []hopmeasure.CandidateStatus // immutable values, guarded by control.mu
	failures    []viaEntryCandidateError
	current     string
	failure     string
	pending     error // guarded by owner.closeMu, only accessed after worker joins
	finish      func(bool)
	accepted    bool
	invalidated bool
	lost        atomic.Bool
	observation *orderedCandidateObservation
}
type orderedCandidateRequest struct {
	RequestID      string   `json:"request_id"`
	ViewToken      string   `json:"view_token"`
	PrefixPosition int      `json:"prefix_position"`
	CandidateIDs   []string `json:"candidate_ids"`
	Samples        int      `json:"samples"`
}

func registerOrderedCandidateRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/multihop/prefix-candidates/catalog", a.orderedCandidateCatalog)
	h.HandleFunc("/api/multihop/prefix-candidates", a.orderedCandidates)
	h.HandleFunc("/api/multihop/prefix-candidates/cancel", a.viaEntryCandidatesCancel)
	h.HandleFunc("/api/multihop/prefix-candidates/save-profile", a.saveOrderedCandidateProfile)
}

func (a *app) orderedCandidateCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", 405)
		return
	}
	query := r.URL.Query()
	positions := query["prefix_position"]
	rawPosition := ""
	if len(positions) == 1 {
		rawPosition = positions[0]
	}
	position, err := strconv.Atoi(rawPosition)
	if len(query) != 1 || len(positions) != 1 || err != nil || strconv.Itoa(position) != rawPosition || position < 0 || position > 7 {
		http.Error(w, "choose an exact connected prefix position", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	identity, capture, _, err := captureOrderedPerformanceContext(ctx, a)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	profiles := make([]common.RouterProfile, len(a.profiles.Profiles))
	for i, p := range a.profiles.Profiles {
		profiles[i] = cloneRouterProfile(p)
	}
	a.mu.Unlock()
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		http.Error(w, "candidate view identity unavailable", 500)
		return
	}
	view := &orderedCandidateView{token: hex.EncodeToString(nonce), capture: capture, expires: time.Now().Add(120 * time.Second), position: position, identity: identity}
	members := identity.Ordered.launch.chain.selection.Nodes
	for i, n := range members {
		if mobilemultihop.NodeChainPrefixMode(n.Mode) {
			view.prefixes = append(view.prefixes, orderedCandidatePrefix{i, n.Profile.ID, n.Profile.Name, n.Mode})
		}
	}
	ids := []string{}
	for _, p := range profiles {
		if ctx.Err() != nil {
			break
		}
		// The source compiler, not a protocol label or UI toggle, decides eligibility.
		if _, err := captureDesktopNodeChainCandidateSources(ctx, a, identity.Ordered.launch, position, []string{p.ID}); err != nil {
			continue
		}
		choice := orderedCandidateChoice{ID: p.ID, Name: p.Name, Kind: "router-vpn"}
		if p.External != nil {
			choice.Kind = "external"
		}
		_, proposal, err := orderedCandidateProposal(members, position, p, profiles)
		if err != nil {
			choice.SaveReason = err.Error()
		} else {
			choice.Proposal = proposal
		}
		view.candidates = append(view.candidates, choice)
		ids = append(ids, p.ID)
		if len(ids) == hopmeasure.CandidateMaximumTargets {
			break
		}
	}
	if len(ids) == 0 || ctx.Err() != nil {
		http.Error(w, "no current exact SS2022 candidate sources for this packet prefix", 409)
		return
	}
	view.catalog, err = captureDesktopNodeChainCandidateSources(ctx, a, identity.Ordered.launch, position, ids)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	view.catalog.identity = identity
	if err = view.catalog.pulseCurrent(ctx); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	c := viaEntryControlFor(a)
	if err = desktopnetwork.LockContext(ctx, &c.mu); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	c.orderedView = view
	c.mu.Unlock()
	viaEntryJSON(w, map[string]any{"schema": 1, "view_token": view.token, "expires_at": view.expires.UnixMilli(), "prefix_position": position, "prefixes": view.prefixes, "candidates": view.candidates, "samples": 50, "measurement": "routed-tcp-connect", "note": "50 TCP connection handshakes through the retained connected prefix. This does not authenticate candidate credentials. Saving creates a next-connection profile; it does not change the active path."})
}

// Proposed paths are explicit suffix replacements, never live mutations. The
// shared ordered compiler subsequently validates the complete original sources.
func orderedCandidateProposal(members []desktopNodeChainMember, position int, candidate common.RouterProfile, profiles []common.RouterProfile) (common.RouterProfile, []common.MultihopNodeSelection, error) {
	var control common.RouterProfile
	if position < 0 || position >= len(members) || !mobilemultihop.NodeChainPrefixMode(members[position].Mode) {
		return control, nil, errors.New("candidate requires an original packet prefix")
	}
	nodes := nodeChainSelectedReferences(members[:position+1])
	nodes = append(nodes, common.MultihopNodeSelection{ID: candidate.ID, Mode: "shadowsocks"})
	control = cloneRouterProfile(candidate)
	if candidate.External != nil || candidate.NodeKind == "external" {
		if position != 0 || len(members) < 2 || members[len(members)-1].Profile.External != nil {
			return control, nil, errors.New("custom SS2022 insertion currently requires the first packet prefix and original paired final")
		}
		final := members[len(members)-1]
		nodes = append(nodes, common.MultihopNodeSelection{ID: final.Profile.ID, Mode: final.Mode})
		control = cloneRouterProfile(final.Profile)
	}
	control.MultihopEnabled = true
	control.MultihopExecution = "local"
	control.MultihopNodes = nodes
	control.MultihopEntryID = ""
	control.MultihopExitID = ""
	control.MultihopEntryMode = ""
	proposed := make([]common.RouterProfile, len(profiles))
	copy(proposed, profiles)
	for i := range proposed {
		if proposed[i].ID == control.ID {
			proposed[i] = control
		}
	}
	if _, err := resolveDesktopNodeChainSelection(control, proposed, nodes, "local"); err != nil {
		return control, nil, err
	}
	return control, nodes, nil
}

func (a *app) orderedCandidates(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.orderedCandidateStatus(w, r)
		return
	}
	var q orderedCandidateRequest
	if !viaEntryDecode(w, r, &q) {
		return
	}
	if !validViaEntryRequestID(q.RequestID) || q.ViewToken == "" || q.Samples != 50 || len(q.CandidateIDs) == 0 || len(q.CandidateIDs) > 64 {
		http.Error(w, "exact view, request identity and 50 samples are required", 400)
		return
	}
	seen := map[string]bool{}
	for _, id := range q.CandidateIDs {
		if !validProfileID(id) || seen[id] {
			http.Error(w, "candidate IDs must be distinct saved nodes", 400)
			return
		}
		seen[id] = true
	}
	ctx, cancel := context.WithTimeout(r.Context(), viaEntryRequestTimeout)
	defer cancel()
	if !a.operationMu.TryLock() {
		http.Error(w, "another operation owns the active path", 409)
		return
	}
	defer a.operationMu.Unlock()
	c := viaEntryControlFor(a)
	release, err := a.lockCandidatePublicationContext(ctx, c)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	c.pruneNoncesLocked()
	view := c.orderedView
	_, repeated := c.seen[q.RequestID]
	if repeated || len(c.seen) >= 1024 || view == nil || view.token != q.ViewToken || view.position != q.PrefixPosition || !time.Now().Before(view.expires) || (c.owner != nil && (c.owner.running || !c.owner.drained)) {
		release()
		http.Error(w, "candidate view expired, request reused, or original cleanup is pending", 409)
		return
	}
	for _, id := range q.CandidateIDs {
		if _, ok := view.catalog.profiles[id]; !ok {
			release()
			http.Error(w, "candidate was not in the original saved catalog", 409)
			return
		}
	}
	job := &orderedCandidateJob{view: view, results: []hopmeasure.CandidateStatus{}, failures: []viaEntryCandidateError{}}
	owner := &viaEntryOwner{id: q.RequestID, cancel: cancel, done: make(chan struct{}), running: true, ordered: job}
	owner.cleanup = func(join context.Context) error {
		if job.pending != nil {
			job.pending = retryDesktopNodeChainCandidateDrain(join, view.identity.Ordered.launch, job.pending)
			if job.pending != nil {
				return job.pending
			}
		}
		if job.finish != nil {
			job.finish(true)
			job.finish = nil
		}
		return nil
	}
	c.owner = owner
	c.seen[q.RequestID] = time.Now()
	release()
	runErr := a.runOrderedCandidates(ctx, c, owner, q)
	cleanupErr := cleanupViaEntryOwner(c, owner)
	if runErr == nil && cleanupErr == nil {
		runErr = job.catalog.current(ctx)
	}
	c.mu.Lock()
	job.accepted = runErr == nil && cleanupErr == nil && !job.invalidated && !job.lost.Load() && !owner.cancelled && ctx.Err() == nil && c.owner == owner
	if runErr != nil {
		job.failure = runErr.Error()
	}
	if cleanupErr != nil {
		job.failure = "original native candidate cleanup is pending; Cancel must join it"
	}
	owner.running = false
	close(owner.done)
	response := orderedCandidateResponseLocked(owner, time.Now())
	c.mu.Unlock()
	if cleanupErr != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	viaEntryJSON(w, response)
}

func (a *app) runOrderedCandidates(ctx context.Context, c *viaEntryControl, owner *viaEntryOwner, q orderedCandidateRequest) error {
	job := owner.ordered
	view := job.view
	identity, _, err := captureSpeedLabIdentityContext(ctx, a)
	if err != nil {
		return err
	}
	current, token, _, err := captureOrderedPerformanceContext(ctx, a)
	if err != nil || identity.Ordered != view.identity.Ordered || current.Ordered != identity.Ordered || token != view.capture {
		return errors.New("connected prefix owner changed since catalog capture")
	}
	if err = view.catalog.current(ctx); err != nil {
		return err
	}
	job.catalog, err = captureDesktopNodeChainCandidates(ctx, a, identity, view.position, q.CandidateIDs)
	if err != nil {
		return err
	}
	if job.catalog.revision != view.catalog.revision {
		return errors.New("saved candidate catalog changed")
	}
	job.finish, err = beginDesktopNodeChainMeasurementHold(ctx, a, identity.Ordered.launch)
	if err != nil {
		return err
	}
	observation, err := captureOrderedCandidateObservation(ctx, job)
	if err != nil {
		return err
	}
	c.mu.Lock()
	job.observation = observation
	c.mu.Unlock()
	for _, id := range q.CandidateIDs {
		if err = ctx.Err(); err != nil {
			return err
		}
		c.mu.Lock()
		job.current = id
		c.mu.Unlock()
		result, e := exchangeDesktopNodeChainCandidate(ctx, job.catalog, id)
		if errors.Is(e, errDesktopNodeChainMeasurementPending) {
			job.pending = e
			return e
		}
		if e != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if e = job.catalog.current(ctx); e != nil {
				return e
			}
			c.mu.Lock()
			job.failures = append(job.failures, viaEntryCandidateError{ID: id, Error: "no complete valid 50-sample TCP receipt"})
			c.mu.Unlock()
			continue
		}
		c.mu.Lock()
		job.results = append(job.results, result)
		c.mu.Unlock()
	}
	return nil
}

func orderedCandidateResponseLocked(owner *viaEntryOwner, now time.Time) map[string]any {
	job := owner.ordered
	rows := []hopmeasure.CandidateStatus{}
	if !owner.cancelled && !job.invalidated && !job.lost.Load() && (owner.running || job.accepted) {
		for _, row := range job.results {
			if validateDesktopNodeChainCandidateStatus(job.catalog.plan, row.CandidateID, row, now) == nil {
				rows = append(rows, row)
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i].Results[0].Benchmark.TrimmedMean, rows[j].Results[0].Benchmark.TrimmedMean
		if a == b {
			return rows[i].CandidateID < rows[j].CandidateID
		}
		return a < b
	})
	return map[string]any{"schema": 1, "request_id": owner.id, "view_token": job.view.token, "prefix_position": job.view.position, "running": owner.running, "drained": owner.drained, "cancelled": owner.cancelled, "accepted": job.accepted && !owner.cancelled, "current_candidate": job.current, "results": rows, "errors": append([]viaEntryCandidateError{}, job.failures...), "failure": job.failure, "measurement": "routed-tcp-connect"}
}
func (a *app) orderedCandidateStatus(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	ids := query["request_id"]
	id := ""
	if len(ids) == 1 {
		id = ids[0]
	}
	if len(query) != 1 || len(ids) != 1 || !validViaEntryRequestID(id) {
		http.Error(w, "exact candidate request identity required", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	c := viaEntryControlFor(a)
	if err := desktopnetwork.LockContext(ctx, &c.mu); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	owner := c.owner
	if owner == nil || owner.id != id || owner.ordered == nil {
		c.mu.Unlock()
		http.Error(w, "original candidate job is no longer retained", 409)
		return
	}
	job := owner.ordered
	observation := job.observation
	if !owner.running && job.accepted && observation == nil {
		invalidateOrderedCandidateLocked(owner, "Original candidate proof observation is unavailable; retest.")
	}
	observe := !owner.cancelled && !job.invalidated && !job.lost.Load() && observation != nil && (owner.running || job.accepted)
	c.mu.Unlock()
	var observed error
	if observe {
		observed = observation.current(ctx, job.catalog)
		if observed != nil {
			job.lost.Store(true)
			owner.cancel()
		}
	}
	if err := desktopnetwork.LockContext(ctx, &c.mu); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	if c.owner != owner || owner.ordered != job {
		c.mu.Unlock()
		http.Error(w, "original candidate owner was replaced during observation", 409)
		return
	}
	if observed != nil || job.lost.Load() {
		invalidateOrderedCandidateLocked(owner, "Original source, session or native proof changed; retest before using candidate timings.")
	}
	response := orderedCandidateResponseLocked(owner, time.Now())
	c.mu.Unlock()
	viaEntryJSON(w, response)
}

func invalidateOrderedCandidateLocked(owner *viaEntryOwner, reason string) {
	if owner == nil || owner.ordered == nil {
		return
	}
	owner.ordered.lost.Store(true)
	owner.ordered.invalidated = true
	owner.ordered.accepted = false
	owner.ordered.results = nil
	owner.ordered.failure = reason
	if owner.running {
		owner.cancel()
	}
}

type orderedCandidateObservation struct {
	live  desktopNodeMTURecord
	ready mobilemultihop.DesktopNodeChainReadyRecord
}

func captureOrderedCandidateObservation(ctx context.Context, job *orderedCandidateJob) (*orderedCandidateObservation, error) {
	launch := job.catalog.launch
	live, err := readDesktopNodeMTUContext(ctx, launch)
	if err != nil || live.Active || live.Failure != "" {
		return nil, errors.Join(err, errors.New("original candidate MTU reader is not idle"))
	}
	if err = desktopnetwork.LockContext(ctx, &launch.chain.mu); err != nil {
		return nil, err
	}
	if launch.chain.ready == nil {
		launch.chain.mu.Unlock()
		return nil, errors.New("original candidate proof disappeared")
	}
	ready := *launch.chain.ready
	launch.chain.mu.Unlock()
	ready, err = readDesktopNodeChainReadyContext(ctx, launch, ready.TransferSHA256, time.UnixMilli(ready.ObservedAt), false, live)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(launch.chain.selection.Nodes))
	for i, n := range launch.chain.selection.Nodes {
		ids[i] = n.Profile.ID
	}
	token, err := orderedPerformanceCapture(job.view.identity, ready, ids)
	if err != nil || token != job.view.capture {
		return nil, errors.New("original candidate reader changed after catalog capture")
	}
	return &orderedCandidateObservation{live, ready}, nil
}
func (o *orderedCandidateObservation) current(ctx context.Context, catalog *desktopNodeChainCandidateCatalog) error {
	if o == nil || catalog == nil {
		return errors.New("candidate status has no original observation")
	}
	if err := catalog.pulseCurrent(ctx); err != nil {
		return err
	}
	live, err := readDesktopNodeMTUContext(ctx, catalog.launch)
	if err != nil || live.Active || live.Failure != "" || live.Session != o.live.Session || live.Config != o.live.Config || live.Path != o.live.Path || live.Reader != o.live.Reader || live.Interface != o.live.Interface || live.Index != o.live.Index || live.MTU != o.live.MTU {
		return errors.Join(err, errors.New("original candidate reader changed"))
	}
	ready, err := readDesktopNodeChainReadyContext(ctx, catalog.launch, o.ready.TransferSHA256, time.UnixMilli(o.ready.ObservedAt), false, live)
	if err != nil || ready.Identity != o.ready.Identity || ready.Generation != o.ready.Generation || ready.Reader != o.ready.Reader {
		return errors.Join(err, errors.New("original candidate proof changed"))
	}
	return catalog.pulseCurrent(ctx)
}
