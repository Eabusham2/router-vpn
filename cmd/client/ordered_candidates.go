package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
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
	token, capture                      string
	expires                             time.Time
	position                            int
	identity                            speedLabPathIdentity
	catalog                             *desktopNodeChainCandidateCatalog
	candidates                          []orderedCandidateChoice
	prefixes                            []orderedCandidatePrefix
	responseNodes                       []orderedCandidateResponseSourceNode
	responseOwners                      []string
	responseRequested, responseSelected string
	responseEpoch                       uint64
	candidateMode                       string
}
type orderedCandidateChoice struct {
	ID             string                         `json:"id"`
	Name           string                         `json:"name"`
	Kind           string                         `json:"kind"`
	Proposal       []common.MultihopNodeSelection `json:"proposed_path,omitempty"`
	SaveReason     string                         `json:"save_reason,omitempty"`
	ProposalAction string                         `json:"proposal_action,omitempty"`
	DraftProposal  []common.MultihopNodeSelection `json:"draft_path,omitempty"`
	DraftAction    string                         `json:"draft_action,omitempty"`
}
type orderedCandidatePrefix struct {
	Position    int    `json:"position"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Mode        string `json:"mode"`
	Measurement string `json:"measurement,omitempty"`
}

func candidateViewMetric(prefixes []orderedCandidatePrefix, position int) string {
	for _, p := range prefixes {
		if p.Position == position && p.Measurement != "" {
			return p.Measurement
		}
	}
	return hopmeasure.CandidateTCPMeasurement
}

func desktopCandidateMetricForIntent(launch *desktopNodeLaunch, position int, serverResponse bool) string {
	if launch == nil || launch.chain == nil || position < 0 || position >= len(launch.chain.selection.Nodes) || !desktopCandidatePositionForIntent(launch, position, serverResponse) {
		return ""
	}
	privateSelected := launch.chain.execution != nil && launch.chain.execution.preparation != nil &&
		(launch.chain.execution.preparation.SupportsCompareLocalResponseCandidate(position) || serverResponse && launch.chain.execution.preparation.SupportsServerResponseCandidate(position))
	publicSelected := launch.chain.execution != nil && launch.chain.execution.preparation != nil &&
		(launch.chain.execution.preparation.SupportsCompareLocalPublicResponseCandidate(position) || serverResponse && launch.chain.execution.preparation.SupportsServerPublicResponseCandidate(position))
	if position > 7 && !privateSelected && !publicSelected && (launch.chain.execution != nil || launch.chain.policy == nil || launch.chain.policy.OriginalChain().ExtendedLocalNodeCount() <= position+1) {
		return ""
	}
	if desktopConnectedHysteria2Candidate(launch, position) {
		return hopmeasure.CandidatePrivateResponseMeasurement
	}
	if mobilemultihop.NodeChainPrefixMode(launch.chain.selection.Nodes[position].Mode) {
		return hopmeasure.CandidateTCPMeasurement
	}
	if launch.chain.execution != nil {
		if publicSelected {
			return hopmeasure.CandidatePublicResponseMeasurement
		}
		if privateSelected {
			return hopmeasure.CandidatePrivateResponseMeasurement
		}
		return ""
	}
	connected := launch.command != nil && launch.chain.preparation == nil
	if connected && launch.chain.socksPolicy != nil {
		original, err := launch.chain.socksPolicy.NativeSource()
		if err == nil {
			return original.CandidatePrefixMeasurement(position)
		}
	}
	if connected && launch.chain.connectPolicy != nil {
		original, err := launch.chain.connectPolicy.NativeSource()
		if err == nil {
			return original.CandidatePrefixMeasurement(position)
		}
	}
	if launch.chain.policy == nil {
		return ""
	}
	if connected {
		return launch.chain.policy.OriginalChain().ConnectedCandidatePrefixMeasurement(position)
	}
	return launch.chain.policy.OriginalChain().CandidatePrefixMeasurement(position)
}

// Source classification selects the candidate protocol. The live catalog and
// native operation separately retain and verify the original connected owner.
func desktopConnectedHysteria2Candidate(launch *desktopNodeLaunch, position int) bool {
	return launch != nil && launch.command != nil && launch.chain != nil &&
		launch.chain.preparation == nil && launch.chain.execution == nil && launch.chain.policy != nil &&
		launch.chain.policy.OriginalChain().SupportsConnectedHysteria2FinalCandidate(position)
}

func orderedPrefixChoice(position int, n desktopNodeChainMember, metric string) orderedCandidatePrefix {
	p := orderedCandidatePrefix{Position: position, ID: n.Profile.ID, Name: n.Profile.Name, Mode: n.Mode}
	if desktopCandidateResponseMetric(metric) {
		p.Measurement = metric
	}
	return p
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
	registerOrderedCandidatePreparedRoutes(h, a)
	h.HandleFunc("/api/multihop/prefix-candidates/catalog", a.orderedCandidateCatalog)
	h.HandleFunc("/api/multihop/prefix-candidates", a.orderedCandidates)
	h.HandleFunc("/api/multihop/prefix-candidates/cancel", a.orderedCandidateConnectedCancel)
	h.HandleFunc("/api/multihop/prefix-candidates/save-profile", a.saveOrderedCandidateProfile)
}

func (a *app) orderedCandidateCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", 405)
		return
	}
	query := r.URL.Query()
	serverResponse, validIntent := takeCandidateServerIntent(query)
	positions := query["prefix_position"]
	rawPosition := ""
	if len(positions) == 1 {
		rawPosition = positions[0]
	}
	position, err := strconv.Atoi(rawPosition)
	if !validIntent || len(query) != 1 || len(positions) != 1 || err != nil || strconv.Itoa(position) != rawPosition || position < 0 || position >= mobilemultihop.NodeChainExtendedLocalMaximumNodes {
		http.Error(w, "choose an exact connected prefix position", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	ctx = candidateServerIntent(ctx, serverResponse)
	identity, capture, _, err := captureOrderedCandidateContext(ctx, a)
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
	revision, err := a.candidateCatalogRevisionLocked()
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		http.Error(w, "candidate view identity unavailable", 500)
		return
	}
	view := &orderedCandidateView{token: hex.EncodeToString(nonce), capture: capture, expires: time.Now().Add(120 * time.Second), position: position, identity: identity}
	if desktopConnectedHysteria2Candidate(identity.Ordered.launch, position) {
		view.candidateMode = "hysteria2"
	}
	members := identity.Ordered.launch.chain.selection.Nodes
	requested, err := orderedCandidateRequestedExecution(identity.Ordered.launch)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	var owners []string
	if e := identity.Ordered.launch.chain.execution; serverResponse && e != nil {
		owners = candidateResponseExecutions(e.preparation, position)
	}
	if e := identity.Ordered.launch.chain.execution; e != nil && len(owners) == 0 && requested == "auto" && e.preparation.SupportsSelectedFinalResponseCandidate(position) {
		owners = []string{"local"}
	}
	privateResponse := view.candidateMode != "" || len(owners) > 0 || desktopCompareLocalPrivateResponseMembers(members, requested, position)
	catalogMetric := desktopCandidateCatalogMetric(identity.Ordered.launch, serverResponse)
	for i, n := range members {
		if metric := catalogMetric(i); metric != "" {
			view.prefixes = append(view.prefixes, orderedPrefixChoice(i, n, metric))
		}
	}
	index := indexOrderedCandidateProposalProfiles(profiles)
	var candidates []*desktopNodeChainCandidateCatalog
	for _, p := range profiles {
		if ctx.Err() != nil {
			break
		}
		// The source compiler, not a protocol label or UI toggle, decides eligibility.
		captured, sourceErr := captureDesktopCandidateViewSource(ctx, a, identity.Ordered.launch, position, p, revision, orderedCandidateSavedCompleteScope, catalogMetric)
		if sourceErr != nil {
			continue
		}
		choice := orderedCandidateChoice{ID: p.ID, Name: p.Name, Kind: "router-vpn"}
		if p.External != nil {
			choice.Kind = "external"
		}
		profiles := index.members(members, p.ID)
		var proposal []common.MultihopNodeSelection
		if desktopCandidateResponseMetric(candidateViewMetric(view.prefixes, position)) {
			var action string
			_, proposal, action, err = orderedResponseProfileWithMode(ctx, identity.Ordered.launch.root, requested, members, position, p, profiles, view.candidateMode)
			if privateResponse || candidateViewMetric(view.prefixes, position) == hopmeasure.CandidatePublicResponseMeasurement {
				choice.ProposalAction = action
			}
		} else {
			_, proposal, err = orderedCandidateProposalForExecution(members, position, p, profiles, requested)
		}
		if err != nil {
			if privateResponse && candidateViewMetric(view.prefixes, position) == hopmeasure.CandidatePrivateResponseMeasurement {
				continue
			}
			choice.SaveReason = err.Error()
		} else {
			choice.Proposal = proposal
		}
		view.candidates = append(view.candidates, choice)
		candidates = append(candidates, captured)
	}
	candidates, view.candidates, err = filterDesktopPublicCandidateViews(ctx, candidates, view.candidates, position)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	if len(candidates) == 0 || ctx.Err() != nil {
		http.Error(w, "no saved candidate supports the measurement available through this prefix", 409)
		return
	}
	view.catalog, err = combineDesktopCandidateViewSources(ctx, candidates, position, orderedCandidateSavedCompleteScope)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	view.catalog.identity = identity
	if view.catalog.candidateMode != view.candidateMode {
		http.Error(w, "candidate catalog changed its original response protocol", 409)
		return
	}
	if err = view.catalog.pulseCurrent(ctx); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	metric := candidateViewMetric(view.prefixes, position)
	note := "50 TCP connection handshakes through the retained connected prefix. This does not authenticate candidate credentials. Saving creates a next-connection profile; it does not change the active path."
	if metric == hopmeasure.CandidatePrivateResponseMeasurement {
		note = "50 authenticated private agent responses through the selected prefix and paired candidate. Saving creates a profile for the next connection."
		if view.candidateMode == "hysteria2" {
			note = "50 authenticated Hysteria2 responses through the original connected prefix. Saving replaces only the final node in a profile for the next connection."
		}
	} else if metric == hopmeasure.CandidatePublicResponseMeasurement {
		note = "50 HTTPS responses after TLS through the selected prefix and the imported candidate. Every response verifies the candidate's recorded public exit IP. Save retains the original suffix and public final in a separate next-connection profile."
	}
	reply := map[string]any{"schema": 1, "view_token": view.token, "expires_at": view.expires.UnixMilli(), "prefix_position": position, "prefixes": view.prefixes, "candidates": view.candidates, "samples": 50, "measurement": metric, "note": note}
	addOrderedPublicCandidateSource(reply, identity.Ordered.launch.chain.selection, position, metric)
	if (requested == "auto" || len(owners) > 0) && desktopCandidateResponseMetric(metric) {
		reply["required_selected_execution"] = "local"
		reply["requested_execution"] = requested
		launch := identity.Ordered.launch.chain.execution
		launch.mu.Lock()
		ready := launch.ready
		launch.mu.Unlock()
		if ready == nil || ready.SelectionEpoch == 0 || (len(owners) == 0 && ready.Progress.Execution != "local") || len(owners) > 0 && !slices.Contains(owners, ready.Progress.Execution) {
			http.Error(w, "candidate responses require the original eligible selected execution", 409)
			return
		}
		reply["selected_execution"], reply["selection_epoch"] = ready.Progress.Execution, ready.SelectionEpoch
		view.responseNodes = orderedCandidateResponseSourceNodes(identity.Ordered.launch.chain.selection, requested, position)
		if metric == hopmeasure.CandidatePublicResponseMeasurement && len(owners) == 0 && requested == "auto" && ready.Progress.Execution == "local" {
			owners = []string{"local"}
		}
		if len(owners) > 0 {
			view.responseNodes = originalCandidateResponseNodes(identity.Ordered.launch.chain.selection)
			view.responseOwners, view.responseRequested, view.responseSelected = owners, requested, ready.Progress.Execution
		}
		if len(view.responseNodes) != 0 {
			view.responseEpoch = ready.SelectionEpoch
		}
	}
	view.addResponseSource(reply)
	// Publish the complete immutable view only after its original winner and
	// public source map have been captured.
	c := viaEntryControlFor(a)
	if err = desktopnetwork.LockContext(ctx, &c.mu); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	if err := rememberOrderedCandidateResponseViewLocked(c, view); err != nil {
		c.mu.Unlock()
		http.Error(w, err.Error(), 429)
		return
	}
	c.orderedView = view
	c.mu.Unlock()
	viaEntryJSON(w, reply)
}

// The result belongs to the next hop after the measured prefix. Preserve every
// other original member; an incompatible replacement cannot shorten the path.
// A chooser evaluates many proposals against the same immutable saved store.
// Duplicate identities still disable proposals. Resolving one proposed route
// needs only its original referenced profiles and the proposed candidate.
type orderedCandidateProposalIndex map[string]common.RouterProfile

func indexOrderedCandidateProposalProfiles(profiles []common.RouterProfile) orderedCandidateProposalIndex {
	byID := make(orderedCandidateProposalIndex, len(profiles))
	for _, profile := range profiles {
		if _, exists := byID[profile.ID]; exists {
			return nil
		}
		byID[profile.ID] = profile
	}
	return byID
}

func (byID orderedCandidateProposalIndex) members(members []desktopNodeChainMember, candidateID string) []common.RouterProfile {
	if byID == nil {
		return nil
	}
	profiles := make([]common.RouterProfile, 0, len(members)+1)
	included := false
	for _, member := range members {
		if original, ok := byID[member.Profile.ID]; ok {
			profiles = append(profiles, original)
			included = included || original.ID == candidateID
		}
	}
	if !included {
		if candidate, ok := byID[candidateID]; ok {
			profiles = append(profiles, candidate)
		}
	}
	return profiles
}

func orderedCandidateProposal(members []desktopNodeChainMember, position int, candidate common.RouterProfile, profiles []common.RouterProfile) (common.RouterProfile, []common.MultihopNodeSelection, error) {
	if len(members) == 0 {
		return common.RouterProfile{}, nil, errors.New("candidate proposal lost its complete original path")
	}
	return orderedCandidateProposalForExecution(members, position, candidate, profiles, desktopNodeChainControlProfile(members).MultihopExecution)
}

func orderedCandidateRequestedExecution(launch *desktopNodeLaunch) (string, error) {
	if launch == nil || launch.chain == nil {
		return "", errors.New("candidate proposal lost its original ordered launch")
	}
	if execution := launch.chain.execution; execution != nil {
		if err := execution.bound(launch); err != nil {
			return "", err
		}
		return execution.preparation.Execution(), nil
	}
	return "local", nil
}

func orderedCandidateProposalForExecution(members []desktopNodeChainMember, position int, candidate common.RouterProfile, profiles []common.RouterProfile, requested string) (common.RouterProfile, []common.MultihopNodeSelection, error) {
	return orderedCandidateProposalForExecutionWithMode(members, position, candidate, profiles, requested, "")
}

func orderedCandidateProposalForExecutionWithMode(members []desktopNodeChainMember, position int, candidate common.RouterProfile, profiles []common.RouterProfile, requested, candidateMode string) (common.RouterProfile, []common.MultihopNodeSelection, error) {
	var control common.RouterProfile
	if candidateMode != "" && (candidateMode != "hysteria2" || !desktopHysteria2FinalResponseMembers(members, requested, position, candidate)) {
		return control, nil, errors.New("candidate response changed its original final protocol or path")
	}
	publicResponse := desktopPublicCandidateMembers(members, requested, position) && desktopNodeChainImportedExecutionMiddle(candidate)
	typedFinal := desktopTypedFinalResponseMembers(members, requested, position)
	if len(members) < 2 || (len(members) > common.MultihopMaximumNodes && !common.ExtendedLocalMultihopSelection(nodeChainSelectedReferences(members)) && !common.ExtendedAWGSelectedMultihopSelection(nodeChainSelectedReferences(members)) && !(requested == "local" && (common.ExtendedPairedLocalMultihopSelection(nodeChainSelectedReferences(members)) || common.ExtendedMixedLocalPacketCount(nodeChainSelectedReferences(members)) > 0))) || position < 0 || position >= len(members)-1 || !(mobilemultihop.NodeChainPrefixMode(members[position].Mode) || publicResponse || (requested == "local" || desktopSelectedResponseProposal(members, requested, position, candidate)) && (members[position].Mode == "shadowsocks" || typedFinal) && candidate.External == nil) || !validDesktopOrderedExecution(requested) {
		return control, nil, errors.New("candidate requires an original packet prefix")
	}
	if desktopNodeChainHasExternalFinal(members) && (!validDesktopOrderedExecution(requested) || position != 0 && !publicResponse || !desktopNodeChainImportedExecutionMiddle(candidate)) {
		return control, nil, errors.New("the external-final route requires an original literal SS2022 candidate through its captured prefix")
	}
	nodes := nodeChainSelectedReferences(members)
	mode := "shadowsocks"
	if candidateMode != "" {
		mode = candidateMode
	}
	if candidate.External != nil {
		switch candidate.External.Protocol {
		case "socks5", "http-connect", "https-connect", "openvpn":
			mode = candidate.External.Protocol
		}
	}
	replacement := position + 1
	selected := common.MultihopNodeSelection{ID: candidate.ID, Mode: mode}
	if publicResponse || members[position].Mode == "shadowsocks" && replacement < len(nodes)-1 &&
		(requested == "local" || desktopSelectedResponseProposal(members, requested, position, candidate)) {
		if len(nodes) >= common.MultihopPhysicalTraversalDepth || nodes[replacement].Mode != "shadowsocks" {
			return control, nil, errors.New("saving this measured intermediate requires the original stream suffix and room for another member")
		}
		nodes = slices.Insert(nodes, replacement, selected)
	} else {
		nodes[replacement] = selected
	}
	control = cloneRouterProfile(desktopNodeChainControlProfile(members))
	if replacement == len(members)-1 && !publicResponse {
		control = cloneRouterProfile(candidate)
	}
	control.MultihopEnabled = true
	control.MultihopExecution = requested
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
	if _, err := resolveDesktopNodeChainSelection(control, proposed, nodes, requested); err != nil {
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
	if !validViaEntryRequestID(q.RequestID) || q.ViewToken == "" || q.Samples != 50 || len(q.CandidateIDs) == 0 {
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
	if err := reserveOrderedCandidateResponseAdmissionLocked(c, q.RequestID, view); err != nil {
		release()
		http.Error(w, err.Error(), 409)
		return
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
	current, token, _, err := captureOrderedCandidateContext(ctx, a)
	if err != nil || identity.Ordered != view.identity.Ordered || current.Ordered != identity.Ordered || token != view.capture {
		return errors.New("connected prefix owner changed since catalog capture")
	}
	if err = view.catalog.current(ctx); err != nil {
		return err
	}
	job.catalog, err = captureDesktopNodeChainCandidates(candidateServerIntent(ctx, view.catalog.serverResponse), a, identity, view.position, q.CandidateIDs)
	if err != nil {
		return err
	}
	if job.catalog.serverResponse != view.catalog.serverResponse || job.catalog.revision != view.catalog.revision || job.catalog.candidateMode != view.candidateMode {
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
			if view.responseSelected == "server" && len(view.responseOwners) > 0 {
				return e
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if e = job.catalog.current(ctx); e != nil {
				return e
			}
			c.mu.Lock()
			job.failures = append(job.failures, viaEntryCandidateError{ID: id, Error: "no complete valid 50-sample measurement"})
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
			if validateDesktopCandidateCatalogStatus(job.catalog, row.CandidateID, row, now) == nil {
				rows = append(rows, row)
			}
		}
	}
	sortOrderedCandidateResults(rows)
	response := map[string]any{"schema": 1, "request_id": owner.id, "view_token": job.view.token, "prefix_position": job.view.position, "running": owner.running, "drained": owner.drained, "cancelled": owner.cancelled, "accepted": job.accepted && !owner.cancelled, "current_candidate": job.current, "results": rows, "errors": append([]viaEntryCandidateError{}, job.failures...), "failure": job.failure, "measurement": candidateViewMetric(job.view.prefixes, job.view.position)}
	job.view.addResponseSource(response)
	return response
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
	live            desktopNodeMTURecord
	ready           mobilemultihop.DesktopNodeChainReadyRecord
	selected        *mobilemultihop.DesktopNodeChainExecutionReadyRecord
	selectedCapture string
}

func captureOrderedCandidateObservation(ctx context.Context, job *orderedCandidateJob) (*orderedCandidateObservation, error) {
	if job.catalog.selectedPlan != nil {
		return captureOrderedSelectedCandidateObservation(ctx, job)
	}
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
	return &orderedCandidateObservation{live: live, ready: ready}, nil
}
func (o *orderedCandidateObservation) current(ctx context.Context, catalog *desktopNodeChainCandidateCatalog) error {
	if o != nil && o.selected != nil {
		return o.currentSelected(ctx, catalog)
	}
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

func sortOrderedCandidateResults(rows []hopmeasure.CandidateStatus) {
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i].Results[0].Benchmark, rows[j].Results[0].Benchmark
		if (a == nil) != (b == nil) {
			return a != nil
		}
		if a != nil && a.TrimmedMean != b.TrimmedMean {
			return a.TrimmedMean < b.TrimmedMean
		}
		return rows[i].CandidateID < rows[j].CandidateID
	})
}
