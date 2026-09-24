package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/routechoice"
)

// One random endpoint is used for an entire comparison, including final proof.
// These bounded connectivity checks carry no node token or profile identifiers.
var comparisonTargets = []string{"https://1.1.1.1/cdn-cgi/trace", "https://1.0.0.1/cdn-cgi/trace"}

func routeExecution(q multihopConnectRequest) (routechoice.Execution, error) {
	switch q.Execution {
	case "", "local":
		return routechoice.Local, nil
	case "server":
		return routechoice.Server, nil
	case "auto":
		return routechoice.Execution("auto"), nil
	}
	return "", errors.New("multihop execution must be local, server, or auto")
}

type routeComparisonProgress struct {
	ID           string                    `json:"id"`
	Stage        string                    `json:"stage"`
	Measurements []routechoice.Measurement `json:"measurements"`
	Complete     bool                      `json:"complete"`
	Failure      string                    `json:"failure,omitempty"`
}
type comparisonOwner struct {
	mu    sync.Mutex
	value routeComparisonProgress
}

var desktopComparisons sync.Map

func comparisonProgress(a *app) routeComparisonProgress {
	p, ok := desktopComparisons.Load(a)
	if !ok {
		return routeComparisonProgress{Stage: "idle", Measurements: []routechoice.Measurement{}}
	}
	owner := p.(*comparisonOwner)
	owner.mu.Lock()
	defer owner.mu.Unlock()
	result := owner.value
	result.Measurements = append([]routechoice.Measurement{}, result.Measurements...)
	return result
}
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}

// Virtual tunnel devices are excluded. A physical address/link change makes all
// samples in the current round stale, rather than comparing different networks.
func physicalNetworkIdentity() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var values []string
	for _, in := range interfaces {
		if len(in.HardwareAddr) == 0 || in.Flags&net.FlagLoopback != 0 {
			continue
		}
		low := strings.ToLower(in.Name)
		if strings.Contains(low, "tun") || strings.Contains(low, "wireguard") || strings.HasPrefix(low, "wg") || strings.Contains(low, "router-vpn") {
			continue
		}
		addresses, e := in.Addrs()
		if e != nil {
			return ""
		}
		values = append(values, fmt.Sprint(in.Index, ":", in.Name, ":", in.Flags, ":", in.HardwareAddr))
		for _, v := range addresses {
			values = append(values, in.Name+":"+v.String())
		}
	}
	sort.Strings(values)
	sum := sha256.Sum256([]byte(strings.Join(values, "\n")))
	return hex.EncodeToString(sum[:])
}

type desktopExecutionDriver struct {
	a         *app
	selection multihopSelection
	network   string
}
type desktopExecutionSession struct {
	driver        *desktopExecutionDriver
	candidate     routechoice.Candidate
	selection     multihopSelection
	command       *exec.Cmd
	descriptorDir string
	generation    string
	relay         *desktopRelayOwner
}
type desktopRelayOwner struct {
	app      *app
	command  *exec.Cmd
	entry    common.RouterProfile
	expected multihoprelay.Lease
	request  multihoprelay.Request
	mu       sync.Mutex
	cancel   context.CancelFunc
	done     chan struct{}
	renewed  bool
}

var desktopRelays sync.Map

func (s *desktopExecutionSession) Identity() string {
	if s.command == nil || !s.driver.a.ownsConnectionRuntime(s.command) || physicalNetworkIdentity() != s.driver.network {
		return ""
	}
	g, ok := getActiveMultihopGraph(s.driver.a)
	if !ok || g.EntryID != s.candidate.EntryID || g.ExitID != s.candidate.ExitID || g.ExitMode != s.candidate.Transport || g.Execution != string(s.candidate.Execution) {
		return ""
	}
	return s.generation
}
func (s *desktopExecutionSession) Verify(ctx context.Context) error {
	if s.Identity() == "" {
		return errors.New("candidate no longer owns its network/session")
	}
	if err := proveMultihopLaneNodeContext(ctx, s.selection.Entry, multihopEntryProofProxy); err != nil {
		return err
	}
	return proveMultihopLaneNodeContext(ctx, s.selection.Exit, multihopProofProxy)
}
func (s *desktopExecutionSession) ProbeLast(ctx context.Context) (time.Duration, error) {
	target, err := multihopLaneProofURL(s.selection.Exit)
	if err != nil {
		return 0, err
	}
	return s.probe(ctx, target, &s.selection.Exit)
}
func (s *desktopExecutionSession) ProbeExternal(ctx context.Context, target string) (time.Duration, error) {
	allowed := false
	for _, t := range comparisonTargets {
		if t == target {
			allowed = true
		}
	}
	if !allowed {
		return 0, errors.New("external comparison target is not approved")
	}
	return s.probe(ctx, target, nil)
}
func (s *desktopExecutionSession) probe(ctx context.Context, target string, node *common.RouterProfile) (time.Duration, error) {
	identity := s.Identity()
	if identity == "" {
		return 0, errors.New("unowned measurement")
	}
	client, closeIdle, err := newMultihopLaneHTTPClient(multihopProofProxy, 2500*time.Millisecond)
	if err != nil {
		return 0, err
	}
	defer closeIdle()
	client.Transport.(*http.Transport).DisableKeepAlives = true
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Accept-Encoding", "identity")
	if node != nil {
		req.Header.Set("Authorization", "Bearer "+node.APIToken)
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, errors.New("routed response-time probe failed")
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4097))
	_ = resp.Body.Close()
	elapsed := time.Since(start)
	if readErr != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 || len(body) > 4096 || ctx.Err() != nil || s.Identity() != identity {
		return 0, errors.New("routed probe failed, expired, or changed path")
	}
	if node != nil {
		if err = validateSelectedNodeProof(*node, body); err != nil {
			return 0, err
		}
	}
	return elapsed, nil
}
func (s *desktopExecutionSession) Close(ctx context.Context) error {
	// Never stop a replacement runtime. Internal transitions retain the selected
	// kill-switch guard; explicit user Disconnect owns its release.
	a := s.driver.a
	if a.ownsConnectionRuntime(s.command) {
		if err := a.stopModeWithIntent(true); err != nil {
			return err
		}
	}
	if s.relay != nil {
		if stored, ok := desktopRelays.Load(a); ok && stored == s.relay {
			return errors.New("server lease cleanup is still owned")
		}
	}
	if s.descriptorDir != "" {
		if err := os.RemoveAll(s.descriptorDir); err != nil {
			return err
		}
	}
	return ctx.Err()
}
func (d *desktopExecutionDriver) Open(ctx context.Context, c routechoice.Candidate) (routechoice.Session, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if c.EntryID != d.selection.Entry.ID || c.ExitID != d.selection.Exit.ID || physicalNetworkIdentity() != d.network {
		return nil, errors.New("comparison node/network changed")
	}
	if err := d.a.checkConnectionOperation(); err != nil {
		return nil, err
	}
	if _, busy := desktopRelays.Load(d.a); busy {
		return nil, errors.New("a previous server lease still requires cleanup")
	}
	sel := d.selection
	sel.ExitMode = c.Transport
	s := &desktopExecutionSession{driver: d, candidate: c, selection: sel}
	var err error
	s.generation, err = randomHex(16)
	if err != nil {
		return nil, err
	}
	var descriptor *desktopExecutionDescriptor
	if c.Execution == routechoice.Server {
		base, e := validatedPrivateRouterAPI(sel.Entry.RouterAPI)
		if e != nil {
			return nil, e
		}
		u, e := url.Parse(base)
		if e != nil {
			return nil, e
		}
		host, e := netip.ParseAddr(u.Hostname())
		if e != nil || host.Zone() != "" || !host.IsPrivate() || host.IsLoopback() || !common.ValidNodeProofID(sel.Entry.NodeProofID) || !common.ValidNodeProofID(sel.Exit.NodeProofID) || sel.Entry.NodeProofID == sel.Exit.NodeProofID || sel.Entry.APIToken == "" {
			return nil, errors.New("server path requires paired private entry and exit identities")
		}
		number, e := rand.Int(rand.Reader, big.NewInt(32))
		if e != nil {
			return nil, e
		}
		user, e := randomHex(24)
		if e != nil {
			return nil, e
		}
		password, e := randomHex(24)
		if e != nil {
			return nil, e
		}
		q := multihoprelay.Request{SessionID: s.generation, EntryNodeID: sel.Entry.NodeProofID, ExitID: sel.Exit.ID, ExitMode: sel.ExitMode, Port: 26240 + int(number.Int64()), Username: user, Password: password}
		lease := multihoprelay.Lease{Request: q, NodeID: sel.Entry.NodeProofID, ExitNodeID: sel.Exit.NodeProofID, Host: host.Unmap().String(), Port: q.Port, Username: user, Password: password}
		descriptor = &desktopExecutionDescriptor{Execution: "server", Lease: lease}
		s.relay = &desktopRelayOwner{app: d.a, entry: sel.Entry, expected: lease, request: q}
	}
	s.command, s.descriptorDir, err = desktopExecutionCommand(d.a, sel, descriptor)
	if err != nil {
		return s, err
	}
	if err = ctx.Err(); err != nil {
		return s, err
	}
	if err = s.command.Start(); err != nil {
		return s, errors.New("owned multihop helper failed to start")
	}
	d.a.mu.Lock()
	d.a.cmd = s.command
	d.a.state.Mode = "multihop"
	d.a.state.LogicalMode = "multihop"
	d.a.state.RuntimeMode = sel.ExitMode
	d.a.state.Base = sel.Base
	d.a.state.RouterID = sel.Exit.ID
	d.a.state.Connected = false
	d.a.state.Phase = "multihop:proving-" + string(c.Execution)
	d.a.mu.Unlock()
	setActiveMultihopGraph(d.a, sel)
	graph, _ := getActiveMultihopGraph(d.a)
	graph.Execution = string(c.Execution)
	activeMultihopGraphs.Store(d.a, graph)
	if s.relay != nil {
		s.relay.command = s.command
	}
	for {
		if s.Identity() == "" {
			return s, errors.New("entry startup lost ownership")
		}
		err = proveMultihopLaneNodeContext(ctx, sel.Entry, multihopEntryProofProxy)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return s, ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	if s.relay != nil {
		if err = s.relay.available(ctx); err != nil {
			return s, err
		}
		// Persist ownership before PUT; a timeout may follow successful creation.
		desktopRelays.Store(d.a, s.relay)
		s.relay.mu.Lock()
		err = s.relay.put(ctx)
		s.relay.mu.Unlock()
		if err != nil {
			var rejected desktopRelayRejected
			if errors.As(err, &rejected) {
				desktopRelays.CompareAndDelete(d.a, s.relay)
			}
			return s, err
		}
		s.relay.startRenewal()
	}
	for {
		err = proveMultihopLaneNodeContext(ctx, sel.Exit, multihopProofProxy)
		if err == nil {
			return s, nil
		}
		select {
		case <-ctx.Done():
			return s, ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
}

type desktopRelayRejected struct{ status int }

func (e desktopRelayRejected) Error() string { return "private relay control request was rejected" }

func (o *desktopRelayOwner) requestControl(ctx context.Context, method string, out any) error {
	if !o.app.ownsConnectionRuntime(o.command) {
		return errors.New("entry control runtime changed")
	}
	base, err := validatedPrivateRouterAPI(o.entry.RouterAPI)
	if err != nil {
		return err
	}
	// This proxy's route is entry-wg (native) or the owned split interface (Linux),
	// not the entry server's SOCKS daemon. The server sees the actual tunnel peer.
	client, closeIdle, err := newMultihopLaneHTTPClient(multihopEntryProofProxy, 8*time.Second)
	if err != nil {
		return err
	}
	defer closeIdle()
	body, _ := json.Marshal(o.request)
	req, err := http.NewRequestWithContext(ctx, method, base+"/api/multihop/lease", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+o.entry.APIToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	response, err := client.Do(req)
	if err != nil {
		return errors.New("private relay control request failed")
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 8193))
	_ = response.Body.Close()
	if readErr == nil && ctx.Err() == nil && len(raw) <= 8192 && response.StatusCode >= 400 && response.StatusCode < 500 {
		return desktopRelayRejected{response.StatusCode}
	}
	if readErr != nil || response.StatusCode != 200 || len(raw) > 8192 || ctx.Err() != nil {
		return errors.New("private relay control was rejected or timed out")
	}
	if err = decodeRelayControlJSON(raw, out); err != nil {
		return err
	}
	if !o.app.ownsConnectionRuntime(o.command) {
		return errors.New("relay control completed for a stale runtime")
	}
	return nil
}
func (o *desktopRelayOwner) available(ctx context.Context) error {
	var response struct {
		NodeID    string `json:"node_id"`
		Execution string `json:"execution"`
		Exits     []struct {
			ID        string `json:"exit_id"`
			Mode      string `json:"exit_mode"`
			NodeID    string `json:"exit_node_id"`
			PublicKey string `json:"client_public_key,omitempty"`
		} `json:"exits"`
	}
	if err := o.requestControl(ctx, http.MethodGet, &response); err != nil {
		return err
	}
	if response.NodeID != o.entry.NodeProofID || response.Execution != "server" {
		return errors.New("server capabilities answered for another node")
	}
	for _, exit := range response.Exits {
		if exit.ID == o.request.ExitID && exit.Mode == o.request.ExitMode && exit.NodeID == o.expected.ExitNodeID {
			return nil
		}
	}
	return multihoprelay.ErrUnavailable
}

func (o *desktopRelayOwner) put(ctx context.Context) error {
	var lease multihoprelay.Lease
	if err := o.requestControl(ctx, http.MethodPut, &lease); err != nil {
		return err
	}
	expected := o.expected
	if lease.Request != o.request || lease.NodeID != expected.NodeID || lease.ExitNodeID != expected.ExitNodeID || lease.Host != expected.Host || lease.Port != expected.Port || lease.Username != expected.Username || lease.Password != expected.Password || !lease.ExpiresAt.After(time.Now().Add(2*time.Second)) || lease.ExpiresAt.After(time.Now().Add(305*time.Second)) {
		return errors.New("relay lease identity, credentials or lifetime do not match the owned request")
	}
	o.expected = lease
	o.renewed = true
	return nil
}
func (o *desktopRelayOwner) startRenewal() {
	ctx, cancel := context.WithCancel(context.Background())
	o.cancel = cancel
	o.done = make(chan struct{})
	go func() {
		defer close(o.done)
		for {
			o.mu.Lock()
			remaining := time.Until(o.expected.ExpiresAt)
			o.mu.Unlock()
			delay := remaining / 3
			if delay < time.Second {
				delay = time.Second
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			child, c := context.WithTimeout(ctx, 8*time.Second)
			o.mu.Lock()
			err := o.put(child)
			o.mu.Unlock()
			c()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				o.app.cancelConnectionOperation()
				go func() {
					o.app.operationMu.Lock()
					defer o.app.operationMu.Unlock()
					if o.app.ownsConnectionRuntime(o.command) {
						_ = o.app.stopModeWithIntent(true)
						o.app.mu.Lock()
						o.app.state.Phase = "failed"
						o.app.state.LastError = "Server multihop lease renewal failed; the owned tunnel was stopped."
						o.app.mu.Unlock()
					}
				}()
				return
			}
		}
	}()
}
func releaseDesktopRelay(a *app, owner *exec.Cmd) error {
	value, ok := desktopRelays.Load(a)
	if !ok {
		return nil
	}
	o := value.(*desktopRelayOwner)
	if o.command != owner || owner == nil {
		return errors.New("server lease has no matching live control tunnel; ownership retained for cleanup")
	}
	if o.cancel != nil {
		o.cancel()
		<-o.done
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var result struct {
		NodeID    string `json:"node_id"`
		SessionID string `json:"session_id"`
		Stopped   bool   `json:"stopped"`
	}
	if err := o.requestControl(ctx, http.MethodDelete, &result); err != nil {
		return err
	}
	if result.NodeID != o.expected.NodeID || result.SessionID != o.request.SessionID || !result.Stopped {
		return errors.New("relay teardown readback did not match the owned session")
	}
	desktopRelays.CompareAndDelete(a, o)
	return nil
}

func (a *app) runMultihopExecution(w http.ResponseWriter, r *http.Request, sel multihopSelection, q multihopConnectRequest) {
	execution, err := routeExecution(q)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	parent := a.connectionOperationContextOrBackground()
	ctx, cancel := context.WithTimeout(parent, 180*time.Second)
	defer cancel()
	stop := context.AfterFunc(r.Context(), cancel)
	defer stop()
	network := physicalNetworkIdentity()
	if network == "" {
		http.Error(w, "could not capture physical network identity", 409)
		return
	}
	// Freeze profile material once for the complete comparison.
	sel.Control = cloneRouterProfile(sel.Control)
	sel.Entry = cloneRouterProfile(sel.Entry)
	sel.Exit = cloneRouterProfile(sel.Exit)
	id, err := randomHex(16)
	if err != nil {
		http.Error(w, "could not allocate comparison identity", 500)
		return
	}
	progress := &comparisonOwner{value: routeComparisonProgress{ID: id, Stage: "starting", Measurements: []routechoice.Measurement{}}}
	desktopComparisons.Store(a, progress)
	finish := func(failure string) {
		progress.mu.Lock()
		defer progress.mu.Unlock()
		progress.value.Complete = true
		progress.value.Failure = failure
		if failure != "" {
			progress.value.Stage = "failed"
		}
	}
	notify := func(event routechoice.Event) {
		progress.mu.Lock()
		defer progress.mu.Unlock()
		progress.value.Stage = event.Stage
		if event.Stage == "measured" && event.Result != nil {
			progress.value.Measurements = append(progress.value.Measurements, *event.Result)
		}
	}
	sessionTrackerFor(a).declareRequest("multihop", sel.Base)
	if err = a.stopModeWithIntent(true); err != nil {
		finish("previous session teardown failed")
		http.Error(w, "previous session teardown failed", 500)
		return
	}
	modes := []string{sel.ExitMode}
	if q.ExitMode == "auto" && execution == "auto" {
		modes = []string{"shadowsocks", "hysteria2"}
	}
	driver := &desktopExecutionDriver{a: a, selection: sel, network: network}
	var active routechoice.Session
	var result routechoice.Result
	if execution == "auto" {
		var candidates []routechoice.Candidate
		for _, mode := range modes {
			for _, kind := range []routechoice.Execution{routechoice.Local, routechoice.Server} {
				candidates = append(candidates, routechoice.Candidate{Execution: kind, Transport: mode, EntryID: sel.Entry.ID, ExitID: sel.Exit.ID})
			}
		}
		result, active, err = routechoice.Compare(ctx, candidates, driver, routechoice.Options{Targets: comparisonTargets, StartupTimeout: 25 * time.Second, ProbeTimeout: 2500 * time.Millisecond, CleanupTimeout: 15 * time.Second, Preferred: routechoice.Local, Notify: notify})
	} else {
		c := routechoice.Candidate{Execution: execution, Transport: sel.ExitMode, EntryID: sel.Entry.ID, ExitID: sel.Exit.ID}
		start, cancelStart := context.WithTimeout(ctx, 25*time.Second)
		active, err = driver.Open(start, c)
		cancelStart()
		if err == nil {
			verify, cancelVerify := context.WithTimeout(ctx, 5*time.Second)
			err = active.Verify(verify)
			cancelVerify()
		}
		if err == nil {
			result.Winner = &c
		}
	}
	if err != nil {
		if active != nil {
			cleanup, c := context.WithTimeout(context.Background(), 15*time.Second)
			cleanErr := active.Close(cleanup)
			c()
			if cleanErr != nil {
				err = routechoice.ErrTeardown
			}
		}
		finish(err.Error())
		sessionTrackerFor(a).markRequestFailure(err.Error())
		http.Error(w, err.Error(), 502)
		return
	}
	real, ok := active.(*desktopExecutionSession)
	if !ok || result.Winner == nil || real.Identity() == "" || ctx.Err() != nil || a.checkConnectionOperation() != nil {
		if active != nil {
			clean, c := context.WithTimeout(context.Background(), 15*time.Second)
			_ = active.Close(clean)
			c()
		}
		finish("winner changed before activation")
		http.Error(w, "winner changed before activation", 409)
		return
	}
	a.mu.Lock()
	currentEntry, e := a.profileByIDLocked(sel.Entry.ID)
	currentExit, x := a.profileByIDLocked(sel.Exit.ID)
	if !e || !x || !reflect.DeepEqual(currentEntry, sel.Entry) || !reflect.DeepEqual(currentExit, sel.Exit) || a.cmd != real.command {
		a.mu.Unlock()
		clean, c := context.WithTimeout(context.Background(), 15*time.Second)
		_ = active.Close(clean)
		c()
		finish("selected node configuration changed")
		http.Error(w, "selected node configuration changed", 409)
		return
	}
	previous := cloneRouterProfileStore(a.profiles)
	now := time.Now().UTC().Format(time.RFC3339)
	for i := range a.profiles.Profiles {
		p := &a.profiles.Profiles[i]
		if p.ID == sel.Entry.ID || p.ID == sel.Exit.ID {
			p.UseCount++
			p.LastUsedAt = now
		}
	}
	err = a.persistProfilesLocked()
	if err != nil {
		a.rollbackProfilesLocked(previous)
	} else {
		a.state.Connected = true
		a.state.Phase = "connected"
		a.state.LastError = ""
	}
	a.mu.Unlock()
	if err != nil {
		clean, c := context.WithTimeout(context.Background(), 15*time.Second)
		_ = active.Close(clean)
		c()
		finish("winner could not be persisted")
		http.Error(w, "winner could not be persisted", 500)
		return
	}
	progress.mu.Lock()
	progress.value.Stage = "selected"
	progress.mu.Unlock()
	finish("")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "execution": result.Winner.Execution, "entry_id": sel.Entry.ID, "exit_id": sel.Exit.ID, "exit_mode": result.Winner.Transport, "comparison": result, "proof": "both nodes verified through the owned candidate"})
}
