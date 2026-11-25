package mobilemultihop

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/multihoprelay"
)

// This is an explicit native-boundary double. The shared runtime, private HTTP
// framing, sealed DELETE, actual fifty-sample service and SOCKS framing execute.
// It is not the native worker's encrypted/provider acceptance fixture.
func (e *nodeChainExecutionRuntimeEngine) CaptureExecutionCandidateStop(ctx context.Context, c NodeChainExecutionCandidateStopCapture) (LeaseStop, error) {
	e.mu.Lock()
	if !e.alive || !e.open || c.Identity() != e.identity || ctx.Err() != nil {
		e.mu.Unlock()
		return nil, nodeChainExecutionError
	}
	e.stops++
	identity, selected, epoch := e.identity, e.selected, e.epoch
	e.mu.Unlock()
	tag, address := c.Route()
	return NewOwnedNodeChainExecutionCandidateStop(c, func(call context.Context) (net.Conn, error) { return e.Dial(call, tag, address) }, func(call context.Context) error {
		e.mu.Lock()
		defer e.mu.Unlock()
		if !e.alive || e.identity != identity || e.selected != selected || e.epoch != epoch {
			return nodeChainExecutionError
		}
		return call.Err()
	}, func() { e.mu.Lock(); e.stops--; e.mu.Unlock() })
}

type remoteCandidateTestOwner struct {
	*nodeChainExecutionMeasurementTestOwner
	capture string
	stale   atomic.Bool
}

func (o *remoteCandidateTestOwner) CandidateInventoryCurrentContext(ctx context.Context, capture string) error {
	if o.stale.Load() || capture != o.capture {
		return nodeChainExecutionError
	}
	return ctx.Err()
}

type remoteCandidateFixture struct {
	absence            func(http.ResponseWriter, *http.Request, multihoprelay.NodeChainCandidateCapture) bool
	f                  *nodeChainExecutionRuntimeFixture
	reply              func(net.Conn, multihoprelay.NodeChainCandidateCapture)
	plan               *NodeChainExecutionRemoteCandidatePlan
	measurement        *NodeChainExecutionRemoteCandidateMeasurement
	owner              *remoteCandidateTestOwner
	mu                 sync.Mutex
	capture            multihoprelay.NodeChainCandidateCapture
	admission          *multihoprelay.NodeChainCandidateAdmission
	put, post, deleted int
	events             []string
	badACK, losePUT    bool
	badReceipt         bool
	beforeGrant        func()
	frontDelay         time.Duration
	payload            atomic.Int32
}

func newRemoteCandidateFixture(t *testing.T, execution string) *remoteCandidateFixture {
	t.Helper()
	return newRemoteCandidateFixtureTTL(t, execution, 0)
}

func newRemoteCandidateFixtureTTL(t *testing.T, execution string, ttlSeconds int) *remoteCandidateFixture {
	t.Helper()
	// Zero selects the actual manager's provisioned/default 90-second lease.
	// Never rewrite a captured lease or refresh a candidate's original expiry.
	f := newNodeChainExecutionRuntimeFixtureFromPreparationTTL(t, nodeChainExecutionFixtureSource(t, 3, "", execution), nil, ttlSeconds)
	return remoteCandidateFixtureAtPacket(t, f, execution, 1)
}

func remoteCandidateFixtureAtPacket(t *testing.T, f *nodeChainExecutionRuntimeFixture, execution string, position int) *remoteCandidateFixture {
	return remoteCandidateFixtureAt(t, f, execution, position, "")
}
func remoteCandidateFixtureAt(t *testing.T, f *nodeChainExecutionRuntimeFixture, execution string, position int, responseInput string, additional ...string) *remoteCandidateFixture {
	t.Helper()
	if execution == "auto" {
		// Separate both successful real HTTP measurements under race instrumentation.
		f.engine.localDelay = 200 * time.Millisecond
		f.engine.serverDelay = time.Millisecond
	}
	r := &remoteCandidateFixture{f: f}
	entry := f.runtime.projection.policy.local.nodes[0]
	api, _ := privateAPI(predecessorText(entry.profile, "router_api"))
	token := predecessorText(entry.profile, "api_token")
	originalPeer := f.engine.peers[f.runtime.projection.policy.local.proofs[0].Tag+"/"+api.Host]
	proxy := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", originalPeer)
	}}}
	t.Cleanup(func() { proxy.CloseIdleConnections() })
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if q.Host != api.Host || q.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "foreign", 403)
			return
		}
		if q.URL.Path != nodeChainExecutionCandidatePath {
			if q.URL.Path == nodeChainExecutionLeasePath && q.Method == "DELETE" {
				r.mu.Lock()
				r.events = append(r.events, "lease-delete")
				r.mu.Unlock()
			}
			outbound := q.Clone(q.Context())
			outbound.RequestURI = ""
			outbound.URL.Scheme = "http"
			outbound.URL.Host = api.Host
			response, err := proxy.Do(outbound)
			if err != nil {
				http.Error(w, "original peer", 502)
				return
			}
			defer response.Body.Close()
			for k, v := range response.Header {
				w.Header()[k] = v
			}
			w.WriteHeader(response.StatusCode)
			_, _ = io.Copy(w, response.Body)
			return
		}
		r.serveCandidate(w, q)
	}))
	t.Cleanup(endpoint.Close)
	f.engine.mu.Lock()
	f.engine.peers[f.runtime.projection.policy.local.proofs[0].Tag+"/"+api.Host] = endpoint.Listener.Addr().String()
	f.engine.mu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if f.runtime.Progress().Execution != "server" {
		t.Fatal("fixture did not retain selected Server")
	}
	input, _ := candidateSourceFixture(t, "external", "2022-blake3-aes-128-gcm")
	if responseInput != "" {
		input = responseInput
	}
	plan, err := f.runtime.NewSelectedRemoteCandidatePlanContext(ctx, position, candidateInventoryFixture(t, "remote-original", append([]string{input}, additional...)...))
	if err != nil {
		t.Fatal(err)
	}
	r.plan = plan
	r.owner = &remoteCandidateTestOwner{nodeChainExecutionMeasurementTestOwner: &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}, capture: plan.capture}
	r.measurement, err = plan.NewMeasurementContext(ctx, r.owner)
	if err != nil {
		t.Fatal(err)
	}
	f.engine.beforeDial = func(ctx context.Context, tag, address string) (net.Conn, error, bool) {
		if address != net.JoinHostPort(plan.projection.policy.Front().Host, strconv.Itoa(plan.trial.leasePort())) {
			return nil, nil, false
		}
		if tag != plan.projection.policy.local.proofs[0].Tag {
			return nil, nodeChainExecutionError, true
		}
		client, server := net.Pipe()
		go r.front(server)
		return client, nil, true
	}
	t.Cleanup(func() {
		r.mu.Lock()
		r.badACK = false
		r.mu.Unlock()
		if err := r.measurement.Close(); err != nil {
			t.Error(err)
		}
		if err := closeRemoteCandidateRuntime(f.runtime); err != nil {
			t.Error(err)
		}
	})
	return r
}
func (s *nodeChainExecutionTrial) leasePort() int {
	s.mu.Lock()
	a := s.attempt
	s.mu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lease.Port
}
func (r *remoteCandidateFixture) serveCandidate(w http.ResponseWriter, q *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(q.Body, multihoprelay.NodeChainCandidateMaximumBytes+1))
	if err != nil {
		http.Error(w, "read", 400)
		return
	}
	request, err := multihoprelay.DecodeNodeChainCandidateRequest(raw)
	if err != nil {
		http.Error(w, "capture", 400)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch q.Method {
	case "PUT":
		if r.beforeGrant != nil {
			r.beforeGrant()
		}
		r.put++
		r.events = append(r.events, "candidate-put")
		r.f.runtime.mu.Lock()
		trial := r.f.runtime.active
		r.f.runtime.mu.Unlock()
		if trial == nil {
			http.Error(w, "retired trial", 409)
			return
		}
		trial.mu.Lock()
		a := trial.attempt
		trial.mu.Unlock()
		a.mu.Lock()
		lease := multihoprelay.NodeChainCapture{Schema: 1, Request: a.request.Clone(), Source: a.source.Clone(), RegistrySHA256: a.lease.RegistrySHA256, OwnerID: a.lease.OwnerID, Peer: a.request.Peer, Host: a.lease.Host, BootstrapDeadline: a.lease.BootstrapDeadline}
		a.mu.Unlock()
		r.capture, err = multihoprelay.NewNodeChainCandidateCapture(lease, request, time.Now())
		if err == nil && r.absence != nil && r.absence(w, q, r.capture) {
			return
		}
		if err == nil {
			r.admission, err = multihoprelay.NewNodeChainCandidateAdmission(context.Background(), r.capture)
		}
		if err != nil {
			http.Error(w, "original grant", 409)
			return
		}
		if r.losePUT {
			h, ok := w.(http.Hijacker)
			if ok {
				c, _, e := h.Hijack()
				if e == nil {
					_ = c.Close()
				}
			}
			return
		}
	case "POST":
		r.post++
		if r.admission == nil {
			http.Error(w, "missing original", 409)
			return
		}
	case "DELETE":
		r.deleted++
		r.events = append(r.events, "candidate-delete")
		if r.admission != nil {
			if err := r.admission.CloseContext(q.Context()); err != nil {
				http.Error(w, "held", 409)
				return
			}
		}
		if r.badACK {
			_ = json.NewEncoder(w).Encode(map[string]any{"stopped": true})
			return
		}
		ack, err := multihoprelay.NewNodeChainCandidateCloseAcknowledgement(request)
		if err != nil {
			http.Error(w, "ack", 409)
			return
		}
		_ = json.NewEncoder(w).Encode(ack)
		return
	default:
		http.Error(w, "method", 400)
		return
	}
	original, _ := r.capture.Request.Digest()
	actual, _ := request.Digest()
	if original != actual {
		http.Error(w, "foreign operation", 409)
		return
	}
	usage := r.admission.Snapshot()
	digest, _ := r.capture.Digest()
	receipt := multihoprelay.NodeChainCandidateReceipt{Schema: 1, Operation: request.Operation, OperationOwnerID: r.capture.OperationOwnerID, CaptureSHA256: digest, DeadlineAt: request.DeadlineAt, Prepared: true, Retired: usage.Retired, Drained: usage.Drained, Accepted: usage.Accepted, InFlight: usage.InFlight}
	if r.badReceipt {
		receipt.Operation = strings.Repeat("d", 64)
	}
	_ = json.NewEncoder(w).Encode(receipt)
}
func (r *remoteCandidateFixture) front(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	var hello [3]byte
	if _, e := io.ReadFull(conn, hello[:]); e != nil || hello != [3]byte{5, 1, 2} {
		return
	}
	if _, e := conn.Write([]byte{5, 2}); e != nil {
		return
	}
	var head [2]byte
	if _, e := io.ReadFull(conn, head[:]); e != nil || head[0] != 1 {
		return
	}
	user := make([]byte, int(head[1]))
	if _, e := io.ReadFull(conn, user); e != nil {
		return
	}
	var n [1]byte
	if _, e := io.ReadFull(conn, n[:]); e != nil {
		return
	}
	pass := make([]byte, int(n[0]))
	if _, e := io.ReadFull(conn, pass); e != nil {
		return
	}
	defer clear(pass)
	r.mu.Lock()
	capture, admission, delay := r.capture, r.admission, r.frontDelay
	r.mu.Unlock()
	if admission == nil || string(user) != capture.Username() || string(pass) != capture.Request.Password {
		_, _ = conn.Write([]byte{1, 1})
		return
	}
	if _, e := conn.Write([]byte{1, 0}); e != nil {
		return
	}
	var request [4]byte
	if _, e := io.ReadFull(conn, request[:]); e != nil || request[0] != 5 || request[1] != 1 || request[2] != 0 {
		return
	}
	size := 0
	if request[3] == 1 {
		size = 4
	} else if request[3] == 4 {
		size = 16
	} else {
		return
	}
	address := make([]byte, size+2)
	if _, e := io.ReadFull(conn, address); e != nil {
		return
	}
	ip, ok := netip.AddrFromSlice(address[:size])
	if !ok {
		return
	}
	target := net.JoinHostPort(ip.String(), strconv.Itoa(int(binary.BigEndian.Uint16(address[size:]))))
	release, err := admission.Begin(context.Background(), string(user), string(pass), "tcp", target)
	if err != nil {
		_, _ = conn.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer release()
	// The native worker owns the actual destination dial. This boundary double
	// acknowledges only after real grant admission, not a claimed provider route.
	// The explicit short-lease refusal owns a bounded 400ms front delay.
	// Fifty successful dials cannot fit its captured 15s grant, while each
	// individual dial remains below the unchanged 2500ms probe deadline.
	if delay != 0 {
		timer := time.NewTimer(delay)
		<-timer.C
	}
	if _, e := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
		return
	}
	if capture.Request.Schema == 2 {
		if r.reply != nil {
			r.reply(conn, capture)
		}
		return
	}
	var payload [1]byte
	if n, _ := conn.Read(payload[:]); n != 0 {
		r.payload.Add(int32(n))
	}
}
func (r *remoteCandidateFixture) wait(t *testing.T) hopmeasure.CandidateStatus {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), hopmeasure.RequestTimeout+hopmeasure.DrainTimeout)
	defer cancel()
	for {
		var status hopmeasure.CandidateStatus
		if json.Unmarshal([]byte(r.measurement.service.StatusContextJSON(ctx)), &status) != nil {
			t.Fatal("status")
		}
		if status.Complete || status.Failure != "" {
			return status
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		// Match the connected candidate UI poll. The worker validates every sample.
		case <-time.After(200 * time.Millisecond):
		}
	}
}
func TestNodeChainExecutionRemoteCandidatesFiftyOriginalConnections(t *testing.T) {
	for _, execution := range []string{"server", "auto"} {
		t.Run(execution, func(t *testing.T) {
			r := newRemoteCandidateFixture(t, execution)
			proofEvents := entryMaintainServerProof(t, r.f)
			before := r.f.engine.opens
			trial := r.plan.trial
			request := strings.Repeat("a", 32)
			if err := r.measurement.Start(request, r.plan.packet.targets[0].ID); err != nil {
				t.Fatal(err)
			}
			status := r.wait(t)
			if err := r.measurement.Drain(request); err != nil {
				t.Fatal(err)
			}
			if status.Failure != "" || len(status.Results) != 1 || status.Results[0].Benchmark == nil || status.Results[0].Benchmark.Attempts != 50 {
				t.Fatal("actual fifty-sample service failed", status)
			}
			r.mu.Lock()
			put, deleted, usage := r.put, r.deleted, r.admission.Snapshot()
			r.mu.Unlock()
			if put != 1 || deleted != 1 || usage.Accepted != 50 || !usage.Drained || r.payload.Load() != 0 || r.owner.active.Load() {
				t.Fatal("grant or exact cleanup mismatch", put, deleted, usage)
			}
			if proofEvents.Load() == 0 || r.f.engine.opens != before || r.f.runtime.active != trial {
				t.Fatal("measurement reran Compare or replaced the original trial")
			}
		})
	}
}
func TestNodeChainExecutionRemoteCandidatesCleanupAndRefusals(t *testing.T) {
	for _, kind := range []string{"lost-put", "wrong-ack", "foreign-receipt", "stale-catalog", "captured-lease"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "captured-lease" {
				remoteCandidateCapturedLeaseRefusal(t)
				return
			}
			r := newRemoteCandidateFixture(t, "server")
			r.mu.Lock()
			r.losePUT = kind == "lost-put"
			r.badACK = kind == "wrong-ack"
			r.badReceipt = kind == "foreign-receipt"
			r.mu.Unlock()
			if kind == "stale-catalog" {
				r.owner.stale.Store(true)
			}
			err := r.measurement.Start(strings.Repeat("b", 32), r.plan.packet.targets[0].ID)
			if kind == "stale-catalog" {
				if err == nil {
					t.Fatal("foreign inventory admitted")
				}
				r.owner.stale.Store(false)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			_ = r.wait(t)
			if kind == "wrong-ack" {
				if r.measurement.Close() == nil || !r.owner.active.Load() {
					t.Fatal("nonexact ACK released original activity")
				}
				r.mu.Lock()
				r.badACK = false
				r.mu.Unlock()
			}
			if err := r.measurement.Close(); err != nil {
				t.Fatal(err)
			}
			r.mu.Lock()
			put, deleted := r.put, r.deleted
			r.mu.Unlock()
			if put != 1 || deleted == 0 || r.owner.active.Load() {
				t.Fatal("lost original cancellation", put, deleted)
			}
		})
	}
}

// Real manager renewal may extend the enclosing VPN lease, but never this
// originally captured candidate grant. No clock or receipt is synthesized.
func remoteCandidateCapturedLeaseRefusal(t *testing.T) {
	t.Helper()
	r := newRemoteCandidateFixtureTTL(t, "server", 15)
	r.mu.Lock()
	r.frontDelay = 400 * time.Millisecond
	r.mu.Unlock()
	r.f.runtime.mu.Lock()
	trial, identity := r.f.runtime.active, r.f.runtime.identity
	r.f.runtime.mu.Unlock()
	r.f.engine.mu.Lock()
	opens, epoch := r.f.engine.opens, r.f.engine.epoch
	r.f.engine.mu.Unlock()
	request := strings.Repeat("e", 32)
	if err := r.measurement.Start(request, r.plan.packet.targets[0].ID); err != nil {
		t.Fatal(err)
	}
	r.measurement.engine.mu.Lock()
	op := r.measurement.engine.operation
	r.measurement.engine.mu.Unlock()
	if op == nil || op.attempt == nil || op.capture.request.DeadlineAt <= time.Now().UnixMilli() {
		t.Fatal("short lease did not capture original operation")
	}
	deadline := op.capture.request.DeadlineAt
	attempt := op.attempt
	attempt.mu.Lock()
	issuedExpiry := attempt.lease.ExpiresAt
	attempt.mu.Unlock()
	status := r.wait(t)
	if status.Failure == "" {
		t.Fatal("expired captured lease did not report invalidation", status)
	}
	for _, result := range status.Results {
		if result.Ready || result.Benchmark != nil {
			t.Fatal("expired captured lease obtained a score")
		}
	}
	if err := r.measurement.Close(); err != nil {
		t.Fatal(err)
	}
	attempt.mu.Lock()
	renewedExpiry := attempt.lease.ExpiresAt
	attempt.mu.Unlock()
	r.mu.Lock()
	put, deleted, capturedDeadline := r.put, r.deleted, r.capture.Request.DeadlineAt
	admission := r.admission
	r.mu.Unlock()
	if admission == nil {
		t.Fatal("short lease never reached its original admission")
	}
	usage := admission.Snapshot()
	if !renewedExpiry.After(issuedExpiry) || !renewedExpiry.After(time.UnixMilli(deadline)) || capturedDeadline != deadline || op.capture.request.DeadlineAt != deadline || time.Now().UnixMilli() < deadline {
		t.Fatal("renewed lease changed or bypassed original candidate deadline")
	}
	if put != 1 || deleted != 1 || !usage.Retired || !usage.Drained || usage.InFlight || usage.Accepted == 0 || usage.Accepted >= 50 || r.owner.active.Load() || r.payload.Load() != 0 {
		t.Fatal("expired original candidate lost exact joined DELETE", put, deleted, usage)
	}
	r.f.runtime.mu.Lock()
	unchanged := r.f.runtime.active == trial && r.f.runtime.identity == identity
	r.f.runtime.mu.Unlock()
	trial.mu.Lock()
	unchanged = unchanged && trial.attempt == attempt
	trial.mu.Unlock()
	r.f.engine.mu.Lock()
	unchanged = unchanged && r.f.engine.opens == opens && r.f.engine.epoch == epoch
	r.f.engine.mu.Unlock()
	if !unchanged {
		t.Fatal("candidate expiry replaced the original selected runtime")
	}
}

func TestNodeChainExecutionRemoteCandidateRetiresBeforeWholeLease(t *testing.T) {
	r := newRemoteCandidateFixture(t, "server")
	// Reserve a real grant directly on the original service engine, then exercise
	// the actual whole-runtime Close path rather than releasing its activity first.
	e := r.measurement.engine
	e.base.nextID = strings.Repeat("c", 32)
	e.target = r.plan.packet.targets[0]
	release, err := e.BeginMeasurementContext(context.Background())
	if release != nil {
		defer func() {
			r.mu.Lock()
			r.badACK = false
			r.mu.Unlock()
			release()
		}()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := e.VerifyMeasurement(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.badACK = true
	r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	err = r.f.runtime.CloseContext(ctx)
	cancel()
	if err == nil {
		t.Fatal("bad candidate ACK allowed whole lease stop")
	}
	r.mu.Lock()
	leaseDeleted := false
	for _, event := range r.events {
		if event == "lease-delete" {
			leaseDeleted = true
		}
	}
	r.badACK = false
	r.mu.Unlock()
	if leaseDeleted {
		t.Fatal("lease stopped before candidate cleanup")
	}
	release()
	if err := closeRemoteCandidateRuntime(r.f.runtime); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	candidate, lease := -1, -1
	for i, event := range r.events {
		if event == "candidate-delete" {
			candidate = i
		}
		if event == "lease-delete" {
			lease = i
		}
	}
	if candidate < 0 || lease <= candidate {
		t.Fatal("original candidate cleanup ordering", r.events)
	}
}
func TestNodeChainExecutionRemoteCandidatePlanClosedScope(t *testing.T) {
	r := newRemoteCandidateFixture(t, "server")
	inventory := r.plan.packet.inventory
	for _, position := range []int{0, 2, 3, 7} {
		if _, err := r.f.runtime.NewRemoteCandidatePlanContext(context.Background(), position, inventory); err == nil {
			t.Fatal("unsupported remote position", position)
		}
	}
	copy := *r.plan
	if copy.CaptureSHA256() != "" || copy.current(context.Background()) == nil {
		t.Fatal("copied sealed plan admitted")
	}
	if _, err := r.measurement.engine.Dial(context.Background(), r.plan.packet.prefix.Tag, "127.0.0.1:9"); err == nil {
		t.Fatal("caller-selected target admitted")
	}
	for _, execution := range []string{"local", "auto"} {
		t.Run(execution, func(t *testing.T) {
			if execution == "local" {
				// Direct Local has its own runtime. The selected-execution API
				// must reject that setting before it can acquire a Server grant.
				source := nodeChainExecutionFixtureSource(t, 3, "", execution)
				if policy, err := NewNodeChainExecutionPolicy(startJSON(t, source)); err == nil || policy != nil {
					t.Fatal("direct Local admitted by selected execution policy")
				}
				if preparation, err := NewNodeChainExecutionPreparation(source.LocalSource, execution); err == nil || preparation != nil {
					t.Fatal("direct Local admitted by selected execution preparation")
				}
				return
			}
			f := newNodeChainExecutionRuntimeFixture(t, "auto")
			entryRun(t, f, "compare-local")
			f.runtime.mu.Lock()
			trial, identity := f.runtime.active, f.runtime.identity
			f.runtime.mu.Unlock()
			f.engine.mu.Lock()
			opens, epoch := f.engine.opens, f.engine.epoch
			f.engine.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if _, err := f.runtime.NewRemoteCandidatePlanContext(ctx, 1, inventory); err == nil {
				t.Fatal("selected Local substituted for Server grant")
			}
			f.runtime.mu.Lock()
			unchanged := f.runtime.active == trial && f.runtime.identity == identity
			f.runtime.mu.Unlock()
			f.engine.mu.Lock()
			unchanged = unchanged && f.engine.opens == opens && f.engine.epoch == epoch
			f.engine.mu.Unlock()
			if !unchanged {
				t.Fatal("refused Server grant changed the selected Local trial")
			}
		})
	}
}
func TestNodeChainExecutionRemoteCandidateDeadlineIsOriginal(t *testing.T) {
	now := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(time.Minute))
	defer cancel()
	lease := now.Add(15 * time.Second)
	if got := remoteCandidateDeadline(ctx, lease); !got.Equal(lease) {
		t.Fatal("lease expiry extended", got)
	}
	ctx2, cancel2 := context.WithDeadline(context.Background(), now.Add(time.Second))
	defer cancel2()
	got := remoteCandidateDeadline(ctx2, lease)
	want, _ := ctx2.Deadline()
	if got != want {
		t.Fatal("request deadline refreshed")
	}
}

func TestNodeChainExecutionRemoteCandidateStopJoinsOriginalCallbacks(t *testing.T) {
	r := newRemoteCandidateFixture(t, "server")
	e := r.measurement.engine
	e.base.nextID = strings.Repeat("d", 32)
	e.target = r.plan.packet.targets[0]
	release, err := e.BeginMeasurementContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	e.mu.Lock()
	op := e.operation
	e.mu.Unlock()
	entered, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var discarded atomic.Int32
	tag, address := op.capture.Route()
	stop, err := NewOwnedNodeChainExecutionCandidateStop(op.capture, func(ctx context.Context) (net.Conn, error) { return r.f.engine.Dial(ctx, tag, address) }, func(ctx context.Context) error { once.Do(func() { close(entered); <-unblock }); return ctx.Err() }, func() { discarded.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- stop.Stop(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(unblock)
		t.Fatal("original cleanup callback never entered")
	}
	if err := <-result; err == nil {
		close(unblock)
		t.Fatal("held original callback reported cleanup joined")
	}
	stop.Discard()
	if discarded.Load() != 0 {
		close(unblock)
		t.Fatal("failed cleanup released original capability")
	}
	close(unblock)
	retry, cancelRetry := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelRetry()
	if err := stop.Stop(retry); err != nil {
		t.Fatal(err)
	}
	stop.Discard()
	stop.Discard()
	if discarded.Load() != 1 {
		t.Fatal("exact cleanup not discarded once")
	}
}

func TestNodeChainExecutionRemoteCandidateGenericExchangeRemainsClosed(t *testing.T) {
	r := newRemoteCandidateFixture(t, "server")
	e := r.measurement.engine
	e.base.nextID = "private-envelope"
	e.target = r.plan.packet.targets[0]
	release, err := e.BeginMeasurementContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	e.mu.Lock()
	op := e.operation
	e.mu.Unlock()
	if _, err := op.control.exchange(context.Background(), "PUT", nodeChainExecutionCandidatePath, []byte(op.capture.body), 1024); err == nil {
		t.Fatal("generic lease exchange admitted candidate route")
	}
	for _, method := range []string{"GET", "PATCH", "CONNECT"} {
		if _, err := op.control.exchangeCandidate(context.Background(), method, []byte(op.capture.body)); err == nil {
			t.Fatal("open candidate method", method)
		}
	}
	if _, err := op.control.exchangeCandidate(context.Background(), "PUT", []byte(op.capture.body+strings.Repeat(" ", 8192))); err == nil {
		t.Fatal("oversized candidate envelope admitted")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.put != 0 {
		t.Fatal("invalid envelope reached private peer")
	}
}

func closeRemoteCandidateRuntime(runtime *NodeChainExecutionRuntime) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return runtime.CloseContext(ctx)
}

// A value engine can implement the entire runtime/stop contract while its
// dynamic interface value is not comparable. It must never reach equality.
type remoteCandidateNonComparableEngine struct {
	*nodeChainExecutionRuntimeEngine
	uncomparable []byte
}

func TestNodeChainExecutionRemoteCandidateNonComparableEngine(t *testing.T) {
	t.Run("constructor", func(t *testing.T) {
		f := newNodeChainExecutionRuntimeFixture(t, "server")
		engine := remoteCandidateNonComparableEngine{f.engine, []byte{1}}
		runtime, err := NewNodeChainExecutionRuntime(f.runtime.projection, engine)
		if err != nil {
			t.Fatal("actual runtime rejected the complete engine contract", err)
		}
		// Replace only the unused fixture runtime, before Run or any watcher.
		f.runtime = runtime
		f.runtime.testTLS = f.trust
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := f.runtime.Run(ctx); err != nil {
			t.Fatal(err)
		}
		if f.runtime.Progress().Execution != "server" {
			t.Fatal("fixture did not retain selected Server")
		}
		input, _ := candidateSourceFixture(t, "external", "2022-blake3-aes-128-gcm")
		if plan, err := f.runtime.NewRemoteCandidatePlanContext(ctx, 1, candidateInventoryFixture(t, "noncomparable-original", input)); err == nil || plan != nil {
			t.Fatal("non-comparable original engine acquired remote authority")
		}
	})
	t.Run("current", func(t *testing.T) {
		r := newRemoteCandidateFixture(t, "server")
		engine := remoteCandidateNonComparableEngine{r.f.engine, []byte{2}}
		current, err := NewNodeChainExecutionRuntime(r.plan.projection, engine)
		if err != nil {
			t.Fatal(err)
		}
		// Forge only test-owned objects; never replace the running runtime's
		// engine. Equal non-comparable dynamic types previously panicked here.
		plan := *r.plan
		plan.self = &plan
		plan.runtime = current
		plan.engine = engine
		if err := plan.current(context.Background()); err == nil {
			t.Fatal("non-comparable captured/current engine admitted")
		}
	})
}
