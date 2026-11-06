package mobilemultihop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/multihoprelay"
)

// The existing external fixture supplies the real authenticated relay manager,
// challenged acquisition and owned process lifetime. Native source, WFP and TUN
// ownership are separately required by the actual Windows composition gate.
type externalLeaseStopTestEngine struct {
	*externalExecutionEngine
	stopMu sync.Mutex
	captures []LeaseStopCapture
	discards int
	captureFailure string
	ordinaryRetired atomic.Bool
	controlRetired atomic.Bool
	ordinaryDials atomic.Int32
	puts atomic.Int32
	deletes atomic.Int32
}
func (*externalLeaseStopTestEngine) LeaseStopRequired() bool { return true }
func (e *externalLeaseStopTestEngine) Dial(ctx context.Context,tag,address string) (net.Conn,error) {
	e.ordinaryDials.Add(1)
	if e.ordinaryRetired.Load() { return nil,net.ErrClosed }
	return e.externalExecutionEngine.Dial(ctx,tag,address)
}
func (e *externalLeaseStopTestEngine) CaptureLeaseStop(ctx context.Context,capture LeaseStopCapture) (LeaseStop,error) {
	e.stopMu.Lock()
	failure := e.captureFailure
	e.captures = append(e.captures,capture)
	e.stopMu.Unlock()
	if failure == "missing" { return nil,nil }
	if failure == "error" { return nil,errors.New("fixture capture denied") }
	peer := e.entry
	stop,err := NewOwnedLeaseStop(capture,func(ctx context.Context)(net.Conn,error) {
		if e.controlRetired.Load() || e.entry != peer { return nil,net.ErrClosed }
		return (&net.Dialer{}).DialContext(ctx,"tcp",peer.Listener.Addr().String())
	},func(ctx context.Context)error {
		if e.controlRetired.Load() || e.entry != peer { return net.ErrClosed }
		return ctx.Err()
	},func() {
		e.stopMu.Lock()
		e.discards++
		e.stopMu.Unlock()
	})
	if err == nil && failure == "partial" { return stop,errors.New("fixture capture lost after sealing") }
	return stop,err
}
func (e *externalLeaseStopTestEngine) captured() []LeaseStopCapture {
	e.stopMu.Lock()
	defer e.stopMu.Unlock()
	return append([]LeaseStopCapture(nil),e.captures...)
}
type externalLeaseStopHook func(*externalLeaseStopTestEngine,http.ResponseWriter,*http.Request,http.Handler)
func externalLeaseStopFixture(t *testing.T,hook externalLeaseStopHook) (*Controller,*externalLeaseStopTestEngine) {
	t.Helper()
	source,capture := externalExecutionFixture(t,"auto")
	prepared,err := PrepareExternalExecutionCapture(source,capture,"")
	if err != nil { t.Fatal(err) }
	policy,err := NewExternalPolicy(source,prepared)
	if err != nil { t.Fatal(err) }
	base := newExternalExecutionEngine(t,policy)
	e := &externalLeaseStopTestEngine{externalExecutionEngine:base}
	original := base.entry.Config.Handler
	base.entry = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
		if r.Method == "PUT" || r.Method == "DELETE" {
			body,readErr := io.ReadAll(io.LimitReader(r.Body,multihoprelay.MaxControlResponseBytes+1))
			_ = r.Body.Close()
			owned := e.captured()
			var q multihoprelay.Request
			if readErr != nil || len(owned) == 0 || json.Unmarshal(body,&q) != nil ||
				q != owned[len(owned)-1].proposal || string(body) != owned[len(owned)-1].body ||
				r.URL.Path != "/api/multihop/lease" || r.URL.RawQuery != "" ||
				r.Header.Get("Authorization") != "Bearer "+owned[len(owned)-1].token {
				t.Error("mutation preceded its final captured request or changed original authority")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if q.ExternalAuthentication == "" || q.ExternalAttempt == "" || q.ExternalEpoch == "" || q.ExternalExpiresAt == 0 {
				t.Error("sealed request omitted the authenticated challenge")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			if r.Method == "PUT" { e.puts.Add(1) } else { e.deletes.Add(1) }
		}
		if hook != nil { hook(e,w,r,original); return }
		original.ServeHTTP(w,r)
	}))
	t.Cleanup(base.entry.Close)
	c,err := newExternalExecution(policy)
	if err != nil { t.Fatal(err) }
	c.engine,c.engineID = e,e.Identity()
	t.Cleanup(func() { _ = c.release() })
	return c,e
}
func externalLeaseStopNoLiveProcess(t *testing.T,e *externalLeaseStopTestEngine) {
	t.Helper()
	e.runner.mu.Lock()
	processes := append([]*externalExecutionProcess(nil),e.runner.processes...)
	e.runner.mu.Unlock()
	for _,process := range processes {
		if process.Alive() { t.Fatal("authenticated stop retained the original relay process") }
	}
}
func TestExternalLeaseStopSealsBeforeChallengedPUT(t *testing.T) {
	c,e := externalLeaseStopFixture(t,nil)
	if err := c.acquire(context.Background()); err != nil { t.Fatal(err) }
	captures := e.captured()
	if len(captures) != 1 || captures[0].proposal != c.proposal || e.puts.Load() != 1 || !c.ownsLease || c.leaseStop == nil {
		t.Fatal("actual challenged acquisition did not retain its pre-PUT stop capability")
	}
	if err := c.release(); err != nil { t.Fatal(err) }
	if c.ownsLease || c.leaseStop != nil || e.deletes.Load() != 1 || e.discards != 1 {
		t.Fatal("exact stop acknowledgement did not release only the captured attempt")
	}
	externalLeaseStopNoLiveProcess(t,e)
}
func TestExternalLeaseStopCaptureFailurePreventsMutation(t *testing.T) {
	for _,failure := range []string{"missing","error","partial"} {
		t.Run(failure,func(t *testing.T) {
			c,e := externalLeaseStopFixture(t,nil)
			e.captureFailure = failure
			if err := c.acquire(context.Background()); err == nil { t.Fatal("missing required capability permitted acquisition") }
			if e.puts.Load() != 0 || e.deletes.Load() != 0 || c.ownsLease || c.leaseStop != nil {
				t.Fatal("failed pre-acquisition capture mutated remote ownership")
			}
			want := 0
			if failure == "partial" { want = 1 }
			if e.discards != want { t.Fatal("partial original capability was not discarded exactly once") }
		})
	}
}

func TestExternalLeaseStopSurvivesOrdinaryAdmissionCancellation(t *testing.T) {
	c,e := externalLeaseStopFixture(t,nil)
	if err := c.acquire(context.Background()); err != nil { t.Fatal(err) }
	e.ordinaryRetired.Store(true)
	c.invalidate()
	if connection,err := e.Dial(context.Background(),c.meta.EntryTag,"10.77.0.1:8787"); connection != nil || err == nil {
		t.Fatal("fixture ordinary data admission did not retire")
	}
	before := e.ordinaryDials.Load()
	if err := c.release(); err != nil { t.Fatal("sealed original stop failed after data retirement",err) }
	if e.ordinaryDials.Load() != before { t.Fatal("cleanup reentered ordinary Engine.Dial") }
	externalLeaseStopNoLiveProcess(t,e)
}
func TestExternalLeaseStopRetainsAppliedPUTAfterCanceledResponse(t *testing.T) {
	applied := make(chan struct{})
	c,e := externalLeaseStopFixture(t,func(e *externalLeaseStopTestEngine,w http.ResponseWriter,r *http.Request,next http.Handler) {
		if r.Method != "PUT" { next.ServeHTTP(w,r); return }
		record := httptest.NewRecorder()
		next.ServeHTTP(record,r)
		if record.Code != http.StatusOK { t.Error("fixture PUT never applied",record.Code) }
		close(applied)
		<-r.Context().Done()
	})
	ctx,cancel := context.WithTimeout(context.Background(),3*time.Second)
	defer cancel()
	done := make(chan error,1)
	go func(){done <- c.acquire(ctx)}()
	select {
	case <-applied:
	case err := <-done: t.Fatal("acquisition ended before the real PUT applied",err)
	case <-ctx.Done(): t.Fatal("actual PUT did not reach its side-effect receipt")
	}
	cancel()
	select {
	case err := <-done: if err == nil { t.Fatal("canceled acquisition reported acknowledgement") }
	case <-time.After(time.Second): t.Fatal("canceled acquisition did not join")
	}
	if !c.ownsLease || c.leaseStop == nil || e.puts.Load() != 1 { t.Fatal("possibly applied PUT lost original cleanup authority") }
	e.ordinaryRetired.Store(true)
	if err := c.release(); err != nil { t.Fatal(err) }
	externalLeaseStopNoLiveProcess(t,e)
}
func TestExternalLeaseStopRequiresExactAcknowledgementAndRetriesSameOwner(t *testing.T) {
	for _,failure := range []string{"node","session","not-stopped","malformed","oversized","redirect","status"} {
		t.Run(failure,func(t *testing.T) {
			c,e := externalLeaseStopFixture(t,func(e *externalLeaseStopTestEngine,w http.ResponseWriter,r *http.Request,next http.Handler) {
				if r.Method != "DELETE" || e.deletes.Load() != 1 { next.ServeHTTP(w,r); return }
				record := httptest.NewRecorder()
				next.ServeHTTP(record,r)
				if record.Code != http.StatusOK { t.Error("real first stop did not complete",record.Code) }
				switch failure {
				case "malformed": _,_ = io.WriteString(w,"{}{}")
				case "oversized": _,_ = io.WriteString(w,strings.Repeat("x",multihoprelay.LeaseResponseLimit("DELETE")+1))
				case "redirect": w.Header().Set("Location","http://10.77.0.1:8787/not-the-owned-stop"); w.WriteHeader(http.StatusTemporaryRedirect)
				case "status": w.WriteHeader(http.StatusServiceUnavailable)
				default:
					var ack map[string]any
					if json.Unmarshal(record.Body.Bytes(),&ack) != nil { t.Error("fixture stop receipt malformed") }
					if failure == "node" { ack["node_id"] = strings.Repeat("f",64) }
					if failure == "session" { ack["session_id"] = strings.Repeat("f",32) }
					if failure == "not-stopped" { ack["stopped"] = false }
					_ = json.NewEncoder(w).Encode(ack)
				}
			})
			if err := c.acquire(context.Background()); err != nil { t.Fatal(err) }
			sealed,request := c.leaseStop,c.leaseStopCapture
			e.ordinaryRetired.Store(true)
			before := e.ordinaryDials.Load()
			if err := c.release(); err == nil { t.Fatal("unverified stop was accepted") }
			if !c.ownsLease || c.leaseStop != sealed || c.leaseStopCapture != request || e.discards != 0 ||
				c.leaseDeadline.Load() != nil || e.deletes.Load() != 1 {
				t.Fatal("unacknowledged stop lost exact cleanup ownership or retained path proof")
			}
			if err := c.release(); err != nil { t.Fatal("same original stop could not be retried",err) }
			if e.deletes.Load() != 2 || len(e.captured()) != 1 || e.discards != 1 ||
				e.ordinaryDials.Load() != before { t.Fatal("retry replaced its capture or used ordinary data admission") }
			externalLeaseStopNoLiveProcess(t,e)
		})
	}
}

func TestExternalLeaseStopRejectsChangedOriginalRequest(t *testing.T) {
	for _,field := range []string{"api","token","entry","node","proposal","challenge"} {
		t.Run(field,func(t *testing.T) {
			c,e := externalLeaseStopFixture(t,nil)
			if err := c.acquire(context.Background()); err != nil { t.Fatal(err) }
			meta,proposal := c.meta,c.proposal
			switch field {
			case "api": c.meta.EntryAPI = "http://10.77.0.9:8787"
			case "token": c.meta.EntryToken = "other-entry-token"
			case "entry": c.meta.EntryTag = "other-entry"
			case "node": c.meta.EntryNodeID = strings.Repeat("f",64)
			case "proposal": c.proposal.Password = strings.Repeat("f",48)
			case "challenge": c.proposal.ExternalAttempt = strings.Repeat("f",64)
			}
			if err := c.checkLeaseStop(); err == nil { t.Fatal("sealed stop comparator accepted changed original authority") }
			if err := c.renewLocked(context.Background()); err == nil { t.Fatal("renewal accepted changed stop authority") }
			if err := c.release(); err == nil { t.Fatal("release accepted changed stop authority") }
			if e.puts.Load() != 1 || e.deletes.Load() != 0 || !c.ownsLease || c.leaseStop == nil {
				t.Fatal("authority mutation replaced the original remote lease")
			}
			c.meta,c.proposal = meta,proposal
			if err := c.release(); err != nil { t.Fatal(err) }
		})
	}
}
func TestExternalLeaseStopPreservesActiveReleaseAndReacquisition(t *testing.T) {
	c,e := externalLeaseStopFixture(t,nil)
	if err := c.acquire(context.Background()); err != nil { t.Fatal(err) }
	first := c.leaseStopCapture
	if err := c.release(); err != nil { t.Fatal(err) }
	if !c.valid() || e.ordinaryRetired.Load() { t.Fatal("active comparison release retired original data admission") }
	if err := c.acquire(context.Background()); err != nil { t.Fatal("same active comparison could not reacquire",err) }
	second := c.leaseStopCapture
	if first == second || first.proposal.ExternalAttempt == second.proposal.ExternalAttempt ||
		first.proposal.SessionID != second.proposal.SessionID || first.address != second.address ||
		first.token != second.token || e.puts.Load() != 2 || len(e.captured()) != 2 {
		t.Fatal("reacquisition did not preserve the same graph with a fresh authenticated attempt")
	}
	if err := c.release(); err != nil { t.Fatal(err) }
	if e.discards != 2 || e.deletes.Load() != 2 { t.Fatal("comparison lost its separate cleanup attempts") }
	externalLeaseStopNoLiveProcess(t,e)
}
func TestExternalLeaseStopExplicitRejectionDiscardsOnlyInertCapture(t *testing.T) {
	c,e := externalLeaseStopFixture(t,func(_ *externalLeaseStopTestEngine,w http.ResponseWriter,r *http.Request,next http.Handler) {
		if r.Method == "PUT" { w.WriteHeader(http.StatusForbidden); return }
		next.ServeHTTP(w,r)
	})
	if err := c.acquire(context.Background()); err == nil { t.Fatal("explicit rejection succeeded") }
	if c.ownsLease || c.leaseStop != nil || e.discards != 1 || e.deletes.Load() != 0 || !c.valid() {
		t.Fatal("explicit no-lease rejection retained debt or retired active comparison")
	}
}
func TestExternalLeaseStopCannotReviveRetiredControlOwner(t *testing.T) {
	c,e := externalLeaseStopFixture(t,nil)
	if err := c.acquire(context.Background()); err != nil { t.Fatal(err) }
	sealed := c.leaseStop
	e.controlRetired.Store(true)
	if err := c.release(); err == nil { t.Fatal("retired original control owner sent a stop") }
	if e.deletes.Load() != 0 || c.leaseStop != sealed || !c.ownsLease || e.discards != 0 {
		t.Fatal("lost control owner silently dropped or replaced unresolved lease debt")
	}
	// The fixture manager cleanup handles its still-owned process. Do not
	// revive this control capability merely to make test cleanup succeed.
}
