package mobilemultihop

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errExternalLeaseStopIOClose = errors.New("original control stream close did not join")
var errExternalLeaseStopIODial = errors.New("original native control dial returned a retained error-path stream")

type externalLeaseStopIOConn struct {
	net.Conn
	allowClose atomic.Bool
	closes atomic.Int32
	closeEntered chan struct{}
	closeRelease <-chan struct{}
	writeEntered chan struct{}
	readEntered chan struct{}
	readOnce sync.Once
	closeOnce sync.Once
	writeOnce sync.Once
}
func(c *externalLeaseStopIOConn)Read(p []byte)(int,error){
 c.readOnce.Do(func(){if c.readEntered!=nil{close(c.readEntered)}})
 return c.Conn.Read(p)
}
func(c *externalLeaseStopIOConn)Write(p []byte)(int,error){
	c.writeOnce.Do(func(){if c.writeEntered!=nil{close(c.writeEntered)}})
	return c.Conn.Write(p)
}
func(c *externalLeaseStopIOConn)Close()error{
	c.closes.Add(1)
	c.closeOnce.Do(func(){if c.closeEntered!=nil{close(c.closeEntered)}})
	if c.closeRelease!=nil{<-c.closeRelease}
	if !c.allowClose.Load(){return errExternalLeaseStopIOClose}
	return c.Conn.Close()
}
type externalLeaseStopIOFixture struct{
	mu sync.Mutex
	raws []*externalLeaseStopIOConn
	peers []net.Conn
	workers []<-chan struct{}
	calls []<-chan struct{}
	cancels []context.CancelFunc
	requests int
	badRequest bool
	cleaning bool
	dials atomic.Int32
	discards atomic.Int32
	entered chan struct{}
	release chan struct{}
	releaseOnce sync.Once
}
func newExternalLeaseStopIOFixture(t *testing.T,fault string)(*ownedLeaseStop,*externalLeaseStopIOFixture){
	t.Helper()
	graph,metadata:=fixture(t,"server")
	controller,err:=New(graph,metadata)
	if err!=nil{t.Fatal(err)}
	capture,err:=newLeaseStopCapture(controller.meta,controller.proposal)
	if err!=nil{t.Fatal(err)}
	state:=&externalLeaseStopIOFixture{entered:make(chan struct{}),release:make(chan struct{})}
	var retained *ownedLeaseStop
	t.Cleanup(func(){
		state.releaseOnce.Do(func(){close(state.release)})
		state.mu.Lock()
		state.cleaning=true
		cancels:=append([]context.CancelFunc(nil),state.cancels...)
		calls:=append([]<-chan struct{}(nil),state.calls...)
		state.mu.Unlock()
		for _,cancel:=range cancels{cancel()}
		if retained!=nil{retained.Discard()}
		state.mu.Lock()
		raws:=append([]*externalLeaseStopIOConn(nil),state.raws...)
		peers:=append([]net.Conn(nil),state.peers...)
		state.mu.Unlock()
		for _,raw:=range raws{raw.allowClose.Store(true);_ = raw.Conn.Close()}
		for _,peer:=range peers{_ = peer.Close()}
		for _,done:=range calls{select{case <-done:case <-time.After(2*time.Second):t.Error("original Stop caller did not join")}}
		if retained!=nil{
			ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
			defer cancel()
			select{
			case <-retained.gate:
				if retained.pending!=nil{retained.pending.retire();if err:=retained.pending.wait(ctx);err!=nil{t.Error("retained HTTP cleanup did not join",err)}}
				retained.gate<-struct{}{}
			case <-ctx.Done():t.Error("original Stop gate did not join")
			}
		}
		state.mu.Lock()
		raws=append([]*externalLeaseStopIOConn(nil),state.raws...)
		peers=append([]net.Conn(nil),state.peers...)
		workers:=append([]<-chan struct{}(nil),state.workers...)
		state.mu.Unlock()
		for _,raw:=range raws{raw.allowClose.Store(true);_ = raw.Conn.Close()}
		for _,peer:=range peers{_ = peer.Close()}
		for _,done:=range workers{select{case <-done:case <-time.After(2*time.Second):t.Error("original control fixture worker did not join")}}
	})

	owner,err:=NewOwnedLeaseStop(capture,func(ctx context.Context)(net.Conn,error){
		index:=state.dials.Add(1)
		client,peer:=net.Pipe()
		raw:=&externalLeaseStopIOConn{Conn:client,closeEntered:make(chan struct{})}
		raw.allowClose.Store(true)
		if index==1{
			if fault=="close-fails"||fault=="dial-error-close-fails"{raw.allowClose.Store(false)}
			if fault=="held-write"||fault=="held-read"||fault=="held-close"{raw.closeRelease=state.release}
			if fault=="held-read"||fault=="queued-read"{raw.readEntered=state.entered}
			if fault=="held-close"{raw.closeEntered=state.entered}
			if fault=="held-write"{raw.writeEntered=state.entered}
		}
		joined:=make(chan struct{})
		state.mu.Lock()
		if state.cleaning{raw.allowClose.Store(true)}
		state.raws=append(state.raws,raw)
		state.peers=append(state.peers,peer)
		state.workers=append(state.workers,joined)
		state.mu.Unlock()
		if index==1&&fault=="dial-error-close-fails"{
			_ = peer.Close()
			close(joined)
			return raw,errExternalLeaseStopIODial
		}
		if index==1&&fault=="held-dial"{close(state.entered);<-state.release}
		go func(){
			defer close(joined)
			defer peer.Close()
			if index==1&&fault=="held-write"{<-state.release}
			request,err:=http.ReadRequest(bufio.NewReader(peer))
			if err!=nil{return}
			body,err:=io.ReadAll(request.Body)
			_ = request.Body.Close()
			state.mu.Lock()
			state.requests++
			if err!=nil||request.Method!="DELETE"||request.Host!=capture.address||
				request.URL.Path!="/api/multihop/lease"||request.URL.RawQuery!=""||
				request.Header.Get("Authorization")!="Bearer "+capture.token||string(body)!=capture.body{
				state.badRequest=true
			}
			state.mu.Unlock()
			if index==1&&(fault=="held-read"||fault=="queued-read"){<-state.release}
			ack,_:=json.Marshal(map[string]any{"node_id":capture.node,"session_id":capture.proposal.SessionID,"stopped":true})
			_ = (&http.Response{StatusCode:200,ProtoMajor:1,ProtoMinor:1,Header:make(http.Header),ContentLength:int64(len(ack)),Body:io.NopCloser(bytes.NewReader(ack)),Close:true}).Write(peer)
		}()
		return raw,nil
	},func(ctx context.Context)error{return ctx.Err()},func(){state.discards.Add(1)})
	if err!=nil{t.Fatal(err)}
	retained=owner.(*ownedLeaseStop)
	return retained,state
}
func externalLeaseStopIOCall(t *testing.T,owner *ownedLeaseStop)error{
	t.Helper()
	ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
	defer cancel()
	return owner.Stop(ctx)
}
func TestExternalLeaseStopRetainsFailedControlCloseBeforeRetry(t *testing.T){
	for _,fault:=range []string{"close-fails","dial-error-close-fails"}{
		t.Run(fault,func(t *testing.T){
			owner,state:=newExternalLeaseStopIOFixture(t,fault)
			firstErr:=externalLeaseStopIOCall(t,owner)
			if !errors.Is(firstErr,errExternalLeaseStopIOClose)||errors.Is(firstErr,context.DeadlineExceeded){t.Fatal("original close failure was not observed",firstErr)}
			if fault=="dial-error-close-fails"&&!errors.Is(firstErr,errExternalLeaseStopIODial){t.Fatal("original nonnil dial-error cause was lost",firstErr)}
			if owner.pending==nil||state.dials.Load()!=1{t.Fatal("failed original control stream lost retained ownership")}
			pending:=owner.pending
			if err:=externalLeaseStopIOCall(t,owner);!errors.Is(err,errExternalLeaseStopIOClose)||errors.Is(err,context.DeadlineExceeded)||owner.pending!=pending||state.dials.Load()!=1{
				t.Fatal("retry replaced unjoined original control stream",err)
			}
			state.mu.Lock()
			original:=state.raws[0]
			state.mu.Unlock()
			original.allowClose.Store(true)
			if err:=externalLeaseStopIOCall(t,owner);err!=nil{t.Fatal("joined original control could not retry exact stop",err)}
			if owner.pending!=nil||state.dials.Load()!=2{t.Fatal("cleanup retry did not join the original before making one new exact request")}
			state.mu.Lock()
			bad:=state.badRequest
			state.mu.Unlock()
			if bad{t.Fatal("fixed stop request changed its original method, authority or proposal")}
			owner.Discard()
			owner.Discard()
			if state.discards.Load()!=1{t.Fatal("original control discard executed twice")}
		})
	}
}

func TestExternalLeaseStopCanceledControlIOCannotBeReplacedBeforeJoin(t *testing.T){
	for _,fault:=range []string{"held-dial","held-write","held-read"}{
		t.Run(fault,func(t *testing.T){
			owner,state:=newExternalLeaseStopIOFixture(t,fault)
			ctx,cancel:=context.WithCancel(context.Background())
			defer cancel()
			done:=externalLeaseStopIOStart(owner,state,ctx)
			select{case <-state.entered:case <-time.After(3*time.Second):t.Fatal("original fixed control I/O did not enter")}
			cancel()
			select{
			case err:=<-done:if !errors.Is(err,context.Canceled){t.Fatal("original control cancellation changed cause",err)}
			case <-time.After(time.Second):t.Fatal("canceled fixed control waited on its blocked original Close")
			}
			if owner.pending==nil||state.dials.Load()!=1{t.Fatal("canceled original HTTP operation was forgotten")}
			pending:=owner.pending
			retry,stop:=context.WithTimeout(context.Background(),200*time.Millisecond)
			err:=owner.Stop(retry)
			stop()
			if !errors.Is(err,context.DeadlineExceeded)||owner.pending!=pending||state.dials.Load()!=1{
				t.Fatal("fresh request replaced a still-entered original write/read/Close",err)
			}
			state.releaseOnce.Do(func(){close(state.release)})
			if err:=externalLeaseStopIOCall(t,owner);err!=nil{t.Fatal("joined original control could not issue its exact retry",err)}
			if state.dials.Load()!=2||owner.pending!=nil{t.Fatal("same-owner retry did not join both HTTP lifetimes")}
			owner.Discard()
		})
	}
}
func TestExternalLeaseStopDiscardCannotAcceptInFlightAcknowledgement(t *testing.T){
	owner,state:=newExternalLeaseStopIOFixture(t,"held-read")
	ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
	defer cancel()
	done:=externalLeaseStopIOStart(owner,state,ctx)
	select{case <-state.entered:case <-ctx.Done():t.Fatal("original stop did not reach the held response")}
	owner.Discard()
	owner.Discard()
	state.releaseOnce.Do(func(){close(state.release)})
	select{
	case err:=<-done:if err==nil{t.Fatal("discarded original capability accepted an in-flight acknowledgement")}
	case <-ctx.Done():t.Fatal("discarded original stop failed to join")
	}
	if owner.pending!=nil||state.discards.Load()!=1{t.Fatal("discard did not join the original HTTP operation exactly once")}
	if err:=externalLeaseStopIOCall(t,owner);err==nil||state.dials.Load()!=1{
		t.Fatal("retired fixed stop capability admitted another network operation",err)
	}
}

func externalLeaseStopIOStart(owner *ownedLeaseStop,state *externalLeaseStopIOFixture,parent context.Context)<-chan error{
	ctx,cancel:=context.WithTimeout(parent,5*time.Second)
	done:=make(chan struct{})
	result:=make(chan error,1)
	state.mu.Lock()
	state.calls=append(state.calls,done)
	state.cancels=append(state.cancels,cancel)
	state.mu.Unlock()
	go func(){defer close(done);defer cancel();result<-owner.Stop(ctx)}()
	return result
}

type externalLeaseStopQueuedContext struct{
	context.Context
	entered chan struct{}
	once sync.Once
}
func(c *externalLeaseStopQueuedContext)Done()<-chan struct{}{
	c.once.Do(func(){close(c.entered)})
	return c.Context.Done()
}
func TestExternalLeaseStopQueuedCancellationPreservesActiveOriginal(t *testing.T){
	owner,state:=newExternalLeaseStopIOFixture(t,"queued-read")
	ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
	defer cancel()
	first:=externalLeaseStopIOStart(owner,state,ctx)
	select{case <-state.entered:case <-ctx.Done():t.Fatal("original HTTP read never entered")}
	state.mu.Lock()
	original:=state.raws[0]
	state.mu.Unlock()
	queuedBase,stop:=context.WithCancel(ctx)
	defer stop()
	queued:=&externalLeaseStopQueuedContext{Context:queuedBase,entered:make(chan struct{})}
	// Call Stop directly in this worker: its Done observation identifies the
	// original gate wait, rather than child-context construction in a helper.
	result:=make(chan error,1)
	joined:=make(chan struct{})
	state.mu.Lock()
	state.calls=append(state.calls,joined)
	state.cancels=append(state.cancels,stop)
	state.mu.Unlock()
	go func(){defer close(joined);result<-owner.Stop(queued)}()
	select{case <-queued.entered:case <-ctx.Done():t.Fatal("queued Stop did not reach original gate")}
	stop()
	select{
	case err:=<-result:if !errors.Is(err,context.Canceled){t.Fatal("queued cancellation changed cause",err)}
	case <-ctx.Done():t.Fatal("queued Stop did not join")
	}
	if original.closes.Load()!=0||state.dials.Load()!=1||state.discards.Load()!=0||owner.closed.Load(){
		t.Fatal("queued caller mutated the active original")
	}
	select{case err:=<-first:t.Fatal("queued caller ended active Stop",err);default:}
	state.releaseOnce.Do(func(){close(state.release)})
	select{
	case err:=<-first:if err!=nil{t.Fatal("original active Stop lost exact acknowledgement",err)}
	case <-ctx.Done():t.Fatal("original active Stop failed to join after release")
	}
	if owner.pending!=nil||state.dials.Load()!=1{t.Fatal("queued caller replaced the original attempt")}
	owner.Discard()
}

func TestExternalLeaseStopAcknowledgementWaitsForOriginalClose(t *testing.T){
	owner,state:=newExternalLeaseStopIOFixture(t,"held-close")
	ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
	defer cancel()
	done:=externalLeaseStopIOStart(owner,state,ctx)
	select{case <-state.entered:case <-ctx.Done():t.Fatal("exact acknowledged stream never entered original Close")}
	state.mu.Lock()
	original,requests,bad:=state.raws[0],state.requests,state.badRequest
	state.mu.Unlock()
	if requests!=1||bad||original.closes.Load()!=1{t.Fatal("held Close did not belong to one exact DELETE")}
	select{case err:=<-done:t.Fatal("acknowledgement escaped an unjoined original Close",err);default:}
	state.releaseOnce.Do(func(){close(state.release)})
	select{
	case err:=<-done:if err!=nil{t.Fatal("exact acknowledgement failed after original Close joined",err)}
	case <-ctx.Done():t.Fatal("acknowledged original Close did not join")
	}
	if owner.pending!=nil||state.dials.Load()!=1||original.closes.Load()!=1{t.Fatal("acknowledgement changed original stream ownership")}
	owner.Discard()
}
