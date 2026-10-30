//go:build windows

package windowsprotection

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sync/atomic"
	"time"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowscontroller"
)

const journalCommitChannelLimit = 45 * time.Second

// JournalCommitServer is a single captured native child's durable intent
// channel. A pipe name, runtime file, nonce or decoded digest is never a flush
// acknowledgment. Receive proves the actual created child and its pinned image
// before it can append to the separately retained administrative journal.
//
// The caller retains the journal, child and expected image until Close joins.
// current must inspect only captured application/process ownership. Receive
// runs while the child's BFE write transaction is held, so current MUST NOT
// re-enter BFE, close that child, or wait for its transaction to finish.
type JournalCommitServer struct {
	ctx      context.Context
	cancel   context.CancelFunc
	pipe     *windowscontroller.Pipe
	journal  *ProtectionJournal
	capture  JournalCommitCapture
	current  func() error
	state    atomic.Int32 // 0 unused, 1 Receive entered, 2 retiring
	joined   chan struct{}
	retired  chan struct{}
	closeErr error
}

func cloneJournalCommitCapture(capture JournalCommitCapture) (JournalCommitCapture, error) {
	raw, err := CanonicalJournalCommitCapture(capture)
	if err != nil {
		return JournalCommitCapture{}, err
	}
	return ParseJournalCommitCapture(raw)
}

func NewJournalCommitServer(ctx context.Context, journal *ProtectionJournal, capture JournalCommitCapture, current func() error) (*JournalCommitServer, error) {
	if ctx == nil || ctx.Err() != nil || journal == nil || current == nil {
		return nil, errors.New("native journal commit server has no live captured owner")
	}
	capture, err := cloneJournalCommitCapture(capture)
	if err != nil {
		return nil, err
	}
	if err := current(); err != nil {
		return nil, err
	}
	previous, err := CanonicalJournalRecord(capture.Head)
	if err != nil {
		return nil, err
	}
	selection, err := journal.Snapshot(ctx)
	if err != nil || selection.Incomplete || selection.SHA256 != journalCommitDigest(previous) || capture.Head.Controller != journal.controller {
		return nil, errors.Join(err, errors.New("native commit channel changed its retained journal head or creator"))
	}
	actual, err := CanonicalJournalRecord(selection.Record)
	if err != nil || !bytes.Equal(actual, previous) {
		return nil, errors.Join(err, errors.New("native commit channel lost its complete journal capture"))
	}
	pipe, err := windowscontroller.NewPipe()
	if err != nil {
		return nil, err
	}
	owned, cancel := context.WithCancel(ctx)
	server := &JournalCommitServer{ctx: owned, cancel: cancel, pipe: pipe, journal: journal, capture: capture,
		current: current, joined: make(chan struct{}), retired: make(chan struct{})}
	if err := server.currentOwner(); err != nil {
		cancel()
		return nil, errors.Join(err, pipe.Close())
	}
	return server, nil
}

// PipeName is public rendezvous information. It never replaces the inherited
// controller handle, actual kernel peer, retained child or image proof.
func (server *JournalCommitServer) PipeName() string {
	if server == nil || server.pipe == nil || server.state.Load() == 2 {
		return ""
	}
	return server.pipe.Name()
}

func (server *JournalCommitServer) currentOwner() error {
	if server == nil || server.ctx == nil || server.current == nil || server.state.Load() == 2 {
		return errors.New("native journal commit server is retiring")
	}
	if err := server.ctx.Err(); err != nil {
		return err
	}
	if err := server.current(); err != nil {
		return err
	}
	if server.state.Load() == 2 {
		return errors.New("native journal commit server lost its captured operation")
	}
	return server.ctx.Err()
}

// Receive may enter once. A returned nonzero record means its exact bytes were
// flushed/read back; an accompanying error still forbids acknowledgment. A
// caller must preserve that intent and independently settle the joined kernel
// outcome. A successful send is not proof that the BFE transaction committed.
func (server *JournalCommitServer) Receive(child *windowscontroller.GUIChild, expectedImage *windowscontroller.Image) (JournalRecord, error) {
	if server == nil || server.ctx == nil || server.pipe == nil || server.joined == nil || !server.state.CompareAndSwap(0, 1) {
		return JournalRecord{}, errors.New("native journal commit server has no unused captured request")
	}
	defer close(server.joined)
	if child == nil || expectedImage == nil {
		return JournalRecord{}, errors.New("native journal commit request has no exact created child")
	}
	if err := server.currentOwner(); err != nil {
		return JournalRecord{}, err
	}
	ctx, cancel := context.WithTimeout(server.ctx, journalCommitChannelLimit)
	defer cancel()
	if err := child.Alive(); err != nil {
		return JournalRecord{}, err
	}
	if err := server.pipe.Accept(ctx); err != nil {
		return JournalRecord{}, err
	}
	frame, err := server.pipe.ReadFrame(ctx)
	if err != nil {
		return JournalRecord{}, err
	}
	peer, err := child.VerifyPeer(server.pipe, expectedImage)
	if err != nil {
		return JournalRecord{}, err
	}
	engine, identity, err := journalProcessCapture(peer.Process)
	peerCloseErr := peer.Process.Close()
	if err != nil || peerCloseErr != nil || !identity.Elevated || !identity.Administrator {
		return JournalRecord{}, errors.Join(err, peerCloseErr, errors.New("journal commit writer is not its retained elevated engine"))
	}
	request, err := ParseJournalCommitRequest(journalCommitFrame(frame), server.capture)
	if err != nil {
		return JournalRecord{}, err
	}
	intent, err := DeriveJournalCommitIntent(server.capture, request, engine)
	if err != nil {
		return JournalRecord{}, err
	}
	if err := server.currentOwner(); err != nil {
		return JournalRecord{}, err
	}
	if err := child.Alive(); err != nil {
		return JournalRecord{}, err
	}
	intentBytes, err := CanonicalJournalRecord(intent)
	if err != nil {
		return JournalRecord{}, err
	}
	selection, appendErr := server.journal.Append(ctx, intent.PreviousSHA256, intent)
	var durable JournalRecord
	if !selection.Incomplete && selection.SHA256 == journalCommitDigest(intentBytes) {
		actual, err := CanonicalJournalRecord(selection.Record)
		if err == nil && bytes.Equal(actual, intentBytes) {
			durable = cloneJournalRecord(selection.Record)
		}
	}
	if appendErr != nil || durable.Validate() != nil {
		return durable, errors.Join(appendErr, errors.New("native journal commit has no acknowledged exact durable intent"))
	}
	// Publication follows both the actual flush and another exact live-owner
	// check. A late cancellation can leave a durable unresolved intent, but it
	// must never be reported as permission to commit a replacement operation.
	if err := server.currentOwner(); err != nil {
		return durable, err
	}
	confirmed, err := child.VerifyPeer(server.pipe, expectedImage)
	if err != nil {
		return durable, err
	}
	actualEngine, actualIdentity, captureErr := journalProcessCapture(confirmed.Process)
	closeErr := confirmed.Process.Close()
	if captureErr != nil || closeErr != nil || actualEngine != engine || actualIdentity != identity {
		return durable, errors.Join(captureErr, closeErr, errors.New("native journal commit writer changed after persistence"))
	}
	reply, err := NewJournalCommitReply(server.capture, request, engine)
	if err != nil {
		return durable, err
	}
	raw, err := CanonicalJournalCommitReply(reply, server.capture, request, engine)
	if err != nil {
		return durable, err
	}
	if err := server.currentOwner(); err != nil {
		return durable, err
	}
	if err := server.pipe.WriteFrame(ctx, append(raw, '\n')); err != nil {
		return durable, err
	}
	return durable, errors.Join(ctx.Err(), server.currentOwner())
}

func journalCommitFrame(frame []byte) []byte {
	if len(frame) < 2 || len(frame) > JournalCommitWireLimit+1 || frame[len(frame)-1] != '\n' || bytes.Count(frame, []byte{'\n'}) != 1 {
		return nil
	}
	return frame[:len(frame)-1]
}

// Close revokes admission immediately and joins any entered native read or
// durable append. A cancelled waiting caller keeps this same server for retry;
// it may not release the journal, created child or image before the join.
func (server *JournalCommitServer) Close(ctx context.Context) error {
	if server == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("native journal commit server retirement requires a bounded caller")
	}
	if server.cancel == nil || server.retired == nil || server.pipe == nil {
		return errors.New("native journal commit server has no retained retirement owner")
	}
	if previous := server.state.Swap(2); previous != 2 {
		server.cancel()
		go func() {
			server.closeErr = server.pipe.Close()
			if previous == 1 {
				<-server.joined
			}
			close(server.retired)
		}()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-server.retired:
		return server.closeErr
	}
}

// JournalCommitClient owns an inherited exact elevated parent reference and a
// native pipe verified against that process/image. Only this channel can return
// a durable precommit acknowledgment; the staged capture is comparison data.
type JournalCommitClient struct {
	ctx         context.Context
	cancel      context.CancelFunc
	pipe        *windowscontroller.Pipe
	parent      *windowscontroller.Process
	parentImage *windowscontroller.Image
	self        *windowscontroller.Process
	engine      Controller
	capture     JournalCommitCapture
	gate        chan struct{}
	closing     atomic.Bool
	retired     chan struct{}
	closeErr    error
	request     *JournalCommitRequest
	resultReady bool
	resultErr   error
}

// ConnectJournalCommitClient consumes inheritedParent, including on error.
// The caller obtains it with CaptureInheritedElevatedParent before opening any
// native graph. expectedParentImage is borrowed only during this call: the
// client takes its own exact image pin and validates it against the real parent.
// A nonnil partial client must be retained until checked Close succeeds.
func ConnectJournalCommitClient(ctx context.Context, name string, inheritedParent *windowscontroller.Process, expectedParentImage *windowscontroller.Image, capture JournalCommitCapture) (_ *JournalCommitClient, failure error) {
	if ctx == nil {
		if inheritedParent != nil {
			return nil, errors.Join(errors.New("native commit client has no lifetime"), inheritedParent.Close())
		}
		return nil, errors.New("native commit client has no lifetime")
	}
	owned, cancel := context.WithCancel(ctx)
	client := &JournalCommitClient{ctx: owned, cancel: cancel, parent: inheritedParent,
		gate: make(chan struct{}, 1), retired: make(chan struct{})}
	client.gate <- struct{}{}
	defer func() {
		if failure != nil {
			retire, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			failure = errors.Join(failure, client.Close(retire))
		}
	}()
	if inheritedParent == nil || expectedParentImage == nil || ctx.Err() != nil {
		return client, errors.Join(ctx.Err(), errors.New("native commit client has no captured inherited parent and image"))
	}
	var err error
	client.capture, err = cloneJournalCommitCapture(capture)
	if err != nil {
		return client, err
	}
	if err := inheritedParent.VerifyImage(expectedParentImage); err != nil {
		return client, err
	}
	client.parentImage, err = windowscontroller.PinImage(expectedParentImage.Path())
	if err != nil {
		return client, err
	}
	client.self, err = windowscontroller.OpenProcess(uint32(os.Getpid()))
	if err != nil {
		return client, err
	}
	client.engine, _, err = journalProcessCapture(client.self)
	if err != nil {
		return client, err
	}
	if err := client.currentOwner(); err != nil {
		return client, err
	}
	bounded, stop := context.WithTimeout(owned, journalCommitChannelLimit)
	defer stop()
	client.pipe, err = windowscontroller.DialPipe(bounded, name)
	if err != nil {
		return client, err
	}
	peer, err := client.pipe.VerifyPeer(client.parent, client.parentImage)
	if err != nil {
		return client, err
	}
	if err := peer.Process.Close(); err != nil {
		return client, err
	}
	return client, client.currentOwner()
}

func (client *JournalCommitClient) currentOwner() error {
	if client == nil || client.ctx == nil || client.closing.Load() || client.parent == nil || client.parentImage == nil || client.self == nil {
		return errors.New("native journal commit client lost its retained owners")
	}
	if err := client.ctx.Err(); err != nil {
		return err
	}
	parent, parentIdentity, err := journalProcessCapture(client.parent)
	if err != nil || parent != client.capture.Head.Controller || !parentIdentity.Elevated || !parentIdentity.Administrator {
		return errors.Join(err, errors.New("native commit parent changed its exact journal creator"))
	}
	engine, identity, err := journalProcessCapture(client.self)
	if err != nil || engine != client.engine || engine.PID == parent.PID || engine.StartTimeUTCTicks < parent.StartTimeUTCTicks ||
		!identity.Elevated || !identity.Administrator || engine.SID != parent.SID || engine.AuthenticationID != parent.AuthenticationID || engine.SessionID != parent.SessionID {
		return errors.Join(err, errors.New("native commit engine changed its captured elevated identity"))
	}
	if err := client.parent.VerifyImage(client.parentImage); err != nil {
		return err
	}
	if client.closing.Load() {
		return errors.New("native journal commit client is retiring")
	}
	return client.ctx.Err()
}

// Barrier is installed as the actual BFE owner's precommit callback. It sends
// one request for the exact normalized native candidate, and verifies a reply
// independently derived from the captured head and actual engine identity.
// Each channel acknowledges at most one actual native commit attempt. Failed
// exchanges are sticky, and a prior success cannot authorize replay after its
// controller operation retires. A native retry must first independently settle
// the original outcome, preserving that exact intent before another operation.
func (client *JournalCommitClient) Barrier(ctx context.Context, change mobiletor.DesktopWindowsProtectionCommit) error {
	if client == nil || client.ctx == nil || client.gate == nil || ctx == nil || change.Validate() != nil || change.Action != "successor" ||
		!journalCommitSameTarget(change.Previous, client.capture.Transfer.Predecessor) {
		return errors.New("native journal commit changed its captured successor transaction")
	}
	bounded, cancel := context.WithTimeout(ctx, journalCommitChannelLimit)
	stop := context.AfterFunc(client.ctx, cancel)
	defer func() { stop(); cancel() }()
	select {
	case <-bounded.Done():
		return bounded.Err()
	case <-client.gate:
	}
	defer func() { client.gate <- struct{}{} }()
	if err := client.currentOwner(); err != nil {
		return err
	}
	if client.resultReady {
		if client.request == nil || client.request.Candidate != *change.Candidate {
			return errors.New("native journal commit retry substituted its normalized candidate")
		}
		return errors.Join(client.resultErr, bounded.Err(), errors.New("native journal commit acknowledgment has already been consumed"))
	}
	if client.pipe == nil {
		return errors.New("native journal commit has no authenticated parent channel")
	}
	client.resultErr = client.exchange(bounded, *change.Candidate)
	client.resultReady = true
	return client.resultErr
}

func (client *JournalCommitClient) exchange(ctx context.Context, candidate mobiletor.DesktopWindowsProtectionTarget) error {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	rawCapture, err := CanonicalJournalCommitCapture(client.capture)
	if err != nil {
		return err
	}
	request := JournalCommitRequest{Schema: JournalCommitSchema, Kind: JournalCommitRequestKind,
		CaptureSHA256: journalCommitDigest(rawCapture), Nonce: hex.EncodeToString(nonce[:]), Candidate: candidate}
	raw, err := CanonicalJournalCommitRequest(request, client.capture)
	if err != nil {
		return err
	}
	client.request = &request
	peer, err := client.pipe.VerifyPeer(client.parent, client.parentImage)
	if err != nil {
		return err
	}
	if err := peer.Process.Close(); err != nil {
		return err
	}
	if err := client.currentOwner(); err != nil {
		return err
	}
	if err := client.pipe.WriteFrame(ctx, append(raw, '\n')); err != nil {
		return err
	}
	frame, err := client.pipe.ReadFrame(ctx)
	if err != nil {
		return err
	}
	if _, err := ParseJournalCommitReply(journalCommitFrame(frame), client.capture, request, client.engine); err != nil {
		return err
	}
	confirmed, err := client.pipe.VerifyPeer(client.parent, client.parentImage)
	if err != nil {
		return err
	}
	if err := confirmed.Process.Close(); err != nil {
		return err
	}
	return errors.Join(ctx.Err(), client.currentOwner())
}

// Close cancels blocked IPC first, then joins the same callback before releasing
// its inherited process and image pins. All callers share the sticky result;
// cancellation while waiting does not turn unjoined cleanup into success.
func (client *JournalCommitClient) Close(ctx context.Context) error {
	if client == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("native journal commit client retirement requires a bounded caller")
	}
	if client.cancel == nil || client.gate == nil || client.retired == nil {
		return errors.New("native journal commit client has no retained retirement owner")
	}
	if !client.closing.Swap(true) {
		client.cancel()
		go func() {
			if client.pipe != nil {
				client.closeErr = client.pipe.Close()
			}
			<-client.gate
			defer func() { client.gate <- struct{}{} }()
			if client.self != nil {
				client.closeErr = errors.Join(client.closeErr, client.self.Close())
			}
			if client.parent != nil {
				client.closeErr = errors.Join(client.closeErr, client.parent.Close())
			}
			if client.parentImage != nil {
				client.closeErr = errors.Join(client.closeErr, client.parentImage.Close())
			}
			close(client.retired)
		}()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-client.retired:
		return client.closeErr
	}
}
