//go:build windows

package windowsprotection

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowscontroller"
)

// journalCommitAcknowledged is retained only after the exact native request
// received its durable intent reply. It retains comparison copies while the
// caller continues to own the actual child, image and administrative store.
type journalCommitAcknowledged struct {
	request  JournalCommitRequest
	engine   Controller
	identity windowscontroller.TokenIdentity
	intent   JournalRecord
	child    *windowscontroller.GUIChild
	image    *windowscontroller.Image
}

func (ack *journalCommitAcknowledged) verify(pipe *windowscontroller.Pipe) error {
	if ack == nil || ack.child == nil || ack.image == nil || pipe == nil {
		return errors.New("native journal admission has no acknowledged child owner")
	}
	peer, err := ack.child.VerifyPeer(pipe, ack.image)
	if err != nil {
		return err
	}
	engine, identity, captureErr := journalProcessCapture(peer.Process)
	closeErr := peer.Process.Close()
	if captureErr != nil || closeErr != nil || engine != ack.engine || identity != ack.identity {
		return errors.Join(captureErr, closeErr, errors.New("native journal admission changed its acknowledged engine"))
	}
	return nil
}

// Admit is the second, authenticated startup phase. Receive must have finished
// successfully first. The child's native write transaction has ended before it
// sends this request, so this method independently reads the complete prepared
// BFE policy rather than re-entering that earlier write transaction.
//
// A returned nonzero record is a flushed settled checkpoint retaining the live
// engine. An accompanying error forbids startup acknowledgment, but that record
// must still be retained and reconciled with the joined native outcome. Neither
// this checkpoint nor its acknowledgment proves selected-node or DNS readiness.
//
// prepared must record this exact copied checkpoint in the captured host
// attempt before it returns. The engine can create TUN/socket state immediately
// after the reply, so a prepared-only host read cannot be deferred until Admit
// returns. The callback must preserve a partially accepted owner on error and
// must not close or wait for this same channel. Missing callbacks fail closed.
func (server *JournalCommitServer) Admit(ctx context.Context, prepared func(context.Context, JournalRecord) error) (JournalRecord, error) {
	return server.admitCaptured(ctx, func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) error {
		return mobiletor.ReadDesktopWindowsPreparedProtection(ctx, target.Capture, target.Policy, target.BaselineSHA256)
	}, prepared)
}

// The injected read is private and used only by the native IPC/storage fixture.
// This fixture has no application slot to update. The exported entry above
// always performs the actual independent BFE read and requires the host owner.
func (server *JournalCommitServer) admit(ctx context.Context, read func(context.Context, mobiletor.DesktopWindowsProtectionTarget) error) (JournalRecord, error) {
	return server.admitCaptured(ctx, read, func(context.Context, JournalRecord) error { return nil })
}

func (server *JournalCommitServer) admitCaptured(ctx context.Context, read func(context.Context, mobiletor.DesktopWindowsProtectionTarget) error, prepared func(context.Context, JournalRecord) error) (JournalRecord, error) {
	if server == nil || ctx == nil || server.ctx == nil || server.joined == nil || server.admissionJoined == nil || read == nil || prepared == nil {
		return JournalRecord{}, errors.New("native journal admission has no retained controller channel")
	}
	bounded, cancel := context.WithTimeout(ctx, journalCommitChannelLimit)
	stop := context.AfterFunc(server.ctx, cancel)
	defer func() { stop(); cancel() }()
	select {
	case <-bounded.Done():
		return JournalRecord{}, bounded.Err()
	case <-server.joined:
	}
	if !server.state.CompareAndSwap(1, 3) {
		return JournalRecord{}, errors.New("native journal admission cannot reuse or replace its commit phase")
	}
	defer close(server.admissionJoined)
	ack := server.commit
	if ack == nil || ack.intent.Validate() != nil || ack.intent.Intent == nil || ack.intent.Intent.Candidate.Target == nil {
		return JournalRecord{}, errors.New("native journal admission has no successful durable predecessor phase")
	}
	if err := server.currentOwner(); err != nil {
		return JournalRecord{}, err
	}
	if err := ack.verify(server.pipe); err != nil {
		return JournalRecord{}, err
	}
	frame, err := server.pipe.ReadFrame(bounded)
	if err != nil {
		return JournalRecord{}, err
	}
	request, err := ParseJournalAdmissionRequest(journalCommitFrame(frame), ack.intent)
	if err != nil {
		return JournalRecord{}, err
	}
	if err := ack.verify(server.pipe); err != nil {
		return JournalRecord{}, err
	}
	if err := server.currentOwner(); err != nil {
		return JournalRecord{}, err
	}
	target := *ack.intent.Intent.Candidate.Target
	if err := read(bounded, target); err != nil {
		return JournalRecord{}, err
	}
	if err := server.currentOwner(); err != nil {
		return JournalRecord{}, err
	}
	if err := ack.verify(server.pipe); err != nil {
		return JournalRecord{}, err
	}
	settled, err := DeriveJournalAdmissionSettlement(ack.intent)
	if err != nil {
		return JournalRecord{}, err
	}
	settledBytes, err := CanonicalJournalRecord(settled)
	if err != nil {
		return JournalRecord{}, err
	}
	attempted := cloneJournalRecord(settled)
	server.attempted = &attempted
	selection, appendErr := server.journal.Append(bounded, settled.PreviousSHA256, settled)
	var durable JournalRecord
	if !selection.Incomplete && selection.SHA256 == journalCommitDigest(settledBytes) {
		actual, err := CanonicalJournalRecord(selection.Record)
		if err == nil && bytes.Equal(actual, settledBytes) {
			durable = cloneJournalRecord(selection.Record)
		}
	}
	if appendErr != nil || durable.Validate() != nil {
		return durable, errors.Join(appendErr, errors.New("native journal admission has no exact durable live-engine checkpoint"))
	}
	// The independent read brackets persistence. A replacement or failed
	// readback after a flush retains this checkpoint but sends no permission.
	if err := read(bounded, target); err != nil {
		return durable, err
	}
	if err := server.currentOwner(); err != nil {
		return durable, err
	}
	if err := ack.verify(server.pipe); err != nil {
		return durable, err
	}
	reply, err := NewJournalAdmissionReply(ack.intent, request)
	if err != nil {
		return durable, err
	}
	raw, err := CanonicalJournalAdmissionReply(reply, ack.intent, request)
	if err != nil {
		return durable, err
	}
	if err := prepared(bounded, cloneJournalRecord(durable)); err != nil {
		return durable, err
	}
	if err := server.currentOwner(); err != nil {
		return durable, err
	}
	if err := ack.verify(server.pipe); err != nil {
		return durable, err
	}
	if err := server.pipe.WriteFrame(bounded, append(raw, '\n')); err != nil {
		return durable, err
	}
	return durable, errors.Join(bounded.Err(), server.currentOwner())
}

// DrainAttempt is a same-owner journal cleanup operation after checked Close.
// It can complete only this channel's last immutable append, including a write
// whose flush failed before any reply. It sends no acknowledgment and cannot
// commit, remove or discover BFE policy. A caller must still join the actual
// engine and independently settle its exact kernel outcome before replacing
// the app's protection slot or opening another journal channel.
//
// Zero with nil error means this channel never attempted a journal write.
// Nonzero means these exact bytes were flushed/read back; a late error still
// preserves that record. Cancellation keeps the same channel/store for retry.
func (server *JournalCommitServer) DrainAttempt(ctx context.Context) (JournalRecord, error) {
	if server == nil || ctx == nil || server.journal == nil || server.retired == nil || server.state.Load() != 2 {
		return JournalRecord{}, errors.New("native journal attempt has no joined channel owner")
	}
	select {
	case <-server.retired:
	default:
		return JournalRecord{}, errors.New("native journal attempt cannot drain an entered callback")
	}
	if server.closeErr != nil {
		return JournalRecord{}, errors.Join(server.closeErr, errors.New("native journal channel retirement remains unproved"))
	}
	if err := ctx.Err(); err != nil {
		return JournalRecord{}, err
	}
	if server.attempted == nil {
		return JournalRecord{}, nil
	}
	attempted := cloneJournalRecord(*server.attempted)
	raw, err := CanonicalJournalRecord(attempted)
	if err != nil {
		return JournalRecord{}, err
	}
	exact := func(selection JournalSelection) (JournalRecord, bool) {
		if selection.Incomplete || selection.SHA256 != journalCommitDigest(raw) {
			return JournalRecord{}, false
		}
		actual, err := CanonicalJournalRecord(selection.Record)
		if err != nil || !bytes.Equal(actual, raw) {
			return JournalRecord{}, false
		}
		return cloneJournalRecord(selection.Record), true
	}
	selection, readErr := server.journal.Snapshot(ctx)
	if durable, ok := exact(selection); ok {
		return durable, errors.Join(readErr, ctx.Err())
	}
	// Append independently checks its retained current slot, creator, native
	// file identities and exact pending bytes. A different/newer append cannot
	// be adopted or overwritten by this old channel's cleanup.
	selection, appendErr := server.journal.Append(ctx, attempted.PreviousSHA256, attempted)
	if durable, ok := exact(selection); ok {
		return durable, appendErr
	}
	return JournalRecord{}, errors.Join(readErr, appendErr, errors.New("native journal attempt still lacks its exact durable bytes"))
}

// Admit runs after the native owner committed and independently read its exact
// prepared target, before any TUN or physical socket can open. The same pipe
// and inherited parent remain retained across both phases; staged files and
// decoded hashes cannot substitute for this authenticated acknowledgment.
func (client *JournalCommitClient) Admit(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) error {
	if client == nil || client.ctx == nil || client.gate == nil || ctx == nil || target.Validate() != nil {
		return errors.New("native journal admission has no exact prepared owner")
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
	if !client.resultReady || client.resultErr != nil || client.request == nil || client.request.Candidate != target {
		return errors.New("native journal admission changed or skipped its exact acknowledged commit")
	}
	if client.admissionAttempted {
		return errors.Join(client.admissionErr, bounded.Err(), errors.New("native journal admission acknowledgment has already been consumed"))
	}
	client.admissionAttempted = true
	client.admissionErr = client.exchangeAdmission(bounded)
	return client.admissionErr
}

func (client *JournalCommitClient) exchangeAdmission(ctx context.Context) error {
	if client.pipe == nil {
		return errors.New("native journal admission lost its authenticated commit pipe")
	}
	intent, err := DeriveJournalCommitIntent(client.capture, *client.request, client.engine)
	if err != nil {
		return err
	}
	intentRaw, err := CanonicalJournalRecord(intent)
	if err != nil {
		return err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	request := JournalAdmissionRequest{Schema: JournalAdmissionSchema, Kind: JournalAdmissionRequestKind,
		IntentSHA256: journalCommitDigest(intentRaw), Nonce: hex.EncodeToString(nonce[:])}
	raw, err := CanonicalJournalAdmissionRequest(request, intent)
	if err != nil {
		return err
	}
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
	if _, err := ParseJournalAdmissionReply(journalCommitFrame(frame), intent, request); err != nil {
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
