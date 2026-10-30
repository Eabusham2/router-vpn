//go:build windows && routervpn_windows_protection_native

package windowsprotection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowscontroller"
)

type journalChannelReport struct {
	Stage, Pipe, Failure string
	Accepted, Replayed   bool
	Closed, Forged       bool
}

func journalChannelWrite(ctx context.Context, pipe *windowscontroller.Pipe, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return pipe.WriteFrame(ctx, append(raw, '\n'))
}

func journalChannelRead(ctx context.Context, pipe *windowscontroller.Pipe) (journalChannelReport, error) {
	raw, err := pipe.ReadFrame(ctx)
	if err != nil {
		return journalChannelReport{}, err
	}
	var report journalChannelReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return journalChannelReport{}, err
	}
	return report, nil
}

func journalChannelCandidate(capture JournalCommitCapture) mobiletor.DesktopWindowsProtectionTarget {
	return mobiletor.DesktopWindowsProtectionTarget{Capture: mobiletor.DesktopSocketCapture{
		SessionID: capture.Transfer.SessionID, SourceSHA256: capture.Transfer.SourceSHA256, NetworkID: strings.Repeat("a", 32)},
		Policy: capture.Transfer.Policy, BaselineSHA256: strings.Repeat("b", 64)}
}

// Every role is an actual created process. The only modeled fact is the BFE
// candidate: this gate proves the authenticated durable IPC, not Firewall
// execution. It never opens the production machine journal or changes routes.
func TestWindowsProtectionJournalChannelFixture(t *testing.T) {
	arguments := flag.Args()
	if len(arguments) == 0 {
		return
	}
	if len(arguments) != 8 {
		t.Fatal("journal channel fixture requires its fixed public arguments")
	}
	if err := runJournalChannelFixture(arguments); err != nil {
		_ = os.WriteFile(arguments[7], []byte(err.Error()), 0600)
		t.Fatal(err)
	}
}

func runJournalChannelFixture(arguments []string) error {
	mode, production, control, handleText, imagePath, capturePath, digest := arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6]
	if mode != "client" && mode != "forger" && mode != "hold" {
		return errors.New("journal channel fixture selected an unknown role")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	pipe, err := windowscontroller.DialPipe(ctx, control)
	if err != nil {
		return err
	}
	defer pipe.Close()
	if mode == "hold" {
		if err := journalChannelWrite(ctx, pipe, journalChannelReport{Stage: "held"}); err != nil {
			return err
		}
		frame, err := pipe.ReadFrame(ctx)
		if err != nil || string(frame) != "finish\n" {
			return errors.Join(err, errors.New("held journal fixture lost its exact retirement request"))
		}
		return nil
	}
	raw, err := os.ReadFile(capturePath)
	if err != nil || len(raw) > JournalCommitCaptureLimit {
		return errors.Join(err, errors.New("journal fixture capture exceeds its fixed bound"))
	}
	actualDigest, err := JournalCommitCaptureSHA256(raw)
	if err != nil || actualDigest != digest {
		return errors.Join(err, errors.New("journal fixture capture lost its launch digest"))
	}
	capture, err := ParseJournalCommitCapture(raw)
	if err != nil {
		return err
	}
	if mode == "forger" {
		return runForgedJournalChannel(ctx, pipe, capture)
	}
	value, err := strconv.ParseUint(handleText, 10, 64)
	if err != nil || strconv.FormatUint(value, 10) != handleText {
		return errors.New("journal fixture inherited parent spelling is invalid")
	}
	parent, captureErr := windowscontroller.CaptureInheritedElevatedParent(value)
	var client *JournalCommitClient
	var expectedImage *windowscontroller.Image
	var resultErr error
	if captureErr != nil {
		resultErr = captureErr
	} else {
		expectedImage, err = windowscontroller.PinImage(imagePath)
		if err != nil {
			resultErr = errors.Join(err, parent.Close())
		} else {
			client, resultErr = ConnectJournalCommitClient(ctx, production, parent, expectedImage, capture)
		}
	}
	report := journalChannelReport{Stage: "client"}
	if resultErr == nil {
		candidate := journalChannelCandidate(capture)
		change := mobiletor.DesktopWindowsProtectionCommit{Action: "successor", Previous: capture.Transfer.Predecessor, Candidate: &candidate}
		resultErr = client.Barrier(ctx, change)
		report.Accepted = resultErr == nil
		report.Replayed = client.Barrier(ctx, change) == nil
	}
	if resultErr != nil {
		report.Failure = resultErr.Error()
		if len(report.Failure) > 1024 {
			report.Failure = report.Failure[:1024]
		}
	}
	retire, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	if client != nil {
		if err := client.Close(retire); err != nil {
			return errors.Join(err, errors.New("journal fixture client did not join its exact channel"))
		}
	}
	if expectedImage != nil {
		if err := expectedImage.Close(); err != nil {
			return err
		}
	}
	report.Closed = true
	if err := journalChannelWrite(ctx, pipe, report); err != nil {
		return err
	}
	frame, err := pipe.ReadFrame(ctx)
	if err != nil || string(frame) != "finish\n" {
		return errors.Join(err, errors.New("journal fixture lost its exact completion request"))
	}
	return nil
}

func runForgedJournalChannel(ctx context.Context, control *windowscontroller.Pipe, capture JournalCommitCapture) error {
	pipe, err := windowscontroller.NewPipe()
	if err != nil {
		return err
	}
	defer pipe.Close()
	if err := journalChannelWrite(ctx, control, journalChannelReport{Stage: "forger-ready", Pipe: pipe.Name()}); err != nil {
		return err
	}
	if err := pipe.Accept(ctx); err != nil {
		return err
	}
	frame, readErr := pipe.ReadFrame(ctx)
	report := journalChannelReport{Stage: "forger-finished"}
	if readErr == nil {
		request, err := ParseJournalCommitRequest(journalCommitFrame(frame), capture)
		if err != nil {
			return err
		}
		peer, err := pipe.Peer()
		if err != nil {
			return err
		}
		engine, _, captureErr := journalProcessCapture(peer.Process)
		closeErr := peer.Process.Close()
		if captureErr != nil || closeErr != nil {
			return errors.Join(captureErr, closeErr)
		}
		// Deliberately derive the exact public reply WITHOUT a journal write.
		// Only the client's actual inherited-parent peer check distinguishes it.
		reply, err := NewJournalCommitReply(capture, request, engine)
		if err != nil {
			return err
		}
		raw, err := CanonicalJournalCommitReply(reply, capture, request, engine)
		if err != nil {
			return err
		}
		if err := pipe.WriteFrame(ctx, append(raw, '\n')); err != nil {
			return err
		}
		report.Forged = true
	}
	if err := journalChannelWrite(ctx, control, report); err != nil {
		return err
	}
	frame, err = control.ReadFrame(ctx)
	if err != nil || string(frame) != "finish\n" {
		return errors.Join(err, errors.New("forged journal fixture lost its exact completion request"))
	}
	return nil
}

type journalChannelChild struct {
	child      *windowscontroller.GUIChild
	pipe       *windowscontroller.Pipe
	diagnostic string
}

type journalChannelNative struct {
	input                          *journalNativeFixture
	store                          *ProtectionJournal
	ctx                            context.Context
	cancel                         context.CancelFunc
	image                          *windowscontroller.Image
	directory, capturePath, digest string
	capture                        JournalCommitCapture
	server                         *JournalCommitServer
	children                       []*journalChannelChild
	result                         chan journalChannelResult
}

type journalChannelResult struct {
	record JournalRecord
	err    error
}

func newJournalChannelNative(t *testing.T, current func(*ProtectionJournal) error) *journalChannelNative {
	t.Helper()
	input := journalNativeInputs(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	fixture := &journalChannelNative{input: input, ctx: ctx, cancel: cancel, directory: t.TempDir(), result: make(chan journalChannelResult, 1)}
	t.Cleanup(func() {
		if err := fixture.close(); err != nil {
			t.Error("journal channel retained native cleanup failure", err)
			if err := fixture.close(); err != nil {
				t.Error("journal channel cleanup retry remains owned", err)
			}
		}
	})
	var err error
	fixture.store, err = createProtectionJournal(ctx, input.machine, input.desktop, input.data, input.initialRead)
	if err != nil || fixture.store == nil {
		t.Fatal("journal channel did not create its real protected private store", err)
	}
	selection, err := fixture.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	capture, _, _ := journalCommitFixture(t, false)
	capture.Head = selection.Record
	fixture.capture = capture
	raw, err := CanonicalJournalCommitCapture(capture)
	if err != nil {
		t.Fatal(err)
	}
	fixture.digest, err = JournalCommitCaptureSHA256(raw)
	if err != nil {
		t.Fatal(err)
	}
	fixture.capturePath = filepath.Join(fixture.directory, "capture.json")
	if err := os.WriteFile(fixture.capturePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	fixture.image, err = windowscontroller.PinCurrentImage()
	if err != nil {
		t.Fatal(err)
	}
	guard := func() error {
		if current == nil {
			return nil
		}
		return current(fixture.store)
	}
	fixture.server, err = NewJournalCommitServer(ctx, fixture.store, capture, guard)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *journalChannelNative) close() error {
	if fixture.cancel != nil {
		fixture.cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if fixture.server != nil {
		if err := fixture.server.Close(ctx); err != nil {
			return err
		}
	}
	for _, child := range fixture.children {
		if child.pipe != nil {
			if err := child.pipe.Close(); err != nil {
				return err
			}
		}
		if child.child != nil {
			if err := child.child.Close(ctx); err != nil {
				return err
			}
		}
	}
	if fixture.image != nil {
		if err := fixture.image.Close(); err != nil {
			return err
		}
	}
	if fixture.store != nil {
		return fixture.store.Close()
	}
	return nil
}

func (fixture *journalChannelNative) launch(t *testing.T, role, production string) *journalChannelChild {
	t.Helper()
	owned := &journalChannelChild{diagnostic: filepath.Join(fixture.directory, fmt.Sprintf("child-%d.txt", len(fixture.children)))}
	fixture.children = append(fixture.children, owned)
	var err error
	owned.pipe, err = windowscontroller.NewPipe()
	if err != nil {
		t.Fatal(err)
	}
	paths, err := windowscontroller.MachineDirectories()
	if err != nil {
		t.Fatal(err)
	}
	environment := []string{"SystemRoot=" + paths.Windows, "SystemDrive=" + paths.SystemDrive, "TEMP=" + fixture.directory, "TMP=" + fixture.directory, "GORACE=atexit_sleep_ms=0"}
	owned.child, err = windowscontroller.LaunchGUIChild(fixture.ctx, fixture.image, func(parent uint64) ([]string, error) {
		return []string{"-test.run=^TestWindowsProtectionJournalChannelFixture$", "-test.count=1", "-test.timeout=50s", "--",
			role, production, owned.pipe.Name(), strconv.FormatUint(parent, 10), fixture.image.Path(), fixture.capturePath, fixture.digest, owned.diagnostic}, nil
	}, environment, fixture.directory)
	if err != nil || owned.child == nil {
		t.Fatal("journal channel fixture launch failed", err)
	}
	return owned
}

func (fixture *journalChannelNative) receive(expected *journalChannelChild) {
	go func() {
		record, err := fixture.server.Receive(expected.child, fixture.image)
		fixture.result <- journalChannelResult{record, err}
		if err != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = fixture.server.Close(ctx)
		}
	}()
}

func (fixture *journalChannelNative) report(t *testing.T, child *journalChannelChild, first bool) journalChannelReport {
	t.Helper()
	diagnostic := func() string { raw, _ := os.ReadFile(child.diagnostic); return string(raw) }
	if first {
		if err := child.pipe.Accept(fixture.ctx); err != nil {
			t.Fatal("journal fixture report did not connect", err, diagnostic())
		}
	}
	report, err := journalChannelRead(fixture.ctx, child.pipe)
	if err != nil {
		t.Fatal("journal fixture did not report its actual channel outcome", err, diagnostic())
	}
	peer, err := child.child.VerifyPeer(child.pipe, fixture.image)
	if err != nil {
		t.Fatal("journal fixture report came from another process", err)
	}
	if err := peer.Process.Close(); err != nil {
		t.Fatal(err)
	}
	return report
}

func (fixture *journalChannelNative) finish(t *testing.T, child *journalChannelChild) {
	t.Helper()
	if err := child.pipe.WriteFrame(fixture.ctx, []byte("finish\n")); err != nil {
		t.Fatal(err)
	}
	if code, err := child.child.Wait(fixture.ctx); err != nil || code != 0 {
		raw, _ := os.ReadFile(child.diagnostic)
		t.Fatal("journal fixture did not exit after checked channel retirement", code, err, string(raw))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := child.child.Close(ctx); err != nil {
		t.Fatal("journal fixture actual Job did not join", err)
	}
}

func (fixture *journalChannelNative) received(t *testing.T) journalChannelResult {
	t.Helper()
	select {
	case result := <-fixture.result:
		return result
	case <-fixture.ctx.Done():
		t.Fatal("journal channel receiver did not join", fixture.ctx.Err())
		return journalChannelResult{}
	}
}

func TestWindowsProtectionJournalChannelActualCommit(t *testing.T) {
	fixture := newJournalChannelNative(t, nil)
	child := fixture.launch(t, "client", fixture.server.PipeName())
	fixture.receive(child)
	report := fixture.report(t, child, true)
	result := fixture.received(t)
	if !report.Accepted || report.Replayed || !report.Closed || report.Failure != "" || result.err != nil || result.record.Validate() != nil {
		t.Fatal("native journal channel did not acknowledge one exact flushed intent", report, result.err)
	}
	selection, err := fixture.store.Snapshot(fixture.ctx)
	if err != nil || selection.Incomplete || selection.Record.Sequence != 2 || selection.Record.Phase != "intent" || selection.Record.Intent.Candidate.Engine.PID != child.child.PID() {
		t.Fatal("native journal channel reply did not bind its actual durable engine", err)
	}
	actual, _ := CanonicalJournalRecord(selection.Record)
	returned, _ := CanonicalJournalRecord(result.record)
	if !bytes.Equal(actual, returned) {
		t.Fatal("native journal receiver returned another acknowledged intent")
	}
	fixture.finish(t, child)
}

func TestWindowsProtectionJournalChannelRejectsForgedServer(t *testing.T) {
	fixture := newJournalChannelNative(t, nil)
	forger := fixture.launch(t, "forger", "unused")
	ready := fixture.report(t, forger, true)
	if ready.Stage != "forger-ready" || ready.Pipe == "" {
		t.Fatal("forged server did not create its actual separate pipe")
	}
	child := fixture.launch(t, "client", ready.Pipe)
	report := fixture.report(t, child, true)
	forged := fixture.report(t, forger, false)
	if report.Accepted || report.Replayed || !report.Closed || report.Failure == "" || forged.Forged {
		t.Fatal("forged native pipe acknowledged an unflushed journal intent", report, forged)
	}
	selection, err := fixture.store.Snapshot(fixture.ctx)
	if err != nil || selection.Record.Sequence != 1 || selection.Record.Phase != "settled" {
		t.Fatal("forged server changed the actual journal", err)
	}
	fixture.finish(t, child)
	fixture.finish(t, forger)
}

func TestWindowsProtectionJournalChannelRejectsDifferentChild(t *testing.T) {
	fixture := newJournalChannelNative(t, nil)
	other := fixture.launch(t, "hold", "unused")
	if report := fixture.report(t, other, true); report.Stage != "held" {
		t.Fatal("replacement child was not actually retained")
	}
	child := fixture.launch(t, "client", fixture.server.PipeName())
	fixture.receive(other)
	report := fixture.report(t, child, true)
	result := fixture.received(t)
	if report.Accepted || report.Replayed || !report.Closed || result.err == nil || result.record.Validate() == nil {
		t.Fatal("another actual child acquired the journal commit owner", report, result.err)
	}
	selection, err := fixture.store.Snapshot(fixture.ctx)
	if err != nil || selection.Record.Sequence != 1 {
		t.Fatal("wrong-child rejection wrote a journal intent", err)
	}
	fixture.finish(t, child)
	fixture.finish(t, other)
}

func TestWindowsProtectionJournalChannelFailedPersistence(t *testing.T) {
	fixture := newJournalChannelNative(t, nil)
	file := fixture.store.slots[1]
	original := file.handle
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	var limited syscall.Handle
	if err := syscall.DuplicateHandle(process, original, process, &limited, 0x00120089, false, 0); err != nil {
		t.Fatal(err)
	}
	file.handle = limited
	defer func() { file.handle = original; _ = syscall.CloseHandle(limited) }()
	child := fixture.launch(t, "client", fixture.server.PipeName())
	fixture.receive(child)
	report := fixture.report(t, child, true)
	result := fixture.received(t)
	if report.Accepted || report.Replayed || !report.Closed || result.err == nil || fixture.store.pending == nil {
		t.Fatal("failed native journal persistence produced a commit acknowledgment", report, result.err)
	}
	if _, err := fixture.store.Snapshot(fixture.ctx); err == nil {
		t.Fatal("failed channel append forgot its pending write")
	}
	fixture.finish(t, child)
}

func TestWindowsProtectionJournalChannelLateReplacement(t *testing.T) {
	var rejected atomic.Bool
	fixture := newJournalChannelNative(t, func(store *ProtectionJournal) error {
		selection, err := store.Snapshot(context.Background())
		if err != nil {
			return err
		}
		if selection.Record.Phase == "intent" {
			rejected.Store(true)
			return errors.New("captured application operation was replaced after persistence")
		}
		return nil
	})
	child := fixture.launch(t, "client", fixture.server.PipeName())
	fixture.receive(child)
	report := fixture.report(t, child, true)
	result := fixture.received(t)
	if !rejected.Load() || report.Accepted || report.Replayed || !report.Closed || result.err == nil || result.record.Validate() != nil {
		t.Fatal("late application replacement acquired a persisted native commit acknowledgment", report, result.err)
	}
	selection, err := fixture.store.Snapshot(fixture.ctx)
	if err != nil || selection.Record.Phase != "intent" || selection.Record.Sequence != 2 {
		t.Fatal("late rejection erased its actual durable unresolved intent", err)
	}
	fixture.finish(t, child)
}

func TestWindowsProtectionJournalChannelCloseJoinsAppend(t *testing.T) {
	entered, resume := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	defer release()
	var armed atomic.Bool
	var fixture *journalChannelNative
	var child *journalChannelChild
	fixture = newJournalChannelNative(t, func(_ *ProtectionJournal) error {
		if !armed.Load() {
			return nil
		}
		// Hold the actual authenticated pre-append boundary. Blocking the
		// first Receive guard instead could close the pipe before the child
		// connects, leaving it in a fresh DialPipe wait rather than exercising
		// cancellation of the entered native request.
		peer, err := child.child.VerifyPeer(fixture.server.pipe, fixture.image)
		if err != nil {
			return nil
		}
		if err := peer.Process.Close(); err != nil {
			return err
		}
		if armed.CompareAndSwap(true, false) {
			close(entered)
			<-resume
		}
		return nil
	})
	child = fixture.launch(t, "client", fixture.server.PipeName())
	armed.Store(true)
	fixture.receive(child)
	select {
	case <-entered:
	case <-fixture.ctx.Done():
		t.Fatal("journal receiver did not enter its captured pre-append guard")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := fixture.server.Close(cancelled); !errors.Is(err, context.Canceled) {
		release()
		t.Fatal("cancelled close acknowledged an unjoined journal callback", err)
	}
	select {
	case <-fixture.server.retired:
		release()
		t.Fatal("journal server retired before its entered callback joined")
	default:
	}
	release()
	report := fixture.report(t, child, true)
	result := fixture.received(t)
	joined, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	if err := fixture.server.Close(joined); err != nil {
		t.Fatal("same journal server did not join after callback release", err)
	}
	if report.Accepted || report.Replayed || !report.Closed || result.err == nil {
		t.Fatal("cancelled entered journal callback acknowledged a commit", report, result.err)
	}
	selection, err := fixture.store.Snapshot(context.Background())
	if err != nil || selection.Record.Sequence != 1 {
		t.Fatal("cancelled before-append receiver changed durable intent", err)
	}
	fixture.finish(t, child)
}

// These two fixtures isolate entered-callback lifetime with deterministic Go
// channels while retaining actual Windows pipe/process handles. The real
// Receive cancellation case above separately exercises the shipping call path.
// They do not manufacture a successful native authentication or journal write.
func TestWindowsProtectionJournalChannelRetirementOwnership(t *testing.T) {
	protectionRequireNative(t)
	t.Run("server", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			pipe, err := windowscontroller.NewPipe()
			if err != nil {
				t.Fatal(err)
			}
			server := &JournalCommitServer{ctx: ctx, cancel: cancel, pipe: pipe, joined: make(chan struct{}), retired: make(chan struct{})}
			release := sync.OnceFunc(func() { close(server.joined) })
			defer release()
			server.state.Store(1) // Explicit modeled entry, never an authority receipt.
			result := make(chan error, 1)
			go func() { result <- server.Close(context.Background()) }()
			synctest.Wait()
			select {
			case err := <-result:
				release()
				t.Fatal("journal server acknowledged retirement before its entered callback joined", err)
			default:
			}
			release()
			synctest.Wait()
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if err := server.Close(context.Background()); err != nil {
				t.Fatal("duplicate journal server close lost its joined result", err)
			}
		})
	})
	t.Run("client", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			pipe, err := windowscontroller.NewPipe()
			if err != nil {
				t.Fatal(err)
			}
			self, err := windowscontroller.OpenProcess(uint32(os.Getpid()))
			if err != nil {
				_ = pipe.Close()
				t.Fatal(err)
			}
			client := &JournalCommitClient{ctx: ctx, cancel: cancel, pipe: pipe, self: self, gate: make(chan struct{}, 1), retired: make(chan struct{})}
			release := sync.OnceFunc(func() {
				select {
				case client.gate <- struct{}{}:
				default:
				}
			})
			defer release()
			// No gate token means one explicitly held callback; no live client
			// or kernel mutation is inferred from this modeled admission.
			result := make(chan error, 1)
			go func() { result <- client.Close(context.Background()) }()
			synctest.Wait()
			select {
			case err := <-result:
				t.Fatal("journal client acknowledged retirement before its callback joined", err)
			default:
			}
			if err := self.Alive(); err != nil {
				t.Fatal("journal client released its actual process handle before callback join", err)
			}
			release()
			synctest.Wait()
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if !errors.Is(self.Alive(), windowscontroller.ErrClosed) {
				t.Fatal("joined journal client retained its old process admission")
			}
			if err := client.Close(context.Background()); err != nil {
				t.Fatal("duplicate journal client close lost its joined result", err)
			}
		})
	})
}
