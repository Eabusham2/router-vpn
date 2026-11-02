//go:build windows

package windowscontroller

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

var fixtureFreshUACContinue = errors.New("authenticated fresh UAC fixture continues in TestMain")
var fixtureFreshUACBootstrapFinish func() error

func fixtureFreshUACFinishBootstrap() error {
	if fixtureFreshUACBootstrapFinish == nil {
		return nil
	}
	finish := fixtureFreshUACBootstrapFinish
	fixtureFreshUACBootstrapFinish = nil
	return finish()
}

func fixtureFreshUACProcessIdentity(api *nativeAPI, process *Process) (fixtureFreshUACIdentity, error) {
	handle, release, err := process.borrow()
	if err != nil {
		return fixtureFreshUACIdentity{}, err
	}
	defer release()
	var token syscall.Token
	if err := syscall.OpenProcessToken(handle, syscall.TOKEN_QUERY, &token); err != nil {
		return fixtureFreshUACIdentity{}, err
	}
	identity, err := fixtureFreshUACObserveToken(api, token)
	return identity, errors.Join(err, token.Close())
}

// This is compiled only into the disposable test executable. The production
// bootstrap protocol has no test selector, receipt or report command. The
// existing independent bootstrap has already proved both native processes,
// protected image, private peer and its own kill-on-close process Job.
func fixtureFreshUACBootstrapHandoff(ctx context.Context, pipe *Pipe, parent *Process, image *Image, frame []byte) error {
	var receipt fixtureFreshUACReceipt
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	if len(frame) > maxFrame || decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF ||
		receipt.Role != "full" || len(receipt.Nonce) != 32 || receipt.FullReport != "" || receipt.FullFile != (syscall.ByHandleFileInformation{}) {
		return errors.New("protected bootstrap received no exact fresh UAC continuation")
	}
	if _, err := hex.DecodeString(receipt.Nonce); err != nil {
		return err
	}
	api, err := native()
	if err != nil {
		return err
	}
	caller, err := fixtureFreshUACProcessIdentity(api, parent)
	if err != nil || !fixtureFreshUACPrimaryMatches(caller, receipt.Limited) || caller.ElevationType != 3 {
		return errors.Join(err, errors.New("fresh UAC continuation lost its exact genuine Limited parent"))
	}
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	limited, full, pairErr := fixtureFreshUACReadPair(api, token, caller.SID)
	closeErr := token.Close()
	if pairErr != nil || closeErr != nil || !fixtureFreshUACFullWorkerMatches(limited, full, receipt.Limited, receipt.Full) || full.ElevationType != 2 {
		return errors.Join(pairErr, closeErr, errors.New("normal runas did not retain the originally observed reciprocal Full logon"))
	}
	executable, err := fixtureFreshUACDOSImage(api, image)
	if err != nil || !strings.EqualFold(filepath.Dir(receipt.Report), filepath.Dir(executable)) ||
		filepath.Base(receipt.Report) != "fresh-uac-full-"+receipt.Nonce+".txt" {
		return errors.Join(err, errors.New("fresh UAC report escaped its original protected compiler directory"))
	}
	// Keep the exact private parent channel through the entire test run. A
	// disappeared parent ends this dedicated process, whose already-owned Job
	// closes its descendants. No PID search or unrelated process is used.
	if fixtureFreshUACParentAuthority != nil || fixtureFreshUACBootstrapFinish != nil {
		return errors.New("fresh Full continuation already has an owned Limited source")
	}
	lifetime, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	ownedParent, err := fixtureRetainFreshUACLimitedParent(lifetime, api, parent, receipt.Limited, limited)
	if err != nil {
		cancel()
		return err
	}
	fixtureFreshUACParentAuthority = ownedParent
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		_ = pipe.ObserveLifetime(lifetime)
		if !errors.Is(lifetime.Err(), context.Canceled) {
			// Revoke the retained primary capability before process retirement.
			cancel()
			os.Exit(125)
		}
	}()
	fixtureFreshUACBootstrapFinish = func() error {
		cancel()
		<-joined
		// TestMain calls this only after m.Run and each exact access thread
		// have joined. A pending lease refuses early token/process closure.
		closeErr := ownedParent.close()
		if closeErr == nil && fixtureFreshUACParentAuthority == ownedParent {
			fixtureFreshUACParentAuthority = nil
		}
		return errors.Join(closeErr, pipe.Close())
	}
	fixtureFreshUACWorkerReceipt = &receipt
	os.Args = []string{os.Args[0], "-test.run=^" + fixtureFreshUACName + "$", "-test.count=1", "-test.timeout=35s", "-test.v"}
	if err := pipe.WriteFrame(ctx, []byte("fresh-uac-ready "+receipt.Nonce+"\n")); err != nil {
		return errors.Join(err, fixtureFreshUACFinishBootstrap())
	}
	return fixtureFreshUACContinue
}

// The linked Full handle is never duplicated, relabeled or passed to a launch
// API. The shipping protected launcher asks Windows to perform normal runas.
// This CI fixture requires an already configured no-prompt UAC policy and does
// not claim that a human consent dialog was exercised.
// https://learn.microsoft.com/windows/win32/api/shellapi/nf-shellapi-shellexecutea
// https://learn.microsoft.com/windows/win32/api/winnt/ne-winnt-security_impersonation_level
func fixtureFreshUACNormalRunas(t *testing.T, receipt *fixtureFreshUACReceipt) {
	t.Helper()
	fixture := newProtectedBootstrapFixture(t)
	current, err := CurrentIdentity()
	if err != nil || !current.Primary || current.Elevated || current.Administrator || current.SID != receipt.Limited.SID {
		t.Fatal("normal runas fixture did not start as its genuine Limited user", err)
	}
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	limited, full, pairErr := fixtureFreshUACReadPair(fixture.api, token, current.SID)
	closeErr := token.Close()
	if pairErr != nil || closeErr != nil || !fixtureFreshUACPrimaryMatches(limited, receipt.Limited) ||
		!fixtureFreshUACAuthorityMatches(full, receipt.Full) {
		t.Fatal("Limited worker changed its independently captured reciprocal logons", pairErr, closeErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()
	fixture.process, err = LaunchProtectedBootstrapElevated(ctx, fixture.capture, fixture.arguments)
	if err != nil {
		t.Fatal("genuine Limited normal protected runas failed", err)
	}
	fixture.hello(t)
	actual, err := fixtureFreshUACProcessIdentity(fixture.api, fixture.process)
	if err != nil || !fixtureFreshUACPrimaryMatches(actual, receipt.Full) || actual.ElevationType != 2 {
		t.Fatal("normal runas did not return the captured genuine Full primary process", err)
	}
	continuation := *receipt
	continuation.Role = "full"
	continuation.Report, continuation.File = receipt.FullReport, receipt.FullFile
	continuation.FullReport, continuation.FullFile = "", syscall.ByHandleFileInformation{}
	frame, err := json.Marshal(continuation)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.pipe.WriteFrame(ctx, append(frame, '\n')); err != nil {
		t.Fatal("exact fresh Full continuation was not delivered", err)
	}
	ready, err := fixture.pipe.ReadFrame(ctx)
	if err != nil || string(ready) != "fresh-uac-ready "+receipt.Nonce+"\n" {
		t.Fatal("fresh Full worker did not retain its exact private caller", err)
	}
	code, err := fixture.process.Wait(ctx)
	if err != nil || code != 0 {
		t.Fatal("fresh Full worker or its original native cases failed", code, err)
	}
	if err := fixture.pipe.Close(); err != nil {
		t.Fatal("fresh Full private caller did not drain", err)
	}
	t.Log(fmt.Sprintf("Normal runas retained the genuine Limited/Full pair: SID=%s session=%d limited_LUID=%d full_LUID=%d. The Full handle was observed from the actual Shell process; no identification token acquired launch authority.", actual.SID, actual.Session, limited.AuthenticationID, actual.AuthenticationID))
}
