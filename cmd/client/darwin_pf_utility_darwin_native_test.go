//go:build darwin && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobiletor"
)

func TestMacOSOwnedControllerNativePFBaselineUtility(t *testing.T) {
	macOSControllerNativeInstall(t)
	request := mobiletor.DesktopDarwinPFBaselineRequest{Schema: 1, Action: "clear", Expected: []mobiletor.DesktopDarwinPFBaselineProof{{}}}
	raw, err := mobiletor.EncodeDesktopDarwinPFBaselineRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(arguments []string, raw []byte) ([]byte, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, macOSOwnedExecutable(), arguments...)
		command.Dir = "/"
		command.Env = append(macOSOwnedEnvironment(), "HOMEVPN_ROOT=/tmp/foreign-baseline", "HOMEVPN_CLIENT_CONFIG=/tmp/foreign-baseline.json")
		command.Stdin = bytes.NewReader(raw)
		return command.CombinedOutput()
	}
	// Planning this fixed clear target is read-only. The disposable installation
	// refuses an already-present production baseline, and no test can select a
	// different kernel namespace through an argument or an environment value.
	output, err := invoke([]string{darwinOwnedPFArgument, "plan"}, raw)
	var result mobiletor.DesktopDarwinPFBaselineResult
	if err != nil || json.Unmarshal(output, &result) != nil || result.Schema != 1 || result.Applied || result.Previous.Present || result.Target.Present {
		t.Fatal("actual installed PF utility did not retain its read-only absent target", string(output), err)
	}
	reference, err := mobiletor.EncodeDesktopDarwinPFReferenceRequest(mobiletor.DesktopDarwinPFReferenceRequest{Schema: 1, Token: "18446744073709551615"})
	if err != nil {
		t.Fatal(err)
	}
	inspect, stop := context.WithTimeout(context.Background(), 5*time.Second)
	expectedReference, inspectErr := mobiletor.RunDesktopDarwinPFReference(inspect, reference)
	stop()
	output, err = invoke([]string{darwinOwnedPFArgument, "reference"}, reference)
	if inspectErr != nil || err != nil || !bytes.Equal(output, expectedReference) {
		t.Fatal("actual installed PF utility lost its exact read-only reference proof", inspectErr, err)
	}
	// Exercise the real root-only Python state lock and both durable syncs in
	// this disposable protected installation. This creates no PF baseline.
	python, _, err := macOSPythonTrustRoot(os.Getenv("ROUTERVPN_MACOS_FIXTURE_PYTHON"))
	if err != nil {
		t.Fatal(err)
	}
	journalCode := `import importlib.util,json,os
from pathlib import Path
root=Path('/opt/router-vpn-client')
spec=importlib.util.spec_from_file_location('actual_owned_pf_journal',root/'modes/darwin_pf_baseline.py')
baseline=importlib.util.module_from_spec(spec);spec.loader.exec_module(baseline)
run=root/'run';run.mkdir(mode=0o700,exist_ok=True)
path=run/'kill-switch.json'
value={'policy':'always','darwin_native_baseline':{'fixture':'no kernel mutation'}}
with baseline.state_guard(root):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    identity=os.fstat(fd)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write((json.dumps(value,indent=2)+'\n').encode());stream.flush();os.fsync(stream.fileno())
        baseline.sync_state(root,value)
        try:
            with baseline.state_guard(root):
                raise AssertionError('native private journal admitted a second mutation owner')
        except BlockingIOError:
            pass
    finally:
        if not os.path.samestat(identity,path.lstat()):
            raise AssertionError('native private journal cleanup lost its exact file')
        path.unlink()
print('actual root PF journal file/parent sync and exclusive state lock passed')
`
	journalContext, stopJournal := context.WithTimeout(context.Background(), 10*time.Second)
	journal := exec.CommandContext(journalContext, python, "-EsS", "-c", journalCode)
	journal.Env = macOSOwnedEnvironment()
	journal.Dir = "/"
	output, err = journal.CombinedOutput()
	stopJournal()
	if err != nil || !bytes.Contains(output, []byte("actual root PF journal file/parent sync and exclusive state lock passed")) {
		t.Fatal("actual installed Python PF journal did not prove its private commit", string(output), err)
	}
	for _, test := range []struct {
		name string
		args []string
		raw  []byte
	}{
		{"extra authority", []string{darwinOwnedPFArgument, "plan", "/com.apple/foreign"}, raw},
		{"wrong phase", []string{darwinOwnedPFArgument, "clear"}, raw},
		{"unknown record field", []string{darwinOwnedPFArgument, "plan"}, append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"anchor":"com.apple/foreign"}`)...)},
		{"oversized record", []string{darwinOwnedPFArgument, "plan"}, []byte(strings.Repeat("x", mobiletor.DesktopDarwinPFBaselineLimit+1))},
		{"missing record", []string{darwinOwnedPFArgument, "plan"}, nil},
		{"reference identity missing", []string{darwinOwnedPFArgument, "reference"}, raw},
		{"reference extra authority", []string{darwinOwnedPFArgument, "reference", "--stop"}, reference},
	} {
		t.Run(test.name, func(t *testing.T) {
			if output, err := invoke(test.args, test.raw); err == nil {
				t.Fatal("actual installed PF utility accepted an invalid private invocation", test.name, string(output))
			}
		})
	}
	lock, err := ownedDesktopLock(macOSOwnedPFOperationLock, true)
	if err != nil {
		t.Fatal(err)
	}
	output, err = invoke([]string{darwinOwnedPFArgument, "plan"}, raw)
	lock.Close()
	if err == nil || !bytes.Contains(output, []byte("another exact Darwin PF transaction")) {
		t.Fatal("actual installed PF utility ignored its retained transaction owner", string(output), err)
	}
	if err := os.Chmod(macOSOwnedExecutable(), 0775); err != nil {
		t.Fatal(err)
	}
	output, err = invoke([]string{darwinOwnedPFArgument, "plan"}, raw)
	if restoreErr := os.Chmod(macOSOwnedExecutable(), 0755); restoreErr != nil {
		t.Fatal(restoreErr)
	}
	if err == nil || !bytes.Contains(output, []byte("unsafe ownership")) {
		t.Fatal("actual PF utility trusted mutable installed code", string(output), err)
	}
}
