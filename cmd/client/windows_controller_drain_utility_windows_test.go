//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/controllertransport"
	"router-vpn/internal/windowscontroller"
)

// These observers belong only to the native fixture. The shipping helper is
// still dot-sourced at its original pathname with its original bytes. The
// fixed, bounded receipt neither resolves a command nor records its arguments.
// In particular it must not warm a first PowerShell launch before acceptance.
const controllerDrainObservationBefore = `
$script:RouterVPNDrainObservationCount=0
function Write-RouterVPNDrainObservation([string]$Stage){
    try{
        if($Stage-cnotmatch'\A(?:script-entered|script-complete|helper-load-(?:begin|complete)|drain-call-(?:begin|complete)|enumeration-(?:begin|complete)|observers-unavailable|(?:pre|post)-observer-restore-failed|lookup-(?:test-path|get-item|split-path|new-object|json|get-process|drain|pinned-drain|ancestors)-(?:begin|complete))\z'){return}
        if($script:RouterVPNDrainObservationCount-lt160){
            $script:RouterVPNDrainObservationCount++
            [IO.File]::AppendAllText($script:RouterVPNDrainObservationPath,$Stage+' ticks='+[DateTime]::UtcNow.Ticks+"` + "`n" + `")
        }
    }catch{}
}
Write-RouterVPNDrainObservation 'script-entered'
$RouterVPNDrainInvocation=$null
$RouterVPNDrainObserversCaptured=$false
try{
    $RouterVPNDrainInvocation=$ExecutionContext.InvokeCommand
    $RouterVPNDrainPre=$RouterVPNDrainInvocation.PreCommandLookupAction
    $RouterVPNDrainPost=$RouterVPNDrainInvocation.PostCommandLookupAction
    if($null-ne$RouterVPNDrainPre-or$null-ne$RouterVPNDrainPost){throw 'Existing lookup observers remain untouched.'}
    $RouterVPNDrainObserversCaptured=$true
    $RouterVPNDrainInvocation.PreCommandLookupAction=[System.EventHandler[System.Management.Automation.CommandLookupEventArgs]]{
        param($Sender,$Lookup)
        try{
            switch -CaseSensitive ($Sender){
                'Test-Path' {Write-RouterVPNDrainObservation 'lookup-test-path-begin'}
                'Get-Item' {Write-RouterVPNDrainObservation 'lookup-get-item-begin'}
                'Split-Path' {Write-RouterVPNDrainObservation 'lookup-split-path-begin'}
                'New-Object' {Write-RouterVPNDrainObservation 'lookup-new-object-begin'}
                'ConvertFrom-Json' {Write-RouterVPNDrainObservation 'lookup-json-begin'}
                'Get-Process' {Write-RouterVPNDrainObservation 'lookup-get-process-begin'}
                'Test-RouterVPNControllerStopping' {Write-RouterVPNDrainObservation 'lookup-drain-begin'}
                'Test-RouterVPNPinnedControllerStopping' {Write-RouterVPNDrainObservation 'lookup-pinned-drain-begin'}
                'Assert-RouterVPNNoReparseAncestors' {Write-RouterVPNDrainObservation 'lookup-ancestors-begin'}
            }
        }catch{}
    }
    $RouterVPNDrainInvocation.PostCommandLookupAction=[System.EventHandler[System.Management.Automation.CommandLookupEventArgs]]{
        param($Sender,$Lookup)
        try{
            switch -CaseSensitive ($Sender){
                'Test-Path' {Write-RouterVPNDrainObservation 'lookup-test-path-complete'}
                'Get-Item' {Write-RouterVPNDrainObservation 'lookup-get-item-complete'}
                'Split-Path' {Write-RouterVPNDrainObservation 'lookup-split-path-complete'}
                'New-Object' {Write-RouterVPNDrainObservation 'lookup-new-object-complete'}
                'ConvertFrom-Json' {Write-RouterVPNDrainObservation 'lookup-json-complete'}
                'Get-Process' {Write-RouterVPNDrainObservation 'lookup-get-process-complete'}
                'Test-RouterVPNControllerStopping' {Write-RouterVPNDrainObservation 'lookup-drain-complete'}
                'Test-RouterVPNPinnedControllerStopping' {Write-RouterVPNDrainObservation 'lookup-pinned-drain-complete'}
                'Assert-RouterVPNNoReparseAncestors' {Write-RouterVPNDrainObservation 'lookup-ancestors-complete'}
            }
        }catch{}
    }
}catch{Write-RouterVPNDrainObservation 'observers-unavailable'}
try{
`

const controllerDrainObservationAfter = `
}finally{
    if($RouterVPNDrainObserversCaptured){
        try{$RouterVPNDrainInvocation.PreCommandLookupAction=$RouterVPNDrainPre}catch{Write-RouterVPNDrainObservation 'pre-observer-restore-failed'}
        try{$RouterVPNDrainInvocation.PostCommandLookupAction=$RouterVPNDrainPost}catch{Write-RouterVPNDrainObservation 'post-observer-restore-failed'}
    }
    Write-RouterVPNDrainObservation 'script-complete'
}
`

func controllerDrainObservationScript(body, path string) string {
	return "$script:RouterVPNDrainObservationPath='" + strings.ReplaceAll(path, "'", "''") + "'\n" +
		controllerDrainObservationBefore + body + controllerDrainObservationAfter
}

func controllerDrainObservationReceipt(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Log("Drain fixture has no script-entry observation; the helper result remains subject to the original acceptance checks", err)
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 16385))
	if err != nil || len(raw) > 16384 {
		t.Log("Drain fixture observation is unavailable or exceeded its fixed bound", err)
		return
	}
	t.Logf("Fixture-only first-launch phases; shipping helper remains unmodified:\n%s", raw)
}

func TestLocalControllerPinnedDrainUtilityWindowsExecution(t *testing.T) {
	workspace := t.TempDir()
	binary := filepath.Join(workspace, fmt.Sprintf("routervpn-drain-%x.exe", time.Now().UnixNano()))
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	started := time.Now()
	build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go.exe"), "build", "-mod=readonly", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("actual drain controller build failed: %v\n%s", err, output)
	}
	remaining, _ := ctx.Deadline()
	t.Logf("Actual shipping utility built in %s; bounded fixture has %s remaining", time.Since(started), time.Until(remaining))
	image, err := windowscontroller.PinImage(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	powershell, err := windowscontroller.PinSystemPowerShell()
	if err != nil {
		t.Fatal(err)
	}
	defer powershell.Close()
	helper, err := filepath.Abs(filepath.Join("..", "..", "client", "Private-RouterVPN-State.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	helperBytes, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	helperDigest := sha256.Sum256(helperBytes)
	defer func() {
		after, err := os.ReadFile(helper)
		if err != nil || sha256.Sum256(after) != helperDigest {
			t.Fatal("actual drain helper changed during native wrapper execution", err)
		}
	}()
	t.Logf("Actual shipping drain helper SHA256 %x; additional phase observers are fixture-only", helperDigest)
	// Make ordinary startup observably invalid. The real command must finish
	// as a read-only utility before configuration/catalog/runtime preparation.
	config := filepath.Join(workspace, "invalid-client.json")
	if err := os.WriteFile(config, []byte("{not client configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	baseEnvironment := func() []string {
		var environment []string
		for _, item := range os.Environ() {
			name, _, _ := strings.Cut(item, "=")
			if strings.HasPrefix(strings.ToUpper(name), "HOMEVPN_") {
				continue
			}
			environment = append(environment, item)
		}
		return append(environment, "HOMEVPN_CLIENT_CONFIG="+config, "HOMEVPN_ROOT="+workspace)
	}
	run := func(t *testing.T, command *exec.Cmd) (string, string, error) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		return strings.TrimSpace(stdout.String()), stderr.String(), err
	}
	for _, mode := range []string{"running", "draining", "wrong-pin", "wrong-owner", "timeout"} {
		t.Run("command/"+mode, func(t *testing.T) {
			identity, err := controllertransport.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			var received atomic.Int32
			joined := make(chan struct{})
			controllerDrainUtilityServer(t, identity, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received.Add(1)
				if r.TLS == nil || r.URL.RequestURI() != controllertransport.DrainPath || r.Method != http.MethodGet || r.ContentLength != 0 ||
					r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("actual drain command escaped its credential-free TLS operation")
				}
				if mode == "timeout" {
					<-r.Context().Done()
					close(joined)
					return
				}
				pid := os.Getpid()
				if mode == "wrong-owner" {
					pid++
				}
				_, _ = io.WriteString(w, fmt.Sprintf(`{"schema":1,"process_id":%d,"draining":%t}`, pid, mode != "running"))
			}))
			pin := identity.Pin()
			if mode == "wrong-pin" {
				other, err := controllertransport.NewIdentity()
				if err != nil {
					t.Fatal(err)
				}
				pin = other.Pin()
			}
			operation, stop := context.WithTimeout(ctx, 5*time.Second)
			defer stop()
			command := exec.CommandContext(operation, binary, windowsControllerDrainUtilityFlag, strconv.Itoa(os.Getpid()), pin)
			command.Env = baseEnvironment()
			stdout, stderr, runErr := run(t, command)
			if operation.Err() != nil {
				t.Fatal("actual drain command did not retain its own bounded lifetime", operation.Err())
			}
			if mode == "running" || mode == "draining" {
				want := fmt.Sprintf(`{"schema":1,"process_id":%d,"draining":%t}`, os.Getpid(), mode == "draining")
				if runErr != nil || stderr != "" || stdout != want || received.Load() != 1 {
					t.Fatal("actual drain command lost its captured native owner", stdout, stderr, runErr)
				}
			} else if runErr == nil || stdout != "" || stderr == "" || mode == "wrong-pin" && received.Load() != 0 {
				t.Fatal("actual drain command turned an unknown transport into stop authority", mode, stdout, stderr, runErr)
			}
			if mode == "timeout" {
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Fatal("actual drain command left its TLS request running after cancellation")
				}
			}
		})
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
	for _, mode := range []string{"running", "draining", "captured-once", "wrong-pin", "malformed", "plaintext-fallback", "legacy", "cancelled"} {
		t.Run("wrapper/"+mode, func(t *testing.T) {
			identity, err := controllertransport.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			var private, public atomic.Int32
			tlsIdentity := identity
			if mode == "plaintext-fallback" || mode == "legacy" {
				tlsIdentity = nil
			}
			controllerDrainUtilityServer(t, tlsIdentity, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/status" {
					private.Add(1)
					_, _ = io.WriteString(w, `{"phase":"stopping"}`)
					return
				}
				public.Add(1)
				if r.URL.RequestURI() != controllertransport.DrainPath || r.TLS == nil || r.Header.Get("Authorization") != "" {
					t.Error("actual wrapper sent another operation or private credential")
				}
				if mode == "cancelled" {
					<-r.Context().Done()
					return
				}
				_, _ = io.WriteString(w, fmt.Sprintf(`{"schema":1,"process_id":%d,"draining":%t}`, os.Getpid(), mode != "running"))
			}))
			pin := identity.Pin()
			if mode == "wrong-pin" {
				other, err := controllertransport.NewIdentity()
				if err != nil {
					t.Fatal(err)
				}
				pin = other.Pin()
			} else if mode == "malformed" {
				pin = "invalid"
			}
			script := "$ErrorActionPreference='Stop'\nWrite-RouterVPNDrainObservation 'helper-load-begin'\n. " + quote(helper) + "\nWrite-RouterVPNDrainObservation 'helper-load-complete'\n"
			if mode == "captured-once" {
				script += "$env:HOMEVPN_CONTROLLER_TRANSPORT='foreign';$env:HOMEVPN_CONTROLLER_PID='0';$env:HOMEVPN_CONTROLLER_TLS_PIN='foreign';$env:HOMEVPN_CONTROLLER_EXECUTABLE='foreign'\n"
			}
			timeout := "2000"
			if mode == "cancelled" {
				timeout = "50"
			}
			script += "Write-RouterVPNDrainObservation 'drain-call-begin'\n$value=Test-RouterVPNControllerStopping -TimeoutMilliseconds " + timeout + "\nWrite-RouterVPNDrainObservation 'drain-call-complete'\n"
			// Every utility is a uniquely named test child. Read-only enumeration
			// proves wrapper cancellation left none of those owned children alive.
			script += "Write-RouterVPNDrainObservation 'enumeration-begin'\nif(@(Get-Process -Name " + quote(strings.TrimSuffix(filepath.Base(binary), ".exe")) + " -ErrorAction SilentlyContinue).Count-ne0){throw 'drain wrapper left its owned utility running'}\nWrite-RouterVPNDrainObservation 'enumeration-complete'\n"
			script += "if($value){[Console]::Out.WriteLine('true')}else{[Console]::Out.WriteLine('false')}\n"
			path := filepath.Join(t.TempDir(), "observe.ps1")
			observation := filepath.Join(filepath.Dir(path), "fixed-phases.txt")
			defer controllerDrainObservationReceipt(t, observation)
			if err := os.WriteFile(path, []byte(controllerDrainObservationScript(script, observation)), 0600); err != nil {
				t.Fatal(err)
			}
			operation, stop := context.WithTimeout(ctx, 8*time.Second)
			defer stop()
			// Use the same normalized volume spelling proven for native managed
			// process creation. No DOS path or PATH search selects PowerShell.
			command := exec.CommandContext(operation, `\\.\`+strings.TrimPrefix(powershell.Path(), `\\?\`), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path)
			command.Env = baseEnvironment()
			if mode != "legacy" {
				command.Env = append(command.Env, "HOMEVPN_CONTROLLER_TRANSPORT=pinned-tls", "HOMEVPN_CONTROLLER_PID="+strconv.Itoa(os.Getpid()),
					"HOMEVPN_CONTROLLER_TLS_PIN="+pin, "HOMEVPN_CONTROLLER_EXECUTABLE="+image.Path())
			}
			stdout, stderr, runErr := run(t, command)
			want := "false"
			if mode == "draining" || mode == "captured-once" || mode == "legacy" {
				want = "true"
			}
			if runErr != nil || operation.Err() != nil || stdout != want || stderr != "" {
				t.Fatal("actual shipping wrapper did not retain its captured drain result", mode, stdout, stderr, runErr, operation.Err())
			}
			if mode == "legacy" {
				if private.Load() != 1 || public.Load() != 0 {
					t.Fatal("legacy unowned helper did not retain its existing transport")
				}
			} else if private.Load() != 0 {
				t.Fatal("owned TLS wrapper fell back to unauthenticated plaintext status")
			}
			if mode == "running" || mode == "draining" || mode == "captured-once" {
				if public.Load() != 1 {
					t.Fatal("actual wrapper omitted its real pinned drain request")
				}
			}
		})
	}
}
