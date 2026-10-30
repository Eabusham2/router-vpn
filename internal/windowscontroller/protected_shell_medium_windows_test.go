//go:build windows

package windowscontroller

import (
	"errors"
	"maps"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const fixtureMediumWorkerEnvironment = "ROUTERVPN_CONTROLLER_MEDIUM_WORKER"

// This case executes the shipping namespace capture from an actual Medium
// primary process. It neither impersonates a test thread nor supplies UAC
// consent. A constructed restricted primary token is not evidence of an
// interactive linked-token or cross-account launch.
func TestWindowsControllerFoundationProtectedShellPrimaryMedium(t *testing.T) {
	const test = "TestWindowsControllerFoundationProtectedShellPrimaryMedium"
	api := fixtureRestrictedAPIs(t)
	if marker := os.Getenv(fixtureMediumWorkerEnvironment); marker != "" {
		if marker != test {
			t.Fatal("primary-Medium worker lost its captured test")
		}
		token, err := syscall.OpenCurrentProcessToken()
		if err != nil {
			t.Fatal(err)
		}
		defer token.Close()
		if _, err := fixturePrimaryMediumIdentity(api, token); err != nil {
			t.Fatal("namespace capture did not run as an actual restricted Medium primary process", err)
		}
		image, err := PinCurrentImage()
		if err != nil {
			t.Fatal(err)
		}
		defer image.Close()
		capture, err := PinProtectedShellImage(image)
		if capture != nil {
			defer func() {
				if err := capture.Close(); err != nil {
					t.Error("primary-Medium namespace capture did not retire its retained owners", err)
				}
			}()
		}
		if err != nil {
			t.Fatal("actual primary-Medium process cannot capture the protected global image", err)
		}
		if err := image.Close(); err != nil {
			t.Fatal(err)
		}
		if err := capture.Verify(); err != nil {
			t.Fatal("actual primary-Medium process cannot reverify its independently retained global image", err)
		}
		t.Log("Constructed primary-Medium process, deny-only Administrators, only SeChangeNotify and no impersonation: actual global directory/link read ACLs, mapping identity and captured image proof passed. This is not linked-token, interactive or cross-account UAC acceptance.")
		return
	}

	directory := t.TempDir()
	worker := &fixtureRestrictedWorker{api: api, directory: directory}
	t.Cleanup(func() {
		if err := worker.close(); err != nil {
			t.Error("primary-Medium worker did not retire its exact native owners", err)
		}
	})
	if err := syscall.OpenProcessToken(^syscall.Handle(0), syscall.TOKEN_QUERY|syscall.TOKEN_DUPLICATE|syscall.TOKEN_ASSIGN_PRIMARY|syscall.TOKEN_ADJUST_DEFAULT, &worker.parent); err != nil {
		t.Fatal(err)
	}
	original, _, err := readTokenIdentity(worker.parent)
	if err != nil || !original.Primary || !original.Elevated || !original.Administrator {
		t.Fatal("primary-Medium fixture requires its captured elevated build parent", err)
	}
	statistics, err := fixtureTokenStatistics(worker.parent)
	if err != nil {
		t.Fatal(err)
	}
	integrity, err := fixtureTokenIntegrity(worker.parent)
	if err != nil || integrity != "S-1-16-12288" {
		t.Fatal("primary-Medium fixture requires its actual high-integrity parent", err)
	}
	worker.privileges, err = fixtureTokenPrivileges(worker.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		actual, _, identityErr := readTokenIdentity(worker.parent)
		after, statisticsErr := fixtureTokenStatistics(worker.parent)
		label, integrityErr := fixtureTokenIntegrity(worker.parent)
		privileges, privilegeErr := fixtureTokenPrivileges(worker.parent)
		// CreateProcessAsUser may temporarily use an already-present privilege
		// and restore it. ModifiedID can change; the original token object,
		// complete privilege attributes and primary authority must not.
		if identityErr != nil || statisticsErr != nil || integrityErr != nil || privilegeErr != nil ||
			!fixtureSamePrimary(original, actual) || after.TokenID != statistics.TokenID ||
			after.AuthenticationID != statistics.AuthenticationID || label != integrity || !maps.Equal(privileges, worker.privileges) {
			t.Error("primary-Medium fixture changed its parent token or privileges", identityErr, statisticsErr, integrityErr, privilegeErr)
		}
	}()
	token := fixtureConstructMediumPrimary(t, api, worker.parent, original, statistics, worker.privileges)
	worker = fixtureStartPrimaryWorker(t, worker, token, test, fixtureMediumWorkerEnvironment, 1, func(actual syscall.Token) error {
		identity, err := fixturePrimaryMediumIdentity(api, actual)
		if err != nil || identity.SID != original.SID || identity.AuthenticationID != original.AuthenticationID || identity.SessionID != original.SessionID {
			return errors.Join(err, errors.New("suspended Medium worker changed its captured user or logon"))
		}
		return nil
	})
	if err := worker.wait(25 * time.Second); err != nil {
		t.Fatal("primary-Medium worker did not join", err, worker.output())
	}
	var exit uint32
	if err := syscall.GetExitCodeProcess(worker.process.Process, &exit); err != nil || exit != 0 {
		t.Fatalf("primary-Medium namespace capture failed (exit=%d): %v\n%s", exit, err, worker.output())
	}
	output := worker.output()
	if !strings.Contains(output, "--- PASS: "+test+" (") || strings.Contains(output, "--- SKIP:") || strings.Contains(output, "DATA RACE") {
		t.Fatal("primary-Medium worker did not execute the actual global capture", output)
	}
	t.Log(output)
}

func fixturePrimaryMediumIdentity(api *fixtureRestrictedAPI, token syscall.Token) (TokenIdentity, error) {
	identity, _, identityErr := readTokenIdentity(token)
	integrity, integrityErr := fixtureTokenIntegrity(token)
	privileges, privilegeErr := fixtureTokenPrivileges(token)
	adminErr := fixtureDenyOnlyAdministrator(token)
	name, _ := syscall.UTF16PtrFromString("SeChangeNotifyPrivilege")
	var notify fixturePrivilegeLUID
	ok, _, lookupErr := api.lookup.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&notify)))
	runtime.KeepAlive(name)
	var lookupFailure error
	if ok == 0 {
		lookupFailure = nativeError("primary-Medium privilege identity", lookupErr)
	}
	var mandatory, returned uint32
	policyErr := syscall.GetTokenInformation(token, 27 /* TokenMandatoryPolicy */, (*byte)(unsafe.Pointer(&mandatory)), 4, &returned)
	attributes, present := privileges[notify]
	if identityErr != nil || integrityErr != nil || privilegeErr != nil || adminErr != nil || ok == 0 || policyErr != nil ||
		!identity.Primary || identity.SID == "" || identity.Elevated || identity.Administrator || integrity != "S-1-16-8192" ||
		len(privileges) != 1 || !present || attributes&2 == 0 || returned != 4 || mandatory&1 == 0 || mandatory&^uint32(3) != 0 {
		return TokenIdentity{}, errors.Join(identityErr, integrityErr, privilegeErr, adminErr, policyErr,
			lookupFailure, errors.New("native primary token is not the constructed bounded Medium authority"))
	}
	return identity, nil
}

func fixtureConstructMediumPrimary(t *testing.T, api *fixtureRestrictedAPI, parent syscall.Token, original TokenIdentity, before tokenStatistics, privileges map[fixturePrivilegeLUID]uint32) syscall.Token {
	t.Helper()
	name, _ := syscall.UTF16PtrFromString("SeChangeNotifyPrivilege")
	var notify fixturePrivilegeLUID
	ok, _, callErr := api.lookup.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&notify)))
	runtime.KeepAlive(name)
	if ok == 0 {
		t.Fatal(nativeError("primary-Medium traverse privilege identity", callErr))
	}
	type privilege struct {
		LUID       fixturePrivilegeLUID
		Attributes uint32
	}
	if unsafe.Sizeof(privilege{}) != 12 {
		t.Fatal("primary-Medium privilege ABI changed")
	}
	var remove []privilege
	for luid := range privileges {
		if luid != notify {
			remove = append(remove, privilege{LUID: luid})
		}
	}
	if len(remove) == 0 || len(remove) > 1024 || privileges[notify]&2 == 0 {
		t.Fatal("primary-Medium fixture has no bounded original privilege capture")
	}
	admin, err := syscall.StringToSid("S-1-5-32-544")
	if err != nil {
		t.Fatal(err)
	}
	disable := syscall.SIDAndAttributes{Sid: admin}
	var token syscall.Token
	ok, _, callErr = api.restrict.Call(uintptr(parent), 4 /* LUA_TOKEN */, 1, uintptr(unsafe.Pointer(&disable)),
		uintptr(len(remove)), uintptr(unsafe.Pointer(&remove[0])), 0, 0, uintptr(unsafe.Pointer(&token)))
	runtime.KeepAlive(admin)
	runtime.KeepAlive(disable)
	runtime.KeepAlive(remove)
	if token != 0 && token != parent {
		// Register immediately so every rejected construction retains cleanup.
		t.Cleanup(func() {
			if err := token.Close(); err != nil {
				t.Error("derived primary-Medium token did not close", err)
			}
		})
	}
	if ok == 0 || token == 0 || token == parent {
		t.Fatal(nativeError("construct independent Medium primary token", callErr))
	}
	statistics, err := fixtureTokenStatistics(token)
	if err != nil || statistics.TokenID == before.TokenID || statistics.AuthenticationID != before.AuthenticationID {
		t.Fatal("primary-Medium fixture did not derive an independent token object", err)
	}
	set, err := api.native.revert.Dll.FindProc("SetTokenInformation")
	if err != nil {
		t.Fatal(err)
	}
	medium, err := syscall.StringToSid("S-1-16-8192")
	if err != nil {
		t.Fatal(err)
	}
	label := syscall.SIDAndAttributes{Sid: medium, Attributes: 0x20 /* SE_GROUP_INTEGRITY */}
	ok, _, callErr = set.Call(uintptr(token), 25 /* TokenIntegrityLevel */, uintptr(unsafe.Pointer(&label)), unsafe.Sizeof(label)+uintptr(medium.Len()))
	runtime.KeepAlive(medium)
	runtime.KeepAlive(label)
	if ok == 0 {
		t.Fatal(nativeError("lower only the derived primary token integrity", callErr))
	}
	actual, err := fixturePrimaryMediumIdentity(api, token)
	afterPrivileges, privilegeErr := fixtureTokenPrivileges(token)
	if err != nil || privilegeErr != nil || actual.SID != original.SID || actual.AuthenticationID != original.AuthenticationID || actual.SessionID != original.SessionID ||
		!maps.Equal(afterPrivileges, map[fixturePrivilegeLUID]uint32{notify: privileges[notify]}) {
		t.Fatal("constructed primary-Medium token changed its captured authority", err, privilegeErr)
	}
	return token
}
