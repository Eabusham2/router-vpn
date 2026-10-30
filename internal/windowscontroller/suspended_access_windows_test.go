//go:build windows

package windowscontroller

import (
	"errors"
	"fmt"
	"maps"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

func fixtureTokenElevationType(token syscall.Token) (uint32, error) {
	var value, returned uint32
	err := syscall.GetTokenInformation(token, 18 /* TokenElevationType */, (*byte)(unsafe.Pointer(&value)), 4, &returned)
	if err != nil || returned != 4 || value < 1 || value > 3 {
		return 0, errors.Join(err, errors.New("native token elevation type is unproved"))
	}
	return value, nil
}

func fixtureTokenIntegrity(token syscall.Token) (string, error) {
	var size, returned uint32
	err := syscall.GetTokenInformation(token, 25 /* TokenIntegrityLevel */, nil, 0, &size)
	type label struct {
		SID        *syscall.SID
		Attributes uint32
	}
	if !errors.Is(err, syscall.ERROR_INSUFFICIENT_BUFFER) || size < uint32(unsafe.Sizeof(label{}))+8 || size > 4096 {
		return "", errors.Join(err, errors.New("native token integrity label has an invalid bound"))
	}
	data := make([]byte, size)
	if err := syscall.GetTokenInformation(token, 25, &data[0], size, &returned); err != nil || returned != size {
		return "", errors.Join(err, errors.New("native token integrity label changed shape"))
	}
	value := (*label)(unsafe.Pointer(&data[0]))
	start, sid := uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(value.SID))
	if value.SID == nil || value.Attributes&0x20 == 0 || sid < start || sid-start > uintptr(len(data)-8) {
		return "", errors.New("native token integrity SID is not in its captured label")
	}
	if length := value.SID.Len(); length < 8 || uintptr(length) > uintptr(len(data))-(sid-start) {
		return "", errors.New("native token integrity SID exceeds its captured label")
	}
	result, err := value.SID.String()
	runtime.KeepAlive(data)
	return result, err
}

func fixtureTokenStatistics(token syscall.Token) (tokenStatistics, error) {
	var value tokenStatistics
	var returned uint32
	if unsafe.Sizeof(value) != 56 {
		return value, errors.New("native token statistics ABI changed")
	}
	err := syscall.GetTokenInformation(token, 10 /* TokenStatistics */, (*byte)(unsafe.Pointer(&value)), uint32(unsafe.Sizeof(value)), &returned)
	if err != nil || returned != uint32(unsafe.Sizeof(value)) || value.TokenID == 0 || value.Type != 1 {
		return tokenStatistics{}, errors.Join(err, errors.New("native primary token object identity is unproved"))
	}
	return value, nil
}

func fixtureDenyOnlyAdministrator(token syscall.Token) error {
	type groupsHeader struct {
		Count uint32
		Items [1]syscall.SIDAndAttributes
	}
	offset := unsafe.Offsetof(groupsHeader{}.Items)
	var size, returned uint32
	err := syscall.GetTokenInformation(token, 2 /* TokenGroups */, nil, 0, &size)
	if !errors.Is(err, syscall.ERROR_INSUFFICIENT_BUFFER) || uintptr(size) < offset || size > 65536 {
		return errors.Join(err, errors.New("constructed token groups have no bounded capture"))
	}
	data := make([]byte, size)
	if err := syscall.GetTokenInformation(token, 2, &data[0], size, &returned); err != nil || returned != size {
		return errors.Join(err, errors.New("constructed token groups changed shape"))
	}
	defer runtime.KeepAlive(data)
	count := *(*uint32)(unsafe.Pointer(&data[0]))
	if count == 0 || uint64(count)*uint64(unsafe.Sizeof(syscall.SIDAndAttributes{}))+uint64(offset) > uint64(len(data)) {
		return errors.New("constructed token groups are truncated")
	}
	found := false
	for _, item := range unsafe.Slice((*syscall.SIDAndAttributes)(unsafe.Add(unsafe.Pointer(&data[0]), offset)), int(count)) {
		start, sid := uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(item.Sid))
		if item.Sid == nil || sid < start || sid-start > uintptr(len(data)-8) {
			return errors.New("constructed token group SID is outside its captured buffer")
		}
		sidOffset := sid - start
		length := uintptr(8) + 4*uintptr(data[sidOffset+1])
		if data[sidOffset] != 1 || data[sidOffset+1] > 15 || length > uintptr(len(data))-sidOffset || uintptr(item.Sid.Len()) != length {
			return errors.New("constructed token group SID exceeds its captured buffer")
		}
		name, err := item.Sid.String()
		if err != nil {
			return err
		}
		if name == "S-1-5-32-544" {
			if found || item.Attributes&0x10 == 0 || item.Attributes&0x6 != 0 {
				return errors.New("constructed token administrator SID is not uniquely deny-only")
			}
			found = true
		}
	}
	if !found {
		return errors.New("constructed token lost its deny-only administrator SID")
	}
	return nil
}

type fixtureMediumThreadResult struct {
	allowed bool
	denial  error
	failure error
}

// Only this locked fixture thread adopts its independently verified medium token.
// The calling case records whether it is a real linked token or a constructed one.
// No privilege is enabled, no process token changes, and no consent or account
// is supplied. A failed identity proof never falls through to OpenThread.
func fixtureMediumThreadAccess(api *nativeAPI, token syscall.Token, expected TokenIdentity, debug fixturePrivilegeLUID, threadID, processID uint32) fixtureMediumThreadResult {
	done := make(chan fixtureMediumThreadResult, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		runtime.LockOSThread()
		clean := false
		defer func() {
			if clean {
				runtime.UnlockOSThread()
			}
		}()
		result := func() (result fixtureMediumThreadResult) {
			var prior syscall.Token
			ok, _, readErr := api.threadToken.Call(^uintptr(1), syscall.TOKEN_QUERY, 1, uintptr(unsafe.Pointer(&prior)))
			if prior != 0 {
				_ = prior.Close()
			}
			if ok != 0 || prior != 0 || !errors.Is(readErr, syscall.Errno(1008)) {
				result.failure = errors.New("limited-token probe found an unowned thread identity")
				return
			}
			impersonate, err := api.revert.Dll.FindProc("ImpersonateLoggedOnUser")
			if err != nil {
				clean = true // No identity-changing call was attempted.
				result.failure = err
				return
			}
			defer func() {
				ok, _, revertErr := api.revert.Call()
				var residual syscall.Token
				found, _, readErr := api.threadToken.Call(^uintptr(1), syscall.TOKEN_QUERY, 1, uintptr(unsafe.Pointer(&residual)))
				var closeErr error
				if residual != 0 {
					closeErr = residual.Close()
				}
				clean = ok != 0 && found == 0 && residual == 0 && errors.Is(readErr, syscall.Errno(1008)) && closeErr == nil
				if !clean {
					result.failure = errors.Join(result.failure, nativeError("limited-token probe reversion", revertErr), closeErr,
						errors.New("limited-token probe did not independently restore its OS thread"))
				}
			}()
			ok, _, callErr := impersonate.Call(uintptr(token))
			if ok == 0 {
				result.failure = nativeError("verified medium token impersonation", callErr)
				return
			}
			var actualToken syscall.Token
			ok, _, callErr = api.threadToken.Call(^uintptr(1), syscall.TOKEN_QUERY, 1, uintptr(unsafe.Pointer(&actualToken)))
			if actualToken != 0 {
				defer func() { result.failure = errors.Join(result.failure, actualToken.Close()) }()
			}
			if ok == 0 || actualToken == 0 {
				result.failure = nativeError("verified medium thread token", callErr)
				return
			}
			actual, level, identityErr := readTokenIdentity(actualToken)
			integrity, integrityErr := fixtureTokenIntegrity(actualToken)
			privileges, privilegeErr := fixtureTokenPrivileges(actualToken)
			_, hasDebug := privileges[debug]
			if identityErr != nil || integrityErr != nil || privilegeErr != nil || actual.Primary || level != 2 || actual.SID != expected.SID ||
				actual.AuthenticationID != expected.AuthenticationID || actual.SessionID != expected.SessionID || actual.Elevated || actual.Administrator ||
				integrity != "S-1-16-8192" || hasDebug {
				result.failure = errors.Join(identityErr, integrityErr, privilegeErr, errors.New("limited-token access probe retained elevated or foreign authority"))
				return
			}
			names := []string{"OpenThread", "GetProcessIdOfThread", "SuspendThread", "ResumeThread"}
			procedures := make([]*syscall.Proc, len(names))
			for index, name := range names {
				procedures[index], err = api.processID.Dll.FindProc(name)
				if err != nil {
					result.failure = err
					return
				}
			}
			value, _, openErr := procedures[0].Call(0x0800|0x0002, 0, uintptr(threadID))
			thread := syscall.Handle(value)
			if thread == 0 {
				if !errors.Is(openErr, syscall.ERROR_ACCESS_DENIED) {
					result.failure = nativeError("limited-token exact thread access", openErr)
					return
				}
				result.denial = openErr
				return
			}
			defer func() { result.failure = errors.Join(result.failure, syscall.CloseHandle(thread)) }()
			pid, _, ownerErr := procedures[1].Call(uintptr(thread))
			if pid != uintptr(processID) {
				result.failure = errors.Join(ownerErr, errors.New("limited-token probe opened a foreign thread owner"))
				return
			}
			// The initial thread has its creation suspension plus the independent
			// readback suspension. Counts 2->3->2 exercise rights without running
			// child code; an unexpected count goes straight to owned retirement.
			count, _, suspendErr := procedures[2].Call(uintptr(thread))
			if uint32(count) != 2 {
				result.failure = errors.Join(suspendErr, fmt.Errorf("limited-token suspend changed captured count: %d", uint32(count)))
				return
			}
			count, _, resumeErr := procedures[3].Call(uintptr(thread))
			if uint32(count) != 3 {
				result.failure = errors.Join(resumeErr, fmt.Errorf("limited-token resume changed captured count: %d", uint32(count)))
				return
			}
			result.allowed = true
			return
		}()
		done <- result
	}()
	result := <-done
	<-joined // Join the native access attempt and independent reversion.
	return result
}

func fixtureSuspendedAccessTarget(t *testing.T, api *nativeAPI, image *Image, pipe *Pipe, original TokenIdentity) (*Process, uint32) {
	t.Helper()
	ctx, _ := mustNativeContext(t)
	site, err := newShellCreationSite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer shellCreationRelease(&site.service)
	process, err := launchElevated(ctx, image, fixtureArguments("hold", pipe, fixtureExecutable(t)), api, func(info *shellExecuteInfo) (bool, error) {
		path, held, err := image.shellCreationNameLocked(api)
		if err != nil {
			return false, err
		}
		name, _ := syscall.UTF16PtrFromString(path)
		info.File, info.Directory = name, nil
		info.Mask |= 0x08000000
		info.Instance = syscall.Handle(uintptr(unsafe.Pointer(&site.service)))
		ok, _, callErr := api.shellExecute.Call(uintptr(unsafe.Pointer(info)))
		if closeErr := syscall.CloseHandle(held); closeErr != nil {
			image.handles = append(image.handles, held)
			callErr, ok = errors.Join(callErr, closeErr), 0
		}
		runtime.KeepAlive(name)
		return ok != 0, callErr
	})
	if process != nil {
		fixtureSuspendedReturnedOwner(t, process)
	}
	if err != nil || process == nil || site.prove() != nil {
		t.Fatal("token-access diagnostic lost the actual suspended Shell child", err)
	}
	thread, err := captureSuspendedShellThread(api, process)
	if thread != 0 {
		process.mu.Lock()
		process.launchThread = thread
		process.mu.Unlock()
	}
	if err != nil {
		t.Fatal("token-access diagnostic lost its retained suspended thread", err)
	}
	if err := verifySuspendedShellImage(api, process, image); err != nil {
		t.Fatal("token-access diagnostic lost its retained suspended image", err)
	}
	child, err := process.Identity()
	if err != nil || !child.Primary || !child.Elevated || !child.Administrator || child.SID != original.SID || child.SessionID != original.SessionID {
		t.Fatal("token-access diagnostic child is not the captured elevated target", err)
	}
	getThreadID, err := api.processID.Dll.FindProc("GetThreadId")
	if err != nil {
		t.Fatal(err)
	}
	threadID, _, callErr := getThreadID.Call(uintptr(thread))
	if threadID == 0 || threadID > 0xffffffff {
		t.Fatal(nativeError("token-access diagnostic captured thread ID", callErr))
	}
	return process, uint32(threadID)
}

// This records the real same-user split-token access boundary. It does not
// drive interactive UAC or establish cross-account or Portable acceptance.
func TestWindowsControllerFoundationLimitedTokenThreadAccess(t *testing.T) {
	api, image, pipe := fixtureSuspendedSetup(t)
	original, err := CurrentIdentity()
	if err != nil || !original.Primary || !original.Elevated || !original.Administrator {
		t.Fatal("linked-token diagnostic requires its actual elevated fixture identity", err)
	}
	parent, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	parentType, err := fixtureTokenElevationType(parent)
	if err != nil || parentType != 2 {
		t.Fatalf("actual linked limited token is unavailable (elevation type=%d): %v", parentType, err)
	}
	var linked syscall.Token
	var returned uint32
	err = syscall.GetTokenInformation(parent, 19 /* TokenLinkedToken */, (*byte)(unsafe.Pointer(&linked)), uint32(unsafe.Sizeof(linked)), &returned)
	if linked != 0 {
		defer linked.Close()
	}
	if err != nil || linked == 0 || returned != uint32(unsafe.Sizeof(linked)) {
		t.Fatal("native linked limited token was not returned", err)
	}
	limited, _, identityErr := readTokenIdentity(linked)
	limitedType, typeErr := fixtureTokenElevationType(linked)
	integrity, integrityErr := fixtureTokenIntegrity(linked)
	privileges, privilegeErr := fixtureTokenPrivileges(linked)
	debug, debugErr := fixtureDebugPrivilege(fixtureRestrictedAPIs(t))
	_, hasDebug := privileges[debug]
	if identityErr != nil || typeErr != nil || integrityErr != nil || privilegeErr != nil || debugErr != nil ||
		!limited.Primary || limitedType != 3 || limited.SID != original.SID || limited.SessionID != original.SessionID || limited.Elevated || limited.Administrator ||
		integrity != "S-1-16-8192" || hasDebug {
		t.Fatal("linked token is not the actual medium-integrity limited user without debug privilege", identityErr, typeErr, integrityErr, privilegeErr, debugErr)
	}
	process, threadID := fixtureSuspendedAccessTarget(t, api, image, pipe, original)
	result := fixtureMediumThreadAccess(api, linked, limited, debug, uint32(threadID), process.PID())
	if result.failure != nil {
		t.Fatal("actual linked-token thread access was not independently proved and reverted", result.failure)
	}
	if after, err := CurrentIdentity(); err != nil || after != original {
		t.Fatal("linked-token diagnostic changed its parent process identity", err)
	}
	if err := process.Alive(); err != nil {
		t.Fatal("linked-token diagnostic lost its live suspended owner before retirement", err)
	}
	fixtureNoSuspendedChildHello(t, pipe)
	if result.allowed {
		t.Log("Actual linked medium token without SeDebug: exact elevated Shell thread rights 0x0802 granted; SuspendThread/ResumeThread preserved counts 2->3->2. No UAC consent or cross-account acceptance is established.")
	} else if errors.Is(result.denial, syscall.ERROR_ACCESS_DENIED) {
		t.Log("Actual linked medium token without SeDebug: exact elevated Shell thread rights 0x0802 denied with ERROR_ACCESS_DENIED. Ordinary-user suspended launch requires another supported owner; this is not UAC acceptance.")
	} else {
		t.Fatal("linked-token diagnostic produced no bounded access result")
	}
	if err := retireSuspendedShell(process); err != nil {
		t.Fatal("linked-token diagnostic did not join its exact suspended child", err)
	}
}

// A constructed token is a real kernel access-control fixture, not a token
// obtained from UAC. It does not establish linked-token, consent, interactive
// launch, another account's credentials, or Portable acceptance.
func TestWindowsControllerFoundationConstructedMediumThreadAccess(t *testing.T) {
	api, image, pipe := fixtureSuspendedSetup(t)
	original, err := CurrentIdentity()
	if err != nil || !original.Primary || !original.Elevated || !original.Administrator {
		t.Fatal("constructed-medium diagnostic requires its captured elevated parent", err)
	}
	var parent syscall.Token
	if err := syscall.OpenProcessToken(^syscall.Handle(0), syscall.TOKEN_QUERY|syscall.TOKEN_DUPLICATE|syscall.TOKEN_ADJUST_DEFAULT, &parent); err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	beforeStatistics, err := fixtureTokenStatistics(parent)
	if err != nil || beforeStatistics.AuthenticationID != original.AuthenticationID {
		t.Fatal("constructed-medium diagnostic lost its captured parent token object", err)
	}
	beforePrivileges, err := fixtureTokenPrivileges(parent)
	if err != nil {
		t.Fatal(err)
	}
	beforeIntegrity, err := fixtureTokenIntegrity(parent)
	if err != nil || beforeIntegrity != "S-1-16-12288" {
		t.Fatal("constructed-medium diagnostic requires the actual high-integrity parent", err)
	}
	defer func() {
		after, identityErr := CurrentIdentity()
		privileges, privilegeErr := fixtureTokenPrivileges(parent)
		integrity, integrityErr := fixtureTokenIntegrity(parent)
		statistics, statisticsErr := fixtureTokenStatistics(parent)
		if identityErr != nil || privilegeErr != nil || integrityErr != nil || statisticsErr != nil || after != original || statistics != beforeStatistics ||
			!maps.Equal(privileges, beforePrivileges) || integrity != beforeIntegrity {
			t.Error("constructed-medium diagnostic changed its parent primary token", identityErr, privilegeErr, integrityErr, statisticsErr)
		}
	}()
	restrictedAPI := fixtureRestrictedAPIs(t)
	debug, err := fixtureDebugPrivilege(restrictedAPI)
	if err != nil {
		t.Fatal(err)
	}
	notifyName, _ := syscall.UTF16PtrFromString("SeChangeNotifyPrivilege")
	var notify fixturePrivilegeLUID
	ok, _, callErr := restrictedAPI.lookup.Call(0, uintptr(unsafe.Pointer(notifyName)), uintptr(unsafe.Pointer(&notify)))
	runtime.KeepAlive(notifyName)
	if ok == 0 {
		t.Fatal(nativeError("constructed-medium traverse privilege identity", callErr))
	}
	type privilege struct {
		LUID       fixturePrivilegeLUID
		Attributes uint32
	}
	if unsafe.Sizeof(privilege{}) != 12 {
		t.Fatal("constructed-medium privilege ABI changed")
	}
	var remove []privilege
	wantPrivileges := make(map[fixturePrivilegeLUID]uint32)
	for luid, attributes := range beforePrivileges {
		if luid == notify {
			wantPrivileges[luid] = attributes
		} else {
			remove = append(remove, privilege{LUID: luid})
		}
	}
	if len(remove) == 0 || len(remove) > 1024 || len(wantPrivileges) != 1 {
		t.Fatal("constructed-medium privilege set has no bounded parent capture")
	}
	admin, err := syscall.StringToSid("S-1-5-32-544")
	if err != nil {
		t.Fatal(err)
	}
	disable := syscall.SIDAndAttributes{Sid: admin}
	var token syscall.Token
	ok, _, callErr = restrictedAPI.restrict.Call(uintptr(parent), 4 /* LUA_TOKEN */, 1, uintptr(unsafe.Pointer(&disable)),
		uintptr(len(remove)), uintptr(unsafe.Pointer(&remove[0])), 0, 0, uintptr(unsafe.Pointer(&token)))
	runtime.KeepAlive(admin)
	runtime.KeepAlive(disable)
	runtime.KeepAlive(remove)
	if token != 0 {
		defer token.Close()
	}
	if ok == 0 || token == 0 || token == parent {
		t.Fatal(nativeError("construct restricted independent primary token", callErr))
	}
	constructedStatistics, err := fixtureTokenStatistics(token)
	if err != nil || constructedStatistics.TokenID == beforeStatistics.TokenID || constructedStatistics.AuthenticationID != beforeStatistics.AuthenticationID {
		t.Fatal("constructed token does not have its own independent native token identity", err)
	}
	if err := fixtureDenyOnlyAdministrator(token); err != nil {
		t.Fatal(err)
	}
	setInformation, err := api.revert.Dll.FindProc("SetTokenInformation")
	if err != nil {
		t.Fatal(err)
	}
	medium, err := syscall.StringToSid("S-1-16-8192")
	if err != nil {
		t.Fatal(err)
	}
	label := syscall.SIDAndAttributes{Sid: medium, Attributes: 0x20 /* SE_GROUP_INTEGRITY */}
	ok, _, callErr = setInformation.Call(uintptr(token), 25 /* TokenIntegrityLevel */, uintptr(unsafe.Pointer(&label)), unsafe.Sizeof(label)+uintptr(medium.Len()))
	runtime.KeepAlive(medium)
	runtime.KeepAlive(label)
	if ok == 0 {
		t.Fatal(nativeError("lower only the constructed token's integrity", callErr))
	}
	constructed, _, identityErr := readTokenIdentity(token)
	integrity, integrityErr := fixtureTokenIntegrity(token)
	privileges, privilegeErr := fixtureTokenPrivileges(token)
	var mandatory, returned uint32
	policyErr := syscall.GetTokenInformation(token, 27 /* TokenMandatoryPolicy */, (*byte)(unsafe.Pointer(&mandatory)), 4, &returned)
	_, hasDebug := privileges[debug]
	if identityErr != nil || integrityErr != nil || privilegeErr != nil || policyErr != nil || returned != 4 || mandatory&1 == 0 || mandatory&^uint32(3) != 0 ||
		!constructed.Primary || constructed.SID != original.SID || constructed.AuthenticationID != original.AuthenticationID || constructed.SessionID != original.SessionID ||
		constructed.Elevated || constructed.Administrator || integrity != "S-1-16-8192" || hasDebug || !maps.Equal(privileges, wantPrivileges) {
		t.Fatal("constructed token did not prove its actual restricted medium authority", identityErr, integrityErr, privilegeErr, policyErr)
	}
	process, threadID := fixtureSuspendedAccessTarget(t, api, image, pipe, original)
	result := fixtureMediumThreadAccess(api, token, constructed, debug, threadID, process.PID())
	if result.failure != nil {
		t.Fatal("constructed-medium thread access was not independently proved and reverted", result.failure)
	}
	if err := process.Alive(); err != nil {
		t.Fatal("constructed-medium diagnostic lost the live suspended owner", err)
	}
	fixtureNoSuspendedChildHello(t, pipe)
	if result.allowed {
		t.Log("Constructed restricted medium token without SeDebug: exact elevated Shell thread rights 0x0802 granted; SuspendThread/ResumeThread preserved counts 2->3->2. This is not linked-token, interactive UAC or cross-account acceptance.")
	} else if errors.Is(result.denial, syscall.ERROR_ACCESS_DENIED) {
		t.Log("Constructed restricted medium token without SeDebug: exact elevated Shell thread rights 0x0802 denied with ERROR_ACCESS_DENIED. This is a real constructed-token access boundary, not linked-token, interactive UAC or cross-account acceptance.")
	} else {
		t.Fatal("constructed-medium diagnostic produced no bounded access result")
	}
	if err := retireSuspendedShell(process); err != nil {
		t.Fatal("constructed-medium diagnostic did not join its exact suspended child", err)
	}
}
