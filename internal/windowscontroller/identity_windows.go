//go:build windows

package windowscontroller

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

// TokenIdentity is read from a retained Windows token, never a request field.
// A UAC controller may belong to a different administrator than its desktop
// caller. Callers must preserve both identities rather than equating their SIDs.
type TokenIdentity struct {
	SID              string
	AuthenticationID uint64
	ModifiedID       uint64
	SessionID        uint32
	Primary          bool
	Elevated         bool
	Administrator    bool
}

type tokenStatistics struct {
	TokenID, AuthenticationID                                    uint64
	Expiration                                                   int64
	Type, ImpersonationLevel                                     uint32
	DynamicCharged, DynamicAvailable, GroupCount, PrivilegeCount uint32
	ModifiedID                                                   uint64
}

func currentIdentity() (TokenIdentity, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return TokenIdentity{}, err
	}
	identity, _, readErr := readTokenIdentity(token)
	err = errors.Join(readErr, token.Close())
	if err != nil || !identity.Primary {
		return TokenIdentity{}, errors.Join(err, errors.New("Windows controller primary identity is unproved"))
	}
	return identity, nil
}

// CurrentIdentity captures the real process token independently of environment,
// account names, group labels in a payload, or a selected data directory.
func CurrentIdentity() (TokenIdentity, error) { return currentIdentity() }

func readTokenIdentity(token syscall.Token) (TokenIdentity, uint32, error) {
	var identity TokenIdentity
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return identity, 0, errors.Join(err, errors.New("Windows controller token has no user SID"))
	}
	identity.SID, err = user.User.Sid.String()
	if err != nil {
		return TokenIdentity{}, 0, err
	}
	var statistics tokenStatistics
	var returned uint32
	if unsafe.Sizeof(statistics) != 56 {
		return TokenIdentity{}, 0, errors.New("Windows controller token ABI changed")
	}
	err = syscall.GetTokenInformation(token, 10, (*byte)(unsafe.Pointer(&statistics)), uint32(unsafe.Sizeof(statistics)), &returned)
	if err != nil || returned != uint32(unsafe.Sizeof(statistics)) || (statistics.Type != 1 && statistics.Type != 2) {
		return TokenIdentity{}, 0, errors.Join(err, errors.New("Windows controller token statistics are unproved"))
	}
	identity.AuthenticationID = statistics.AuthenticationID
	identity.ModifiedID = statistics.ModifiedID
	identity.Primary = statistics.Type == 1
	var elevation uint32
	for _, field := range []struct {
		class uint32
		value *uint32
	}{{20, &elevation}, {12, &identity.SessionID}} {
		if err := syscall.GetTokenInformation(token, field.class, (*byte)(unsafe.Pointer(field.value)), 4, &returned); err != nil || returned != 4 {
			return TokenIdentity{}, 0, errors.Join(err, errors.New("Windows controller token field is unproved"))
		}
	}
	if elevation > 1 {
		return TokenIdentity{}, 0, errors.New("Windows controller token elevation is invalid")
	}
	identity.Elevated = elevation == 1
	var size uint32
	err = syscall.GetTokenInformation(token, 2, nil, 0, &size)
	if !errors.Is(err, syscall.ERROR_INSUFFICIENT_BUFFER) || size < 8 || size > 65536 {
		return TokenIdentity{}, 0, errors.Join(err, errors.New("Windows controller token groups are unproved"))
	}
	groups := make([]byte, size)
	if err := syscall.GetTokenInformation(token, 2, &groups[0], size, &returned); err != nil || returned != size {
		return TokenIdentity{}, 0, errors.Join(err, errors.New("Windows controller token group shape changed"))
	}
	type group struct {
		SID        *syscall.SID
		Attributes uint32
	}
	count := *(*uint32)(unsafe.Pointer(&groups[0]))
	if count == 0 || uint64(count)*uint64(unsafe.Sizeof(group{}))+8 > uint64(len(groups)) {
		return TokenIdentity{}, 0, errors.New("Windows controller token groups are truncated")
	}
	for _, item := range unsafe.Slice((*group)(unsafe.Pointer(&groups[8])), int(count)) {
		if item.SID == nil {
			return TokenIdentity{}, 0, errors.New("Windows controller group SID is absent")
		}
		sid, err := item.SID.String()
		if err != nil {
			return TokenIdentity{}, 0, err
		}
		if sid == "S-1-5-32-544" && item.Attributes&4 != 0 && item.Attributes&0x10 == 0 {
			identity.Administrator = true
		}
	}
	runtime.KeepAlive(user)
	runtime.KeepAlive(groups)
	return identity, statistics.ImpersonationLevel, nil
}

// inspectWriter captures identification-only authority from the most recent
// message on the exact connected server handle. No operation runs as that user;
// only token readback is allowed before an independently checked RevertToSelf.
func inspectWriter(pipe syscall.Handle) (TokenIdentity, error) {
	api, err := native()
	if err != nil {
		return TokenIdentity{}, err
	}
	type result struct {
		identity TokenIdentity
		err      error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		clean := false
		defer func() {
			if clean {
				runtime.UnlockOSThread()
			}
		}()
		value, err := func() (identity TokenIdentity, resultErr error) {
			var prior syscall.Token
			ok, _, callErr := api.threadToken.Call(^uintptr(1), syscall.TOKEN_QUERY, 1, uintptr(unsafe.Pointer(&prior)))
			if ok != 0 || prior != 0 || !errors.Is(callErr, syscall.Errno(1008)) {
				if prior != 0 {
					_ = prior.Close()
				}
				return identity, errors.New("Windows controller inspection thread already has an unowned token")
			}
			// Even a failed native impersonation call is followed by reversion
			// and independent thread-token readback. No ambiguous thread is
			// returned to the Go scheduler after an attempted identity change.
			defer func() {
				ok, _, callErr := api.revert.Call()
				var residual syscall.Token
				found, _, readErr := api.threadToken.Call(^uintptr(1), syscall.TOKEN_QUERY, 1, uintptr(unsafe.Pointer(&residual)))
				if residual != 0 {
					_ = residual.Close()
				}
				clean = ok != 0 && found == 0 && residual == 0 && errors.Is(readErr, syscall.Errno(1008))
				if !clean {
					identity = TokenIdentity{}
					resultErr = errors.Join(resultErr, nativeError("pipe writer reversion", callErr), errors.New("Windows controller inspection thread did not return to its own identity"))
				}
			}()
			ok, _, callErr = api.impersonate.Call(uintptr(pipe))
			if ok == 0 {
				return identity, nativeError("pipe writer identification", callErr)
			}
			var token syscall.Token
			ok, _, callErr = api.threadToken.Call(^uintptr(1), syscall.TOKEN_QUERY, 1, uintptr(unsafe.Pointer(&token)))
			if ok == 0 || token == 0 {
				return identity, nativeError("pipe writer token", callErr)
			}
			captured, level, readErr := readTokenIdentity(token)
			closeErr := token.Close()
			if readErr != nil || closeErr != nil || captured.Primary || level != 1 {
				return identity, errors.Join(readErr, closeErr, errors.New("Windows controller pipe requires identification-only message authority"))
			}
			return captured, nil
		}()
		done <- result{value, err}
	}()
	value := <-done
	return value.identity, value.err
}
