//go:build windows

package windowscontroller

import (
	"context"
	"errors"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"router-vpn/internal/windowsbootstrap"
)

// LaunchProtectedBootstrapElevated uses the retained global-drive capability
// for the controller's bounded, pre-application bootstrap only. Windows still
// performs ordinary runas consent. Unlike the suspended-child API, this path
// does not require a Medium caller to open an elevated initial thread.
//
// A returned process, including one returned with an error or cancellation,
// remains the caller's exact cleanup owner. The caller must close its private
// rendezvous, join that process, and retain capture until the join completes.
// No credentials or application configuration belong to this launch; the
// high-side bootstrap must independently capture its protected current image
// and authenticate the retained pipe peer before accepting either.
//
// This primitive does not establish interactive same-user or cross-account
// UAC acceptance. Those require the corresponding real desktop/token tests.
func LaunchProtectedBootstrapElevated(ctx context.Context, capture *ProtectedShellImage, arguments []string) (*Process, error) {
	api, err := native()
	if err != nil {
		return nil, err
	}
	return launchProtectedBootstrapElevated(ctx, capture, arguments, api, func(info *shellExecuteInfo) (bool, error) {
		ok, _, err := api.shellExecute.Call(uintptr(unsafe.Pointer(info)))
		return ok != 0, err
	})
}

func protectedBootstrapIdentity(original, actual TokenIdentity) error {
	// The consenting administrator can be another account. The same captured
	// desktop session, primary token and actual enabled elevation are required;
	// equating SIDs or authentication IDs would break credential-prompt UAC.
	if !original.Primary || original.SID == "" || !actual.Primary || actual.SID == "" ||
		!actual.Elevated || !actual.Administrator || actual.SessionID != original.SessionID {
		return errors.New("protected bootstrap process lacks its actual elevated desktop identity")
	}
	return nil
}

func launchProtectedBootstrapElevated(ctx context.Context, capture *ProtectedShellImage, arguments []string, api *nativeAPI, execute func(*shellExecuteInfo) (bool, error)) (*Process, error) {
	if ctx == nil || capture == nil || api == nil || execute == nil {
		return nil, errors.New("protected bootstrap launch requires its retained caller and global image")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	arguments = append([]string(nil), arguments...)
	rendezvous, err := windowsbootstrap.ParseArguments(arguments)
	if err != nil || rendezvous.ParentPID != uint32(os.Getpid()) {
		return nil, errors.Join(err, errors.New("protected bootstrap launch lost its exact public caller rendezvous"))
	}
	if _, err := localExecutablePath(rendezvous.ParentImage); err != nil {
		return nil, err
	}
	namespace, err := protectedShellNative()
	if err != nil {
		return nil, err
	}
	// Close cannot release the protected spelling or its image while consent
	// is outstanding. launchElevated joins its locked COM thread even on caller
	// cancellation and retains every actual Shell process handle it receives.
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if err := capture.verifyLocked(api, namespace); err != nil {
		return nil, err
	}
	path, err := syscall.UTF16PtrFromString(capture.path)
	if err != nil {
		return nil, err
	}
	process, launchErr := launchElevated(ctx, capture.image, arguments, api, func(info *shellExecuteInfo) (bool, error) {
		// Independently prove the effective namespace on the actual original
		// process COM thread immediately before Windows consumes the spelling.
		if err := capture.verifyLocked(api, namespace); err != nil {
			return false, err
		}
		if err := ctx.Err(); err != nil {
			return false, err
		}
		info.File = path
		info.Directory = nil
		return execute(info)
	})
	runtime.KeepAlive(path)
	proofErr := capture.verifyLocked(api, namespace)
	if process != nil {
		// This is the exact Shell creation handle, never a reopened PID. These
		// proofs authorize the later private handshake, not an arbitrary launch.
		proofErr = errors.Join(proofErr, process.VerifyImage(capture.image))
		identity, identityErr := process.Identity()
		proofErr = errors.Join(proofErr, identityErr, protectedBootstrapIdentity(capture.identity, identity), process.Alive())
	}
	return process, errors.Join(launchErr, proofErr, ctx.Err())
}
