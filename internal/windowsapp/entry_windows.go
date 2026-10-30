//go:build windows

package windowsapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"router-vpn/internal/windowscontroller"
)

// Main is the installed/Portable entry point. A public TCP listener never
// adopts an existing controller. The actual captured launcher creates its own
// session, and every exit passes through checked retirement of that session.
func Main(portable bool) int {
	selfTest, err := selfTestArgument(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Router VPN:", err)
		return 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session, failure := Start(ctx, portable)
	if failure == nil {
		if !selfTest {
			if err := session.StartUpdateCheck(); err != nil {
				fmt.Fprintln(os.Stderr, "Router VPN update check:", err)
			}
		}
		failure = session.RunUI(selfTest)
	}
	if session != nil {
		// A failed close retains its real owners. Do not exit the launcher and
		// drop those handles or report success because the process disappeared.
		// Each retry has a fresh bounded operation; the app admits no new work.
		for {
			retirement, stop := context.WithTimeout(context.Background(), 30*time.Second)
			closeErr := session.Close(retirement)
			stop()
			if closeErr == nil {
				break
			}
			fmt.Fprintln(os.Stderr, "Router VPN shutdown remains unproved:", closeErr)
			if !selfTest {
				if err := showMessage("Router VPN is still waiting for its own connection to stop.\n\n" +
					closeErr.Error() + "\n\nSelect OK to retry shutdown. This session remains closed to new connections."); err == nil {
					continue
				}
			}
			time.Sleep(time.Second)
		}
	}
	if failure != nil {
		fmt.Fprintln(os.Stderr, "Router VPN:", failure)
		if !selfTest {
			_ = showMessage(failure.Error())
		}
		return 1
	}
	return 0
}

// Native error reporting does not execute an interpreter selected from PATH
// or from the caller's environment. It never launches a replacement session.
func showMessage(message string) error {
	system, err := windowscontroller.SystemDirectory()
	if err != nil {
		return err
	}
	library, err := syscall.LoadDLL(filepath.Join(system, "user32.dll"))
	if err != nil {
		return err
	}
	defer library.Release()
	show, err := library.FindProc("MessageBoxW")
	if err != nil {
		return err
	}
	message = strings.ReplaceAll(message, "\x00", " ")
	if len(message) > 8192 {
		message = message[:8192]
	}
	text, err := syscall.UTF16PtrFromString(message)
	if err != nil {
		return err
	}
	title, _ := syscall.UTF16PtrFromString("Router VPN")
	result, _, callErr := show.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0x10 /* MB_OK | MB_ICONERROR */)
	runtime.KeepAlive(text)
	runtime.KeepAlive(title)
	if result == 0 {
		return errors.Join(callErr, errors.New("the native Router VPN error window could not open"))
	}
	return nil
}
