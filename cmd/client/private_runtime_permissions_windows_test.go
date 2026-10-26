//go:build windows

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func windowsRuntimeTestUser(t *testing.T) string {
	t.Helper()
	user, err := windowsRuntimeCurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func setWindowsRuntimeTestDACL(t *testing.T, path, sddl string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := openWindowsPrivateRuntime(path, info, windowsRuntimeReadControl|windowsRuntimeReadAttributes|windowsRuntimeWriteDAC)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	security, err := windowsRuntimeSecurityFromSDDL(sddl)
	if err != nil {
		t.Fatal(err)
	}
	defer security.close()
	result, _, _ := windowsRuntimeSetSecurityInfo.Call(file.Fd(), windowsRuntimeFileObject,
		windowsRuntimeDACLInformation|windowsRuntimeProtectedDACL, 0, 0, uintptr(unsafe.Pointer(security.dacl)), 0)
	if result != 0 {
		t.Fatal("set actual test DACL", syscall.Errno(result))
	}
}

func makeDNSRuntimeTestPublic(t *testing.T, path string) {
	t.Helper()
	user := windowsRuntimeTestUser(t)
	setWindowsRuntimeTestDACL(t, path, "O:"+user+"D:P(A;;FA;;;"+user+")(A;;GR;;;WD)")
}

func windowsRuntimeTestSDDL(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := openWindowsPrivateRuntime(path, info, windowsRuntimeReadControl|windowsRuntimeReadAttributes)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	security, err := windowsRuntimeInspectSecurity(file)
	if err != nil {
		t.Fatal(err)
	}
	defer security.close()
	convert := windowsRuntimeSecurityDLL.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
	var text *uint16
	var length uint32
	ok, _, callErr := convert.Call(uintptr(security.descriptor), 1, windowsRuntimeOwnerInformation|windowsRuntimeDACLInformation,
		uintptr(unsafe.Pointer(&text)), uintptr(unsafe.Pointer(&length)))
	if ok == 0 {
		t.Fatal("serialize actual test DACL", callErr)
	}
	defer syscall.LocalFree(syscall.Handle(unsafe.Pointer(text)))
	if text == nil || length == 0 || length > 65536 {
		t.Fatal("invalid security descriptor string length")
	}
	return syscall.UTF16ToString(unsafe.Slice(text, int(length)))
}

func TestNativeMultihopWindowsRuntimePrivateDACLAndInheritedInput(t *testing.T) {
	root := t.TempDir()
	directory, err := newPrivateRuntimeDir(root, "native-multihop")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, filepath.Join(root, "run"), filepath.Dir(directory), directory} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := validatePrivateRuntimePathPermissions(path, info); err != nil {
			t.Fatal("prepared directory did not receive a private Windows DACL", path, err)
		}
		if !strings.Contains(windowsRuntimeTestSDDL(t, path), "D:P") {
			t.Fatal("private runtime directory still inherits ambient grants", path)
		}
	}
	path := filepath.Join(directory, "sing-box.json")
	body := []byte("{\"owned\":true}\n")
	if err := writePrivateRuntimeFile(path, body); err != nil {
		t.Fatal(err)
	}
	if got, err := readPrivateRuntimeSnapshot(path, maxPrivateStoreBytes); err != nil || !bytes.Equal(got, body) {
		t.Fatal("new native input did not inherit private Windows access", err)
	}
}

func TestNativeMultihopWindowsRuntimeRejectsActualPublicNullAndUnknownDACL(t *testing.T) {
	for _, kind := range []string{"public", "null", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			a, path, observation := registeredDNSRuntimeSnapshotFixture(t)
			user := windowsRuntimeTestUser(t)
			sddl := "O:" + user
			switch kind {
			case "public":
				sddl += "D:P(A;;FA;;;" + user + ")(A;;GR;;;WD)"
			case "unknown":
				sddl += "D:P(A;;FA;;;" + user + ")(A;;GR;;;S-1-5-21-111-222-333-444)"
			}
			setWindowsRuntimeTestDACL(t, path, sddl)
			before := windowsRuntimeTestSDDL(t, path)
			calls := 0
			proof := proveSelectedDNSWithLookup(context.Background(), a, observation, "external-socks5", func(context.Context, string) ([]string, error) {
				calls++
				return []string{"192.0.2.1"}, nil
			})
			if proof.Status != "failed" || calls != 0 {
				t.Fatal("unsafe actual Windows DACL reached DNS lookup", kind, proof, calls)
			}
			if after := windowsRuntimeTestSDDL(t, path); after != before {
				t.Fatal("active DNS verification modified the unsafe DACL", before, after)
			}
		})
	}
}

func TestNativeMultihopWindowsRuntimeRejectsUnsupportedOwnerAndACE(t *testing.T) {
	user := windowsRuntimeTestUser(t)
	private := "D:P(A;;FA;;;" + user + ")(A;;FA;;;SY)(A;;FA;;;BA)"
	for _, tc := range []struct{ name, sddl string }{
		{"foreign-owner", "O:S-1-5-21-111-222-333-444" + private},
		{"absent-DACL", "O:" + user},
		{"empty-DACL", "O:" + user + "D:P"},
		{"object-ACE", "O:" + user + "D:P(OA;;GR;11111111-1111-1111-1111-111111111111;;" + user + ")"},
		{"inherit-only-public", "O:" + user + "D:P(A;;FA;;;" + user + ")(A;OICIIO;GR;;;WD)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			security, err := windowsRuntimeSecurityFromSDDL(tc.sddl)
			if err != nil {
				t.Fatal("Windows rejected the intended valid negative descriptor", err)
			}
			defer security.close()
			if err := windowsRuntimeValidateSecurity(security, user); err == nil {
				t.Fatal("unsafe descriptor was accepted", tc.name)
			}
		})
	}
}

func TestNativeMultihopWindowsRuntimePreparationDoesNotRewriteDescendants(t *testing.T) {
	parent := t.TempDir()
	user := windowsRuntimeTestUser(t)
	setWindowsRuntimeTestDACL(t, parent, "O:"+user+"D:P(A;OICI;FA;;;"+user+")(A;OICI;GR;;;WD)")
	child := filepath.Join(parent, "existing-child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	before := windowsRuntimeTestSDDL(t, child)
	if !strings.Contains(before, ";;;WD)") {
		t.Fatal("child sentinel did not inherit the deliberate public grant", before)
	}
	if err := ensurePrivateRuntimeDirectory(parent); err != nil {
		t.Fatal(err)
	}
	if after := windowsRuntimeTestSDDL(t, child); after != before {
		t.Fatal("directory hardening rewrote an existing descendant", before, after)
	}
	future := filepath.Join(parent, "new-child")
	if err := os.Mkdir(future, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(future)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateRuntimePathPermissions(future, info); err != nil {
		t.Fatal("future child did not inherit the new private boundary", err)
	}
}

func TestNativeMultihopWindowsRuntimeRejectsJunctionAndLeavesTargetUntouched(t *testing.T) {
	parent, outside := t.TempDir(), t.TempDir()
	junction := filepath.Join(parent, "junction")
	before := windowsRuntimeTestSDDL(t, outside)
	command := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, outside)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("create actual NTFS junction: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = os.Remove(junction) })
	if err := ensurePrivateRuntimeDirectory(junction); err == nil {
		t.Fatal("junction runtime directory was accepted")
	}
	if after := windowsRuntimeTestSDDL(t, outside); after != before {
		t.Fatal("rejected junction changed its target DACL")
	}
	if err := os.WriteFile(filepath.Join(outside, "sing-box.json"), []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateExistingRuntimeAncestors(parent, filepath.Join(junction, "sing-box.json")); err == nil {
		t.Fatal("DNS runtime ancestor validation followed a junction")
	}
}
