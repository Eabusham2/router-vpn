//go:build linux

package standardengine

import (
	"os"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

func sealedFixture(t *testing.T, body []byte, seal bool) *os.File {
	t.Helper()
	number := uintptr(319)
	if runtime.GOARCH == "arm64" {
		number = 279
	} else if runtime.GOARCH != "amd64" {
		t.Skip("native memfd ABI requires shipped Linux target")
	}
	name, _ := syscall.BytePtrFromString("standard-library-test")
	fd, _, errno := syscall.Syscall(number, uintptr(unsafe.Pointer(name)), 3, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	file := os.NewFile(fd, "original-test-library")
	t.Cleanup(func() { file.Close() })
	if _, err := file.Write(body); err != nil {
		t.Fatal(err)
	}
	if seal {
		if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, 1033, 15); errno != 0 {
			t.Fatal(errno)
		}
	}
	return file
}

func TestOriginalSealedLibraryRejectsWrongMutableAndReplacedInputs(t *testing.T) {
	body := []byte("exact builder-sealed library bytes")
	original := sealedFixture(t, body, true)
	if err := VerifyLibrary(original, int64(len(body)), SHA256(body)); err != nil {
		t.Fatal(err)
	}
	if _, err := original.WriteAt([]byte("X"), 0); err == nil {
		t.Fatal("published library bytes remained mutable")
	}
	for _, test := range []struct {
		name   string
		file   *os.File
		size   int64
		digest string
	}{
		{"unsealed", sealedFixture(t, body, false), int64(len(body)), SHA256(body)},
		{"wrong", sealedFixture(t, []byte("foreign sealed bytes"), true), int64(len(body)), SHA256(body)},
		{"truncated", sealedFixture(t, body[:len(body)-1], true), int64(len(body)), SHA256(body)},
		{"wrong-digest", original, int64(len(body)), SHA256([]byte("another build"))},
		{"absent", nil, int64(len(body)), SHA256(body)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if VerifyLibrary(test.file, test.size, test.digest) == nil {
				t.Fatal("foreign or mutable library accepted")
			}
		})
	}
	foreign := sealedFixture(t, []byte("foreign descriptor replacement"), true)
	if _, _, errno := syscall.Syscall(syscall.SYS_DUP3, foreign.Fd(), original.Fd(), syscall.O_CLOEXEC); errno != 0 {
		t.Fatal(errno)
	}
	if VerifyLibrary(original, int64(len(body)), SHA256(body)) == nil {
		t.Fatal("replaced original descriptor accepted")
	}
}
