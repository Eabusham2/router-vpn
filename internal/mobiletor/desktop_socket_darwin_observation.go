//go:build darwin

package mobiletor

import (
	"context"
	"os"
	"syscall"
)

type desktopDarwinObservationOutputKey struct{}

// The pipe is separate from the authenticated control stream and stderr. Only
// these owned descriptions become nonblocking; no inherited logging flags or
// unrelated process descriptors are changed. A full pipe drops observations.
func desktopDarwinObservationPipe() (*os.File, *os.File, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	for _, file := range []*os.File{reader, writer} {
		raw, failure := file.SyscallConn()
		if failure == nil {
			var changed error
			failure = raw.Control(func(fd uintptr) { changed = syscall.SetNonblock(int(fd), true) })
			if failure == nil {
				failure = changed
			}
		}
		if failure != nil {
			reader.Close()
			writer.Close()
			return nil, nil, failure
		}
	}
	return reader, writer, nil
}

// Only the packaged guardian receives this fourth descriptor from its actual
// native parent. It never becomes a creator/PF command descendant's handle.
func desktopDarwinInheritedObservation() *os.File {
	var stat syscall.Stat_t
	if syscall.Fstat(4, &stat) != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFIFO || stat.Uid != 0 {
		return nil
	}
	syscall.CloseOnExec(4)
	if syscall.SetNonblock(4, true) != nil {
		return nil
	}
	return os.NewFile(4, "routervpn-original-observation")
}

func desktopDarwinReadbackReporter(ctx context.Context) func(desktopDarwinReadbackSnapshot) {
	file, _ := ctx.Value(desktopDarwinObservationOutputKey{}).(*os.File)
	if file == nil {
		return nil
	}
	return func(snapshot desktopDarwinReadbackSnapshot) {
		raw, err := file.SyscallConn()
		if err != nil {
			return
		}
		line := []byte(snapshot.String() + "\n")
		if len(line) > 512 {
			return
		}
		// One nonblocking write of at most PIPE_BUF bytes: no retries, waits,
		// goroutines, borrowed stderr, or cleanup authority on failure.
		_ = raw.Control(func(fd uintptr) { _, _ = syscall.Write(int(fd), line) })
	}
}

func desktopDarwinReadbackMessages(file *os.File) string {
	if file == nil {
		return ""
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return ""
	}
	buffer := make([]byte, 16<<10)
	n := 0
	_ = raw.Control(func(fd uintptr) { n, _ = syscall.Read(int(fd), buffer) })
	if n <= 0 {
		return ""
	}
	return string(buffer[:n])
}
