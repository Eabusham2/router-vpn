//go:build darwin

package mobiletor

import (
	"context"
	"os"
)

type desktopDarwinProcessAuthorityKey struct{}

// WithDesktopDarwinProcessAuthority carries already validated installation
// descriptions into exact native command descendants. It grants no namespace,
// executable, rule or credential selector and cannot change a kernel verdict.
func WithDesktopDarwinProcessAuthority(ctx context.Context, files []*os.File) context.Context {
	return context.WithValue(ctx, desktopDarwinProcessAuthorityKey{}, append([]*os.File(nil), files...))
}

func desktopDarwinProcessAuthority(ctx context.Context) []*os.File {
	files, _ := ctx.Value(desktopDarwinProcessAuthorityKey{}).([]*os.File)
	return append([]*os.File(nil), files...)
}
