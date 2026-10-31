//go:build linux

package mobiletor

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestLinuxBaselineGuardianPartialWitnessCannotCreateProof(t *testing.T) {
	open := func() *os.File {
		file, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		return file
	}
	first, second, replacement := open(), open(), open()
	defer replacement.Close()
	witness := desktopLinuxNewGuardianProcess(-1)
	witness.pidfd, witness.directory = first, second
	for _, retired := range []bool{false, true} {
		if _, err := witness.observe(context.Background(), retired); err == nil {
			t.Fatal("partial descriptor ownership created a guardian proof")
		}
	}
	if err := witness.close(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, file := range []*os.File{first, second} {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("partial guardian witness retained an original descriptor", err)
		}
	}
	if _, err := replacement.Stat(); err != nil {
		t.Fatal("partial guardian cleanup closed an unrelated descriptor", err)
	}
	if err := witness.close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := witness.observe(context.Background(), true); err == nil {
		t.Fatal("closing partial witnesses fabricated a complete retired identity")
	}
}
