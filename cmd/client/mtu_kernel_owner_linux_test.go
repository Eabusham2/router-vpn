//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func linuxMTUFileFixture(t *testing.T) (*mtuLinuxKernelOwner, string) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "mtu")
	if os.WriteFile(path, []byte("1400\n"), 0600) != nil || os.WriteFile(filepath.Join(directory, "ifindex"), []byte("41\n"), 0600) != nil {
		t.Fatal("fixture files")
	}
	mtu, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	index, err := os.Open(filepath.Join(directory, "ifindex"))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := newMTULinuxKernelOwner(mtuLiveSnapshot{Interface: "router-vpn", Family: 4, OriginalMTU: 1400}, 41, path, mtu, index)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	return owner, path
}

func TestMTUKernelLinuxRetainsExactFileAndReadback(t *testing.T) {
	owner, path := linuxMTUFileFixture(t)
	before, err := owner.Read()
	if err != nil {
		t.Fatal(err)
	}
	after, err := owner.Change(before, 1320)
	if err != nil || after.MTU != 1320 || after.Identity != before.Identity {
		t.Fatal("captured file mutation failed", err)
	}
	if _, err := owner.Change(before, 1280); err == nil {
		t.Fatal("stale readback authorized a write")
	}
	if err := os.Rename(path, path+".retired"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("1500\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Change(after, 1400); err == nil {
		t.Fatal("same-name replacement authorized rollback")
	}
	data, _ := os.ReadFile(path)
	old, _ := os.ReadFile(path + ".retired")
	if string(data) != "1500\n" || string(old) != "1320\n" {
		t.Fatal("rejected rollback changed an interface")
	}
}

type replacingMTUFile struct {
	*os.File
	path string
}

func (f *replacingMTUFile) WriteAt(data []byte, offset int64) (int, error) {
	if err := os.Rename(f.path, f.path+".retired"); err != nil {
		return 0, err
	}
	if err := os.WriteFile(f.path, []byte("1500\n"), 0600); err != nil {
		return 0, err
	}
	return f.File.WriteAt(data, offset)
}

func TestMTUKernelLinuxReplacementAtWriteCannotRedirectDescriptor(t *testing.T) {
	owner, path := linuxMTUFileFixture(t)
	before, _ := owner.Read()
	owner.mtu = &replacingMTUFile{File: owner.mtu.(*os.File), path: path}
	if _, err := owner.Change(before, 1320); err == nil {
		t.Fatal("post-write replacement identity was accepted")
	}
	replacement, _ := os.ReadFile(path)
	retired, _ := os.ReadFile(path + ".retired")
	if string(replacement) != "1500\n" || string(retired) != "1320\n" {
		t.Fatal("mutation resolved an alias instead of retaining the original descriptor")
	}
}

func TestMTUKernelLinuxChangedIndexAndClosedOwnerRejectWrites(t *testing.T) {
	owner, path := linuxMTUFileFixture(t)
	before, _ := owner.Read()
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "ifindex"), []byte("42\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Change(before, 1320); err == nil {
		t.Fatal("changed kernel interface index was accepted")
	}
	_ = owner.Close()
	if _, err := owner.Change(before, 1320); err == nil {
		t.Fatal("closed retained descriptor accepted mutation")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "1400\n" {
		t.Fatal("rejected owner changed MTU")
	}
}

type delayedCloseMTUFile struct {
	*os.File
	closeCalls int
}

func (f *delayedCloseMTUFile) Close() error {
	f.closeCalls++
	if f.closeCalls == 1 {
		return errors.Join(os.ErrClosed, errors.New("retained descriptor has not drained"))
	}
	return f.File.Close()
}

func TestMTUKernelLinuxFailedCloseRetainsRetiredHandleForRetry(t *testing.T) {
	owner, _ := linuxMTUFileFixture(t)
	before, _ := owner.Read()
	file := &delayedCloseMTUFile{File: owner.mtu.(*os.File)}
	owner.mtu = file
	if owner.Close() == nil || file.closeCalls != 1 {
		t.Fatal("pending descriptor close was reported successful")
	}
	if _, err := owner.Change(before, 1320); err == nil {
		t.Fatal("retired owner accepted mutation during cleanup")
	}
	if owner.Close() != nil || file.closeCalls != 2 {
		t.Fatal("cleanup did not retry the same retained descriptor")
	}
	if owner.Close() != nil || file.closeCalls != 2 {
		t.Fatal("closed owner reused or reclosed its descriptor")
	}
}
