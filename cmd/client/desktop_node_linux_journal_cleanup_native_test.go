//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"router-vpn/internal/linuxprotection"
)

// Cancel upon the first actual original unlink, not a scheduling timeout.
// Done and Err still come from an actual context cancellation. This observer
// does not mutate filesystem state or replace a production removal operation.
type linuxJournalUnlinkCancellation struct {
	context.Context
	cancel   context.CancelFunc
	original *os.File
}

func (c *linuxJournalUnlinkCancellation) Err() error {
	if info, err := c.original.Stat(); err == nil {
		if native, ok := info.Sys().(*syscall.Stat_t); ok && native.Nlink == 0 {
			c.cancel()
		}
	}
	return c.Context.Err()
}

func linuxNodeJournalCleanupFixture(ctx context.Context, session *desktopLinuxNodeSession, scenario string) error {
	j := session.journal
	if j == nil || session.active != nil || session.predecessor != nil || j.pending != nil || j.current.Record.Committed.Target != nil {
		return errors.New("journal cleanup fixture requires its actual joined empty application session")
	}
	root := filepath.Join("/opt", desktopLinuxNodeJournalDirectory)
	originals := []*desktopLinuxNodeJournalFile{j.slots[0], j.slots[1], j.headerFile, j.lock}
	bodies := make(map[string][]byte)
	for _, original := range originals {
		body, err := j.readFile(original, linuxprotection.JournalRecordLimit)
		if err != nil {
			return err
		}
		bodies[original.name] = body
	}
	p := session.parent.parent
	if scenario == "cleanup-cancel" {
		lifetime, cancel := context.WithCancel(ctx)
		defer cancel()
		observed := &linuxJournalUnlinkCancellation{Context: lifetime, cancel: cancel, original: j.slots[0].file}
		if err := p.Close(observed); err == nil || lifetime.Err() == nil || j.removal == nil ||
			j.removal.complete || !j.removal.files[0].removed || j.removal.files[1].removed || j.closed || p.closed || p.ctx.Err() != nil {
			return errors.Join(err, errors.New("cancelled empty-journal removal lost its exact partial unlink owner"))
		}
		if err := j.Close(ctx); err == nil || j.closed || j.released || j.lock.file == nil {
			return errors.New("unfinished journal unlink released its captured lock or retry descriptors")
		}
		if _, err := j.Append(ctx, j.current.SHA256, linuxJournalCheckpoint(j.current)); err == nil {
			return errors.New("unfinished terminal removal reopened ordinary journal mutation")
		}
		if next, err := createDesktopLinuxNodeJournal(ctx, session.parent); err == nil || next != nil {
			return errors.New("stopped original controller registered a replacement journal during removal")
		}
		for _, original := range originals {
			if _, err := original.file.Stat(); err != nil {
				return errors.Join(err, errors.New("partial removal closed an original retry descriptor"))
			}
		}
		return nil // The caller retries the actual terminal Close with live ctx.
	}
	if scenario == "cleanup-pending" {
		var before syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &before); err != nil || before.Cur < 512 {
			return errors.Join(err, errors.New("partial cleanup fixture lost its actual file-size limit"))
		}
		limited := before
		limited.Cur = 512
		signal.Ignore(syscall.SIGXFSZ)
		defer signal.Reset(syscall.SIGXFSZ)
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
			return err
		}
		_, writeErr := j.Append(ctx, j.current.SHA256, linuxJournalCheckpoint(j.current))
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &before); err != nil {
			return err
		}
		if !errors.Is(writeErr, syscall.EFBIG) || j.pending == nil {
			return errors.Join(writeErr, errors.New("cleanup fixture did not retain a real partial append"))
		}
		file := j.slots[j.pending.slot]
		body, err := j.readFile(file, linuxprotection.JournalRecordLimit)
		old := bodies[file.name]
		if err != nil || len(body) < 512 || !bytes.Equal(body[:512], j.pending.body[:512]) ||
			bytes.Equal(body, j.pending.body) || len(old) < 512 || !bytes.Equal(body[512:], old[512:]) {
			return errors.Join(err, errors.New("cleanup fixture lost its exact torn native bytes"))
		}
		bodies[file.name] = body
		if err := p.Close(ctx); err != nil || j.removal != nil || !j.closed {
			return errors.Join(err, errors.New("terminal cleanup removed or rewrote a partial recovery journal"))
		}
		for name, before := range bodies {
			after, err := os.ReadFile(filepath.Join(root, name))
			if err != nil || !bytes.Equal(after, before) {
				return errors.Join(err, errors.New("terminal cleanup altered an unresolved original recovery file"))
			}
		}
		return nil
	}
	var restore func() error
	marker := []byte("unrelated replacement must survive")
	switch scenario {
	case "cleanup-extra":
		path := filepath.Join(root, "unrelated.json")
		if err := os.WriteFile(path, marker, 0600); err != nil {
			return err
		}
		restore = func() error {
			body, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(body, marker) {
				return errors.Join(err, errors.New("journal cleanup deleted an unrelated original entry"))
			}
			return os.Remove(path)
		}
	case "cleanup-root":
		moved := root + ".cleanup-original"
		if err := os.Rename(root, moved); err != nil {
			return err
		}
		if err := os.Mkdir(root, 0700); err != nil {
			return err
		}
		path := filepath.Join(root, "replacement")
		if err := os.WriteFile(path, marker, 0600); err != nil {
			return err
		}
		restore = func() error {
			body, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(body, marker) {
				return errors.Join(err, errors.New("journal cleanup altered a replacement root"))
			}
			if err := os.Remove(path); err != nil {
				return err
			}
			if err := os.Remove(root); err != nil {
				return err
			}
			return os.Rename(moved, root)
		}
	case "cleanup-file":
		path := filepath.Join(root, j.slots[0].name)
		moved := filepath.Join("/opt", "cleanup-original-slot")
		if err := os.Rename(path, moved); err != nil {
			return err
		}
		if err := os.WriteFile(path, bodies[j.slots[0].name], 0600); err != nil {
			return err
		}
		restore = func() error {
			body, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(body, bodies[j.slots[0].name]) {
				return errors.Join(err, errors.New("journal cleanup removed an equal-content replacement file"))
			}
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Rename(moved, path)
		}
	case "cleanup-bytes":
		path := filepath.Join(root, j.slots[j.current.Slot].name)
		if err := os.WriteFile(path, marker, 0600); err != nil {
			return err
		}
		restore = func() error {
			body, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(body, marker) {
				return errors.Join(err, errors.New("journal cleanup changed mismatched checkpoint bytes"))
			}
			return os.WriteFile(path, bodies[j.slots[j.current.Slot].name], 0600)
		}
	case "cleanup-foreign-nft":
		const table = "router_vpn_node_cleanup_fixture"
		if output, err := exec.CommandContext(ctx, "nft", "add", "table", "inet", table).CombinedOutput(); err != nil {
			return fmt.Errorf("create isolated cleanup counterexample: %v: %s", err, output)
		}
		restore = func() error {
			if output, err := exec.CommandContext(ctx, "nft", "list", "table", "inet", table).CombinedOutput(); err != nil {
				return fmt.Errorf("journal cleanup removed unowned native policy: %v: %s", err, output)
			}
			if output, err := exec.CommandContext(ctx, "nft", "delete", "table", "inet", table).CombinedOutput(); err != nil {
				return fmt.Errorf("retire isolated fixture policy: %v: %s", err, output)
			}
			return nil
		}
	default:
		return errors.New("unknown exact journal cleanup scenario")
	}
	if err := p.Close(ctx); err == nil || j.removal != nil || j.closed || p.closed || p.ctx.Err() != nil {
		return errors.Join(err, errors.New("journal cleanup accepted a changed owner or unproved native absence"))
	}
	if err := restore(); err != nil {
		return err
	}
	for _, original := range originals {
		body, err := io.ReadAll(io.NewSectionReader(original.file, 0, linuxprotection.JournalRecordLimit+1))
		if err != nil || !bytes.Equal(body, bodies[original.name]) {
			return errors.Join(err, errors.New("rejected journal removal changed or closed original retained bytes"))
		}
	}
	return nil
}
