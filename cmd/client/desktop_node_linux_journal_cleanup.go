//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"sort"
	"syscall"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
)

type desktopLinuxNodeJournalRemovalFile struct {
	owner   *desktopLinuxNodeJournalFile
	body    []byte
	removed bool
}

// Terminal cleanup retains its original creator. The separately captured
// startup capability is limited to a proved-dead creator's settled-empty
// checkpoint. Both retain the original descriptors and each successful unlink;
// neither a pathname nor a decoded record can resume another removal.
type desktopLinuxNodeJournalRemoval struct {
	files            [4]desktopLinuxNodeJournalRemovalFile
	recovery         *desktopLinuxEmptyJournalRecovery
	directoryRemoved bool
	complete         bool
}

func (p *desktopLinuxNodeParent) prepareEmptyJournalShutdown(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	if !p.stopping {
		p.gate <- struct{}{}
		return errors.New("Linux empty journal cleanup requires permanent admission stop")
	}
	session := p.session
	if session == nil {
		p.gate <- struct{}{}
		return nil
	}
	var others []ownedDesktopNodeParent
	for dependent := range p.dependents {
		if _, journal := dependent.(*desktopLinuxNodeJournal); !journal {
			others = append(others, dependent)
		}
	}
	p.gate <- struct{}{}
	// All transaction settlement has already completed. Join remaining host,
	// process and session owners while native parent witnesses are still live.
	for _, dependent := range others {
		if err := dependent.Close(ctx); err != nil {
			return err
		}
	}
	if err := session.enter(ctx); err != nil {
		return err
	}
	journal := session.journal
	joined := session.closed && session.released
	session.gate <- struct{}{}
	if !joined {
		return errors.New("Linux empty journal cleanup lost its original joined application session")
	}
	if journal == nil {
		return nil
	}
	return journal.removeEmptyCheckpoint(ctx)
}

func (j *desktopLinuxNodeJournal) removalParent(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || j.parent == nil || j.closed || j.released {
		return errors.New("Linux journal removal lost its original bounded creator")
	}
	if err := j.parent.retirementCurrent(ctx); err != nil {
		return err
	}
	p := j.parent.parent
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	defer func() { p.gate <- struct{}{} }()
	if !p.stopping || j.header.Creator != j.parent.record || p.session == nil || p.session.journal != j ||
		!p.session.closed || !p.session.released {
		return errors.New("Linux journal removal cannot borrow a live or reopened creator")
	}
	if _, retained := p.dependents[j]; !retained {
		return errors.New("Linux journal removal lost its original parent registration")
	}
	for dependent := range p.dependents {
		if _, ok := dependent.(*desktopLinuxNodeJournal); !ok {
			return errors.New("Linux journal removal preceded an original dependent join")
		}
	}
	return nil
}

func (j *desktopLinuxNodeJournal) removalObjects() error {
	if j.removal == nil || j.root == nil || j.anchor == nil || j.directory == nil {
		return errors.New("Linux journal removal has no retained native storage")
	}
	anchor, err := j.anchor.Stat(".")
	anchorID, identityErr := desktopLinuxNodeObjectOf(anchor)
	if err != nil || identityErr != nil || anchorID != j.parent.record.InstallationAnchor {
		return errors.Join(err, identityErr, errors.New("Linux journal removal changed its installation anchor"))
	}
	directory, err := j.directory.Stat()
	root, rootErr := j.root.Stat(".")
	rootID, identityErr := desktopLinuxNodeObjectOf(root)
	entry, pathErr := j.anchor.Lstat(desktopLinuxNodeJournalDirectory)
	if err != nil || rootErr != nil || identityErr != nil || rootID != j.rootIdentity || rootID != j.header.Root ||
		!root.IsDir() || !ownedDesktopInfo(root) || root.Mode().Perm() != 0700 || !os.SameFile(root, directory) {
		return errors.Join(err, rootErr, identityErr, errors.New("Linux journal removal changed its original directory"))
	}
	native, ok := directory.Sys().(*syscall.Stat_t)
	if !ok || (j.removal.directoryRemoved && (native.Nlink != 0 || !errors.Is(pathErr, os.ErrNotExist))) ||
		(!j.removal.directoryRemoved && (native.Nlink == 0 || pathErr != nil || !entry.IsDir() || !os.SameFile(root, entry))) {
		return errors.Join(pathErr, errors.New("Linux journal removal refuses a replacement sibling directory"))
	}
	want := []string{}
	for _, original := range j.removal.files {
		owner := original.owner
		if owner == nil || owner.file == nil {
			return errors.New("Linux journal removal lost an original file")
		}
		info, err := owner.file.Stat()
		identity, identityErr := desktopLinuxNodeObjectOf(info)
		if err != nil || identityErr != nil || identity != owner.identity || !info.Mode().IsRegular() ||
			identity.UID != 0 || identity.GID != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) != 0 || info.Mode().Perm() != 0600 {
			return errors.Join(err, identityErr, errors.New("Linux journal removal changed its original private file"))
		}
		// Ordinary ownedDesktopInfo requires one link. Here the exact original
		// descriptor must instead have zero links after its acknowledged unlink.
		native, ok := info.Sys().(*syscall.Stat_t)
		entry, pathErr := j.root.Lstat(owner.name)
		if !ok || (original.removed && (native.Nlink != 0 || !errors.Is(pathErr, os.ErrNotExist))) ||
			(!original.removed && (native.Nlink != 1 || pathErr != nil || !entry.Mode().IsRegular() || !os.SameFile(info, entry))) {
			return errors.Join(pathErr, errors.New("Linux journal removal refuses a replaced or linked private file"))
		}
		body, err := io.ReadAll(io.NewSectionReader(owner.file, 0, int64(linuxprotection.JournalRecordLimit+1)))
		if err != nil || !bytes.Equal(body, original.body) {
			return errors.Join(err, errors.New("Linux journal removal changed its captured checkpoint bytes"))
		}
		if !original.removed {
			want = append(want, owner.name)
		}
	}
	if j.removal.directoryRemoved {
		return nil
	}
	descriptor, err := j.root.Open(".")
	if err != nil {
		return err
	}
	names, readErr := descriptor.Readdirnames(6)
	closeErr := descriptor.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	sort.Strings(names)
	sort.Strings(want)
	if len(names) != len(want) {
		return errors.New("Linux journal removal preserves unrelated or replaced entries")
	}
	for index := range want {
		if names[index] != want[index] {
			return errors.New("Linux journal removal preserves unrelated or replaced entries")
		}
	}
	return nil
}

func (j *desktopLinuxNodeJournal) removeEmptyCheckpoint(ctx context.Context) error {
	if ctx == nil || j == nil || j.gate == nil {
		return errors.New("Linux journal removal requires its original terminal owner")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-j.gate:
	}
	defer func() { j.gate <- struct{}{} }()
	if j.removal != nil && j.removal.complete {
		return ctx.Err()
	}
	if j.removal == nil {
		// These are retained recovery records, not garbage. No pathname or
		// decoded old controller may turn them into removal authority.
		if !j.initialized || j.closed || j.released || j.ctx.Err() != nil || j.pending != nil ||
			j.header.Creator != j.parent.record || j.current.Incomplete || j.current.Record.Phase != "settled" ||
			j.current.Record.Controller != j.parent.record || j.current.Record.Intent != nil ||
			!reflect.DeepEqual(j.current.Record.Committed, linuxprotection.JournalState{}) {
			return nil
		}
		if err := j.removalParent(ctx); err != nil {
			return err
		}
		if err := j.verifyObjects(); err != nil {
			return err
		}
		selection, body, err := j.readSelection()
		if err != nil || selection.Incomplete || selection.SHA256 != j.current.SHA256 || selection.Slot != j.current.Slot ||
			!bytes.Equal(body, j.currentBytes) {
			return errors.Join(err, errors.New("Linux journal removal lost its exact settled empty checkpoint"))
		}
		if err := mobiletor.ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
			return err
		}
		removal := &desktopLinuxNodeJournalRemoval{}
		for index, file := range []*desktopLinuxNodeJournalFile{j.slots[0], j.slots[1], j.headerFile, j.lock} {
			body, err := j.readFile(file, linuxprotection.JournalRecordLimit)
			if err != nil {
				return err
			}
			removal.files[index] = desktopLinuxNodeJournalRemovalFile{owner: file, body: body}
		}
		j.removal = removal
	}
	return j.finishEmptyCheckpointRemoval(ctx, nil, true)
}

func (j *desktopLinuxNodeJournal) finishEmptyCheckpointRemoval(ctx context.Context, recovery *desktopLinuxEmptyJournalRecovery, retiring bool) error {
	if j.removal == nil || j.removal.recovery != recovery || recovery != nil && recovery.journal != j {
		return errors.New("Linux journal removal lost its original terminal or startup capability")
	}
	current := func() error {
		if recovery != nil {
			return recovery.removalCurrent(ctx, retiring)
		}
		return j.removalParent(ctx)
	}
	if err := mobiletor.ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
		return err
	}
	for index := range j.removal.files {
		if err := current(); err != nil {
			return err
		}
		if err := j.removalObjects(); err != nil {
			return err
		}
		file := &j.removal.files[index]
		if !file.removed {
			if err := j.root.Remove(file.owner.name); err != nil {
				return err
			}
			file.removed = true
			if err := j.directory.Sync(); err != nil {
				return err
			}
		}
	}
	if err := current(); err != nil {
		return err
	}
	if err := j.removalObjects(); err != nil {
		return err
	}
	if !j.removal.directoryRemoved {
		if err := j.anchor.Remove(desktopLinuxNodeJournalDirectory); err != nil {
			return err
		}
		j.removal.directoryRemoved = true
	}
	anchor, err := j.anchor.Open(".")
	if err != nil {
		return err
	}
	if err := errors.Join(anchor.Sync(), anchor.Close()); err != nil {
		return err
	}
	if err := j.removalObjects(); err != nil {
		return err
	}
	if err := mobiletor.ReadDesktopLinuxProtectionAbsence(ctx); err != nil {
		return err
	}
	if err := current(); err != nil {
		return err
	}
	j.removal.complete = true
	return ctx.Err()
}
