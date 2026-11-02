package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

const desktopExternalComparisonLimit = 128
const desktopExternalComparisonBytes = 64 << 20

var errDesktopComparisonSourceBound = errors.New("external comparison captured sources exceed the 64 MiB aggregate bound")

type desktopExternalComparisonCandidate struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	EntryID     string `json:"entry_id,omitempty"`
	EntryName   string `json:"entry_name,omitempty"`
	EntryMode   string `json:"entry_mode,omitempty"`
	Requested   string `json:"requested_execution"`
	SourceToken string `json:"source_token"`
	Failure     string `json:"failure,omitempty"`
	request     speedLabRequest
	profile     common.RouterProfile
	entry       common.RouterProfile
	entrySource string
}

// These are immutable original bytes, not generated copies that a later
// selection can replace. Shared entry assets are stored once across the batch.
type desktopExternalComparisonFile struct {
	path string
	info os.FileInfo
	data []byte
}

type desktopExternalComparisonCohort struct {
	ID         string
	profiles   common.RouterProfileStore
	candidates []desktopExternalComparisonCandidate
	files      map[string]desktopExternalComparisonFile
	bytes      int
}

func desktopComparisonDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func desktopComparisonProfileSource(profile common.RouterProfile) string {
	// Include every saved user choice, including startup, while excluding only
	// historical presentation/measurement fields from the immutable path key.
	return profileStartupSettingsToken(profile)
}

func desktopComparisonCatalogToken(store common.RouterProfileStore) (string, error) {
	if len(store.Profiles) == 0 || len(store.Profiles) > 512 {
		return "", errors.New("external comparison needs a bounded saved node catalog")
	}
	parts := []string{store.SelectedID}
	seen := map[string]bool{}
	count := 0
	for _, profile := range store.Profiles {
		if !validProfileID(profile.ID) || seen[profile.ID] {
			return "", errors.New("external comparison node identities are invalid or duplicated")
		}
		seen[profile.ID] = true
		parts = append(parts, profile.ID+":"+desktopComparisonProfileSource(profile))
		if profile.NodeKind == "external" && profile.External != nil {
			count++
		}
	}
	if count == 0 || count > desktopExternalComparisonLimit {
		return "", errors.New("external comparison requires between one and 128 saved external paths")
	}
	// Catalog order is display state; the selected node and complete source
	// revisions are the authority. A rename/reorder cannot pick a different path.
	sort.Strings(parts[1:])
	return desktopComparisonDigest([]byte(strings.Join(parts, "\x00"))), nil
}

func (c *desktopExternalComparisonCohort) close() {
	if c == nil {
		return
	}
	for path, file := range c.files {
		clear(file.data)
		delete(c.files, path)
	}
	c.candidates = nil
	c.profiles = common.RouterProfileStore{}
	c.ID = ""
}

func (c *desktopExternalComparisonCohort) captureAssets(a *app, entry common.RouterProfile, mode string) error {
	if entry.ID == "" || entry.NodeKind == "external" || entry.External != nil {
		return nil
	}
	modes := []string{mode}
	if entry.StartLayer != "" && entry.StartLayer != "off" && !mobilemultihop.MAXMode(mode) && mode != "shadowsocks" {
		modes = append(modes, "shadowsocks")
	}
	for _, selected := range modes {
		directory, err := nativeGeneratedDir(clientRoot(a), entry.ID, selected)
		if err != nil {
			return err
		}
		if _, exists := c.files[directory]; exists {
			continue
		}
		before, err := desktopComparisonCaptureFileInfo(directory)
		if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			return errors.New("captured external entry directory is missing or linked")
		}
		assets, err := readDesktopNodeAssets(clientRoot(a), entry.ID, selected)
		if err != nil {
			return err
		}
		defer func() {
			for _, raw := range assets {
				clear(raw)
			}
		}()
		for name, raw := range assets {
			path := filepath.Join(directory, name)
			info, err := desktopComparisonCaptureFileInfo(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("captured external entry asset was replaced")
			}
			readback, err := readPrivateRegular(path, 4<<20)
			equal := err == nil && bytes.Equal(raw, readback)
			clear(readback)
			after, err := os.Lstat(path)
			if !equal || err != nil || !desktopComparisonSameFile(info, after) {
				return errors.New("captured external entry asset changed while reading")
			}
			if c.bytes+len(raw) > desktopExternalComparisonBytes {
				return errDesktopComparisonSourceBound
			}
			c.files[path] = desktopExternalComparisonFile{path: path, info: after, data: append([]byte(nil), raw...)}
			c.bytes += len(raw)
		}
		after, err := os.Lstat(directory)
		if err != nil || !desktopComparisonSameFile(before, after) {
			return errors.New("captured external entry directory changed while reading")
		}
		c.files[directory] = desktopExternalComparisonFile{path: directory, info: after}
	}
	return nil
}

// Windows Lstat defers loading its native file ID until SameFile. Bind it
// before reading content or invoking a later callback, so a replacement cannot
// be mistaken for the original when the first identity check finally runs.
func desktopComparisonCaptureFileInfo(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, info) {
		return nil, errors.New("external comparison cannot capture the original file identity")
	}
	return info, nil
}

func desktopComparisonSameFile(before, after os.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) && before.Mode() == after.Mode() &&
		before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func captureDesktopExternalComparisonCohort(a *app, expected string) (*desktopExternalComparisonCohort, error) {
	a.mu.Lock()
	store := cloneRouterProfileStore(a.profiles)
	a.mu.Unlock()
	id, err := desktopComparisonCatalogToken(store)
	if err != nil || expected != "" && expected != id {
		return nil, errors.Join(err, errors.New("external comparison saved path selection changed"))
	}
	encoded, err := json.Marshal(store)
	if err != nil || len(encoded) > maxPrivateStoreBytes {
		clear(encoded)
		return nil, errors.New("external comparison private catalog exceeds its 4 MiB bound")
	}
	c := &desktopExternalComparisonCohort{ID: id, profiles: store, files: map[string]desktopExternalComparisonFile{}, bytes: len(encoded)}
	clear(encoded)
	ok := false
	defer func() {
		if !ok {
			c.close()
		}
	}()
	for _, p := range store.Profiles {
		if p.NodeKind != "external" || p.External == nil {
			continue
		}
		candidate := desktopExternalComparisonCandidate{ID: p.ID, Name: p.Name, Protocol: p.External.Protocol,
			Requested: p.MultihopExecution, SourceToken: desktopComparisonProfileSource(p), profile: p}
		q := speedLabRequest{Scope: "temporary", Topology: "external", NodeID: p.ID, Execution: p.MultihopExecution}
		if p.MultihopEnabled {
			q.EntryID, q.EntryMode = p.MultihopEntryID, p.MultihopEntryMode
		}
		entry, kind, _, entryErr := speedLabExternalEntry(store.Profiles, p, q)
		if entryErr == nil && entry.ID != "" && kind == "router-vpn" {
			q.EntryMode, entryErr = desktopExternalEntryMode(p, entry, q.EntryMode, "")
		}
		if entryErr == nil {
			entryErr = c.captureAssets(a, entry, q.EntryMode)
		}
		if entryErr == nil {
			candidate.entrySource, entryErr = startupExternalSourceToken(a, entry, q.EntryMode)
		}
		if errors.Is(entryErr, errDesktopComparisonSourceBound) || c.bytes > desktopExternalComparisonBytes {
			return nil, errors.New("external comparison aggregate source bound exceeded before any connection change")
		}
		// The catalog is already a private immutable copy. Keep value views of
		// that same source instead of cloning one large entry for each exit.
		candidate.entry = entry
		candidate.SourceToken = desktopComparisonDigest([]byte(candidate.SourceToken + "\x00" + desktopComparisonProfileSource(entry) + "\x00" + candidate.entrySource))
		candidate.EntryID, candidate.EntryName, candidate.EntryMode = entry.ID, entry.Name, q.EntryMode
		candidate.request = q
		if !desktopTorProtocol(p.External.Protocol) && !desktopExternalNativeProtocol(p.External.Protocol) {
			candidate.Failure = "This saved path has no owned native 50-response measurement engine"
		} else if entryErr != nil {
			candidate.Failure = "The saved entry source could not be captured before comparison"
		}
		c.candidates = append(c.candidates, candidate)
	}
	if err := c.current(a, store.SelectedID); err != nil {
		return nil, err
	}
	ok = true
	return c, nil
}

func (c *desktopExternalComparisonCohort) current(a *app, selected string) error {
	if c == nil || c.files == nil || c.ID == "" {
		return errors.New("external comparison source cohort is retired")
	}
	a.mu.Lock()
	err := c.currentLocked(a, selected)
	a.mu.Unlock()
	if err != nil {
		return err
	}
	return c.sourcesCurrent()
}

func (c *desktopExternalComparisonCohort) currentLocked(a *app, selected string) error {
	if a.closing || a.profiles.SelectedID != selected || len(a.profiles.Profiles) != len(c.profiles.Profiles) {
		return errors.New("external comparison user selection or catalog changed")
	}
	for _, original := range c.profiles.Profiles {
		fresh, exists := profileByID(a.profiles.Profiles, original.ID)
		if !exists || desktopComparisonProfileSource(fresh) != desktopComparisonProfileSource(original) {
			return errors.New("external comparison saved credentials or policy changed")
		}
	}
	return nil
}

func (c *desktopExternalComparisonCohort) sourcesCurrent() error {
	for _, file := range c.files {
		info, err := os.Lstat(file.path)
		if err != nil || !desktopComparisonSameFile(file.info, info) {
			return errors.New("external comparison original entry source was replaced or edited")
		}
		if info.IsDir() {
			continue
		}
		raw, err := readPrivateRegular(file.path, 4<<20)
		equal := err == nil && bytes.Equal(raw, file.data)
		clear(raw)
		after, err := os.Lstat(file.path)
		if !equal || err != nil || !desktopComparisonSameFile(file.info, after) {
			return errors.New("external comparison private source bytes changed")
		}
	}
	return nil
}

// The private store remains an exact retained file capability across the
// batch's own restoration writes. A different writer is never overwritten.
type desktopComparisonStoreOwner struct {
	path string
	info os.FileInfo
	raw  []byte
}

func captureDesktopComparisonStore(a *app, expected common.RouterProfileStore) (*desktopComparisonStoreOwner, error) {
	path := a.cfg.ProfilesFile
	info, err := desktopComparisonCaptureFileInfo(path)
	if err != nil {
		return nil, err
	}
	raw, err := readPrivateRegular(path, maxPrivateStoreBytes)
	if err != nil {
		return nil, err
	}
	var stored common.RouterProfileStore
	after, statErr := os.Lstat(path)
	if statErr != nil || !desktopComparisonSameFile(info, after) || decodeRelayControlJSON(raw, &stored) != nil || !reflect.DeepEqual(stored, expected) {
		clear(raw)
		return nil, errors.New("external comparison private profile store differs from its captured saved state")
	}
	return &desktopComparisonStoreOwner{path: path, info: after, raw: raw}, nil
}

func (s *desktopComparisonStoreOwner) current() error {
	if s == nil || s.info == nil {
		return errors.New("external comparison private store authority is unavailable")
	}
	before, err := os.Lstat(s.path)
	if err != nil || !desktopComparisonSameFile(s.info, before) {
		return errors.New("external comparison private store was replaced")
	}
	raw, err := readPrivateRegular(s.path, maxPrivateStoreBytes)
	equal := err == nil && bytes.Equal(raw, s.raw)
	clear(raw)
	after, err := os.Lstat(s.path)
	if !equal || err != nil || !desktopComparisonSameFile(s.info, after) {
		return errors.New("external comparison private store changed")
	}
	return nil
}

func (s *desktopComparisonStoreOwner) write(store common.RouterProfileStore) error {
	return s.writeChecked(store, nil)
}

func (s *desktopComparisonStoreOwner) writeChecked(store common.RouterProfileStore, extra func() error) error {
	if err := s.current(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(store, "", "  ")
	if err != nil || len(raw) > maxPrivateStoreBytes {
		clear(raw)
		return errors.New("external comparison cannot serialize the captured private store")
	}
	raw = append(raw, '\n')
	defer clear(raw)
	published, err := atomicWritePrivateChecked(s.path, raw, func() error {
		if err := s.current(); err != nil {
			return err
		}
		if extra != nil {
			return extra()
		}
		return nil
	})
	if err != nil {
		return err
	}
	// The rename committed. Never mistake a post-commit readback failure for a
	// safe rollback opportunity; callers report the durable outcome separately.
	clear(s.raw)
	s.info, s.raw = published, append([]byte(nil), raw...)
	before, err := os.Lstat(s.path)
	readback, readErr := readPrivateRegular(s.path, maxPrivateStoreBytes)
	after, afterErr := os.Lstat(s.path)
	equal := bytes.Equal(raw, readback)
	clear(readback)
	if err != nil || readErr != nil || afterErr != nil || !equal || !desktopComparisonSameFile(published, before) || !desktopComparisonSameFile(published, after) {
		return &desktopComparisonCommittedWriteError{errors.New("private selection was written, but its exact readback is unresolved")}
	}
	return nil
}

type desktopComparisonCommittedWriteError struct{ error }

func desktopComparisonStoreCommitted(err error) bool {
	var committed *desktopComparisonCommittedWriteError
	return errors.As(err, &committed)
}

func (c desktopExternalComparisonCandidate) description() string {
	if c.EntryID == "" {
		return fmt.Sprintf("%s · %s · direct saved path", c.Name, c.Protocol)
	}
	return fmt.Sprintf("%s · %s · via %s (%s)", c.Name, c.Protocol, c.EntryName, c.EntryMode)
}
