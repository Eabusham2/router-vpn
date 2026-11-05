//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const linuxStandardGenerationActivation = "service-generation.json"
const linuxStandardGenerationManifest = "generation.json"

type linuxStandardGenerationSelection struct {
	Schema      int    `json:"schema"`
	Generation  string `json:"generation"`
	ImageSHA256 string `json:"image_sha256"`
}
type linuxStandardGenerationEntry struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}
type linuxStandardGenerationManifestData struct {
	Schema int                            `json:"schema"`
	Files  []linuxStandardGenerationEntry `json:"files"`
}
type linuxStandardGenerationObject struct {
	path string
	info os.FileInfo
}

// The selection is only initial discovery. This capability retains its original
// immutable generation and lease when a later installation selects another one.
// It cannot construct, recover, or delete a native protection creator.
type linuxStandardServiceGeneration struct {
	root, imagePath                   string
	directory, manifest, image, lease *os.File
	store                             *os.File
	storeInfo                         os.FileInfo
	objects                           []linuxStandardGenerationObject
	imageInfo                         os.FileInfo
}

func linuxStandardGenerationEqual(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Dev == y.Dev && x.Ino == y.Ino && x.Mode == y.Mode && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Size == y.Size && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}
func linuxStandardGenerationTrusted(info os.FileInfo, directory bool) bool {
	if info == nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && st.Gid == 0 && info.Mode().Perm()&0022 == 0 && (directory && info.IsDir() || !directory && info.Mode().IsRegular() && st.Nlink == 1)
}
func linuxStandardGenerationOpen(path string, directory bool) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil || !linuxStandardGenerationTrusted(before, directory) {
		return nil, nil, errors.Join(err, errors.New("service generation contains an unsafe original object"))
	}
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	if directory {
		flags |= syscall.O_DIRECTORY
	}
	fd, err := syscall.Open(path, flags, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), "captured-service-generation")
	info, err := f.Stat()
	if err != nil || !linuxStandardGenerationEqual(before, info) {
		f.Close()
		return nil, nil, errors.Join(err, errors.New("service generation object changed during capture"))
	}
	return f, info, nil
}
func linuxStandardGenerationRead(ctx context.Context, f *os.File, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	buf := make([]byte, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := f.Read(buf)
		if int64(out.Len()+n) > limit {
			return nil, errors.New("service generation object exceeded bound")
		}
		out.Write(buf[:n])
		if err == io.EOF {
			return out.Bytes(), ctx.Err()
		}
		if err != nil {
			return nil, err
		}
	}
}
func linuxStandardGenerationHash(ctx context.Context, f *os.File) (string, error) {
	if _, err := f.Seek(0, 0); err != nil {
		return "", err
	}
	h := sha256.New()
	buf := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := f.Read(buf)
		h.Write(buf[:n])
		if err == io.EOF {
			return hex.EncodeToString(h.Sum(nil)), ctx.Err()
		}
		if err != nil {
			return "", err
		}
	}
}
func linuxStandardGenerationDecode(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("service generation metadata has trailing data")
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.Join(err, errors.New("service generation metadata is not canonical"))
	}
	return nil
}
func linuxStandardGenerationHex(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func captureLinuxStandardServiceGeneration(ctx context.Context, root string) (out *linuxStandardServiceGeneration, failure error) {
	if ctx == nil {
		return nil, errors.New("service generation has no caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	activation := filepath.Join(root, linuxStandardGenerationActivation)
	if _, err := os.Lstat(activation); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	file, activationInfo, err := linuxStandardGenerationOpen(activation, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := linuxStandardGenerationRead(ctx, file, 4096)
	if err != nil {
		return nil, err
	}
	var selection linuxStandardGenerationSelection
	if err = linuxStandardGenerationDecode(raw, &selection); err != nil || selection.Schema != 1 || !linuxStandardGenerationHex(selection.Generation) || !linuxStandardGenerationHex(selection.ImageSHA256) {
		return nil, errors.Join(err, errors.New("service activation lost exact generation selection"))
	}
	store := root + ".service-generations"
	if err = ownedDesktopAncestors(store); err != nil {
		return nil, err
	}
	g := &linuxStandardServiceGeneration{root: filepath.Join(store, selection.Generation)}
	g.store, g.storeInfo, err = linuxStandardGenerationOpen(store, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if failure != nil {
			g.Close()
		}
	}()
	g.directory, _, err = linuxStandardGenerationOpen(g.root, true)
	if err != nil {
		return nil, err
	}
	directoryInfo, err := g.directory.Stat()
	if err != nil {
		return nil, err
	}
	g.objects = append(g.objects, linuxStandardGenerationObject{g.root, directoryInfo})
	lockPath := filepath.Join(store, selection.Generation+".lock")
	lockInfo, err := os.Lstat(lockPath)
	if err != nil {
		return nil, err
	}
	g.lease, err = ownedDesktopLock(lockPath, false)
	if err != nil {
		return nil, err
	}
	opened, err := g.lease.Stat()
	if err != nil || !linuxStandardGenerationEqual(lockInfo, opened) {
		return nil, errors.Join(err, errors.New("service generation lease was replaced"))
	}
	g.objects = append(g.objects, linuxStandardGenerationObject{lockPath, opened})
	manifestPath := filepath.Join(g.root, linuxStandardGenerationManifest)
	g.manifest, opened, err = linuxStandardGenerationOpen(manifestPath, false)
	if err != nil {
		return nil, err
	}
	g.objects = append(g.objects, linuxStandardGenerationObject{manifestPath, opened})
	body, err := linuxStandardGenerationRead(ctx, g.manifest, 2<<20)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != selection.Generation {
		return nil, errors.New("service generation manifest differs from selection")
	}
	var manifest linuxStandardGenerationManifestData
	if err = linuxStandardGenerationDecode(body, &manifest); err != nil || manifest.Schema != 1 || len(manifest.Files) == 0 || len(manifest.Files) > 8192 {
		return nil, errors.Join(err, errors.New("service generation inventory is invalid"))
	}
	names := make([]string, 0, len(manifest.Files))
	seen := map[string]bool{}
	for _, entry := range manifest.Files {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if entry.Path == "" || entry.Path == linuxStandardGenerationManifest || filepath.IsAbs(entry.Path) || filepath.Clean(entry.Path) != entry.Path || entry.Path == ".." || strings.HasPrefix(entry.Path, "../") || strings.ContainsAny(entry.Path, "\\\x00") || seen[entry.Path] || entry.Mode&^0777 != 0 {
			return nil, errors.New("service generation inventory changed its exact path scope")
		}
		seen[entry.Path] = true
		names = append(names, entry.Path)
		path := filepath.Join(g.root, entry.Path)
		directory := entry.SHA256 == ""
		f, info, readErr := linuxStandardGenerationOpen(path, directory)
		if readErr != nil {
			return nil, readErr
		}
		if uint32(info.Mode().Perm()) != entry.Mode {
			f.Close()
			return nil, errors.New("service generation mode differs from manifest")
		}
		if !directory {
			if !linuxStandardGenerationHex(entry.SHA256) {
				f.Close()
				return nil, errors.New("service generation digest invalid")
			}
			hash, hashErr := linuxStandardGenerationHash(ctx, f)
			if hashErr != nil || hash != entry.SHA256 {
				f.Close()
				return nil, errors.Join(hashErr, errors.New("service generation code changed"))
			}
		}
		after, statErr := f.Stat()
		if statErr != nil || !linuxStandardGenerationEqual(info, after) {
			f.Close()
			return nil, errors.Join(statErr, errors.New("service generation code changed while hashing"))
		}
		g.objects = append(g.objects, linuxStandardGenerationObject{path, info})
		if entry.Path == "router-vpn-client" {
			if directory || entry.Mode&0111 == 0 || entry.SHA256 != selection.ImageSHA256 {
				f.Close()
				return nil, errors.New("service generation lost exact executable")
			}
			g.image, g.imageInfo, g.imagePath = f, info, path
		} else {
			f.Close()
		}
	}
	if !sort.StringsAreSorted(names) || g.image == nil {
		return nil, errors.New("service generation inventory is incomplete or unordered")
	}
	count := 0
	err = filepath.WalkDir(g.root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == g.root || path == manifestPath {
			return nil
		}
		rel, err := filepath.Rel(g.root, path)
		if err != nil || !seen[rel] {
			return errors.Join(err, errors.New("service generation contains undeclared source"))
		}
		count++
		return nil
	})
	if err != nil || count != len(manifest.Files) {
		return nil, errors.Join(err, errors.New("service generation inventory differs from actual source"))
	}
	if err = g.Current(ctx); err != nil {
		return nil, err
	}
	// Activation must remain the exact originally read object through discovery.
	actual, err := os.Lstat(activation)
	captured, statErr := file.Stat()
	if err != nil || statErr != nil || !linuxStandardGenerationEqual(activationInfo, captured) || !linuxStandardGenerationEqual(actual, captured) {
		return nil, errors.Join(err, statErr, errors.New("service activation changed during discovery"))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return g, nil
}
func (g *linuxStandardServiceGeneration) Current(ctx context.Context) error {
	if g == nil || ctx == nil || g.directory == nil || g.manifest == nil || g.image == nil || g.lease == nil {
		return errors.New("service generation lost retained capability")
	}
	storeInfo, err := os.Lstat(filepath.Dir(g.root))
	if err != nil || g.store == nil || !os.SameFile(storeInfo, g.storeInfo) || !linuxStandardGenerationTrusted(storeInfo, true) {
		return errors.Join(err, errors.New("original generation store was replaced"))
	}
	for _, object := range g.objects {
		if err := ctx.Err(); err != nil {
			return err
		}
		actual, err := os.Lstat(object.path)
		if err != nil || !linuxStandardGenerationEqual(object.info, actual) {
			return errors.Join(err, errors.New("original service generation was changed"))
		}
	}
	for _, f := range []*os.File{g.directory, g.manifest, g.image, g.lease, g.store} {
		if _, err := f.Stat(); err != nil {
			return err
		}
	}
	return ctx.Err()
}
func (g *linuxStandardServiceGeneration) Close() error {
	if g == nil {
		return nil
	}
	var failures []error
	for _, f := range []*os.File{g.image, g.manifest, g.directory, g.lease, g.store} {
		if f != nil {
			failures = append(failures, f.Close())
		}
	}
	g.image, g.manifest, g.directory, g.lease, g.store = nil, nil, nil, nil, nil
	return errors.Join(failures...)
}

func (g *linuxStandardServiceGeneration) socket(directory string) string {
	if g == nil {
		return filepath.Join(directory, "control.sock")
	}
	return filepath.Join(directory, "g-"+filepath.Base(g.root)+".sock")
}

// Discovery resolves activation only before a live owner is retained. A later
// activation cannot redirect that owner's Stop or original cleanup channel.
func linuxStandardServiceDestination(ctx context.Context, root, directory string, legacyImage os.FileInfo, prior *linuxStandardServicePeer) (os.FileInfo, []string, string, *linuxStandardServiceGeneration, error) {
	if prior != nil {
		if err := prior.Current(ctx); err != nil {
			return nil, nil, "", nil, err
		}
		return prior.image, strings.Split(strings.TrimSuffix(string(prior.arguments), "\x00"), "\x00"), prior.generation.socket(directory), nil, nil
	}
	generation, err := captureLinuxStandardServiceGeneration(ctx, root)
	if err != nil {
		return nil, nil, "", nil, err
	}
	if generation == nil {
		return legacyImage, []string{filepath.Join(root, "router-vpn-client"), linuxStandardServiceArgument}, generation.socket(directory), nil, nil
	}
	return generation.imageInfo, []string{generation.imagePath, linuxStandardServiceArgument}, generation.socket(directory), generation, nil
}
