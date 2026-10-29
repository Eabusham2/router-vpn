//go:build darwin || linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// Framework Python locates its standard library relative to the loaded Python
// image, not necessarily the launcher in usr/bin. Capture that image from the
// actual Mach-O load commands before executing any candidate. The CLT SDK,
// debugger and unrelated tools are not Python's runtime or trust authority.
// See CPython Modules/getpath.c and Mac/Tools/pythonw.c, and Apple's dyld
// run-path documentation. All runtime paths below still receive real owner,
// mode, ACL and symlink checks; no candidate is asked to establish its own trust.

type macPythonLoad struct {
	name string
	weak bool
}

type macPythonImage struct {
	cpu, subtype, kind uint32
	loads              []macPythonLoad
	rpaths             []string
}

const macPythonMetadataLimit = 2 << 20

func macOSPythonEnvironment() []string {
	return []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/var/root", "LC_ALL=C", "PYTHONNOUSERSITE=1",
		"DYLD_FALLBACK_LIBRARY_PATH=/usr/lib", "DYLD_FALLBACK_FRAMEWORK_PATH=/System/Library/Frameworks",
	}
}

func macPythonMachO(reader io.ReaderAt, size int64) ([]macPythonImage, bool, error) {
	var header [8]byte
	if size < 4 {
		return nil, false, nil
	}
	if _, err := reader.ReadAt(header[:4], 0); err != nil {
		return nil, false, err
	}
	magic := binary.BigEndian.Uint32(header[:4])
	if magic == 0xcafebabe || magic == 0xbebafeca || magic == 0xcafebabf || magic == 0xbfbafeca {
		order := binary.ByteOrder(binary.BigEndian)
		if magic == 0xbebafeca || magic == 0xbfbafeca {
			order = binary.LittleEndian
		}
		if size < 8 {
			return nil, true, errors.New("truncated Python universal image")
		}
		if _, err := reader.ReadAt(header[:], 0); err != nil {
			return nil, true, err
		}
		count := order.Uint32(header[4:])
		width := int64(20)
		if magic == 0xcafebabf || magic == 0xbfbafeca {
			width = 32
		}
		if count == 0 || count > 8 || int64(count)*width > size-8 {
			return nil, true, errors.New("unbounded Python universal image")
		}
		table := make([]byte, int64(count)*width)
		if _, err := reader.ReadAt(table, 8); err != nil {
			return nil, true, err
		}
		var images []macPythonImage
		var ranges [][2]uint64
		seen := make(map[[2]uint32]bool)
		for at := int64(0); at < int64(len(table)); at += width {
			entry := table[at : at+width]
			cpu, subtype := order.Uint32(entry), order.Uint32(entry[4:])
			offset, length, alignment := uint64(order.Uint32(entry[8:])), uint64(order.Uint32(entry[12:])), order.Uint32(entry[16:])
			if width == 32 {
				offset, length, alignment = order.Uint64(entry[8:]), order.Uint64(entry[16:]), order.Uint32(entry[24:])
				if order.Uint32(entry[28:]) != 0 {
					return nil, true, errors.New("Python universal image has nonzero reserved metadata")
				}
			}
			if seen[[2]uint32{cpu, subtype}] || alignment > 30 || offset < uint64(8+len(table)) || offset > uint64(size) || length > uint64(size)-offset || length < 28 || offset%(uint64(1)<<alignment) != 0 {
				return nil, true, errors.New("Python universal image has ambiguous architecture bounds")
			}
			for _, span := range ranges {
				if offset < span[1] && span[0] < offset+length {
					return nil, true, errors.New("Python universal architectures overlap")
				}
			}
			seen[[2]uint32{cpu, subtype}] = true
			ranges = append(ranges, [2]uint64{offset, offset + length})
			image, err := macPythonThinMachO(io.NewSectionReader(reader, int64(offset), int64(length)), int64(length))
			if err != nil {
				return nil, true, err
			}
			if image.cpu != cpu || image.subtype != subtype {
				return nil, true, errors.New("Python universal architecture differs from its actual image")
			}
			images = append(images, image)
		}
		return images, true, nil
	}
	if magic != 0xfeedface && magic != 0xcefaedfe && magic != 0xfeedfacf && magic != 0xcffaedfe {
		return nil, false, nil
	}
	image, err := macPythonThinMachO(reader, size)
	return []macPythonImage{image}, true, err
}

func macPythonThinMachO(reader io.ReaderAt, size int64) (macPythonImage, error) {
	var image macPythonImage
	var header [32]byte
	if size < 32 {
		return image, errors.New("truncated privileged Python Mach-O header")
	}
	if _, err := reader.ReadAt(header[:], 0); err != nil {
		return image, err
	}
	order := binary.ByteOrder(binary.LittleEndian)
	if binary.BigEndian.Uint32(header[:]) == 0xfeedfacf {
		order = binary.BigEndian
	}
	if order.Uint32(header[:]) != 0xfeedfacf {
		return image, errors.New("privileged Python needs a supported 64-bit native image")
	}
	image.cpu, image.subtype, image.kind = order.Uint32(header[4:]), order.Uint32(header[8:]), order.Uint32(header[12:])
	if (image.cpu != 0x01000007 && image.cpu != 0x0100000c) || (image.kind != 1 && image.kind != 2 && image.kind != 6 && image.kind != 8) {
		return image, errors.New("privileged Python image has an unsupported architecture or type")
	}
	count, length := order.Uint32(header[16:]), order.Uint32(header[20:])
	if count == 0 || count > 4096 || length < 8 || length > macPythonMetadataLimit || int64(length) > size-32 {
		return image, errors.New("privileged Python load commands exceed their captured bounds")
	}
	commands := make([]byte, length)
	if _, err := reader.ReadAt(commands, 32); err != nil {
		return image, err
	}
	for number, at := uint32(0), 0; ; number++ {
		if number == count {
			if at != len(commands) {
				return image, errors.New("privileged Python has unaccounted load commands")
			}
			break
		}
		if at+8 > len(commands) {
			return image, errors.New("truncated privileged Python load command")
		}
		kind, span := order.Uint32(commands[at:]), uint64(order.Uint32(commands[at+4:]))
		if span < 8 || span%8 != 0 || span > uint64(len(commands)-at) {
			return image, errors.New("invalid privileged Python load command extent")
		}
		command := commands[at : at+int(span)]
		path := func(minimum uint32) (string, error) {
			if len(command) < int(minimum) {
				return "", errors.New("truncated privileged Python dependency")
			}
			offset := order.Uint32(command[8:])
			if offset < minimum || uint64(offset) >= span {
				return "", errors.New("invalid privileged Python dependency offset")
			}
			value := command[offset:]
			end := bytes.IndexByte(value, 0)
			if end < 1 || end > 4096 || bytes.IndexFunc(value[:end], func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
				return "", errors.New("invalid privileged Python dependency name")
			}
			return string(value[:end]), nil
		}
		switch kind {
		case 0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023:
			name, err := path(24)
			if err != nil {
				return image, err
			}
			image.loads = append(image.loads, macPythonLoad{name, kind == 0x80000018})
		case 0x8000001c:
			name, err := path(12)
			if err != nil {
				return image, err
			}
			image.rpaths = append(image.rpaths, name)
		case 0xe:
			name, err := path(12)
			if err != nil || name != "/usr/lib/dyld" {
				return image, errors.New("privileged Python selected a foreign dynamic loader")
			}
		case 0x6, 0x9, 0x10, 0x27:
			return image, errors.New("privileged Python contains an unsupported loader or embedded environment")
		case 0x1, 0x2, 0x3, 0x4, 0x5, 0x7, 0x8, 0xa, 0xb, 0xd, 0xf, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x19, 0x1a, 0x1b, 0x1d, 0x1e, 0x21, 0x22, 0x80000022, 0x24, 0x25, 0x26, 0x80000028, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x80000033, 0x80000034, 0x36, 0x37, 0x38, 0x39:
			// Non-loading metadata, sections, symbol tables and code signatures.
		default:
			return image, fmt.Errorf("privileged Python has an unrecognized load command %#x", kind)
		}
		at += int(span)
	}
	return image, nil
}

// Resolve each lexical component before processing '..'. Cleaning a path
// first can conceal a writable symlink which dyld or the Python importer would
// actually traverse. Missing suffixes are returned only after the complete
// existing prefix has been proved; callers decide whether absence is allowed.
func macPythonOwnedResolve(path string) (string, fs.FileInfo, error) {
	if !filepath.IsAbs(path) || len(path) > 16384 || strings.ContainsAny(path, "\x00\r\n") {
		return "", nil, errors.New("invalid privileged Python runtime path")
	}
	if err := trustedMacToolAncestors("/"); err != nil {
		return "", nil, err
	}
	components, current, links := strings.Split(path, "/"), "/", 0
	for len(components) != 0 {
		part := components[0]
		components = components[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			current = filepath.Dir(current)
			continue
		}
		name := current + "/" + part
		if current == "/" {
			name = "/" + part
		}
		info, err := os.Lstat(name)
		if err != nil {
			return filepath.Clean(name + "/" + strings.Join(components, "/")), nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 || links >= 40 {
				return "", nil, macPythonRejectedLink(name, "", stat, errors.New("untrusted or cyclic runtime link"))
			}
			if err := ownedPathACL(name); err != nil {
				return "", nil, err
			}
			target, err := os.Readlink(name)
			if err != nil {
				return "", nil, err
			}
			if filepath.IsAbs(target) {
				current = "/"
			}
			components = append(strings.Split(target, "/"), components...)
			links++
			continue
		}
		if !trustedMacToolInfo(info) || len(components) != 0 && !info.IsDir() {
			return "", nil, fmt.Errorf("privileged Python runtime path has foreign mutation authority: %s", macPythonDiagnosticValue(name))
		}
		if err := ownedPathACL(name); err != nil {
			return "", nil, err
		}
		current = name
	}
	info, err := os.Lstat(current)
	if err != nil || !trustedMacToolInfo(info) {
		return "", nil, errors.New("the privileged Python runtime path is not protected")
	}
	return current, info, ownedPathACL(current)
}

func macPythonReadImages(path string) ([]macPythonImage, error) {
	canonical, before, err := macPythonOwnedResolve(path)
	if err != nil || canonical != path || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("cannot capture privileged Python native image %s: %w", macPythonDiagnosticValue(path), err)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !trustedMacToolInfo(opened) || opened.Size() > 512<<20 {
		return nil, errors.New("privileged Python native image changed its captured object or size")
	}
	images, _, err := macPythonMachO(file, opened.Size())
	if err != nil {
		return nil, fmt.Errorf("inspect privileged Python image %s: %w", macPythonDiagnosticValue(path), err)
	}
	after, err := file.Stat()
	named, nameErr := os.Lstat(path)
	if err != nil || nameErr != nil || !os.SameFile(opened, named) || !trustedMacToolInfo(named) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || opened.Mode() != after.Mode() {
		return nil, errors.New("privileged Python native image changed during inspection")
	}
	return images, nil
}

func macPythonSystemLibrary(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && (strings.HasPrefix(path, "/usr/lib/") || strings.HasPrefix(path, "/System/Library/"))
}

func macPythonExpand(name, loader, executable string) (string, error) {
	switch {
	case name == "@loader_path":
		return filepath.Dir(loader), nil
	case name == "@executable_path":
		return filepath.Dir(executable), nil
	case strings.HasPrefix(name, "@loader_path/"):
		return filepath.Dir(loader) + "/" + strings.TrimPrefix(name, "@loader_path/"), nil
	case strings.HasPrefix(name, "@executable_path/"):
		return filepath.Dir(executable) + "/" + strings.TrimPrefix(name, "@executable_path/"), nil
	case filepath.IsAbs(name):
		return name, nil
	default:
		return "", errors.New("privileged Python has an ambient or unbound loader search path")
	}
}

type macPythonRuntimeCapture struct {
	executable string
	core       string
	images     map[string][]macPythonImage
	visited    map[string]bool
}

var macPythonCoreImage = regexp.MustCompile("(?i)/python3?\\.framework/versions/[^/]+/python3?$")

func (capture *macPythonRuntimeCapture) image(path string) ([]macPythonImage, error) {
	if images, ok := capture.images[path]; ok {
		return images, nil
	}
	if len(capture.images) >= 4096 {
		return nil, errors.New("privileged Python native dependency graph exceeded its bound")
	}
	images, err := macPythonReadImages(path)
	if err == nil && len(images) != 0 {
		capture.images[path] = images
	}
	return images, err
}

func (capture *macPythonRuntimeCapture) paths(image macPythonImage, loader string, inherited []string) ([]string, error) {
	var paths []string
	for _, raw := range image.rpaths {
		path, err := macPythonExpand(raw, loader, capture.executable)
		if err != nil {
			return nil, err
		}
		resolved, info, err := macPythonOwnedResolve(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) || err == nil && !info.IsDir() {
			return nil, fmt.Errorf("privileged Python rpath is not protected: %s: %w", macPythonDiagnosticValue(raw), err)
		}
		paths = append(paths, resolved)
	}
	paths = append(paths, inherited...)
	unique := paths[:0]
	seen := make(map[string]bool)
	for _, path := range paths {
		if !seen[path] {
			unique = append(unique, path)
			seen[path] = true
		}
	}
	paths = unique
	if len(paths) > 256 {
		return nil, errors.New("privileged Python rpath stack exceeded its bound")
	}
	return paths, nil
}

func (capture *macPythonRuntimeCapture) resolve(load macPythonLoad, loader string, rpaths []string) (string, error) {
	var candidates []string
	if strings.HasPrefix(load.name, "@rpath/") {
		for _, path := range rpaths {
			candidates = append(candidates, path+"/"+strings.TrimPrefix(load.name, "@rpath/"))
		}
	} else {
		path, err := macPythonExpand(load.name, loader, capture.executable)
		if err != nil {
			return "", err
		}
		candidates = []string{path}
	}
	for _, path := range candidates {
		resolved, info, err := macPythonOwnedResolve(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		// Modern macOS removes cached OS dylibs from the filesystem. Their
		// authority is the protected OS namespace, not a fabricated file read.
		// Every launch fixes dyld fallback to these same OS-only directories;
		// a missing image cannot fall back to a user-owned ~/lib or /usr/local.
		if macPythonSystemLibrary(resolved) {
			return resolved, nil
		}
		if err == nil {
			if !info.Mode().IsRegular() {
				return "", errors.New("privileged Python dependency is not a regular image")
			}
			return resolved, nil
		}
	}
	if load.weak && len(candidates) != 0 {
		return "", nil
	}
	return "", fmt.Errorf("privileged Python dependency has no protected target: %s from %s", macPythonDiagnosticValue(load.name), macPythonDiagnosticValue(loader))
}

func (capture *macPythonRuntimeCapture) inspect(path string, image macPythonImage, inherited []string, depth int) error {
	if depth > 64 {
		return errors.New("privileged Python dependency graph is cyclic or too deep")
	}
	rpaths, err := capture.paths(image, path, inherited)
	if err != nil {
		return err
	}
	key := capture.executable + "\x00" + path + "\x00" + strconv.FormatUint(uint64(image.cpu), 10) + "\x00" + strconv.FormatUint(uint64(image.subtype), 10) + "\x00" + strings.Join(rpaths, "\x00")
	if capture.visited[key] {
		return nil
	}
	if len(capture.visited) >= 8192 {
		return errors.New("privileged Python loader contexts exceeded their bound")
	}
	capture.visited[key] = true
	for _, load := range image.loads {
		target, err := capture.resolve(load, path, rpaths)
		if err != nil {
			return err
		}
		if target == "" {
			continue
		}
		if macPythonCoreImage.MatchString(target) && target != capture.core {
			return errors.New("a native dependency selected another Python core outside the captured runtime")
		}
		if macPythonSystemLibrary(target) {
			continue
		}
		images, err := capture.image(target)
		if err != nil {
			return err
		}
		matched := false
		for _, child := range images {
			if child.cpu == image.cpu && child.kind == 6 {
				matched = true
				if err := capture.inspect(target, child, rpaths, depth+1); err != nil {
					return err
				}
			}
		}
		if !matched {
			return fmt.Errorf("privileged Python dependency lacks its selected architecture: %s", macPythonDiagnosticValue(target))
		}
	}
	return nil
}

func (capture *macPythonRuntimeCapture) executableUsesCore(path string, image macPythonImage) error {
	if image.kind != 2 || capture.core == "" {
		return errors.New("the Python executable has no captured runtime core")
	}
	rpaths, err := capture.paths(image, path, nil)
	if err != nil {
		return err
	}
	matched := false
	for _, load := range image.loads {
		target, err := capture.resolve(load, path, rpaths)
		if err != nil {
			return err
		}
		if target == capture.core && !load.weak {
			matched = true
		}
		if macPythonCoreImage.MatchString(target) && target != capture.core {
			return errors.New("a Python executable selected another core and an uncaptured standard library")
		}
	}
	if !matched {
		return errors.New("a Python executable does not bind the captured framework core")
	}
	return nil
}

func validateMacPythonRuntime(executable, framework string) (string, error) {
	canonical, info, err := macPythonOwnedResolve(executable)
	if err != nil || canonical != executable || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return "", errors.New("the privileged interpreter is not a protected native executable")
	}
	if err := trustedMacToolAncestors(framework); err != nil {
		return "", err
	}
	capture := macPythonRuntimeCapture{executable: executable, images: make(map[string][]macPythonImage), visited: make(map[string]bool)}
	entries, err := capture.image(executable)
	if err != nil || len(entries) == 0 {
		return "", errors.Join(errors.New("the privileged interpreter has no captured native loader"), err)
	}
	coreName := strings.TrimSuffix(filepath.Base(framework), ".framework")
	corePattern := regexp.MustCompile("^" + regexp.QuoteMeta(framework) + `/Versions/(3\.[0-9]+)/` + regexp.QuoteMeta(coreName) + "$")
	root, version := "", ""
	for _, entry := range entries {
		if entry.kind != 2 {
			return "", errors.New("the selected Python entry is not a native executable")
		}
		rpaths, err := capture.paths(entry, executable, nil)
		if err != nil {
			return "", err
		}
		found := ""
		for _, load := range entry.loads {
			target, err := capture.resolve(load, executable, rpaths)
			if err != nil {
				return "", err
			}
			match := corePattern.FindStringSubmatch(target)
			if len(match) == 0 {
				continue
			}
			minor, _ := strconv.Atoi(strings.TrimPrefix(match[1], "3."))
			if minor < 9 || found != "" && found != filepath.Dir(target) {
				return "", errors.New("the Python entry selected an old or ambiguous framework")
			}
			found, version = filepath.Dir(target), match[1]
		}
		if found == "" || root != "" && root != found {
			var names []string
			for _, load := range entry.loads {
				names = append(names, load.name)
			}
			return "", fmt.Errorf("the Python entry has no single captured framework for every architecture: entry=%s cpu=%#x imports=%s rpaths=%s",
				macPythonDiagnosticValue(executable), entry.cpu, macPythonDiagnosticValue(strings.Join(names, ",")), macPythonDiagnosticValue(strings.Join(rpaths, ",")))
		}
		root = found
		capture.core = root + "/" + coreName
		if err := capture.executableUsesCore(executable, entry); err != nil {
			return "", err
		}
		if err := capture.inspect(executable, entry, nil, 0); err != nil {
			return "", err
		}
	}
	stdlib := root + "/lib/python" + version
	for _, landmark := range []string{stdlib + "/os.py", stdlib + "/encodings/__init__.py"} {
		resolved, info, err := macPythonOwnedResolve(landmark)
		if err != nil || !strings.HasPrefix(resolved, root+"/") || !info.Mode().IsRegular() {
			return "", fmt.Errorf("captured Python framework lacks its protected standard library: %s", macPythonDiagnosticValue(landmark))
		}
	}
	zip := root + "/lib/python" + strings.ReplaceAll(version, ".", "") + ".zip"
	if resolved, info, err := macPythonOwnedResolve(zip); err == nil {
		if !strings.HasPrefix(resolved, root+"/") || !info.Mode().IsRegular() {
			return "", errors.New("the Python standard library archive escaped its captured framework")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	// Python's framework launcher can exec Resources/Python.app. Its exact
	// owned executable and every stdlib extension receive the same native
	// dependency inspection, including lazy/weak/reexport/upward imports.
	var pending = []string{stdlib}
	app := root + "/Resources/Python.app"
	if _, err := os.Lstat(app); err == nil {
		pending = append(pending, app)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	seen, count := make(map[string]bool), 0
	runtimeImages := make(map[string][]macPythonImage)
	for len(pending) > 0 {
		tree := pending[0]
		pending = pending[1:]
		if seen[tree] {
			continue
		}
		seen[tree] = true
		err := filepath.WalkDir(tree, func(path string, entry fs.DirEntry, failure error) error {
			count++
			if failure != nil || count > 300000 {
				return errors.New("the Python runtime closure cannot be bounded and inspected")
			}
			resolved, info, err := macPythonOwnedResolve(path)
			if err != nil {
				return err
			}
			if !strings.HasPrefix(resolved, root+"/") {
				return errors.New("the Python standard library link escaped its captured framework")
			}
			if info.IsDir() {
				if resolved != path {
					pending = append(pending, resolved)
				}
				return nil
			}
			if strings.HasSuffix(path, "._pth") || filepath.Base(path) == "pyvenv.cfg" {
				return errors.New("the privileged Python runtime contains a path override")
			}
			images, err := capture.image(resolved)
			if err != nil {
				return err
			}
			if len(images) != 0 {
				runtimeImages[resolved] = images
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	// An app launcher starts a fresh dyld executable context. Inspect extension
	// imports with every captured entry's own @executable_path/rpath stack,
	// rather than applying the outer usr/bin launcher's path to the app child.
	contexts := map[string][]macPythonImage{executable: entries}
	for path, images := range runtimeImages {
		for _, image := range images {
			if image.kind == 2 {
				contexts[path] = append(contexts[path], image)
			}
		}
	}
	for entryPath, entries := range contexts {
		context := capture
		context.executable = entryPath
		for _, entry := range entries {
			if err := context.executableUsesCore(entryPath, entry); err != nil {
				return "", err
			}
			rpaths, err := context.paths(entry, entryPath, nil)
			if err != nil {
				return "", err
			}
			if err := context.inspect(entryPath, entry, nil, 0); err != nil {
				return "", err
			}
			for path, images := range runtimeImages {
				for _, image := range images {
					if image.cpu == entry.cpu && (image.kind == 6 || image.kind == 8) {
						if err := context.inspect(path, image, rpaths, 0); err != nil {
							return "", err
						}
					}
				}
			}
		}
	}
	// These configuration files change prefix/import search before -S takes
	// effect. Absence must be proved in the already-owned entry/core parents.
	overrides := []string{root + "/pyvenv.cfg", root + "/" + coreName + "._pth"}
	for entryPath := range contexts {
		base := filepath.Base(entryPath)
		for _, parent := range []string{filepath.Dir(entryPath), filepath.Dir(filepath.Dir(entryPath))} {
			for _, name := range []string{"pyvenv.cfg", base + "._pth", strings.TrimSuffix(base, filepath.Ext(base)) + "._pth"} {
				overrides = append(overrides, parent+"/"+name)
			}
		}
	}
	for _, path := range overrides {
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("privileged Python prefix override cannot be admitted: %s", macPythonDiagnosticValue(path))
		}
	}
	return root, nil
}
