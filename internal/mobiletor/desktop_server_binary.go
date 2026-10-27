package mobiletor

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const ServerTorSourceLockSHA256 = "ca52ffdbda44d1554c6ac0cadd7ce84bca2c1e1f46f5ca6c5aaab1d34bf0459f"

// ServerTorBinary captures the installed image's static executable. Neither a
// lease nor a private source can provide an executable, digest or launch flag.
type ServerTorBinary struct {
	path   string
	info   os.FileInfo
	digest string
}

func VerifyServerTorPackage(prefix string) (*ServerTorBinary, error) {
	bad := errors.New("installed server Tor package is unavailable or changed")
	if runtime.GOOS != "linux" || !filepath.IsAbs(prefix) || filepath.Clean(prefix) != prefix {
		return nil, bad
	}
	for path := prefix; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, bad
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	root, err := os.OpenRoot(prefix)
	if err != nil {
		return nil, bad
	}
	defer root.Close()
	raw, _, err := serverTorRead(root, "share/router-vpn/tor/BUILD.json", 256<<10, false)
	if err != nil {
		return nil, bad
	}
	if _, err := profileObject(string(raw), 256<<10); err != nil {
		return nil, bad
	}
	var receipt struct {
		Schema        int    `json:"schema"`
		Kind          string `json:"kind"`
		Platform      string `json:"platform"`
		NativeVersion string `json:"native_version"`
		SourceLock    string `json:"source_lock_sha256"`
		Executable    struct {
			Path    string `json:"path"`
			SHA256  string `json:"sha256"`
			Size    int64  `json:"size"`
			Machine int    `json:"elf_machine"`
			Class   int    `json:"elf_class"`
		} `json:"executable"`
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.Schema != 1 || receipt.Kind != "standalone-server-tor" || receipt.Platform != "linux/"+runtime.GOARCH || receipt.NativeVersion != "tor 0.4.9.14" || receipt.SourceLock != ServerTorSourceLockSHA256 || receipt.Executable.Path != "bin/routervpn-tor" || !desktopHex(receipt.Executable.SHA256, 32) || receipt.Executable.Size < 1 || receipt.Executable.Size > 64<<20 || receipt.Executable.Class != 2 {
		return nil, bad
	}
	machine := map[string]int{"amd64": 62, "arm64": 183}[runtime.GOARCH]
	if machine == 0 || receipt.Executable.Machine != machine {
		return nil, bad
	}
	_, info, err := serverTorRead(root, receipt.Executable.Path, 64<<20, false)
	if err != nil || info.Mode().Perm()&0111 == 0 || info.Size() != receipt.Executable.Size {
		return nil, bad
	}
	file, err := root.Open(receipt.Executable.Path)
	if err != nil {
		return nil, bad
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, bad
	}
	binary, err := elf.NewFile(file)
	if err != nil || binary.Class != elf.ELFCLASS64 || binary.Data != elf.ELFDATA2LSB || int(binary.Machine) != machine {
		return nil, bad
	}
	for _, program := range binary.Progs {
		if program.Type == elf.PT_INTERP {
			return nil, bad
		}
	}
	if libraries, err := binary.ImportedLibraries(); err != nil || len(libraries) != 0 {
		return nil, bad
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, bad
	}
	hash := sha256.New()
	if n, err := io.Copy(hash, io.LimitReader(file, (64<<20)+1)); err != nil || n != info.Size() || hex.EncodeToString(hash.Sum(nil)) != receipt.Executable.SHA256 {
		return nil, bad
	}
	current, err := root.Lstat(receipt.Executable.Path)
	if err != nil || !sameServerTorFile(info, current) {
		return nil, bad
	}
	return &ServerTorBinary{path: filepath.Join(prefix, receipt.Executable.Path), info: info, digest: receipt.Executable.SHA256}, nil
}

func (b *ServerTorBinary) Current() bool {
	if b == nil {
		return false
	}
	info, err := os.Lstat(b.path)
	return err == nil && sameServerTorFile(b.info, info)
}
func sameServerTorFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && b.Mode().IsRegular() && b.Mode().Perm()&0022 == 0 && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && a.Mode() == b.Mode()
}

// All traversed components are examined relative to retained directory handles.
// os.Root containment alone would permit an in-root symlink, which is unwanted
// for executable/cookie/source authority.
func serverTorRead(root *os.Root, name string, limit int64, private bool) ([]byte, os.FileInfo, error) {
	bad := errors.New("captured server Tor file is unavailable")
	if root == nil || !filepath.IsLocal(name) || filepath.Clean(name) != name {
		return nil, nil, bad
	}
	for parent := filepath.Dir(name); parent != "."; parent = filepath.Dir(parent) {
		info, err := root.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return nil, nil, bad
		}
	}
	info, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || private && info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > limit {
		return nil, nil, bad
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, nil, bad
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !sameServerTorFile(info, opened) {
		return nil, nil, bad
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, nil, bad
	}
	after, err := root.Lstat(name)
	if err != nil || !sameServerTorFile(info, after) {
		return nil, nil, bad
	}
	return raw, info, nil
}
