package main

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const bundledNativeXray = "50231eaff98ccc31b5cbd247a721c16e97fe5ec1"
const bundledNativeRosenpass = "00569eb273016a10d2e75e5142236f06f7c3d4b3"
const bundledNativeMaxBytes = 384 << 20

type bundledNativeFile struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type bundledNativeReceipt struct {
	Schema         int                          `json:"schema_version"`
	Runtime        string                       `json:"runtime"`
	Version        string                       `json:"version"`
	Upstream       string                       `json:"upstream_revision"`
	Xray           string                       `json:"xray_revision"`
	AmneziaVersion string                       `json:"amnezia_version"`
	AmneziaSum     string                       `json:"amnezia_sum"`
	Rosenpass      string                       `json:"rosenpass_revision"`
	Policy         string                       `json:"policy_sha256"`
	Target         string                       `json:"target"`
	Toolchain      string                       `json:"toolchain"`
	RustToolchain  string                       `json:"rust_toolchain"`
	PQABI          int                          `json:"native_pq_abi"`
	Size           int64                        `json:"size"`
	SHA256         string                       `json:"sha256"`
	Files          map[string]bundledNativeFile `json:"files"`
}

func nativeDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

func nativeBinaryName() string {
	if runtime.GOOS == "windows" {
		return "sing-box-routervpn.exe"
	}
	return "sing-box-routervpn"
}

func validateNativeReceipt(raw []byte) (bundledNativeReceipt, error) {
	var r bundledNativeReceipt
	bad := errors.New("native runtime receipt differs from the required source, target or payload")
	if decodeRelayControlJSON(raw, &r) != nil || r.Schema != 1 || r.Runtime != "sing-box-routervpn" || r.Version != "1.14.1" || r.Upstream != bundledAmneziaCore || r.Xray != bundledNativeXray || r.AmneziaVersion != bundledAmneziaVersion || r.AmneziaSum != bundledAmneziaSum || r.Rosenpass != bundledNativeRosenpass || r.Toolchain != bundledAmneziaGo || r.RustToolchain != "1.99.0" || r.PQABI != 1 || r.Target != runtime.GOOS+"/"+runtime.GOARCH || r.Size <= 0 || r.Size > bundledNativeMaxBytes || !nativeDigest(r.Policy) || !nativeDigest(r.SHA256) || len(r.Files) < 4 || len(r.Files) > 32 {
		return r, bad
	}
	for name, f := range r.Files {
		if name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "/\\\x00\r\n") || strings.HasPrefix(name, ".") || f.Size <= 0 || f.Size > bundledNativeMaxBytes || !nativeDigest(f.SHA256) {
			return r, bad
		}
		if name != nativeBinaryName() && name != "libcronet.dll" && name != "libcronet.so" && ((!strings.HasSuffix(name, "-LICENSE") && name != "ROSENPASS-LICENSE-MIT" && name != "ROSENPASS-LICENSE-APACHE") || f.Size > 256<<10) {
			return r, bad
		}
		if (name == "libcronet.dll" && runtime.GOOS != "windows") || (name == "libcronet.so" && runtime.GOOS != "linux") || ((name == "libcronet.dll" || name == "libcronet.so") && f.Size > 128<<20) {
			return r, bad
		}
	}
	if r.Files[nativeBinaryName()].Size != r.Size || r.Files[nativeBinaryName()].SHA256 != r.SHA256 {
		return r, bad
	}
	for _, name := range []string{"SING-BOX-LICENSE", "AMNEZIA-LICENSE", "XRAY-LICENSE", "ROSENPASS-LICENSE-MIT", "ROSENPASS-LICENSE-APACHE", "CRONET-LICENSE"} {
		if _, ok := r.Files[name]; !ok {
			return r, bad
		}
	}
	if runtime.GOOS == "linux" && r.Files["libcronet.so"].Size == 0 {
		return r, bad
	}
	if runtime.GOOS == "windows" && r.Files["libcronet.dll"].Size == 0 {
		return r, bad
	}
	return r, nil
}

func verifyNativeFile(path string, expected bundledNativeFile) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != expected.Size {
		return errors.New("native runtime payload is missing, linked or changed")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("native runtime payload changed during verification")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, expected.Size+1))
	if err != nil || n != expected.Size || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		return errors.New("native runtime payload digest differs from its receipt")
	}
	return nil
}

func verifyBundledNative(root string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	directory := filepath.Join(root, "runtime", "native")
	for _, path := range []string{root, filepath.Join(root, "runtime"), directory} {
		if err := bundledAmneziaDirectory(path); err != nil {
			return "", fmt.Errorf("native engine directory: %w", err)
		}
	}
	raw, err := bundledAmneziaRegular(filepath.Join(directory, "NATIVE-RUNTIME.json"), 32768)
	if err != nil {
		return "", fmt.Errorf("native engine receipt: %w", err)
	}
	receipt, err := validateNativeReceipt(raw)
	if err != nil {
		return "", err
	}
	for name, expected := range receipt.Files {
		if err := verifyNativeFile(filepath.Join(directory, name), expected); err != nil {
			return "", fmt.Errorf("native engine %s: %w", name, err)
		}
	}
	binary := filepath.Join(directory, nativeBinaryName())
	metadata, err := buildinfo.ReadFile(binary)
	if err != nil || metadata.GoVersion != bundledAmneziaGo {
		return "", errors.New("native engine has no pinned Go build metadata")
	}
	settings := map[string]string{}
	for _, value := range metadata.Settings {
		settings[value.Key] = value.Value
	}
	if settings["GOOS"] != runtime.GOOS || settings["GOARCH"] != runtime.GOARCH || settings["CGO_ENABLED"] != "1" {
		return "", errors.New("native engine targets another device or lacks the native PQ ABI")
	}
	tags := map[string]bool{}
	for _, tag := range strings.Split(settings["-tags"], ",") {
		tags[tag] = true
	}
	for _, tag := range []string{"with_wireguard", "with_quic", "with_gvisor", "with_openvpn", "with_naive_outbound", "routervpn_native_pq"} {
		if !tags[tag] {
			return "", errors.New("native engine omitted a required protocol")
		}
	}
	if (runtime.GOOS == "windows" || runtime.GOOS == "linux") && !tags["with_purego"] {
		return "", errors.New("native engine lacks its packaged Cronet loader")
	}
	backend := false
	for _, module := range metadata.Deps {
		if module.Path == "github.com/amnezia-vpn/amneziawg-go/v3" {
			backend = module.Replace == nil && module.Version == bundledAmneziaVersion && module.Sum == bundledAmneziaSum
		}
	}
	if !backend {
		return "", errors.New("native engine lacks its pinned AmneziaWG backend")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "version")
	cmd.Dir = directory
	cmd.Env = nativeLibraryEnvironment(os.Environ(), directory)
	output, err := cmd.Output()
	if err != nil || len(output) > 8192 || !strings.HasPrefix(string(output), "sing-box version 1.14.1-routervpn-native."+receipt.Policy+"\n") {
		return "", errors.New("native engine failed its exact build version check")
	}
	return binary, nil
}

func nativeLibraryEnvironment(environment []string, directory string) []string {
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, "LD_LIBRARY_PATH") || strings.EqualFold(name, "LD_PRELOAD") || strings.EqualFold(name, "DYLD_LIBRARY_PATH") || strings.EqualFold(name, "DYLD_INSERT_LIBRARIES") {
			continue
		}
		result = append(result, entry)
	}
	if runtime.GOOS == "linux" {
		result = append(result, "LD_LIBRARY_PATH="+directory)
	}
	return result
}

func bundledNativeUtility(args []string) (bool, error) {
	if len(args) == 0 || args[0] != "--verify-native-runtime" {
		return false, nil
	}
	if len(args) != 2 {
		return true, errors.New("--verify-native-runtime requires one application root")
	}
	binary, err := verifyBundledNative(args[1])
	if err != nil {
		return true, err
	}
	fmt.Println(binary)
	return true, nil
}
