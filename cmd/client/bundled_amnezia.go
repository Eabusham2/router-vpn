package main

import (
	"bytes"
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

const bundledAmneziaCore = "1ac1a339cb1223e9c70eae14c44411c75033c02d"
const bundledAmneziaVersion = "v3.1.20260814"
const bundledAmneziaSum = "h1:l2AhBD+sFycU8Im81n/bZORMxW7fWtlZJEuJ4Hh0+z0="
const bundledAmneziaGo = "go1.26.3"
const bundledAmneziaMaxBytes = 160 << 20

type bundledAmneziaReceipt struct {
	Schema         int    `json:"schema_version"`
	Runtime        string `json:"runtime"`
	Version        string `json:"version"`
	Upstream       string `json:"upstream_revision"`
	AmneziaVersion string `json:"amnezia_version"`
	AmneziaSum     string `json:"amnezia_sum"`
	Policy         string `json:"policy_sha256"`
	Target         string `json:"target"`
	Toolchain      string `json:"toolchain"`
	Size           int64  `json:"size"`
	SHA256         string `json:"sha256"`
}

func bundledAmneziaRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("native AmneziaWG package input is missing or unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("native AmneziaWG package input is unreadable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("native AmneziaWG package input changed during verification")
	}
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(value)) != info.Size() {
		return nil, errors.New("native AmneziaWG package input changed during reading")
	}
	return value, nil
}

func bundledAmneziaDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("native AmneziaWG package directory is missing or linked")
	}
	return nil
}

// verifyBundledAmnezia accepts only the receipt and target embedded in the
// packaged executable. It never downloads a replacement or modifies the
// ordinary installed sing-box. Package authenticity remains the release's
// responsibility; this check detects altered, stale and wrong-target engines.
func verifyBundledAmnezia(root string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	for _, path := range []string{root, filepath.Join(root, "runtime"), filepath.Join(root, "runtime", "amnezia")} {
		if err := bundledAmneziaDirectory(path); err != nil {
			return "", err
		}
	}
	directory := filepath.Join(root, "runtime", "amnezia")
	raw, err := bundledAmneziaRegular(filepath.Join(directory, "AMNEZIA-RUNTIME.json"), 8192)
	if err != nil {
		return "", err
	}
	var receipt bundledAmneziaReceipt
	if decodeRelayControlJSON(raw, &receipt) != nil {
		return "", errors.New("native AmneziaWG receipt must be exact unambiguous JSON")
	}
	if receipt.Schema != 1 || receipt.Runtime != "sing-box-amnezia" || receipt.Version != "1.14.1" || receipt.Upstream != bundledAmneziaCore || receipt.AmneziaVersion != bundledAmneziaVersion || receipt.AmneziaSum != bundledAmneziaSum || receipt.Toolchain != bundledAmneziaGo || receipt.Target != runtime.GOOS+"/"+runtime.GOARCH || receipt.Size <= 0 || receipt.Size > bundledAmneziaMaxBytes {
		return "", errors.New("native AmneziaWG receipt differs from the required source or device")
	}
	for _, value := range []string{receipt.Policy, receipt.SHA256} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size || strings.ToLower(value) != value {
			return "", errors.New("native AmneziaWG receipt digest is invalid")
		}
	}
	name := "sing-box-amnezia"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(directory, name)
	contents, err := bundledAmneziaRegular(binary, bundledAmneziaMaxBytes)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(contents)
	marker := "1.14.1-routervpn-amnezia." + receipt.Policy
	if int64(len(contents)) != receipt.Size || hex.EncodeToString(digest[:]) != receipt.SHA256 || !bytes.Contains(contents, []byte(marker)) {
		return "", errors.New("native AmneziaWG executable differs from the packaged receipt")
	}
	for _, name := range []string{"SING-BOX-LICENSE", "AMNEZIA-LICENSE"} {
		if _, err := bundledAmneziaRegular(filepath.Join(directory, name), 128<<10); err != nil {
			return "", err
		}
	}
	metadata, err := buildinfo.ReadFile(binary)
	if err != nil || metadata.GoVersion != bundledAmneziaGo {
		return "", errors.New("native AmneziaWG executable lacks its pinned Go build metadata")
	}
	settings := map[string]string{}
	for _, value := range metadata.Settings {
		settings[value.Key] = value.Value
	}
	if settings["GOOS"] != runtime.GOOS || settings["GOARCH"] != runtime.GOARCH || settings["CGO_ENABLED"] != "0" {
		return "", errors.New("native AmneziaWG executable targets another device")
	}
	backend := false
	for _, module := range metadata.Deps {
		if module.Path == "github.com/amnezia-vpn/amneziawg-go/v3" {
			backend = module.Replace == nil && module.Version == bundledAmneziaVersion && module.Sum == bundledAmneziaSum
		}
	}
	if !backend {
		return "", errors.New("native AmneziaWG executable does not contain the exact authenticated backend")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, "version").Output()
	if err != nil || len(output) > 8192 || !strings.HasPrefix(string(output), "sing-box version "+marker+"\n") {
		return "", errors.New("native AmneziaWG executable failed its version check")
	}
	return binary, nil
}

func bundledAmneziaUtility(args []string) (bool, error) {
	if len(args) == 0 || args[0] != "--verify-amnezia-runtime" {
		return false, nil
	}
	if len(args) != 2 {
		return true, errors.New("--verify-amnezia-runtime requires one application root")
	}
	binary, err := verifyBundledAmnezia(args[1])
	if err != nil {
		return true, err
	}
	fmt.Println(binary)
	return true, nil
}

func standardExitAmneziaCapability() standardExitCapability {
	_, err := verifyBundledAmnezia(desktopAmneziaPackageRoot())
	result := standardExitCapability{Protocol: "amneziawg", Implemented: true, Supported: err == nil}
	if err != nil {
		result.Reason = "Install the current Router VPN package with its native AmneziaWG engine: " + err.Error()
	}
	return result
}

func desktopAmneziaPackageRoot() string {
	// Portable keeps application binaries beside the running controller and
	// private node data in Data/. Select only this executable's own package.
	if os.Getenv("HOMEVPN_PORTABLE") == "1" {
		if executable, err := os.Executable(); err == nil {
			return filepath.Dir(executable)
		}
	}
	return getenv("HOMEVPN_ROOT", "/opt/router-vpn-client")
}
