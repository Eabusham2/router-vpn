package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

type activeDNSRuntimeIdentity struct {
	ProfileID string
	RuntimeID string
	Config    string
}

var activeDNSRuntimeIdentities sync.Map // map[*app]activeDNSRuntimeIdentity

func runtimeConfigUnderPrivateRun(a *app, path string) (string, error) {
	if a == nil {
		return "", errors.New("active DNS runtime has no app owner")
	}
	root, err := filepath.Abs(filepath.Clean(clientRoot(a)))
	if err != nil {
		return "", err
	}
	runRoot := filepath.Join(root, "run")
	candidate, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(runRoot, candidate)
	if err != nil || rel == "." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		return "", errors.New("active DNS runtime config escaped the private run root")
	}
	if filepath.Base(candidate) != "sing-box.json" {
		return "", errors.New("active DNS runtime config must be the owned sing-box.json")
	}
	return candidate, nil
}

func registerActiveDNSRuntimeConfig(a *app, profileID, runtimeID, configPath string) error {
	profileID = strings.TrimSpace(profileID)
	runtimeID = strings.TrimSpace(runtimeID)
	if !validProfileID(profileID) {
		return errors.New("active DNS runtime profile id is invalid")
	}
	if runtimeID == "" || len(runtimeID) > 128 || strings.ContainsAny(runtimeID, "\r\n\x00/\\") {
		return errors.New("active DNS runtime id is invalid")
	}
	configPath, err := runtimeConfigUnderPrivateRun(a, configPath)
	if err != nil {
		return err
	}
	activeDNSRuntimeIdentities.Store(a, activeDNSRuntimeIdentity{ProfileID: profileID, RuntimeID: runtimeID, Config: configPath})
	return nil
}

func clearActiveDNSRuntimeConfig(a *app) { activeDNSRuntimeIdentities.Delete(a) }

func validateExistingRuntimeAncestors(runRoot, configPath string) error {
	runRoot, err := filepath.Abs(filepath.Clean(runRoot))
	if err != nil {
		return err
	}
	configPath, err = filepath.Abs(filepath.Clean(configPath))
	if err != nil {
		return err
	}
	parent := filepath.Dir(configPath)
	for current := parent; ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		if statErr != nil {
			return fmt.Errorf("active DNS runtime parent is missing: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("active DNS runtime parent is unsafe: %s", current)
		}
		if current == runRoot {
			break
		}
		next := filepath.Dir(current)
		if next == current {
			return errors.New("active DNS runtime parent escaped private run root")
		}
	}
	info, err := os.Lstat(configPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("active DNS runtime config is not a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("active DNS runtime config is not private")
	}
	if info.Size() <= 0 || info.Size() > maxPrivateStoreBytes {
		return errors.New("active DNS runtime config is empty or oversized")
	}
	return nil
}

func deterministicLinuxMultihopDNSRuntime(a *app, profileID, runtimeID string) (activeDNSRuntimeIdentity, bool, error) {
	if runtime.GOOS != "linux" || a == nil {
		return activeDNSRuntimeIdentity{}, false, nil
	}
	profileID = strings.TrimSpace(profileID)
	runtimeID = strings.TrimSpace(runtimeID)
	a.mu.Lock()
	st := a.state
	a.mu.Unlock()
	if !st.Connected || st.Phase != "connected" || st.Mode != "multihop" || st.RouterID != profileID || st.RuntimeMode != runtimeID {
		return activeDNSRuntimeIdentity{}, false, nil
	}
	graph, ok := getActiveMultihopGraph(a)
	if !ok || graph.ExitID != profileID || graph.ExitMode != runtimeID {
		return activeDNSRuntimeIdentity{}, false, nil
	}
	configPath := filepath.Join(clientRoot(a), "run", "multihop", "exit", "sing-box.json")
	configPath, err := runtimeConfigUnderPrivateRun(a, configPath)
	if err != nil {
		return activeDNSRuntimeIdentity{}, true, err
	}
	return activeDNSRuntimeIdentity{ProfileID: profileID, RuntimeID: runtimeID, Config: configPath}, true, nil
}

func activeDNSRuntimeConfigFor(a *app, profileID, runtimeID string) (string, bool, error) {
	profileID = strings.TrimSpace(profileID)
	runtimeID = strings.TrimSpace(runtimeID)
	var identity activeDNSRuntimeIdentity
	matched := false
	if raw, ok := activeDNSRuntimeIdentities.Load(a); ok {
		registered, typeOK := raw.(activeDNSRuntimeIdentity)
		if !typeOK {
			return "", true, errors.New("active DNS runtime identity has invalid type")
		}
		if registered.ProfileID == profileID && registered.RuntimeID == runtimeID {
			identity = registered
			matched = true
		}
	}
	if !matched {
		deterministic, owned, err := deterministicLinuxMultihopDNSRuntime(a, profileID, runtimeID)
		if err != nil {
			return "", owned, err
		}
		if !owned {
			return "", false, nil
		}
		identity = deterministic
		matched = true
	}
	if !matched {
		return "", false, nil
	}
	configPath, err := runtimeConfigUnderPrivateRun(a, identity.Config)
	if err != nil {
		return "", true, err
	}
	root, err := filepath.Abs(filepath.Clean(clientRoot(a)))
	if err != nil {
		return "", true, err
	}
	if err := validateExistingRuntimeAncestors(filepath.Join(root, "run"), configPath); err != nil {
		return "", true, err
	}
	// Reuse the race-safe open+SameFile reader only after the non-creating
	// ancestor/file checks above have proved the registered runtime still exists.
	if _, err := readPrivateRegular(configPath, maxPrivateStoreBytes); err != nil {
		return "", true, err
	}
	return configPath, true, nil
}
