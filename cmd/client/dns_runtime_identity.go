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
		if err := validatePrivateRuntimePathPermissions(current, info); err != nil {
			return fmt.Errorf("active DNS runtime parent is not private: %w", err)
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
	if err := validatePrivateRuntimePathPermissions(configPath, info); err != nil {
		return fmt.Errorf("active DNS runtime config is not private: %w", err)
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
	command := a.cmd
	a.mu.Unlock()
	if !st.Connected || st.Phase != "connected" || st.Mode != "multihop" || st.RouterID != profileID || st.RuntimeMode != runtimeID {
		return activeDNSRuntimeIdentity{}, false, nil
	}
	graph, ok := getActiveMultihopGraph(a)
	if !ok || graph.ExitID != profileID || graph.ExitMode != runtimeID {
		return activeDNSRuntimeIdentity{}, false, nil
	}
	if graph.SourceSHA != "" {
		owner, err := capturedNativeMultihopRuntime(a, command, graph)
		if err != nil {
			return activeDNSRuntimeIdentity{}, true, err
		}
		return activeDNSRuntimeIdentity{ProfileID: profileID, RuntimeID: runtimeID, Config: filepath.Join(owner.launch.directory, "sing-box.json")}, true, nil
	}
	configPath := filepath.Join(clientRoot(a), "run", "multihop", "exit", "sing-box.json")
	configPath, err := runtimeConfigUnderPrivateRun(a, configPath)
	if err != nil {
		return activeDNSRuntimeIdentity{}, true, err
	}
	return activeDNSRuntimeIdentity{ProfileID: profileID, RuntimeID: runtimeID, Config: configPath}, true, nil
}

func deterministicExternalDNSRuntime(a *app, profileID, runtimeID string) (activeDNSRuntimeIdentity, bool, error) {
	if a == nil {
		return activeDNSRuntimeIdentity{}, false, nil
	}
	profileID = strings.TrimSpace(profileID)
	runtimeID = strings.TrimSpace(runtimeID)
	if !strings.HasPrefix(runtimeID, "external-") || runtimeID == "external-openvpn" {
		return activeDNSRuntimeIdentity{}, false, nil
	}
	a.mu.Lock()
	st := a.state
	cmd := a.cmd
	profile, profileOK := a.profileByIDLocked(profileID)
	a.mu.Unlock()
	if !st.Connected || st.Phase != "connected" || st.Mode != "external-node" || st.RouterID != profileID || st.RuntimeMode != runtimeID || cmd == nil {
		return activeDNSRuntimeIdentity{}, false, nil
	}
	if !profileOK || profile.NodeKind != "external" || profile.External == nil {
		return activeDNSRuntimeIdentity{}, false, nil
	}
	runtimeDir, err := nativeMultihopRuntimeDirFromCommand(cmd)
	if err != nil {
		return activeDNSRuntimeIdentity{}, true, fmt.Errorf("active external runtime does not expose an owned RuntimeDir: %w", err)
	}
	configPath, err := runtimeConfigUnderPrivateRun(a, filepath.Join(runtimeDir, "sing-box.json"))
	if err != nil {
		return activeDNSRuntimeIdentity{}, true, err
	}
	return activeDNSRuntimeIdentity{ProfileID: profileID, RuntimeID: runtimeID, Config: configPath}, true, nil
}

func activeDNSRuntimeConfigFor(a *app, profileID, runtimeID string) (string, bool, error) {
	snapshot, owned, err := activeDNSRuntimeSnapshotFor(a, profileID, runtimeID)
	if err != nil || !owned {
		return "", owned, err
	}
	return snapshot.source.path, true, nil
}

func captureActiveDNSRuntimeSource(a *app, profileID, runtimeID string) (*activeDNSRuntimeSource, bool, error) {
	if a == nil {
		return nil, false, nil
	}
	profileID = strings.TrimSpace(profileID)
	runtimeID = strings.TrimSpace(runtimeID)
	owner, err := captureActiveDNSRuntimeOwner(a, profileID)
	if err != nil {
		return nil, true, err
	}
	var identity activeDNSRuntimeIdentity
	matched := false
	kind := ""
	if raw, ok := activeDNSRuntimeIdentities.Load(a); ok {
		registered, typeOK := raw.(activeDNSRuntimeIdentity)
		if !typeOK {
			return nil, true, errors.New("active DNS runtime identity has invalid type")
		}
		if registered.ProfileID == profileID && registered.RuntimeID == runtimeID {
			identity = registered
			matched = true
			kind = "registered"
		}
	}
	if !matched {
		deterministic, owned, err := deterministicLinuxMultihopDNSRuntime(a, profileID, runtimeID)
		if err != nil {
			return nil, owned, err
		}
		if owned {
			identity = deterministic
			matched = true
			kind = "linux-multihop"
		}
	}
	if !matched {
		deterministic, owned, err := deterministicExternalDNSRuntime(a, profileID, runtimeID)
		if err != nil {
			return nil, owned, err
		}
		if owned {
			identity = deterministic
			matched = true
			kind = "external"
		}
	}
	if !matched {
		return nil, false, nil
	}
	configPath, err := runtimeConfigUnderPrivateRun(a, identity.Config)
	if err != nil {
		return nil, true, err
	}
	root, err := filepath.Abs(filepath.Clean(clientRoot(a)))
	if err != nil {
		return nil, true, err
	}
	if err := validateExistingRuntimeAncestors(filepath.Join(root, "run"), configPath); err != nil {
		return nil, true, err
	}
	info, err := os.Lstat(configPath)
	if err != nil {
		return nil, true, err
	}
	file, err := openPrivateRuntimeForRead(configPath, info)
	if err != nil {
		return nil, true, err
	}
	defer file.Close()
	// Windows pathname FileInfo can defer its file-ID query. Freeze the ID
	// from this actual open handle before handing the source to its reader.
	info, err = file.Stat()
	if err != nil {
		return nil, true, err
	}
	source := &activeDNSRuntimeSource{app: a, identity: identity, kind: kind, owner: owner, path: configPath, runRoot: filepath.Join(root, "run"), fileInfo: info}
	if err := source.current(); err != nil {
		return nil, true, err
	}
	return source, true, nil
}
