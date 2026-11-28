package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

type relayNodeChainPrefixRegistryCheck struct {
	runner         *relayNodeChainExecRunner
	policies       []*mobilemultihop.NodeChainServerPrefixPolicy
	currentSources []func() bool
	coreInfo       os.FileInfo
	coreSHA        string
}

func newRelayNodeChainPrefixRegistryCheck(registry multihoprelay.Config, entry cfg, paths relayRegistryCheckPaths) (*relayNodeChainPrefixRegistryCheck, error) {
	if len(registry.NodeChainPrefixes) == 0 {
		return nil, nil
	}
	bad := errors.New("private ordered prefix sources or native core are unavailable")
	sourceDir := paths.nodeChainPrefixSources
	if sourceDir == "" {
		sourceDir = serverNodeChainPrefixSourcesDirectory
	}
	if info, err := os.Lstat(sourceDir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return nil, bad
	}
	file, info, digest, err := captureRelayNodeChainImage(paths.core)
	if err != nil {
		return nil, bad
	}
	if file.Close() != nil {
		return nil, bad
	}
	state := &relayNodeChainPrefixRegistryCheck{runner: &relayNodeChainExecRunner{prefixSources: sourceDir, core: paths.core}, coreInfo: info, coreSHA: digest}
	for _, source := range registry.NodeChainPrefixes {
		policy, current, err := state.runner.capturePrefixSource(source, entry.NodeID)
		if err != nil {
			return nil, bad
		}
		state.policies = append(state.policies, policy)
		state.currentSources = append(state.currentSources, current)
	}
	return state, nil
}
func (s *relayNodeChainPrefixRegistryCheck) checkNative(directory string) (outErr error) {
	if s == nil {
		return nil
	}
	bad := errors.New("bundled relay core rejected a private prefix source")
	image, info, digest, err := captureRelayNodeChainImage(s.runner.core)
	if err != nil {
		return bad
	}
	defer image.Close()
	if !os.SameFile(info, s.coreInfo) || digest != s.coreSHA {
		return bad
	}
	for _, policy := range s.policies {
		// The check command parses the original private source and constructs only an
		// unstarted listener-free Box when a real suffix exists. Zero stays graph-free.
		dir, err := os.MkdirTemp(directory, "prefix-check-")
		if err != nil {
			return err
		}
		if err = atomicWritePrivilegedState(filepath.Join(dir, "node-chain-prefix-source.json"), []byte(policy.Source())); err != nil {
			return errors.Join(err, os.RemoveAll(dir))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		command := exec.CommandContext(ctx, "/proc/self/fd/3", "routervpn-node-chain-prefix-check", "--runtime-dir", dir)
		command.ExtraFiles = []*os.File{image}
		command.Dir = dir
		command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C"}
		command.Stdout, command.Stderr = io.Discard, io.Discard
		runErr := command.Run()
		cancel()
		removeErr := os.RemoveAll(dir)
		if runErr != nil || removeErr != nil {
			return errors.Join(bad, removeErr)
		}
	}
	return s.current()
}
func (s *relayNodeChainPrefixRegistryCheck) current() error {
	if s == nil {
		return nil
	}
	bad := errors.New("private ordered prefix source or core changed during verification")
	image, info, digest, err := captureRelayNodeChainImage(s.runner.core)
	if err != nil {
		return bad
	}
	defer image.Close()
	if !os.SameFile(info, s.coreInfo) || digest != s.coreSHA || !info.ModTime().Equal(s.coreInfo.ModTime()) {
		return bad
	}
	for _, current := range s.currentSources {
		if current == nil || !current() {
			return bad
		}
	}
	return nil
}
func checkRelayRegistryWithPrefixSources(registryPath, agentPath, torSources, nodeChainSources, prefixSources string) (int, error) {
	return checkRelayRegistryWithPaths(registryPath, agentPath, relayRegistryCheckPaths{torSources: torSources, nodeChainSources: nodeChainSources, nodeChainPrefixSources: prefixSources, packagePrefix: "/usr/local", core: "/usr/local/bin/sing-box", temporary: "/run/router-vpn-relay-checks"})
}
