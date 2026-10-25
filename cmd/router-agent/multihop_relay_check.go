package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"router-vpn/internal/multihoprelay"
	"strings"
	"time"
)

type relayCheckOnlyRunner struct{}

func (relayCheckOnlyRunner) Start(context.Context, []byte, multihoprelay.Lease) (multihoprelay.Process, error) {
	return nil, errors.New("configuration verification never starts a relay")
}

// checkRelayRegistry validates an operator-staged registry with the real pinned
// core but does not open a tunnel, change routes, or modify live agent state.
func checkRelayRegistry(registryPath, agentPath string) (int, error) {
	registry, err := readRelayRegistry(registryPath)
	if err != nil {
		return 0, errors.New("private staged registry could not be read")
	}
	raw, err := readPrivilegedState(agentPath, 1<<20)
	if err != nil {
		return 0, errors.New("private entry configuration could not be read")
	}
	var entry cfg
	if json.Unmarshal(raw, &entry) != nil || !validNodeID(entry.NodeID) {
		return 0, errors.New("entry node identity is invalid")
	}
	ip, err := netip.ParseAddr(registry.ListenIP)
	if err != nil {
		return 0, errors.New("entry listen address is invalid")
	}
	covered := false
	for _, s := range entry.TunnelCIDRs {
		prefix, err := netip.ParsePrefix(s)
		if err == nil && prefix.Contains(ip) {
			covered = true
		}
	}
	if !covered || registry.FirstPort < 26240 || registry.LastPort > 26271 {
		return 0, errors.New("registry must use the entry tunnel address and reserved listener pool")
	}
	manager, err := multihoprelay.New(registry, entry.NodeID, relayCheckOnlyRunner{})
	if err != nil {
		return 0, err
	}
	defer manager.Close(context.Background())
	root := "/run/router-vpn-relay-checks"
	if err = validatePrivilegedStateParent(filepath.Join(root, "plan")); err != nil {
		return 0, err
	}
	dir, err := os.MkdirTemp(root, "check-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(dir)
	for _, exit := range registry.Exits {
		lease, err := relayValidationLease(exit, registry.ListenIP, registry.FirstPort, entry.NodeID)
		if err != nil {
			return 0, err
		}
		body, err := multihoprelay.Build(exit, ip.Next(), lease)
		if err != nil {
			return 0, err
		}
		path := filepath.Join(dir, "sing-box.json")
		if err = atomicWritePrivilegedState(path, body); err != nil {
			return 0, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, "/usr/local/bin/sing-box", "check", "-c", path)
		cmd.Dir = dir
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		err = cmd.Run()
		cancel()
		if err != nil {
			return 0, errors.New("bundled relay core rejected a paired exit configuration")
		}
	}
	return len(registry.Exits), nil
}

// Offline checks must use the same layer identity required by a live lease.
func relayValidationLease(exit multihoprelay.Exit, host string, port int, entryNodeID string) (multihoprelay.Lease, error) {
	lease := multihoprelay.Lease{
		Request: multihoprelay.Request{ExitID: exit.ID, ExitMode: exit.Mode, ExitStartLayer: multihoprelay.ExitLayerMode(exit)},
		Host:    host, Port: port, Username: strings.Repeat("a", 48), Password: strings.Repeat("b", 48),
	}
	if exit.External != nil {
		// Offline validation proves the same private credential binding as a live
		// proposal. This synthetic owner is only compiled; no manager starts it.
		lease.Request.SessionID = strings.Repeat("0", 32)
		lease.Request.EntryNodeID = entryNodeID
		lease.Request.Port, lease.Request.Username, lease.Request.Password = lease.Port, lease.Username, lease.Password
		request, err := multihoprelay.AuthenticateExternalRequest(exit, lease.Request)
		if err != nil {
			return multihoprelay.Lease{}, err
		}
		lease.Request = request
	}
	return lease, nil
}
