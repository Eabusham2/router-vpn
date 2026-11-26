package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

type relayNodeChainRegistryCheck struct {
	runner         *relayNodeChainExecRunner
	sources        []multihoprelay.NodeChainDescriptor
	policies       []*mobilemultihop.NodeChainServerPolicy
	currentSources []func() bool
	host           string
	peers          []string
	port           int
	coreInfo       os.FileInfo
	coreSHA        string
}

func newRelayNodeChainRegistryCheck(registry multihoprelay.Config, entry cfg, paths relayRegistryCheckPaths) (*relayNodeChainRegistryCheck, error) {
	if len(registry.NodeChains) == 0 {
		return nil, nil
	}
	bad := errors.New("private ordered server sources or native core are unavailable")
	if info, err := os.Lstat(paths.nodeChainSources); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return nil, bad
	}
	image, info, digest, err := captureRelayNodeChainImage(paths.core)
	if err != nil {
		return nil, bad
	}
	if image.Close() != nil {
		return nil, bad
	}
	host, err := netip.ParseAddr(registry.ListenIP)
	if err != nil || host.Zone() != "" || host.Is4In6() || !host.IsPrivate() {
		return nil, bad
	}
	// A parser-only capture still uses a peer in the actual configured entry
	// tunnel range. It never allocates a lease, opens a listener, or dials it.
	var peer netip.Addr
	for _, text := range entry.TunnelCIDRs {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || !prefix.Contains(host) {
			continue
		}
		for _, candidate := range []netip.Addr{host.Next(), host.Prev()} {
			if candidate.IsValid() && candidate != host && candidate.IsPrivate() && !candidate.IsLoopback() && !candidate.IsLinkLocalUnicast() && prefix.Contains(candidate) {
				peer = candidate
				break
			}
		}
		if peer.IsValid() {
			break
		}
	}
	state := &relayNodeChainRegistryCheck{runner: &relayNodeChainExecRunner{sources: paths.nodeChainSources, core: paths.core},
		host: host.String(), port: registry.FirstPort, coreInfo: info, coreSHA: digest}
	for _, source := range registry.NodeChains {
		policy, current, err := state.runner.captureSource(source, entry.NodeID)
		if err != nil {
			return nil, bad
		}
		capturedPeer := peer
		if source.Schema == 8 {
			capturedPeer = registeredNodeChainCheckPeer(source, host, entry.TunnelCIDRs)
		}
		if !capturedPeer.IsValid() {
			return nil, bad
		}
		state.sources = append(state.sources, source.Clone())
		state.policies = append(state.policies, policy)
		state.currentSources = append(state.currentSources, current)
		state.peers = append(state.peers, capturedPeer.String())
	}
	return state, nil
}

// Validate a parser-only request with a tunnel address belonging to this
// exact registered public key. The front and peer may occupy different
// configured tunnel subnets; both must be valid for the installed agent.
func registeredNodeChainCheckPeer(source multihoprelay.NodeChainDescriptor, host netip.Addr, ranges []string) netip.Addr {
	for _, text := range source.ExternalFinal.EntryPeerAddresses {
		peer, err := netip.ParseAddr(text)
		if err != nil || peer == host || peer.Is4() != host.Is4() {
			continue
		}
		for _, cidr := range ranges {
			if prefix, err := netip.ParsePrefix(cidr); err == nil && prefix.Contains(peer) {
				return peer
			}
		}
	}
	return netip.Addr{}
}

func (s *relayNodeChainRegistryCheck) checkNative(directory string) error {
	if s == nil {
		return nil
	}
	bad := errors.New("bundled relay core rejected a private ordered server configuration")
	var image *os.File
	if slices.ContainsFunc(s.sources, func(d multihoprelay.NodeChainDescriptor) bool { return d.Schema == 8 }) {
		file, info, digest, err := captureRelayNodeChainImage(s.runner.core)
		if err != nil {
			return bad
		}
		defer file.Close()
		if !os.SameFile(info, s.coreInfo) || digest != s.coreSHA {
			return bad
		}
		image = file
	}
	for i, source := range s.sources {
		capture, err := relayNodeChainValidationCapture(source, s.host, s.peers[i], s.port, time.Now().UTC())
		if err != nil {
			return bad
		}
		if source.Schema == 8 {
			if err := checkNativeExternalFinalSource(directory, image, s.policies[i], capture); err != nil {
				return bad
			}
			continue
		}
		graph, err := s.policies[i].NativeConfig(capture)
		if err != nil || checkNativeRelayConfig(directory, s.runner.core, []byte(graph)) != nil {
			return bad
		}
	}
	return nil
}

// Home DNS has a private, lease-bound native outbound. Only the dedicated
// checker can reconstruct the complete registered worker without starting it.
func checkNativeExternalFinalSource(directory string, image *os.File, policy *mobilemultihop.NodeChainServerPolicy, capture multihoprelay.NodeChainCapture) (outErr error) {
	bad := errors.New("bundled relay core rejected the registered public-final source")
	raw, err := multihoprelay.MarshalNodeChainWorkerCapture(capture)
	if err != nil {
		return bad
	}
	defer clear(raw)
	dir, err := os.MkdirTemp(directory, "registered-final-")
	if err != nil {
		return err
	}
	defer func() { outErr = errors.Join(outErr, os.RemoveAll(dir)) }()
	if err = atomicWritePrivilegedState(filepath.Join(dir, "node-chain-capture.json"), raw); err != nil {
		return err
	}
	source := []byte(policy.Source())
	defer clear(source)
	if err = atomicWritePrivilegedState(filepath.Join(dir, "node-chain-source.json"), source); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proc/self/fd/3", "routervpn-node-chain-check", "--runtime-dir", dir)
	command.ExtraFiles = []*os.File{image}
	command.Dir = dir
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C"}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if command.Run() != nil {
		return bad
	}
	return nil
}

func (s *relayNodeChainRegistryCheck) current() error {
	if s == nil {
		return nil
	}
	bad := errors.New("private ordered server source or core changed during validation")
	image, info, digest, err := captureRelayNodeChainImage(s.runner.core)
	if err != nil {
		return bad
	}
	defer image.Close()
	if !os.SameFile(s.coreInfo, info) || digest != s.coreSHA || !info.ModTime().Equal(s.coreInfo.ModTime()) {
		return bad
	}
	for _, currentSource := range s.currentSources {
		if !currentSource() {
			return bad
		}
	}
	return nil
}

// The resulting credentials and keys are used only in the private native
// parser input. They are not saved, registered, acquired or returned as client
// authority. Real leases must still supply their independently captured keys.
func relayNodeChainValidationCapture(source multihoprelay.NodeChainDescriptor, host, peer string, port int, now time.Time) (multihoprelay.NodeChainCapture, error) {
	bad := errors.New("invalid private ordered parser capture")
	digest, err := source.Digest()
	if err != nil || now.IsZero() || host == peer {
		return multihoprelay.NodeChainCapture{}, bad
	}
	secret := func(size int) (string, error) {
		raw := make([]byte, size)
		defer clear(raw)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		return hex.EncodeToString(raw), nil
	}
	session, err := secret(16)
	if err != nil {
		return multihoprelay.NodeChainCapture{}, bad
	}
	epoch, err := secret(32)
	if err != nil {
		return multihoprelay.NodeChainCapture{}, bad
	}
	owner, err := secret(32)
	if err != nil {
		return multihoprelay.NodeChainCapture{}, bad
	}
	request := multihoprelay.NodeChainRequest{Schema: source.Schema, SessionID: session, EntryNodeID: source.EntryNodeID,
		SourceSHA256: source.SourceSHA256, DescriptorSHA256: digest, DNSPolicySHA256: source.DNSPolicySHA256,
		Epoch: epoch, Peer: peer, AcquireExpiresAt: now.Add(time.Minute).Unix(), Port: port}
	keys := make(map[string]bool)
	for _, member := range source.Members {
		keys[member.ClientPublicKey], keys[member.ServerPublicKey] = true, true
	}
	count := len(source.Members)
	if source.Schema == 8 {
		// This operator registry pins the public half of the client entry.
		// A randomly generated parser key would validate a different origin.
		request.LocalPacketPositions = []int{0}
		request.LocalPacketPublicKeys = []string{source.ExternalFinal.EntryClientPublicKey}
		count = 0
	} else if source.Schema == 6 {
		// Imported members have no packet identity. Retain the actual sparse
		// packet positions, including the client entry omitted from the suffix.
		request.LocalPacketPositions = []int{0}
		for _, member := range source.Members[:len(source.Members)-1] {
			if member.ClientPublicKey != "" {
				request.LocalPacketPositions = append(request.LocalPacketPositions, member.Position)
			}
		}
		count = len(request.LocalPacketPositions)
	} else if source.Schema == 2 || source.Schema == 3 || source.Schema == 4 || source.Schema == 5 {
		// Complete imported SS/SOCKS/CONNECT/OpenVPN graphs keep every paired packet position before
		// the original penultimate import. These are fresh parser-only keys,
		// never either side of the operator's actual packet identities.
		count = len(source.Members) - 1
		for position := 0; position < count; position++ {
			request.LocalPacketPositions = append(request.LocalPacketPositions, position)
		}
	}
	for i := 0; i < count; i++ {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return multihoprelay.NodeChainCapture{}, bad
		}
		public := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
		if keys[public] {
			return multihoprelay.NodeChainCapture{}, bad
		}
		keys[public] = true
		request.LocalPacketPublicKeys = append(request.LocalPacketPublicKeys, public)
	}
	switch {
	case source.Schema == 8:
		request, err = multihoprelay.NewExternalFinalFrontCredentials(request, len(source.Members))
	case source.Schema == 6 && len(source.Members) > multihoprelay.NodeChainMaximumMembers:
		request, err = multihoprelay.NewExtendedPrivateFrontCredentials(request, len(source.Members))
	default:
		for _, member := range source.Members {
			user, err := secret(24)
			if err != nil {
				return multihoprelay.NodeChainCapture{}, bad
			}
			password, err := secret(24)
			if err != nil {
				return multihoprelay.NodeChainCapture{}, bad
			}
			request.Users = append(request.Users, multihoprelay.NodeChainUser{Position: member.Position, Username: user, Password: password})
		}
	}
	if err != nil {
		return multihoprelay.NodeChainCapture{}, bad
	}
	capture := multihoprelay.NodeChainCapture{Schema: 1, Request: request, Source: source.Clone(), RegistrySHA256: digest,
		OwnerID: owner, Host: host, Peer: peer, BootstrapDeadline: now.Add(time.Minute).UTC()}
	if err := capture.Validate(); err != nil {
		return multihoprelay.NodeChainCapture{}, bad
	}
	return capture, nil
}
