package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"time"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

type relayNodeChainRegistryCheck struct {
	runner   *relayNodeChainExecRunner
	sources  []multihoprelay.NodeChainDescriptor
	policies []*mobilemultihop.NodeChainServerPolicy
	node     string
	host     string
	peer     string
	port     int
	coreInfo os.FileInfo
	coreSHA  string
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
	if !peer.IsValid() {
		return nil, bad
	}
	state := &relayNodeChainRegistryCheck{runner: &relayNodeChainExecRunner{sources: paths.nodeChainSources, core: paths.core},
		node: entry.NodeID, host: host.String(), peer: peer.String(), port: registry.FirstPort, coreInfo: info, coreSHA: digest}
	for _, source := range registry.NodeChains {
		policy, err := state.runner.source(source, entry.NodeID)
		if err != nil {
			return nil, bad
		}
		state.sources = append(state.sources, source.Clone())
		state.policies = append(state.policies, policy)
	}
	return state, nil
}

func (s *relayNodeChainRegistryCheck) checkNative(directory string) error {
	if s == nil {
		return nil
	}
	bad := errors.New("bundled relay core rejected a private ordered server configuration")
	for i, source := range s.sources {
		capture, err := relayNodeChainValidationCapture(source, s.host, s.peer, s.port, time.Now().UTC())
		if err != nil {
			return bad
		}
		graph, err := s.policies[i].NativeConfig(capture)
		if err != nil || checkNativeRelayConfig(directory, s.runner.core, []byte(graph)) != nil {
			return bad
		}
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
	for _, source := range s.sources {
		if _, err := s.runner.source(source, s.node); err != nil {
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
	if source.Schema == 2 {
		count = 1
		request.LocalPacketPositions = []int{0}
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
	capture := multihoprelay.NodeChainCapture{Schema: 1, Request: request, Source: source.Clone(), RegistrySHA256: digest,
		OwnerID: owner, Host: host, Peer: peer, BootstrapDeadline: now.Add(time.Minute).UTC()}
	if err := capture.Validate(); err != nil {
		return multihoprelay.NodeChainCapture{}, bad
	}
	return capture, nil
}
