package mobiletor

import (
	"encoding/json"
	"errors"
)

// MobileServerTorOptions contains the actual frozen inputs, not a caller's
// success receipt or a replaceable hash. Native construction recompiles them,
// and admission compares that result with the same Box's complete snapshot.
type MobileServerTorOptions struct {
	Profile      string `json:"profile"`
	SessionID    string `json:"session_id"`
	EntryConfig  string `json:"entry_config"`
	EntryProfile string `json:"entry_profile"`
}

type MobileServerTorPolicy struct {
	config, entryTag, leaseSession string
	options                        MobileServerTorOptions
	entry                          *PredecessorProof
	server                         *ServerTorPolicy
}

func (p *MobileServerTorPolicy) Config() string                  { return p.config }
func (p *MobileServerTorPolicy) EntryTag() string                { return p.entryTag }
func (p *MobileServerTorPolicy) SessionID() string               { return p.options.SessionID }
func (p *MobileServerTorPolicy) LeaseSessionID() string          { return p.leaseSession }
func (p *MobileServerTorPolicy) EntryProof() *PredecessorProof   { return p.entry }
func (p *MobileServerTorPolicy) ServerPolicy() *ServerTorPolicy  { return p.server }
func (p *MobileServerTorPolicy) Options() MobileServerTorOptions { return p.options }

// CompileServerProfileWithPredecessor is deliberately separate from Local.
// The server request requires the private Router's live source match and lease;
// compiling its one existing TUN grants neither of those runtime authorities.
func CompileServerProfileWithPredecessor(profile, session, entryConfig, entryProfile string) (string, error) {
	policy, err := NewMobileServerTorPolicy(MobileServerTorOptions{Profile: profile, SessionID: session, EntryConfig: entryConfig, EntryProfile: entryProfile})
	if err != nil {
		return "", err
	}
	return policy.Config(), nil
}

func NewMobileServerTorPolicy(options MobileServerTorOptions) (*MobileServerTorPolicy, error) {
	failure := errors.New("mobile Tor Server requires its complete captured private entry and explicit Server selection")
	profile, bridges, err := capturedTorProfile(options.Profile)
	if err != nil || !profileIdentifier.MatchString(options.SessionID) || options.EntryConfig == "" || options.EntryProfile == "" ||
		profile["multihop_enabled"] != true || profileString(profile, "multihop_execution") != "server" {
		return nil, failure
	}
	entry, err := NewPredecessorProof(options.EntryProfile)
	if err != nil {
		return nil, err
	}
	entryProfile, err := profileObject(options.EntryProfile, 256<<10)
	if err != nil {
		return nil, err
	}
	// The common compiler supplies the same DNS, IPv6, LAN, protection and MTU
	// policy. This data-only intermediate is never handed to a Local runtime.
	profile["multihop_execution"] = "local"
	normalizeMobileServerDNSMode(profile)
	localSource, _ := json.Marshal(profile)
	compiled, err := CompileProfileWithPredecessor(string(localSource), options.SessionID, options.EntryConfig, options.EntryProfile)
	if err != nil {
		return nil, err
	}
	graph, err := profileObject(compiled, 4<<20)
	if err != nil {
		return nil, err
	}
	selected, _, err := torSelectedDNS(profile, entryProfile, false)
	if err != nil {
		return nil, err
	}
	dns, err := selectedDNSMetadata(profile, selected)
	if err != nil {
		return nil, err
	}
	mode := profile["external"].(map[string]any)["protocol"]
	source := map[string]any{"schema": 1, "id": profile["id"], "entry_node_id": entry.NodeID(), "mode": mode, "dns": dns}
	padding, paddingSelected, err := capturedTorPaddingPolicy(profile)
	if err != nil {
		return nil, err
	}
	if paddingSelected {
		source["padding"] = padding
	}
	if mode == "tor-bridge" {
		source["tor_bridge"] = map[string]any{"transport": "custom", "bridges": bridges}
	}
	if dns.Mode == "home" {
		for _, key := range []string{"adguard_ipv4", "adguard_ipv6"} {
			if value, exists := entryProfile[key]; exists && value != "" {
				source[key] = value
			}
		}
	}
	rawSource, _ := json.Marshal(source)
	server, err := NewServerTorPolicy(string(rawSource), entry.NodeID())
	if err != nil {
		return nil, err
	}
	var entryTag string
	matched := 0
	outbounds, _ := graph["outbounds"].([]any)
	for index, raw := range outbounds {
		outbound, ok := raw.(map[string]any)
		if !ok {
			return nil, failure
		}
		if outbound["type"] == "routervpn-tor" || outbound["tag"] == ProfileOutboundTag {
			if outbound["type"] != "routervpn-tor" || outbound["tag"] != ProfileOutboundTag || outbound["entry_sha256"] != entry.Fingerprint() {
				return nil, failure
			}
			entryTag = profileString(outbound, "detour")
			if !profileIdentifier.MatchString(entryTag) {
				return nil, failure
			}
			outbounds[index] = map[string]any{"type": ServerTorClientType, "tag": ProfileOutboundTag, "profile": options.Profile,
				"session_id": options.SessionID, "entry_config": options.EntryConfig, "entry_profile": options.EntryProfile}
			matched++
		}
	}
	if matched != 1 {
		return nil, failure
	}
	// Client-side bridge/bootstrap networking no longer exists. Keep every
	// original entry resolver, including explicit Naive/bootstrap dependencies.
	dnsGraph, _ := graph["dns"].(map[string]any)
	servers, _ := dnsGraph["servers"].([]any)
	kept := make([]any, 0, len(servers))
	removed := 0
	for _, raw := range servers {
		resolver, ok := raw.(map[string]any)
		if !ok {
			return nil, failure
		}
		if resolver["tag"] == bootstrapDNS {
			removed++
			continue
		}
		kept = append(kept, raw)
	}
	if removed != 1 {
		return nil, failure
	}
	dnsGraph["servers"] = kept
	encoded, err := json.Marshal(graph)
	if err != nil || len(encoded) > 4<<20 {
		return nil, errors.New("mobile Tor Server captured configuration exceeds its native bound")
	}
	// The mobile host keeps its original UUID. The private lease protocol uses
	// 128 bits of a domain-separated digest of that fresh session and all its
	// immutable sources; restoring another profile cannot reuse an old lease.
	identity, _ := json.Marshal([]string{"routervpn-mobile-server-tor-lease-v1", options.SessionID, options.Profile, options.EntryConfig, options.EntryProfile, server.SourceSHA256()})
	return &MobileServerTorPolicy{config: string(encoded), entryTag: entryTag, leaseSession: capturedDigest(identity)[:32], options: options, entry: entry, server: server}, nil
}

func normalizeMobileServerDNSMode(profile map[string]any) {
	switch mode := profileString(profile, "dns_mode"); mode {
	case "":
		profile["dns_mode"] = "home"
	case "dot", "doh", "doh3":
		profile["dns_mode"], profile["dns_protocol"] = "custom", mode
	}
}
