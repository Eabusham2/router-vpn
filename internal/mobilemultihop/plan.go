// Package mobilemultihop composes and compares local/server exits inside one
// already-owned mobile TUN. It does not start another OS VPN or alter host routes.
package mobilemultihop

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/routechoice"
)

const LocalTag = "routervpn-execution-local"
const ServerTag = "routervpn-execution-server"
const SelectorTag = "proxy"

var exactID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
var proofID = regexp.MustCompile(`^[0-9a-f]{64}$`)
var Targets = []string{"https://1.1.1.1/cdn-cgi/trace", "https://1.0.0.1/cdn-cgi/trace"}

// Metadata is captured from the paired entry and exit, never the mutable UI.
// It contains credentials and must not be returned by a progress/status API.
type Metadata struct {
	EntryID     string `json:"entry_id"`
	ExitID      string `json:"exit_id"`
	EntryNodeID string `json:"entry_node_id"`
	ExitNodeID  string `json:"exit_node_id"`
	EntryAPI    string `json:"entry_api"`
	ExitAPI     string `json:"exit_api"`
	EntryToken  string `json:"entry_token"`
	ExitToken   string `json:"exit_token"`
	EntryTag    string `json:"entry_tag"`
	ExitMode    string `json:"exit_mode"`
	Execution   string `json:"execution"`
}

// Engine must dial the named outbound on the same retained native instance.
// A recreated instance, network transition, sleep/wake or stop invalidates it.
type Engine interface {
	Identity() string
	Dial(context.Context, string, string) (net.Conn, error)
	Select(string) error
	Selected() string
}

type Progress struct {
	Stage        string                    `json:"stage"`
	Complete     bool                      `json:"complete"`
	Execution    string                    `json:"execution,omitempty"`
	Measurements []routechoice.Measurement `json:"measurements"`
	Failure      string                    `json:"failure,omitempty"`
}

type Controller struct {
	meta           Metadata
	config         string
	proposal       multihoprelay.Request
	expected       multihoprelay.Lease
	localPublicKey string
	generation     atomic.Uint64
	mu             sync.Mutex
	progress       Progress
	engine         Engine
	engineID       string
	cancel         context.CancelFunc
	runDone        chan struct{}
	leaseMu        sync.Mutex
	ownsLease      bool
	renewCancel    context.CancelFunc
	renewDone      chan struct{}
}

func exactJSON(data []byte, output any, limit int) error {
	bad := errors.New("bounded unambiguous multihop JSON required")
	if len(data) == 0 || len(data) > limit || !utf8.Valid(data) {
		return bad
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var check func(int) error
	check = func(depth int) error {
		if depth > 48 {
			return bad
		}
		t, e := decoder.Token()
		if e != nil {
			return bad
		}
		d, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				k, e := decoder.Token()
				s, ok := k.(string)
				if e != nil || !ok || seen[s] {
					return bad
				}
				seen[s] = true
				if e = check(depth + 1); e != nil {
					return e
				}
			}
			end, e := decoder.Token()
			if e != nil || end != json.Delim('}') {
				return bad
			}
		case '[':
			for decoder.More() {
				if e := check(depth + 1); e != nil {
					return e
				}
			}
			end, e := decoder.Token()
			if e != nil || end != json.Delim(']') {
				return bad
			}
		default:
			return bad
		}
		return nil
	}
	if check(0) != nil {
		return bad
	}
	if _, e := decoder.Token(); e != io.EOF {
		return bad
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(output) != nil {
		return bad
	}
	return nil
}
func privateAPI(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u == nil || !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("private paired Router API required")
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if e != nil || ip.Zone() != "" || !ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return nil, errors.New("private literal Router API required")
	}
	if port, e := strconv.Atoi(u.Port()); e != nil || port < 1 || port > 65535 {
		return nil, errors.New("explicit Router API port required")
	}
	return u, nil
}
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}

func New(config, metadata string) (*Controller, error) {
	var meta Metadata
	if exactJSON([]byte(metadata), &meta, 16384) != nil {
		return nil, errors.New("invalid frozen multihop metadata")
	}
	if !exactID.MatchString(meta.EntryID) || !exactID.MatchString(meta.ExitID) || meta.EntryID == meta.ExitID || !proofID.MatchString(meta.EntryNodeID) || !proofID.MatchString(meta.ExitNodeID) || meta.EntryNodeID == meta.ExitNodeID {
		return nil, errors.New("distinct paired multihop identities required")
	}
	if meta.EntryTag != "entry-wg" && meta.EntryTag != "routervpn-hop-entry" {
		return nil, errors.New("unowned entry endpoint")
	}
	if meta.ExitMode != "wg" && meta.ExitMode != "shadowsocks" && meta.ExitMode != "hysteria2" {
		return nil, errors.New("unimplemented exit transport")
	}
	if meta.Execution != "local" && meta.Execution != "server" && meta.Execution != "auto" {
		return nil, errors.New("select local, server, or auto execution")
	}
	entry, e := privateAPI(meta.EntryAPI)
	if e != nil {
		return nil, e
	}
	if _, e = privateAPI(meta.ExitAPI); e != nil {
		return nil, e
	}
	for _, token := range []string{meta.EntryToken, meta.ExitToken} {
		if len(token) < 1 || len(token) > 4096 || strings.ContainsAny(token, "\r\n\x00") {
			return nil, errors.New("invalid node credential")
		}
	}
	var root map[string]any
	if exactJSON([]byte(config), &root, 4<<20) != nil || root == nil {
		return nil, errors.New("invalid owned mobile graph")
	}
	route, ok := root["route"].(map[string]any)
	if !ok || route["final"] != "proxy" {
		return nil, errors.New("mobile graph lost its exit final route")
	}
	endpoints, ok := root["endpoints"].([]any)
	if !ok {
		return nil, errors.New("mobile graph has no entry endpoint")
	}
	var local map[string]any
	entryCount, exitCount := 0, 0
	for _, list := range []string{"outbounds", "endpoints"} {
		values, _ := root[list].([]any)
		for _, raw := range values {
			value, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("invalid mobile outbound")
			}
			if value["tag"] == LocalTag || value["tag"] == ServerTag {
				return nil, errors.New("execution tags already owned")
			}
			if value["tag"] == meta.EntryTag {
				entryCount++
				if value["type"] != "wireguard" {
					return nil, errors.New("entry is not a native WireGuard endpoint")
				}
			}
			if value["tag"] == "proxy" {
				exitCount++
				local = value
			}
		}
	}
	if entryCount != 1 || exitCount != 1 || local == nil || local["detour"] != meta.EntryTag {
		return nil, errors.New("exact nested local graph required")
	}
	expectedType := meta.ExitMode
	if expectedType == "wg" {
		expectedType = "wireguard"
	}
	if local["type"] != expectedType {
		return nil, errors.New("exit label does not match the dataplane")
	}
	_ = endpoints
	c := &Controller{meta: meta, progress: Progress{Stage: "prepared", Measurements: []routechoice.Measurement{}}}
	c.generation.Store(1)
	nonce, e := randomHex(16)
	if e != nil {
		return nil, e
	}
	user, e := randomHex(24)
	if e != nil {
		return nil, e
	}
	password, e := randomHex(24)
	if e != nil {
		return nil, e
	}
	var seed [1]byte
	if _, e = rand.Read(seed[:]); e != nil {
		return nil, e
	}
	c.proposal = multihoprelay.Request{SessionID: nonce, EntryNodeID: meta.EntryNodeID, ExitID: meta.ExitID, ExitMode: meta.ExitMode, Port: 26240 + int(seed[0]%32), Username: user, Password: password}
	c.expected = multihoprelay.Lease{Request: c.proposal, NodeID: meta.EntryNodeID, ExitNodeID: meta.ExitNodeID, Host: entry.Hostname(), Port: c.proposal.Port, Username: user, Password: password}
	if meta.ExitMode == "wg" {
		text, _ := local["private_key"].(string)
		key, e := base64.StdEncoding.Strict().DecodeString(text)
		if e != nil || len(key) != 32 {
			return nil, errors.New("invalid local WireGuard key")
		}
		private, e := ecdh.X25519().NewPrivateKey(key)
		if e != nil {
			return nil, e
		}
		c.localPublicKey = base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
	}
	local["tag"] = LocalTag
	outbounds, _ := root["outbounds"].([]any)
	outbounds = append(outbounds, map[string]any{"type": "socks", "tag": ServerTag, "server": c.expected.Host, "server_port": c.expected.Port, "version": "5", "username": user, "password": password, "detour": meta.EntryTag})
	initial := LocalTag
	if meta.Execution == "server" {
		initial = ServerTag
	}
	outbounds = append(outbounds, map[string]any{"type": "selector", "tag": "proxy", "outbounds": []string{LocalTag, ServerTag}, "default": initial, "interrupt_exist_connections": true})
	root["outbounds"] = outbounds
	// All existing DNS detours and exit-proof routes still point to proxy, now the
	// selected encrypted path. The comparator dials individual tags internally.
	encoded, e := json.Marshal(root)
	if e != nil {
		return nil, e
	}
	c.config = string(encoded)
	return c, nil
}
func (c *Controller) Config() string { return c.config }
func (c *Controller) ProgressJSON() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, _ := json.Marshal(c.progress)
	return string(b)
}
func (c *Controller) invalidate() {
	c.generation.Add(1)
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
}
func (c *Controller) NetworkChanged() { c.invalidate() }
func (c *Controller) valid() bool {
	return c.engine != nil && c.engine.Identity() != "" && c.engine.Identity() == c.engineID && c.generation.Load() == 1
}
func (c *Controller) candidate(execution routechoice.Execution) routechoice.Candidate {
	return routechoice.Candidate{Execution: execution, Transport: c.meta.ExitMode, EntryID: c.meta.EntryID, ExitID: c.meta.ExitID}
}
func (c *Controller) event(event routechoice.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.progress.Stage = event.Stage
	if event.Stage == "measured" && event.Result != nil {
		c.progress.Measurements = append(c.progress.Measurements, *event.Result)
	}
}
func (c *Controller) failed(message string) {
	c.mu.Lock()
	c.progress.Complete = true
	c.progress.Stage = "failed"
	c.progress.Failure = message
	c.mu.Unlock()
}
func (c *Controller) requireValid() error {
	if !c.valid() {
		return fmt.Errorf("mobile multihop session or network changed")
	}
	return nil
}
