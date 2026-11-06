package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// This private seal is captured while the original, proved external owner is
// still retained. Restoration may consume it, but cannot refresh it from a
// changed saved profile. Source identity covers layer keys/API/ports, both
// imported nodes, predecessor and the already proved execution choice.
type speedLabExternalRestoreSeal struct {
	identity, sourceSHA256, configSHA256 string
	executionController                  bool
}

func speedLabExternalRestoreIdentity(saved *speedLabExternalRestore, controller bool) (string, error) {
	if saved == nil {
		return "", errors.New("missing external restore source")
	}
	raw, err := json.Marshal(struct {
		Source                 []byte
		Profile, Entry         common.RouterProfile
		Predecessor, Execution string
		Direct                 bool
		ExecutionController    bool
	}{saved.source, saved.profile, saved.entry, saved.predecessor, saved.execution, saved.direct, controller})
	if err != nil {
		return "", err
	}
	defer clear(raw)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// The caller holds the original runtime mutex. Original proof validation has
// already happened; this additionally checks the retained inputs against that
// runtime's exact compiled identity before any temporary connection mutation.
func captureSpeedLabExternalRestoreSeal(saved *speedLabExternalRestore, owner *desktopExternalRuntime) error {
	if saved == nil || owner == nil || saved.seal != nil || owner.session == "" || owner.expected.SessionID != owner.session ||
		saved.execution != "local" && saved.execution != "server" || saved.direct && saved.execution != "local" ||
		!bytes.Equal(saved.source, owner.source) || saved.predecessor != owner.predecessor || saved.direct != owner.direct ||
		!reflect.DeepEqual(saved.profile, owner.profile) ||
		!reflect.DeepEqual(saved.entry, owner.entry) {
		return errors.New("external restore capture lost its original retained source")
	}
	policy, err := mobilemultihop.NewExternalPolicy(string(owner.source), string(owner.capture))
	if err != nil {
		return err
	}
	var identity struct {
		SourceSHA256 string `json:"source_sha256"`
		ConfigSHA256 string `json:"config_sha256"`
	}
	if json.Unmarshal([]byte(policy.Metadata()), &identity) != nil || identity.SourceSHA256 != owner.expected.SourceSHA256 || identity.ConfigSHA256 != owner.expected.ConfigSHA256 || policy.SourceSHA256() != owner.expected.SourceSHA256 {
		return errors.New("external restore capture differs from its original compiled proof identity")
	}
	var captured struct {
		Execution *json.RawMessage `json:"execution"`
	}
	if json.Unmarshal(owner.capture, &captured) != nil {
		return errors.New("external restore lost its original controller capture")
	}
	sealed, err := speedLabExternalRestoreIdentity(saved, captured.Execution != nil)
	if err != nil {
		return err
	}
	saved.seal = &speedLabExternalRestoreSeal{identity: sealed, sourceSHA256: identity.SourceSHA256, configSHA256: identity.ConfigSHA256, executionController: captured.Execution != nil}
	return nil
}

func (seal *speedLabExternalRestoreSeal) current(saved *speedLabExternalRestore) error {
	if seal == nil || len(seal.sourceSHA256) != 64 || len(seal.configSHA256) != 64 {
		return errors.New("external restoration has no original source seal")
	}
	current, err := speedLabExternalRestoreIdentity(saved, seal.executionController)
	if err != nil || current != seal.identity {
		return errors.New("external restoration changed its sealed original source")
	}
	return nil
}
